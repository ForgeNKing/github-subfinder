#!/usr/bin/env python3
# github-subfinder
# Developer: ForgeNKing
# Description: Find subdomains by mining GitHub Code Search and raw file contents.
# Standalone script, stdlib-only, no external dependencies.

import argparse
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Config ----------

TOOL_NAME = "github-subfinder"
DEVELOPER = "ForgeNKing"
VERSION = "1.0.0"

DEFAULT_LANGUAGES = [
    "JavaScript","Python","Java","Go","Ruby","PHP","Shell","CSV","Markdown","XML",
    "JSON","Text","CSS","HTML","Perl","ActionScript","Lua","C","C%2B%2B","C%23"
]

DEFAULT_NOISE = [
    "api","private","secret","internal","corp","development","production"
]

SEARCH_PER_PAGE = 100
SEARCH_MAX_PAGES = 10
CODE_TIMEOUT = 7.5
SEARCH_TIMEOUT = 7.5
RAW_DELAY_SEC = 0.20
MAX_FETCH_WORKERS = 30
RATE_LIMIT_COOLDOWN = 61

TOKEN_RE = re.compile(r"(?:[0-9a-f]{40}|ghp_[A-Za-z0-9]{36}|github_pat_[_A-Za-z0-9]{82})")
UA = f"{TOOL_NAME}/{VERSION} ({DEVELOPER})"

# ---------- Utility ----------

def log(msg, level="info", raw=False):
    if raw and level == "found":
        print(msg)
        return
    if raw:
        return
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

def read_tokens_from_file(path):
    if not os.path.exists(path):
        return []
    toks = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            t = line.strip()
            if t and TOKEN_RE.search(t) and t not in toks:
                toks.append(t)
    return toks

class TokenPool:
    def __init__(self, tokens, stop_when_empty=False):
        self.tokens = [{"value": t, "disabled_until": 0.0} for t in tokens]
        random.shuffle(self.tokens)
        self.lock = threading.Lock()
        self.stop_when_empty = stop_when_empty
        self.idx = 0

    def _available_indices(self):
        now = time.time()
        return [i for i, t in enumerate(self.tokens) if t["disabled_until"] <= now]

    def get(self):
        with self.lock:
            avail = self._available_indices()
            if not avail:
                return None
            if self.idx not in avail:
                self.idx = avail[0]
            t = self.tokens[self.idx]
            nxt = avail.index(self.idx) + 1
            if nxt >= len(avail):
                nxt = 0
            self.idx = avail[nxt]
            return t["value"]

    def disable(self, tok, cooldown=RATE_LIMIT_COOLDOWN):
        with self.lock:
            now = time.time()
            for t in self.tokens:
                if t["value"] == tok:
                    t["disabled_until"] = now + cooldown
                    break

    def any_available(self):
        return any(t["disabled_until"] <= time.time() for t in self.tokens)

# ---------- Domain helpers ----------

def split_domain(user_domain):
    host = user_domain.strip().lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return ("", host, "")
    tld = labels[-1]
    registrable = labels[-2]
    sub = ".".join(labels[:-2])
    return (sub, registrable, tld)

def build_patterns(user_domain, extended=False):
    sub, registrable, tld = split_domain(user_domain)
    if extended:
        search = registrable
        pat = rf"(?i)[0-9a-z\-\.]+\.([0-9a-z\-]+)?{re.escape(registrable)}([0-9a-z\-\.]+)?\.[a-z]{{1,5}}"
        return search, re.compile(pat)
    else:
        if sub:
            search = f"{sub}.{registrable}.{tld}"
            core = rf"{re.escape(sub)}\.{re.escape(registrable)}\.{re.escape(tld)}"
        else:
            search = f"{registrable}.{tld}"
            core = rf"{re.escape(registrable)}\.{re.escape(tld)}"
        pat = rf"(?i)(([0-9a-z\-\.]+)\.)?{core}"
        return search, re.compile(pat)

# ---------- GitHub API ----------

def gh_request(url, token, timeout):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": UA,
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
            headers = dict(resp.headers)
            return status, headers, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body
    except Exception:
        return None, {}, b""

def github_search(query, page, token):
    params = {
        "q": query,
        "per_page": str(SEARCH_PER_PAGE),
        "page": str(page),
        "sort": "indexed",
        "order": "desc",
    }
    url = "https://api.github.com/search/code?" + urllib.parse.urlencode(params)
    status, hdr, body = gh_request(url, token, SEARCH_TIMEOUT)
    if status is None:
        return {"error": "network"}, None
    if status == 403 or hdr.get("X-RateLimit-Remaining") == "0":
        msg = ""
        try:
            msg = json.loads(body.decode("utf-8", "ignore")).get("message", "")
        except Exception:
            pass
        return {"error": "ratelimit", "message": msg}, None
    if status != 200:
        return {"error": f"http_{status}"}, None
    try:
        data = json.loads(body.decode("utf-8", "ignore"))
    except Exception:
        return {"error": "json"}, None
    return None, data

def to_raw_url(html_url):
    return html_url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")

def fetch_code(html_url, token):
    raw = to_raw_url(html_url)
    status, hdr, body = gh_request(raw, token, CODE_TIMEOUT)
    if status is None or (isinstance(status, int) and status >= 500):
        return {"error": "network"}, None
    if status == 403 or hdr.get("X-RateLimit-Remaining") == "0":
        return {"error": "ratelimit"}, None
    if status != 200:
        return {"error": f"http_{status}"}, None
    try:
        txt = body.decode("utf-8", "ignore")
    except Exception:
        txt = ""
    return None, txt

# ---------- Search plan ----------

def build_searches(base_search, quick=False):
    searches = []
    searches.append(f"\"{base_search}\"")
    if quick:
        return searches
    for lang in DEFAULT_LANGUAGES:
        searches.append(f"\"{base_search}\" language:{lang}")
    for term in DEFAULT_NOISE:
        searches.append(f"\"{base_search}\" {term}")
    return searches

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(prog=TOOL_NAME, description="Find subdomains via GitHub Code Search (ForgeNKing).")
    ap.add_argument("-d", dest="domain", required=True, help="target domain, e.g. example.com")
    ap.add_argument("-t", dest="tokens", default="", help="comma-separated GitHub tokens; else GITHUB_TOKEN env; else .tokens file")
    ap.add_argument("-o", dest="output", default="", help="output file (default <domain>.txt)")
    ap.add_argument("-e", dest="extended", action="store_true", help="extended mode (wider regex, search by registrable name)")
    ap.add_argument("-q", dest="quick", action="store_true", help="quick mode (base query only)")
    ap.add_argument("-k", dest="stop_when_no_token", action="store_true", help="exit if all tokens are rate-limited")
    ap.add_argument("--raw", dest="raw", action="store_true", help="raw output: print only found domains")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} by {DEVELOPER}")
        sys.exit(0)

    tokens = []
    if args.tokens:
        tokens = [t.strip() for t in args.tokens.split(",") if TOKEN_RE.search(t.strip())]
    if not tokens:
        env = os.getenv("GITHUB_TOKEN", "").strip()
        if env and TOKEN_RE.search(env):
            tokens = [env]
    if not tokens:
        tokens = read_tokens_from_file(".tokens")
    if not tokens:
        log("no token provided or found (use -t, GITHUB_TOKEN, or .tokens)", "error", raw=args.raw)
        sys.exit(2)

    pool = TokenPool(tokens, stop_when_empty=args.stop_when_no_token)
    out_file = args.output or f"{args.domain}.txt"
    seen_urls = set()
    found_domains = set()

    search_keyword, domain_re = build_patterns(args.domain, extended=args.extended)
    searches = build_searches(search_keyword, quick=args.quick)

    if not args.raw:
        log(f"{TOOL_NAME} v{VERSION} by {DEVELOPER}")
        log(f"domain={args.domain} extended={args.extended} quick={args.quick} tokens={len(tokens)} output={out_file}")

    for q in searches:
        page = 1
        while page <= SEARCH_MAX_PAGES:
            tok = pool.get()
            if tok is None:
                if args.stop_when_no_token:
                    log("no available token, exiting", "error", raw=args.raw)
                    break
                log("no available token, waiting...", "info", raw=args.raw)
                time.sleep(3)
                continue

            err, data = github_search(q, page, tok)
            if err:
                if err.get("error") == "ratelimit":
                    pool.disable(tok)
                    log("rate limit hit, token disabled ~60s", "warn", raw=args.raw)
                    time.sleep(1)
                    continue
                else:
                    log(f"search error: {err.get('error')} (q={q}, page={page})", "warn", raw=args.raw)
                    time.sleep(0.5)
                    break

            items = data.get("items") or []
            total = data.get("total_count", 0)
            if not items:
                if not args.raw:
                    log(f"no items: q={q} page={page} total={total}")
                break

            with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as ex:
                futures = []
                for it in items:
                    html_url = it.get("html_url")
                    if not html_url or html_url in seen_urls:
                        continue
                    seen_urls.add(html_url)
                    futures.append(ex.submit(fetch_code, html_url, tok))

                for fu in as_completed(futures):
                    ferr, text = fu.result()
                    if ferr:
                        if ferr.get("error") == "ratelimit":
                            pool.disable(tok)
                        continue
                    if not text:
                        continue
                    for m in re.finditer(domain_re, text):
                        dom = m.group(0).lower().strip(".")
                        if dom and dom not in found_domains:
                            found_domains.add(dom)
                            log(dom, "found", raw=args.raw)

            page += 1
            time.sleep(RAW_DELAY_SEC)

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            for d in sorted(found_domains):
                f.write(d + "\n")
    except Exception as e:
        log(f"cannot write output: {e}", "error", raw=args.raw)
        sys.exit(4)

    if not args.raw:
        log(f"done: {len(found_domains)} unique -> {out_file}", "info", raw=args.raw)


if __name__ == "__main__":
    main()
