Developer: ForgeNKing • Language: Python 3 • License: MIT
github-subfinder is a lightweight, token-aware reconnaissance tool that mines GitHub Code Search and raw file contents to uncover subdomains relevant to your target. It favors speed, signal, and portability, using only the Python standard library while handling pagination, concurrency, deduplication, and rate-limit rotation automatically.
✨ Features
⚡ Fast parallel fetching — pulls raw files concurrently and extracts hostnames with resilient regex.
🧠 Smart search plan — combines quoted domain terms with language filters and context hints (api, private, internal) to boost signal.
🎯 Quick & Extended modes — quick mode for fast sweeps; extended mode widens matches around the registrable domain.
🔁 Token pool & cooldown — rotates across multiple GitHub tokens; cools down rate-limited tokens and resumes automatically.
🧹 Deduped output — streams raw lines to stdout or writes a clean, sorted file suitable for dnsx/massdns/httpx.
🧩 Zero dependencies — pure stdlib; easy to audit, easy to run anywhere Python 3 is available.
🪪 Versioned UA — polite User-Agent string; simple to integrate into CI or larger pipelines.
🚀 Usage
# Quick run (single token via env)
export GITHUB_TOKEN=ghp_xxx
python3 github-subfinder.py -d example.com

# Multiple tokens (comma-separated) and extended mode
python3 github-subfinder.py -d example.com -t ghp_xxx,ghp_yyy -e -o example.com.txt

# Raw streaming for piping into resolvers/probers
python3 github-subfinder.py -d example.com --raw | dnsx -silent | httpx -silent
CLI Flags
-d target domain (required)
-t GitHub token(s), comma-separated; else uses GITHUB_TOKEN; else reads from .tokens
-o output file (default <domain>.txt)
-e extended mode (wider regex, registrable-domain search)
-q quick mode (base query only)
-k exit when all tokens are rate-limited
--raw print only found domains
--version print version and exit
🔑 How to get a GitHub token (PAT)
Sign in to GitHub and open Settings → Developer settings → Personal access tokens.
Prefer Fine-grained tokens. Click Generate new token.
Repository access: Only select repositories or All repositories (for public code search, read access is enough).
Permissions: grant Contents: Read. For public-only hunting, that’s typically sufficient.
Generate and copy the token. Store it in GITHUB_TOKEN or pass with -t.
(Optional) Prepare a .tokens file with one token per line for rotation.
Note: Authenticated search has higher rate limits than anonymous. The tool rotates tokens and cools down any that hit the quota.
🧪 Tips
Pair with dnsx, massdns, and httpx to validate and probe results.
Use -q during triage; add -e to widen recall when chasing hidden environments.
