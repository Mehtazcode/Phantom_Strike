# PhantomStrike

A modular, automated red team framework built from scratch in Python — using raw sockets and raw HTTP instead of wrapping existing tools like Nmap or SQLMap. Built to understand offensive security tooling at the protocol level, not just to use it.

> ⚠️ **Authorized testing only.** This tool is built and tested exclusively against systems I own or have explicit permission to test: DVWA, Metasploitable, and `scanme.nmap.org`.

## Why raw sockets?

Most student pentest projects wrap Nmap, SQLMap, or Metasploit behind a CLI. PhantomStrike doesn't — the scanner, recon engine, and vulnerability detector are built directly on Python's socket and `requests` libraries. The point isn't to outperform mature tools; it's to demonstrate real understanding of what those tools are doing underneath: TCP handshakes, HTTP request construction, banner parsing, timeout/RST behavior, boolean-based confirmation logic, and so on.

## Pipeline
Recon → Port Scanner → Vulnerability Detector → Payload Generator → Report Generator

Each phase is a standalone module that can also run independently via the CLI.

## Status

| Phase | Module              | Status         |
|-------|----------------------|----------------|
| 0     | Foundation            | ✅ Done |
| 1     | Recon Engine           | ✅ Done |
| 2     | Port Scanner           | ✅ Done |
| 3     | Vulnerability Detector | ✅ Done |
| 4     | Payload Generator      | ⬜ Not started |
| 5     | Report Generator       | ⬜ Not started |
| 6     | Integration & polish   | ⬜ Not started |

## Phase 1 — Recon Engine

- **Subdomain enumeration**: wordlist brute-force + DNS resolution, multi-threaded via `ThreadPoolExecutor`
- **Certificate Transparency lookup**: passive OSINT via crt.sh, merged with wordlist results before resolution. Includes retry logic and graceful degradation — crt.sh is a free public service with known reliability issues (confirmed during development: observed timeouts, 502s, and 404s across consecutive runs), so the tool falls back to wordlist-only results rather than failing the whole recon run.
- **WHOIS lookup**: registrar and domain metadata via `python-whois`
- **Shodan search**: optional, gated behind a `SHODAN_API_KEY` environment variable — the tool works fully without it
- **Google dork generation**: passive-only, generates ready-to-use dork query strings across 6 categories (exposed files, admin panels, directory listings, config/backup leaks, error pages, subdomain discovery). Gated behind an explicit `--dorks` flag so it doesn't run on every recon call.

## Phase 2 — Port Scanner

- **TCP connect scanning** (`connect_ex()`) — full three-way handshake, no root required. Raw SYN (half-open) scanning was deliberately deferred to backlog in favor of shipping a working end-to-end MVP first; same "prove the pipeline, then optimize" pattern used elsewhere in the project.
- **Threaded scanning** via `ThreadPoolExecutor`, with banner grabbing done *inline within each worker thread* rather than deferred to the main thread after `as_completed()` — the latter caused empty banners on slow services (Telnet, SMTP) that perform ident/reverse-DNS lookups before greeting.
- **Two independent timeouts**: a fast `DEFAULT_SOCKET_TIMEOUT` for the connect itself, and a longer `BANNER_GRAB_TIMEOUT` for slow-to-greet services — tuned against real behavior observed on Metasploitable 2.
- **Service detection**: banner pattern-matching first (more reliable than port number alone — services get moved to nonstandard ports constantly in real engagements), falling back to a well-known port map.
- Tested against `scanme.nmap.org` and Metasploitable 2 (12 open ports across FTP, SSH, Telnet, SMTP, DNS, HTTP, RPC, NetBIOS, SMB) with banners and service detection confirmed working across a real mixed-service target.

## Phase 3 — Vulnerability Detector

Rule-based only (no AI) — the AI-assisted false-positive triage layer originally scoped for this phase was deferred and bundled with Phase 5's AI report generator instead, once API billing is set up.

**Core design principle: a finding is only marked `confirmed: true` if it's backed by real, verifiable evidence — not pattern-matching alone.** Every finding includes a `verification_method` field documenting exactly how it was confirmed:

- **SQL Injection** — three independent checks, each looking for a different kind of proof:
  - `boolean_diff` — sends a TRUE/FALSE payload pair, confirms only if the response bodies genuinely diverge (not just "payload appears in response")
  - `time_based` — measures response time against a `SLEEP(5)` payload vs. baseline, catching blind SQLi with no visible output difference
  - `error_signature` — matches known DB error strings in the response (lower-confidence signal; proves the input reached the query unsanitized, not necessarily that it's exploitable)
- **Reflected XSS** — confirms only if a payload containing a fresh per-run random token comes back **unescaped and verbatim** in the response. This rules out the classic false-positive trap of "the payload string shows up somewhere" (e.g. inside an error message) counting as a hit.
- **Local File Inclusion** — confirms via actual content-pattern matching against real `/etc/passwd` output (`root:.*:0:0:`), not "response changed" or "status 200" — both of which are unreliable signals on their own.
- **Default credential check** (bonus) — attempts a short list of common credential pairs against a login form using a persistent `requests.Session()`, scraping any CSRF token present on the login page fresh before each attempt. Confirms success via the genuine *absence* of the target's known login-failure string from the response, not status code alone (login pages frequently return 200 on both success and failure).

### Real engineering problems found and fixed during testing

Two of these came from testing against a real target rather than assuming request behavior would "just work":

- **Form submission requires more than the payload param.** DVWA's SQLi page silently no-ops without a `Submit=Submit` parameter alongside the injected field — confirmed by comparing raw `curl` requests with and without it. Added `extra_params` support to the detector so any static form fields (submit buttons, hidden tokens) can be passed alongside the payload.
- **Multi-cookie targets need a raw cookie header, not a single session ID.** DVWA gates content behind *two* cookies (`PHPSESSID` and `security`), so a dict keyed to one cookie name silently fails authentication. Switched `--cookie` to accept a raw `Cookie:` header string copied straight from devtools instead.

### Security-level evasion testing (DVWA low / medium / high)

Ran all three core detectors against DVWA at each security tier to see what survives basic filtering — real evidence, not assumption, in every case below:

+----------+----------------------------+------------------------+------------+------------------------------------------+
| Detector | Low                        | Medium                 | High       | Why                                       |
+----------+----------------------------+------------------------+------------+------------------------------------------+
| SQLi     | confirmed                  | blocked                | blocked    | quote escaping blocks breakout entirely   |
| XSS      | confirmed                  | confirmed (bypass)     | confirmed  | filter blacklists <script> tag only       |
| LFI      | confirmed (traversal+path) | confirmed (path only)  | blocked    | medium blocks traversal, not bare path;   |
|          |                            |                        |            | high switches to a whitelist              |
+----------+----------------------------+------------------------+------------+------------------------------------------+

**Traversal depth is install-specific and was found empirically, not assumed.** The originally-assumed depth (4 levels of `../`) never worked on this install at *any* security level — not because of filtering, but because this DVWA deployment sits 6 directory levels below filesystem root. Confirmed via a depth-sweep (1–6) cross-checked against Apache's error log, which showed the literal path PHP attempted to `include()` at each depth. `LFI_PAYLOADS` now sweeps depths 4–8 to improve the odds of landing on the right depth on a different install, though a fully dynamic depth-detection pass would be the more robust fix (tracked as a known limitation, not yet built).

**Lesson worth calling out:** none of DVWA's XSS or LFI filters were defeated by a clever encoding trick — they were defeated by the filter's *scope* being narrower than the actual attack surface (blacklisting one tag, or one traversal pattern, while leaving an equally valid alternate route completely uncovered). This matters more for the detector's design than any single bypass: real-world WAFs and input filters fail the same way far more often than they fail to a sophisticated payload.

## Usage

```bash
# Full recon
python3 main.py recon --target example.com

# Include Google dork generation
python3 main.py recon --target example.com --dorks

# Port scan
python3 main.py scan --target 192.168.1.10 --ports 1-1000

# Vulnerability scan (SQLi + XSS + LFI against a single param)
python3 main.py vuln --target "http://localhost/dvwa/vulnerabilities/sqli/" --param id \
  --cookie "PHPSESSID=xxx; security=low" --extra-params "Submit=Submit"

# Default credential check against a login page
python3 main.py vuln --target "http://localhost/dvwa/login.php" --param unused --check-creds

# Payload generation (Phase 4, not yet implemented)
python3 main.py payload --type reverse_shell --lhost 10.0.0.5 --lport 4444 --lang python

# Report generation (Phase 5, not yet implemented)
python3 main.py report --target example.com
```

## Setup

```bash
git clone https://github.com/Mehtazcode/PhantomStrike.git
cd PhantomStrike
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py --help
```

Optional environment variables:

```bash
export SHODAN_API_KEY="your_key_here"      # enables shodan_search()
export ANTHROPIC_API_KEY="your_key_here"   # enables AI-assisted reporting (Phase 5, planned)
```

## Architecture

PhantomStrike/
├── main.py # CLI entry point (argparse)
├── phantomstrike/
│ ├── core/ # config, banner
│ ├── recon/ # Phase 1 - ReconEngine
│ ├── scanner/ # Phase 2 - PortScanner
│ ├── vuln/ # Phase 3 - VulnDetector
│ ├── payload/ # Phase 4 - PayloadGenerator
│ ├── report/ # Phase 5 - ReportGenerator
│ └── utils/ # shared logger
├── data/wordlists/
├── output/ # JSON results and PDF reports (gitignored)
└── learning_exercises/ # raw socket fundamentals exercises

## About

Built by Pratham, final-year B.Tech Computer Engineering student, as a portfolio project for penetration testing roles.

This is a work in progress, built at ~1–2 hours/day. Follow along for updates as each phase ships.
