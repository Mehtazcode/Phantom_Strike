# PhantomStrike

A modular, automated red team framework built from scratch in Python — using raw sockets and raw HTTP instead of wrapping existing tools like Nmap or SQLMap. Built to understand offensive security tooling at the protocol level, not just to use it.

> ⚠️ **Authorized testing only.** This tool is built and tested exclusively against systems I own or have explicit permission to test: DVWA, Metasploitable, and `scanme.nmap.org`.

## Why raw sockets?

Most student pentest projects wrap Nmap, SQLMap, or Metasploit behind a CLI. PhantomStrike doesn't — the scanner, recon engine, and payload generator are built directly on Python's socket and `requests` libraries. The point isn't to outperform mature tools; it's to demonstrate real understanding of what those tools are doing underneath: TCP handshakes, HTTP request construction, banner parsing, timeout/RST behavior, and so on.

## Pipeline
Recon → Port Scanner → Vulnerability Detector → Payload Generator → Report Generator

Each phase is a standalone module that can also run independently via the CLI.

## Status

| Phase | Module              | Status         |
|-------|----------------------|----------------|
| 0     | Foundation            | ✅ Done |
| 1     | Recon Engine           | ✅ Done |
| 2     | Port Scanner           | 🔄 In progress |
| 3     | Vulnerability Detector | ⬜ Not started |
| 4     | Payload Generator      | ⬜ Not started |
| 5     | Report Generator       | ⬜ Not started |
| 6     | Integration & polish   | ⬜ Not started |

## Phase 1 — Recon Engine

- **Subdomain enumeration**: wordlist brute-force + DNS resolution, multi-threaded via `ThreadPoolExecutor`
- **Certificate Transparency lookup**: passive OSINT via crt.sh, merged with wordlist results before resolution. Includes retry logic and graceful degradation — crt.sh is a free public service with known reliability issues (confirmed during development: observed timeouts, 502s, and 404s across consecutive runs), so the tool falls back to wordlist-only results rather than failing the whole recon run.
- **WHOIS lookup**: registrar and domain metadata via `python-whois`
- **Shodan search**: optional, gated behind a `SHODAN_API_KEY` environment variable — the tool works fully without it
- **Google dork generation**: passive-only, generates ready-to-use dork query strings across 6 categories (exposed files, admin panels, directory listings, config/backup leaks, error pages, subdomain discovery). Gated behind an explicit `--dorks` flag so it doesn't run on every recon call.

## Usage

```bash
# Full recon
python3 main.py recon --target example.com

# Include Google dork generation
python3 main.py recon --target example.com --dorks

# Port scan (Phase 2, in progress)
python3 main.py scan --target 192.168.1.10 --ports 1-1000

# Vulnerability scan (Phase 3, not yet implemented)
python3 main.py vuln --target http://localhost/dvwa --param id

# Payload generation (Phase 4, not yet implemented)
python3 main.py payload --type reverse_shell --lhost 10.0.0.5 --lport 4444 --lang python

# Report generation (Phase 5, not yet implemented)
python3 main.py report --target example.com
```

## Setup

```bash
git clone https://github.com/<your-username>/PhantomStrike.git
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
```
PhantomStrike/
├── main.py                     # CLI entry point (argparse)
├── phantomstrike/
│   ├── core/                   # config, banner
│   ├── recon/                  # Phase 1 - ReconEngine
│   ├── scanner/                # Phase 2 - PortScanner
│   ├── vuln/                   # Phase 3 - VulnDetector
│   ├── payload/                # Phase 4 - PayloadGenerator
│   ├── report/                 # Phase 5 - ReportGenerator
│   └── utils/                  # shared logger
├── data/wordlists/
├── output/                     # JSON results and PDF reports (gitignored)
└── learning_exercises/         # raw socket fundamentals exercises

```
## About

Built by Pratham, final-year B.Tech Computer Engineering student, as a portfolio project for penetration testing roles.

This is a work in progress, built at ~1–2 hours/day. Follow along for updates as each phase ships.
