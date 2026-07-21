"""
core/config.py

Central place for constants used across modules. As you build each
phase, add config values here instead of hardcoding them inside
individual modules — this is what real frameworks do, and it makes
the tool configurable later (e.g. via a config file or env vars)
without rewriting module internals.
"""

import os

# Project root — used to build absolute paths to data/ and output/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
WORDLIST_DIR = os.path.join(DATA_DIR, "wordlists")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

# Networking defaults — tune these as you build Phase 2's threaded scanner
DEFAULT_SOCKET_TIMEOUT = 2.0
BANNER_GRAB_TIMEOUT = 15.0  # some services (Telnet/SMTP on Metasploitable) do ident/reverse-DNS lookups before greeting
DEFAULT_THREAD_COUNT = 50

# HTTP request timeout for Phase 3's requests-based vuln checks (SQLi/XSS/LFI).
# Kept separate from the socket timeouts above -- those time raw TCP connects,
# this times full HTTP request/response round-trips over `requests`, and must
# be long enough to let a SLEEP(5) time-based SQLi payload actually complete
# (see vuln_detector.py detect_sqli()).
# Bumped from 10.0 -- too tight against detect_sqli()'s SLEEP(5)
# time-based payload once DB scheduling + network overhead is added;
# confirmed via a real timeout during DVWA testing (Phase 3).
HTTP_REQUEST_TIMEOUT = 20.0

# Top 100 most common ports — a reasonable default scan range before you
# implement full 1-65535 scanning. Extend this list as you learn which
# ports matter for which services.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
]

# Shodan API key — set this as an environment variable, never hardcode it
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
