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

# Top 100 most common ports — a reasonable default scan range before you
# implement full 1-65535 scanning. Extend this list as you learn which
# ports matter for which services.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
]

# Shodan API key — set this as an environment variable, never hardcode it
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
