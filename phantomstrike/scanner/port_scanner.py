"""
scanner/port_scanner.py — PHASE 2 (Weeks 8-12)

This is where learning_exercises/02_simple_port_checker.py grows up.
You already proved the single-port logic works in Phase 0 — this
module's job is to make it fast (threaded) and useful (banner grabbing
+ service detection), then wrap it in a reusable class.

Build order:
  1. scan_port()        — basically your Phase 0 exercise, moved here
  2. grab_banner()       — read the first bytes a service sends
  3. scan_range()        — threaded scan across many ports
  4. detect_service()    — match banners against known patterns
"""

import socket
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from phantomstrike.core.config import (
    DEFAULT_SOCKET_TIMEOUT,
    DEFAULT_THREAD_COUNT,
    COMMON_PORTS,
    OUTPUT_DIR,
)
from phantomstrike.utils import logger


class PortScanner:
    def __init__(self, target: str, ports: list = None, timeout: float = DEFAULT_SOCKET_TIMEOUT):
        self.target = target
        self.ports = ports if ports else COMMON_PORTS
        self.timeout = timeout
        self.results = []

    def scan_port(self, port: int) -> dict:
        """
        TODO (Week 8):
        - This is your learning_exercises/02_simple_port_checker.py
          check_port() function, adapted to return a richer dict instead
          of just a string:
          {"port": port, "status": "open"/"closed"/"filtered", "banner": None}
        - Copy your working logic over from the exercise, don't rewrite
          from scratch — the point of Phase 0 was to build this once.
        """
        logger.warning("scan_port() not implemented — copy logic from Phase 0 exercise")
        raise NotImplementedError("Build this in Phase 2, Week 8")

    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        TODO (Week 9):
        - After confirming a port is open, try to read whatever bytes
          the service sends without prompting (many services like SSH,
          FTP, and SMTP send a banner immediately on connect — you saw
          this hinted at in exercise 01's "EXERCISE FOR YOU" section).
        - For HTTP-like ports (80, 443, 8080), you'll need to actually
          SEND a basic GET request first (reuse logic from exercise 01)
          before you get anything back — HTTP servers don't send banners
          unprompted.
        - Wrap in try/except since not every port will respond the same
          way; a banner grab can legitimately time out.
        - Return the banner as a decoded string (or empty string if none).
        """
        logger.warning("grab_banner() not implemented — Phase 2")
        raise NotImplementedError("Build this in Phase 2, Week 9")

    def detect_service(self, port: int, banner: str) -> str:
        """
        TODO (Week 10):
        - Build a small dictionary mapping common ports to expected
          service names as a fallback: {21: "FTP", 22: "SSH", 80: "HTTP", ...}
        - Then improve on that fallback by pattern-matching the banner
          string itself (e.g. if "SSH-2.0" appears in the banner, you
          know it's SSH regardless of port — services aren't always on
          their "default" port in real engagements).
        - Return your best guess as a string, e.g. "OpenSSH 8.2".
        """
        logger.warning("detect_service() not implemented — Phase 2")
        raise NotImplementedError("Build this in Phase 2, Week 10")

    def scan_range(self) -> list:
        """
        TODO (Week 11-12):
        - This is the big one: use ThreadPoolExecutor (imported above)
          with DEFAULT_THREAD_COUNT workers to call scan_port() across
          self.ports concurrently instead of sequentially.
        - Pattern to follow:

            with ThreadPoolExecutor(max_workers=DEFAULT_THREAD_COUNT) as executor:
                futures = {executor.submit(self.scan_port, p): p for p in self.ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result["status"] == "open":
                        result["banner"] = self.grab_banner(...)
                        result["service"] = self.detect_service(...)
                    self.results.append(result)

        - Time this against your Phase 0 sequential version on the same
          target — this comparison is the actual "aha" moment of Phase 2.
          Write the before/after numbers down, they're great interview
          talking points.
        """
        logger.warning("scan_range() not implemented — Phase 2")
        raise NotImplementedError("Build this in Phase 2, Weeks 11-12")

    def run(self) -> list:
        """
        Orchestrates the scan and saves results to output/.
        Once scan_range() works, this should just function.
        """
        logger.info(f"Starting port scan against {self.target}")

        self.results = self.scan_range()

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        out_path = os.path.join(OUTPUT_DIR, f"scan_{self.target}.json")
        with open(out_path, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.success(f"Scan results saved to {out_path}")
        return self.results
