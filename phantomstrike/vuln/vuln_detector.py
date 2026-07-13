"""
vuln/vuln_detector.py — PHASE 3 (Weeks 13-18)

This is the heart of PhantomStrike. Build ONE detector at a time, test
it fully against DVWA before starting the next. Don't try to build all
three simultaneously — that's how this phase stalls out.

Build order (matches your roadmap, and your existing DVWA experience):
  1. detect_sqli()   — Week 13-15 (you know this best from your internship)
  2. detect_xss()    — Week 16-17
  3. detect_lfi()    — Week 17-18
  4. check_default_creds() — bonus, if time allows

Test target: your local DVWA instance. Set security level to "low"
first to confirm detection logic works, then try "medium" once your
detectors are solid — DVWA's medium level filters basic payloads, which
will teach you a lot about payload evasion.
"""

import json
import os
import requests
from phantomstrike.core.config import OUTPUT_DIR
from phantomstrike.utils import logger


# Common SQLi test payloads — start here, expand as you learn more
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR SLEEP(5)--",
    "\" OR \"1\"=\"1",
]

# Common XSS test payloads
XSS_PAYLOADS = [
    "<script>alert('phantomstrike')</script>",
    "\"><script>alert('phantomstrike')</script>",
    "<img src=x onerror=alert('phantomstrike')>",
]

# Common LFI test payloads (Linux targets)
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
]


class VulnDetector:
    def __init__(self, target_url: str, session_cookie: str = None):
        self.target_url = target_url
        self.session_cookie = session_cookie  # needed for authenticated DVWA testing
        self.findings = []

    def detect_sqli(self, param_name: str) -> list:
        """
        TODO (Week 13-15):
        - For each payload in SQLI_PAYLOADS, send a request to
          self.target_url with param_name set to that payload.
        - ERROR-BASED detection: check if the response contains SQL
          error strings ("you have an error in your sql syntax",
          "mysql_fetch", "ORA-", "SQLite error", etc.) — build a small
          list of these signatures.
        - TIME-BASED detection: for the "SLEEP(5)" payload, measure
          response time. If it takes 5+ seconds, that's strong evidence
          of blind SQLi even with no visible error.
        - For each confirmed finding, append a dict to self.findings:
          {"type": "SQLi", "param": param_name, "payload": payload,
           "severity": "high", "evidence": "..."}
        - Use logger.finding("high", "...") to print as you find things.

        Reference for sending requests with cookies:
          requests.get(url, params={param_name: payload},
                        cookies={"PHPSESSID": self.session_cookie})
        """
        logger.warning("detect_sqli() not implemented — Phase 3, start here")
        raise NotImplementedError("Build this in Phase 3, Weeks 13-15")

    def detect_xss(self, param_name: str) -> list:
        """
        TODO (Week 16-17):
        - For each payload in XSS_PAYLOADS, send it as param_name.
        - Check if the EXACT payload string appears unescaped/unencoded
          in the response body. If your <script> tag comes back as
          &lt;script&gt; the server is encoding it — not vulnerable. If
          it comes back as <script> verbatim — vulnerable (reflected XSS).
        - This is "reflected XSS" detection only — stored XSS (where you
          submit a payload, then check a DIFFERENT page later) is a
          stretch goal, you'll need to understand DVWA's persistent
          storage to test for it.
        """
        logger.warning("detect_xss() not implemented — Phase 3")
        raise NotImplementedError("Build this in Phase 3, Weeks 16-17")

    def detect_lfi(self, param_name: str) -> list:
        """
        TODO (Week 17-18):
        - For each payload in LFI_PAYLOADS, send it as param_name.
        - Check if the response contains telltale /etc/passwd content
          like "root:x:0:0:" — that string appearing means you
          successfully read a system file through path traversal.
        - This confirms the vulnerability AND demonstrates real impact,
          which is exactly what a report needs evidence for.
        """
        logger.warning("detect_lfi() not implemented — Phase 3")
        raise NotImplementedError("Build this in Phase 3, Weeks 17-18")

    def check_default_creds(self, login_url: str, creds_list: list = None) -> list:
        """
        TODO (bonus, if time allows):
        - Try a small list of common default credential pairs
          (admin/admin, admin/password, root/root, etc.) against a
          login form using `requests.post()`.
        - Detect success by checking for a redirect, a cookie being set,
          or absence of a "login failed" string in the response.
        - Keep this list SHORT and only test against systems you own —
          this is functionally a brute force attack.
        """
        logger.warning("check_default_creds() not implemented — optional, Phase 3")
        raise NotImplementedError("Optional — build if time allows")

    def run_all(self, param_name: str) -> list:
        """
        Orchestrates all detectors against a single parameter and saves
        results. Call this once each detector above is implemented.
        """
        logger.info(f"Starting vulnerability scan against {self.target_url}")

        for detector in (self.detect_sqli, self.detect_xss, self.detect_lfi):
            try:
                self.findings.extend(detector(param_name))
            except NotImplementedError:
                pass

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_name = self.target_url.replace("://", "_").replace("/", "_")
        out_path = os.path.join(OUTPUT_DIR, f"vuln_{safe_name}.json")
        with open(out_path, "w") as f:
            json.dump(self.findings, f, indent=2)

        logger.success(f"Vulnerability findings saved to {out_path}")
        return self.findings
