"""
core/target_profile.py

Loads and validates a Target Profile -- a JSON file describing a
specific engagement's target: auth flow, endpoints, params to test,
and noise patterns to strip before diffing responses.

WHY THIS EXISTS: everything built in Phase 3 so far (field names,
single-param testing, query-string-only requests) was tuned to DVWA
specifically. A real pentester needs to point PhantomStrike at THEIR
target's actual shape without editing Python source. This is the
mechanism for that -- one JSON file per engagement, no code changes.

This module only loads and validates. It does not perform requests --
that stays in VulnDetector, which will accept a TargetProfile instance
(or fall back to legacy single --target/--param CLI args if no profile
is given, so existing DVWA workflows keep working unchanged).
"""

import json
from phantomstrike.utils import logger


class TargetProfileError(Exception):
    """Raised when a profile file is missing required fields or malformed."""
    pass


class Endpoint:
    """
    One testable endpoint within a target. test_params are the fields
    that get payloads injected into (one at a time); default_params
    supplies safe baseline values for every field on the request
    (including the ones being tested -- their baseline gets overwritten
    by the actual payload during a test, but a baseline value is still
    needed so the request is well-formed when OTHER fields are being
    tested and this one just needs to hold still).
    """
    def __init__(self, data: dict):
        self.url = data["url"]
        self.method = data.get("method", "GET").upper()
        self.body_type = data.get("body_type", "query")  # "query" | "json"
        self.test_params = data.get("test_params", [])
        self.default_params = data.get("default_params", {})
        self.extra_static_params = data.get("extra_static_params", {})

        if self.body_type not in ("query", "json"):
            raise TargetProfileError(
                f"Endpoint {self.url!r}: body_type must be 'query' or 'json', got {self.body_type!r}"
            )
        if not self.test_params:
            raise TargetProfileError(
                f"Endpoint {self.url!r}: test_params is empty -- nothing to test here"
            )
        missing_defaults = [p for p in self.test_params if p not in self.default_params]
        if missing_defaults:
            raise TargetProfileError(
                f"Endpoint {self.url!r}: test_params {missing_defaults} have no "
                f"corresponding default_params entry -- every test_param needs a "
                f"baseline value so the request stays well-formed"
            )

    def __repr__(self):
        return f"Endpoint(url={self.url!r}, method={self.method}, test_params={self.test_params})"


class AuthConfig:
    """
    Describes how to authenticate against this target -- either a
    static cookie string (matches the --cookie flow already built),
    or a full login flow (login_url + field_map + optional CSRF
    scraping) for check_default_creds()-style testing.
    """
    def __init__(self, data: dict):
        self.login_url = data.get("login_url")
        self.field_map = data.get("field_map", {})
        self.csrf_token = data.get("csrf_token", {"present": False})
        self.failure_string = data.get("failure_string")
        self.cookie = data.get("cookie")

    @property
    def has_login_flow(self) -> bool:
        return bool(self.login_url and self.field_map and self.failure_string)


class TargetProfile:
    """
    Top-level parsed profile. Load via TargetProfile.from_file(path).
    """
    def __init__(self, data: dict):
        if "target" not in data:
            raise TargetProfileError("Profile missing required 'target' field")
        if "endpoints" not in data or not data["endpoints"]:
            raise TargetProfileError("Profile missing required 'endpoints' field, or it's empty")

        self.target = data["target"]
        self.rate_limit_ms = data.get("rate_limit_ms", 0)
        self.auth = AuthConfig(data.get("auth", {}))
        self.endpoints = [Endpoint(e) for e in data["endpoints"]]
        self.noise_patterns = data.get("noise_patterns", [])

    @classmethod
    def from_file(cls, path: str) -> "TargetProfile":
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise TargetProfileError(f"Profile file not found: {path}")
        except json.JSONDecodeError as e:
            raise TargetProfileError(f"Profile file is not valid JSON: {e}")

        profile = cls(data)
        logger.success(
            f"Loaded profile for {profile.target} -- "
            f"{len(profile.endpoints)} endpoint(s), "
            f"rate limit {profile.rate_limit_ms}ms"
        )
        return profile
