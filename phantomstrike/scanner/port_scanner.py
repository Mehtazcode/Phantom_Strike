"""
scanner/port_scanner.py — PHASE 2 (Weeks 8-12)

TCP connect scan (nmap -sT style) — full three-way handshake, no root
required. Raw SYN scan (half-open, -sS style) is a tracked upgrade for
a later pass; this MVP proves the pipeline (threaded scan -> banner
grab -> service detect -> save) works end to end first.
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
    BANNER_GRAB_TIMEOUT,
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
        Single-port TCP connect scan.
        connect_ex() instead of connect() -- returns an errno instead of
        raising, cheaper to check across hundreds of ports in a loop.
        On open ports we keep the socket alive for grab_banner() and
        stash it under "_sock" (popped before results are saved to JSON).
        """
        result = {"port": port, "status": "closed", "banner": None}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_GRAB_TIMEOUT)

        try:
            err = sock.connect_ex((self.target, port))
            result["status"] = "open" if err == 0 else "closed"
        except socket.timeout:
            result["status"] = "filtered"
        except socket.gaierror:
            logger.error(f"Could not resolve target: {self.target}")
            result["status"] = "error"
        except OSError as e:
            logger.warning(f"Port {port} scan error: {e}")
            result["status"] = "error"

        if result["status"] == "open":
            result["banner"] = self.grab_banner(sock, port)
            result["service"] = self.detect_service(port, result["banner"])
        else:
            sock.close()

        return result

    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Read whatever bytes the service sends unprompted (SSH/FTP/SMTP
        do this). HTTP-like ports stay silent until spoken to, so send
        a HEAD request first for those.
        """
        banner = ""
        try:
            sock.settimeout(BANNER_GRAB_TIMEOUT)

            if port in (80, 443, 8080, 8000, 8443):
                request = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                sock.sendall(request)

            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
        except (socket.timeout, OSError):
            banner = ""
        finally:
            sock.close()

        return banner

    def detect_service(self, port: int, banner: str) -> str:
        """
        Pattern-match the banner first (more reliable than port number
        alone -- services get moved to nonstandard ports constantly in
        real engagements). Falls back to well-known port mapping.
        """
        fallback_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 8080: "HTTP-Proxy",
        }

        if banner:
            b = banner.lower()
            if "ssh" in b:
                parts = banner.split("-", 2)
                if len(parts) >= 3:
                    version = parts[2].split()[0].replace("_", " ")
                    return f"SSH ({version})"
                return "SSH"
            if b.startswith("http/") or "server:" in b:
                for line in banner.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                return "HTTP"
            if "ftp" in b:
                return "FTP"
            if "smtp" in b or "mail" in b:
                return "SMTP"

        return fallback_map.get(port, "unknown")

    def scan_range(self) -> list:
        """
        Threaded scan across self.ports. Open ports get banner-grabbed
        and service-detected before being added to results.
        """
        results = []
        with ThreadPoolExecutor(max_workers=DEFAULT_THREAD_COUNT) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda r: r["port"])
        return results

    def run(self) -> list:
        """
        Orchestrates the scan and saves results to output/.
        """
        logger.info(f"Starting port scan against {self.target}")

        self.results = self.scan_range()

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        out_path = os.path.join(OUTPUT_DIR, f"scan_{self.target}.json")
        with open(out_path, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.success(f"Scan results saved to {out_path}")
        return self.results
