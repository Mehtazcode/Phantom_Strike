"""
PhantomStrike — Learning Exercise 02
Simple Port Checker

GOAL: Check whether a single port on a target is open, closed, or
filtered, using nothing but raw sockets. This is the absolute seed of
the multi-threaded scanner you'll build in Phase 2 — get this single-
port version solid first.

SAFE TARGET: scanme.nmap.org. Ports 22 and 80 are intentionally left
open by the Nmap project for testing.

Run:
    python 02_simple_port_checker.py
"""

import socket
import time


def check_port(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    Now returns a dict instead of a string so we can carry banner info.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = ""

    try:
        result = sock.connect_ex((host, port))

        if result == 0:
            # Port is open — now try to read whatever the service sends first
            try:
                sock.settimeout(1.5)  # shorter timeout just for the banner read
                banner_bytes = sock.recv(1024)
                banner = banner_bytes.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                # Service didn't send anything automatically (e.g. HTTP doesn't)
                # That's fine — we just get no banner
                banner = ""
            return {"status": "open", "banner": banner}
        else:
            return {"status": "closed", "banner": ""}

    except socket.timeout:
        return {"status": "filtered", "banner": ""}
    except socket.error:
        return {"status": "filtered", "banner": ""}
    finally:
        sock.close()


def main():
    target_host = "scanme.nmap.org"
    ports_to_check = [22, 80, 443, 8080, 31337]

    print(f"[*] Checking ports on {target_host}\n")

    for port in ports_to_check:
        start = time.time()
        result = check_port(target_host, port)
        elapsed = time.time() - start

        banner_display = f"| {result['banner'][:50]}" if result['banner'] else ""
        print(f"  Port {port:<6} → {result['status']:<10} ({elapsed:.2f}s) {banner_display}")
if __name__ == "__main__":
    main()
