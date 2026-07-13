"""
PhantomStrike — Learning Exercise 01
Raw Socket HTTP GET Request

GOAL: Understand what `requests.get(url)` is actually doing under the hood
by building it yourself with nothing but Python's built-in `socket` module.

Why this matters: every module you build later (scanner, vuln detector)
is fundamentally just "open a socket, send bytes, read bytes". If you
understand this script completely, the rest of the project gets much
easier to reason about.

SAFE TARGET: scanme.nmap.org is explicitly provided by the Nmap project
for testing tools like this one. It is legal and safe to connect to.
Do not point this at anything else without permission.

Run:
    python 01_raw_socket_http_get.py
"""

import socket


def raw_http_get(host: str, port: int = 80, path: str = "/", timeout: float = 5.0) -> str:
    """
    Manually performs an HTTP GET request over a raw TCP socket.

    Step by step, this is what `requests.get()` hides from you:
      1. Resolve the hostname to an IP (DNS).
      2. Open a TCP connection (the 3-way handshake — SYN, SYN-ACK, ACK —
         is handled by the OS, but socket.connect() triggers it).
      3. Build the raw HTTP request as a string, following HTTP/1.1 spec.
      4. Encode it to bytes and send it over the socket.
      5. Read the raw bytes that come back and decode them.
      6. Close the connection.
    """

    # Step 1 & 2 — create a TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
    # and connect to host:port. This is the same socket() + connect()
    # pair that's happening under the hood in every networking tool
    # you've ever used.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))

    # Step 3 — build the raw HTTP/1.1 request manually.
    # Note the exact formatting: method, path, HTTP version, then headers,
    # then a BLANK LINE (\r\n\r\n) which tells the server "headers are done,
    # this is the end of the request". Get this wrong and servers will
    # either hang waiting for more data or reject the request outright.
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: PhantomStrike-LearningExercise/0.1\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    # Step 4 — sockets send/receive bytes, not strings, so we encode.
    sock.sendall(request.encode("utf-8"))

    # Step 5 — read the response in chunks until the server closes the
    # connection (because we sent "Connection: close" above, it will).
    response_chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response_chunks.append(chunk)

    sock.close()  # Step 6

    raw_response = b"".join(response_chunks)
    return raw_response.decode("utf-8", errors="replace")


def main():
    target_host = "scanme.nmap.org"
    target_port = 80

    print(f"[*] Sending raw HTTP GET to {target_host}:{target_port}\n")

    response = raw_http_get(target_host, target_port, path="/")

    # Split the response into headers and body so it's readable.
    # HTTP responses are separated from their body by \r\n\r\n, same
    # rule as the request we built above.
    header_section, _, body_section = response.partition("\r\n\r\n")

    print("=" * 60)
    print("RAW RESPONSE HEADERS")
    print("=" * 60)
    print(header_section)

    print("\n" + "=" * 60)
    print("BODY (first 300 characters)")
    print("=" * 60)
    print(body_section[:300])

    # ---- EXERCISE FOR YOU ----
    # 1. Change `path` to "/this-page-does-not-exist" and observe the
    #    status code in the headers. This is exactly how vuln scanners
    #    detect things like directory listing or 404 behavior.
    # 2. Try connecting to port 22 (SSH) instead of 80 — what happens?
    #    (Hint: SSH servers send a banner immediately on connect, before
    #    you even send anything. This is the basis of "banner grabbing",
    #    which you'll build properly in Phase 2.)
    # 3. Try removing the "Connection: close" header and see how the
    #    behavior changes (you may need to add a timeout-based read loop
    #    instead of relying on the server closing the connection).


if __name__ == "__main__":
    main()
