#!/usr/bin/env python3
"""
PhantomStrike — main.py
CLI entry point. Dispatches to each module based on the subcommand.

Usage:
    python main.py recon --target example.com
    python main.py scan --target 192.168.1.10 --ports 1-1000
    python main.py vuln --target http://localhost/dvwa --param id
    python main.py payload --type reverse_shell --lhost 10.0.0.5 --lport 4444 --lang python
    python main.py report --target example.com

As you build out each phase, the corresponding subcommand here will
start actually working. Right now, every subcommand runs but the
underlying module methods raise NotImplementedError with guidance on
what to build next — that's intentional, it's your TODO list made
executable.
"""

import argparse
from phantomstrike.core.banner import show_banner
from phantomstrike.utils import logger


def cmd_recon(args):
    from phantomstrike.recon.recon_engine import ReconEngine
    engine = ReconEngine(args.target)
    engine.run_all(run_dorks=args.dorks)


def cmd_scan(args):
    from phantomstrike.scanner.port_scanner import PortScanner

    ports = None
    if args.ports:
        # supports "1-1000" or "22,80,443"
        if "-" in args.ports:
            start, end = args.ports.split("-")
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(p) for p in args.ports.split(",")]

    scanner = PortScanner(args.target, ports=ports)
    results = scanner.run()

    open_ports = [r for r in results if r["status"] == "open"]
    if open_ports:
        logger.success(f"Found {len(open_ports)} open port(s):")
        for r in open_ports:
            service = r.get("service", "unknown")
            banner = r.get("banner", "")
            preview = f" -- {banner[:60]}" if banner else ""
            logger.info(f"  {r['port']}/tcp  {service}{preview}")
    else:
        logger.warning("No open ports found")


def cmd_vuln(args):
    from phantomstrike.vuln.vuln_detector import VulnDetector
    detector = VulnDetector(args.target, session_cookie=args.cookie)
    detector.run_all(args.param)


def cmd_payload(args):
    from phantomstrike.payload.payload_gen import PayloadGenerator
    generator = PayloadGenerator(args.lhost, args.lport)
    payload = generator.generate(args.lang, encode=args.encode)
    print(payload)


def cmd_report(args):
    from phantomstrike.report.report_gen import ReportGenerator
    generator = ReportGenerator(args.target)
    generator.generate(output_path=args.output)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="phantomstrike",
        description="PhantomStrike — Modular Automated Red Team Framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # recon
    p_recon = subparsers.add_parser("recon", help="Run recon module against a target domain")
    p_recon.add_argument("--target", required=True, help="Target domain, e.g. example.com")
    p_recon.add_argument("--dorks", action="store_true", help="Also generate Google dork queries for this target")
    p_recon.set_defaults(func=cmd_recon)

    # scan
    p_scan = subparsers.add_parser("scan", help="Run port scanner against a target host")
    p_scan.add_argument("--target", required=True, help="Target IP or hostname")
    p_scan.add_argument("--ports", default=None, help="e.g. 1-1000 or 22,80,443")
    p_scan.set_defaults(func=cmd_scan)

    # vuln
    p_vuln = subparsers.add_parser("vuln", help="Run vulnerability detector against a target URL")
    p_vuln.add_argument("--target", required=True, help="Full target URL, e.g. http://localhost/dvwa")
    p_vuln.add_argument("--param", required=True, help="Parameter name to test, e.g. id")
    p_vuln.add_argument("--cookie", default=None, help="Session cookie for authenticated testing (DVWA etc.)")
    p_vuln.set_defaults(func=cmd_vuln)

    # payload
    p_payload = subparsers.add_parser("payload", help="Generate a reverse shell payload")
    p_payload.add_argument("--type", default="reverse_shell", choices=["reverse_shell"])
    p_payload.add_argument("--lhost", required=True, help="Attacker listener IP")
    p_payload.add_argument("--lport", required=True, type=int, help="Attacker listener port")
    p_payload.add_argument("--lang", required=True, choices=["bash", "python", "powershell", "php", "perl"])
    p_payload.add_argument("--encode", default=None, choices=["base64", "url"])
    p_payload.set_defaults(func=cmd_payload)

    # report
    p_report = subparsers.add_parser("report", help="Generate a PDF report from saved JSON results")
    p_report.add_argument("--target", required=True, help="Target name used to find saved JSON results")
    p_report.add_argument("--output", default=None, help="Output PDF path")
    p_report.set_defaults(func=cmd_report)

    return parser


def main():
    show_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except NotImplementedError as e:
        logger.error(f"This module isn't built yet: {e}")
        logger.info("Check the module's docstrings for what to implement next.")


if __name__ == "__main__":
    main()
