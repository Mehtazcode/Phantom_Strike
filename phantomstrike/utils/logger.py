"""
utils/logger.py

A tiny shared logging helper so every module prints output in a
consistent style (instead of everyone calling print() differently).
Uses `rich` for color-coded severity levels, which also doubles as
your first exposure to building "tool-grade" CLI output instead of
plain print statements.
"""

from rich.console import Console

console = Console()


def info(message: str):
    console.print(f"[cyan][*][/cyan] {message}")


def success(message: str):
    console.print(f"[green][+][/green] {message}")


def warning(message: str):
    console.print(f"[yellow][!][/yellow] {message}")


def error(message: str):
    console.print(f"[red][-][/red] {message}")


def finding(severity: str, message: str):
    """
    Used by the vuln detector (Phase 3) to log confirmed findings with
    a severity tag, matching the style of professional pentest tools.
    severity should be one of: "critical", "high", "medium", "low", "info"
    """
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = colors.get(severity.lower(), "white")
    console.print(f"[{color}][{severity.upper()}][/{color}] {message}")
