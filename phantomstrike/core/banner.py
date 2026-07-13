"""
core/banner.py

Displays the PhantomStrike startup banner. Trivial module, but every
serious CLI security tool (Metasploit, SQLMap, etc.) has one — it's a
small thing that makes the tool feel finished and professional.
"""

from rich.console import Console

console = Console()

BANNER = r"""
[bold magenta]
 ____  _                 _              ____  _        _ _
|  _ \| |__   __ _ _ __ | |_ ___  _ __ / ___|| |_ _ __(_) | _____
| |_) | '_ \ / _` | '_ \| __/ _ \| '_ \\___ \| __| '__| | |/ / _ \
|  __/| | | | (_| | | | | || (_) | | | |___) | |_| |  | |   <  __/
|_|   |_| |_|\__,_|_| |_|\__\___/|_| |_|____/ \__|_|  |_|_|\_\___|
[/bold magenta]
[dim]  Modular Automated Red Team Framework — v0.1 (Phase 0)[/dim]
"""


def show_banner():
    console.print(BANNER)
    console.print(
        "[yellow]Only use against systems you own or have explicit "
        "permission to test.[/yellow]\n"
    )
