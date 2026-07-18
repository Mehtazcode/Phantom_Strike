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
    ____  __                __                 _____ __       _ __      
   / __ \/ /_  ____ _____  / /_____  ____ ___ / ___// /______(_) /_____ 
  / /_/ / __ \/ __ `/ __ \/ __/ __ \/ __ `__ \\__ \/ __/ ___/ / //_/ _ \
 / ____/ / / / /_/ / / / / /_/ /_/ / / / / / /__/ / /_/ /  / / ,< /  __/
/_/   /_/ /_/\__,_/_/ /_/\__/\____/_/ /_/ /_/____/\__/_/  /_/_/|_|\___/
[/bold magenta]
[dim]  Modular Automated Red Team Framework — v0.1 (Phase 0)[/dim]
"""


def show_banner():
    console.print(BANNER)
    console.print(
        "[yellow]Only use against systems you own or have explicit "
        "permission to test.[/yellow]\n"
    )
