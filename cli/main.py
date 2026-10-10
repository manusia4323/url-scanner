"""Main CLI entry point for URL Scanner."""

from typing import Optional
from pathlib import Path

import typer
from rich.console import Console
from rich import print as rprint

from cli import __version__
from cli.commands import scan, blacklist, logs, system

# Create main Typer app
app = typer.Typer(
    name="scanner",
    help="URL Security Scanner CLI - Scan URLs for security threats from the command line",
    epilog="Run 'scanner COMMAND --help' for more information on a command.",
    no_args_is_help=True,
    add_completion=True,
)

# Create console for output
console = Console()


# Add subcommand groups
app.add_typer(scan.app, name="scan")
app.add_typer(blacklist.app, name="blacklist")
app.add_typer(logs.app, name="logs")
app.add_typer(system.app, name="system")


# Version command
@app.command()
def version():
    """Show version and exit."""
    console.print(f"[bold green]URL Scanner CLI[/bold green] version {__version__}")
    raise typer.Exit(0)


# Quick scan shortcuts (aliases)
@app.command("quick", hidden=True)
def quick_scan(
    url: str = typer.Argument(..., help="URL to scan"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
):
    """
    Quick scan (alias for 'scan --mode normal').
    """
    from cli.commands.scan import scan_command
    scan_command(urls=[url], mode="normal", output=output, api_url=api_url)


# Register convenience aliases at top level
# These allow: scanner URL, scanner -A URL, scanner -P URL, scanner -N URL
@app.command("passive", hidden=True)
def passive_scan(
    url: str = typer.Argument(..., help="URL to scan"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
):
    """
    Passive scan (alias for 'scan --mode passive').
    """
    from cli.commands.scan import scan_command
    scan_command(urls=[url], mode="passive", output=output, api_url=api_url)


@app.command("aggressive", hidden=True)
def aggressive_scan(
    url: str = typer.Argument(..., help="URL to scan"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
):
    """
    Aggressive scan (alias for 'scan --mode aggressive').
    """
    from cli.commands.scan import scan_command
    scan_command(urls=[url], mode="aggressive", output=output, yes=yes, api_url=api_url)


# Custom command routing for short flags
# This handles: scanner -A URL, scanner -P URL, scanner -N URL
def main():
    """Main entry point with custom argument handling."""
    import sys

    # Check for shorthand flags
    if len(sys.argv) > 1:
        # Handle -A (aggressive), -P (passive), -N (normal)
        if sys.argv[1] == "-A":
            sys.argv[1] = "aggressive"
        elif sys.argv[1] == "-P":
            sys.argv[1] = "passive"
        elif sys.argv[1] == "-N":
            sys.argv[1] = "scan"
            sys.argv.insert(2, "--mode")
            sys.argv.insert(3, "normal")
        # Handle direct URL (no subcommand)
        elif sys.argv[1].startswith(("http://", "https://")):
            # Insert 'scan' command before the URL
            sys.argv.insert(1, "scan")

    # Run the app
    app()


if __name__ == "__main__":
    main()