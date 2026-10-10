"""System commands for health, version, and config."""

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cli import __version__
from cli.config import load_config, merge_config
from cli.client import APIClient, APIClientError


app = typer.Typer(help="System information and health checks")
console = Console()


@app.command("health")
def health_check(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Check API health status.

    Examples:
        scanner health
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        result = client.health_check()

        status = result.get("status", "unknown")
        db_status = result.get("db", "unknown")

        status_color = "green" if status == "ok" else "red"
        db_color = "green" if db_status == "ok" else "red"

        console.print(Panel(
            f"[{status_color}]API Status: {status.upper()}[/{status_color}]\n"
            f"[{db_color}]Database: {db_status.upper()}[/{db_color}]",
            title="🏥 Health Check",
            border_style=status_color,
        ))

    except APIClientError as e:
        console.print(Panel(
            f"[red]❌ API Unreachable[/red]\n\n"
            f"Error: {e}\n"
            f"API URL: {config.api_url}\n\n"
            f"[dim]Suggestions:[/dim]\n"
            f"  • Check if the API server is running\n"
            f"  • Verify the API URL is correct\n"
            f"  • Run 'uvicorn app.main:app' to start the server",
            title="🏥 Health Check Failed",
            border_style="red",
        ))
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("version")
def show_version(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Show CLI and API version information.

    Examples:
        scanner version
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    # Show CLI version
    console.print(Panel(
        f"[bold]CLI Version:[/bold] {__version__}",
        title="URL Scanner CLI",
        border_style="blue",
    ))

    # Try to get API version
    client = APIClient(config)

    try:
        # Try root endpoint for API info
        response = client.client.get("/")
        if response.status_code == 200:
            data = response.json()
            api_version = data.get("version", "unknown")

            console.print(Panel(
                f"[bold]API Version:[/bold] {api_version}\n"
                f"[bold]API URL:[/bold] {config.api_url}",
                title="URL Scanner API",
                border_style="green",
            ))
    except Exception:
        console.print("[dim]API version could not be retrieved (API may not be running)[/dim]")
    finally:
        client.close()


@app.command("config")
def show_config(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Show resolved CLI configuration.

    Displays the final configuration after applying:
    1. CLI flags (highest priority)
    2. Environment variables
    3. .env file
    4. Defaults

    Examples:
        scanner config
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    # Create config table
    table = Table(title="CLI Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")

    # Determine sources
    import os

    sources = {
        "api_url": "env" if os.getenv("SCANNER_API_URL") else "default",
        "default_mode": "env" if os.getenv("SCANNER_DEFAULT_MODE") else "default",
        "tolerance": "env" if os.getenv("SCANNER_TOLERANCE") else "default",
        "output_format": "env" if os.getenv("SCANNER_OUTPUT") else "default",
        "parallel_scans": "env" if os.getenv("SCANNER_PARALLEL") else "default",
        "timeout": "env" if os.getenv("SCANNER_TIMEOUT") else "default",
    }

    # Override if CLI flag was provided
    if api_url:
        sources["api_url"] = "flag"

    table.add_row("API URL", config.api_url, sources["api_url"])
    table.add_row("Default Mode", config.default_mode, sources["default_mode"])
    table.add_row("Tolerance", str(config.tolerance), sources["tolerance"])
    table.add_row("Output Format", config.output_format, sources["output_format"])
    table.add_row("Parallel Scans", str(config.parallel_scans), sources["parallel_scans"])
    table.add_row("Timeout", f"{config.timeout}s", sources["timeout"])
    table.add_row("Color Enabled", str(config.color_enabled), "env" if os.getenv("NO_COLOR") else "default")

    # Token (masked)
    if config.token:
        masked_token = config.token[:8] + "..." if len(config.token) > 8 else "***"
        table.add_row("Token", masked_token, "env" if os.getenv("SCANNER_TOKEN") else "flag")

    console.print(table)

    # Show precedence
    console.print(Panel(
        "[bold]Configuration Precedence:[/bold]\n\n"
        "1. CLI flags (highest)\n"
        "2. Environment variables (SCANNER_*)\n"
        "3. .env file\n"
        "4. Built-in defaults (lowest)",
        title="ℹ️  Configuration Loading",
        border_style="blue",
    ))


if __name__ == "__main__":
    app()