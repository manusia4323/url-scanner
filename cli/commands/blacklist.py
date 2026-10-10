"""Blacklist management commands."""

import json
import csv
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

from cli.config import load_config, merge_config
from cli.client import APIClient, APIClientError
from cli.formatters import get_formatter


app = typer.Typer(help="Manage URL blacklist")
console = Console()


@app.command("list")
def list_blacklist(
    page: int = typer.Option(1, "--page", "-p", help="Page number"),
    size: int = typer.Option(20, "--size", "-s", help="Items per page"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: text | json | table"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    List blacklisted URLs.

    Examples:
        scanner blacklist list
        scanner blacklist list --domain evil.com
        scanner blacklist list --page 2 --size 50
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, output_format=output, color_enabled=not no_color)

    client = APIClient(config)

    try:
        result = client.list_blacklist(page=page, size=size, domain=domain)

        if output == "json":
            console.print_json(json.dumps(result, indent=2))
        elif output == "text":
            for item in result["items"]:
                console.print(f"{item['url_hash'][:16]}... | {item['domain']:40} | {item['risiko']:8} | {item['sumber']}")
        else:
            # Table format
            table = Table(title=f"Blacklist (Page {page} of {(result['total'] + size - 1) // size})")
            table.add_column("Hash", style="dim", no_wrap=True)
            table.add_column("Domain", style="cyan")
            table.add_column("Risk", style="yellow")
            table.add_column("Source", style="blue")
            table.add_column("Added", style="dim")

            for item in result["items"]:
                # Color code risk level
                risk = item["risiko"]
                risk_style = "red" if risk == "high" else "yellow" if risk == "medium" else "green"

                # Truncate hash
                hash_short = item["url_hash"][:16] + "..." if len(item["url_hash"]) > 16 else item["url_hash"]

                # Format date
                added = item.get("created_at", "")[:19] if item.get("created_at") else ""

                table.add_row(
                    hash_short,
                    item["domain"],
                    f"[{risk_style}]{risk}[/{risk_style}]",
                    item["sumber"],
                    added,
                )

            console.print(table)
            console.print(f"\n[dim]Total: {result['total']} entries[/dim]")

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("add")
def add_to_blacklist(
    url: str = typer.Argument(..., help="URL to blacklist"),
    risiko: str = typer.Option("high", "--risiko", "-r", help="Risk level: low | medium | high"),
    toleransi: int = typer.Option(70, "--toleransi", "-t", help="Tolerance threshold"),
    sumber: str = typer.Option("manual", "--sumber", "-s", help="Source identifier"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Add a URL to the blacklist.

    Examples:
        scanner blacklist add https://evil.com/phishing
        scanner blacklist add https://malware.xyz --risiko high --toleransi 50
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        result = client.add_to_blacklist(
            url=url,
            risiko=risiko,
            toleransi=toleransi,
            sumber=sumber,
        )

        console.print(Panel(
            f"[green]✓ URL added to blacklist[/green]\n\n"
            f"URL: {result['url']}\n"
            f"Hash: {result['url_hash']}\n"
            f"Domain: {result['domain']}\n"
            f"Risk: {result['risiko']}\n"
            f"Source: {result['sumber']}",
            title="Blacklist Entry Added",
            border_style="green",
        ))

    except APIClientError as e:
        if "already exists" in str(e).lower():
            console.print(f"[yellow]Warning: {e}[/yellow]")
            raise typer.Exit(0)
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("remove")
def remove_from_blacklist(
    url_hash: str = typer.Argument(..., help="URL hash to remove"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Remove a URL from the blacklist by its hash.

    Examples:
        scanner blacklist remove abc123def456...
        scanner blacklist remove abc123def456... --yes
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        if not yes:
            if not Confirm.ask(f"Remove URL with hash {url_hash[:16]}... from blacklist?"):
                console.print("[dim]Aborted.[/dim]")
                raise typer.Exit(0)

        client.remove_from_blacklist(url_hash)
        console.print(f"[green]✓ Removed from blacklist: {url_hash[:16]}...[/green]")

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("check")
def check_blacklist(
    url: str = typer.Argument(..., help="URL to check"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Check if a URL is in the blacklist.

    Examples:
        scanner blacklist check https://suspicious.com
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        result = client.check_blacklist(url)

        if result.get("found"):
            console.print(Panel(
                f"[red]⛔ URL found in blacklist[/red]\n\n"
                f"Risk: {result.get('risiko', 'N/A')}\n"
                f"Tolerance: {result.get('toleransi', 'N/A')}\n"
                f"Source: {result.get('sumber', 'N/A')}",
                title="Blacklist Check Result",
                border_style="red",
            ))
        else:
            console.print(Panel(
                f"[green]✓ URL not in blacklist[/green]\n\nURL: {url}",
                title="Blacklist Check Result",
                border_style="green",
            ))

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("import")
def import_blacklist(
    path: Path = typer.Argument(..., help="File to import (CSV or JSON)"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Import blacklist entries from CSV or JSON file.

    CSV format: url,risiko,toleransi,sumber
    JSON format: [{"url": "...", "risiko": "high", ...}, ...]

    Examples:
        scanner blacklist import blacklist.csv
        scanner blacklist import blacklist.json
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(2)

    client = APIClient(config)

    try:
        entries = []

        # Parse file
        if path.suffix.lower() == ".json":
            with open(path) as f:
                entries = json.load(f)
        elif path.suffix.lower() == ".csv":
            with open(path, newline="") as f:
                reader = csv.DictReader(f)
                entries = list(reader)
        else:
            console.print(f"[red]Unsupported file format: {path.suffix}[/red]")
            console.print("[dim]Supported formats: .csv, .json[/dim]")
            raise typer.Exit(2)

        # Import entries
        added = 0
        skipped = 0
        errors = 0

        console.print(f"[bold]Importing {len(entries)} entries...[/bold]")

        for entry in entries:
            try:
                client.add_to_blacklist(
                    url=entry["url"],
                    risiko=entry.get("risiko", "high"),
                    toleransi=int(entry.get("toleransi", 70)),
                    sumber=entry.get("sumber", "import"),
                )
                added += 1
            except APIClientError as e:
                if "already exists" in str(e).lower():
                    skipped += 1
                else:
                    errors += 1
                    console.print(f"[yellow]Warning: {e}[/yellow]")

        console.print(Panel(
            f"[green]Added: {added}[/green]\n"
            f"[yellow]Skipped (duplicates): {skipped}[/yellow]\n"
            f"[red]Errors: {errors}[/red]",
            title="Import Summary",
            border_style="blue",
        ))

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("export")
def export_blacklist(
    path: Path = typer.Argument(..., help="Output file (CSV or JSON)"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Export blacklist entries to CSV or JSON file.

    Examples:
        scanner blacklist export blacklist.json
        scanner blacklist export blacklist.csv
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        # Fetch all entries (paginated)
        all_entries = []
        page = 1
        size = 100

        console.print("[bold]Fetching blacklist entries...[/bold]")

        while True:
            result = client.list_blacklist(page=page, size=size)
            all_entries.extend(result["items"])

            if len(all_entries) >= result["total"]:
                break
            page += 1

        # Export to file
        if path.suffix.lower() == ".json":
            with open(path, "w") as f:
                json.dump(all_entries, f, indent=2)
        elif path.suffix.lower() == ".csv":
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["url_hash", "url", "domain", "risiko", "toleransi", "sumber", "created_at"])
                writer.writeheader()
                writer.writerows(all_entries)
        else:
            console.print(f"[red]Unsupported file format: {path.suffix}[/red]")
            raise typer.Exit(2)

        console.print(f"[green]✓ Exported {len(all_entries)} entries to {path}[/green]")

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("sync")
def sync_blacklist(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Sync blacklist from external sources (URLhaus, PhishTank).

    This triggers the update_blacklist.py script via the API.

    Examples:
        scanner blacklist sync
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        console.print("[bold]Syncing blacklist from external sources...[/bold]")

        # Call the sync endpoint
        response = client.client.post("/blacklist/sync")
        response.raise_for_status()
        result = response.json()

        console.print(Panel(
            f"[green]Sync completed[/green]\n\n"
            f"Fetched: {result.get('fetched', 0)}\n"
            f"Inserted: {result.get('inserted', 0)}\n"
            f"Skipped: {result.get('skipped', 0)}\n"
            f"Failed: {result.get('failed', 0)}",
            title="Blacklist Sync Result",
            border_style="blue",
        ))

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[dim]Note: The /blacklist/sync endpoint may not be implemented yet.[/dim]")
        raise typer.Exit(3)
    finally:
        client.close()


if __name__ == "__main__":
    app()