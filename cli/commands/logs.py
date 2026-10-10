"""Logs management commands."""

import json
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

from cli.config import load_config, merge_config
from cli.client import APIClient, APIClientError


app = typer.Typer(help="View and manage scan logs")
console = Console()


@app.command("list")
def list_logs(
    page: int = typer.Option(1, "--page", "-p", help="Page number"),
    size: int = typer.Option(20, "--size", "-s", help="Items per page"),
    keputusan: Optional[str] = typer.Option(None, "--keputusan", "-k", help="Filter by verdict: AMAN | BERBAHAYA"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by time (ISO format: YYYY-MM-DD)"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: text | json | table"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    List scan logs with optional filtering.

    Examples:
        scanner logs list
        scanner logs list --keputusan BERBAHAYA
        scanner logs list --since 2025-01-01
        scanner logs list --page 2 --size 50
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, output_format=output, color_enabled=not no_color)

    # Validate keputusan
    if keputusan and keputusan not in ("AMAN", "BERBAHAYA"):
        console.print(f"[red]Invalid keputusan: {keputusan}. Must be AMAN or BERBAHAYA[/red]")
        raise typer.Exit(2)

    client = APIClient(config)

    try:
        result = client.list_logs(page=page, size=size, keputusan=keputusan, since=since)

        if output == "json":
            console.print_json(json.dumps(result, indent=2))
        elif output == "text":
            for item in result["items"]:
                console.print(
                    f"{item['waktu'][:19]} | {item['keputusan']:10} | "
                    f"{item['skor_final']:5.1f} | {item['url'][:60]}"
                )
        else:
            # Table format
            table = Table(title=f"Scan Logs (Page {page})")
            table.add_column("Time", style="dim", no_wrap=True)
            table.add_column("Verdict")
            table.add_column("Score", justify="right")
            table.add_column("URL", style="cyan", no_wrap=False)

            for item in result["items"]:
                # Color code verdict
                verdict = item["keputusan"]
                verdict_style = "red" if verdict == "BERBAHAYA" else "green"
                verdict_icon = "⛔" if verdict == "BERBAHAYA" else "✅"

                # Truncate URL if needed
                url = item["url"]
                if len(url) > 60:
                    url = url[:57] + "..."

                # Format time
                time_str = item["waktu"][:19] if item["waktu"] else ""

                table.add_row(
                    time_str,
                    f"[{verdict_style}]{verdict_icon} {verdict}[/{verdict_style}]",
                    f"{item['skor_final']:.1f}",
                    url,
                )

            console.print(table)
            console.print(f"\n[dim]Total: {result['total']} entries[/dim]")

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("stats")
def get_stats(
    since: Optional[str] = typer.Option(None, "--since", "-s", help="Filter by time (ISO format: YYYY-MM-DD)"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Show scan statistics and trends.

    Examples:
        scanner logs stats
        scanner logs stats --since 2025-01-01
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        result = client.get_log_stats(since=since)

        # Create statistics panel
        console.print(Panel(
            f"[bold]Total Scans:[/bold] {result['total_scans']}\n"
            f"[green]Safe (AMAN):[/green] {result['aman_count']}\n"
            f"[red]Dangerous (BERBAHAYA):[/red] {result['berbahaya_count']}\n"
            f"[yellow]Danger Rate:[/yellow] {result['danger_rate']}%",
            title="📊 Scan Statistics",
            border_style="blue",
        ))

        # Average scores table
        avg = result.get("average_scores", {})
        if avg:
            table = Table(title="Average Scores", show_header=True)
            table.add_column("Metric", style="cyan")
            table.add_column("Average", justify="right")

            table.add_row("Final Score", f"{avg.get('final', 0):.2f}")
            table.add_row("Prediction", f"{avg.get('prediksi', 0):.2f}")
            table.add_row("Vulnerability", f"{avg.get('kerentanan', 0):.2f}")
            table.add_row("Reputation", f"{avg.get('reputasi', 0):.2f}")

            console.print(table)

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("clear")
def clear_logs(
    before: Optional[str] = typer.Option(None, "--before", "-b", help="Delete logs before this date (ISO format)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Clear scan logs. Use --before to delete only older entries.

    Examples:
        scanner logs clear --yes
        scanner logs clear --before 2025-01-01
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, color_enabled=not no_color)

    client = APIClient(config)

    try:
        # Warning message
        if before:
            msg = f"Delete all scan logs before {before}?"
        else:
            msg = "Delete ALL scan logs?"

        if not yes:
            console.print(f"[yellow]⚠️  {msg}[/yellow]")
            if not Confirm.ask("This cannot be undone. Continue?"):
                console.print("[dim]Aborted.[/dim]")
                raise typer.Exit(0)

        # Call API to clear logs
        params = {}
        if before:
            params["before"] = before

        response = client.client.delete("/logs/clear", params=params)
        response.raise_for_status()
        result = response.json()

        console.print(f"[green]✓ Deleted {result.get('deleted', 0)} log entries[/green]")

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


@app.command("show")
def show_log(
    log_id: int = typer.Argument(..., help="Log entry ID"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format: text | json | pretty"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Show details of a specific log entry.

    Examples:
        scanner logs show 123
        scanner logs show 123 --output json
    """
    config = load_config()
    config = merge_config(config, api_url=api_url, output_format=output, color_enabled=not no_color)

    client = APIClient(config)

    try:
        response = client.client.get(f"/logs/{log_id}")
        response.raise_for_status()
        result = response.json()

        if output == "json":
            console.print_json(json.dumps(result, indent=2))
        else:
            # Pretty format
            verdict = result["keputusan"]
            verdict_style = "red" if verdict == "BERBAHAYA" else "green"
            verdict_icon = "⛔" if verdict == "BERBAHAYA" else "✅"

            console.print(Panel(
                f"[bold]URL:[/bold] {result['url']}\n"
                f"[bold]Hash:[/bold] {result['url_hash']}\n"
                f"[bold]Verdict:[/bold] [{verdict_style}]{verdict_icon} {verdict}[/{verdict_style}]\n"
                f"[bold]Final Score:[/bold] {result['skor_final']:.1f}/100\n\n"
                f"[bold]Score Breakdown:[/bold]\n"
                f"  Prediction:     {result['skor_prediksi']:.1f}\n"
                f"  Vulnerability:  {result['skor_kerentanan']:.1f}\n"
                f"  Reputation:     {result['skor_reputasi']:.1f}\n\n"
                f"[bold]Time:[/bold] {result['waktu']}",
                title=f"Log Entry #{log_id}",
                border_style=verdict_style,
            ))

    except APIClientError as e:
        if "not found" in str(e).lower():
            console.print(f"[red]Log entry #{log_id} not found[/red]")
            raise typer.Exit(1)
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(3)
    finally:
        client.close()


if __name__ == "__main__":
    app()