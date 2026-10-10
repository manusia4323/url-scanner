"""Scan command implementation."""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm
from rich.panel import Panel

from cli.config import CLIConfig, load_config, merge_config
from cli.client import APIClient, APIClientError, ScanResponse
from cli.formatters import get_formatter, Formatter


app = typer.Typer(help="Scan URLs for security threats")
console = Console()


def scan_command(
    urls: List[str] = typer.Argument(None, help="URLs to scan"),
    mode: str = typer.Option("normal", "--mode", "-m", help="Scan mode: passive | normal | aggressive"),
    tolerance: Optional[int] = typer.Option(None, "--tolerance", "-t", help="Override tolerance threshold (0-100)"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format: text | json | table | pretty"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print final verdict"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed scores and reasons"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Request timeout in seconds"),
    no_block: bool = typer.Option(False, "--no-block", help="Do not block even if verdict is BERBAHAYA"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save JSON response to file"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read URLs from file"),
    parallel: Optional[int] = typer.Option(None, "--parallel", "-p", help="Parallel scans for batch mode"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation for aggressive mode"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
):
    """
    Scan URLs for security threats.

    Modes:
    - passive: Local blacklist + heuristic prediction only (fast, safe)
    - normal: Full scan with all modules (default)
    - aggressive: Extended probing with headers, TLS, and port checks
    """
    # Load configuration
    config = load_config()
    config = merge_config(
        config,
        api_url=api_url,
        tolerance=tolerance,
        output_format=output,
        parallel_scans=parallel,
        timeout=timeout,
        color_enabled=not no_color,
    )

    # Validate mode
    if mode not in ("passive", "normal", "aggressive"):
        console.print(f"[red]Invalid mode: {mode}. Must be: passive, normal, or aggressive[/red]")
        raise typer.Exit(2)

    # Collect URLs
    url_list = list(urls) if urls else []

    if file:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(2)
        with open(file) as f:
            file_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            url_list.extend(file_urls)

    if not url_list:
        console.print("[red]No URLs provided. Use positional arguments or --file[/red]")
        raise typer.Exit(2)

    # Warn for aggressive mode
    if mode == "aggressive" and not yes:
        console.print(Panel(
            "[yellow]Aggressive mode performs active probing against the target.\n"
            "Only use on URLs you are authorized to test.[/yellow]",
            title="⚠️  Warning",
            border_style="yellow",
        ))
        if not Confirm.ask("Continue with aggressive scan?"):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)

    # Create API client
    client = APIClient(config)

    try:
        # Single URL scan
        if len(url_list) == 1:
            result = scan_single(client, url_list[0], mode, tolerance, verbose, quiet, config)

            # Save if requested
            if save:
                save_result(save, result, config)

            # Determine exit code
            exit_code = 0 if no_block else get_exit_code(result)
            raise typer.Exit(exit_code)

        # Batch scan
        else:
            results = scan_batch(client, url_list, mode, tolerance, config)

            # Save if requested
            if save:
                save_batch_result(save, results, config)

            # Determine exit code
            if no_block:
                exit_code = 0
            else:
                exit_code = 1 if any(r.keputusan == "BERBAHAYA" for r in results) else 0

            raise typer.Exit(exit_code)

    except APIClientError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(f"[dim]API URL: {config.api_url}[/dim]")
        console.print("[dim]Run 'scanner health' to check if the API is running.[/dim]")
        raise typer.Exit(3)

    finally:
        client.close()


def scan_single(
    client: APIClient,
    url: str,
    mode: str,
    tolerance: Optional[int],
    verbose: bool,
    quiet: bool,
    config: CLIConfig,
) -> ScanResponse:
    """
    Scan a single URL.

    Args:
        client: API client
        url: URL to scan
        mode: Scan mode
        tolerance: Override tolerance
        verbose: Show details
        quiet: Minimal output
        config: CLI configuration

    Returns:
        Scan response
    """
    if not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Scanning {url}...", total=None)
            result = client.scan_url(url, mode=mode, tolerance=tolerance)
    else:
        result = client.scan_url(url, mode=mode, tolerance=tolerance)

    # Format output
    if quiet:
        verdict_icon = "⛔" if result.keputusan == "BERBAHAYA" else "✅"
        console.print(f"{verdict_icon} {result.keputusan}")
    else:
        formatter = get_formatter(config.output_format, config.color_enabled)
        output = formatter.format_scan(result)
        console.print(output)

    return result


def scan_batch(
    client: APIClient,
    urls: List[str],
    mode: str,
    tolerance: Optional[int],
    config: CLIConfig,
) -> List[ScanResponse]:
    """
    Scan multiple URLs with progress bar.

    Args:
        client: API client
        urls: URLs to scan
        mode: Scan mode
        tolerance: Override tolerance
        config: CLI configuration

    Returns:
        List of scan responses
    """
    console.print(f"[bold]Scanning {len(urls)} URLs...[/bold]")

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=len(urls))
        results = client.batch_scan(urls, mode=mode, tolerance=tolerance, progress=progress, task_id=task)

    # Format output as table
    formatter = get_formatter("table", config.color_enabled)
    output = formatter.format_batch(results)
    console.print(output)

    # Summary
    dangerous = sum(1 for r in results if r.keputusan == "BERBAHAYA")
    safe = len(results) - dangerous
    console.print(f"\n[bold]Summary:[/bold] {safe} safe, {dangerous} dangerous")

    return results


def save_result(path: Path, result: ScanResponse, config: CLIConfig) -> None:
    """
    Save scan result to file.

    Args:
        path: File path
        result: Scan result
        config: CLI configuration
    """
    import json
    data = {
        "url": result.url,
        "url_hash": result.url_hash,
        "skor": result.skor,
        "keputusan": result.keputusan,
        "toleransi": result.toleransi,
        "alasan": result.alasan,
        "waktu": result.waktu,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Result saved to {path}[/dim]")


def save_batch_result(path: Path, results: List[ScanResponse], config: CLIConfig) -> None:
    """
    Save batch results to file.

    Args:
        path: File path
        results: Scan results
        config: CLI configuration
    """
    import json
    data = []
    for result in results:
        data.append({
            "url": result.url,
            "url_hash": result.url_hash,
            "skor": result.skor,
            "keputusan": result.keputusan,
            "toleransi": result.toleransi,
            "alasan": result.alasan,
            "waktu": result.waktu,
        })
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Results saved to {path}[/dim]")


def get_exit_code(result: ScanResponse) -> int:
    """
    Get exit code based on verdict.

    Args:
        result: Scan result

    Returns:
        Exit code (0 for safe, 1 for dangerous)
    """
    return 1 if result.keputusan == "BERBAHAYA" else 0


# Create Typer command
@app.command()
def scan(
    urls: List[str] = typer.Argument(None, help="URLs to scan"),
    mode: str = typer.Option("normal", "--mode", "-m", help="Scan mode: passive | normal | aggressive"),
    tolerance: Optional[int] = typer.Option(None, "--tolerance", "-t", help="Override tolerance threshold"),
    output: str = typer.Option("pretty", "--output", "-o", help="Output format"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print verdict"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Request timeout"),
    no_block: bool = typer.Option(False, "--no-block", help="Exit 0 regardless of verdict"),
    save: Optional[Path] = typer.Option(None, "--save", help="Save JSON to file"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read URLs from file"),
    parallel: Optional[int] = typer.Option(None, "--parallel", "-p", help="Parallel scans"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="API base URL"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colors"),
):
    """Scan URLs for security threats."""
    scan_command(
        urls=urls,
        mode=mode,
        tolerance=tolerance,
        output=output,
        quiet=quiet,
        verbose=verbose,
        timeout=timeout,
        no_block=no_block,
        save=save,
        file=file,
        parallel=parallel,
        yes=yes,
        api_url=api_url,
        no_color=no_color,
    )