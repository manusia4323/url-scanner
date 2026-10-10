"""Output formatters for different display formats."""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.progress_bar import ProgressBar

from cli.client import ScanResponse


class Formatter:
    """Base formatter class."""

    def __init__(self, color_enabled: bool = True):
        """
        Initialize formatter.

        Args:
            color_enabled: Whether to use colors
        """
        self.console = Console(color_system="auto" if color_enabled else None)

    def format_scan(self, result: ScanResponse) -> str:
        """
        Format a scan result.

        Args:
            result: Scan response

        Returns:
            Formatted string
        """
        raise NotImplementedError

    def format_batch(self, results: List[ScanResponse]) -> str:
        """
        Format batch scan results.

        Args:
            results: List of scan responses

        Returns:
            Formatted string
        """
        raise NotImplementedError


class TextFormatter(Formatter):
    """Plain text formatter."""

    def format_scan(self, result: ScanResponse) -> str:
        """Format as plain text."""
        lines = [
            f"URL: {result.url}",
            f"Hash: {result.url_hash}",
            f"Verdict: {result.keputusan}",
            f"Score: {result.skor['final']:.1f}/100 (tolerance: {result.toleransi})",
            "",
            "Score Breakdown:",
            f"  Prediction:     {result.skor['prediksi']:.1f}",
            f"  Vulnerability:  {result.skor['kerentanan']:.1f}",
            f"  Reputation:     {result.skor['reputasi']:.1f}",
        ]

        if result.alasan:
            lines.extend(["", "Reasons:"])
            for reason in result.alasan:
                lines.append(f"  • {reason}")

        lines.extend(["", f"Time: {result.waktu}"])

        return "\n".join(lines)

    def format_batch(self, results: List[ScanResponse]) -> str:
        """Format batch results as text."""
        lines = []
        for i, result in enumerate(results):
            if i > 0:
                lines.append("---")
            lines.append(self.format_scan(result))
        return "\n".join(lines)


class JSONFormatter(Formatter):
    """JSON formatter."""

    def format_scan(self, result: ScanResponse) -> str:
        """Format as JSON."""
        data = {
            "url": result.url,
            "url_hash": result.url_hash,
            "skor": result.skor,
            "keputusan": result.keputusan,
            "toleransi": result.toleransi,
            "alasan": result.alasan,
            "waktu": result.waktu,
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def format_batch(self, results: List[ScanResponse]) -> str:
        """Format batch results as JSON array."""
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
        return json.dumps(data, indent=2, ensure_ascii=False)


class TableFormatter(Formatter):
    """Table formatter."""

    def format_scan(self, result: ScanResponse) -> str:
        """Format as table (single row)."""
        return self.format_batch([result])

    def format_batch(self, results: List[ScanResponse]) -> str:
        """Format batch results as table."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", no_wrap=False)
        table.add_column("Verdict")
        table.add_column("Score", justify="right")
        table.add_column("Pred", justify="right")
        table.add_column("Vuln", justify="right")
        table.add_column("Rep", justify="right")
        table.add_column("Time", style="dim")

        for result in results:
            # Color verdict
            verdict_color = "red" if result.keputusan == "BERBAHAYA" else "green"
            verdict_text = Text(result.keputusan, style=verdict_color)

            # Format time (just date if available)
            time_str = ""
            if result.waktu:
                try:
                    dt = datetime.fromisoformat(result.waktu.replace("Z", "+00:00"))
                    time_str = dt.strftime("%Y-%m-%d %H:%M")
                except (ValueError, AttributeError):
                    time_str = str(result.waktu)[:19]

            table.add_row(
                result.url[:50] + ("..." if len(result.url) > 50 else ""),
                verdict_text,
                f"{result.skor['final']:.1f}",
                f"{result.skor['prediksi']:.1f}",
                f"{result.skor['kerentanan']:.1f}",
                f"{result.skor['reputasi']:.1f}",
                time_str,
            )

        # Render to string
        with self.console.capture() as capture:
            self.console.print(table)
        return capture.get()


class PrettyFormatter(Formatter):
    """Pretty formatter with Rich panels and colors."""

    def format_scan(self, result: ScanResponse) -> str:
        """Format as pretty panel."""
        # Determine colors based on verdict
        panel_style = "red" if result.keputusan == "BERBAHAYA" else "green"
        verdict_icon = "⛔" if result.keputusan == "BERBAHAYA" else "✅"

        # Create score breakdown with progress bars
        score_panel = self._create_score_panel(result)

        # Create reasons panel
        reasons_panel = self._create_reasons_panel(result)

        # Create main panel
        main_content = Text()
        main_content.append(f"URL: {result.url}\n", style="bold")
        main_content.append(f"Hash: {result.url_hash}\n", style="dim")
        main_content.append(f"Verdict: {verdict_icon} {result.keputusan}\n", style=panel_style)
        main_content.append(f"Score: {result.skor['final']:.1f}/100 (tolerance: {result.toleransi})\n\n")

        # Create columns for score and reasons
        columns = Columns([score_panel, reasons_panel], equal=True, expand=True)

        # Render
        with self.console.capture() as capture:
            self.console.print(Panel(
                columns,
                title=f"Scan Result",
                style=panel_style,
                border_style=panel_style,
            ))
        return capture.get()

    def format_batch(self, results: List[ScanResponse]) -> str:
        """Format batch results as pretty table."""
        # Use TableFormatter for batch pretty output
        table_formatter = TableFormatter(self.console.color_system is not None)
        return table_formatter.format_batch(results)

    def _create_score_panel(self, result: ScanResponse) -> Panel:
        """Create score breakdown panel."""
        content = Text()

        # Prediction score
        pred_bar = self._create_progress_bar(result.skor["prediksi"])
        content.append(f"Prediction:     {result.skor['prediksi']:5.1f}  ")
        content.append(pred_bar)
        content.append("\n")

        # Vulnerability score
        vuln_bar = self._create_progress_bar(result.skor["kerentanan"])
        content.append(f"Vulnerability:  {result.skor['kerentanan']:5.1f}  ")
        content.append(vuln_bar)
        content.append("\n")

        # Reputation score
        rep_bar = self._create_progress_bar(result.skor["reputasi"])
        content.append(f"Reputation:     {result.skor['reputasi']:5.1f}  ")
        content.append(rep_bar)
        content.append("\n")

        # Final score
        final_bar = self._create_progress_bar(result.skor["final"])
        content.append(f"\nFinal Score:    {result.skor['final']:5.1f}  ", style="bold")
        content.append(final_bar)

        return Panel(content, title="Score Breakdown", border_style="blue")

    def _create_reasons_panel(self, result: ScanResponse) -> Panel:
        """Create reasons panel."""
        if not result.alasan:
            content = Text("No issues detected", style="green")
        else:
            content = Text()
            for reason in result.alasan:
                content.append(f"• {reason}\n", style="yellow")

        return Panel(content, title="Reasons", border_style="yellow")

    def _create_progress_bar(self, score: float) -> ProgressBar:
        """Create a Rich progress bar for a score."""
        color = "red" if score > 70 else "yellow" if score > 40 else "green"
        return ProgressBar(total=100, completed=score, width=20, style=f"bar.{color}")


def get_formatter(format_name: str, color_enabled: bool = True) -> Formatter:
    """
    Get formatter by name.

    Args:
        format_name: Format name (text, json, table, pretty)
        color_enabled: Whether to use colors

    Returns:
        Formatter instance

    Raises:
        ValueError: If format name is invalid
    """
    formatters = {
        "text": TextFormatter,
        "json": JSONFormatter,
        "table": TableFormatter,
        "pretty": PrettyFormatter,
    }

    if format_name not in formatters:
        raise ValueError(f"Invalid format: {format_name}. Must be one of: {list(formatters.keys())}")

    return formatters[format_name](color_enabled)