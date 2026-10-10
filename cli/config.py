"""CLI configuration management."""

import os
from typing import Optional
from pathlib import Path
from dataclasses import dataclass, field

import dotenv


@dataclass
class CLIConfig:
    """CLI configuration with precedence: CLI flags > env vars > .env > defaults."""

    # API settings
    api_url: str = "http://localhost:8000"
    token: Optional[str] = None

    # Default scan settings
    default_mode: str = "normal"
    tolerance: int = 70
    output_format: str = "pretty"

    # Batch settings
    parallel_scans: int = 4
    timeout: int = 30

    # UI settings
    color_enabled: bool = True

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.default_mode not in ("passive", "normal", "aggressive"):
            raise ValueError(f"Invalid default mode: {self.default_mode}")
        if self.output_format not in ("text", "json", "table", "pretty"):
            raise ValueError(f"Invalid output format: {self.output_format}")
        if not 0 <= self.tolerance <= 100:
            raise ValueError(f"Tolerance must be between 0 and 100, got {self.tolerance}")


def load_config() -> CLIConfig:
    """
    Load configuration with precedence order:
    1. Environment variables
    2. .env file
    3. Defaults

    Environment variables:
        SCANNER_API_URL
        SCANNER_TOKEN
        SCANNER_DEFAULT_MODE
        SCANNER_TOLERANCE
        SCANNER_OUTPUT
        SCANNER_PARALLEL
        SCANNER_TIMEOUT
        NO_COLOR (for color_enabled)
    """
    # Load .env file if it exists
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        dotenv.load_dotenv(env_file)

    # Get values from environment
    api_url = os.getenv("SCANNER_API_URL", "http://localhost:8000")
    token = os.getenv("SCANNER_TOKEN")
    default_mode = os.getenv("SCANNER_DEFAULT_MODE", "normal")
    tolerance_str = os.getenv("SCANNER_TOLERANCE")
    output_format = os.getenv("SCANNER_OUTPUT", "pretty")
    parallel_str = os.getenv("SCANNER_PARALLEL")
    timeout_str = os.getenv("SCANNER_TIMEOUT")
    no_color = os.getenv("NO_COLOR", "0")  # Standard NO_COLOR convention

    # Convert string values
    try:
        tolerance = int(tolerance_str) if tolerance_str else 70
    except ValueError:
        tolerance = 70

    try:
        parallel_scans = int(parallel_str) if parallel_str else 4
    except ValueError:
        parallel_scans = 4

    try:
        timeout = int(timeout_str) if timeout_str else 30
    except ValueError:
        timeout = 30

    color_enabled = no_color.lower() not in ("1", "true", "yes")

    return CLIConfig(
        api_url=api_url.rstrip("/"),
        token=token,
        default_mode=default_mode,
        tolerance=tolerance,
        output_format=output_format,
        parallel_scans=parallel_scans,
        timeout=timeout,
        color_enabled=color_enabled,
    )


def merge_config(
    base: CLIConfig,
    *,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
    default_mode: Optional[str] = None,
    tolerance: Optional[int] = None,
    output_format: Optional[str] = None,
    parallel_scans: Optional[int] = None,
    timeout: Optional[int] = None,
    color_enabled: Optional[bool] = None,
) -> CLIConfig:
    """
    Merge CLI flags into base configuration.

    Args:
        base: Base configuration
        **kwargs: CLI flag values to override

    Returns:
        Merged configuration
    """
    return CLIConfig(
        api_url=api_url or base.api_url,
        token=token or base.token,
        default_mode=default_mode or base.default_mode,
        tolerance=tolerance or base.tolerance,
        output_format=output_format or base.output_format,
        parallel_scans=parallel_scans or base.parallel_scans,
        timeout=timeout or base.timeout,
        color_enabled=color_enabled if color_enabled is not None else base.color_enabled,
    )