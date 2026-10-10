"""Configuration management using Pydantic Settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # External APIs
    google_safe_browsing_key: str = ""
    virustotal_api_key: str = ""

    # Scoring weights
    weight_prediction: float = 0.5
    weight_vulnerability: float = 0.3
    weight_reputation: float = 0.2
    default_tolerance: int = 70

    # Database
    database_url: str = "sqlite:///./data/scanner.db"

    # HTTP
    http_timeout: int = 10
    user_agent: str = "URLScanner/1.0"
    max_concurrent_scans: int = 10

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # Paths
    model_path: str = "models/phishing_model.pkl"

    def is_google_sb_configured(self) -> bool:
        """Check if Google Safe Browsing API is configured."""
        return bool(self.google_safe_browsing_key)

    def is_virustotal_configured(self) -> bool:
        """Check if VirusTotal API is configured."""
        return bool(self.virustotal_api_key)

    def has_ml_model(self) -> bool:
        """Check if ML model file exists."""
        import os
        return os.path.exists(self.model_path)


# Global settings instance
settings = Settings()