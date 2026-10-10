"""Tests for CLI commands."""

import json
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

import pytest
import respx
from httpx import Response

from cli.main import app


runner = CliRunner()


class TestScanCommand:
    """Test scan command."""

    @respx.mock
    def test_scan_normal_mode(self):
        """Test normal scan mode."""
        # Mock API response
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {
                        "prediksi": 25.0,
                        "kerentanan": 30.0,
                        "reputasi": 0.0,
                        "final": 21.5,
                    },
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": ["No suspicious features detected"],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code == 0
        assert "AMAN" in result.stdout or "aman" in result.stdout.lower()

    @respx.mock
    def test_scan_dangerous_url_exit_code_1(self):
        """Test exit code 1 for dangerous URL."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://malicious.xyz",
                    "url_hash": "def456",
                    "skor": {
                        "prediksi": 85.0,
                        "kerentanan": 70.0,
                        "reputasi": 100.0,
                        "final": 85.5,
                    },
                    "keputusan": "BERBAHAYA",
                    "toleransi": 70,
                    "alasan": ["Suspicious TLD", "Found in blacklist"],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "https://malicious.xyz"])
        assert result.exit_code == 1

    @respx.mock
    def test_scan_passive_mode(self):
        """Test passive scan mode."""
        respx.post("http://localhost:8000/scan/passive").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {
                        "prediksi": 25.0,
                        "kerentanan": 0.0,
                        "reputasi": 0.0,
                        "final": 12.5,
                    },
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": ["Passive mode - vulnerability not checked"],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "--mode", "passive", "https://example.com"])
        assert result.exit_code == 0

    @respx.mock
    def test_scan_output_json(self):
        """Test JSON output format."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {
                        "prediksi": 25.0,
                        "kerentanan": 30.0,
                        "reputasi": 0.0,
                        "final": 21.5,
                    },
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "--output", "json", "https://example.com"])
        assert result.exit_code == 0
        # Verify output is valid JSON
        output_data = json.loads(result.stdout)
        assert output_data["url"] == "https://example.com"
        assert output_data["keputusan"] == "AMAN"

    @respx.mock
    def test_scan_with_tolerance_override(self):
        """Test tolerance override."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {
                        "prediksi": 25.0,
                        "kerentanan": 30.0,
                        "reputasi": 0.0,
                        "final": 21.5,
                    },
                    "keputusan": "AMAN",
                    "toleransi": 50,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "--tolerance", "50", "https://example.com"])
        assert result.exit_code == 0

    @respx.mock
    def test_scan_no_block_exit_code_0(self):
        """Test --no-block always returns exit code 0."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://malicious.xyz",
                    "url_hash": "def456",
                    "skor": {
                        "prediksi": 85.0,
                        "kerentanan": 70.0,
                        "reputasi": 100.0,
                        "final": 85.5,
                    },
                    "keputusan": "BERBAHAYA",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "--no-block", "https://malicious.xyz"])
        assert result.exit_code == 0

    @respx.mock
    def test_scan_batch(self):
        """Test batch scanning multiple URLs."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {"prediksi": 25.0, "kerentanan": 30.0, "reputasi": 0.0, "final": 21.5},
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "https://example1.com", "https://example2.com"])
        assert result.exit_code == 0

    def test_scan_invalid_mode(self):
        """Test invalid scan mode."""
        result = runner.invoke(app, ["scan", "--mode", "invalid", "https://example.com"])
        assert result.exit_code == 2

    def test_scan_no_urls(self):
        """Test scan with no URLs provided."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 2


class TestBlacklistCommand:
    """Test blacklist commands."""

    @respx.mock
    def test_blacklist_list(self):
        """Test listing blacklist."""
        respx.get("http://localhost:8000/blacklist").mock(
            return_value=Response(
                200,
                json={
                    "total": 2,
                    "page": 1,
                    "size": 20,
                    "items": [
                        {
                            "id": 1,
                            "url_hash": "abc123",
                            "url": "https://evil.com",
                            "domain": "evil.com",
                            "risiko": "high",
                            "toleransi": 70,
                            "sumber": "manual",
                            "created_at": "2025-01-15T10:00:00Z",
                        }
                    ],
                }
            )
        )

        result = runner.invoke(app, ["blacklist", "list"])
        assert result.exit_code == 0

    @respx.mock
    def test_blacklist_add(self):
        """Test adding to blacklist."""
        respx.post("http://localhost:8000/blacklist").mock(
            return_value=Response(
                201,
                json={
                    "id": 1,
                    "url_hash": "abc123",
                    "url": "https://evil.com",
                    "domain": "evil.com",
                    "risiko": "high",
                    "toleransi": 70,
                    "sumber": "manual",
                    "created_at": "2025-01-15T10:00:00Z",
                }
            )
        )

        result = runner.invoke(app, ["blacklist", "add", "https://evil.com", "--risiko", "high"])
        assert result.exit_code == 0

    @respx.mock
    def test_blacklist_add_duplicate(self):
        """Test adding duplicate URL."""
        respx.post("http://localhost:8000/blacklist").mock(
            return_value=Response(409, json={"detail": "URL already exists"})
        )

        result = runner.invoke(app, ["blacklist", "add", "https://evil.com"])
        assert result.exit_code == 0  # Exits 0 for duplicate warning

    @respx.mock
    def test_blacklist_check(self):
        """Test checking URL in blacklist."""
        respx.get("http://localhost:8000/blacklist/check/https://evil.com").mock(
            return_value=Response(200, json={"found": True, "risiko": "high"})
        )

        result = runner.invoke(app, ["blacklist", "check", "https://evil.com"])
        assert result.exit_code == 0


class TestLogsCommand:
    """Test logs commands."""

    @respx.mock
    def test_logs_list(self):
        """Test listing logs."""
        respx.get("http://localhost:8000/logs").mock(
            return_value=Response(
                200,
                json={
                    "total": 10,
                    "page": 1,
                    "size": 20,
                    "items": [
                        {
                            "id": 1,
                            "url": "https://example.com",
                            "url_hash": "abc123",
                            "skor_prediksi": 25.0,
                            "skor_kerentanan": 30.0,
                            "skor_reputasi": 0.0,
                            "skor_final": 21.5,
                            "keputusan": "AMAN",
                            "waktu": "2025-01-15T10:00:00Z",
                        }
                    ],
                }
            )
        )

        result = runner.invoke(app, ["logs", "list"])
        assert result.exit_code == 0

    @respx.mock
    def test_logs_stats(self):
        """Test logs statistics."""
        respx.get("http://localhost:8000/logs/stats").mock(
            return_value=Response(
                200,
                json={
                    "total_scans": 100,
                    "aman_count": 80,
                    "berbahaya_count": 20,
                    "danger_rate": 20.0,
                    "average_scores": {
                        "final": 35.5,
                        "prediksi": 30.0,
                        "kerentanan": 25.0,
                        "reputasi": 15.0,
                    },
                }
            )
        )

        result = runner.invoke(app, ["logs", "stats"])
        assert result.exit_code == 0


class TestSystemCommand:
    """Test system commands."""

    @respx.mock
    def test_health_check(self):
        """Test health check."""
        respx.get("http://localhost:8000/health").mock(
            return_value=Response(200, json={"status": "ok", "db": "ok"})
        )

        result = runner.invoke(app, ["health"])
        assert result.exit_code == 0

    def test_version(self):
        """Test version display."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.stdout

    def test_config(self):
        """Test config display."""
        result = runner.invoke(app, ["config"])
        assert result.exit_code == 0


class TestConfigPrecedence:
    """Test configuration precedence."""

    @respx.mock
    def test_flag_overrides_env(self, monkeypatch):
        """Test that CLI flags override environment variables."""
        # Set env var
        monkeypatch.setenv("SCANNER_API_URL", "http://env-url:8000")

        # Use different URL via flag
        respx.get("http://flag-url:8000/health").mock(
            return_value=Response(200, json={"status": "ok"})
        )

        result = runner.invoke(app, ["--api-url", "http://flag-url:8000", "health"])
        assert result.exit_code == 0


class TestAPIErrors:
    """Test API error handling."""

    @respx.mock
    def test_api_unreachable(self):
        """Test handling of unreachable API."""
        respx.post("http://localhost:8000/scan").mock(side_effect=Exception("Connection refused"))

        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code == 3

    @respx.mock
    def test_api_500_error(self):
        """Test handling of API 500 error."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(500, json={"detail": "Internal server error"})
        )

        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code == 3

    @respx.mock
    def test_api_400_error(self):
        """Test handling of API 400 error."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(400, json={"detail": "Invalid URL", "code": "INVALID_URL"})
        )

        result = runner.invoke(app, ["scan", "not-a-url"])
        assert result.exit_code == 3


class TestBatchScan:
    """Test batch scanning."""

    @respx.mock
    def test_batch_scan_from_file(self, tmp_path):
        """Test batch scanning from file."""
        # Create temp file with URLs
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://example1.com\nhttps://example2.com\n")

        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {"prediksi": 25.0, "kerentanan": 30.0, "reputasi": 0.0, "final": 21.5},
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(app, ["scan", "--file", str(urls_file)])
        assert result.exit_code == 0

    @respx.mock
    def test_batch_scan_parallel(self):
        """Test batch scan with parallel option."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {"prediksi": 25.0, "kerentanan": 30.0, "reputasi": 0.0, "final": 21.5},
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        result = runner.invoke(
            app,
            ["scan", "--parallel", "2", "https://example1.com", "https://example2.com"]
        )
        assert result.exit_code == 0


class TestShortcuts:
    """Test CLI shortcuts."""

    @respx.mock
    def test_direct_url_scan(self):
        """Test scanning URL without 'scan' subcommand."""
        respx.post("http://localhost:8000/scan").mock(
            return_value=Response(
                200,
                json={
                    "url": "https://example.com",
                    "url_hash": "abc123",
                    "skor": {"prediksi": 25.0, "kerentanan": 30.0, "reputasi": 0.0, "final": 21.5},
                    "keputusan": "AMAN",
                    "toleransi": 70,
                    "alasan": [],
                    "waktu": "2025-01-15T10:30:00Z",
                }
            )
        )

        # This test would require the main() function to be called
        # For now, test through the scan command directly
        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])