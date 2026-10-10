"""Unit tests for scoring services."""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import UrlBlacklist
from app.services.prediction import score_prediction, get_score_sync as get_prediction_sync
from app.services.vulnerability import score_vulnerability, get_score_sync as get_vulnerability_sync
from app.services.reputation import score_reputation, get_score_sync as get_reputation_sync
from app.services.fusion import calculate_final_score, determine_verdict, fuse_results


# Setup test database
@pytest.fixture(scope="session")
def test_db():
    """Create test database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


class TestPredictionService:
    """Test prediction scoring module."""

    @pytest.mark.asyncio
    async def test_score_prediction_clean_url(self):
        """Test scoring a clean URL."""
        url = "https://google.com"
        result = await score_prediction(url)

        assert "score" in result
        assert "reasons" in result
        assert result["score"] >= 0
        assert result["score"] <= 100

    @pytest.mark.asyncio
    async def test_score_prediction_phishing_url(self):
        """Test scoring a suspicious phishing URL."""
        url = "https://verify-login-secure.xyz/account/confirm"
        result = await score_prediction(url)

        assert result["score"] > 0
        assert len(result["reasons"]) > 0

    @pytest.mark.asyncio
    async def test_score_prediction_suspicious_length(self):
        """Test URL with excessive length."""
        url = "https://example.com/" + "a" * 100
        result = await score_prediction(url)

        assert result["score"] > 0
        assert any("length" in r.lower() for r in result["reasons"])

    @pytest.mark.asyncio
    async def test_score_prediction_at_symbol(self):
        """Test URL with @ symbol."""
        url = "https://google.com@malicious.com"
        result = await score_prediction(url)

        assert result["score"] > 0
        assert any("@" in r for r in result["reasons"])

    def test_score_prediction_sync(self):
        """Test synchronous prediction scoring."""
        url = "https://example.com"
        result = get_prediction_sync(url)

        assert "score" in result
        assert "reasons" in result
        assert result["score"] >= 0
        assert result["score"] <= 100


class TestVulnerabilityService:
    """Test vulnerability scoring module."""

    @pytest.mark.asyncio
    async def test_score_vulnerability_http_url(self):
        """Test vulnerability score for HTTP URL."""
        url = "http://example.com"
        result = await score_vulnerability(url)

        assert "score" in result
        assert "reasons" in result
        assert result["score"] > 0
        assert any("HTTPS" in r or "https" in r.lower() for r in result["reasons"])

    @pytest.mark.asyncio
    async def test_score_vulnerability_https_url(self):
        """Test vulnerability score for HTTPS URL."""
        url = "https://example.com"
        result = await score_vulnerability(url)

        assert "score" in result
        assert "reasons" in result
        # Score may vary depending on actual SSL cert and headers

    def test_score_vulnerability_sync(self):
        """Test synchronous vulnerability scoring."""
        url = "http://example.com"
        result = get_vulnerability_sync(url)

        assert "score" in result
        assert "reasons" in result
        assert result["score"] >= 0


class TestReputationService:
    """Test reputation scoring module."""

    @pytest.mark.asyncio
    async def test_score_reputation_clean_url(self, test_db):
        """Test reputation score for clean URL."""
        url = "https://google.com"
        result = await score_reputation(url, test_db)

        assert "score" in result
        assert "reasons" in result
        assert result["score"] >= 0

    @pytest.mark.asyncio
    async def test_score_reputation_blacklist_hit(self, test_db):
        """Test reputation score when URL is in blacklist."""
        # Add test URL to blacklist
        from app.utils.url_parser import get_url_hash, normalize_url, extract_domain

        url = "https://malicious.example.com/phishing"
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        url_hash = get_url_hash(normalized)

        blacklist_entry = UrlBlacklist(
            url_hash=url_hash,
            url=normalized,
            domain=domain,
            risiko="high",
            sumber="test"
        )
        test_db.add(blacklist_entry)
        test_db.commit()

        result = await score_reputation(url, test_db)

        assert result["score"] == 100
        assert "blacklist" in result["reasons"][0].lower()

    def test_score_reputation_sync(self, test_db):
        """Test synchronous reputation scoring."""
        url = "https://google.com"
        result = get_reputation_sync(url, test_db)

        assert "score" in result
        assert "reasons" in result


class TestFusionService:
    """Test score fusion module."""

    def test_calculate_final_score(self):
        """Test final score calculation."""
        score = calculate_final_score(50, 60, 70)

        # 0.5*50 + 0.3*60 + 0.2*70 = 25 + 18 + 14 = 57
        assert score == 57.0

    def test_calculate_final_score_weights(self):
        """Test final score with custom weights."""
        from app.config import settings

        original_weights = (
            settings.weight_prediction,
            settings.weight_vulnerability,
            settings.weight_reputation
        )

        try:
            # Test with equal weights
            settings.weight_prediction = 0.33
            settings.weight_vulnerability = 0.33
            settings.weight_reputation = 0.34

            score = calculate_final_score(100, 100, 100)
            assert abs(score - 100.0) < 0.01

        finally:
            # Restore original weights
            (settings.weight_prediction,
             settings.weight_vulnerability,
             settings.weight_reputation) = original_weights

    def test_determine_verdict_dangerous(self):
        """Test verdict for dangerous score."""
        verdict = determine_verdict(75)
        assert verdict == "BERBAHAYA"

    def test_determine_verdict_safe(self):
        """Test verdict for safe score."""
        verdict = determine_verdict(65)
        assert verdict == "AMAN"

    def test_determine_verdict_boundary(self):
        """Test verdict at exact tolerance boundary."""
        verdict_70 = determine_verdict(70)
        verdict_71 = determine_verdict(71)

        assert verdict_70 == "AMAN"
        assert verdict_71 == "BERBAHAYA"

    def test_fuse_results(self):
        """Test result fusion."""
        prediksi = {"score": 50, "reasons": ["reason 1"]}
        kerentanan = {"score": 60, "reasons": ["reason 2"]}
        reputasi = {"score": 70, "reasons": ["reason 3"]}

        result = fuse_results(prediksi, kerentanan, reputasi)

        assert result["skor_prediksi"] == 50
        assert result["skor_kerentanan"] == 60
        assert result["skor_reputasi"] == 70
        assert result["skor_final"] == 57.0
        assert result["keputusan"] == "AMAN"
        assert len(result["alasan"]) == 3

    def test_fuse_results_dangerous(self):
        """Test result fusion with dangerous verdict."""
        prediksi = {"score": 80, "reasons": ["phishing"]}
        kerentanan = {"score": 75, "reasons": ["no ssl"]}
        reputasi = {"score": 100, "reasons": ["blacklist"]}

        result = fuse_results(prediksi, kerentanan, reputasi)

        assert result["keputusan"] == "BERBAHAYA"
        assert result["skor_final"] > 70


class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self, test_db):
        """Test complete scanning workflow."""
        url = "https://example.com"

        prediksi = await score_prediction(url)
        kerentanan = await score_vulnerability(url)
        reputasi = await score_reputation(url, test_db)

        result = fuse_results(prediksi, kerentanan, reputasi)

        assert "skor_prediksi" in result
        assert "skor_kerentanan" in result
        assert "skor_reputasi" in result
        assert "skor_final" in result
        assert "keputusan" in result
        assert result["keputusan"] in ("AMAN", "BERBAHAYA")

    @pytest.mark.asyncio
    async def test_full_scan_with_blacklist(self, test_db):
        """Test scanning with blacklist."""
        from app.utils.url_parser import get_url_hash, normalize_url, extract_domain

        # Add to blacklist
        url = "https://known-malware.com/payload"
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        url_hash = get_url_hash(normalized)

        entry = UrlBlacklist(
            url_hash=url_hash,
            url=normalized,
            domain=domain,
            risiko="high",
            sumber="test"
        )
        test_db.add(entry)
        test_db.commit()

        # Scan
        prediksi = await score_prediction(url)
        reputasi = await score_reputation(url, test_db)

        # Reputation should be max because of blacklist
        assert reputasi["score"] == 100

        result = fuse_results(
            prediksi,
            {"score": 0, "reasons": []},
            reputasi
        )

        assert result["keputusan"] == "BERBAHAYA"