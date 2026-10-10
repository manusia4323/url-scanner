"""Integration tests for scan endpoints."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db
from app.models import UrlBlacklist
from app.utils.url_parser import get_url_hash, normalize_url, extract_domain


# Setup test database
@pytest.fixture(scope="session")
def test_db_engine():
    """Create test database engine."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def test_db(test_db_engine):
    """Create test database session."""
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_db_engine
    )
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def client(test_db):
    """Create test client with test database."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


class TestScanEndpoint:
    """Test POST /scan endpoint."""

    def test_scan_valid_url(self, client):
        """Test scanning a valid URL."""
        response = client.post("/scan", json={"url": "https://example.com"})

        assert response.status_code == 200
        data = response.json()

        assert "url" in data
        assert "url_hash" in data
        assert "skor" in data
        assert "keputusan" in data
        assert "alasan" in data
        assert "waktu" in data

        skor = data["skor"]
        assert "prediksi" in skor
        assert "kerentanan" in skor
        assert "reputasi" in skor
        assert "final" in skor

        # Scores should be between 0 and 100
        assert 0 <= skor["prediksi"] <= 100
        assert 0 <= skor["kerentanan"] <= 100
        assert 0 <= skor["reputasi"] <= 100
        assert 0 <= skor["final"] <= 100

    def test_scan_invalid_url_format(self, client):
        """Test scanning with invalid URL format."""
        response = client.post("/scan", json={"url": "not-a-url"})

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data or "code" in data

    def test_scan_localhost(self, client):
        """Test scanning localhost (SSRF protection)."""
        response = client.post("/scan", json={"url": "http://localhost:8000"})

        assert response.status_code == 400

    def test_scan_private_ip(self, client):
        """Test scanning private IP (SSRF protection)."""
        response = client.post("/scan", json={"url": "http://192.168.1.1"})

        assert response.status_code == 400

    def test_scan_empty_url(self, client):
        """Test scanning with empty URL."""
        response = client.post("/scan", json={"url": ""})

        assert response.status_code == 400

    def test_scan_http_url(self, client):
        """Test scanning HTTP URL."""
        response = client.post("/scan", json={"url": "http://example.com"})

        assert response.status_code == 200
        data = response.json()
        assert data["keputusan"] in ("AMAN", "BERBAHAYA")

    def test_scan_phishing_indicators(self, client):
        """Test scanning URL with phishing indicators."""
        # URL with phishing keywords
        response = client.post(
            "/scan",
            json={"url": "https://verify-your-account-login.xyz"}
        )

        assert response.status_code == 200
        data = response.json()

        # Should have higher prediction score due to phishing keywords
        assert len(data["alasan"]) > 0

    def test_scan_response_persistence(self, client, test_db):
        """Test that scan results are saved to database."""
        response = client.post("/scan", json={"url": "https://test.example.com"})

        assert response.status_code == 200
        data = response.json()
        url_hash = data["url_hash"]

        # Check database
        from app.models import ScanVerdict
        verdict = test_db.query(ScanVerdict).filter(
            ScanVerdict.url_hash == url_hash
        ).first()

        assert verdict is not None
        assert verdict.keputusan in ("AMAN", "BERBAHAYA")

    def test_scan_missing_field(self, client):
        """Test scanning with missing URL field."""
        response = client.post("/scan", json={})

        assert response.status_code == 422  # Validation error


class TestHealthEndpoint:
    """Test health check endpoints."""

    def test_health_check(self, client):
        """Test /health endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_root_endpoint(self, client):
        """Test root / endpoint."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data


class TestConcurrentScans:
    """Test concurrent scan handling."""

    def test_sequential_scans(self, client):
        """Test multiple sequential scans."""
        urls = [
            "https://example1.com",
            "https://example2.com",
            "https://example3.com",
        ]

        for url in urls:
            response = client.post("/scan", json={"url": url})
            assert response.status_code == 200

    def test_same_url_twice(self, client):
        """Test scanning same URL twice."""
        url = "https://same-url.com"

        response1 = client.post("/scan", json={"url": url})
        response2 = client.post("/scan", json={"url": url})

        assert response1.status_code == 200
        assert response2.status_code == 200

        data1 = response1.json()
        data2 = response2.json()

        # Same URL should produce same hash
        assert data1["url_hash"] == data2["url_hash"]


class TestErrorHandling:
    """Test error handling."""

    def test_malformed_json(self, client):
        """Test sending malformed JSON."""
        response = client.post(
            "/scan",
            content=b"not json",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code >= 400

    def test_very_long_url(self, client):
        """Test scanning very long URL."""
        long_url = "https://example.com/" + "a" * 3000

        response = client.post("/scan", json={"url": long_url})

        # Should either reject or handle gracefully
        assert response.status_code in (200, 400, 422)

    def test_invalid_scheme(self, client):
        """Test URL with invalid scheme."""
        response = client.post("/scan", json={"url": "ftp://example.com"})

        assert response.status_code == 400