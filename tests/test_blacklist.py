"""Integration tests for blacklist endpoints."""

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


class TestBlacklistListEndpoint:
    """Test GET /blacklist endpoint."""

    def test_list_empty_blacklist(self, client):
        """Test listing empty blacklist."""
        response = client.get("/blacklist")

        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 0
        assert data["page"] == 1
        assert data["size"] == 20
        assert data["items"] == []

    def test_list_with_pagination(self, client, test_db):
        """Test blacklist listing with pagination."""
        # Add test entries
        for i in range(25):
            url = f"https://malicious{i}.com/phishing"
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

        # Test first page
        response = client.get("/blacklist?page=1&size=10")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 25
        assert data["page"] == 1
        assert data["size"] == 10
        assert len(data["items"]) == 10

        # Test second page
        response = client.get("/blacklist?page=2&size=10")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 10

        # Test third page (partial)
        response = client.get("/blacklist?page=3&size=10")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 5

    def test_list_with_domain_filter(self, client, test_db):
        """Test blacklist listing with domain filter."""
        # Add entries with different domains
        for domain in ["evil.com", "malware.org", "phishing.net"]:
            url = f"https://{domain}/payload"
            normalized = normalize_url(url)
            extracted = extract_domain(normalized)
            url_hash = get_url_hash(normalized)

            entry = UrlBlacklist(
                url_hash=url_hash,
                url=normalized,
                domain=extracted,
                risiko="high",
                sumber="test"
            )
            test_db.add(entry)

        test_db.commit()

        # Filter by domain
        response = client.get("/blacklist?domain=evil")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] >= 1
        assert any("evil.com" in item["domain"] for item in data["items"])


class TestBlacklistCreateEndpoint:
    """Test POST /blacklist endpoint."""

    def test_add_valid_entry(self, client):
        """Test adding a valid entry to blacklist."""
        response = client.post(
            "/blacklist",
            json={
                "url": "https://malicious.example.com/phishing",
                "risiko": "high",
                "toleransi": 70,
                "sumber": "manual"
            }
        )

        assert response.status_code == 201
        data = response.json()

        assert "id" in data
        assert data["url"] == "https://malicious.example.com/phishing"
        assert data["risiko"] == "high"
        assert data["sombre"] == "manual"

    def test_add_with_defaults(self, client):
        """Test adding entry with default values."""
        response = client.post(
            "/blacklist",
            json={
                "url": "https://default-test.com",
                "risiko": "medium",
            }
        )

        assert response.status_code == 201
        data = response.json()

        assert data["toleransi"] == 70
        assert data["sombre"] == "manual"

    def test_add_duplicate_url(self, client):
        """Test adding duplicate URL."""
        url = "https://duplicate.example.com"

        # First add
        response1 = client.post(
            "/blacklist",
            json={
                "url": url,
                "risiko": "high",
            }
        )
        assert response1.status_code == 201

        # Try to add same URL again
        response2 = client.post(
            "/blacklist",
            json={
                "url": url,
                "risiko": "high",
            }
        )
        assert response2.status_code == 409

    def test_add_invalid_risiko(self, client):
        """Test adding with invalid risk level."""
        response = client.post(
            "/blacklist",
            json={
                "url": "https://example.com",
                "risiko": "invalid_level",
            }
        )

        assert response.status_code == 422

    def test_add_invalid_url(self, client):
        """Test adding invalid URL."""
        response = client.post(
            "/blacklist",
            json={
                "url": "not a valid url",
                "risiko": "high",
            }
        )

        assert response.status_code == 400

    def test_add_empty_url(self, client):
        """Test adding empty URL."""
        response = client.post(
            "/blacklist",
            json={
                "url": "",
                "risiko": "high",
            }
        )

        assert response.status_code == 400


class TestBlacklistGetEndpoint:
    """Test GET /blacklist/{item_id} endpoint."""

    def test_get_existing_entry(self, client, test_db):
        """Test getting an existing blacklist entry."""
        # Add test entry
        url = "https://test.example.com"
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

        response = client.get(f"/blacklist/{entry.id}")

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == entry.id
        assert data["url"] == normalized

    def test_get_nonexistent_entry(self, client):
        """Test getting nonexistent entry."""
        response = client.get("/blacklist/99999")

        assert response.status_code == 404


class TestBlacklistDeleteEndpoint:
    """Test DELETE /blacklist/{item_id} endpoint."""

    def test_delete_entry(self, client, test_db):
        """Test deleting a blacklist entry."""
        # Add test entry
        url = "https://delete-test.com"
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

        entry_id = entry.id

        # Delete
        response = client.delete(f"/blacklist/{entry_id}")
        assert response.status_code == 204

        # Verify deleted
        assert test_db.query(UrlBlacklist).filter(
            UrlBlacklist.id == entry_id
        ).first() is None

    def test_delete_nonexistent_entry(self, client):
        """Test deleting nonexistent entry."""
        response = client.delete("/blacklist/99999")

        assert response.status_code == 404


class TestBlacklistCheckEndpoint:
    """Test GET /blacklist/check/{url} endpoint."""

    def test_check_url_in_blacklist(self, client, test_db):
        """Test checking if URL is in blacklist."""
        # Add test entry
        url = "https://check-test.com/payload"
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

        # Check URL
        response = client.get(f"/blacklist/check/{normalized}")
        assert response.status_code == 200
        data = response.json()

        assert data["found"] is True
        assert data["risiko"] == "high"

    def test_check_url_not_in_blacklist(self, client):
        """Test checking URL not in blacklist."""
        response = client.get("/blacklist/check/https://safe-url.com")

        assert response.status_code == 200
        data = response.json()

        assert data["found"] is False