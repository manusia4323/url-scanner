"""Script to update blacklist from external sources."""

import asyncio
import logging
import sys
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.models import UrlBlacklist
from app.database import Base
from app.utils.url_parser import extract_domain, get_url_hash, normalize_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Database setup
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


async def fetch_urlhaus_feed() -> List[Dict[str, Any]]:
    """
    Fetch URLhaus public feed.

    Returns:
        List of entries with url, domain, threat_type
    """
    logger.info("Fetching URLhaus feed...")
    entries = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"User-Agent": settings.user_agent}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    for entry in data.get("urls", []):
                        entries.append({
                            "url": entry.get("url"),
                            "threat_type": entry.get("threat"),
                            "source": "urlhaus",
                        })
                    logger.info(f"Fetched {len(entries)} entries from URLhaus")
                else:
                    logger.warning(f"URLhaus API error: {data.get('query_status')}")
            else:
                logger.warning(f"URLhaus API returned {response.status_code}")

    except Exception as e:
        logger.error(f"Failed to fetch URLhaus feed: {e}")

    return entries


async def fetch_phishtank_feed() -> List[Dict[str, Any]]:
    """
    Fetch PhishTank feed (requires API key, falls back to online verification).

    Returns:
        List of entries with url, domain, threat_type
    """
    logger.info("Fetching PhishTank feed...")
    entries = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # PhishTank free feed (limited, no API key required)
            response = await client.get(
                "https://data.phishtank.com/data/online-valid.json",
                headers={"User-Agent": settings.user_agent}
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for entry in data[:100]:  # Limit to first 100
                        entries.append({
                            "url": entry.get("url"),
                            "threat_type": "phishing",
                            "source": "phishtank",
                        })
                    logger.info(f"Fetched {len(entries)} entries from PhishTank")
                else:
                    logger.warning("PhishTank returned unexpected format")
            else:
                logger.warning(f"PhishTank API returned {response.status_code}")

    except Exception as e:
        logger.warning(f"PhishTank feed not available: {e}")

    return entries


def map_threat_to_risiko(threat_type: Optional[str]) -> str:
    """
    Map external threat type to internal risk level.

    Args:
        threat_type: External threat type string

    Returns:
        Risk level: low, medium, or high
    """
    if not threat_type:
        return "medium"

    threat_type = str(threat_type).lower()

    high_risk = {"malware", "trojan", "ransomware", "worm", "botnet"}
    medium_risk = {"phishing", "exploit", "suspicious", "defacement"}

    for pattern in high_risk:
        if pattern in threat_type:
            return "high"

    for pattern in medium_risk:
        if pattern in threat_type:
            return "medium"

    return "low"


def process_entry(
    entry: Dict[str, Any],
    db,
    stats: Dict[str, int]
) -> None:
    """
    Process a single blacklist entry and insert into database.

    Args:
        entry: Entry with url, threat_type, source
        db: Database session
        stats: Statistics dictionary to update
    """
    url = entry.get("url", "").strip()
    if not url:
        stats["invalid"] += 1
        return

    try:
        # Normalize and extract domain
        normalized_url = normalize_url(url)
        domain = extract_domain(normalized_url)

        if not domain:
            stats["invalid"] += 1
            logger.warning(f"Could not extract domain from {url}")
            return

        # Generate hash
        url_hash = get_url_hash(normalized_url)

        # Check if already exists
        existing = db.query(UrlBlacklist).filter(
            UrlBlacklist.url_hash == url_hash
        ).first()

        if existing:
            stats["skipped"] += 1
            return

        # Map threat type to risk level
        threat_type = entry.get("threat_type")
        risiko = map_threat_to_risiko(threat_type)
        sumber = entry.get("source", "external")

        # Create entry
        blacklist_entry = UrlBlacklist(
            url_hash=url_hash,
            url=normalized_url,
            domain=domain,
            risiko=risiko,
            sumber=sumber,
        )

        db.add(blacklist_entry)
        stats["inserted"] += 1

    except Exception as e:
        logger.error(f"Error processing entry {url}: {e}")
        stats["failed"] += 1


async def update_blacklist() -> Dict[str, int]:
    """
    Update blacklist from all configured sources.

    Returns:
        Statistics dictionary with counts
    """
    logger.info("Starting blacklist update...")

    stats = {
        "fetched": 0,
        "inserted": 0,
        "skipped": 0,
        "invalid": 0,
        "failed": 0,
    }

    # Initialize database
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Fetch from URLhaus
        urlhaus_entries = await fetch_urlhaus_feed()
        stats["fetched"] += len(urlhaus_entries)

        # Fetch from PhishTank
        phishtank_entries = await fetch_phishtank_feed()
        stats["fetched"] += len(phishtank_entries)

        # Process all entries
        all_entries = urlhaus_entries + phishtank_entries

        for entry in all_entries:
            process_entry(entry, db, stats)

        # Commit changes
        db.commit()
        logger.info("Changes committed to database")

    except Exception as e:
        logger.error(f"Error updating blacklist: {e}")
        db.rollback()
        stats["failed"] += 1
        return stats
    finally:
        db.close()

    return stats


def log_summary(stats: Dict[str, int]) -> None:
    """Log summary statistics."""
    logger.info("=" * 50)
    logger.info("Blacklist Update Summary")
    logger.info("=" * 50)
    logger.info(f"Total fetched:    {stats['fetched']}")
    logger.info(f"Inserted:         {stats['inserted']}")
    logger.info(f"Skipped (exists): {stats['skipped']}")
    logger.info(f"Invalid entries:  {stats['invalid']}")
    logger.info(f"Failed:           {stats['failed']}")
    logger.info("=" * 50)


async def main():
    """Main entry point."""
    try:
        stats = await update_blacklist()
        log_summary(stats)

        # Exit with appropriate code
        if stats["failed"] > 0 and stats["inserted"] == 0:
            logger.error("Update failed - no entries were inserted")
            sys.exit(1)

        logger.info("Blacklist update completed successfully")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())