"""Reputation scoring module - blacklist checks and external APIs."""

import logging
import hashlib
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.config import settings
from app.models import UrlBlacklist
from app.utils.url_parser import extract_domain, normalize_url, get_url_hash

logger = logging.getLogger(__name__)

# Score constants
BLACKLIST_SCORE = 100
GSB_THREAT_SCORE = 100
GSB_SAFE_SCORE = 0
MAX_VIRUSTOTAL_SCORE = 100


def _check_local_blacklist(db: Session, url: str) -> Optional[Dict[str, Any]]:
    """
    Check if URL is in local blacklist.

    Args:
        db: Database session
        url: URL to check

    Returns:
        Dict with blacklist info if found, None otherwise
    """
    url_hash = get_url_hash(url)
    entry = db.query(UrlBlacklist).filter(UrlBlacklist.url_hash == url_hash).first()

    if entry:
        return {
            "found": True,
            "url": entry.url,
            "domain": entry.domain,
            "risiko": entry.risiko,
            "sumber": entry.sumber,
        }

    return None


def _check_domain_blacklist(db: Session, domain: str) -> Optional[Dict[str, Any]]:
    """
    Check if domain is in local blacklist.

    Args:
        db: Database session
        domain: Domain to check

    Returns:
        Dict with blacklist info if found, None otherwise
    """
    # Check exact domain match
    entry = db.query(UrlBlacklist).filter(UrlBlacklist.domain == domain).first()
    if entry:
        return {
            "found": True,
            "url": entry.url,
            "domain": entry.domain,
            "risiko": entry.risiko,
            "sumber": entry.sumber,
        }

    # Check if any subdomain is blacklisted
    parts = domain.split(".")
    for i in range(len(parts)):
        subdomain = ".".join(parts[i:])
        entry = db.query(UrlBlacklist).filter(UrlBlacklist.domain == subdomain).first()
        if entry:
            return {
                "found": True,
                "url": entry.url,
                "domain": entry.domain,
                "risiko": entry.risiko,
                "sumber": entry.sumber,
            }

    return None


async def _check_google_safe_browsing(url: str) -> Optional[Dict[str, Any]]:
    """
    Check URL against Google Safe Browsing API.

    Args:
        url: URL to check

    Returns:
        Dict with GSB result or None if not configured
    """
    if not settings.is_google_sb_configured():
        return None

    import json

    api_key = settings.google_safe_browsing_key
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {
            "clientId": "urlscanner",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        from app.utils.http_client import fetch_url
        response = await fetch_url(
            api_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            timeout=5
        )

        if response and response.get("status_code") == 200:
            body = json.loads(response.get("body", "{}"))
            if body.get("matches"):
                return {"found": True, "threats": body["matches"]}
            return {"found": False}
        elif response and response.get("status_code") == 400:
            # Invalid request - URL might be too long or malformed
            logger.warning(f"GSB invalid request for {url}")
            return None

    except Exception as e:
        logger.warning(f"Google Safe Browsing check failed: {e}")

    return None


async def _check_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Check URL against VirusTotal API.

    Args:
        url: URL to check

    Returns:
        Dict with VirusTotal result or None if not configured
    """
    if not settings.is_virustotal_configured():
        return None

    import base64

    api_key = settings.virustotal_api_key

    # Encode URL as base64 (remove padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        from app.utils.http_client import fetch_url
        response = await fetch_url(
            api_url,
            method="GET",
            headers={"x-apikey": api_key},
            timeout=10
        )

        if response and response.get("status_code") == 200:
            import json
            data = json.loads(response.get("body", "{}"))
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})

            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            total = sum(last_analysis.values())

            if total > 0:
                # Calculate score - give more weight to malicious/suspicious
                score = ((malicious + suspicious) / total) * 200
                return {
                    "score": min(score, MAX_VIRUSTOTAL_SCORE),
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                }
            return {"score": 0, "total": total}

    except Exception as e:
        logger.warning(f"VirusTotal check failed: {e}")

    return None


async def score_reputation(url: str, db: Session) -> Dict[str, Any]:
    """
    Calculate reputation score for a URL.

    Args:
        url: URL to score
        db: Database session

    Returns:
        Dictionary with score and reasons
    """
    reasons = []

    # 1. Check local blacklist first (highest priority)
    blacklist_result = _check_local_blacklist(db, url)
    if blacklist_result:
        return {
            "score": BLACKLIST_SCORE,
            "reasons": [f"URL found in local blacklist ({blacklist_result['sumber']})"]
        }

    # Also check domain blacklist
    domain = extract_domain(url)
    if domain:
        domain_result = _check_domain_blacklist(db, domain)
        if domain_result:
            return {
                "score": BLACKLIST_SCORE,
                "reasons": [f"Domain found in local blacklist ({domain_result['sumber']})"]
            }

    # 2. Check Google Safe Browsing if configured
    gsb_result = await _check_google_safe_browsing(url)
    if gsb_result is not None:
        if gsb_result.get("found"):
            return {
                "score": GSB_THREAT_SCORE,
                "reasons": ["URL flagged by Google Safe Browsing"]
            }
        return {
            "score": GSB_SAFE_SCORE,
            "reasons": ["URL not found in Google Safe Browsing"]
        }

    # 3. Check VirusTotal if configured
    vt_result = await _check_virustotal(url)
    if vt_result is not None:
        score = vt_result.get("score", 0)
        if score > 50:
            reasons.append(f"VirusTotal: {vt_result.get('malicious', 0)} malicious detections")
        elif score > 0:
            reasons.append(f"VirusTotal: Some security vendors flagged this URL")
        else:
            reasons.append("URL not flagged by VirusTotal")

        return {
            "score": score,
            "reasons": reasons if reasons else ["URL clean according to VirusTotal"]
        }

    # 4. No APIs configured - return neutral score
    return {
        "score": 0.0,
        "reasons": ["No reputation data available (no API keys configured)"]
    }


def get_score_sync(url: str, db: Session) -> Dict[str, Any]:
    """
    Synchronous wrapper for reputation scoring (for testing).

    Args:
        url: URL to score
        db: Database session

    Returns:
        Dictionary with score and reasons
    """
    # Check local blacklist only (sync version)
    blacklist_result = _check_local_blacklist(db, url)
    if blacklist_result:
        return {
            "score": BLACKLIST_SCORE,
            "reasons": [f"URL found in local blacklist ({blacklist_result['sumber']})"]
        }

    return {
        "score": 0.0,
        "reasons": ["No reputation data available"]
    }