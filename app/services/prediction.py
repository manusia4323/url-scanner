"""Prediction scoring module - heuristics + optional ML."""

import logging
from typing import Dict, Any, Optional
import joblib
from app.config import settings
from app.utils.url_parser import (
    extract_domain,
    count_subdomains,
    calculate_domain_entropy,
    has_suspicious_tld,
    has_punycode,
    has_phishing_keywords,
    is_private_ip,
    parse_url,
)

logger = logging.getLogger(__name__)

# ML model weight
ML_WEIGHT = 0.6
HEURISTIC_WEIGHT = 0.4

# Score caps
MAX_SCORE = 100

# Feature weights
WEIGHTS = {
    "url_length": 5,
    "subdomains": 10,
    "at_symbol": 15,
    "ip_address": 20,
    "suspicious_tld": 10,
    "phishing_keywords": 15,
    "high_entropy": 10,
    "punycode": 15,
}

# URL length threshold
URL_LENGTH_THRESHOLD = 75

# Subdomain threshold
SUBDOMAIN_THRESHOLD = 3

# Entropy threshold
ENTROPY_THRESHOLD = 3.5

# Feature threshold values
URL_LENGTH_THRESHOLD = 75
SUBDOMAIN_THRESHOLD = 3
ENTROPY_THRESHOLD = 3.5

# ML model instance (lazy loaded)
_ml_model: Optional[Any] = None


def _load_ml_model() -> Optional[Any]:
    """Load ML model if available."""
    global _ml_model
    if _ml_model is None:
        try:
            if settings.has_ml_model():
                _ml_model = joblib.load(settings.model_path)
                logger.info(f"Loaded ML model from {settings.model_path}")
        except Exception as e:
            logger.warning(f"Could not load ML model: {e}")
            _ml_model = False  # Mark as unavailable
    return _ml_model if _ml_model else None


def _extract_features(url: str, domain: str) -> Dict[str, Any]:
    """
    Extract heuristic features from URL.

    Args:
        url: Full URL
        domain: Extracted domain

    Returns:
        Dictionary of feature names and values
    """
    features = {}

    # URL length
    features["url_length"] = len(url)
    features["url_length_flag"] = 1 if len(url) > URL_LENGTH_THRESHOLD else 0

    # Subdomain count
    subdomains = count_subdomains(domain)
    features["subdomain_count"] = subdomains
    features["subdomain_flag"] = 1 if subdomains > SUBDOMAIN_THRESHOLD else 0

    # @ symbol in URL
    features["has_at_symbol"] = 1 if "@" in url else 0

    # IP address instead of domain
    parts = parse_url(url)
    is_ip = False
    if parts:
        _, netloc, _ = parts
        # Check if netloc is an IP
        try:
            import ipaddress
            ipaddress.ip_address(netloc.split(":")[0])
            is_ip = True
        except ValueError:
            # Not an IP, check if private
            is_ip = is_private_ip(netloc.split(":")[0])
    features["is_ip_address"] = 1 if is_ip else 0

    # Suspicious TLD
    features["suspicious_tld"] = 1 if has_suspicious_tld(domain) else 0

    # Phishing keywords
    features["phishing_keywords"] = 1 if has_phishing_keywords(url) else 0

    # High domain entropy
    entropy = calculate_domain_entropy(domain)
    features["domain_entropy"] = entropy
    features["high_entropy"] = 1 if entropy > ENTROPY_THRESHOLD else 0

    # Punycode
    features["punycode"] = 1 if has_punycode(domain) else 0

    return features


def _calculate_heuristic_score(url: str, domain: str) -> float:
    """
    Calculate heuristic-based phishing score.

    Args:
        url: Full URL
        domain: Extracted domain

    Returns:
        Score from 0-100
    """
    features = _extract_features(url, domain)
    score = 0.0

    # Apply weights
    if features["url_length_flag"]:
        score += WEIGHTS["url_length"]
    if features["subdomain_flag"]:
        score += WEIGHTS["subdomains"]
    if features["has_at_symbol"]:
        score += WEIGHTS["at_symbol"]
    if features["is_ip_address"]:
        score += WEIGHTS["ip_address"]
    if features["suspicious_tld"]:
        score += WEIGHTS["suspicious_tld"]
    if features["phishing_keywords"]:
        score += WEIGHTS["phishing_keywords"]
    if features["high_entropy"]:
        score += WEIGHTS["high_entropy"]
    if features["punycode"]:
        score += WEIGHTS["punycode"]

    return min(score, MAX_SCORE)


def _get_ml_prediction(url: str) -> Optional[float]:
    """
    Get ML model prediction if available.

    Args:
        url: URL to analyze

    Returns:
        ML prediction score (0-100) or None
    """
    model = _load_ml_model()
    if model is None:
        return None

    try:
        # Simple feature extraction for ML model
        # This assumes the model expects specific features
        features = _extract_ml_features(url)

        # Get prediction
        if hasattr(model, "predict_proba"):
            # Binary classification - get probability of phishing
            proba = model.predict_proba([features])[0]
            # Assume class 1 is phishing
            ml_score = float(proba[1]) * 100
        else:
            # Simple prediction
            pred = model.predict([features])[0]
            ml_score = float(pred) * 100

        return min(ml_score, MAX_SCORE)
    except Exception as e:
        logger.warning(f"ML prediction failed: {e}")
        return None


def _extract_ml_features(url: str) -> list:
    """
    Extract features for ML model.

    Args:
        url: URL to analyze

    Returns:
        List of features
    """
    domain = extract_domain(url) or ""
    features = _extract_features(url, domain)

    # Return numeric features as list
    return [
        features.get("url_length", 0),
        features.get("subdomain_count", 0),
        features.get("has_at_symbol", 0),
        features.get("is_ip_address", 0),
        features.get("suspicious_tld", 0),
        features.get("phishing_keywords", 0),
        features.get("domain_entropy", 0),
        features.get("punycode", 0),
    ]


async def score_prediction(url: str) -> Dict[str, Any]:
    """
    Calculate prediction score for a URL.

    Args:
        url: URL to score

    Returns:
        Dictionary with score and reasons
    """
    domain = extract_domain(url)
    if not domain:
        return {
            "score": 0.0,
            "reasons": ["Invalid URL - could not extract domain"]
        }

    reasons = []

    # Get heuristic score
    heuristic_score = _calculate_heuristic_score(url, domain)

    # Generate reasons based on features
    features = _extract_features(url, domain)
    if features["url_length_flag"]:
        reasons.append("URL length exceeds 75 characters")
    if features["subdomain_flag"]:
        reasons.append(f"More than {SUBDOMAIN_THRESHOLD} subdomains detected")
    if features["has_at_symbol"]:
        reasons.append("URL contains @ symbol (possible credential theft)")
    if features["is_ip_address"]:
        reasons.append("URL uses raw IP address instead of domain")
    if features["suspicious_tld"]:
        reasons.append("Suspicious top-level domain detected")
    if features["phishing_keywords"]:
        reasons.append("URL contains phishing-related keywords")
    if features["high_entropy"]:
        reasons.append("High domain entropy (random-looking domain)")
    if features["punycode"]:
        reasons.append("Punycode/internationalized domain detected")

    # Try to blend with ML if available
    ml_score = _get_ml_prediction(url)
    if ml_score is not None:
        # Blend scores
        final_score = (ML_WEIGHT * ml_score) + (HEURISTIC_WEIGHT * heuristic_score)
        reasons.append("ML model prediction blended with heuristics")
    else:
        final_score = heuristic_score

    final_score = min(final_score, MAX_SCORE)

    return {
        "score": round(final_score, 2),
        "reasons": reasons if reasons else ["No suspicious features detected"]
    }


def get_score_sync(url: str) -> Dict[str, Any]:
    """
    Synchronous wrapper for scoring (for testing).

    Args:
        url: URL to score

    Returns:
        Dictionary with score and reasons
    """
    domain = extract_domain(url)
    if not domain:
        return {
            "score": 0.0,
            "reasons": ["Invalid URL - could not extract domain"]
        }

    reasons = []
    heuristic_score = _calculate_heuristic_score(url, domain)

    features = _extract_features(url, domain)
    if features["url_length_flag"]:
        reasons.append("URL length exceeds 75 characters")
    if features["subdomain_flag"]:
        reasons.append(f"More than {SUBDOMAIN_THRESHOLD} subdomains detected")
    if features["has_at_symbol"]:
        reasons.append("URL contains @ symbol (possible credential theft)")
    if features["is_ip_address"]:
        reasons.append("URL uses raw IP address instead of domain")
    if features["suspicious_tld"]:
        reasons.append("Suspicious top-level domain detected")
    if features["phishing_keywords"]:
        reasons.append("URL contains phishing-related keywords")
    if features["high_entropy"]:
        reasons.append("High domain entropy (random-looking domain)")
    if features["punycode"]:
        reasons.append("Punycode/internationalized domain detected")

    final_score = min(heuristic_score, MAX_SCORE)

    return {
        "score": round(final_score, 2),
        "reasons": reasons if reasons else ["No suspicious features detected"]
    }