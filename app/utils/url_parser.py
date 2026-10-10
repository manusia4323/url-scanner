"""URL parsing and normalization utilities."""

import hashlib
import ipaddress
import re
from urllib.parse import urlparse
from typing import Optional, Tuple


def normalize_url(url: str) -> str:
    """
    Normalize a URL by standardizing format.

    Args:
        url: The URL to normalize

    Returns:
        Normalized URL string
    """
    url = url.strip()

    # Add https if no scheme provided
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def parse_url(url: str) -> Optional[Tuple[str, str, int]]:
    """
    Parse URL into components.

    Args:
        url: The URL to parse

    Returns:
        Tuple of (scheme, domain, port) or None if invalid
    """
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return parsed.scheme, parsed.netloc, parsed.port
    except Exception:
        return None


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL.

    Args:
        url: The URL to extract from

    Returns:
        Domain string or None if invalid
    """
    parsed = urlparse(url)
    netloc = parsed.netloc

    # Remove port if present
    if ":" in netloc:
        netloc = netloc.rsplit(":", 1)[0]

    # Handle username:password@ prefix
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    return netloc.lower() if netloc else None


def get_url_hash(url: str) -> str:
    """
    Generate SHA256 hash of normalized URL.

    Args:
        url: The URL to hash

    Returns:
        SHA256 hash as hex string
    """
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def is_private_ip(domain: str) -> bool:
    """
    Check if domain resolves to a private IP address.

    Args:
        domain: The domain to check

    Returns:
        True if domain is a private IP
    """
    try:
        # Check if it's an IP address directly
        ipaddress.ip_address(domain)
        # It's an IP, check if private
        ip = ipaddress.ip_address(domain)
        return ip.is_private
    except ValueError:
        # It's not an IP, try to resolve it
        try:
            import socket
            result = socket.gethostbyname(domain)
            ip = ipaddress.ip_address(result)
            return ip.is_private
        except (socket.gaierror, ValueError):
            # Can't resolve, assume not private
            return False


def is_localhost(url: str) -> bool:
    """
    Check if URL points to localhost.

    Args:
        url: The URL to check

    Returns:
        True if URL points to localhost
    """
    domain = extract_domain(url)
    if not domain:
        return False

    localhost_patterns = [
        "localhost",
        "127.",
        "::1",
        "0.0.0.0",
    ]

    for pattern in localhost_patterns:
        if domain == pattern or domain.startswith(pattern):
            return True

    # Also check resolved IP
    return is_private_ip(domain)


def count_subdomains(domain: str) -> int:
    """
    Count number of subdomains in a domain.

    Args:
        domain: The domain to analyze

    Returns:
        Number of subdomains
    """
    parts = domain.split(".")
    # Remove TLD and root domain
    if len(parts) >= 2:
        return len(parts) - 2
    return 0


def calculate_domain_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of domain string.

    Args:
        domain: The domain to analyze

    Returns:
        Entropy score
    """
    import math
    from collections import Counter

    if not domain:
        return 0.0

    length = len(domain)
    counter = Counter(domain)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {"xyz", "tk", "top", "ml", "ga", "cf", "gq", "buzz", "cam", "rest"}

# Phishing keywords
PHISHING_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "credential", "auth", "access",
    "wallet", "crypto", "free", "gift", "prize", "win", "claim"
}

# Suspicious keywords regex pattern
PHISHING_PATTERN = re.compile(
    r"(login|verify|secure[\-_]?|account|update|confirm|signin|"
    r"banking|password|credential|auth|access|wallet|crypto|"
    r"free|gift|prize|win|claim)",
    re.IGNORECASE
)


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a suspicious TLD."""
    parts = domain.lower().split(".")
    if parts:
        tld = parts[-1]
        return tld in SUSPICIOUS_TLDS
    return False


def has_punycode(domain: str) -> bool:
    """Check if domain uses punycode (internationalized domain)."""
    return domain.startswith("xn--")


def has_phishing_keywords(url: str) -> bool:
    """Check if URL contains phishing keywords."""
    return bool(PHISHING_PATTERN.search(url))


def extract_domain_parts(domain: str) -> Tuple[str, str, str]:
    """
    Split domain into subdomain, domain, and TLD.

    Returns:
        Tuple of (subdomain, sld, tld)
    """
    parts = domain.lower().split(".")
    if len(parts) >= 3:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    elif len(parts) == 2:
        return "", parts[0], parts[1]
    return "", domain, ""


def get_base_domain(domain: str) -> str:
    """
    Get the base domain (second-level domain + TLD).

    Args:
        domain: Full domain

    Returns:
        Base domain string
    """
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain