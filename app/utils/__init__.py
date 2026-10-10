"""Utility modules for URL scanning."""

from app.utils.url_parser import (
    normalize_url,
    extract_domain,
    parse_url,
    get_url_hash,
    is_private_ip,
    is_localhost,
    count_subdomains,
    calculate_domain_entropy,
    has_suspicious_tld,
    has_punycode,
    has_phishing_keywords,
    get_base_domain,
)

from app.utils.http_client import (
    get_async_client,
    close_async_client,
    fetch_url,
    get_with_retry,
)

__all__ = [
    "normalize_url",
    "extract_domain",
    "parse_url",
    "get_url_hash",
    "is_private_ip",
    "is_localhost",
    "count_subdomains",
    "calculate_domain_entropy",
    "has_suspicious_tld",
    "has_punycode",
    "has_phishing_keywords",
    "get_base_domain",
    "get_async_client",
    "close_async_client",
    "fetch_url",
    "get_with_retry",
]