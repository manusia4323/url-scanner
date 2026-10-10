"""Async HTTP client utilities."""

import httpx
import logging
from typing import Optional, Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)

# Global async client (will be initialized on app startup)
_async_client: Optional[httpx.AsyncClient] = None


async def get_async_client() -> httpx.AsyncClient:
    """
    Get or create the global async HTTP client.

    Returns:
        Configured httpx.AsyncClient instance
    """
    global _async_client
    if _async_client is None:
        _async_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout),
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20
            )
        )
    return _async_client


async def close_async_client() -> None:
    """Close the global async HTTP client."""
    global _async_client
    if _async_client is not None:
        await _async_client.aclose()
        _async_client = None


async def fetch_url(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """
    Fetch a URL with error handling.

    Args:
        url: URL to fetch
        method: HTTP method
        headers: Additional headers
        timeout: Request timeout in seconds

    Returns:
        Dict with status_code and body, or None on failure
    """
    client = await get_async_client()

    try:
        request_headers = {"User-Agent": settings.user_agent}
        if headers:
            request_headers.update(headers)

        request_timeout = timeout or settings.http_timeout

        response = await client.request(
            method=method,
            url=url,
            headers=request_headers,
            timeout=request_timeout
        )

        return {
            "status_code": response.status_code,
            "body": response.text,
            "headers": dict(response.headers)
        }
    except httpx.TimeoutException:
        logger.warning(f"Timeout fetching {url}")
        return None
    except httpx.RequestError as e:
        logger.warning(f"Request error for {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {e}")
        return None


async def get_with_retry(
    url: str,
    max_retries: int = 3,
    backoff_factor: float = 1.0
) -> Optional[Dict[str, Any]]:
    """
    Fetch a URL with automatic retries.

    Args:
        url: URL to fetch
        max_retries: Maximum number of retry attempts
        backoff_factor: Exponential backoff factor

    Returns:
        Dict with response data, or None on failure
    """
    import asyncio

    for attempt in range(max_retries):
        result = await fetch_url(url)
        if result is not None:
            return result

        if attempt < max_retries - 1:
            wait_time = backoff_factor * (2 ** attempt)
            logger.info(f"Retrying {url} in {wait_time}s (attempt {attempt + 2})")
            await asyncio.sleep(wait_time)

    return None