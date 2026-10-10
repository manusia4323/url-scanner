"""HTTP client wrapper for the URL Scanner API."""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import httpx
from rich.progress import Progress, TaskID

from cli.config import CLIConfig


@dataclass
class ScanResponse:
    """Structured scan response."""

    url: str
    url_hash: str
    skor: Dict[str, float]
    keputusan: str
    toleransi: int
    alasan: List[str]
    waktu: str


class APIClient:
    """Client for the URL Scanner API."""

    def __init__(self, config: CLIConfig):
        """
        Initialize API client.

        Args:
            config: CLI configuration
        """
        self.config = config
        self.base_url = config.api_url
        self.timeout = config.timeout

        # Prepare headers
        headers = {"User-Agent": "URL-Scanner-CLI/1.0.0"}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"

        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=headers,
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check.

        Returns:
            Health check response
        """
        try:
            response = self.client.get("/health")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise APIClientError(f"Health check failed: {e}")

    def scan_url(
        self,
        url: str,
        mode: str = "normal",
        tolerance: Optional[int] = None,
    ) -> ScanResponse:
        """
        Scan a URL.

        Args:
            url: URL to scan
            mode: Scan mode (passive, normal, aggressive)
            tolerance: Override tolerance threshold

        Returns:
            Scan response
        """
        try:
            # For passive mode, we need to modify the request
            if mode == "passive":
                # Passive mode uses a different endpoint or parameters
                # We'll use a custom request for now
                payload = {
                    "url": url,
                    "mode": "passive",
                    "tolerance": tolerance or self.config.tolerance,
                }
                response = self.client.post("/scan/passive", json=payload)
            elif mode == "aggressive":
                # Aggressive mode
                payload = {
                    "url": url,
                    "mode": "aggressive",
                    "tolerance": (tolerance or self.config.tolerance) - 10,
                }
                response = self.client.post("/scan/aggressive", json=payload)
            else:
                # Normal mode
                payload = {
                    "url": url,
                    "tolerance": tolerance or self.config.tolerance,
                }
                response = self.client.post("/scan", json=payload)

            response.raise_for_status()
            data = response.json()

            # Convert to structured response
            return ScanResponse(
                url=data["url"],
                url_hash=data["url_hash"],
                skor=data["skor"],
                keputusan=data["keputusan"],
                toleransi=data["toleransi"],
                alasan=data.get("alasan", []),
                waktu=data["waktu"],
            )

        except httpx.HTTPError as e:
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get("detail", str(e))
                except json.JSONDecodeError:
                    error_msg = e.response.text
            else:
                error_msg = str(e)

            raise APIClientError(f"Scan failed: {error_msg}")

    def batch_scan(
        self,
        urls: List[str],
        mode: str = "normal",
        tolerance: Optional[int] = None,
        progress: Optional[Progress] = None,
        task_id: Optional[TaskID] = None,
    ) -> List[ScanResponse]:
        """
        Scan multiple URLs with progress tracking.

        Args:
            urls: List of URLs to scan
            mode: Scan mode
            tolerance: Override tolerance threshold
            progress: Rich progress bar
            task_id: Task ID for progress tracking

        Returns:
            List of scan responses
        """
        results = []
        for i, url in enumerate(urls):
            try:
                result = self.scan_url(url, mode=mode, tolerance=tolerance)
                results.append(result)
            except APIClientError as e:
                # Create an error response
                results.append(
                    ScanResponse(
                        url=url,
                        url_hash="error",
                        skor={"prediksi": 0, "kerentanan": 0, "reputasi": 0, "final": 0},
                        keputusan="ERROR",
                        toleransi=tolerance or self.config.tolerance,
                        alasan=[f"Scan failed: {str(e)}"],
                        waktu="",
                    )
                )

            if progress and task_id is not None:
                progress.update(task_id, advance=1)

        return results

    def list_blacklist(
        self,
        page: int = 1,
        size: int = 20,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List blacklist entries.

        Args:
            page: Page number
            size: Items per page
            domain: Filter by domain

        Returns:
            Blacklist response
        """
        try:
            params = {"page": page, "size": size}
            if domain:
                params["domain"] = domain

            response = self.client.get("/blacklist", params=params)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            raise APIClientError(f"Failed to list blacklist: {e}")

    def add_to_blacklist(
        self,
        url: str,
        risiko: str,
        toleransi: int = 70,
        sumber: str = "manual",
    ) -> Dict[str, Any]:
        """
        Add URL to blacklist.

        Args:
            url: URL to blacklist
            risiko: Risk level (low, medium, high)
            toleransi: Tolerance threshold
            sumber: Source of blacklist entry

        Returns:
            Created blacklist entry
        """
        try:
            payload = {
                "url": url,
                "risiko": risiko,
                "toleransi": toleransi,
                "sumber": sumber,
            }

            response = self.client.post("/blacklist", json=payload)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            if e.response is not None and e.response.status_code == 409:
                raise APIClientError("URL already exists in blacklist")
            raise APIClientError(f"Failed to add to blacklist: {e}")

    def remove_from_blacklist(self, url_hash: str) -> None:
        """
        Remove URL from blacklist.

        Args:
            url_hash: Hash of URL to remove
        """
        try:
            # First find the entry ID
            entries = self.list_blacklist(page=1, size=100)
            for item in entries.get("items", []):
                if item.get("url_hash") == url_hash:
                    response = self.client.delete(f"/blacklist/{item['id']}")
                    response.raise_for_status()
                    return

            raise APIClientError(f"URL with hash {url_hash} not found in blacklist")

        except httpx.HTTPError as e:
            raise APIClientError(f"Failed to remove from blacklist: {e}")

    def check_blacklist(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is in blacklist.

        Args:
            url: URL to check

        Returns:
            Blacklist check result
        """
        try:
            # URL encode the URL for the path
            import urllib.parse
            encoded_url = urllib.parse.quote(url, safe="")
            response = self.client.get(f"/blacklist/check/{encoded_url}")
            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            raise APIClientError(f"Failed to check blacklist: {e}")

    def list_logs(
        self,
        page: int = 1,
        size: int = 20,
        keputusan: Optional[str] = None,
        since: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List scan logs.

        Args:
            page: Page number
            size: Items per page
            keputusan: Filter by verdict (AMAN, BERBAHAYA)
            since: Filter by time (ISO format)

        Returns:
            Logs response
        """
        try:
            params = {"page": page, "size": size}
            if keputusan:
                params["keputusan"] = keputusan
            if since:
                params["since"] = since

            response = self.client.get("/logs", params=params)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            raise APIClientError(f"Failed to list logs: {e}")

    def get_log_stats(self, since: Optional[str] = None) -> Dict[str, Any]:
        """
        Get scan statistics.

        Args:
            since: Filter by time (ISO format)

        Returns:
            Statistics response
        """
        try:
            params = {}
            if since:
                params["since"] = since

            response = self.client.get("/logs/stats", params=params)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            raise APIClientError(f"Failed to get stats: {e}")

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class APIClientError(Exception):
    """API client error."""
    pass