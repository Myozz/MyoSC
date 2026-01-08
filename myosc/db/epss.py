"""EPSS API client for exploit prediction scores.

EPSS (Exploit Prediction Scoring System) provides probability
that a CVE will be exploited in the next 30 days. This is more
actionable than static CVSS scores for prioritization.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx

from myosc.core.exceptions import DatabaseError, RateLimitError

EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TIMEOUT = 30.0
CACHE_TTL_HOURS = 24


@dataclass
class EPSSScore:
    """EPSS score data."""

    cve: str
    epss: float  # probability 0-1
    percentile: float  # percentile ranking 0-1
    date: str


class EPSSClient:
    """Client for FIRST.org EPSS API."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[EPSSScore, datetime]] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_cached(self, cve: str) -> EPSSScore | None:
        """Get cached score if not expired."""
        if cve in self._cache:
            score, cached_at = self._cache[cve]
            if datetime.now() - cached_at < timedelta(hours=CACHE_TTL_HOURS):
                return score
            del self._cache[cve]
        return None

    def _cache_score(self, score: EPSSScore) -> None:
        """Cache a score."""
        self._cache[score.cve] = (score, datetime.now())

    async def get_score(self, cve: str) -> EPSSScore | None:
        """Get EPSS score for a CVE.

        Args:
            cve: CVE ID (e.g., CVE-2021-44228)

        Returns:
            EPSS score or None if not found
        """
        # Check cache first
        cached = self._get_cached(cve)
        if cached:
            return cached

        client = await self._get_client()

        try:
            response = await client.get(EPSS_API_URL, params={"cve": cve})
            if response.status_code == 429:
                raise RateLimitError("EPSS API rate limit exceeded")
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as e:
            raise DatabaseError(f"EPSS API error: {e}") from e

        scores = data.get("data", [])
        if not scores:
            return None

        score = self._parse_score(scores[0])
        self._cache_score(score)
        return score

    async def get_scores_batch(self, cves: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for multiple CVEs in a single request.

        Args:
            cves: List of CVE IDs

        Returns:
            Dict mapping CVE IDs to scores
        """
        # Filter out cached CVEs
        uncached = [c for c in cves if not self._get_cached(c)]
        results: dict[str, EPSSScore] = {}

        # Add cached results
        for cve in cves:
            cached = self._get_cached(cve)
            if cached:
                results[cve] = cached

        if not uncached:
            return results

        # Batch API supports comma-separated CVEs
        # API has a limit, process in chunks of 100
        chunk_size = 100
        for i in range(0, len(uncached), chunk_size):
            chunk = uncached[i : i + chunk_size]
            cve_list = ",".join(chunk)

            client = await self._get_client()

            try:
                response = await client.get(EPSS_API_URL, params={"cve": cve_list})
                if response.status_code == 429:
                    raise RateLimitError("EPSS API rate limit exceeded")
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                raise DatabaseError(f"EPSS API error: {e}") from e

            for item in data.get("data", []):
                score = self._parse_score(item)
                self._cache_score(score)
                results[score.cve] = score

        return results

    def _parse_score(self, data: dict[str, Any]) -> EPSSScore:
        """Parse API response into EPSSScore."""
        return EPSSScore(
            cve=data.get("cve", ""),
            epss=float(data.get("epss", 0)),
            percentile=float(data.get("percentile", 0)),
            date=data.get("date", ""),
        )

    def clear_cache(self) -> None:
        """Clear the score cache."""
        self._cache.clear()
