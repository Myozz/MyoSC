"""OSV.dev API client for vulnerability data.

OSV provides better coverage for open-source packages compared to NVD:
- Faster updates (no enrichment lag)
- Precise version range mapping
- Multi-ecosystem support (PyPI, npm, Go, etc.)
- Free API with no rate limits for reasonable usage
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from myosc.core.exceptions import DatabaseError
from myosc.core.models import Package, Severity


OSV_API_URL = "https://api.osv.dev/v1"
DEFAULT_TIMEOUT = 30.0


@dataclass
class OSVVulnerability:
    """Parsed OSV vulnerability data."""

    id: str
    summary: str
    details: str
    severity: Severity
    cvss_score: float
    affected_versions: list[str]
    fixed_version: str
    aliases: list[str]  # CVE IDs
    references: list[str]


class OSVClient:
    """Client for OSV.dev vulnerability database."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=OSV_API_URL,
                timeout=self._timeout,
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def query_package(self, package: Package) -> list[OSVVulnerability]:
        """Query vulnerabilities for a specific package.

        Args:
            package: Package to query

        Returns:
            List of vulnerabilities affecting the package
        """
        client = await self._get_client()

        # Map ecosystem names to OSV format
        ecosystem_map = {
            "pypi": "PyPI",
            "npm": "npm",
            "go": "Go",
            "cargo": "crates.io",
            "maven": "Maven",
            "nuget": "NuGet",
        }

        osv_ecosystem = ecosystem_map.get(package.ecosystem.lower(), package.ecosystem)

        payload = {
            "version": package.version,
            "package": {
                "name": package.name,
                "ecosystem": osv_ecosystem,
            },
        }

        try:
            response = await client.post("/query", json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as e:
            raise DatabaseError(f"OSV API error: {e}") from e

        vulns = data.get("vulns", [])
        return [self._parse_vulnerability(v) for v in vulns]

    async def query_batch(
        self, packages: list[Package], concurrency: int = 10
    ) -> dict[Package, list[OSVVulnerability]]:
        """Query vulnerabilities for multiple packages.

        Args:
            packages: List of packages to query
            concurrency: Max concurrent requests

        Returns:
            Dict mapping packages to their vulnerabilities
        """
        semaphore = asyncio.Semaphore(concurrency)
        results: dict[Package, list[OSVVulnerability]] = {}

        async def query_with_limit(pkg: Package) -> tuple[Package, list[OSVVulnerability]]:
            async with semaphore:
                vulns = await self.query_package(pkg)
                return pkg, vulns

        tasks = [query_with_limit(pkg) for pkg in packages]
        for coro in asyncio.as_completed(tasks):
            pkg, vulns = await coro
            results[pkg] = vulns

        return results

    def _parse_vulnerability(self, data: dict[str, Any]) -> OSVVulnerability:
        """Parse OSV API response into structured data."""
        # Extract severity from database_specific or severity array
        severity = Severity.UNKNOWN
        cvss_score = 0.0

        if "severity" in data:
            for sev in data["severity"]:
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # Parse CVSS vector or score
                    if score_str:
                        try:
                            cvss_score = float(score_str.split("/")[0].split(":")[-1])
                        except (ValueError, IndexError):
                            pass
                    severity = Severity.from_cvss(cvss_score)
                    break

        # If no CVSS, try to infer from ecosystem severity
        if severity == Severity.UNKNOWN:
            db_specific = data.get("database_specific", {})
            sev_str = db_specific.get("severity", "").upper()
            if sev_str in [s.value for s in Severity]:
                severity = Severity(sev_str)

        # Extract fixed version from affected ranges
        fixed_version = ""
        affected_versions: list[str] = []

        for affected in data.get("affected", []):
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                    if "introduced" in event:
                        affected_versions.append(f">={event['introduced']}")

        # Extract references
        references = [ref.get("url", "") for ref in data.get("references", []) if ref.get("url")]

        # Extract CVE aliases
        aliases = [a for a in data.get("aliases", []) if a.startswith("CVE-")]

        return OSVVulnerability(
            id=data.get("id", ""),
            summary=data.get("summary", ""),
            details=data.get("details", ""),
            severity=severity,
            cvss_score=cvss_score,
            affected_versions=affected_versions,
            fixed_version=fixed_version,
            aliases=aliases,
            references=references,
        )

    async def get_vulnerability(self, vuln_id: str) -> OSVVulnerability | None:
        """Get vulnerability by ID.

        Args:
            vuln_id: OSV or CVE ID

        Returns:
            Vulnerability data or None if not found
        """
        client = await self._get_client()

        try:
            response = await client.get(f"/vulns/{vuln_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return self._parse_vulnerability(response.json())
        except httpx.HTTPError as e:
            raise DatabaseError(f"OSV API error: {e}") from e
