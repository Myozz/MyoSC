# MyoAPI Client for MyoSC
# Single data source replacing OSV, EPSS, GHSA

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from myosc.core.models import Package, Severity

MYOAPI_BASE_URL = "https://api.myoapi.workers.dev/api/v1"
DEFAULT_TIMEOUT = 30.0

# In-memory cache for session (avoid duplicate API calls)
_cache: dict[str, Any] = {}


@dataclass
class MyoVulnerability:
    """Vulnerability data from MyoAPI."""

    id: str
    cve_id: str
    title: str
    description: str
    severity: Severity
    myo_score: float
    cvss_score: float  # Best available from nvd/ghsa/osv
    epss_score: float
    epss_percentile: float
    is_kev: bool
    kev_date: str | None
    ghsa_id: str | None
    affected_package: str
    ecosystem: str
    affected_versions: list[str]
    fixed_versions: list[str]
    references: list[str]


class MyoAPIClient:
    """Client for MyoAPI - aggregated vulnerability data."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=MYOAPI_BASE_URL,
                timeout=DEFAULT_TIMEOUT,
                headers={"Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def query_package(
        self,
        package: Package,
    ) -> list[MyoVulnerability]:
        """Query vulnerabilities for a package.

        Args:
            package: Package with name, version, ecosystem

        Returns:
            List of vulnerabilities affecting this package
        """
        # Check cache first
        cache_key = f"{package.ecosystem}:{package.name}"
        if cache_key in _cache:
            return _cache[cache_key]

        client = await self._get_client()

        # Map ecosystem names
        ecosystem_map = {
            "pypi": "pypi",
            "npm": "npm",
            "go": "go",
            "maven": "maven",
            "nuget": "nuget",
            "rubygems": "rubygems",
            "packagist": "packagist",
            "cargo": "cargo",
        }
        ecosystem = ecosystem_map.get(package.ecosystem.lower(), package.ecosystem.lower())

        try:
            response = await client.get(
                "/cve/package",
                params={
                    "ecosystem": ecosystem,
                    "name": package.name.lower(),
                    "limit": 500,
                },
            )

            if response.status_code == 400:
                # Bad request - likely invalid params
                return []

            if response.status_code != 200:
                # API error, return empty
                return []

            data = response.json()
            vulns = self._parse_vulnerabilities(data.get("data", []), package)

            # Cache results
            _cache[cache_key] = vulns
            return vulns

        except httpx.HTTPError:
            return []

    async def query_packages_batch(
        self,
        packages: list[Package],
    ) -> dict[Package, list[MyoVulnerability]]:
        """Query vulnerabilities for multiple packages concurrently.

        Args:
            packages: List of packages to query

        Returns:
            Dict mapping package to its vulnerabilities
        """
        results: dict[Package, list[MyoVulnerability]] = {}

        # Query packages concurrently (with limit to avoid rate limiting)
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests

        async def query_one(pkg: Package) -> tuple[Package, list[MyoVulnerability]]:
            async with semaphore:
                vulns = await self.query_package(pkg)
                return pkg, vulns

        tasks = [query_one(pkg) for pkg in packages]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, tuple):
                pkg, vulns = result
                if vulns:
                    results[pkg] = vulns

        return results

    async def get_cve(self, cve_id: str) -> MyoVulnerability | None:
        """Get single CVE by ID.

        Args:
            cve_id: CVE ID (e.g., CVE-2024-3400)

        Returns:
            Vulnerability data or None if not found
        """
        # Check cache
        if cve_id in _cache:
            return _cache[cve_id]

        client = await self._get_client()

        try:
            response = await client.get(f"/cve/{cve_id}")

            if response.status_code == 404:
                return None

            if response.status_code != 200:
                return None

            data = response.json()
            cve_data = data.get("data")
            if not cve_data:
                return None

            vuln = self._parse_single_cve(cve_data)
            _cache[cve_id] = vuln
            return vuln

        except httpx.HTTPError:
            return None

    def _parse_vulnerabilities(
        self,
        data: list[dict[str, Any]],
        package: Package,
    ) -> list[MyoVulnerability]:
        """Parse MyoAPI response into vulnerability objects."""
        vulns = []

        for item in data:
            vuln = self._parse_cve_item(item, package)
            if vuln:
                vulns.append(vuln)

        return vulns

    def _parse_cve_item(
        self,
        item: dict[str, Any],
        package: Package | None = None,
    ) -> MyoVulnerability | None:
        """Parse single CVE item from API response."""
        try:
            # Get best CVSS score (prefer nvd > ghsa > osv)
            cvss = item.get("cvss", {})
            cvss_score = cvss.get("nvd") or cvss.get("ghsa") or cvss.get("osv") or 0.0

            # Get EPSS data
            epss = item.get("epss", {})
            epss_score = epss.get("score") or 0.0
            epss_percentile = epss.get("percentile") or 0.0

            # Get KEV data
            kev = item.get("kev", {})
            is_kev = kev.get("is_known", False)
            kev_date = kev.get("date_added")

            # Get severity from myo_severity
            severity_str = item.get("myo_severity", "UNKNOWN").upper()
            severity = Severity(severity_str) if severity_str in [s.value for s in Severity] else Severity.UNKNOWN

            # Get affected package info
            affected_pkgs = item.get("affected_packages", [])
            affected_pkg = ""
            ecosystem = ""
            affected_versions: list[str] = []
            fixed_versions: list[str] = []

            if affected_pkgs:
                # Use first matching package or first available
                for ap in affected_pkgs:
                    if package and ap.get("package", "").lower() == package.name.lower():
                        affected_pkg = ap.get("package", "")
                        ecosystem = ap.get("ecosystem", "")
                        affected_versions = ap.get("affected_versions", [])
                        fixed_versions = ap.get("fixed_versions", [])
                        break
                else:
                    ap = affected_pkgs[0]
                    affected_pkg = ap.get("package", "")
                    ecosystem = ap.get("ecosystem", "")
                    affected_versions = ap.get("affected_versions", [])
                    fixed_versions = ap.get("fixed_versions", [])
            elif package:
                affected_pkg = package.name
                ecosystem = package.ecosystem

            # Get aliases for CVE ID
            aliases = item.get("aliases", [])
            cve_id = item.get("id", "")
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            if not cve_id.startswith("CVE-"):
                cve_id = item.get("id", "")

            return MyoVulnerability(
                id=item.get("id", ""),
                cve_id=cve_id,
                title=item.get("title") or item.get("id", ""),
                description=item.get("description", ""),
                severity=severity,
                myo_score=item.get("myo_score", 0.0),
                cvss_score=cvss_score,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                is_kev=is_kev,
                kev_date=kev_date,
                ghsa_id=item.get("ghsa_id"),
                affected_package=affected_pkg,
                ecosystem=ecosystem,
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
                references=item.get("refs", [])[:10],  # Limit refs
            )

        except Exception:
            return None

    def _parse_single_cve(self, item: dict[str, Any]) -> MyoVulnerability | None:
        """Parse single CVE from get_cve response."""
        return self._parse_cve_item(item)


def clear_cache() -> None:
    """Clear the in-memory cache."""
    global _cache
    _cache = {}
