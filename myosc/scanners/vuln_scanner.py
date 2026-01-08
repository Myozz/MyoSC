"""Vulnerability scanner using OSV database."""

from pathlib import Path

from myosc.core.models import (
    Finding,
    Package,
    ScanTarget,
    TargetType,
    VulnerabilityFinding,
)
from myosc.core.scanner import BaseScanner
from myosc.db.epss import EPSSClient
from myosc.db.osv import OSVClient
from myosc.scanners.package_parsers import PARSERS


class VulnerabilityScanner(BaseScanner):
    """Scanner for detecting vulnerabilities in dependencies."""

    def __init__(self) -> None:
        self._osv = OSVClient()
        self._epss = EPSSClient()

    @property
    def name(self) -> str:
        return "vulnerability"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_targets(self) -> list[str]:
        return [TargetType.FILESYSTEM.value, TargetType.REPOSITORY.value]

    async def scan(self, target: ScanTarget) -> list[Finding]:
        """Scan target for vulnerable dependencies."""
        path = Path(target.path)
        findings: list[Finding] = []

        # Discover and parse package files
        packages = await self._discover_packages(path)

        if not packages:
            return findings

        # Query OSV for vulnerabilities
        vuln_map = await self._osv.query_batch(packages)

        # Collect all CVE IDs for EPSS lookup
        all_cves: list[str] = []
        for vulns in vuln_map.values():
            for v in vulns:
                all_cves.extend(v.aliases)

        # Get EPSS scores
        epss_scores = {}
        if all_cves:
            epss_scores = await self._epss.get_scores_batch(all_cves)

        # Build findings
        for package, vulns in vuln_map.items():
            for vuln in vulns:
                # Get EPSS score (use highest if multiple CVEs)
                epss_score = 0.0
                cve_id = ""
                for alias in vuln.aliases:
                    if alias in epss_scores:
                        score = epss_scores[alias].epss
                        if score > epss_score:
                            epss_score = score
                            cve_id = alias

                finding = VulnerabilityFinding(
                    id=vuln.id,
                    cve_id=cve_id or (vuln.aliases[0] if vuln.aliases else ""),
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    epss_score=epss_score,
                    title=vuln.summary or vuln.id,
                    description=vuln.details,
                    affected_package=package,
                    fixed_version=vuln.fixed_version,
                    file_path=package.path,
                    references=vuln.references,
                )
                findings.append(finding)

        return findings

    async def _discover_packages(self, path: Path) -> list[Package]:
        """Discover and parse package files in directory."""
        packages: list[Package] = []

        if path.is_file():
            if path.name in PARSERS:
                result = PARSERS[path.name](path)
                packages.extend(result.packages)
        else:
            # Walk directory for package files
            for pattern in PARSERS:
                for file in path.rglob(pattern):
                    # Skip node_modules, venv, etc.
                    if self._should_skip(file):
                        continue
                    result = PARSERS[pattern](file)
                    packages.extend(result.packages)

        return packages

    def _should_skip(self, path: Path) -> bool:
        """Check if path should be skipped."""
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "env",
            ".env",
            "__pycache__",
            ".git",
            "vendor",
            "dist",
            "build",
        }
        return any(part in skip_dirs for part in path.parts)

    async def close(self) -> None:
        """Close database connections."""
        await self._osv.close()
        await self._epss.close()
