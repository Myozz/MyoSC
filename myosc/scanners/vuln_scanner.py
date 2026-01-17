# Vulnerability scanner using MyoAPI

from __future__ import annotations

from pathlib import Path

from myosc.core.models import (
    Finding,
    Package,
    ScanTarget,
    TargetType,
    VulnerabilityFinding,
)
from myosc.core.scanner import BaseScanner
from myosc.db.myoapi import MyoAPIClient, clear_cache
from myosc.scanners.package_parsers import PARSERS


class VulnerabilityScanner(BaseScanner):
    """Scanner for detecting vulnerabilities in dependencies using MyoAPI."""

    def __init__(self) -> None:
        self._myoapi = MyoAPIClient()

    @property
    def name(self) -> str:
        return "vulnerability"

    @property
    def version(self) -> str:
        return "0.2.0"  # Version bump for MyoAPI integration

    @property
    def supported_targets(self) -> list[str]:
        return [TargetType.FILESYSTEM.value, TargetType.REPOSITORY.value]

    async def scan(self, target: ScanTarget) -> list[Finding]:
        """Scan target for vulnerable dependencies using MyoAPI."""
        path = Path(target.path)
        findings: list[Finding] = []

        # Discover and parse package files
        packages = await self._discover_packages(path)

        if not packages:
            return findings

        # Query MyoAPI for vulnerabilities (batch query with caching)
        vuln_map = await self._myoapi.query_packages_batch(packages)

        # Build findings from MyoAPI results
        for package, vulns in vuln_map.items():
            for vuln in vulns:
                # Get fixed version (first one if multiple)
                fixed_version = ""
                if vuln.fixed_versions:
                    fixed_version = vuln.fixed_versions[0]

                finding = VulnerabilityFinding(
                    id=vuln.id,
                    cve_id=vuln.cve_id,
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    epss_score=vuln.epss_score,
                    myo_score=vuln.myo_score,
                    is_kev=vuln.is_kev,
                    title=vuln.title or vuln.id,
                    description=vuln.description,
                    affected_package=package,
                    fixed_version=fixed_version,
                    file_path=package.path,
                    references=vuln.references,
                )
                findings.append(finding)

        return findings

    async def _discover_packages(self, path: Path) -> list[Package]:
        """Discover and parse package files in directory."""
        packages: list[Package] = []

        if path.is_file():
            # Exact match: check if filename is in PARSERS
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
        """Close API connections and clear cache."""
        await self._myoapi.close()
        clear_cache()
