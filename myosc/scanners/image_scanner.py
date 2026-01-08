"""Docker image scanner for container security analysis."""

import json
import tarfile
import tempfile
from dataclasses import dataclass
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


@dataclass
class ImageLayer:
    """Represents a Docker image layer."""

    digest: str
    size: int
    created: str
    command: str


@dataclass
class ImageManifest:
    """Parsed Docker image manifest."""

    config_digest: str
    layers: list[str]
    platform: str


class ImageScanner(BaseScanner):
    """Scanner for Docker/OCI container images."""

    def __init__(self) -> None:
        self._osv = OSVClient()
        self._epss = EPSSClient()

    @property
    def name(self) -> str:
        return "image"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_targets(self) -> list[str]:
        return [TargetType.IMAGE.value]

    async def scan(self, target: ScanTarget) -> list[Finding]:
        """Scan Docker image for vulnerabilities.

        Supports:
        - Local tar archives (docker save)
        - Running containers (via docker SDK)
        """
        findings: list[Finding] = []
        image_path = target.path

        # Check if it's a tar file
        if Path(image_path).exists() and image_path.endswith(".tar"):
            packages = self._extract_packages_from_tar(Path(image_path))
        else:
            # Try to use docker SDK for running image
            packages = await self._extract_packages_from_docker(image_path)

        if not packages:
            return findings

        # Query vulnerabilities
        vuln_map = await self._osv.query_batch(packages)

        # Get EPSS scores
        all_cves: list[str] = []
        for vulns in vuln_map.values():
            for v in vulns:
                all_cves.extend(v.aliases)

        epss_scores = {}
        if all_cves:
            epss_scores = await self._epss.get_scores_batch(all_cves)

        # Build findings
        for package, vulns in vuln_map.items():
            for vuln in vulns:
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
                    file_path=f"image:{target.path}",
                    references=vuln.references,
                )
                findings.append(finding)

        return findings

    def _extract_packages_from_tar(self, tar_path: Path) -> list[Package]:
        """Extract packages from a Docker image tar archive."""
        packages: list[Package] = []

        try:
            with tarfile.open(tar_path, "r") as tar:
                # Find and parse OS packages
                packages.extend(self._find_dpkg_packages(tar))
                packages.extend(self._find_rpm_packages(tar))
                packages.extend(self._find_apk_packages(tar))

                # Find language packages
                packages.extend(self._find_python_packages(tar))
                packages.extend(self._find_node_packages(tar))

        except Exception:
            pass

        return packages

    def _find_dpkg_packages(self, tar: tarfile.TarFile) -> list[Package]:
        """Find Debian/Ubuntu packages from dpkg status."""
        packages: list[Package] = []

        for member in tar.getmembers():
            if member.name.endswith("var/lib/dpkg/status"):
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    packages.extend(self._parse_dpkg_status(content))
                    break

        return packages

    def _parse_dpkg_status(self, content: str) -> list[Package]:
        """Parse dpkg status file."""
        packages: list[Package] = []
        current: dict[str, str] = {}

        for line in content.splitlines():
            if line.startswith("Package:"):
                current["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                current["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                current["status"] = line.split(":", 1)[1].strip()
            elif not line.strip() and current:
                if (
                    "install ok installed" in current.get("status", "")
                    and current.get("name")
                    and current.get("version")
                ):
                    packages.append(
                        Package(
                            name=current["name"],
                            version=current["version"],
                            ecosystem="debian",
                            path="dpkg",
                        )
                    )
                current = {}

        return packages

    def _find_rpm_packages(self, tar: tarfile.TarFile) -> list[Package]:
        """Find RPM packages (placeholder - requires rpm db parsing)."""
        # RPM database parsing is complex, simplified for MVP
        return []

    def _find_apk_packages(self, tar: tarfile.TarFile) -> list[Package]:
        """Find Alpine packages from apk installed."""
        packages: list[Package] = []

        for member in tar.getmembers():
            if member.name.endswith("lib/apk/db/installed"):
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    packages.extend(self._parse_apk_installed(content))
                    break

        return packages

    def _parse_apk_installed(self, content: str) -> list[Package]:
        """Parse Alpine apk installed file."""
        packages: list[Package] = []
        current: dict[str, str] = {}

        for line in content.splitlines():
            if line.startswith("P:"):
                current["name"] = line[2:].strip()
            elif line.startswith("V:"):
                current["version"] = line[2:].strip()
            elif not line.strip() and current:
                if current.get("name") and current.get("version"):
                    packages.append(
                        Package(
                            name=current["name"],
                            version=current["version"],
                            ecosystem="alpine",
                            path="apk",
                        )
                    )
                current = {}

        return packages

    def _find_python_packages(self, tar: tarfile.TarFile) -> list[Package]:
        """Find Python packages from site-packages."""
        packages: list[Package] = []
        seen: set[tuple[str, str]] = set()

        for member in tar.getmembers():
            # Look for METADATA files in site-packages
            if "site-packages" in member.name and member.name.endswith("METADATA"):
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    pkg = self._parse_python_metadata(content)
                    if pkg and (pkg.name, pkg.version) not in seen:
                        packages.append(pkg)
                        seen.add((pkg.name, pkg.version))

        return packages

    def _parse_python_metadata(self, content: str) -> Package | None:
        """Parse Python package METADATA file."""
        name = ""
        version = ""

        for line in content.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip().lower()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            if name and version:
                break

        if name and version:
            return Package(name=name, version=version, ecosystem="pypi", path="python")
        return None

    def _find_node_packages(self, tar: tarfile.TarFile) -> list[Package]:
        """Find Node.js packages from node_modules."""
        packages: list[Package] = []
        seen: set[tuple[str, str]] = set()

        for member in tar.getmembers():
            # Look for package.json in node_modules
            if "node_modules" in member.name and member.name.endswith("package.json"):
                # Skip nested node_modules
                if member.name.count("node_modules") > 1:
                    continue

                f = tar.extractfile(member)
                if f:
                    try:
                        data = json.loads(f.read().decode("utf-8"))
                        name = data.get("name", "")
                        version = data.get("version", "")
                        if name and version and (name, version) not in seen:
                            packages.append(
                                Package(name=name, version=version, ecosystem="npm", path="node")
                            )
                            seen.add((name, version))
                    except json.JSONDecodeError:
                        pass

        return packages

    async def _extract_packages_from_docker(self, image_name: str) -> list[Package]:
        """Extract packages from a running Docker image using docker SDK."""
        packages: list[Package] = []

        try:
            import docker

            client = docker.from_env()

            # Create temporary container
            container = client.containers.create(image_name)

            try:
                # Export container filesystem
                with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                    for chunk in container.export():
                        tmp.write(chunk)
                    tmp_path = tmp.name

                # Extract packages from exported tar
                packages = self._extract_packages_from_tar(Path(tmp_path))

                # Cleanup
                Path(tmp_path).unlink(missing_ok=True)

            finally:
                container.remove()

        except Exception:
            # Docker not available or image not found
            pass

        return packages

    async def close(self) -> None:
        """Close database connections."""
        await self._osv.close()
        await self._epss.close()
