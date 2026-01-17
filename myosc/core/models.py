"""Data models for scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.UNKNOWN


class TargetType(str, Enum):
    """Scan target types."""

    FILESYSTEM = "filesystem"
    IMAGE = "image"
    REPOSITORY = "repository"


@dataclass
class Package:
    """Represents a software package."""

    name: str
    version: str
    ecosystem: str  # pypi, npm, go, etc.
    path: str = ""  # file path where package was found

    def __hash__(self) -> int:
        return hash((self.name, self.version, self.ecosystem))


@dataclass
class Finding:
    """Base class for all findings."""

    id: str
    severity: Severity
    title: str
    description: str
    file_path: str = ""
    line_number: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityFinding(Finding):
    """Represents a vulnerability finding."""

    cve_id: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0  # exploit prediction score (0-1)
    myo_score: float = 0.0   # MyoAPI priority score (0-1), pre-calculated
    is_kev: bool = False     # whether CVE is in CISA KEV catalog
    affected_package: Package | None = None
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def priority_score(self) -> float:
        """Get priority score.

        If myo_score is available (from MyoAPI), use it directly.
        Otherwise calculate: (CVSS/10 * 0.3) + (EPSS * 0.5) + (KEV * 0.2)
        """
        if self.myo_score > 0:
            return self.myo_score

        # Fallback calculation
        cvss_normalized = self.cvss_score / 10.0
        kev_bonus = 1.0 if self.is_kev else 0.0
        return (cvss_normalized * 0.3) + (self.epss_score * 0.5) + (kev_bonus * 0.2)


@dataclass
class SecretFinding(Finding):
    """Represents a detected secret."""

    secret_type: str = ""  # aws_key, github_token, etc.
    match: str = ""  # the matched pattern (redacted)
    entropy: float = 0.0
    verified: bool = False  # whether secret was verified as active
    context: str = ""  # surrounding code context


@dataclass
class ScanTarget:
    """Represents a scan target."""

    path: str
    target_type: TargetType
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregated scan results."""

    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    scanner_versions: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def vulnerability_count(self) -> dict[Severity, int]:
        """Count vulnerabilities by severity."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            if isinstance(f, VulnerabilityFinding):
                counts[f.severity] += 1
        return counts

    @property
    def secret_count(self) -> int:
        """Count detected secrets."""
        return sum(1 for f in self.findings if isinstance(f, SecretFinding))

    def filter_by_severity(self, min_severity: Severity) -> list[Finding]:
        """Filter findings by minimum severity."""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        min_idx = severity_order.index(min_severity)
        allowed = set(severity_order[: min_idx + 1])
        return [f for f in self.findings if f.severity in allowed]
