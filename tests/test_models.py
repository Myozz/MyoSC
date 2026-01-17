"""Tests for core models."""

import pytest

from myosc.core.models import (
    Package,
    ScanResult,
    ScanTarget,
    Severity,
    TargetType,
    VulnerabilityFinding,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_from_cvss_critical(self) -> None:
        assert Severity.from_cvss(9.5) == Severity.CRITICAL
        assert Severity.from_cvss(10.0) == Severity.CRITICAL

    def test_from_cvss_high(self) -> None:
        assert Severity.from_cvss(7.0) == Severity.HIGH
        assert Severity.from_cvss(8.9) == Severity.HIGH

    def test_from_cvss_medium(self) -> None:
        assert Severity.from_cvss(4.0) == Severity.MEDIUM
        assert Severity.from_cvss(6.9) == Severity.MEDIUM

    def test_from_cvss_low(self) -> None:
        assert Severity.from_cvss(0.1) == Severity.LOW
        assert Severity.from_cvss(3.9) == Severity.LOW

    def test_from_cvss_unknown(self) -> None:
        assert Severity.from_cvss(0.0) == Severity.UNKNOWN


class TestVulnerabilityFinding:
    """Tests for VulnerabilityFinding."""

    def test_priority_score_uses_myo_score_if_available(self) -> None:
        """When myo_score is set (from MyoAPI), use it directly."""
        finding = VulnerabilityFinding(
            id="TEST-001",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cvss_score=8.0,
            epss_score=0.5,
            myo_score=0.85,  # MyoAPI pre-calculated score
        )
        assert finding.priority_score == 0.85

    def test_priority_score_fallback_calculation(self) -> None:
        """When myo_score is 0, calculate from CVSS/EPSS/KEV."""
        finding = VulnerabilityFinding(
            id="TEST-001",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            cvss_score=8.0,
            epss_score=0.0,
            myo_score=0.0,  # No MyoAPI score
        )
        # CVSS/10 * 0.3 = 0.8 * 0.3 = 0.24
        assert finding.priority_score == pytest.approx(0.24)

    def test_priority_score_with_kev(self) -> None:
        """KEV adds 0.2 to priority score."""
        finding = VulnerabilityFinding(
            id="TEST-001",
            severity=Severity.CRITICAL,
            title="Test",
            description="Test",
            cvss_score=10.0,
            epss_score=0.9,
            is_kev=True,
            myo_score=0.0,  # Force fallback calculation
        )
        # CVSS: 10/10 * 0.3 = 0.3
        # EPSS: 0.9 * 0.5 = 0.45
        # KEV: 1.0 * 0.2 = 0.2
        # Total: 0.95
        assert finding.priority_score == pytest.approx(0.95)



class TestScanResult:
    """Tests for ScanResult."""

    def test_vulnerability_count(self) -> None:
        target = ScanTarget(path="/test", target_type=TargetType.FILESYSTEM)
        result = ScanResult(target=target)

        result.findings = [
            VulnerabilityFinding(
                id="1", severity=Severity.CRITICAL, title="", description=""
            ),
            VulnerabilityFinding(
                id="2", severity=Severity.CRITICAL, title="", description=""
            ),
            VulnerabilityFinding(
                id="3", severity=Severity.HIGH, title="", description=""
            ),
        ]

        counts = result.vulnerability_count
        assert counts[Severity.CRITICAL] == 2
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.MEDIUM] == 0

    def test_filter_by_severity(self) -> None:
        target = ScanTarget(path="/test", target_type=TargetType.FILESYSTEM)
        result = ScanResult(target=target)

        result.findings = [
            VulnerabilityFinding(
                id="1", severity=Severity.CRITICAL, title="", description=""
            ),
            VulnerabilityFinding(
                id="2", severity=Severity.HIGH, title="", description=""
            ),
            VulnerabilityFinding(
                id="3", severity=Severity.LOW, title="", description=""
            ),
        ]

        filtered = result.filter_by_severity(Severity.HIGH)
        assert len(filtered) == 2
        severities = {f.severity for f in filtered}
        assert severities == {Severity.CRITICAL, Severity.HIGH}
