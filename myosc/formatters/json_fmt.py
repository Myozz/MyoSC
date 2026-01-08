"""JSON output formatter."""

import json
from datetime import datetime
from typing import Any

from myosc.core.models import (
    ScanResult,
    SecretFinding,
    Severity,
    VulnerabilityFinding,
)
from myosc.formatters.base import BaseFormatter


class JsonFormatter(BaseFormatter):
    """JSON output formatter."""

    def __init__(self, indent: int = 2, include_metadata: bool = True) -> None:
        self._indent = indent
        self._include_metadata = include_metadata

    @property
    def name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def format(self, result: ScanResult) -> str:
        """Format result as JSON string."""
        data = self._to_dict(result)
        return json.dumps(data, indent=self._indent, default=self._json_default)

    def _to_dict(self, result: ScanResult) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        output: dict[str, Any] = {
            "target": {
                "path": result.target.path,
                "type": result.target.target_type.value,
            },
            "summary": {
                "total_findings": len(result.findings),
                "vulnerabilities": self._vuln_summary(result),
                "secrets": result.secret_count,
            },
            "findings": {
                "vulnerabilities": [],
                "secrets": [],
            },
        }

        if self._include_metadata:
            output["metadata"] = {
                "scan_time": result.scan_time.isoformat(),
                "scanner_versions": result.scanner_versions,
            }

        # Add findings
        for finding in result.findings:
            if isinstance(finding, VulnerabilityFinding):
                output["findings"]["vulnerabilities"].append(self._vuln_to_dict(finding))
            elif isinstance(finding, SecretFinding):
                output["findings"]["secrets"].append(self._secret_to_dict(finding))

        # Add errors if any
        if result.errors:
            output["errors"] = result.errors

        return output

    def _vuln_summary(self, result: ScanResult) -> dict[str, int]:
        """Generate vulnerability count summary."""
        counts = result.vulnerability_count
        return {
            "critical": counts[Severity.CRITICAL],
            "high": counts[Severity.HIGH],
            "medium": counts[Severity.MEDIUM],
            "low": counts[Severity.LOW],
        }

    def _vuln_to_dict(self, finding: VulnerabilityFinding) -> dict[str, Any]:
        """Convert vulnerability finding to dict."""
        return {
            "id": finding.id,
            "cve_id": finding.cve_id,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "epss_score": finding.epss_score,
            "priority_score": finding.priority_score,
            "title": finding.title,
            "description": finding.description,
            "package": {
                "name": finding.affected_package.name if finding.affected_package else None,
                "version": finding.affected_package.version if finding.affected_package else None,
                "ecosystem": finding.affected_package.ecosystem if finding.affected_package else None,
            },
            "fixed_version": finding.fixed_version,
            "file_path": finding.file_path,
            "references": finding.references,
        }

    def _secret_to_dict(self, finding: SecretFinding) -> dict[str, Any]:
        """Convert secret finding to dict."""
        return {
            "id": finding.id,
            "type": finding.secret_type,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "match": finding.match,
            "entropy": finding.entropy,
            "verified": finding.verified,
        }

    def _json_default(self, obj: Any) -> Any:
        """Handle non-serializable types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Severity):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
