"""SARIF output formatter for GitHub Code Scanning integration.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for static analysis tools. GitHub Code Scanning accepts SARIF files.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from typing import Any

from myosc import __version__
from myosc.core.models import (
    ScanResult,
    SecretFinding,
    Severity,
    VulnerabilityFinding,
)
from myosc.formatters.base import BaseFormatter


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class SarifFormatter(BaseFormatter):
    """SARIF format output for GitHub Code Scanning."""

    @property
    def name(self) -> str:
        return "sarif"

    @property
    def file_extension(self) -> str:
        return ".sarif"

    def format(self, result: ScanResult) -> str:
        """Format result as SARIF JSON."""
        sarif = self._build_sarif(result)
        return json.dumps(sarif, indent=2)

    def _build_sarif(self, result: ScanResult) -> dict[str, Any]:
        """Build SARIF document."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        # Process findings
        rule_ids: set[str] = set()

        for finding in result.findings:
            if isinstance(finding, VulnerabilityFinding):
                rule, sarif_result = self._vuln_to_sarif(finding)
            elif isinstance(finding, SecretFinding):
                rule, sarif_result = self._secret_to_sarif(finding)
            else:
                continue

            # Add rule if not already added
            if rule["id"] not in rule_ids:
                rules.append(rule)
                rule_ids.add(rule["id"])

            results.append(sarif_result)

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "myosc",
                            "version": __version__,
                            "informationUri": "https://github.com/Myozz/myosc",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": len(result.errors) == 0,
                            "toolExecutionNotifications": [
                                {"message": {"text": e}} for e in result.errors
                            ],
                        }
                    ],
                }
            ],
        }

    def _vuln_to_sarif(
        self, finding: VulnerabilityFinding
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Convert vulnerability to SARIF rule and result."""
        rule_id = finding.cve_id or finding.id

        rule = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "helpUri": finding.references[0] if finding.references else "",
            "defaultConfiguration": {
                "level": self._severity_to_level(finding.severity)
            },
            "properties": {
                "security-severity": str(finding.cvss_score),
                "tags": ["security", "vulnerability"],
            },
        }

        sarif_result = {
            "ruleId": rule_id,
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": self._build_vuln_message(finding),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/"),
                        },
                    }
                }
            ],
            "properties": {
                "cvss_score": finding.cvss_score,
                "epss_score": finding.epss_score,
                "priority_score": finding.priority_score,
            },
        }

        return rule, sarif_result

    def _secret_to_sarif(
        self, finding: SecretFinding
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Convert secret finding to SARIF rule and result."""
        rule_id = finding.secret_type

        rule = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {
                "level": self._severity_to_level(finding.severity)
            },
            "properties": {
                "tags": ["security", "secret"],
            },
        }

        sarif_result = {
            "ruleId": rule_id,
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": f"{finding.title} detected: {finding.match}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/"),
                        },
                        "region": {
                            "startLine": finding.line_number,
                        },
                    }
                }
            ],
            "properties": {
                "entropy": finding.entropy,
            },
        }

        return rule, sarif_result

    def _severity_to_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.UNKNOWN: "note",
        }
        return mapping.get(severity, "note")

    def _build_vuln_message(self, finding: VulnerabilityFinding) -> str:
        """Build vulnerability message."""
        parts = [finding.title]

        if finding.affected_package:
            parts.append(
                f"Package: {finding.affected_package.name}@{finding.affected_package.version}"
            )

        if finding.fixed_version:
            parts.append(f"Fixed in: {finding.fixed_version}")

        if finding.epss_score:
            parts.append(f"EPSS: {finding.epss_score:.1%}")

        return " | ".join(parts)
