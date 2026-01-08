"""Secret scanner with pattern and entropy-based detection.

Detection strategy:
1. Pattern-based: High-confidence regex for known secret formats
2. Entropy-based: Shannon entropy for random-looking strings
3. Keyword proximity: Reduce false positives by requiring keywords nearby

Entropy thresholds (based on character set):
- Base64: 4.5 bits/char (theoretical max ~6.0)
- Hex: 3.5 bits/char (theoretical max ~4.0)
- Alphanumeric: 4.0 bits/char (theoretical max ~5.95)
"""

import math
import re
from collections.abc import Iterator
from pathlib import Path

from myosc.core.models import Finding, ScanTarget, SecretFinding, Severity, TargetType
from myosc.core.scanner import BaseScanner
from myosc.scanners.secret_patterns import (
    Confidence,
    get_patterns_by_confidence,
)

# Entropy thresholds
ENTROPY_THRESHOLD_BASE64 = 4.5
ENTROPY_THRESHOLD_HEX = 3.5
ENTROPY_THRESHOLD_DEFAULT = 4.0

# Minimum length for entropy detection
MIN_SECRET_LENGTH = 16

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".rs",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".properties",
    ".tf",
    ".tfvars",
    ".sql",
    ".md",
    ".txt",
}

# Files to always scan regardless of extension
ALWAYS_SCAN_FILES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "secrets",
    ".htpasswd",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "vendor",
    "dist",
    "build",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
    ".coverage",
    "htmlcov",
    ".idea",
    ".vscode",
    "target",
    "bin",
    "obj",
}


class SecretScanner(BaseScanner):
    """Scanner for detecting hardcoded secrets."""

    def __init__(
        self,
        use_entropy: bool = True,
        min_confidence: Confidence = Confidence.MEDIUM,
        max_file_size_mb: float = 1.0,
    ) -> None:
        self._use_entropy = use_entropy
        self._min_confidence = min_confidence
        self._max_file_size = int(max_file_size_mb * 1024 * 1024)
        self._patterns = get_patterns_by_confidence(min_confidence)

    @property
    def name(self) -> str:
        return "secret"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_targets(self) -> list[str]:
        return [TargetType.FILESYSTEM.value, TargetType.REPOSITORY.value]

    async def scan(self, target: ScanTarget) -> list[Finding]:
        """Scan target for secrets."""
        path = Path(target.path)
        findings: list[Finding] = []

        for file_path in self._iter_files(path):
            file_findings = self._scan_file(file_path)
            findings.extend(file_findings)

        return findings

    def _iter_files(self, path: Path) -> Iterator[Path]:
        """Iterate over scannable files."""
        if path.is_file():
            if self._should_scan(path):
                yield path
            return

        for item in path.rglob("*"):
            if item.is_file() and self._should_scan(item):
                # Check file size
                try:
                    if item.stat().st_size <= self._max_file_size:
                        yield item
                except OSError:
                    continue

    def _should_scan(self, path: Path) -> bool:
        """Check if file should be scanned."""
        # Skip directories in ignore list
        if any(part in SKIP_DIRS for part in path.parts):
            return False

        # Always scan certain files
        if path.name in ALWAYS_SCAN_FILES:
            return True

        # Check extension
        return path.suffix.lower() in SCANNABLE_EXTENSIONS

    def _scan_file(self, path: Path) -> list[SecretFinding]:
        """Scan a single file for secrets."""
        findings: list[SecretFinding] = []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or self._is_comment(stripped):
                continue

            # Pattern-based detection
            for pattern in self._patterns:
                matches = pattern.match(line)
                for match in matches:
                    secret_value = match.group(1) if match.lastindex else match.group(0)

                    # Skip if looks like a placeholder
                    if self._is_placeholder(secret_value):
                        continue

                    findings.append(
                        SecretFinding(
                            id=f"{pattern.id}-{path.name}-{line_num}",
                            secret_type=pattern.id,
                            severity=self._confidence_to_severity(pattern.confidence),
                            title=pattern.name,
                            description=f"Detected {pattern.name} in {path.name}",
                            file_path=str(path),
                            line_number=line_num,
                            match=self._redact(secret_value),
                            entropy=self._calculate_entropy(secret_value),
                            context=self._get_context(lines, line_num),
                        )
                    )

            # Entropy-based detection
            if self._use_entropy:
                high_entropy_matches = self._find_high_entropy(line)
                for secret_value in high_entropy_matches:
                    # Skip if already detected by patterns
                    if any(
                        secret_value in f.match or self._redact(secret_value) == f.match
                        for f in findings
                        if f.line_number == line_num
                    ):
                        continue

                    entropy = self._calculate_entropy(secret_value)
                    findings.append(
                        SecretFinding(
                            id=f"high-entropy-{path.name}-{line_num}",
                            secret_type="high-entropy-string",
                            severity=Severity.LOW,
                            title="High Entropy String",
                            description=f"Detected high entropy string (entropy={entropy:.2f})",
                            file_path=str(path),
                            line_number=line_num,
                            match=self._redact(secret_value),
                            entropy=entropy,
                            context=self._get_context(lines, line_num),
                        )
                    )

        return findings

    def _is_comment(self, line: str) -> bool:
        """Check if line is a comment."""
        comment_prefixes = ("#", "//", "/*", "*", "--", ";", "<!--")
        return any(line.startswith(p) for p in comment_prefixes)

    def _is_placeholder(self, value: str) -> bool:
        """Check if value looks like a placeholder."""
        placeholders = (
            "xxx",
            "your-",
            "your_",
            "example",
            "sample",
            "test",
            "dummy",
            "fake",
            "placeholder",
            "${",
            "{{",
            "<your",
            "[your",
            "change-me",
            "replace-me",
            "todo",
            "fixme",
        )
        lower = value.lower()
        return any(p in lower for p in placeholders)

    def _confidence_to_severity(self, confidence: Confidence) -> Severity:
        """Map confidence to severity."""
        mapping = {
            Confidence.HIGH: Severity.HIGH,
            Confidence.MEDIUM: Severity.MEDIUM,
            Confidence.LOW: Severity.LOW,
        }
        return mapping.get(confidence, Severity.LOW)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0

        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def _find_high_entropy(self, line: str) -> list[str]:
        """Find high entropy strings in a line."""
        matches: list[str] = []

        # Find quoted strings and assignments
        patterns = [
            r"['\"]([a-zA-Z0-9+/=_\-]{16,})['\"]",  # quoted strings
            r"=\s*([a-zA-Z0-9+/=_\-]{16,})",  # assignments
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, line):
                value = match.group(1)

                if len(value) < MIN_SECRET_LENGTH:
                    continue

                if self._is_placeholder(value):
                    continue

                entropy = self._calculate_entropy(value)

                # Use appropriate threshold based on character set
                threshold = ENTROPY_THRESHOLD_DEFAULT
                if all(c in "0123456789abcdefABCDEF" for c in value):
                    threshold = ENTROPY_THRESHOLD_HEX
                elif all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
                    threshold = ENTROPY_THRESHOLD_BASE64

                if entropy >= threshold:
                    matches.append(value)

        return matches

    def _redact(self, secret: str, visible_chars: int = 4) -> str:
        """Redact secret, showing only first and last few characters."""
        if len(secret) <= visible_chars * 2:
            return "*" * len(secret)
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

    def _get_context(self, lines: list[str], line_num: int, context_lines: int = 1) -> str:
        """Get surrounding context lines."""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return "\n".join(lines[start:end])
