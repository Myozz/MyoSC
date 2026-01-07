"""Tests for secret scanner."""

from pathlib import Path
from textwrap import dedent

import pytest

from myosc.core.models import ScanTarget, TargetType
from myosc.scanners.secret_scanner import SecretScanner


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


class TestSecretPatterns:
    """Tests for pattern-based detection."""

    @pytest.mark.asyncio
    async def test_detect_aws_access_key(self, tmp_path: Path, scanner: SecretScanner) -> None:
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7KEYABCD"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("aws" in f.secret_type for f in findings)

    @pytest.mark.asyncio
    async def test_detect_github_token(self, tmp_path: Path, scanner: SecretScanner) -> None:
        content = 'GITHUB_TOKEN = "ghp_aBcDeFgH1JkLmNoPqRsTuVwXyZ0123456789"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("github" in f.secret_type for f in findings)

    @pytest.mark.asyncio
    async def test_detect_postgres_uri(self, tmp_path: Path, scanner: SecretScanner) -> None:
        content = 'DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) >= 1
        assert any("postgres" in f.secret_type for f in findings)


class TestPlaceholderFiltering:
    """Tests for placeholder detection."""

    @pytest.mark.asyncio
    async def test_skip_placeholder_values(self, tmp_path: Path, scanner: SecretScanner) -> None:
        content = dedent("""
            API_KEY = "your-api-key-here"
            SECRET = "xxxxxxxxxxxxxxxxxxxx"
            TOKEN = "example-token-placeholder"
        """)

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        # Should not detect placeholder values
        assert len(findings) == 0


class TestEntropyDetection:
    """Tests for entropy-based detection."""

    @pytest.mark.asyncio
    async def test_high_entropy_string(self, tmp_path: Path) -> None:
        scanner = SecretScanner(use_entropy=True)
        # High entropy random string
        content = 'SECRET = "aB3dE5gH7jK9mN1pR3tV5xZ7bD9fH1jL3nP5rT7vX9"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_low_entropy_skipped(self, tmp_path: Path) -> None:
        scanner = SecretScanner(use_entropy=True)
        # Low entropy repetitive string
        content = 'VALUE = "aaaaaaaaaaaaaaaaaaaaaa"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) == 0


class TestRedaction:
    """Tests for secret redaction."""

    @pytest.mark.asyncio
    async def test_secrets_are_redacted(self, tmp_path: Path, scanner: SecretScanner) -> None:
        content = 'GITHUB_TOKEN = "ghp_aBcDeFgH1JkLmNoPqRsTuVwXyZ0123456789"'

        test_file = tmp_path / "config.py"
        test_file.write_text(content)

        target = ScanTarget(path=str(tmp_path), target_type=TargetType.FILESYSTEM)
        findings = await scanner.scan(target)

        assert len(findings) >= 1
        # Match should be redacted
        for f in findings:
            assert "****" in f.match or "*" in f.match
