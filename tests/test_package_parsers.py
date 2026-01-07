"""Tests for package parsers."""

from pathlib import Path
from textwrap import dedent

import pytest

from myosc.scanners.package_parsers import (
    parse_requirements_txt,
    parse_package_json,
    parse_pyproject_toml,
    parse_go_mod,
)


class TestRequirementsTxt:
    """Tests for requirements.txt parser."""

    def test_parse_simple(self, tmp_path: Path) -> None:
        content = dedent("""
            requests==2.28.0
            flask>=2.0.0
            django~=4.0
        """).strip()

        req_file = tmp_path / "requirements.txt"
        req_file.write_text(content)

        result = parse_requirements_txt(req_file)

        assert len(result.packages) == 3
        assert result.packages[0].name == "requests"
        assert result.packages[0].version == "2.28.0"
        assert result.packages[0].ecosystem == "pypi"

    def test_skip_comments_and_blanks(self, tmp_path: Path) -> None:
        content = dedent("""
            # Comment
            requests==2.28.0

            # Another comment
            flask==2.0.0
        """).strip()

        req_file = tmp_path / "requirements.txt"
        req_file.write_text(content)

        result = parse_requirements_txt(req_file)

        assert len(result.packages) == 2

    def test_skip_includes(self, tmp_path: Path) -> None:
        content = dedent("""
            -r base.txt
            requests==2.28.0
            -e git+https://github.com/user/repo.git
        """).strip()

        req_file = tmp_path / "requirements.txt"
        req_file.write_text(content)

        result = parse_requirements_txt(req_file)

        assert len(result.packages) == 1

    def test_extras(self, tmp_path: Path) -> None:
        content = "requests[security]==2.28.0"

        req_file = tmp_path / "requirements.txt"
        req_file.write_text(content)

        result = parse_requirements_txt(req_file)

        assert len(result.packages) == 1
        assert result.packages[0].name == "requests"


class TestPackageJson:
    """Tests for package.json parser."""

    def test_parse_dependencies(self, tmp_path: Path) -> None:
        content = """{
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "^29.0.0"
            }
        }"""

        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(content)

        result = parse_package_json(pkg_file)

        assert len(result.packages) == 3
        names = {p.name for p in result.packages}
        assert names == {"express", "lodash", "jest"}

        express = next(p for p in result.packages if p.name == "express")
        assert express.version == "4.18.0"
        assert express.ecosystem == "npm"


class TestPyprojectToml:
    """Tests for pyproject.toml parser."""

    def test_parse_pep621(self, tmp_path: Path) -> None:
        content = dedent("""
            [project]
            name = "myapp"
            dependencies = [
                "requests>=2.28.0",
                "flask~=2.0.0"
            ]
        """).strip()

        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(content)

        result = parse_pyproject_toml(toml_file)

        assert len(result.packages) == 2

    def test_parse_poetry(self, tmp_path: Path) -> None:
        content = dedent("""
            [tool.poetry.dependencies]
            python = "^3.11"
            requests = "^2.28.0"
            flask = {version = "^2.0.0", optional = true}
        """).strip()

        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(content)

        result = parse_pyproject_toml(toml_file)

        # Should skip python
        assert len(result.packages) == 2
        names = {p.name for p in result.packages}
        assert "python" not in names


class TestGoMod:
    """Tests for go.mod parser."""

    def test_parse_require_block(self, tmp_path: Path) -> None:
        content = dedent("""
            module github.com/user/repo

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.0
                github.com/lib/pq v1.10.9
            )
        """).strip()

        mod_file = tmp_path / "go.mod"
        mod_file.write_text(content)

        result = parse_go_mod(mod_file)

        assert len(result.packages) == 2
        assert result.packages[0].name == "github.com/gin-gonic/gin"
        assert result.packages[0].version == "v1.9.0"
        assert result.packages[0].ecosystem == "go"

    def test_parse_single_require(self, tmp_path: Path) -> None:
        content = dedent("""
            module github.com/user/repo
            go 1.21
            require github.com/pkg/errors v0.9.1
        """).strip()

        mod_file = tmp_path / "go.mod"
        mod_file.write_text(content)

        result = parse_go_mod(mod_file)

        assert len(result.packages) == 1
