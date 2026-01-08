"""Package file parsers for dependency extraction."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from myosc.core.models import Package


@dataclass
class ParseResult:
    """Result of parsing a package file."""

    packages: list[Package]
    errors: list[str]


def parse_requirements_txt(path: Path) -> ParseResult:
    """Parse Python requirements.txt file.

    Handles:
    - package==version
    - package>=version
    - package~=version
    - Comments and blank lines
    - -r includes (skipped)
    - Environment markers
    """
    packages: list[Package] = []
    errors: list[str] = []

    # Regex to match package specifications
    # Matches: package==1.0.0, package>=1.0.0, package[extra]==1.0.0
    pattern = re.compile(
        r"^([a-zA-Z0-9_-]+)"  # package name
        r"(?:\[[^\]]+\])?"  # optional extras
        r"(?:([=<>~!]+)([a-zA-Z0-9._-]+))?"  # version specifier
    )

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        return ParseResult([], [f"Failed to read {path}: {e}"])

    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()

        # Skip comments, blank lines, and includes
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Remove environment markers
        line = line.split(";")[0].strip()

        match = pattern.match(line)
        if match:
            name = match.group(1)
            version = match.group(3) or ""

            packages.append(
                Package(
                    name=name.lower(),
                    version=version,
                    ecosystem="pypi",
                    path=str(path),
                )
            )
        else:
            errors.append(f"{path}:{line_num}: Could not parse: {line}")

    return ParseResult(packages, errors)


def parse_pyproject_toml(path: Path) -> ParseResult:
    """Parse Python pyproject.toml dependencies.

    Handles:
    - [project.dependencies]
    - [tool.poetry.dependencies]
    """
    packages: list[Package] = []
    errors: list[str] = []

    try:
        import tomli

        content = path.read_bytes()
        data = tomli.loads(content.decode("utf-8"))
    except Exception as e:
        return ParseResult([], [f"Failed to parse {path}: {e}"])

    # Standard PEP 621 format
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        pkg = _parse_pep508(dep)
        if pkg:
            pkg.path = str(path)
            packages.append(pkg)

    # Poetry format
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue

        version = ""
        if isinstance(spec, str):
            version = spec.lstrip("^~>=<")
        elif isinstance(spec, dict):
            version = spec.get("version", "").lstrip("^~>=<")

        packages.append(
            Package(
                name=name.lower(),
                version=version,
                ecosystem="pypi",
                path=str(path),
            )
        )

    return ParseResult(packages, errors)


def parse_package_json(path: Path) -> ParseResult:
    """Parse Node.js package.json dependencies."""
    packages: list[Package] = []
    errors: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as e:
        return ParseResult([], [f"Failed to parse {path}: {e}"])

    # Combine dependencies and devDependencies
    all_deps: dict[str, str] = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_spec in all_deps.items():
        # Strip version prefixes
        version = version_spec.lstrip("^~>=<")

        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="npm",
                path=str(path),
            )
        )

    return ParseResult(packages, errors)


def parse_package_lock_json(path: Path) -> ParseResult:
    """Parse Node.js package-lock.json for exact versions."""
    packages: list[Package] = []
    errors: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as e:
        return ParseResult([], [f"Failed to parse {path}: {e}"])

    # Handle both lockfileVersion 1 and 2/3
    lock_version = data.get("lockfileVersion", 1)

    if lock_version >= 2:
        # v2/v3 format uses "packages"
        pkgs = data.get("packages", {})
        for pkg_path, info in pkgs.items():
            if not pkg_path:  # root package
                continue
            name = info.get("name") or pkg_path.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                packages.append(
                    Package(name=name, version=version, ecosystem="npm", path=str(path))
                )
    else:
        # v1 format uses "dependencies"
        deps = data.get("dependencies", {})
        for name, info in deps.items():
            version = info.get("version", "")
            if version:
                packages.append(
                    Package(name=name, version=version, ecosystem="npm", path=str(path))
                )

    return ParseResult(packages, errors)


def parse_go_mod(path: Path) -> ParseResult:
    """Parse Go go.mod dependencies."""
    packages: list[Package] = []
    errors: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        return ParseResult([], [f"Failed to read {path}: {e}"])

    in_require = False

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("require ("):
            in_require = True
            continue
        elif line == ")":
            in_require = False
            continue

        # Single require statement: require github.com/pkg v1.0.0
        if line.startswith("require "):
            parts = line[8:].split()
            if len(parts) >= 2:
                packages.append(
                    Package(
                        name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        path=str(path),
                    )
                )
        # Inside require block
        elif in_require:
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                packages.append(
                    Package(
                        name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        path=str(path),
                    )
                )

    return ParseResult(packages, errors)


def _parse_pep508(spec: str) -> Package | None:
    """Parse PEP 508 dependency specification."""
    # Simple pattern for common cases
    pattern = re.compile(
        r"^([a-zA-Z0-9_-]+)"  # package name
        r"(?:\[[^\]]+\])?"  # optional extras
        r"(?:([=<>~!]+)([a-zA-Z0-9._-]+))?"  # version specifier
    )

    match = pattern.match(spec.strip())
    if match:
        return Package(
            name=match.group(1).lower(),
            version=match.group(3) or "",
            ecosystem="pypi",
        )
    return None


# Map of supported files to parsers
PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements_dev.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock_json,
    "go.mod": parse_go_mod,
}


def detect_and_parse(path: Path) -> ParseResult:
    """Detect file type and parse packages."""
    parser = PARSERS.get(path.name)
    if parser:
        return parser(path)
    return ParseResult([], [f"Unsupported file type: {path.name}"])
