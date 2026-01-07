# MyoSC - Security Scanner

[![CI](https://github.com/Myozz/myosc/actions/workflows/ci.yml/badge.svg)](https://github.com/Myozz/myosc/actions/workflows/ci.yml)

**[🇻🇳 Tiếng Việt](docs/README_VN.md)**

Multi-purpose security scanner for source code, container images, and secrets.

## Installation

```bash
# Development
git clone https://github.com/Myozz/myosc.git
cd myosc
poetry install

# Or pip (coming soon)
pip install myosc
```

## Usage

```
Usage: myosc [command] [target] [options]
```

### Commands

```
┌─────────────────────────────────────────────────────────────────┐
│ COMMAND     │ DESCRIPTION                                       │
├─────────────┼───────────────────────────────────────────────────┤
│ fs          │ Scan filesystem (vulnerabilities + secrets)       │
│ vulns       │ Scan for vulnerabilities only                     │
│ secrets     │ Scan for secrets only                             │
│ image       │ Scan Docker image (.tar or image name)            │
└─────────────┴───────────────────────────────────────────────────┘
```

### Options

```
┌─────────────────────────────────────────────────────────────────┐
│ OPTION              │ DEFAULT   │ DESCRIPTION                   │
├─────────────────────┼───────────┼───────────────────────────────┤
│ -f, --format        │ table     │ Output: table, json, sarif    │
│ -o, --output        │ stdout    │ Write to file                 │
│ -s, --severity      │ low       │ Min severity: critical, high, │
│                     │           │ medium, low                   │
│ --no-secrets        │           │ Skip secret scanning (fs)     │
│ --no-vulns          │           │ Skip vuln scanning (fs)       │
│ -v, --version       │           │ Show version                  │
│ --help              │           │ Show help                     │
└─────────────────────┴───────────┴───────────────────────────────┘
```

### Examples

```bash
# Full scan
myosc fs ./my-project

# Vulnerabilities only (high+ severity)
myosc vulns ./my-project --severity high

# Secrets only
myosc secrets ./my-project

# Docker image (extracted)
myosc image python:3.11-slim.tar

# SARIF output for GitHub
myosc fs . --format sarif --output results.sarif
```

## Output Formats

```
┌──────────┬────────────────────────────────────────────────────┐
│ FORMAT   │ USE CASE                                           │
├──────────┼────────────────────────────────────────────────────┤
│ table    │ Terminal output (default)                          │
│ json     │ Machine parsing, CI/CD, scripts                    │
│ sarif    │ GitHub Code Scanning, VS Code                      │
└──────────┴────────────────────────────────────────────────────┘
```

---

## How It Works

### Vulnerability Scanner

```
Package Files ──▶ OSV.dev API ──▶ EPSS API ──▶ Priority Score
                  (vulns)         (exploit     (CVSS*0.4 + EPSS*0.6)
                                   probability)
```

- **Supported:** `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`
- **OSV.dev:** Faster updates than NVD, focused on open-source
- **EPSS:** Real-world exploit probability in next 30 days

### Secret Scanner

```
Source Files ──▶ 30+ Regex Patterns ──▶ Entropy Analysis ──▶ Placeholder Filter
```

- **Patterns:** AWS, GitHub, Google, Slack, DBs, Private Keys, JWT...
- **Entropy:** Shannon entropy to detect random strings
- **Filter:** Remove placeholders (`your-api-key`, `xxx`)

### Image Scanner

```
Docker Image ──▶ Layer Extraction ──▶ Package Detection ──▶ Vuln Scan
                                      (dpkg, apk, pip, npm)
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run MyoSC
  run: |
    pip install myosc
    myosc fs . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  script:
    - pip install myosc
    - myosc fs . --format json --output report.json
  artifacts:
    reports:
      sast: report.json
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No CRITICAL/HIGH findings |
| 1 | At least 1 CRITICAL or HIGH finding |

---

## FAQ

**Q: Does the tool send source code to any server?**

No. Only package names + versions are sent to OSV.dev.

**Q: What is EPSS?**

Exploit Prediction Scoring System - probability a CVE will be exploited in the next 30 days (0-100%).

**Q: How to add custom secret patterns?**

Edit `myosc/scanners/secret_patterns.py` and add to `ALL_PATTERNS`.

## License

MIT
