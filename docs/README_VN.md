# MyoSC

## Giới Thiệu

**MyoSC** (Myo Security Scanner) là công cụ quét bảo mật đa năng:
- **Vulnerabilities** - Lỗ hổng trong dependencies (OSV.dev + EPSS)
- **Secrets** - API keys, tokens hardcode trong source code
- **Container Images** - Quét Docker images

---

## Cài Đặt

```bash
# Development
git clone https://github.com/Myozz/myosc.git
cd myosc
poetry install

# Hoặc pip (coming soon)
pip install myosc
```

---

## Cách Sử Dụng

```
Usage: myosc [command] [target] [options]
```

### Commands

```
┌─────────────────────────────────────────────────────────────────┐
│ COMMAND     │ DESCRIPTION                                       │
├─────────────┼───────────────────────────────────────────────────┤
│ fs          │ Quét filesystem (vulnerabilities + secrets)       │
│ vulns       │ Chỉ quét vulnerabilities                          │
│ secrets     │ Chỉ quét secrets                                  │
│ image       │ Quét Docker image (.tar hoặc image name)          │
└─────────────┴───────────────────────────────────────────────────┘
```

### Global Options

```
┌─────────────────────────────────────────────────────────────────┐
│ OPTION              │ DEFAULT   │ DESCRIPTION                   │
├─────────────────────┼───────────┼───────────────────────────────┤
│ -f, --format        │ table     │ Output: table, json, sarif    │
│ -o, --output        │ stdout    │ Ghi ra file                   │
│ -s, --severity      │ low       │ Min severity: critical, high, │
│                     │           │ medium, low                   │
│ -v, --version       │           │ Hiển thị version              │
│ --help              │           │ Hiển thị help                 │
└─────────────────────┴───────────┴───────────────────────────────┘
```

### Ví Dụ

```bash
# Quét toàn bộ project
myosc fs ./my-project

# Chỉ quét vulnerabilities (severity high+)
myosc vulns ./my-project --severity high

# Chỉ quét secrets
myosc secrets ./my-project

# Quét Docker image (extracted)
myosc image python:3.11-slim.tar

# Xuất SARIF cho GitHub
myosc fs . --format sarif --output results.sarif

# Xuất JSON
myosc fs . --format json --output report.json
```

---

## Output Formats

```
┌──────────┬────────────────────────────────────────────────────┐
│ FORMAT   │ MỤC ĐÍCH                                           │
├──────────┼────────────────────────────────────────────────────┤
│ table    │ Xem trực tiếp trên terminal (mặc định)             │
│ json     │ Machine parsing, CI/CD, scripts                    │
│ sarif    │ GitHub Code Scanning, VS Code                      │
└──────────┴────────────────────────────────────────────────────┘
```

---

## Cách Thức Hoạt Động

### Vulnerability Scanner

```
Package Files ──▶ OSV.dev API ──▶ EPSS API ──▶ Priority Score
                  (lỗ hổng)       (xác suất)   (CVSS*0.4 + EPSS*0.6)
```

- **Hỗ trợ:** `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`
- **OSV.dev:** Cập nhật nhanh hơn NVD, focus open-source
- **EPSS:** Xác suất thực tế bị exploit trong 30 ngày

### Secret Scanner

```
Source Files ──▶ 30+ Regex Patterns ──▶ Entropy Analysis ──▶ Placeholder Filter
```

- **Patterns:** AWS, GitHub, Google, Slack, DBs, Private Keys, JWT...
- **Entropy:** Shannon entropy để detect random strings
- **Filter:** Loại bỏ placeholders (`your-api-key`, `xxx`)

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

| Code | Ý nghĩa |
|------|---------|
| 0 | Không có CRITICAL/HIGH findings |
| 1 | Có ít nhất 1 CRITICAL hoặc HIGH |

---

## FAQ

**Q: Tool có gửi source code lên server không?**

Không. Chỉ gửi tên package + version lên OSV.dev.

**Q: EPSS là gì?**

Exploit Prediction Scoring System - xác suất CVE bị exploit trong 30 ngày tới (0-100%).

**Q: Làm sao thêm pattern mới?**

Chỉnh `myosc/scanners/secret_patterns.py`, thêm vào `ALL_PATTERNS`.

## License

MIT
