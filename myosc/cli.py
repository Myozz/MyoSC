"""myosc CLI using Click directly for stability."""

import asyncio
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from myosc import __version__
from myosc.core.models import ScanResult, ScanTarget, Severity, TargetType
from myosc.formatters import JsonFormatter, SarifFormatter, TableFormatter
from myosc.scanners import SecretScanner, VulnerabilityScanner


console = Console()


@click.group()
@click.version_option(__version__, "--version", "-v")
def app() -> None:
    """myosc - Multi-purpose security scanner."""
    pass


@app.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", default="table", help="Output format: table, json, sarif")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="low", help="Min severity: critical, high, medium, low")
@click.option("--no-secrets", is_flag=True, help="Skip secret scanning")
@click.option("--no-vulns", is_flag=True, help="Skip vulnerability scanning")
def fs(
    path: str,
    format: str,
    output: Optional[str],
    severity: str,
    no_secrets: bool,
    no_vulns: bool,
) -> None:
    """Scan filesystem for vulnerabilities and secrets."""
    target = ScanTarget(path=str(Path(path).resolve()), target_type=TargetType.FILESYSTEM)
    result = asyncio.run(_run_scan(target, not no_vulns, not no_secrets))

    min_sev = Severity[severity.upper()]
    result.findings = result.filter_by_severity(min_sev)

    output_path = Path(output) if output else None
    _output_result(result, format, output_path)


@app.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", default="table", help="Output format: table, json, sarif")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def secrets(path: str, format: str, output: Optional[str]) -> None:
    """Scan for secrets only."""
    target = ScanTarget(path=str(Path(path).resolve()), target_type=TargetType.FILESYSTEM)
    result = asyncio.run(_run_scan(target, scan_vulns=False, scan_secrets=True))

    output_path = Path(output) if output else None
    _output_result(result, format, output_path)


@app.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", default="table", help="Output format: table, json, sarif")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="low", help="Min severity: critical, high, medium, low")
def vulns(path: str, format: str, output: Optional[str], severity: str) -> None:
    """Scan for vulnerabilities only."""
    target = ScanTarget(path=str(Path(path).resolve()), target_type=TargetType.FILESYSTEM)
    result = asyncio.run(_run_scan(target, scan_vulns=True, scan_secrets=False))

    min_sev = Severity[severity.upper()]
    result.findings = result.filter_by_severity(min_sev)

    output_path = Path(output) if output else None
    _output_result(result, format, output_path)


@app.command()
@click.argument("image_ref", type=str)
@click.option("--format", "-f", default="table", help="Output format: table, json, sarif")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", default="low", help="Min severity: critical, high, medium, low")
def image(image_ref: str, format: str, output: Optional[str], severity: str) -> None:
    """Scan Docker image for vulnerabilities.

    IMAGE_REF can be a tar file path or Docker image name.
    """
    from myosc.scanners import ImageScanner

    target = ScanTarget(path=image_ref, target_type=TargetType.IMAGE)
    result = asyncio.run(_run_image_scan(target))

    min_sev = Severity[severity.upper()]
    result.findings = result.filter_by_severity(min_sev)

    output_path = Path(output) if output else None
    _output_result(result, format, output_path)


async def _run_image_scan(target: ScanTarget) -> ScanResult:
    """Execute image scan."""
    from myosc.scanners import ImageScanner

    result = ScanResult(target=target)
    errors: list[str] = []

    try:
        scanner = ImageScanner()
        console.print("[dim]Scanning container image...[/dim]")
        findings = await scanner.scan(target)
        result.findings.extend(findings)
        result.scanner_versions["image"] = scanner.version
        await scanner.close()
    except Exception as e:
        errors.append(f"Image scan error: {e}")

    result.errors = errors
    return result


async def _run_scan(
    target: ScanTarget,
    scan_vulns: bool = True,
    scan_secrets: bool = True,
) -> ScanResult:
    """Execute scan with selected scanners."""
    result = ScanResult(target=target)
    errors: list[str] = []

    if scan_vulns:
        try:
            scanner = VulnerabilityScanner()
            console.print("[dim]Scanning for vulnerabilities...[/dim]")
            findings = await scanner.scan(target)
            result.findings.extend(findings)
            result.scanner_versions["vulnerability"] = scanner.version
            await scanner.close()
        except Exception as e:
            errors.append(f"Vulnerability scan error: {e}")

    if scan_secrets:
        try:
            scanner = SecretScanner()
            console.print("[dim]Scanning for secrets...[/dim]")
            findings = await scanner.scan(target)
            result.findings.extend(findings)
            result.scanner_versions["secret"] = scanner.version
        except Exception as e:
            errors.append(f"Secret scan error: {e}")

    result.errors = errors
    return result


def _output_result(result: ScanResult, format: str, output: Optional[Path]) -> None:
    """Format and output result."""
    format = format.lower()

    if format == "table":
        formatter = TableFormatter(console)
        if output:
            output.write_text(formatter.format(result), encoding="utf-8")
            console.print(f"[green]Results written to {output}[/green]")
        else:
            formatter.print(result)

    elif format == "json":
        fmt = JsonFormatter()
        content = fmt.format(result)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Results written to {output}[/green]")
        else:
            console.print(content)

    elif format == "sarif":
        fmt = SarifFormatter()
        content = fmt.format(result)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]SARIF report written to {output}[/green]")
        else:
            console.print(content)

    else:
        console.print(f"[red]Unknown format: {format}[/red]")
        raise SystemExit(1)

    # Exit with error code if critical/high findings
    if result.findings:
        critical_high = sum(
            1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        if critical_high > 0:
            raise SystemExit(1)


def run() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    run()
