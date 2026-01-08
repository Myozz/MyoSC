"""Rich table formatter for CLI output."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

from myosc.core.models import (
    ScanResult,
    SecretFinding,
    Severity,
    VulnerabilityFinding,
)
from myosc.formatters.base import BaseFormatter

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.UNKNOWN: "dim",
}


class TableFormatter(BaseFormatter):
    """Rich table output formatter."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    @property
    def name(self) -> str:
        return "table"

    @property
    def file_extension(self) -> str:
        return ".txt"

    def format(self, result: ScanResult) -> str:
        """Format result as table string."""
        # Use string IO to capture console output
        from io import StringIO

        string_io = StringIO()
        console = Console(file=string_io, force_terminal=True)

        self._render_to_console(result, console)

        return string_io.getvalue()

    def print(self, result: ScanResult) -> None:
        """Print result to console."""
        self._render_to_console(result, self._console)

    def _render_to_console(self, result: ScanResult, console: Console) -> None:
        """Render result to console."""
        # Summary header
        console.print()
        console.print(f"[bold]Target:[/bold] {result.target.path}")
        console.print(f"[bold]Scan Time:[/bold] {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print()

        # Vulnerability summary
        vuln_counts = result.vulnerability_count
        total_vulns = sum(vuln_counts.values())

        if total_vulns > 0:
            console.print("[bold]Vulnerability Summary:[/bold]")
            summary_parts = []
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = vuln_counts[sev]
                if count > 0:
                    color = SEVERITY_COLORS[sev]
                    summary_parts.append(f"[{color}]{sev.value}: {count}[/{color}]")
            console.print("  " + " | ".join(summary_parts))
            console.print()

        # Secret summary
        secret_count = result.secret_count
        if secret_count > 0:
            console.print(f"[bold]Secrets Detected:[/bold] [red]{secret_count}[/red]")
            console.print()

        # Vulnerabilities table
        vuln_findings = [f for f in result.findings if isinstance(f, VulnerabilityFinding)]
        if vuln_findings:
            self._print_vulnerabilities(vuln_findings, console)

        # Secrets table
        secret_findings = [f for f in result.findings if isinstance(f, SecretFinding)]
        if secret_findings:
            self._print_secrets(secret_findings, console)

        # Errors
        if result.errors:
            console.print("[bold red]Errors:[/bold red]")
            for error in result.errors:
                console.print(f"  [red]- {error}[/red]")

        # No findings message
        if not result.findings:
            console.print("[green]No vulnerabilities or secrets detected.[/green]")

    def _print_vulnerabilities(self, findings: list[VulnerabilityFinding], console: Console) -> None:
        """Print vulnerabilities table."""
        # Sort by priority score (highest first)
        findings = sorted(findings, key=lambda f: f.priority_score, reverse=True)

        table = Table(title="Vulnerabilities", show_header=True, header_style="bold")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Package", style="green")
        table.add_column("Version", style="dim")
        table.add_column("Fixed", style="green dim")
        table.add_column("CVSS", justify="right")
        table.add_column("EPSS", justify="right")
        table.add_column("Title", max_width=40)

        for f in findings:
            # Severity with color
            sev_color = SEVERITY_COLORS[f.severity]
            severity = Text(f.severity.value, style=sev_color)

            # Package info
            pkg_name = f.affected_package.name if f.affected_package else "-"
            pkg_version = f.affected_package.version if f.affected_package else "-"

            # CVSS and EPSS scores
            cvss = f"{f.cvss_score:.1f}" if f.cvss_score else "-"
            epss = f"{f.epss_score:.1%}" if f.epss_score else "-"

            table.add_row(
                f.cve_id or f.id,
                severity,
                pkg_name,
                pkg_version,
                f.fixed_version or "-",
                cvss,
                epss,
                f.title[:40],
            )

        console.print(table)
        console.print()

    def _print_secrets(self, findings: list[SecretFinding], console: Console) -> None:
        """Print secrets table."""
        table = Table(title="Secrets", show_header=True, header_style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("File", style="green")
        table.add_column("Line", justify="right")
        table.add_column("Match", style="red")
        table.add_column("Entropy", justify="right")

        for f in findings:
            sev_color = SEVERITY_COLORS[f.severity]
            severity = Text(f.severity.value, style=sev_color)

            table.add_row(
                f.secret_type,
                severity,
                f.file_path.split("/")[-1] if "/" in f.file_path else f.file_path.split("\\")[-1],
                str(f.line_number),
                f.match,
                f"{f.entropy:.2f}" if f.entropy else "-",
            )

        console.print(table)
        console.print()
