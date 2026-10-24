"""
console/output.py — Rich formatting helpers for all console output.

This module provides reusable output functions that all modules use
for consistent formatting. Modules should import these helpers instead
of using Rich directly — keeps styling centralized and consistent.

Functions here cover:
- Section headers and dividers
- Success / warning / error / info message lines
- Tables (generic and specialized)
- IP intel display panels
- Threat display panels
- Progress indicators
- Key-value info panels
"""

from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box


# ── Severity color mapping ────────────────────────────────────────────────────
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim white",
}

SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def print_success(console: Console, message: str) -> None:
    """Print a green success/OK line."""
    try:
        console.print(f"  [bold green]✓[/bold green] {message}")
    except Exception:
        pass


def print_warning(console: Console, message: str) -> None:
    """Print a yellow warning line."""
    try:
        console.print(f"  [bold yellow]⚠[/bold yellow]  {message}")
    except Exception:
        pass


def print_error(console: Console, message: str) -> None:
    """Print a red error line."""
    try:
        console.print(f"  [bold red]✗[/bold red] {message}")
    except Exception:
        pass


def print_info(console: Console, message: str) -> None:
    """Print a cyan info line."""
    try:
        console.print(f"  [bold cyan]ℹ[/bold cyan] {message}")
    except Exception:
        pass


def print_section(console: Console, title: str) -> None:
    """Print a styled section divider with title."""
    try:
        console.print()
        console.rule(f"[bold cyan]  {title}  [/bold cyan]", style="dim cyan")
        console.print()
    except Exception:
        pass


def print_subsection(console: Console, title: str) -> None:
    """Print a smaller subsection label."""
    try:
        console.print(f"\n  [bold white]▶ {title}[/bold white]")
    except Exception:
        pass


def print_module_hint(console: Console, module: str) -> None:
    """
    Print the standard module entry hints.

    Shown when a user enters a module with 'use <module>'.
    """
    try:
        console.print()
        console.print(f"  [dim][[bold]{module}[/bold]] Type [bold white]show options[/bold white] to see settings[/dim]")
        console.print(f"  [dim][[bold]{module}[/bold]] Type [bold white]run[/bold white] to execute[/dim]")
        console.print(f"  [dim][[bold]{module}[/bold]] Type [bold white]back[/bold white] to return to main console[/dim]")
        console.print()
    except Exception:
        pass


def print_threat_panel(console: Console, threat: dict[str, Any]) -> None:
    """
    Display a single detected threat in a formatted panel.

    Args:
        console: Rich Console.
        threat: Threat dict with keys: threat_type, severity, source_ip,
                username, event_count, raw_data.
    """
    try:
        severity = threat.get("severity", "INFO")
        color    = SEVERITY_COLORS.get(severity, "white")
        icon     = SEVERITY_ICONS.get(severity, "⚪")
        t_type   = threat.get("threat_type", "UNKNOWN").replace("_", " ")
        ip       = threat.get("source_ip", "N/A")
        user     = threat.get("username", "N/A")
        count    = threat.get("event_count", 1)

        content = Text()
        content.append(f"  Type:      ", style="dim")
        content.append(f"{t_type}\n", style=color)
        content.append(f"  Severity:  ", style="dim")
        content.append(f"{icon} {severity}\n", style=color)
        content.append(f"  Source IP: ", style="dim")
        content.append(f"{ip}\n", style="bold white")
        content.append(f"  Username:  ", style="dim")
        content.append(f"{user}\n", style="white")
        content.append(f"  Events:    ", style="dim")
        content.append(f"{count} log events triggered this alert\n", style="white")

        console.print(Panel(
            content,
            title=f"[{color}]{icon} THREAT DETECTED[/{color}]",
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 1),
        ))
    except Exception:
        pass


def print_ip_intel_table(console: Console, intel: dict[str, Any]) -> None:
    """
    Display enriched IP intelligence in a styled table.

    Args:
        console: Rich Console.
        intel: IP intel dict from integrations modules.
    """
    try:
        ip = intel.get("ip_address", "Unknown")

        table = Table(
            title=f"[bold cyan]🌐 IP Intelligence: {ip}[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("Field", style="dim white", width=22)
        table.add_column("Value", style="bold white")

        # GeoIP / IPInfo data
        rows = [
            ("Country",         intel.get("country", "—")),
            ("City",            intel.get("city", "—")),
            ("Organization",    intel.get("org", "—")),
            ("ISP",             intel.get("isp", "—")),
            ("ASN",             intel.get("asn", "—")),
            ("Hostname",        intel.get("hostname", "—")),
        ]

        # AbuseIPDB data
        abuse_score = intel.get("abuse_score")
        if abuse_score is not None:
            score_color = "red" if abuse_score > 50 else ("yellow" if abuse_score > 10 else "green")
            rows.append(("Abuse Score", f"[{score_color}]{abuse_score}/100[/{score_color}]"))
            rows.append(("Abuse Reports", str(intel.get("abuse_reports", 0))))

        # VirusTotal data
        vt_mal = intel.get("vt_malicious")
        vt_tot = intel.get("vt_total")
        if vt_mal is not None:
            vt_color = "red" if vt_mal > 0 else "green"
            rows.append(("VirusTotal", f"[{vt_color}]{vt_mal}/{vt_tot} engines flagged[/{vt_color}]"))

        # Shodan data
        shodan_ports = intel.get("shodan_ports", [])
        if shodan_ports:
            rows.append(("Open Ports (Shodan)", ", ".join(str(p) for p in shodan_ports[:15])))
        shodan_vulns = intel.get("shodan_vulns", [])
        if shodan_vulns:
            rows.append(("Vulns (Shodan)", f"[red]{', '.join(shodan_vulns[:5])}[/red]"))

        # Fail2ban
        banned = intel.get("fail2ban_banned", False)
        rows.append(("Fail2ban Status", "[red]BANNED[/red]" if banned else "[green]Not banned[/green]"))

        for field, value in rows:
            table.add_row(field, value)

        console.print(table)
        console.print()

    except Exception:
        pass


def build_threats_summary_table(threats: list[dict[str, Any]]) -> Table:
    """
    Build a Rich Table summarizing all detected threats.

    Args:
        threats: List of threat dicts.

    Returns:
        A Rich Table ready to print.
    """
    table = Table(
        title="[bold red]⚡ Threats Detected[/bold red]",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("#",        style="dim",       width=4)
    table.add_column("Severity", style="bold",      width=10)
    table.add_column("Type",     style="cyan",      width=28)
    table.add_column("Source IP",style="white",     width=18)
    table.add_column("Username", style="white",     width=16)
    table.add_column("Events",   style="dim white", width=8)

    for i, threat in enumerate(threats, 1):
        try:
            sev   = threat.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "white")
            icon  = SEVERITY_ICONS.get(sev, "⚪")
            table.add_row(
                str(i),
                f"[{color}]{icon} {sev}[/{color}]",
                threat.get("threat_type", "").replace("_", " "),
                threat.get("source_ip", "—"),
                threat.get("username", "—"),
                str(threat.get("event_count", 1)),
            )
        except Exception:
            continue

    return table


def build_kv_panel(title: str, data: dict[str, Any], border_color: str = "cyan") -> Panel:
    """
    Build a simple key-value panel for displaying structured data.

    Args:
        title: Panel title.
        data: Dict of key: value pairs to display.
        border_color: Rich color name for border.

    Returns:
        A Rich Panel.
    """
    try:
        content = Text()
        for key, value in data.items():
            content.append(f"  {key:<24}", style="dim white")
            content.append(f"{value}\n", style="bold white")

        return Panel(
            content,
            title=f"[bold {border_color}]{title}[/bold {border_color}]",
            border_style=border_color,
            box=box.ROUNDED,
            padding=(0, 1),
        )
    except Exception:
        return Panel("Error rendering panel", title=title)


def print_help_table(console: Console, commands: list[tuple[str, str]]) -> None:
    """
    Print a formatted help table of commands and descriptions.

    Args:
        console: Rich Console.
        commands: List of (command, description) tuples.
    """
    try:
        table = Table(
            box=box.SIMPLE,
            border_style="dim",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 2),
        )
        table.add_column("Command",     style="bold green", width=30)
        table.add_column("Description", style="white")

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        console.print(table)
    except Exception:
        pass


def print_scan_header(console: Console, scan_id: str, source: str) -> None:
    """
    Print the scan start header panel.

    Args:
        console: Rich Console.
        scan_id: The unique scan session ID.
        source: The log source being scanned.
    """
    try:
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        content = (
            f"  [dim]Scan ID:[/dim]    [bold white]{scan_id}[/bold white]\n"
            f"  [dim]Source:[/dim]     [bold white]{source}[/bold white]\n"
            f"  [dim]Started:[/dim]    [bold white]{now}[/bold white]"
        )

        console.print(Panel(
            content,
            title="[bold cyan]🔍 SCAN STARTING[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE_EDGE,
        ))
        console.print()
    except Exception:
        pass
