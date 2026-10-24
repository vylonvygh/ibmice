"""
reporter/pdf_report.py — PDF report generation using ReportLab.

Generates a comprehensive, formatted PDF security report.
Every scan creates a new PDF — never overwrites old ones.
Filename: zephyrveil_report_2025-01-15_14-32-05.pdf

Report sections:
1. Cover page — scan summary, hostname, timestamp
2. Executive Summary — threat counts, severity breakdown
3. Threats Detected — full detail per threat
4. IP Intelligence — enriched data per IP
5. System Audit — tools, network, health, hygiene
6. CVE Findings — vulnerable packages
7. Recommendations — actionable fixes

If PDF generation fails for any reason, falls back gracefully.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


# ── ReportLab imports — wrapped to handle import failures gracefully ──────────
def _import_reportlab():
    """Import reportlab components. Returns None on failure."""
    try:
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        return {
            "A4": A4, "letter": letter,
            "getSampleStyleSheet": getSampleStyleSheet,
            "ParagraphStyle": ParagraphStyle,
            "cm": cm, "mm": mm, "colors": colors,
            "SimpleDocTemplate": SimpleDocTemplate,
            "Paragraph": Paragraph,
            "Spacer": Spacer,
            "Table": Table,
            "TableStyle": TableStyle,
            "PageBreak": PageBreak,
            "HRFlowable": HRFlowable,
            "KeepTogether": KeepTogether,
            "TA_CENTER": TA_CENTER,
            "TA_LEFT": TA_LEFT,
            "TA_RIGHT": TA_RIGHT,
        }
    except ImportError:
        return None


# ── Severity colors for PDF (as RGB tuples 0-1 range) ───────────────────────
SEVERITY_COLORS_RGB = {
    "CRITICAL": (0.85, 0.1,  0.1),
    "HIGH":     (0.9,  0.45, 0.0),
    "MEDIUM":   (0.85, 0.75, 0.0),
    "LOW":      (0.2,  0.4,  0.8),
    "INFO":     (0.5,  0.5,  0.5),
}


def generate_pdf_report(
    scan_data: dict[str, Any],
    output_dir: str,
) -> tuple[bool, str]:
    """
    Generate a full PDF security report from scan data.

    Args:
        scan_data: Complete scan data dict containing all results.
        output_dir: Directory to save the PDF in.

    Returns:
        Tuple of (success: bool, filepath_or_error: str).
    """
    # Check if reportlab is available
    rl = _import_reportlab()
    if rl is None:
        return False, "reportlab not installed — run: uv add reportlab"

    try:
        # ── Setup output path ─────────────────────────────────────────────
        output_path = Path(output_dir).expanduser()
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename  = f"zephyrveil_report_{timestamp}.pdf"
        filepath  = output_path / filename

        # ── Create PDF document ───────────────────────────────────────────
        doc = rl["SimpleDocTemplate"](
            str(filepath),
            pagesize=rl["A4"],
            rightMargin=2 * rl["cm"],
            leftMargin=2 * rl["cm"],
            topMargin=2 * rl["cm"],
            bottomMargin=2 * rl["cm"],
            title="Zephyrveil Security Report",
            author="Zephyrveil v1.0.0",
        )

        # ── Get styles ────────────────────────────────────────────────────
        styles = rl["getSampleStyleSheet"]()
        colors = rl["colors"]

        # Custom styles
        style_title = rl["ParagraphStyle"](
            "ZVTitle",
            parent=styles["Title"],
            fontSize=28,
            textColor=colors.HexColor("#00BFFF"),
            spaceAfter=12,
            alignment=rl["TA_CENTER"],
        )
        style_h1 = rl["ParagraphStyle"](
            "ZVH1",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#00BFFF"),
            spaceBefore=16,
            spaceAfter=8,
            borderPad=4,
        )
        style_h2 = rl["ParagraphStyle"](
            "ZVH2",
            parent=styles["Heading2"],
            fontSize=13,
            textColor=colors.HexColor("#1E90FF"),
            spaceBefore=10,
            spaceAfter=6,
        )
        style_body = rl["ParagraphStyle"](
            "ZVBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=14,
            spaceAfter=4,
        )
        style_mono = rl["ParagraphStyle"](
            "ZVMono",
            parent=styles["Code"],
            fontSize=8,
            leading=12,
            backColor=colors.HexColor("#F0F0F0"),
            leftIndent=10,
        )
        style_center = rl["ParagraphStyle"](
            "ZVCenter",
            parent=styles["Normal"],
            alignment=rl["TA_CENTER"],
            fontSize=10,
        )

        # Collect all story elements
        story = []

        # ── Cover Page ────────────────────────────────────────────────────
        story += _build_cover_page(scan_data, rl, style_title, style_center, style_body, colors)
        story.append(rl["PageBreak"]())

        # ── Executive Summary ─────────────────────────────────────────────
        story += _build_executive_summary(scan_data, rl, style_h1, style_h2, style_body, colors)
        story.append(rl["PageBreak"]())

        # ── Threats Section ───────────────────────────────────────────────
        threats = scan_data.get("threats", [])
        if threats:
            story += _build_threats_section(threats, rl, style_h1, style_h2, style_body, style_mono, colors)
            story.append(rl["PageBreak"]())

        # ── IP Intelligence Section ───────────────────────────────────────
        ip_intel = scan_data.get("ip_intel", [])
        if ip_intel:
            story += _build_ip_intel_section(ip_intel, rl, style_h1, style_h2, style_body, colors)
            story.append(rl["PageBreak"]())

        # ── System Audit Section ──────────────────────────────────────────
        story += _build_audit_section(scan_data, rl, style_h1, style_h2, style_body, colors)

        # ── CVE Findings ──────────────────────────────────────────────────
        cve_data = scan_data.get("audit_cve", {})
        cve_results = cve_data.get("results", []) if isinstance(cve_data, dict) else []
        if cve_results:
            story.append(rl["PageBreak"]())
            story += _build_cve_section(cve_results, rl, style_h1, style_h2, style_body, colors)

        # ── Build PDF ─────────────────────────────────────────────────────
        doc.build(story)

        return True, str(filepath)

    except PermissionError:
        return False, f"Cannot write PDF to {output_dir} — check directory permissions"
    except OSError as exc:
        return False, f"File system error: {exc.strerror}"
    except Exception as exc:
        return False, f"PDF generation failed: {type(exc).__name__} — {exc}"


def _build_cover_page(scan_data, rl, style_title, style_center, style_body, colors):
    """Build the cover page elements."""
    elements = []
    try:
        Paragraph = rl["Paragraph"]
        Spacer    = rl["Spacer"]
        Table     = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm        = rl["cm"]

        elements.append(Spacer(1, 3 * cm))
        elements.append(Paragraph("ZEPHYRVEIL", style_title))
        elements.append(Paragraph("Linux Threat Detection & Security Intelligence", style_center))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph("SECURITY SCAN REPORT", style_center))
        elements.append(Spacer(1, 2 * cm))

        # Scan info table
        now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname  = scan_data.get("hostname", "unknown")
        scan_id   = scan_data.get("scan_id", "unknown")
        source    = scan_data.get("source", "auto")
        threats   = len(scan_data.get("threats", []))
        ips       = len(scan_data.get("ip_intel", []))

        table_data = [
            ["Generated",      now],
            ["Hostname",       hostname],
            ["Scan ID",        scan_id],
            ["Log Source",     source],
            ["Threats Found",  str(threats)],
            ["IPs Analyzed",   str(ips)],
            ["Report Version", "1.0.0"],
        ]

        t = Table(table_data, colWidths=[5 * cm, 10 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#00BFFF")),
            ("BACKGROUND",  (1, 0), (1, -1), colors.HexColor("#f8f8f8")),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (1, 1), (1, -1), [colors.white, colors.HexColor("#f0f4ff")]),
            ("PADDING",     (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 2 * cm))

        # Threat count highlight box
        threat_color = colors.HexColor("#cc0000") if threats > 0 else colors.HexColor("#006600")
        threat_label = f"⚡ {threats} THREAT(S) DETECTED" if threats > 0 else "✓ NO THREATS DETECTED"

        summary_table = Table([[threat_label]], colWidths=[15 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), threat_color),
            ("TEXTCOLOR",  (0, 0), (-1, -1), colors.white),
            ("FONTSIZE",   (0, 0), (-1, -1), 16),
            ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("PADDING",    (0, 0), (-1, -1), 14),
        ]))
        elements.append(summary_table)

    except Exception:
        pass
    return elements


def _build_executive_summary(scan_data, rl, style_h1, style_h2, style_body, colors):
    """Build the executive summary section."""
    elements = []
    try:
        Paragraph  = rl["Paragraph"]
        Spacer     = rl["Spacer"]
        Table      = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm         = rl["cm"]

        elements.append(Paragraph("Executive Summary", style_h1))
        elements.append(rl["HRFlowable"](width="100%", thickness=1, color=colors.HexColor("#00BFFF")))
        elements.append(Spacer(1, 0.3 * cm))

        threats = scan_data.get("threats", [])

        # Severity breakdown
        severity_counts = {}
        for t in threats:
            sev = t.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sev_data = [["Severity", "Count", "Meaning"]]
        sev_info = [
            ("CRITICAL", "Immediate threat, active attack in progress"),
            ("HIGH",     "Serious threat, likely malicious activity"),
            ("MEDIUM",   "Suspicious activity, warrants investigation"),
            ("LOW",      "Minor anomaly, probably benign"),
            ("INFO",     "Informational only"),
        ]
        sev_colors_map = {
            "CRITICAL": "#cc0000",
            "HIGH":     "#e65c00",
            "MEDIUM":   "#cc9900",
            "LOW":      "#0055cc",
            "INFO":     "#666666",
        }

        for sev, meaning in sev_info:
            count = severity_counts.get(sev, 0)
            sev_data.append([sev, str(count), meaning])

        sev_table = Table(sev_data, colWidths=[4 * cm, 2 * cm, 9 * cm])
        style_cmds = [
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("PADDING",      (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]
        for i, (sev, _) in enumerate(sev_info, 1):
            count = severity_counts.get(sev, 0)
            if count > 0:
                hex_c = sev_colors_map.get(sev, "#000000")
                style_cmds.append(("TEXTCOLOR", (0, i), (1, i), colors.HexColor(hex_c)))
                style_cmds.append(("FONTNAME",  (0, i), (1, i), "Helvetica-Bold"))
        sev_table.setStyle(TableStyle(style_cmds))

        elements.append(Paragraph("Threat Severity Breakdown", style_h2))
        elements.append(sev_table)
        elements.append(Spacer(1, 0.5 * cm))

        # Threat type summary
        if threats:
            elements.append(Paragraph("Threat Types Detected", style_h2))
            threat_types = {}
            for t in threats:
                tt = t.get("threat_type", "UNKNOWN")
                threat_types[tt] = threat_types.get(tt, 0) + 1

            type_data = [["Threat Type", "Count", "Top Source IP"]]
            ip_by_type: dict[str, str] = {}
            for t in threats:
                tt = t.get("threat_type", "")
                if tt not in ip_by_type and t.get("source_ip"):
                    ip_by_type[tt] = t.get("source_ip", "")

            for tt, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                type_data.append([
                    tt.replace("_", " "),
                    str(count),
                    ip_by_type.get(tt, "—"),
                ])

            type_table = Table(type_data, colWidths=[7 * cm, 2 * cm, 6 * cm])
            type_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE",     (0, 0), (-1, -1), 9),
                ("PADDING",      (0, 0), (-1, -1), 6),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ]))
            elements.append(type_table)

    except Exception:
        pass
    return elements


def _build_threats_section(threats, rl, style_h1, style_h2, style_body, style_mono, colors):
    """Build the threats detail section."""
    elements = []
    try:
        Paragraph  = rl["Paragraph"]
        Spacer     = rl["Spacer"]
        Table      = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm         = rl["cm"]

        elements.append(Paragraph("Threats Detected", style_h1))
        elements.append(rl["HRFlowable"](width="100%", thickness=1, color=colors.HexColor("#cc0000")))
        elements.append(Spacer(1, 0.3 * cm))

        for i, threat in enumerate(threats, 1):
            try:
                sev      = threat.get("severity", "INFO")
                t_type   = threat.get("threat_type", "").replace("_", " ")
                ip       = threat.get("source_ip", "N/A")
                username = threat.get("username", "N/A")
                count    = threat.get("event_count", 1)
                hex_c    = "#" + "".join(
                    f"{int(c*255):02x}"
                    for c in SEVERITY_COLORS_RGB.get(sev, (0.5, 0.5, 0.5))
                )

                elements.append(Paragraph(
                    f"<font color='{hex_c}'>[{sev}]</font> {i}. {t_type}",
                    style_h2,
                ))

                detail_data = [
                    ["Severity",   sev],
                    ["Source IP",  ip],
                    ["Username",   username],
                    ["Event Count", str(count)],
                ]

                # Add raw_data details if available
                raw = threat.get("raw_data", {})
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        raw = {}

                if isinstance(raw, dict):
                    note = raw.get("note", "")
                    if note:
                        detail_data.append(["Note", note])

                det_table = Table(detail_data, colWidths=[4 * cm, 11 * cm])
                det_table.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#00BFFF")),
                    ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE",    (0, 0), (-1, -1), 9),
                    ("PADDING",     (0, 0), (-1, -1), 5),
                ]))
                elements.append(det_table)
                elements.append(Spacer(1, 0.4 * cm))

            except Exception:
                continue

    except Exception:
        pass
    return elements


def _build_ip_intel_section(ip_intel, rl, style_h1, style_h2, style_body, colors):
    """Build the IP intelligence section."""
    elements = []
    try:
        Paragraph  = rl["Paragraph"]
        Spacer     = rl["Spacer"]
        Table      = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm         = rl["cm"]

        elements.append(Paragraph("IP Intelligence", style_h1))
        elements.append(rl["HRFlowable"](width="100%", thickness=1, color=colors.HexColor("#00BFFF")))
        elements.append(Spacer(1, 0.3 * cm))

        for intel in ip_intel:
            try:
                ip = intel.get("ip_address", "unknown")
                elements.append(Paragraph(f"IP: {ip}", style_h2))

                abuse_score = intel.get("abuse_score", 0) or 0
                vt_mal      = intel.get("vt_malicious", 0) or 0
                vt_tot      = intel.get("vt_total", 0) or 0
                banned      = "YES" if intel.get("fail2ban_banned") else "No"

                rows = [
                    ["Country",       intel.get("country", "—")],
                    ["City",          intel.get("city", "—")],
                    ["Organization",  intel.get("org", "—")],
                    ["ISP",           intel.get("isp", "—")],
                    ["ASN",           intel.get("asn", "—")],
                    ["Hostname",      intel.get("hostname", "—")],
                    ["Abuse Score",   f"{abuse_score}/100"],
                    ["Abuse Reports", str(intel.get("abuse_reports", 0))],
                    ["VirusTotal",    f"{vt_mal}/{vt_tot} engines flagged"],
                    ["Fail2ban",      banned],
                ]

                shodan_ports = intel.get("shodan_ports", [])
                if isinstance(shodan_ports, str):
                    try:
                        shodan_ports = json.loads(shodan_ports)
                    except Exception:
                        shodan_ports = []
                if shodan_ports:
                    rows.append(["Open Ports", ", ".join(str(p) for p in shodan_ports[:15])])

                shodan_vulns = intel.get("shodan_vulns", [])
                if isinstance(shodan_vulns, str):
                    try:
                        shodan_vulns = json.loads(shodan_vulns)
                    except Exception:
                        shodan_vulns = []
                if shodan_vulns:
                    rows.append(["Shodan CVEs", ", ".join(shodan_vulns[:5])])

                t = Table(rows, colWidths=[4 * cm, 11 * cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#00BFFF")),
                    ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE",    (0, 0), (-1, -1), 8),
                    ("PADDING",     (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ]))
                elements.append(t)
                elements.append(Spacer(1, 0.5 * cm))

            except Exception:
                continue

    except Exception:
        pass
    return elements


def _build_audit_section(scan_data, rl, style_h1, style_h2, style_body, colors):
    """Build the system audit section."""
    elements = []
    try:
        Paragraph  = rl["Paragraph"]
        Spacer     = rl["Spacer"]
        Table      = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm         = rl["cm"]

        elements.append(Paragraph("System Security Audit", style_h1))
        elements.append(rl["HRFlowable"](width="100%", thickness=1, color=colors.HexColor("#00BFFF")))
        elements.append(Spacer(1, 0.3 * cm))

        # System health summary
        health = scan_data.get("audit_health", {})
        if health:
            elements.append(Paragraph("System Health", style_h2))
            ram    = health.get("ram", {})
            uptime = health.get("uptime", {})
            cpu    = health.get("cpu", {})

            health_rows = []
            if ram:
                health_rows.append(["RAM",    f"{ram.get('used_mb', 0)}MB / {ram.get('total_mb', 0)}MB ({ram.get('percent_used', 0)}%)"])
            if uptime:
                health_rows.append(["Uptime", uptime.get("uptime_human", "—")])
                health_rows.append(["Load",   f"{uptime.get('load_1m', 0)} / {uptime.get('load_5m', 0)} / {uptime.get('load_15m', 0)}"])
            if cpu:
                health_rows.append(["CPU",    cpu.get("model", "—")])
            health_rows.append(["Kernel",  scan_data.get("kernel", health.get("kernel", "—"))])

            if health_rows:
                ht = Table(health_rows, colWidths=[4 * cm, 11 * cm])
                ht.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#00BFFF")),
                    ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE",    (0, 0), (-1, -1), 9),
                    ("PADDING",     (0, 0), (-1, -1), 5),
                ]))
                elements.append(ht)
                elements.append(Spacer(1, 0.4 * cm))

        # Security tools
        tools_data = scan_data.get("audit_tools", {})
        tools      = tools_data.get("tools", []) if isinstance(tools_data, dict) else []
        if tools:
            elements.append(Paragraph("Security Tools", style_h2))
            tool_rows = [["Tool", "Status", "Description"]]
            for tool in tools:
                status = tool.get("status_label", "")
                color_str = "#006600" if "RUNNING" in status or status == "INSTALLED" else "#cc0000"
                tool_rows.append([
                    tool.get("name", ""),
                    status,
                    tool.get("description", ""),
                ])

            tt = Table(tool_rows, colWidths=[4 * cm, 4 * cm, 7 * cm])
            tt.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("PADDING",      (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ]))
            elements.append(tt)
            elements.append(Spacer(1, 0.4 * cm))

    except Exception:
        pass
    return elements


def _build_cve_section(cve_results, rl, style_h1, style_h2, style_body, colors):
    """Build the CVE findings section."""
    elements = []
    try:
        Paragraph  = rl["Paragraph"]
        Spacer     = rl["Spacer"]
        Table      = rl["Table"]
        TableStyle = rl["TableStyle"]
        cm         = rl["cm"]

        elements.append(Paragraph("CVE Findings", style_h1))
        elements.append(rl["HRFlowable"](width="100%", thickness=1, color=colors.HexColor("#cc9900")))
        elements.append(Spacer(1, 0.3 * cm))

        for pkg_result in cve_results:
            try:
                pkg_name = pkg_result.get("package", "")
                pkg_ver  = pkg_result.get("version", "")
                cves     = pkg_result.get("cves", [])

                elements.append(Paragraph(f"Package: {pkg_name} ({pkg_ver})", style_h2))

                for cve in cves:
                    try:
                        cve_id   = cve.get("cve_id", "")
                        score    = cve.get("score", 0)
                        severity = cve.get("severity", "")
                        desc     = cve.get("description", "")[:250]
                        pub_date = cve.get("published", "")

                        cve_rows = [
                            ["CVE ID",      cve_id],
                            ["Score",       f"{score} ({severity})"],
                            ["Published",   pub_date],
                            ["Description", desc],
                        ]

                        ct = Table(cve_rows, colWidths=[4 * cm, 11 * cm])
                        ct.setStyle(TableStyle([
                            ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#2a2a1e")),
                            ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#FFD700")),
                            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
                            ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
                            ("FONTSIZE",    (0, 0), (-1, -1), 8),
                            ("PADDING",     (0, 0), (-1, -1), 5),
                        ]))
                        elements.append(ct)
                        elements.append(Spacer(1, 0.2 * cm))
                    except Exception:
                        continue

                elements.append(Spacer(1, 0.3 * cm))
            except Exception:
                continue

    except Exception:
        pass
    return elements
