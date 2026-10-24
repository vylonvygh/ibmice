"""
reporter/html_report.py — Professional HTML security report for Zephyrveil.

Generates a single self-contained HTML file with embedded CSS.
No JavaScript. No external dependencies. Works offline.
Responsive for both desktop and mobile.

Style: Dark monochrome with deep crimson accent.
Developer: Andre Joseph (Albin S) — @avdrevygh

Report sections:
1.  Project header — tool info, developer details
2.  Scan metadata — host, kernel, date, time, source
3.  Security score — CSS gauge 0-100
4.  Summary cards — threats, IPs, events, CVEs
5.  Severity breakdown — CSS stacked bar
6.  Attack timeline — CSS vertical timeline
7.  Threats detected — severity cards
8.  IP intelligence — table + raw API highlights
9.  Event type breakdown — CSS bar chart
10. Top attacking IPs — ranked with CSS bars
11. Attack geography — country breakdown
12. System audit — pass/fail grid
13. CVE findings — package cards with scores
14. Recommendations — auto-generated action list
15. Scan metadata footer
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Developer / Project constants ─────────────────────────────────────────────
DEVELOPER_NAME = "Andre Joseph (Albin S)"
DEVELOPER_HANDLE = "@avdrevygh"
DEVELOPER_GITHUB = "github.com/avdrevygh"
COLLEGE_NAME = "YIASCM, Balmatta"
PROJECT_VERSION = "1.0.0"
PROJECT_NAME = "Zephyrveil"
PROJECT_DESC = "Linux Threat Detection & Security Intelligence Tool"
PROJECT_LICENSE = "MIT"
PROJECT_PLATFORM = "Linux"
PROJECT_LANGUAGE = "Python 3.11+"


# ── Severity config ────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#cc0000",
    "HIGH": "#cc5500",
    "MEDIUM": "#aa8800",
    "LOW": "#336699",
    "INFO": "#555555",
}

SEVERITY_ICONS = {
    "CRITICAL": "&#9632;",
    "HIGH": "&#9650;",
    "MEDIUM": "&#9670;",
    "LOW": "&#9679;",
    "INFO": "&#9675;",
}


def _calculate_security_score(scan_data: dict[str, Any]) -> tuple[int, str]:
    """
    Calculate a security score from 0 to 100 based on scan findings.

    Deductions:
    - CRITICAL threat:      -15 each
    - HIGH threat:          -10 each
    - MEDIUM threat:        -5 each
    - Failed audit check:   -3 each
    - CVE score >= 7:       -4 each
    - No firewall:          -10
    - PermitRootLogin on:   -10
    - LUKS not active:      -5
    - Missing HIGH tools:   -3 each

    Returns:
        Tuple of (score: int, label: str)
    """
    try:
        score = 100

        # Threat deductions
        threats = scan_data.get("threats", [])
        for threat in threats:
            sev = threat.get("severity", "INFO")
            if sev == "CRITICAL":
                score -= 15
            elif sev == "HIGH":
                score -= 10
            elif sev == "MEDIUM":
                score -= 5

        # Hygiene deductions
        hygiene = scan_data.get("audit_hygiene", {})
        if isinstance(hygiene, dict):
            # Firewall
            fw = hygiene.get("firewall", {})
            if isinstance(fw, dict) and not fw.get("active", True):
                score -= 10

            # LUKS
            luks = hygiene.get("luks", {})
            if isinstance(luks, dict) and not luks.get("luks_active", True):
                score -= 5

            # SSH checks
            ssh_checks = hygiene.get("ssh_checks", [])
            for check in ssh_checks:
                if isinstance(check, dict):
                    if check.get("status") == "FAIL":
                        score -= 3
                    # Extra penalty for PermitRootLogin
                    if (
                        check.get("setting") == "PermitRootLogin"
                        and check.get("status") == "FAIL"
                    ):
                        score -= 7  # Total -10 for this one

        # Tools deductions
        tools = scan_data.get("audit_tools", {})
        if isinstance(tools, dict):
            missing_high = tools.get("missing_high", [])
            score -= len(missing_high) * 3

        # CVE deductions
        cve_data = scan_data.get("audit_cve", {})
        if isinstance(cve_data, dict):
            for pkg in cve_data.get("results", []):
                for cve in pkg.get("cves", []):
                    if float(cve.get("score", 0)) >= 7:
                        score -= 4

        # Clamp to 0-100
        score = max(0, min(100, score))

        # Label
        if score >= 85:
            label = "SECURE"
        elif score >= 70:
            label = "LOW RISK"
        elif score >= 50:
            label = "MODERATE RISK"
        elif score >= 30:
            label = "HIGH RISK"
        else:
            label = "CRITICAL RISK"

        return score, label

    except Exception:
        return 50, "UNKNOWN"


def _get_css() -> str:
    """Return the complete embedded CSS for the report."""
    return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg:         #0a0a0a;
            --bg2:        #111111;
            --bg3:        #1a1a1a;
            --bg4:        #222222;
            --border:     #2a2a2a;
            --border2:    #333333;
            --text:       #e0e0e0;
            --text2:      #aaaaaa;
            --text3:      #666666;
            --accent:     #8b0000;
            --accent2:    #6b0000;
            --accent3:    #aa1111;
            --mono:       'Courier New', 'Lucida Console', monospace;
            --sans:       system-ui, -apple-system, 'Segoe UI', sans-serif;
            --critical:   #cc0000;
            --high:       #cc5500;
            --medium:     #aa8800;
            --low:        #336699;
            --info:       #555555;
            --pass:       #1a5c1a;
            --pass-text:  #44cc44;
            --fail:       #5c1a1a;
            --fail-text:  #cc4444;
            --warn:       #5c4a00;
            --warn-text:  #ccaa00;
        }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
        }

        /* ── Layout ── */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px 16px;
        }

        .section {
            margin-bottom: 32px;
        }

        /* ── Header ── */
        .report-header {
            border-bottom: 1px solid var(--accent);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }

        .header-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
        }

        .project-name {
            font-family: var(--mono);
            font-size: 28px;
            font-weight: bold;
            color: var(--text);
            letter-spacing: 4px;
            text-transform: uppercase;
        }

        .project-name span {
            color: var(--accent3);
        }

        .project-subtitle {
            font-size: 12px;
            color: var(--text3);
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: 4px;
        }

        .report-badge {
            background: var(--accent);
            color: #fff;
            font-family: var(--mono);
            font-size: 10px;
            letter-spacing: 2px;
            padding: 4px 10px;
            text-transform: uppercase;
            border: 1px solid var(--accent3);
        }

        .header-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0;
            border: 1px solid var(--border);
        }

        .header-meta-item {
            padding: 10px 16px;
            border-right: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }

        .header-meta-item:last-child {
            border-right: none;
        }

        .meta-label {
            font-size: 10px;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 2px;
        }

        .meta-value {
            font-family: var(--mono);
            font-size: 13px;
            color: var(--text);
        }

        /* ── Developer info ── */
        .developer-block {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }

        .developer-block .dev-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .dev-name {
            font-size: 15px;
            font-weight: 600;
            color: var(--text);
        }

        .dev-handle {
            font-family: var(--mono);
            font-size: 12px;
            color: var(--accent3);
        }

        .dev-college {
            font-size: 12px;
            color: var(--text2);
        }

        .dev-links {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 2px;
        }

        .dev-link {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
        }

        /* ── Section headers ── */
        .section-title {
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--text3);
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-title::before {
            content: '';
            display: inline-block;
            width: 3px;
            height: 14px;
            background: var(--accent);
        }

        /* ── Security score ── */
        .score-section {
            display: flex;
            align-items: center;
            gap: 40px;
            background: var(--bg2);
            border: 1px solid var(--border);
            padding: 32px;
            flex-wrap: wrap;
        }

        .score-gauge {
            position: relative;
            width: 140px;
            height: 140px;
            flex-shrink: 0;
        }

        .score-ring-bg {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            border: 10px solid var(--bg4);
            position: absolute;
            top: 0;
            left: 0;
        }

        .score-ring {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            position: absolute;
            top: 0;
            left: 0;
            border: 10px solid transparent;
            border-top-color: var(--score-color, var(--accent));
            border-right-color: var(--score-color, var(--accent));
        }

        .score-inner {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .score-number {
            font-family: var(--mono);
            font-size: 36px;
            font-weight: bold;
            line-height: 1;
            color: var(--text);
        }

        .score-max {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
        }

        .score-details {
            flex: 1;
        }

        .score-label {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 2px;
            margin-bottom: 8px;
        }

        .score-description {
            font-size: 13px;
            color: var(--text2);
            line-height: 1.7;
            max-width: 500px;
        }

        .score-factors {
            margin-top: 16px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .score-factor {
            font-family: var(--mono);
            font-size: 10px;
            padding: 3px 8px;
            background: var(--bg3);
            border: 1px solid var(--border);
            color: var(--text2);
        }

        /* ── Summary cards ── */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
        }

        .summary-card {
            background: var(--bg2);
            padding: 20px;
            text-align: center;
        }

        .summary-card-number {
            font-family: var(--mono);
            font-size: 36px;
            font-weight: bold;
            line-height: 1;
            margin-bottom: 6px;
        }

        .summary-card-label {
            font-size: 10px;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--text3);
        }

        .number-threat   { color: var(--critical); }
        .number-ip       { color: var(--text); }
        .number-event    { color: var(--text2); }
        .number-cve      { color: var(--high); }
        .number-pass     { color: var(--pass-text); }
        .number-fail     { color: var(--fail-text); }

        /* ── Severity bar ── */
        .severity-bar-container {
            background: var(--bg2);
            border: 1px solid var(--border);
            padding: 20px;
        }

        .severity-bar {
            display: flex;
            height: 24px;
            overflow: hidden;
            border: 1px solid var(--border2);
            margin-bottom: 12px;
        }

        .severity-segment {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--mono);
            font-size: 10px;
            font-weight: bold;
            color: rgba(255,255,255,0.9);
            transition: none;
            min-width: 0;
            overflow: hidden;
        }

        .severity-legend {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--text2);
        }

        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        /* ── Timeline ── */
        .timeline {
            position: relative;
            padding-left: 24px;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 6px;
            top: 0;
            bottom: 0;
            width: 1px;
            background: var(--border2);
        }

        .timeline-item {
            position: relative;
            margin-bottom: 16px;
            padding: 12px 16px;
            background: var(--bg2);
            border: 1px solid var(--border);
            border-left: 2px solid var(--border2);
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -20px;
            top: 50%;
            transform: translateY(-50%);
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent);
            border: 1px solid var(--accent3);
        }

        .timeline-item.severity-CRITICAL { border-left-color: var(--critical); }
        .timeline-item.severity-CRITICAL::before { background: var(--critical); }
        .timeline-item.severity-HIGH { border-left-color: var(--high); }
        .timeline-item.severity-HIGH::before { background: var(--high); }
        .timeline-item.severity-MEDIUM { border-left-color: var(--medium); }
        .timeline-item.severity-MEDIUM::before { background: var(--medium); }
        .timeline-item.severity-LOW { border-left-color: var(--low); }
        .timeline-item.severity-LOW::before { background: var(--low); }

        .timeline-header {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 4px;
        }

        .timeline-time {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
        }

        .timeline-type {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text);
        }

        .timeline-ip {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--accent3);
        }

        .timeline-user {
            font-size: 11px;
            color: var(--text3);
        }

        /* ── Threat cards ── */
        .threat-card {
            background: var(--bg2);
            border: 1px solid var(--border);
            margin-bottom: 12px;
            overflow: hidden;
        }

        .threat-card-header {
            padding: 12px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 8px;
            border-bottom: 1px solid var(--border);
        }

        .threat-title {
            font-family: var(--mono);
            font-size: 13px;
            font-weight: bold;
            color: var(--text);
        }

        .threat-card-body {
            padding: 14px 16px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
        }

        .threat-field label {
            font-size: 10px;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            display: block;
            margin-bottom: 2px;
        }

        .threat-field value {
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text);
            display: block;
        }

        .threat-raw {
            padding: 10px 16px;
            background: var(--bg);
            border-top: 1px solid var(--border);
        }

        .threat-raw-title {
            font-size: 10px;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 6px;
        }

        .log-line {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
            padding: 2px 0;
            border-bottom: 1px solid var(--border);
            word-break: break-all;
        }

        .log-line:last-child {
            border-bottom: none;
        }

        /* ── Severity badge ── */
        .badge {
            font-family: var(--mono);
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
            padding: 2px 8px;
            border: 1px solid currentColor;
        }

        .badge-CRITICAL { color: var(--critical); border-color: var(--critical); background: rgba(204,0,0,0.1); }
        .badge-HIGH     { color: var(--high);     border-color: var(--high);     background: rgba(204,85,0,0.1); }
        .badge-MEDIUM   { color: var(--medium);   border-color: var(--medium);   background: rgba(170,136,0,0.1); }
        .badge-LOW      { color: var(--low);       border-color: var(--low);     background: rgba(51,102,153,0.1); }
        .badge-INFO     { color: var(--info);      border-color: var(--info);    background: rgba(85,85,85,0.1); }
        .badge-PASS     { color: var(--pass-text); border-color: var(--pass);    background: rgba(26,92,26,0.1); }
        .badge-FAIL     { color: var(--fail-text); border-color: var(--fail);    background: rgba(92,26,26,0.1); }
        .badge-WARN     { color: var(--warn-text); border-color: var(--warn);    background: rgba(92,74,0,0.1); }

        /* ── IP table ── */
        .ip-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }

        .ip-table th {
            background: var(--bg3);
            color: var(--text3);
            font-size: 10px;
            letter-spacing: 1px;
            text-transform: uppercase;
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border2);
            font-weight: 600;
        }

        .ip-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        .ip-table tr:last-child td {
            border-bottom: none;
        }

        .ip-table tr:hover td {
            background: var(--bg3);
        }

        .ip-mono {
            font-family: var(--mono);
            color: var(--accent3);
        }

        /* ── Abuse score bar ── */
        .score-bar-wrapper {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .score-bar-track {
            flex: 1;
            height: 6px;
            background: var(--bg4);
            border: 1px solid var(--border);
            max-width: 80px;
        }

        .score-bar-fill {
            height: 100%;
        }

        .score-bar-text {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text2);
            white-space: nowrap;
        }

        /* ── Port tags ── */
        .port-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 3px;
        }

        .port-tag {
            font-family: var(--mono);
            font-size: 10px;
            padding: 1px 5px;
            background: var(--bg3);
            border: 1px solid var(--border2);
            color: var(--text3);
        }

        /* ── Raw API response ── */
        .api-response-block {
            margin-top: 8px;
            background: var(--bg);
            border: 1px solid var(--border);
            padding: 12px;
        }

        .api-response-title {
            font-size: 10px;
            color: var(--accent3);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 8px;
            font-weight: 600;
        }

        .api-row {
            display: flex;
            gap: 8px;
            padding: 3px 0;
            border-bottom: 1px solid var(--border);
            font-size: 11px;
        }

        .api-row:last-child {
            border-bottom: none;
        }

        .api-key {
            font-family: var(--mono);
            color: var(--text3);
            min-width: 140px;
            flex-shrink: 0;
        }

        .api-val {
            font-family: var(--mono);
            color: var(--text);
            word-break: break-all;
        }

        .api-val.highlight {
            color: var(--accent3);
            font-weight: bold;
        }

        .api-val.danger {
            color: var(--critical);
            font-weight: bold;
        }

        .api-val.safe {
            color: var(--pass-text);
        }

        /* ── IP detail section ── */
        .ip-detail {
            background: var(--bg);
            border: 1px solid var(--border);
            border-top: none;
            padding: 16px;
        }

        .ip-detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px;
        }

        /* ── Bar chart ── */
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .bar-row {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .bar-label {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text2);
            min-width: 180px;
            flex-shrink: 0;
        }

        .bar-track {
            flex: 1;
            height: 18px;
            background: var(--bg3);
            border: 1px solid var(--border);
            max-width: 400px;
        }

        .bar-fill {
            height: 100%;
            background: var(--accent);
            display: flex;
            align-items: center;
            padding-left: 6px;
        }

        .bar-count {
            font-family: var(--mono);
            font-size: 10px;
            color: var(--text);
            min-width: 40px;
            text-align: right;
        }

        /* ── Audit grid ── */
        .audit-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 8px;
        }

        .audit-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 12px;
            background: var(--bg2);
            border: 1px solid var(--border);
        }

        .audit-icon {
            font-size: 14px;
            flex-shrink: 0;
            margin-top: 1px;
        }

        .audit-icon.pass { color: var(--pass-text); }
        .audit-icon.fail { color: var(--fail-text); }
        .audit-icon.warn { color: var(--warn-text); }

        .audit-text {
            flex: 1;
        }

        .audit-label {
            font-size: 12px;
            color: var(--text);
            font-weight: 500;
            margin-bottom: 2px;
        }

        .audit-detail {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
        }

        /* ── CVE cards ── */
        .cve-package {
            background: var(--bg2);
            border: 1px solid var(--border);
            margin-bottom: 12px;
        }

        .cve-package-header {
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 8px;
        }

        .cve-package-name {
            font-family: var(--mono);
            font-size: 14px;
            font-weight: bold;
            color: var(--text);
        }

        .cve-package-version {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
        }

        .cve-item {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }

        .cve-item:last-child {
            border-bottom: none;
        }

        .cve-header {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 8px;
        }

        .cve-id {
            font-family: var(--mono);
            font-size: 13px;
            font-weight: bold;
            color: var(--text);
        }

        .cve-score-display {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .cve-score-box {
            font-family: var(--mono);
            font-size: 13px;
            font-weight: bold;
            padding: 2px 8px;
            border: 1px solid currentColor;
        }

        .cve-score-critical { color: var(--critical); }
        .cve-score-high     { color: var(--high); }
        .cve-score-medium   { color: var(--medium); }
        .cve-score-low      { color: var(--low); }

        .cve-description {
            font-size: 12px;
            color: var(--text2);
            line-height: 1.6;
            margin-top: 6px;
        }

        .cve-meta {
            display: flex;
            gap: 16px;
            margin-top: 6px;
            flex-wrap: wrap;
        }

        .cve-meta-item {
            font-family: var(--mono);
            font-size: 10px;
            color: var(--text3);
        }

        /* ── Recommendations ── */
        .rec-item {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-left: 3px solid var(--border);
            padding: 14px 16px;
            margin-bottom: 8px;
        }

        .rec-item.priority-CRITICAL { border-left-color: var(--critical); }
        .rec-item.priority-HIGH     { border-left-color: var(--high); }
        .rec-item.priority-MEDIUM   { border-left-color: var(--medium); }
        .rec-item.priority-LOW      { border-left-color: var(--low); }

        .rec-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 6px;
            flex-wrap: wrap;
        }

        .rec-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text);
        }

        .rec-description {
            font-size: 12px;
            color: var(--text2);
            margin-bottom: 8px;
            line-height: 1.6;
        }

        .rec-fix {
            background: var(--bg);
            border: 1px solid var(--border);
            padding: 8px 12px;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--accent3);
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* ── Geography table ── */
        .geo-table {
            width: 100%;
            border-collapse: collapse;
        }

        .geo-table th {
            background: var(--bg3);
            color: var(--text3);
            font-size: 10px;
            letter-spacing: 1px;
            text-transform: uppercase;
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border2);
        }

        .geo-table td {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            font-size: 12px;
        }

        .geo-bar-track {
            height: 6px;
            background: var(--bg4);
            border: 1px solid var(--border);
            width: 100%;
            max-width: 200px;
        }

        .geo-bar-fill {
            height: 100%;
            background: var(--accent);
        }

        /* ── Footer ── */
        .report-footer {
            border-top: 1px solid var(--border);
            padding-top: 20px;
            margin-top: 40px;
        }

        .footer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 0;
            border: 1px solid var(--border);
            margin-bottom: 16px;
        }

        .footer-item {
            padding: 10px 16px;
            border-right: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }

        .footer-item:last-child {
            border-right: none;
        }

        .footer-label {
            font-size: 10px;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 2px;
        }

        .footer-value {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text2);
        }

        .footer-bottom {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            padding-top: 12px;
        }

        .footer-brand {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
            letter-spacing: 1px;
        }

        .footer-brand span {
            color: var(--accent3);
        }

        /* ── Responsive ── */
        @media (max-width: 768px) {
            .container { padding: 12px 8px; }
            .project-name { font-size: 20px; letter-spacing: 2px; }
            .score-section { flex-direction: column; align-items: flex-start; padding: 20px; }
            .header-top { flex-direction: column; }
            .dev-links { align-items: flex-start; }
            .summary-cards { grid-template-columns: repeat(2, 1fr); }
            .bar-label { min-width: 120px; font-size: 10px; }
            .ip-table { display: block; overflow-x: auto; }
        }

        @media (max-width: 480px) {
            .summary-cards { grid-template-columns: repeat(2, 1fr); }
            .summary-card-number { font-size: 26px; }
            .score-gauge { width: 100px; height: 100px; }
            .score-ring-bg, .score-ring { width: 100px; height: 100px; }
            .score-number { font-size: 26px; }
        }

        /* ── Print ── */
        @media print {
            body { background: #fff; color: #000; }
            .container { max-width: 100%; }
            .threat-card, .cve-package, .rec-item { break-inside: avoid; }
        }

        /* ── Utilities ── */
        .mono { font-family: var(--mono); }
        .text-dim { color: var(--text3); }
        .text-accent { color: var(--accent3); }
        .mt-8 { margin-top: 8px; }
        .mt-16 { margin-top: 16px; }
        .table-wrapper { overflow-x: auto; }
        .empty-state {
            padding: 24px;
            text-align: center;
            color: var(--text3);
            font-size: 13px;
            background: var(--bg2);
            border: 1px solid var(--border);
        }
    """


def _score_ring_style(score: int) -> str:
    """
    Generate inline CSS for the score ring based on score value.
    Pure CSS rotation trick — no JavaScript needed.
    """
    try:
        if score >= 85:
            color = "#1a8a1a"
        elif score >= 70:
            color = "#5c8a1a"
        elif score >= 50:
            color = "#8a6a00"
        elif score >= 30:
            color = "#8a3300"
        else:
            color = "#8b0000"

        # Calculate rotation based on score
        # Full circle = 360deg, half = 180deg
        # We use border trick: top+right = 50%, top only = 25%
        deg = int((score / 100) * 360)

        if score <= 50:
            # Only top border
            style = f"border-top-color:{color}; transform:rotate({45 + deg}deg);"
        else:
            # Top and right border
            style = f"border-top-color:{color}; border-right-color:{color}; transform:rotate({45 + deg - 180}deg);"

        return style
    except Exception:
        return ""


def _score_label_color(label: str) -> str:
    """Return color for the score label text."""
    colors = {
        "SECURE": "#1a8a1a",
        "LOW RISK": "#5c8a1a",
        "MODERATE RISK": "#8a6a00",
        "HIGH RISK": "#8a3300",
        "CRITICAL RISK": "#8b0000",
        "UNKNOWN": "#555555",
    }
    return colors.get(label, "#555555")


def _build_recommendations(scan_data: dict[str, Any]) -> list[dict[str, str]]:
    """
    Auto-generate recommendations based on scan findings.

    Returns list of dicts: {priority, title, description, fix}
    """
    recs = []

    try:
        threats = scan_data.get("threats", [])
        hygiene = scan_data.get("audit_hygiene", {})
        tools = scan_data.get("audit_tools", {})
        cves = scan_data.get("audit_cve", {})

        # Threat-based recommendations
        threat_types = {t.get("threat_type", "") for t in threats}

        if "SSH_BRUTE_FORCE" in threat_types:
            recs.append(
                {
                    "priority": "CRITICAL",
                    "title": "SSH Brute Force Detected — Install Fail2ban",
                    "description": "Multiple failed SSH login attempts detected from external IPs. Fail2ban will automatically ban IPs that exceed the threshold.",
                    "fix": "sudo pacman -S fail2ban\nsudo systemctl enable --now fail2ban",
                }
            )

        if "ROOT_LOGIN_ATTEMPT" in threat_types:
            recs.append(
                {
                    "priority": "CRITICAL",
                    "title": "Disable Root SSH Login",
                    "description": "Direct root SSH login attempts detected. Root login via SSH should always be disabled.",
                    "fix": "sudo nano /etc/ssh/sshd_config\n# Set: PermitRootLogin no\nsudo systemctl restart sshd",
                }
            )

        if "CREDENTIAL_STUFFING" in threat_types:
            recs.append(
                {
                    "priority": "HIGH",
                    "title": "Credential Stuffing Detected — Enforce Key-Based Auth",
                    "description": "Multiple usernames tried from single IPs. Disable password authentication and use SSH keys only.",
                    "fix": "sudo nano /etc/ssh/sshd_config\n# Set: PasswordAuthentication no\nsudo systemctl restart sshd",
                }
            )

        if "SUDO_ABUSE" in threat_types:
            recs.append(
                {
                    "priority": "HIGH",
                    "title": "Sudo Abuse Detected — Review User Privileges",
                    "description": "Failed sudo authentication detected. Review which users have sudo access and check for unauthorized privilege escalation attempts.",
                    "fix": "sudo cat /etc/sudoers\nsudo grep -r NOPASSWD /etc/sudoers.d/\nlast | head -20",
                }
            )

        # Hygiene recommendations
        if isinstance(hygiene, dict):
            fw = hygiene.get("firewall", {})
            if isinstance(fw, dict) and not fw.get("active", True):
                recs.append(
                    {
                        "priority": "HIGH",
                        "title": "No Active Firewall Detected",
                        "description": "No active firewall found. Enable firewalld or ufw immediately to control inbound and outbound traffic.",
                        "fix": "sudo pacman -S firewalld\nsudo systemctl enable --now firewalld\nsudo firewall-cmd --set-default-zone=drop",
                    }
                )

            luks = hygiene.get("luks", {})
            if isinstance(luks, dict) and not luks.get("luks_active", True):
                recs.append(
                    {
                        "priority": "MEDIUM",
                        "title": "No LUKS Disk Encryption Detected",
                        "description": "Full disk encryption is not active. If the device is lost or stolen, all data is readable without a password.",
                        "fix": "# Enable LUKS on new installations during OS setup\n# For existing systems use cryptsetup on non-system partitions\ncryptsetup luksFormat /dev/sdXN",
                    }
                )

            ssh_checks = hygiene.get("ssh_checks", [])
            for check in ssh_checks:
                if isinstance(check, dict) and check.get("status") in ("FAIL", "WARN"):
                    setting = check.get("setting", "")
                    fix = check.get("fix", "")
                    desc = check.get("description", "")
                    if setting and fix:
                        recs.append(
                            {
                                "priority": "MEDIUM",
                                "title": f"SSH Config Issue: {setting}",
                                "description": desc,
                                "fix": fix,
                            }
                        )

            sudo = hygiene.get("sudo", {})
            if isinstance(sudo, dict) and sudo.get("nopasswd_entries"):
                recs.append(
                    {
                        "priority": "HIGH",
                        "title": "NOPASSWD Entries Found in Sudoers",
                        "description": "Users can run sudo without a password. This is a significant privilege escalation risk.",
                        "fix": "sudo visudo\n# Remove all NOPASSWD entries unless strictly required",
                    }
                )

        # Tools recommendations
        if isinstance(tools, dict):
            missing = tools.get("missing_high", [])
            if missing:
                recs.append(
                    {
                        "priority": "MEDIUM",
                        "title": f"Missing Security Tools: {', '.join(missing)}",
                        "description": "High-priority security tools are not installed. These provide important protection and monitoring capabilities.",
                        "fix": f"sudo pacman -S {' '.join(missing)}",
                    }
                )

        # CVE recommendations
        if isinstance(cves, dict):
            vuln_pkgs = cves.get("results", [])
            critical_pkgs = []
            for pkg in vuln_pkgs:
                for cve in pkg.get("cves", []):
                    if float(cve.get("score", 0)) >= 9:
                        critical_pkgs.append(pkg.get("package", ""))
                        break
            if critical_pkgs:
                recs.append(
                    {
                        "priority": "HIGH",
                        "title": f"Critical CVEs Found in Installed Packages",
                        "description": f"Packages with CVSS score >= 9 found: {', '.join(set(critical_pkgs))}. Update immediately.",
                        "fix": "sudo pacman -Syu\n# Or for specific packages:\nsudo pacman -S "
                        + " ".join(set(critical_pkgs)),
                    }
                )

        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recs.sort(key=lambda r: priority_order.get(r.get("priority", "LOW"), 3))

        # If no recommendations
        if not recs:
            recs.append(
                {
                    "priority": "LOW",
                    "title": "No Critical Issues Found",
                    "description": "No critical or high priority security issues were detected in this scan. Continue regular monitoring.",
                    "fix": "# Run regular scans:\nuv run zephyrveil --scan",
                }
            )

    except Exception:
        pass

    return recs


def _h(text: Any) -> str:
    """HTML escape a value safely."""
    try:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
    except Exception:
        return ""


def _safe(data: Any, key: str, default: str = "—") -> str:
    """Safely get and HTML-escape a value from a dict."""
    try:
        val = data.get(key, default) if isinstance(data, dict) else default
        return _h(val if val not in (None, "", 0) else default)
    except Exception:
        return _h(default)


def _abuse_bar(score: int) -> str:
    """Generate HTML for an abuse score progress bar."""
    try:
        if score >= 75:
            color = "#cc0000"
        elif score >= 30:
            color = "#cc5500"
        elif score >= 10:
            color = "#aa8800"
        else:
            color = "#336699"

        return f"""
        <div class="score-bar-wrapper">
            <div class="score-bar-track">
                <div class="score-bar-fill" style="width:{score}%;background:{color}"></div>
            </div>
            <span class="score-bar-text">{score}/100</span>
        </div>"""
    except Exception:
        return "—"


def _cve_score_class(score: float) -> str:
    """Return CSS class based on CVE score."""
    if score >= 9:
        return "cve-score-critical"
    elif score >= 7:
        return "cve-score-high"
    elif score >= 4:
        return "cve-score-medium"
    else:
        return "cve-score-low"


def _render_header(scan_data: dict[str, Any], score: int, score_label: str) -> str:
    """Render the report header with project info and developer details."""
    try:
        scan_id = _h(scan_data.get("scan_id", "—"))
        hostname = _h(scan_data.get("hostname", "—"))
        kernel = _h(scan_data.get("kernel", "—"))
        source = _h(scan_data.get("source", "—"))
        started = _h(scan_data.get("started_at", "—")[:19])
        finished = _h(scan_data.get("finished_at", "—")[:19])
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_count = scan_data.get("event_count", 0)

        return f"""
        <div class="report-header">
            <div class="header-top">
                <div>
                    <div class="project-name">
                        <span>Z</span>ephyr<span>v</span>eil
                    </div>
                    <div class="project-subtitle">
                        {PROJECT_DESC}
                    </div>
                </div>
                <div class="report-badge">Security Report</div>
            </div>

            <div class="developer-block">
                <div class="dev-info">
                    <span class="dev-name">{_h(DEVELOPER_NAME)}</span>
                    <span class="dev-handle">{_h(DEVELOPER_HANDLE)}</span>
                    <span class="dev-college">{_h(COLLEGE_NAME)}</span>
                </div>
                <div class="dev-links">
                    <span class="dev-link">{_h(DEVELOPER_GITHUB)}</span>
                    <span class="dev-link">v{_h(PROJECT_VERSION)} &mdash; {_h(PROJECT_LICENSE)} License</span>
                    <span class="dev-link">Platform: {_h(PROJECT_PLATFORM)} &mdash; {_h(PROJECT_LANGUAGE)}</span>
                </div>
            </div>

            <div class="header-meta">
                <div class="header-meta-item">
                    <div class="meta-label">Scan ID</div>
                    <div class="meta-value">{scan_id}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Host</div>
                    <div class="meta-value">{hostname}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Kernel</div>
                    <div class="meta-value">{kernel}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Log Source</div>
                    <div class="meta-value">{source}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Scan Started</div>
                    <div class="meta-value">{started}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Scan Finished</div>
                    <div class="meta-value">{finished}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Events Processed</div>
                    <div class="meta-value">{event_count:,}</div>
                </div>
                <div class="header-meta-item">
                    <div class="meta-label">Report Generated</div>
                    <div class="meta-value">{_h(now)}</div>
                </div>
            </div>
        </div>"""
    except Exception:
        return "<div class='report-header'>Header error</div>"


def _render_score(score: int, score_label: str, scan_data: dict[str, Any]) -> str:
    """Render the security score section with CSS gauge."""
    try:
        ring_style = _score_ring_style(score)
        label_color = _score_label_color(score_label)

        threat_count = len(scan_data.get("threats", []))
        ip_count = len(scan_data.get("ip_intel", []))
        cve_count = (
            scan_data.get("audit_cve", {}).get("vuln_count", 0)
            if isinstance(scan_data.get("audit_cve"), dict)
            else 0
        )

        tools = scan_data.get("audit_tools", {})
        missing = tools.get("missing_high", []) if isinstance(tools, dict) else []

        hygiene = scan_data.get("audit_hygiene", {})
        fw_ok = True
        luks_ok = True
        if isinstance(hygiene, dict):
            fw = hygiene.get("firewall", {})
            luks = hygiene.get("luks", {})
            fw_ok = fw.get("active", True) if isinstance(fw, dict) else True
            luks_ok = luks.get("luks_active", True) if isinstance(luks, dict) else True

        score_desc = {
            "SECURE": "System shows strong security posture. Continue regular monitoring and keep software updated.",
            "LOW RISK": "Minor issues detected. Address recommendations to improve security posture.",
            "MODERATE RISK": "Notable security issues found. Review and address high-priority recommendations promptly.",
            "HIGH RISK": "Significant security vulnerabilities detected. Immediate action required on critical items.",
            "CRITICAL RISK": "Critical security threats active. Immediate response required. Review all recommendations.",
            "UNKNOWN": "Could not calculate security score from available data.",
        }.get(score_label, "")

        factors_html = ""
        if threat_count > 0:
            factors_html += (
                f'<span class="score-factor">-{threat_count} threat(s) detected</span>'
            )
        if not fw_ok:
            factors_html += '<span class="score-factor">-firewall inactive</span>'
        if not luks_ok:
            factors_html += '<span class="score-factor">-no LUKS encryption</span>'
        if missing:
            factors_html += (
                f'<span class="score-factor">-{len(missing)} missing tool(s)</span>'
            )
        if cve_count > 0:
            factors_html += (
                f'<span class="score-factor">-{cve_count} CVE(s) found</span>'
            )
        if not factors_html:
            factors_html = '<span class="score-factor">no deductions</span>'

        return f"""
        <div class="section">
            <div class="section-title">Security Score</div>
            <div class="score-section">
                <div class="score-gauge">
                    <div class="score-ring-bg"></div>
                    <div class="score-ring" style="{ring_style}"></div>
                    <div class="score-inner">
                        <div class="score-number">{score}</div>
                        <div class="score-max">/100</div>
                    </div>
                </div>
                <div class="score-details">
                    <div class="score-label" style="color:{label_color}">{_h(score_label)}</div>
                    <div class="score-description">{_h(score_desc)}</div>
                    <div class="score-factors">{factors_html}</div>
                </div>
            </div>
        </div>"""
    except Exception:
        return ""


def _render_summary(scan_data: dict[str, Any]) -> str:
    """Render summary stat cards."""
    try:
        threats = scan_data.get("threats", [])
        ip_intel = scan_data.get("ip_intel", [])
        events = scan_data.get("event_count", 0)
        cve_data = scan_data.get("audit_cve", {})
        cve_count = cve_data.get("vuln_count", 0) if isinstance(cve_data, dict) else 0

        tools = scan_data.get("audit_tools", {})
        inst_count = tools.get("installed_count", 0) if isinstance(tools, dict) else 0
        miss_count = (
            len(tools.get("missing_high", [])) if isinstance(tools, dict) else 0
        )

        return f"""
        <div class="section">
            <div class="section-title">Scan Summary</div>
            <div class="summary-cards">
                <div class="summary-card">
                    <div class="summary-card-number number-threat">{len(threats)}</div>
                    <div class="summary-card-label">Threats Detected</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-number number-ip">{len(ip_intel)}</div>
                    <div class="summary-card-label">IPs Analyzed</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-number number-event">{events:,}</div>
                    <div class="summary-card-label">Log Events</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-number number-cve">{cve_count}</div>
                    <div class="summary-card-label">CVEs Found</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-number number-pass">{inst_count}</div>
                    <div class="summary-card-label">Security Tools</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-number number-fail">{miss_count}</div>
                    <div class="summary-card-label">Missing Tools</div>
                </div>
            </div>
        </div>"""
    except Exception:
        return ""


def _render_severity_bar(threats: list) -> str:
    """Render a CSS stacked severity bar."""
    try:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for t in threats:
            sev = t.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        total = len(threats)
        if total == 0:
            return ""

        segments = ""
        for sev, color in SEVERITY_COLORS.items():
            count = counts.get(sev, 0)
            if count == 0:
                continue
            pct = (count / total) * 100
            segments += f'<div class="severity-segment" style="width:{pct:.1f}%;background:{color}" title="{sev}: {count}">{count}</div>'

        legend = ""
        for sev, color in SEVERITY_COLORS.items():
            count = counts.get(sev, 0)
            if count == 0:
                continue
            legend += f'<div class="legend-item"><div class="legend-dot" style="background:{color}"></div>{sev}: {count}</div>'

        return f"""
        <div class="section">
            <div class="section-title">Threat Severity Breakdown</div>
            <div class="severity-bar-container">
                <div class="severity-bar">{segments}</div>
                <div class="severity-legend">{legend}</div>
            </div>
        </div>"""
    except Exception:
        return ""


def _render_timeline(events: list) -> str:
    """Render a CSS vertical attack timeline."""
    try:
        # Filter to security events only
        security_events = [
            e
            for e in events
            if e.get("event_type")
            in (
                "failed_login",
                "invalid_user",
                "root_login_attempt",
                "sudo_failure",
                "sudo_command",
                "accepted_login",
            )
        ]

        if not security_events:
            return f"""
            <div class="section">
                <div class="section-title">Attack Timeline</div>
                <div class="empty-state">No security events to display in timeline</div>
            </div>"""

        # Take up to 30 most recent events
        display_events = security_events[:30]

        # Assign severity color per event type
        event_severity = {
            "root_login_attempt": "CRITICAL",
            "failed_login": "HIGH",
            "invalid_user": "MEDIUM",
            "sudo_failure": "HIGH",
            "sudo_command": "LOW",
            "accepted_login": "INFO",
        }

        items = ""
        for event in display_events:
            etype = event.get("event_type", "")
            sev = event_severity.get(etype, "INFO")
            time_str = _h(str(event.get("occurred_at", ""))[:19])
            ip = _h(event.get("source_ip", ""))
            username = _h(event.get("username", ""))
            etype_display = _h(etype.replace("_", " ").upper())

            ip_html = f'<span class="timeline-ip">{ip}</span>' if ip else ""
            user_html = (
                f'<span class="timeline-user">user: {username}</span>'
                if username
                else ""
            )

            items += f"""
            <div class="timeline-item severity-{sev}">
                <div class="timeline-header">
                    <span class="badge badge-{sev}">{sev}</span>
                    <span class="timeline-time">{time_str}</span>
                    <span class="timeline-type">{etype_display}</span>
                    {ip_html}
                    {user_html}
                </div>
            </div>"""

        count_note = ""
        if len(security_events) > 30:
            count_note = f'<div class="text-dim" style="font-size:11px;padding:8px 0;">Showing 30 of {len(security_events)} events</div>'

        return f"""
        <div class="section">
            <div class="section-title">Attack Timeline</div>
            {count_note}
            <div class="timeline">{items}</div>
        </div>"""
    except Exception:
        return ""


def _render_threats(threats: list) -> str:
    """Render threat detection cards."""
    try:
        if not threats:
            return f"""
            <div class="section">
                <div class="section-title">Threats Detected</div>
                <div class="empty-state">&#10003; No threats detected in this scan</div>
            </div>"""

        cards = ""
        for i, threat in enumerate(threats, 1):
            sev = threat.get("severity", "INFO")
            ttype = _h(str(threat.get("threat_type", "")).replace("_", " "))
            ip = _h(threat.get("source_ip", "—"))
            username = _h(threat.get("username", "—"))
            count = threat.get("event_count", 1)
            color = SEVERITY_COLORS.get(sev, "#555")

            raw_data = threat.get("raw_data", {})
            if isinstance(raw_data, str):
                try:
                    raw_data = json.loads(raw_data)
                except Exception:
                    raw_data = {}

            # Sample log lines
            sample_lines = (
                raw_data.get("sample_lines", []) if isinstance(raw_data, dict) else []
            )
            logs_html = ""
            if sample_lines:
                logs_html = '<div class="threat-raw"><div class="threat-raw-title">Sample Log Lines</div>'
                for line in sample_lines[:3]:
                    if line:
                        logs_html += f'<div class="log-line">{_h(str(line))}</div>'
                logs_html += "</div>"

            # Raw data details
            raw_html = ""
            if isinstance(raw_data, dict):
                raw_html = '<div class="threat-raw"><div class="threat-raw-title">Raw Detection Data</div>'
                for k, v in list(raw_data.items())[:8]:
                    if k != "sample_lines" and v:
                        raw_html += f'<div class="api-row"><span class="api-key">{_h(k)}</span><span class="api-val">{_h(str(v)[:200])}</span></div>'
                raw_html += "</div>"

            cards += f"""
            <div class="threat-card">
                <div class="threat-card-header" style="border-left:3px solid {color}">
                    <div>
                        <span style="font-size:11px;color:{color};margin-right:8px">#{i}</span>
                        <span class="threat-title">{ttype}</span>
                    </div>
                    <span class="badge badge-{sev}">{sev}</span>
                </div>
                <div class="threat-card-body">
                    <div class="threat-field">
                        <label>Source IP</label>
                        <value class="mono text-accent">{ip}</value>
                    </div>
                    <div class="threat-field">
                        <label>Username</label>
                        <value>{username}</value>
                    </div>
                    <div class="threat-field">
                        <label>Event Count</label>
                        <value>{count}</value>
                    </div>
                    <div class="threat-field">
                        <label>Severity</label>
                        <value style="color:{color}">{sev}</value>
                    </div>
                </div>
                {logs_html}
                {raw_html}
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">Threats Detected ({len(threats)})</div>
            {cards}
        </div>"""
    except Exception:
        return ""


def _render_ip_intelligence(ip_intel: list) -> str:
    """Render IP intelligence table with full raw API responses."""
    try:
        if not ip_intel:
            return f"""
            <div class="section">
                <div class="section-title">IP Intelligence</div>
                <div class="empty-state">No IP intelligence data available</div>
            </div>"""

        # Summary table
        table_rows = ""
        for intel in ip_intel:
            if not isinstance(intel, dict):
                continue

            ip = _h(intel.get("ip_address", "—"))
            country = _h(intel.get("country", "—"))
            org = _h(intel.get("org", "—"))
            abuse_score = intel.get("abuse_score") or 0
            vt_mal = intel.get("vt_malicious") or 0
            vt_tot = intel.get("vt_total") or 0
            ports = intel.get("shodan_ports", [])
            banned = intel.get("fail2ban_banned", False)

            if isinstance(ports, str):
                try:
                    ports = json.loads(ports)
                except Exception:
                    ports = []

            ports_html = ""
            if ports:
                ports_html = '<div class="port-tags">'
                for p in list(ports)[:8]:
                    ports_html += f'<span class="port-tag">{_h(str(p))}</span>'
                if len(ports) > 8:
                    ports_html += f'<span class="port-tag">+{len(ports) - 8}</span>'
                ports_html += "</div>"
            else:
                ports_html = '<span class="text-dim">—</span>'

            banned_html = (
                '<span class="badge badge-FAIL">BANNED</span>'
                if banned
                else '<span class="badge badge-PASS">CLEAN</span>'
            )

            vt_color = "danger" if vt_mal > 0 else "safe"
            vt_html = (
                f'<span class="api-val {vt_color}">{vt_mal}/{vt_tot}</span>'
                if vt_tot
                else "—"
            )

            table_rows += f"""
            <tr>
                <td><span class="ip-mono">{ip}</span></td>
                <td>{country}</td>
                <td style="max-width:200px;word-break:break-word">{org}</td>
                <td>{_abuse_bar(int(abuse_score))}</td>
                <td>{vt_html}</td>
                <td>{ports_html}</td>
                <td>{banned_html}</td>
            </tr>"""

        table = f"""
        <div class="table-wrapper">
        <table class="ip-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>Organization</th>
                    <th>Abuse Score</th>
                    <th>VirusTotal</th>
                    <th>Open Ports</th>
                    <th>Fail2ban</th>
                </tr>
            </thead>
            <tbody>{table_rows}</tbody>
        </table>
        </div>"""

        # Full raw API responses per IP
        detail_sections = ""
        for intel in ip_intel:
            if not isinstance(intel, dict):
                continue

            ip = _h(intel.get("ip_address", "unknown"))

            def render_api_block(
                title: str, raw_key: str, highlights: list[str]
            ) -> str:
                raw = intel.get(raw_key, {})
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        raw = {}
                if not raw or not isinstance(raw, dict):
                    return ""

                rows = ""
                for k, v in list(raw.items())[:20]:
                    if v in (None, "", [], {}):
                        continue
                    val_str = str(v)[:300]
                    css_class = "api-val"
                    if k in highlights:
                        if isinstance(v, (int, float)) and float(v) > 0:
                            css_class = "api-val danger"
                        elif isinstance(v, (int, float)) and float(v) == 0:
                            css_class = "api-val safe"
                        else:
                            css_class = "api-val highlight"
                    rows += f'<div class="api-row"><span class="api-key">{_h(k)}</span><span class="{css_class}">{_h(val_str)}</span></div>'

                if not rows:
                    return ""

                return f"""
                <div class="api-response-block">
                    <div class="api-response-title">{_h(title)}</div>
                    {rows}
                </div>"""

            ipinfo_block = render_api_block(
                "IPInfo Response", "raw_ipinfo", ["country", "org", "hostname"]
            )
            abuse_block = render_api_block(
                "AbuseIPDB Response",
                "raw_abuseipdb",
                ["abuseConfidenceScore", "totalReports", "isTor"],
            )
            vt_block = render_api_block(
                "VirusTotal Response",
                "raw_virustotal",
                ["malicious", "suspicious", "reputation"],
            )
            shodan_block = render_api_block(
                "Shodan Response", "raw_shodan", ["ports", "vulns", "org", "os"]
            )

            all_blocks = ipinfo_block + abuse_block + vt_block + shodan_block
            if all_blocks:
                detail_sections += f"""
                <div class="ip-detail mt-16">
                    <div style="padding:8px 12px;background:var(--bg3);border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;color:var(--accent3)">
                        Full API Response: {ip}
                    </div>
                    <div class="ip-detail-grid" style="padding:12px">
                        {all_blocks}
                    </div>
                </div>"""

        return f"""
        <div class="section">
            <div class="section-title">IP Intelligence ({len(ip_intel)} IPs)</div>
            {table}
            {detail_sections}
        </div>"""
    except Exception:
        return ""


def _render_event_breakdown(events: list) -> str:
    """Render event type breakdown bar chart."""
    try:
        type_counts: dict[str, int] = {}
        for event in events:
            etype = event.get("event_type", "unknown")
            type_counts[etype] = type_counts.get(etype, 0) + 1

        if not type_counts:
            return ""

        total = sum(type_counts.values())
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        max_count = sorted_types[0][1] if sorted_types else 1

        bars = ""
        for etype, count in sorted_types:
            pct = (count / max_count) * 100
            label = _h(etype.replace("_", " ").title())
            bars += f"""
            <div class="bar-row">
                <span class="bar-label">{label}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{pct:.1f}%"></div>
                </div>
                <span class="bar-count">{count:,}</span>
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">Event Type Breakdown</div>
            <div class="bar-chart" style="background:var(--bg2);border:1px solid var(--border);padding:20px">
                {bars}
                <div style="margin-top:12px;font-size:11px;color:var(--text3)">Total events: {total:,}</div>
            </div>
        </div>"""
    except Exception:
        return ""


def _render_top_ips(events: list) -> str:
    """Render top attacking IPs ranked bar chart."""
    try:
        ip_counts: dict[str, int] = {}
        for event in events:
            ip = event.get("source_ip", "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        if not ip_counts:
            return ""

        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        max_count = sorted_ips[0][1] if sorted_ips else 1

        bars = ""
        for i, (ip, count) in enumerate(sorted_ips, 1):
            pct = (count / max_count) * 100
            bars += f"""
            <div class="bar-row">
                <span class="bar-label mono text-accent">#{i} {_h(ip)}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{pct:.1f}%;background:var(--critical)"></div>
                </div>
                <span class="bar-count">{count}</span>
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">Top Attacking IPs</div>
            <div class="bar-chart" style="background:var(--bg2);border:1px solid var(--border);padding:20px">
                {bars}
            </div>
        </div>"""
    except Exception:
        return ""


def _render_geography(ip_intel: list) -> str:
    """Render attack geography by country."""
    try:
        country_counts: dict[str, int] = {}
        for intel in ip_intel:
            if isinstance(intel, dict):
                country = intel.get("country", "")
                if country:
                    country_counts[country] = country_counts.get(country, 0) + 1

        if not country_counts:
            return ""

        sorted_countries = sorted(
            country_counts.items(), key=lambda x: x[1], reverse=True
        )
        total = sum(country_counts.values())

        rows = ""
        for country, count in sorted_countries:
            pct = (count / total) * 100
            rows += f"""
            <tr>
                <td class="mono">{_h(country)}</td>
                <td>{count}</td>
                <td>{pct:.1f}%</td>
                <td>
                    <div class="geo-bar-track">
                        <div class="geo-bar-fill" style="width:{pct:.1f}%"></div>
                    </div>
                </td>
            </tr>"""

        return f"""
        <div class="section">
            <div class="section-title">Attack Geography</div>
            <div class="table-wrapper">
            <table class="geo-table">
                <thead>
                    <tr>
                        <th>Country</th>
                        <th>IP Count</th>
                        <th>Percentage</th>
                        <th>Distribution</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
            </div>
        </div>"""
    except Exception:
        return ""


def _render_system_audit(scan_data: dict[str, Any]) -> str:
    """Render system audit pass/fail grid."""
    try:
        items_html = ""

        # ── Tools ──
        tools = scan_data.get("audit_tools", {})
        if isinstance(tools, dict):
            for tool in tools.get("tools", []):
                if not isinstance(tool, dict):
                    continue
                name = _h(tool.get("name", ""))
                status = tool.get("status_label", "")
                inst = tool.get("installed", False)
                running = tool.get("running", False)
                desc = _h(tool.get("description", ""))

                if running:
                    icon_class = "pass"
                    icon = "&#10003;"
                    detail = "installed &amp; running"
                elif inst:
                    icon_class = "warn"
                    icon = "&#9888;"
                    detail = "installed but not running"
                else:
                    icon_class = "fail"
                    icon = "&#10007;"
                    detail = f"not installed &mdash; {_h(tool.get('install_cmd', ''))}"

                items_html += f"""
                <div class="audit-item">
                    <span class="audit-icon {icon_class}">{icon}</span>
                    <div class="audit-text">
                        <div class="audit-label">{name}</div>
                        <div class="audit-detail">{detail}</div>
                    </div>
                </div>"""

        # ── Network ──
        network = scan_data.get("audit_network", {})
        if isinstance(network, dict):
            pub_ip = _h(network.get("public_ip", "unknown"))
            ports = network.get("open_ports", [])
            items_html += f"""
            <div class="audit-item">
                <span class="audit-icon pass">&#9679;</span>
                <div class="audit-text">
                    <div class="audit-label">Public IP: {pub_ip}</div>
                    <div class="audit-detail">{len(ports)} open port(s) detected</div>
                </div>
            </div>"""

            # Show open ports
            for port_info in ports[:10]:
                if isinstance(port_info, dict):
                    port = port_info.get("port", "")
                    proto = port_info.get("protocol", "")
                    process = _h(port_info.get("process", ""))
                    items_html += f"""
                    <div class="audit-item">
                        <span class="audit-icon warn">&#9670;</span>
                        <div class="audit-text">
                            <div class="audit-label">Port {port}/{proto}</div>
                            <div class="audit-detail">{process if process else "process unknown"}</div>
                        </div>
                    </div>"""

        # ── Health ──
        health = scan_data.get("audit_health", {})
        if isinstance(health, dict):
            kernel = _h(health.get("kernel", "unknown"))
            ram = health.get("ram", {})
            uptime = health.get("uptime", {})
            cpu = health.get("cpu", {})
            procs = health.get("process_count", 0)

            ram_pct = ram.get("percent_used", 0) if isinstance(ram, dict) else 0
            ram_icon = "pass" if ram_pct < 80 else "warn"

            items_html += f"""
            <div class="audit-item">
                <span class="audit-icon pass">&#9679;</span>
                <div class="audit-text">
                    <div class="audit-label">Kernel: {kernel}</div>
                    <div class="audit-detail">{procs} processes running</div>
                </div>
            </div>
            <div class="audit-item">
                <span class="audit-icon {ram_icon}">&#9679;</span>
                <div class="audit-text">
                    <div class="audit-label">RAM: {ram_pct}% used</div>
                    <div class="audit-detail">{ram.get("used_mb", 0) if isinstance(ram, dict) else 0}MB / {ram.get("total_mb", 0) if isinstance(ram, dict) else 0}MB &mdash; uptime: {uptime.get("uptime_human", "unknown") if isinstance(uptime, dict) else "unknown"}</div>
                </div>
            </div>"""

        # ── Hygiene ──
        hygiene = scan_data.get("audit_hygiene", {})
        if isinstance(hygiene, dict):
            # Firewall
            fw = hygiene.get("firewall", {})
            if isinstance(fw, dict):
                fw_active = fw.get("active", False)
                fw_type = _h(fw.get("type", "unknown"))
                items_html += f"""
                <div class="audit-item">
                    <span class="audit-icon {"pass" if fw_active else "fail"}">{"&#10003;" if fw_active else "&#10007;"}</span>
                    <div class="audit-text">
                        <div class="audit-label">Firewall: {"Active" if fw_active else "INACTIVE"}</div>
                        <div class="audit-detail">type: {fw_type}</div>
                    </div>
                </div>"""

            # LUKS
            luks = hygiene.get("luks", {})
            if isinstance(luks, dict):
                luks_active = luks.get("luks_active", False)
                encrypted = luks.get("encrypted_devices", [])
                items_html += f"""
                <div class="audit-item">
                    <span class="audit-icon {"pass" if luks_active else "warn"}">{"&#10003;" if luks_active else "&#9888;"}</span>
                    <div class="audit-text">
                        <div class="audit-label">LUKS Encryption: {"Active" if luks_active else "Not Detected"}</div>
                        <div class="audit-detail">{"devices: " + ", ".join(_h(str(d)) for d in encrypted) if encrypted else "no encrypted devices found"}</div>
                    </div>
                </div>"""

            # SSH checks
            for check in hygiene.get("ssh_checks", []):
                if not isinstance(check, dict):
                    continue
                setting = _h(check.get("setting", ""))
                status = check.get("status", "")
                value = _h(check.get("current_value", ""))
                desc = _h(check.get("description", ""))

                if status == "PASS":
                    icon_class = "pass"
                    icon = "&#10003;"
                elif status == "FAIL":
                    icon_class = "fail"
                    icon = "&#10007;"
                else:
                    icon_class = "warn"
                    icon = "&#9888;"

                items_html += f"""
                <div class="audit-item">
                    <span class="audit-icon {icon_class}">{icon}</span>
                    <div class="audit-text">
                        <div class="audit-label">SSH: {setting} = {value}</div>
                        <div class="audit-detail">{desc}</div>
                    </div>
                </div>"""

            # Sudo
            sudo = hygiene.get("sudo", {})
            if isinstance(sudo, dict):
                nopasswd = sudo.get("nopasswd_entries", [])
                items_html += f"""
                <div class="audit-item">
                    <span class="audit-icon {"warn" if nopasswd else "pass"}">{"&#9888;" if nopasswd else "&#10003;"}</span>
                    <div class="audit-text">
                        <div class="audit-label">Sudo: {"NOPASSWD entries found" if nopasswd else "Password required"}</div>
                        <div class="audit-detail">{f"{len(nopasswd)} NOPASSWD entry(ies) detected" if nopasswd else "All sudo operations require password"}</div>
                    </div>
                </div>"""

        if not items_html:
            return f"""
            <div class="section">
                <div class="section-title">System Audit</div>
                <div class="empty-state">No audit data available — run 'use health' to generate</div>
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">System Audit</div>
            <div class="audit-grid">{items_html}</div>
        </div>"""
    except Exception:
        return ""


def _render_cves(cve_data: dict[str, Any]) -> str:
    """Render CVE findings section."""
    try:
        if not isinstance(cve_data, dict):
            return ""

        results = cve_data.get("results", [])
        checked = cve_data.get("checked_count", 0)
        total = cve_data.get("vuln_count", 0)

        if not results:
            return f"""
            <div class="section">
                <div class="section-title">CVE Findings</div>
                <div class="empty-state">&#10003; No CVEs found in {checked} checked packages</div>
            </div>"""

        cards = ""
        for pkg in results:
            if not isinstance(pkg, dict):
                continue
            pkg_name = _h(pkg.get("package", ""))
            pkg_ver = _h(pkg.get("version", ""))
            cves = pkg.get("cves", [])

            cve_items = ""
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                cve_id = _h(cve.get("cve_id", ""))
                score = float(cve.get("score", 0))
                severity = _h(cve.get("severity", ""))
                desc = _h(cve.get("description", ""))
                pub_date = _h(cve.get("published", ""))
                affected = cve.get("affected_versions", [])

                score_class = _cve_score_class(score)
                affected_str = (
                    ", ".join(_h(str(v)) for v in affected[:3])
                    if affected
                    else "see NVD"
                )

                cve_items += f"""
                <div class="cve-item">
                    <div class="cve-header">
                        <span class="cve-id">{cve_id}</span>
                        <div class="cve-score-display">
                            <span class="cve-score-box {score_class}">{score}</span>
                            <span class="badge badge-{"CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"}">{severity}</span>
                        </div>
                    </div>
                    <div class="cve-description">{desc}</div>
                    <div class="cve-meta">
                        <span class="cve-meta-item">Published: {pub_date}</span>
                        <span class="cve-meta-item">Affected: {affected_str}</span>
                    </div>
                </div>"""

            cards += f"""
            <div class="cve-package">
                <div class="cve-package-header">
                    <span class="cve-package-name">{pkg_name}</span>
                    <span class="cve-package-version">v{pkg_ver}</span>
                    <span class="badge badge-MEDIUM">{len(cves)} CVE(s)</span>
                </div>
                {cve_items}
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">CVE Findings — {total} CVEs in {len(results)} package(s)</div>
            {cards}
        </div>"""
    except Exception:
        return ""


def _render_recommendations(recommendations: list) -> str:
    """Render auto-generated recommendations."""
    try:
        if not recommendations:
            return ""

        items = ""
        for rec in recommendations:
            priority = rec.get("priority", "LOW")
            title = _h(rec.get("title", ""))
            desc = _h(rec.get("description", ""))
            fix = _h(rec.get("fix", ""))

            items += f"""
            <div class="rec-item priority-{priority}">
                <div class="rec-header">
                    <span class="badge badge-{priority}">{priority}</span>
                    <span class="rec-title">{title}</span>
                </div>
                <div class="rec-description">{desc}</div>
                {f'<div class="rec-fix">{fix}</div>' if fix else ""}
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">Recommendations ({len(recommendations)})</div>
            {items}
        </div>"""
    except Exception:
        return ""


def _render_footer(scan_data: dict[str, Any]) -> str:
    """Render the detailed footer with scan metadata."""
    try:
        scan_id = _h(scan_data.get("scan_id", "—"))
        source = _h(scan_data.get("source", "—"))
        hostname = _h(scan_data.get("hostname", "—"))
        kernel = _h(scan_data.get("kernel", "—"))
        started = _h(scan_data.get("started_at", "—")[:19])
        finished = _h(scan_data.get("finished_at", "—")[:19])
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events = scan_data.get("event_count", 0)

        return f"""
        <div class="report-footer">
            <div class="footer-grid">
                <div class="footer-item">
                    <div class="footer-label">Scan ID</div>
                    <div class="footer-value">{scan_id}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Log Source</div>
                    <div class="footer-value">{source}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Hostname</div>
                    <div class="footer-value">{hostname}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Kernel</div>
                    <div class="footer-value">{kernel}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Scan Started</div>
                    <div class="footer-value">{started}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Scan Finished</div>
                    <div class="footer-value">{finished}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Events Processed</div>
                    <div class="footer-value">{events:,}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Report Generated</div>
                    <div class="footer-value">{_h(now)}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Tool Version</div>
                    <div class="footer-value">Zephyrveil v{_h(PROJECT_VERSION)}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Report Format</div>
                    <div class="footer-value">HTML v1.0 — Single File</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Developer</div>
                    <div class="footer-value">{_h(DEVELOPER_NAME)}</div>
                </div>
                <div class="footer-item">
                    <div class="footer-label">Institution</div>
                    <div class="footer-value">{_h(COLLEGE_NAME)}</div>
                </div>
            </div>
            <div class="footer-bottom">
                <div class="footer-brand">
                    <span>{_h(PROJECT_NAME)}</span> v{_h(PROJECT_VERSION)} &mdash;
                    {_h(PROJECT_DESC)}
                </div>
                <div class="footer-brand">
                    {_h(DEVELOPER_GITHUB)} &mdash; {_h(PROJECT_LICENSE)} License
                </div>
            </div>
        </div>"""
    except Exception:
        return ""


def generate_html_report(
    scan_data: dict[str, Any],
    output_dir: str,
) -> tuple[bool, str]:
    """
    Generate a full HTML security report from scan data.

    This is the main entry point called by modules/scan.py
    and modules/report.py.

    Args:
        scan_data: Complete scan data dict from the scan pipeline.
        output_dir: Directory to save the HTML file in.

    Returns:
        Tuple of (success: bool, filepath_or_error: str).
    """
    try:
        # ── Build output path ─────────────────────────────────────────────
        out_path = Path(output_dir).expanduser()
        out_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"zephyrveil_report_{timestamp}.html"
        filepath = out_path / filename

        # ── Compute score ─────────────────────────────────────────────────
        score, score_label = _calculate_security_score(scan_data)

        # ── Extract data ──────────────────────────────────────────────────
        threats = scan_data.get("threats", [])
        ip_intel = scan_data.get("ip_intel", [])
        events = scan_data.get("events", [])
        cve_data = scan_data.get("audit_cve", {})

        # Deserialize any JSON strings from SQLite
        clean_threats = []
        for t in threats:
            if isinstance(t, dict):
                t2 = dict(t)
                if isinstance(t2.get("raw_data"), str):
                    try:
                        t2["raw_data"] = json.loads(t2["raw_data"])
                    except Exception:
                        pass
                clean_threats.append(t2)

        clean_ip_intel = []
        for intel in ip_intel:
            if isinstance(intel, dict):
                intel2 = dict(intel)
                for field in (
                    "shodan_ports",
                    "shodan_vulns",
                    "raw_ipinfo",
                    "raw_abuseipdb",
                    "raw_virustotal",
                    "raw_shodan",
                ):
                    if isinstance(intel2.get(field), str):
                        try:
                            intel2[field] = json.loads(intel2[field])
                        except Exception:
                            pass
                clean_ip_intel.append(intel2)

        # ── Generate recommendations ──────────────────────────────────────
        recommendations = _build_recommendations(scan_data)

        # ── Build HTML ────────────────────────────────────────────────────
        css = _get_css()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="Zephyrveil v{PROJECT_VERSION}">
    <meta name="author" content="{_h(DEVELOPER_NAME)}">
    <title>Zephyrveil Security Report — {_h(scan_data.get("scan_id", ""))}</title>
    <style>{css}</style>
</head>
<body>
<div class="container">

    {_render_header(scan_data, score, score_label)}
    {_render_score(score, score_label, scan_data)}
    {_render_summary(scan_data)}
    {_render_severity_bar(clean_threats)}
    {_render_timeline(events)}
    {_render_threats(clean_threats)}
    {_render_ip_intelligence(clean_ip_intel)}
    {_render_event_breakdown(events)}
    {_render_top_ips(events)}
    {_render_geography(clean_ip_intel)}
    {_render_system_audit(scan_data)}
    {_render_cves(cve_data)}
    {_render_recommendations(recommendations)}
    {_render_footer(scan_data)}

</div>
</body>
</html>"""

        # ── Write file ────────────────────────────────────────────────────
        filepath.write_text(html, encoding="utf-8")
        return True, str(filepath)

    except PermissionError:
        return False, f"Cannot write to {output_dir} — check directory permissions"
    except OSError as exc:
        return False, f"File system error: {exc.strerror}"
    except Exception as exc:
        return False, f"HTML report generation failed: {type(exc).__name__}"
