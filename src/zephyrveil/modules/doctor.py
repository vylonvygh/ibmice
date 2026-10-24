"""
modules/doctor.py — Self-diagnostic module.

'use doctor' checks everything: API keys, dependencies, file permissions,
network connectivity, and database health. Every issue has an exact fix.
"""

from rich.console import Console
from zephyrveil.modules.base import BaseModule
from zephyrveil.console.output import (
    print_section, print_subsection, print_success, print_warning,
    print_error, print_info,
)


class DoctorModule(BaseModule):
    """Self-diagnostic module — checks all Zephyrveil requirements."""

    NAME        = "doctor"
    DESCRIPTION = "Self-diagnostic — validate API keys, config, deps, permissions"

    DEFAULT_OPTIONS = {
        "FIX": ("false", "Show detailed fix instructions for every issue: true/false"),
    }

    def run(self, console: Console) -> None:
        """Run the full diagnostic and display results."""
        try:
            show_fix = self.options.get("FIX", "false").lower() == "true"

            print_section(console, "ZEPHYRVEIL SELF-DIAGNOSTIC")

            from zephyrveil.auditor.doctor import run_full_diagnostic
            diagnostic = run_full_diagnostic(self.config)

            # ── API Keys ──────────────────────────────────────────────────
            self._show_api_keys(console, diagnostic.get("api_keys", []), show_fix)

            # ── Dependencies ──────────────────────────────────────────────
            self._show_dependencies(console, diagnostic.get("dependencies", []))

            # ── File Permissions ──────────────────────────────────────────
            self._show_permissions(console, diagnostic.get("permissions", []), show_fix)

            # ── Network ───────────────────────────────────────────────────
            self._show_network(console, diagnostic.get("network", {}))

            # ── Database ──────────────────────────────────────────────────
            self._show_database(console, diagnostic.get("database", {}))

            # ── Summary ───────────────────────────────────────────────────
            summary = diagnostic.get("summary", {})
            print_section(console, "DIAGNOSTIC SUMMARY")
            total = summary.get("total_issues", 0)
            crit  = summary.get("critical_issues", 0)
            warns = summary.get("warnings", 0)

            if total == 0:
                print_success(console, "All checks passed — Zephyrveil is fully operational")
            else:
                if crit > 0:
                    print_error(console, f"{crit} critical issue(s) found — some features may not work")
                if warns > 0:
                    print_warning(console, f"{warns} warning(s) found — some features may be limited")
                if not show_fix:
                    print_info(console, "Run: set FIX true  then  run  — to see detailed fix instructions")

        except KeyboardInterrupt:
            print_warning(console, "Diagnostic interrupted")
        except Exception:
            print_error(console, "Doctor module encountered an error")

    def _show_api_keys(self, console, api_keys, show_fix):
        """Display API key status."""
        try:
            print_section(console, "API KEYS")
            for key in api_keys:
                name   = key.get("name", "")
                status = key.get("status", "")
                conf   = key.get("configured", False)

                if conf:
                    print_success(console, f"{name}: configured")
                elif status == "NOT CONFIGURED":
                    print_info(console, f"{name}: optional — {key.get('docs', '')}")
                else:
                    print_warning(console, f"{name}: MISSING — {key.get('docs', '')}")
                    if show_fix:
                        console.print(f"  [dim]  Fix: {key.get('fix', '').replace(chr(10), chr(10) + '         ')}[/dim]")
        except Exception:
            pass

    def _show_dependencies(self, console, deps):
        """Display Python package dependency status."""
        try:
            print_section(console, "PYTHON DEPENDENCIES")
            for dep in deps:
                if dep.get("status") == "OK":
                    print_success(console, f"{dep['package']}: installed")
                else:
                    print_error(console, f"{dep['package']}: {dep['status']} — fix: {dep.get('install_cmd', '')}")
        except Exception:
            pass

    def _show_permissions(self, console, permissions, show_fix):
        """Display file permission check results."""
        try:
            print_section(console, "FILE PERMISSIONS")
            for perm in permissions:
                path   = perm.get("path", "")
                label  = perm.get("type", "")
                status = perm.get("status", "")

                if status == "OK":
                    print_success(console, f"{label}: accessible")
                elif not perm.get("exists"):
                    print_warning(console, f"{label}: not found at {path}")
                    if show_fix:
                        print_info(console, f"Fix: {perm.get('fix', '')}")
                else:
                    print_error(console, f"{label}: {status} — {path}")
                    if show_fix:
                        print_info(console, f"Fix: {perm.get('fix', '')}")
        except Exception:
            pass

    def _show_network(self, console, network):
        """Display network connectivity results."""
        try:
            print_section(console, "NETWORK CONNECTIVITY")
            if network.get("reachable", True):
                print_success(console, "All API endpoints reachable")
            else:
                failed = network.get("failed_hosts", [])
                print_warning(console, f"Cannot reach: {', '.join(failed)}")
                print_info(console, "Fix: Check your internet connection and firewall rules")
        except Exception:
            pass

    def _show_database(self, console, db):
        """Display database health results."""
        try:
            print_section(console, "DATABASE HEALTH")
            if db.get("accessible"):
                print_success(console, "Database accessible")
                if db.get("tables_exist"):
                    print_success(console, "All tables present")
                    counts = db.get("row_counts", {})
                    for table, count in counts.items():
                        console.print(f"  [dim]{table}:[/dim] [white]{count} rows[/white]")
                else:
                    print_error(console, f"Database issue: {db.get('error', '')}")
            else:
                print_error(console, f"Database not accessible: {db.get('error', '')}")
                print_info(console, "Fix: Run zephyrveil — it will recreate the database automatically")
        except Exception:
            pass
