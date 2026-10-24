"""
modules/base.py — Base class for all Zephyrveil console modules.

Every module (scan, log, ip, health, report, doctor, alerts) inherits
from BaseModule. This ensures consistent behavior:
- Options management (set/get/show)
- Standardized run() interface
- Config injection
- Help display

Modules never touch the console engine — they only receive the Rich Console
as a parameter to print() through.
"""

from typing import Any
from rich.console import Console
from rich.table import Table
from rich import box

from zephyrveil.console.output import print_error, print_info


class BaseModule:
    """
    Base class providing common module functionality.

    Subclasses must implement:
    - NAME: str — module name shown in prompt
    - DESCRIPTION: str — shown in 'show options'
    - DEFAULT_OPTIONS: dict[str, tuple[str, str]] — {name: (default, description)}
    - run(console): the actual module logic

    Subclasses may override:
    - show_help(console)
    - validate_options(console) -> bool
    """

    NAME: str = "base"
    DESCRIPTION: str = "Base module"
    DEFAULT_OPTIONS: dict[str, tuple[str, str]] = {}

    def __init__(self):
        """Initialize module with default options and empty config."""
        # options dict holds current values — starts with defaults
        self.options: dict[str, str] = {
            name: default
            for name, (default, _) in self.DEFAULT_OPTIONS.items()
        }
        # Config is injected by the console prompt after instantiation
        self.config: dict[str, Any] = {}

    def set_option(self, console: Console, name: str, value: str) -> None:
        """
        Set a module option value.

        Args:
            console: Rich Console for output.
            name: Option name (case insensitive).
            value: New value to set.
        """
        try:
            name_upper = name.upper()
            if name_upper in self.options:
                self.options[name_upper] = value
                print_info(console, f"{name_upper} => {value}")
            else:
                print_error(console, f"Unknown option '{name}' — type 'show options' to see available options")
        except Exception:
            print_error(console, f"Could not set option '{name}'")

    def show_options(self, console: Console) -> None:
        """
        Display current module options in a formatted table.

        Args:
            console: Rich Console for output.
        """
        try:
            table = Table(
                title=f"[bold cyan]Module: {self.NAME}[/bold cyan]",
                box=box.ROUNDED,
                border_style="cyan",
                header_style="bold white",
                show_lines=False,
            )
            table.add_column("Option",      style="bold green", width=18)
            table.add_column("Current",     style="bold white", width=20)
            table.add_column("Default",     style="dim white",  width=20)
            table.add_column("Description", style="white")

            for name, (default, description) in self.DEFAULT_OPTIONS.items():
                current = self.options.get(name, default)
                # Highlight if value differs from default
                current_display = (
                    f"[bold yellow]{current}[/bold yellow]"
                    if current != default
                    else current
                )
                table.add_row(name, current_display, default, description)

            console.print()
            console.print(table)
            console.print()

        except Exception:
            print_error(console, "Could not display options")

    def show_help(self, console: Console) -> None:
        """
        Display module-specific help.

        Default implementation shows options table + basic commands.
        Override in subclass for custom help text.
        """
        try:
            from zephyrveil.console.output import print_help_table
            console.print(f"\n  [bold cyan]{self.NAME}[/bold cyan] — {self.DESCRIPTION}\n")
            self.show_options(console)
            print_help_table(console, [
                ("show options",       "Show current option values"),
                (f"set OPTION value",  "Change an option value"),
                ("run",                f"Execute the {self.NAME} module"),
                ("back",               "Return to main console"),
            ])
        except Exception:
            pass

    def get_db_path(self) -> str:
        """
        Get the database path from config, with a safe fallback.

        Returns:
            Database file path string.
        """
        try:
            return self.config.get("database", {}).get("path", "~/.local/share/zephyrveil/zephyrveil.db")
        except Exception:
            return "~/.local/share/zephyrveil/zephyrveil.db"

    def get_api_key(self, service: str) -> str:
        """
        Get an API key from config.

        Args:
            service: Key name (abuseipdb, virustotal, shodan, nvd, ipinfo).

        Returns:
            API key string or "" if not configured.
        """
        try:
            return self.config.get("api_keys", {}).get(service, "").strip()
        except Exception:
            return ""

    def get_reports_dir(self) -> str:
        """Get the reports output directory from config."""
        try:
            return self.config.get("reports", {}).get("output_dir", "~/Documents/zephyrveil/")
        except Exception:
            return "~/Documents/zephyrveil/"

    def run(self, console: Console) -> None:
        """
        Execute the module. Must be overridden by subclasses.

        Args:
            console: Rich Console instance for all output.
        """
        print_error(console, f"Module '{self.NAME}' has no run() implementation")
