"""
console/prompt.py — The main interactive console loop for Zephyrveil.

This is the heart of the CLI console. It:
- Runs the main Read-Eval-Print Loop (REPL)
- Routes commands to the right module
- Handles 'use <module>', 'help', 'clear', 'exit', 'show options'
- Switches context between main console and module prompts
- Never shows raw tracebacks — all errors are caught here
- Handles Ctrl+C gracefully (asks to confirm quit)
- Handles Ctrl+L to clear output (banner stays hidden — never reprints)

The console follows the Metasploit pattern:
    zephyrveil > use scan
    scan > show options
    scan > set SOURCE auto
    scan > run
    scan > back
    zephyrveil >
"""

import os
import signal
import sys
from typing import Any

from rich.console import Console

from zephyrveil.console.output import (
    print_error,
    print_help_table,
    print_info,
    print_section,
    print_warning,
)


def _clear_terminal(console: Console) -> None:
    """
    Properly clear the terminal — wipes BOTH the visible screen AND the
    scrollback buffer so mouse-scroll shows nothing above the prompt.

    Uses two ANSI escape sequences:
      \\033[H\\033[2J  — move cursor to top, clear visible screen
      \\033[3J        — clear the scrollback buffer (the mouse-scroll history)

    This is what `clear` command in bash actually does under the hood.
    Rich's console.clear() only does the visible screen — it does NOT
    clear scrollback, which is why scroll-up still showed old output.

    After clearing, prints a single subtle status line so the user
    knows the console is alive and ready. Banner is NEVER reprinted —
    that flag is permanent for the session.
    """
    try:
        # Write directly to stdout — bypasses Rich's buffering
        # \\033[H  = move cursor to position 0,0 (top-left)
        # \\033[2J = erase entire visible screen
        # \\033[3J = erase scrollback buffer (the key fix for mouse scroll)
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()

        # Print a minimal ready-line — no banner (it's gone forever this session)
        console.print(
            "  [dim]zephyrveil — screen cleared. "
            "Type [bold white]help[/bold white] for commands.[/dim]\n"
        )
    except Exception:
        # Absolute fallback — at minimum try the OS clear command
        try:
            os.system("clear")
        except Exception:
            pass


# ── Main console commands help text ──────────────────────────────────────────
MAIN_HELP_COMMANDS = [
    ("help", "Show this help menu"),
    ("show options", "List all available modules with descriptions"),
    ("use scan", "Full threat detection scan — runs everything"),
    ("use log", "Parse logs and enrich all IPs found"),
    ("use ip", "Investigate a single IP address"),
    ("use health", "Run a full system security audit"),
    ("use report", "Generate a report from the last scan"),
    ("use doctor", "Self-diagnostic — check API keys, config, DB"),
    ("use alerts", "Configure and test Telegram alerts"),
    ("clear", "Clear screen output (banner stays gone)"),
    ("exit / quit", "Exit Zephyrveil"),
]

# ── Available modules: name → (description, class path) ─────────────────────
# We import lazily inside the handler to avoid circular imports
MODULE_DESCRIPTIONS: dict[str, str] = {
    "scan": "Full threat detection scan — runs everything in one shot",
    "log": "Parse logs (journalctl/auth.log) and enrich all IPs found",
    "ip": "Investigate a single IP address with all threat intel APIs",
    "health": "Full system security audit — tools, ports, SSH, LUKS, CVEs",
    "report": "Generate PDF and/or JSON report from the last scan",
    "doctor": "Self-diagnostic — validate API keys, config, permissions",
    "alerts": "Configure Telegram alerts and send test messages",
}


def _load_module(name: str) -> Any | None:
    """
    Lazily import and return a module class by name.

    We import lazily here so startup is fast and circular imports are avoided.
    Each module class has a run() method and an options dict.

    Args:
        name: Module name (scan, log, ip, health, report, doctor, alerts).

    Returns:
        Instantiated module object or None if import fails.
    """
    try:
        if name == "scan":
            from zephyrveil.modules.scan import ScanModule

            return ScanModule()
        elif name == "log":
            from zephyrveil.modules.log import LogModule

            return LogModule()
        elif name == "ip":
            from zephyrveil.modules.ip import IPModule

            return IPModule()
        elif name == "health":
            from zephyrveil.modules.health import HealthModule

            return HealthModule()
        elif name == "report":
            from zephyrveil.modules.report import ReportModule

            return ReportModule()
        elif name == "doctor":
            from zephyrveil.modules.doctor import DoctorModule

            return DoctorModule()
        elif name == "alerts":
            from zephyrveil.modules.alerts import AlertsModule

            return AlertsModule()
        else:
            return None
    except ImportError as exc:
        return None
    except Exception:
        return None


def _show_modules_table(console: Console) -> None:
    """
    Print a table of all available modules with descriptions.

    Args:
        console: Rich Console instance.
    """
    try:
        from rich import box
        from rich.table import Table

        table = Table(
            title="[bold cyan]Available Modules[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold white",
            show_lines=False,
        )
        table.add_column("Module", style="bold green", width=12)
        table.add_column("Usage", style="dim white", width=20)
        table.add_column("Description", style="white")

        for mod_name, desc in MODULE_DESCRIPTIONS.items():
            table.add_row(
                mod_name,
                f"use {mod_name}",
                desc,
            )

        console.print()
        console.print(table)
        console.print()
    except Exception:
        pass


def _run_module_loop(
    console: Console, module_name: str, config: dict[str, Any]
) -> None:
    """
    Enter a module's interactive sub-loop.

    Inside this loop:
    - Prompt changes to `modulename >`
    - User can type: show options, set OPTION value, run, back
    - 'back' returns to main console loop
    - All errors caught and shown as friendly messages

    Args:
        console: Rich Console instance.
        module_name: Name of the module to enter.
        config: App config dict.
    """
    try:
        # Load the module
        module = _load_module(module_name)
        if module is None:
            print_error(
                console,
                f"Module '{module_name}' could not be loaded — check installation",
            )
            return

        # Inject config so modules can access API keys, DB path, etc.
        module.config = config

        # Show entry hints
        from zephyrveil.console.output import print_module_hint

        print_module_hint(console, module_name)

        # ── Module sub-loop ──────────────────────────────────────────────
        while True:
            try:
                # Show module prompt: "scan > "
                prompt_str = (
                    "\001\033[0m\002"
                    "  "
                    "\001\033[32;1m\002"
                    f"\u27e6{module_name}\u27e7"
                    "\001\033[0m\002"
                    " "
                    "\001\033[1m\002"
                    "\u00bb"
                    "\001\033[0m\002"
                    " "
                )
                raw = input(prompt_str)
                cmd = raw.strip()

            except KeyboardInterrupt:
                # Ctrl+C inside module — go back to main console
                console.print()
                print_info(console, "Use 'back' to return to main console")
                continue
            except EOFError:
                # Ctrl+D — exit gracefully
                console.print()
                sys.exit(0)

            # Empty input — just show prompt again
            if not cmd:
                continue

            cmd_lower = cmd.lower()

            # ── back: exit module loop ───────────────────────────────────
            if cmd_lower == "back":
                console.print(f"  [dim]Returning to main console...[/dim]")
                console.print()
                return

            # ── show options: display current module options ─────────────
            elif cmd_lower == "show options":
                try:
                    module.show_options(console)
                except Exception:
                    print_error(console, "Could not display options")

            # ── set OPTION value: change a module option ─────────────────
            elif cmd_lower.startswith("set "):
                parts = cmd.split(None, 2)  # "set", "OPTION", "value"
                if len(parts) < 3:
                    print_error(console, "Usage: set OPTION value")
                else:
                    opt_name = parts[1].upper()
                    opt_value = parts[2]
                    try:
                        module.set_option(console, opt_name, opt_value)
                    except Exception:
                        print_error(console, f"Cannot set option '{opt_name}'")

            # ── run: execute the module ──────────────────────────────────
            elif cmd_lower == "run":
                try:
                    module.run(console)
                except KeyboardInterrupt:
                    console.print()
                    print_warning(console, "Scan interrupted by user (Ctrl+C)")
                except Exception as exc:
                    print_error(
                        console,
                        f"Module execution error — try 'use doctor' to diagnose",
                    )

            # ── help: show module-level help ─────────────────────────────
            elif cmd_lower in ("help", "?"):
                try:
                    module.show_help(console)
                except Exception:
                    print_help_table(
                        console,
                        [
                            ("show options", "Show current option values"),
                            ("set OPTION value", "Set an option"),
                            ("run", "Execute this module"),
                            ("back", "Return to main console"),
                            ("help", "Show this help"),
                        ],
                    )

            # ── clear inside module — same behavior as main console ───────
            elif cmd_lower in ("clear", "cls"):
                _clear_terminal(console)
                # Remind user which module they're in after clearing
                console.print(
                    f"  [dim][bold]{module_name}[/bold] module active. "
                    f"Type [bold white]run[/bold white] to execute or "
                    f"[bold white]back[/bold white] to return.[/dim]\n"
                )

            # ── Unknown command ──────────────────────────────────────────
            else:
                print_error(
                    console, f"Unknown command: '{cmd}' — type 'help' for options"
                )

    except Exception:
        print_error(console, f"Module '{module_name}' encountered an unexpected error")
        return


def run_console(console: Console, config: dict[str, Any]) -> None:
    """
    Main console loop — the entry point for the interactive console.

    This function runs forever until the user types 'exit' or presses Ctrl+D.
    It handles all top-level commands and delegates to module loops.

    Args:
        console: Rich Console instance (shared across all modules).
        config: Loaded app config dict.
    """
    try:
        # Ctrl+L is not bound — type 'clear' to wipe screen + scrollback.
        # readline key bindings interfere with Rich's input rendering.

        while True:
            try:
                # Main prompt: "zephyrveil > "
                # \001 and \002 wrap invisible characters so readline counts width correctly.
                # Without these, backspace eats into the prompt because readline
                # miscounts the width of the ANSI color escape codes.
                prompt_str = (
                    "\001\033[0m\002"
                    "  "
                    "\001\033[36;1m\002"
                    "\u27e6zephyrveil\u27e7"
                    "\001\033[0m\002"
                    " "
                    "\001\033[1m\002"
                    "\u00bb"
                    "\001\033[0m\002"
                    " "
                )
                raw = input(prompt_str)
                cmd = raw.strip()

            except KeyboardInterrupt:
                # Ctrl+C at main prompt — ask for confirmation
                console.print()
                try:
                    confirm = (
                        console.input("  [yellow]Really exit? (y/N):[/yellow] ")
                        .strip()
                        .lower()
                    )
                    if confirm in ("y", "yes"):
                        console.print("\n [dim]session ended — stay safe.[/dim]\n")
                        sys.exit(0)
                    else:
                        continue
                except (KeyboardInterrupt, EOFError):
                    console.print("\n [dim]session ended — stay safe.[/dim]\n")
                    sys.exit(0)

            except EOFError:
                # Ctrl+D — clean exit
                console.print("\n [dim]session ended — stay safe.[/dim]\n")
                sys.exit(0)

            # Empty input — show prompt again
            if not cmd:
                continue

            cmd_lower = cmd.lower()
            parts = cmd_lower.split()

            # ── exit / quit ──────────────────────────────────────────────
            if cmd_lower in ("exit", "quit", "q"):
                console.print("\n [dim]session ended — stay safe.[/dim]\n")
                sys.exit(0)

            # ── help ─────────────────────────────────────────────────────
            elif cmd_lower in ("help", "?", "h"):
                console.print()
                console.rule("[bold cyan]  ⟦ ZEPHYRVEIL HELP ⟧  [/bold cyan]", style="cyan")
                console.print()
                # Main commands group
                console.print("  [bold white]CONSOLE[/bold white]")
                print_help_table(console, [
                    ("help",           "Show this help menu"),
                    ("show options",   "List all available modules"),
                    ("clear",          "Clear screen and scrollback"),
                    ("exit / quit",    "Exit Zephyrveil"),
                ])
                console.print("  [bold white]MODULES[/bold white]")
                print_help_table(console, [
                    ("use scan",       "Full threat detection scan — runs everything"),
                    ("use log",        "Parse logs and enrich all IPs found"),
                    ("use ip",         "Investigate a single IP address"),
                    ("use health",     "Run a full system security audit"),
                    ("use history",    "Show recent scan history"),
                    ("use report",     "Generate report from last scan"),
                    ("use doctor",     "Self-diagnostic — check API keys, config, DB"),
                    ("use alerts",     "Configure and test Telegram alerts"),
                ])
                console.print("  [bold white]INSIDE A MODULE[/bold white]")
                print_help_table(console, [
                    ("show options",   "Show current option values"),
                    ("set OPTION val", "Change an option"),
                    ("run",            "Execute the module"),
                    ("back",           "Return to main console"),
                ])

            # ── show options / show modules ──────────────────────────────
            elif cmd_lower in ("show options", "show modules", "list", "modules"):
                _show_modules_table(console)

            # ── clear / cls ──────────────────────────────────────────────
            elif cmd_lower in ("clear", "cls"):
                # Wipe screen + scrollback buffer — mouse scroll shows nothing
                # Banner is NEVER reprinted — it's gone for the whole session
                _clear_terminal(console)

            # ── use <module> ─────────────────────────────────────────────
            elif parts[0] == "use":
                if len(parts) < 2:
                    print_error(
                        console,
                        "Usage: use <module>  — type 'show options' to see all modules",
                    )
                else:
                    module_name = parts[1]
                    if module_name not in MODULE_DESCRIPTIONS:
                        print_error(
                            console,
                            f"Unknown module '{module_name}' — type 'show options' to see all modules",
                        )
                    else:
                        _run_module_loop(console, module_name, config)

            # ── version ──────────────────────────────────────────────────
            elif cmd_lower in ("version", "ver"):
                print_info(
                    console,
                    "Zephyrveil v1.0.0 — Linux Threat Detection & Security Intelligence",
                )

            # ── Unknown command ──────────────────────────────────────────
            else:
                print_error(
                    console,
                    f"Unknown command: '{cmd}' — type 'help' to see all commands",
                )

    except SystemExit:
        raise  # Let sys.exit() propagate cleanly
    except Exception:
        print_error(console, "Console encountered an unexpected error — please restart")
        sys.exit(1)
