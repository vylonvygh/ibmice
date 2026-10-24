"""
cli.py — Command-line argument parsing for Zephyrveil.

Handles optional CLI flags passed at launch time.
By default (no args), Zephyrveil launches the interactive console.
Flags allow quick one-shot usage without entering the console.

Usage examples:
    zephyrveil                    # Interactive console (default)
    zephyrveil --version          # Print version and exit
    zephyrveil --scan             # Run a full scan and exit
    zephyrveil --health           # Run health check and exit
    zephyrveil --ip 1.2.3.4       # Investigate IP and exit
"""

import argparse
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments passed to the zephyrveil command.

    Returns:
        argparse.Namespace with all parsed arguments.
        If no arguments given, all flags default to False/None.
    """
    try:
        parser = argparse.ArgumentParser(
            prog="zephyrveil",
            description="Zephyrveil — Linux Threat Detection & Security Intelligence",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  zephyrveil                  Launch interactive console
  zephyrveil --scan           Run full scan and exit
  zephyrveil --health         Run system health check and exit
  zephyrveil --ip 192.168.1.1 Investigate single IP and exit
  zephyrveil --version        Show version and exit

For the full interactive experience, run without arguments.
            """,
        )

        parser.add_argument(
            "--version", "-v",
            action="store_true",
            help="Print version and exit",
        )

        parser.add_argument(
            "--scan",
            action="store_true",
            help="Run a full scan non-interactively and exit",
        )

        parser.add_argument(
            "--health",
            action="store_true",
            help="Run system health audit non-interactively and exit",
        )

        parser.add_argument(
            "--ip",
            metavar="IP_ADDRESS",
            help="Investigate a single IP address and exit",
        )

        parser.add_argument(
            "--source",
            metavar="SOURCE",
            default="auto",
            help="Log source: auto, journalctl, /path/to/log (default: auto)",
        )

        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )

        return parser.parse_args()

    except SystemExit:
        raise
    except Exception:
        # Argument parsing failure — return empty namespace (use defaults)
        return argparse.Namespace(
            version=False,
            scan=False,
            health=False,
            ip=None,
            source="auto",
            verbose=False,
        )


def handle_cli_args(args: argparse.Namespace, config: dict[str, Any]) -> bool:
    """
    Handle any non-interactive CLI flags.

    If a flag like --scan or --health was passed, run that module directly
    without entering the interactive console, then exit.

    Args:
        args: Parsed argparse Namespace.
        config: Loaded config dict.

    Returns:
        True if a CLI action was performed (caller should not start console).
        False if no special flags — caller should start the console normally.
    """
    from rich.console import Console
    console = Console(highlight=False)

    try:
        # --version: print and exit
        if args.version:
            console.print("[bold cyan]Zephyrveil[/bold cyan] v1.0.0")
            console.print("[dim]Linux Threat Detection & Security Intelligence[/dim]")
            sys.exit(0)

        # --scan: run full scan and exit
        if args.scan:
            from zephyrveil.modules.scan import ScanModule
            mod = ScanModule()
            mod.config = config
            if args.source != "auto":
                mod.options["SOURCE"] = args.source
            if args.verbose:
                mod.options["VERBOSE"] = "true"
            mod.run(console)
            return True

        # --health: run health check and exit
        if args.health:
            from zephyrveil.modules.health import HealthModule
            mod = HealthModule()
            mod.config = config
            mod.run(console)
            return True

        # --ip: investigate single IP and exit
        if args.ip:
            from zephyrveil.modules.ip import IPModule
            mod = IPModule()
            mod.config = config
            mod.options["TARGET"] = args.ip
            mod.run(console)
            return True

        # No special flags — tell caller to launch interactive console
        return False

    except KeyboardInterrupt:
        console.print("\n  [dim]Interrupted.[/dim]\n")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception:
        console.print("  [bold red]✗[/bold red] CLI execution failed — try running without flags for the interactive console")
        sys.exit(1)
