"""
main.py — Entry point for Zephyrveil.

Startup sequence:
1. Parse CLI arguments (--scan, --ip, --health flags for non-interactive use)
2. First run setup (create config, DB, directories)
3. Database initialization
4. Splash screen
5. Clear + Banner (once only)
6. Interactive console loop
"""

import sys
from rich.console import Console

if sys.platform != "linux":
    print("Zephyrveil runs on Linux only.")
    sys.exit(1)


def main() -> None:
    """
    Main entry point called by the `zephyrveil` console script
    and by `python -m zephyrveil`.
    """
    console = Console(highlight=False)

    try:
        # Step 0: Parse CLI arguments
        from zephyrveil.cli import parse_args
        args = parse_args()

        # Step 1: First run setup (dirs, config.toml)
        from zephyrveil.config.settings import first_run_setup
        setup_result   = first_run_setup()
        config         = setup_result["config"]
        created_dirs   = setup_result.get("created_dirs", [])
        config_created = setup_result.get("config_created", False)

        # Step 2: Initialize database schema
        from zephyrveil.storage.db import initialize_database
        db_path  = config["database"]["path"]
        db_ok, _ = initialize_database(db_path)

        # Step 3: Handle non-interactive CLI flags
        from zephyrveil.cli import handle_cli_args
        if handle_cli_args(args, config):
            return  # Non-interactive mode — exit after action

        # Step 4: Show splash screen
        from zephyrveil.console.banner import show_splash, show_banner

        # First run welcome message
        if config_created or created_dirs:
            console.print()
            console.print("  [bold green]✓[/bold green] [bold white]First Run — setup complete[/bold white]")
            for d in created_dirs:
                console.print(f"  [dim]  Created:[/dim] {d}")
            if config_created:
                from zephyrveil.config.settings import CONFIG_FILE
                console.print(f"  [dim]  Config:[/dim]  {CONFIG_FILE}")
                console.print("  [dim]  Edit config.toml to add API keys.[/dim]")
            console.print()

        show_splash(console, config, db_ok)

        # Step 5: Clear screen, show banner once
        console.clear()
        show_banner(console)

        if not db_ok:
            console.print("  [bold yellow]⚠[/bold yellow]  Database issue — history features limited\n")

        # Apply any CLI overrides to config
        if args.verbose:
            config.setdefault("general", {})["verbose"] = True
        if args.source and args.source != "auto":
            config.setdefault("general", {})["log_source"] = args.source

        # Step 6: Launch interactive console loop
        from zephyrveil.console.prompt import run_console
        run_console(console, config)

    except KeyboardInterrupt:
        console.print("\n  [dim]Interrupted. Goodbye.[/dim]\n")
        sys.exit(0)
    except ImportError as exc:
        console.print(f"\n  [bold red]✗[/bold red] Import error: {exc}")
        console.print("  [dim]  Reinstall: uv tool install zephyrveil[/dim]\n")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception:
        console.print("\n  [bold red]✗[/bold red] Startup failed unexpectedly.")
        console.print("  [dim]  Run 'use doctor' to diagnose.[/dim]\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
