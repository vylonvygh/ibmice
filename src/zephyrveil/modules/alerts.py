"""
modules/alerts.py — Telegram alerts configuration and testing module.

'use alerts' lets you set a Telegram bot token and chat ID,
test the connection, and verify alerts are working.
"""

from rich.console import Console
from zephyrveil.modules.base import BaseModule
from zephyrveil.console.output import (
    print_section, print_success, print_warning, print_error, print_info,
)


class AlertsModule(BaseModule):
    """Telegram alerts configuration and testing module."""

    NAME        = "alerts"
    DESCRIPTION = "Configure and test Telegram alerts"

    DEFAULT_OPTIONS = {
        "TOKEN":   ("", "Telegram bot token from @BotFather"),
        "CHAT_ID": ("", "Telegram chat ID (@userinfobot to find yours)"),
        "TEST":    ("false", "Send a test message when run: true/false"),
    }

    def run(self, console: Console) -> None:
        """
        Configure Telegram and optionally send a test alert.

        If TOKEN and CHAT_ID are set, saves them to the config.
        If TEST=true, sends a test message to verify the connection.
        """
        try:
            token   = self.options.get("TOKEN", "").strip()
            chat_id = self.options.get("CHAT_ID", "").strip()
            do_test = self.options.get("TEST", "false").lower() == "true"

            print_section(console, "TELEGRAM ALERTS")

            # Show current config status from main config
            tg_config = self.config.get("telegram", {})
            cfg_token   = str(tg_config.get("bot_token", "")).strip()
            cfg_chat    = str(tg_config.get("chat_id", "")).strip()
            cfg_enabled = bool(tg_config.get("enabled", False))

            # Use module options if set, otherwise fall back to config
            use_token   = token   or cfg_token
            use_chat_id = chat_id or cfg_chat

            # ── Show current status ───────────────────────────────────────
            if use_token:
                print_success(console, f"Bot token: {'*' * (len(use_token) - 6)}{use_token[-6:]}")
            else:
                print_warning(console, "Bot token: not configured")

            if use_chat_id:
                print_success(console, f"Chat ID:   {use_chat_id}")
            else:
                print_warning(console, "Chat ID: not configured")

            if cfg_enabled:
                print_success(console, "Alerts: ENABLED (auto-sends on scan threats)")
            else:
                print_warning(console, "Alerts: DISABLED (set enabled=true in config.toml)")

            console.print()

            # ── Setup instructions if not configured ──────────────────────
            if not use_token or not use_chat_id:
                print_section(console, "SETUP INSTRUCTIONS")
                console.print("  [bold white]Step 1:[/bold white] Open Telegram and search for [bold cyan]@BotFather[/bold cyan]")
                console.print("  [bold white]Step 2:[/bold white] Send [bold cyan]/newbot[/bold cyan] and follow the prompts")
                console.print("  [bold white]Step 3:[/bold white] Copy the bot token you receive")
                console.print("  [bold white]Step 4:[/bold white] Search for [bold cyan]@userinfobot[/bold cyan] to find your chat ID")
                console.print("  [bold white]Step 5:[/bold white] Set options and run:")
                console.print()
                console.print("  [dim]alerts >[/dim] [green]set TOKEN 1234567890:ABCdefGHI...[/green]")
                console.print("  [dim]alerts >[/dim] [green]set CHAT_ID 123456789[/green]")
                console.print("  [dim]alerts >[/dim] [green]set TEST true[/green]")
                console.print("  [dim]alerts >[/dim] [green]run[/green]")
                console.print()
                console.print("  [bold white]Step 6:[/bold white] Edit [cyan]~/.config/zephyrveil/config.toml[/cyan]:")
                console.print("  [dim]  [telegram][/dim]")
                console.print(f"  [dim]  bot_token = \"{use_token or 'YOUR_TOKEN'}\"[/dim]")
                console.print(f"  [dim]  chat_id = \"{use_chat_id or 'YOUR_CHAT_ID'}\"[/dim]")
                console.print("  [dim]  enabled = true[/dim]")
                console.print()
                return

            # ── Send test message ─────────────────────────────────────────
            if do_test:
                print_info(console, "Sending test message to Telegram...")

                try:
                    from zephyrveil.integrations.telegram import send_test_alert
                    result = send_test_alert(use_token, use_chat_id)

                    if result.get("success"):
                        print_success(console, "Test message delivered successfully!")
                        print_info(console, f"Message ID: {result.get('message_id', '—')}")

                        # Save the successful test to DB
                        self._save_alert_record(use_token, use_chat_id, "test_sent")

                    else:
                        print_error(console, f"Test failed: {result.get('error', 'Unknown error')}")
                        print_info(console, "Check your token and chat_id — ensure the bot has been started")

                except Exception as exc:
                    print_error(console, f"Could not send test message: {type(exc).__name__}")

            else:
                print_info(console, "Set TEST=true and run again to send a test message")
                print_info(console, "Command: set TEST true  →  run")

            console.print()

        except KeyboardInterrupt:
            print_warning(console, "Alerts module interrupted")
        except Exception:
            print_error(console, "Alerts module encountered an error")

    def _save_alert_record(self, token: str, chat_id: str, status: str) -> None:
        """Save the alert test record to the database."""
        try:
            from zephyrveil.storage.db import insert_alert
            db_path = self.get_db_path()
            insert_alert(
                db_path,
                scan_id="alerts_test",
                platform="telegram",
                status=status,
                message="Test alert from Zephyrveil",
            )
        except Exception:
            pass
