"""
console/banner.py — Splash screen and ASCII banner for Zephyrveil.

This module handles:
- The ASCII art banner (prints ONCE only on launch)
- The animated splash screen (shows status of config, DB, API keys)
- Banner state tracking so it never reprints

Rules:
- Banner prints exactly once — tracked via module-level flag
- Splash runs before banner, then screen clears
- No raw exceptions ever shown to user
"""

import time
from typing import Any

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# ── Module-level flag: has the banner been shown yet? ────────────────────────
_BANNER_SHOWN: bool = False

# ── The ASCII art banner text ────────────────────────────────────────────────
BANNER_ART = """[bold cyan]
  ███████╗███████╗██████╗ ██╗  ██╗██╗   ██╗██████╗ ██╗   ██╗███████╗██╗██╗
  ╚══███╔╝██╔════╝██╔══██╗██║  ██║╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝██║██║
    ███╔╝ █████╗  ██████╔╝███████║ ╚████╔╝ ██████╔╝██║   ██║█████╗  ██║██║
   ███╔╝  ██╔══╝  ██╔═══╝ ██╔══██║  ╚██╔╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██║██║
  ███████╗███████╗██║     ██║  ██║   ██║   ██║  ██║ ╚████╔╝ ███████╗██║███████╗
  ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝╚══════╝
[/bold cyan]"""

BANNER_SUBTITLE = "[bold white]   Linux Threat Detection  [dim]•[/dim]  Security Intelligence  [dim]•[/dim]  IP Intelligence[/bold white]"
BANNER_VERSION  = "[white]   v1.0.0  |  Linux[/white]"
BANNER_META = """[dim]  ─────────────────────────────────────────────────────────────────────────
   Developed by  : Andre J (Albin S) / https://avdre.pages.dev
   Platform      : Linux only  •  Python 3.11+
   License       : MIT
   GitHub        : github.com/avdrevygh/zephyrveil
  ─────────────────────────────────────────────────────────────────────────[/dim]"""

BANNER_TAGLINE = "[dim]   Type [bold white]help[/bold white] to see all commands  •  [bold white]use doctor[/bold white] to validate your setup[/dim]"


def show_splash(console: Console, config: dict[str, Any], db_ok: bool) -> None:
    """
    Display the animated splash screen that shows initialization status.

    This runs before the main banner. It shows:
    - A loading bar animation
    - Config file status
    - Database connection status
    - Log source detection
    - Status of each API key (OK or WARN)

    Args:
        console: Rich Console instance.
        config: The loaded config dict from settings.py.
        db_ok: Whether the database initialized successfully.
    """
    try:
        # ── Loading bar animation ────────────────────────────────────────
        console.print()
        bar_width = 40
        for i in range(bar_width + 1):
            filled = "▰" * i
            empty  = "▱" * (bar_width - i)
            pct    = int((i / bar_width) * 100)
            console.print(
                f"    [bold cyan][{filled}{empty}][/bold cyan] [bold white]{pct:>3}%[/bold white]  [dim]Loading...[/dim]",
                end="\r",
            )
            time.sleep(0.02)

        console.print()  # Newline after bar
        console.print()

        # ── Status checks ────────────────────────────────────────────────
        api_keys = config.get("api_keys", {})

        # Determine log source
        import shutil

        log_source = "auth.log"
        if shutil.which("journalctl"):
            log_source = "journalctl"
        if config.get("general", {}).get("log_source", "auto") not in ("auto", ""):
            log_source = config["general"]["log_source"]

        # Build status lines
        def ok_line(label: str) -> str:
            return f"    [bold green]  OK  [/bold green] {label}"

        def warn_line(label: str) -> str:
            return f"    [bold yellow] WARN [/bold yellow] {label}"

        def err_line(label: str) -> str:
            return f"    [bold red] FAIL [/bold red] {label}"

        # Print each status line with a tiny pause for effect
        lines = [
            (ok_line("Config loaded"), 0.07),
            (
                ok_line("Database connected")
                if db_ok
                else err_line("Database failed — check ~/.local/share/zephyrveil/"),
                0.07,
            ),
            (ok_line(f"Log source: {log_source}"), 0.07),
        ]

        # API key status lines
        key_checks = [
            ("AbuseIPDB", "abuseipdb", "abuseipdb.com/api"),
            ("IPInfo", "ipinfo", "ipinfo.io/signup"),
            ("VirusTotal", "virustotal", "virustotal.com/gui/my-apikey"),
            ("Shodan", "shodan", "account.shodan.io"),
            ("NVD/NIST", "nvd", "nvd.nist.gov/developers"),
        ]

        for display_name, key_name, url in key_checks:
            key_val = str(api_keys.get(key_name, "")).strip()
            if key_val:
                lines.append((ok_line(f"{display_name}: configured"), 0.06))
            else:
                lines.append(
                    (
                        warn_line(
                            f"{display_name}: API key missing — add to config or run: use doctor"
                        ),
                        0.06,
                    )
                )

        # Telegram status
        tg = config.get("telegram", {})
        if str(tg.get("bot_token", "")).strip() and str(tg.get("chat_id", "")).strip():
            lines.append((ok_line("Telegram: configured"), 0.06))
        else:
            lines.append(
                (warn_line("Telegram: not configured — run: use alerts"), 0.06)
            )

        for line_text, delay in lines:
            console.print(line_text)
            time.sleep(delay)

        console.print()
        time.sleep(0.4)  # Brief pause before clearing

    except KeyboardInterrupt:
        # User pressed Ctrl+C during splash — just continue
        pass
    except Exception:
        # Splash failed silently — not critical, just continue
        pass


def show_banner(console: Console) -> None:
    """
    Print the ASCII art banner. Tracks state to print EXACTLY ONCE per session.

    After the first call, subsequent calls are silently ignored.
    This ensures the banner never reprints when the user types 'clear'
    or switches between modules.

    Args:
        console: Rich Console instance to print to.
    """
    global _BANNER_SHOWN

    # Guard: never print twice
    if _BANNER_SHOWN:
        return

    try:
        console.print(BANNER_ART)
        console.print(BANNER_SUBTITLE)
        console.print(BANNER_VERSION)
      #  console.print()
        console.print(BANNER_META)
        console.print(BANNER_TAGLINE)
        console.print()

        # Mark as shown — this flag persists for the whole session
        _BANNER_SHOWN = True

    except Exception:
        # Even if banner fails, mark as shown so we don't retry forever
        _BANNER_SHOWN = True


def is_banner_shown() -> bool:
    """
    Returns True if the banner has already been displayed this session.

    Used by the prompt module to decide whether to show the banner
    after a clear command (answer: no, never reprint).
    """
    return _BANNER_SHOWN


def reset_banner_state() -> None:
    """
    Reset banner shown flag. Only used in testing — not called in production.
    """
    global _BANNER_SHOWN
    _BANNER_SHOWN = False
