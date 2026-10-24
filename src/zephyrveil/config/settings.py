"""
config/settings.py — Configuration management and first run setup.

This module handles:
- Loading config from ~/.config/zephyrveil/config.toml
- Creating config file on first run with safe defaults
- Creating all required directories automatically
- Loading API keys (dev: .env, prod: config.toml)
- Providing a global CONFIG dict used throughout the app
"""

import os
import tomllib          # stdlib in Python 3.11+
from pathlib import Path
from typing import Any

# ── Path constants ──────────────────────────────────────────────────────────
CONFIG_DIR  = Path.home() / ".config" / "zephyrveil"
CONFIG_FILE = CONFIG_DIR / "config.toml"
DATA_DIR    = Path.home() / ".local" / "share" / "zephyrveil"
DB_FILE     = DATA_DIR / "zephyrveil.db"
REPORTS_DIR = Path.home() / "Documents" / "zephyrveil"

# ── Default config.toml content (written as a string to avoid tomli_w dep) ──
DEFAULT_CONFIG_TOML = """\
# Zephyrveil Configuration File
# Edit this file to configure Zephyrveil behavior and API keys.
# After editing, restart Zephyrveil for changes to take effect.

[general]
version = "1.0.0"
log_source = "auto"
verbose = false
color = true

[thresholds]
brute_force_attempts = 5
brute_force_window = 60
cred_stuffing_usernames = 3
repeated_auth_failures = 10

[database]
path = "~/.local/share/zephyrveil/zephyrveil.db"

[api_keys]
abuseipdb  = ""
virustotal = ""
shodan     = ""
nvd        = ""
ipinfo     = ""

[telegram]
bot_token = ""
chat_id   = ""
enabled   = false

[reports]
output_dir = "~/Documents/zephyrveil/"
"""


def ensure_directories() -> list[str]:
    """
    Create all required directories if they don't exist.

    Returns a list of directory paths that were newly created,
    so the caller can inform the user what was set up.
    """
    created = []
    # List of all dirs we need
    dirs_needed = [CONFIG_DIR, DATA_DIR, REPORTS_DIR]

    for directory in dirs_needed:
        try:
            if not directory.exists():
                # Create including all parents (like mkdir -p)
                directory.mkdir(parents=True, exist_ok=True)
                created.append(str(directory))
        except PermissionError:
            # Cannot create dir — caller handles this gracefully
            pass
        except OSError:
            pass

    return created


def ensure_config_file() -> bool:
    """
    Create the default config.toml if it doesn't exist.

    Returns True if the file was newly created, False if it already existed.
    """
    try:
        if not CONFIG_FILE.exists():
            # Write the default config template
            CONFIG_FILE.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
            return True  # Newly created
        return False  # Already existed
    except PermissionError:
        # Can't write to config dir — not fatal, use defaults in memory
        return False
    except OSError:
        return False


def load_config() -> dict[str, Any]:
    """
    Load config.toml and return it as a nested dict.

    Priority for API keys:
    1. .env file (development only, via python-dotenv if installed)
    2. config.toml values
    3. Empty string / None (graceful skip with warning)

    Returns a flat-ish config dict with all needed values.
    """
    # Start with a full set of safe defaults in case file is broken
    config: dict[str, Any] = {
        "general": {
            "version": "1.0.0",
            "log_source": "auto",
            "verbose": False,
            "color": True,
        },
        "thresholds": {
            "brute_force_attempts": 5,
            "brute_force_window": 60,
            "cred_stuffing_usernames": 3,
            "repeated_auth_failures": 10,
        },
        "database": {
            "path": str(DB_FILE),
        },
        "api_keys": {
            "abuseipdb": "",
            "virustotal": "",
            "shodan": "",
            "nvd": "",
            "ipinfo": "",
        },
        "telegram": {
            "bot_token": "",
            "chat_id": "",
            "enabled": False,
        },
        "reports": {
            "output_dir": str(REPORTS_DIR),
        },
    }

    # Try to load the actual config file
    try:
        if CONFIG_FILE.exists():
            raw = CONFIG_FILE.read_bytes()
            loaded = tomllib.loads(raw.decode("utf-8"))

            # Merge loaded values into defaults (so missing keys use defaults)
            for section, values in loaded.items():
                if section in config and isinstance(values, dict):
                    config[section].update(values)
                else:
                    config[section] = values

    except PermissionError:
        # Can't read config — use defaults silently
        pass
    except tomllib.TOMLDecodeError:
        # Malformed TOML — use defaults, warn caller via return
        pass
    except OSError:
        pass

    # ── Overlay .env values if python-dotenv is installed (dev mode) ──
    try:
        # Only attempt if dotenv is installed; it's a dev dependency
        from dotenv import load_dotenv  # type: ignore
        env_path = Path(".env")
        if env_path.exists():
            load_dotenv(env_path)

        # Map env var names to config keys
        env_key_map = {
            "ABUSEIPDB_KEY":  ("api_keys", "abuseipdb"),
            "VIRUSTOTAL_KEY": ("api_keys", "virustotal"),
            "SHODAN_KEY":     ("api_keys", "shodan"),
            "NVD_KEY":        ("api_keys", "nvd"),
            "IPINFO_KEY":     ("api_keys", "ipinfo"),
            "TELEGRAM_TOKEN": ("telegram", "bot_token"),
            "TELEGRAM_CHAT":  ("telegram", "chat_id"),
        }
        for env_var, (section, key) in env_key_map.items():
            val = os.environ.get(env_var, "")
            if val:
                config[section][key] = val

    except ImportError:
        # python-dotenv not installed — fine, this is prod mode
        pass
    except Exception:
        # Any other error loading .env — silently skip
        pass

    # ── Resolve ~ in paths ──
    try:
        config["database"]["path"] = str(
            Path(config["database"]["path"]).expanduser()
        )
        config["reports"]["output_dir"] = str(
            Path(config["reports"]["output_dir"]).expanduser()
        )
    except Exception:
        # Path expansion failed — use hardcoded fallbacks
        config["database"]["path"] = str(DB_FILE)
        config["reports"]["output_dir"] = str(REPORTS_DIR)

    return config


def first_run_setup() -> dict[str, Any]:
    """
    Run the complete first-run initialization sequence.

    This is called once at startup. It:
    1. Creates all required directories
    2. Creates the default config.toml if missing
    3. Loads and returns the final config

    Returns a dict with keys:
    - "config": the loaded config dict
    - "created_dirs": list of newly created directory paths
    - "config_created": bool, True if config.toml was new
    - "errors": list of error strings to surface to the user
    """
    result: dict[str, Any] = {
        "config": {},
        "created_dirs": [],
        "config_created": False,
        "errors": [],
    }

    # Step 1: Create directories
    try:
        result["created_dirs"] = ensure_directories()
    except Exception as exc:
        result["errors"].append(f"Directory setup failed: {exc}")

    # Step 2: Create config file
    try:
        result["config_created"] = ensure_config_file()
    except Exception as exc:
        result["errors"].append(f"Config file setup failed: {exc}")

    # Step 3: Load config
    try:
        result["config"] = load_config()
    except Exception as exc:
        result["errors"].append(f"Config load failed: {exc}")
        # Return bare defaults so the app can still run
        result["config"] = load_config()

    return result


def get_api_key(config: dict[str, Any], service: str) -> str:
    """
    Safely retrieve an API key for a given service name.

    Args:
        config: The loaded config dict from load_config()
        service: One of: abuseipdb, virustotal, shodan, nvd, ipinfo

    Returns:
        The API key string, or "" if not configured.
        Never raises — missing key returns empty string.
    """
    try:
        key = config.get("api_keys", {}).get(service, "")
        # Treat whitespace-only strings as empty
        return key.strip() if isinstance(key, str) else ""
    except Exception:
        return ""


def is_telegram_configured(config: dict[str, Any]) -> bool:
    """
    Check if Telegram is fully configured (token + chat_id + enabled).

    Returns True only if all three are set correctly.
    """
    try:
        tg = config.get("telegram", {})
        token   = str(tg.get("bot_token", "")).strip()
        chat_id = str(tg.get("chat_id", "")).strip()
        enabled = bool(tg.get("enabled", False))
        return bool(token and chat_id and enabled)
    except Exception:
        return False
