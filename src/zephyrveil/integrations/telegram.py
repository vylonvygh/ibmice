"""
integrations/telegram.py — Telegram bot alert sender.

Sends threat alerts to a Telegram chat via the Bot API.
No external library needed — uses plain HTTP via requests.

Setup:
1. Create a bot via @BotFather in Telegram
2. Get the bot token
3. Start a chat with the bot or add it to a group
4. Get the chat_id (use getUpdates or @userinfobot)
5. Add token + chat_id to config.toml [telegram] section

API endpoint: https://api.telegram.org/bot{token}/sendMessage
"""

import requests
from typing import Any


TELEGRAM_API_BASE = "https://api.telegram.org"
REQUEST_TIMEOUT   = 8  # seconds


def send_telegram_message(
    bot_token: str,
    chat_id: str,
    message: str,
    parse_mode: str = "HTML",
) -> dict[str, Any]:
    """
    Send a message to a Telegram chat via the Bot API.

    Args:
        bot_token: Telegram bot token from @BotFather.
        chat_id: Target chat ID (can be user, group, or channel).
        message: The message text to send. Supports HTML or Markdown.
        parse_mode: "HTML" or "Markdown" or "MarkdownV2".

    Returns:
        Dict with keys:
        - success: bool — True if message was delivered
        - message_id: Telegram message ID if successful
        - error: error string if failed
    """
    result: dict[str, Any] = {
        "success":    False,
        "message_id": None,
        "error":      "",
    }

    # ── Guard: require config ─────────────────────────────────────────────
    if not bot_token or not bot_token.strip():
        result["error"] = "Telegram bot token not configured — run: use alerts"
        return result

    if not chat_id or not chat_id.strip():
        result["error"] = "Telegram chat_id not configured — run: use alerts"
        return result

    if not message or not message.strip():
        result["error"] = "No message text provided"
        return result

    try:
        url = f"{TELEGRAM_API_BASE}/bot{bot_token.strip()}/sendMessage"

        response = requests.post(
            url,
            json={
                "chat_id":    chat_id.strip(),
                "text":       message[:4096],  # Telegram has 4096 char limit per message
                "parse_mode": parse_mode,
            },
            timeout=REQUEST_TIMEOUT,
        )

        # ── Handle HTTP errors ────────────────────────────────────────────
        if response.status_code == 401:
            result["error"] = "Telegram bot token invalid — create a new bot with @BotFather"
            return result

        if response.status_code == 400:
            try:
                err_data = response.json()
                err_desc = err_data.get("description", "Bad request")
                result["error"] = f"Telegram rejected message: {err_desc}"
            except Exception:
                result["error"] = "Telegram rejected the message — check chat_id and bot permissions"
            return result

        if response.status_code == 403:
            result["error"] = "Telegram bot blocked or not in chat — start the bot first by sending /start"
            return result

        if response.status_code == 429:
            result["error"] = "Telegram rate limit hit — too many messages sent"
            return result

        if response.status_code != 200:
            result["error"] = f"Telegram returned status {response.status_code}"
            return result

        # ── Parse success response ────────────────────────────────────────
        try:
            data = response.json()
        except ValueError:
            result["error"] = "Telegram returned invalid JSON"
            return result

        if data.get("ok"):
            result["success"]    = True
            result["message_id"] = data.get("result", {}).get("message_id")
        else:
            result["error"] = data.get("description", "Telegram returned ok=false")

        return result

    except requests.Timeout:
        result["error"] = "Telegram request timed out — check your internet connection"
        return result
    except requests.ConnectionError:
        result["error"] = "Cannot reach Telegram API — check your internet connection"
        return result
    except Exception:
        result["error"] = "Telegram send failed — unexpected error"
        return result


def build_threat_alert_message(
    threats: list[dict[str, Any]],
    scan_id: str,
    hostname: str = "",
) -> str:
    """
    Build a formatted HTML Telegram message for threat alerts.

    Creates a concise but informative alert with severity summary,
    top threatening IPs, and a link to check full details.

    Args:
        threats: List of threat dicts from the threat engine.
        scan_id: The current scan session ID.
        hostname: The machine hostname (for context in the alert).

    Returns:
        Formatted HTML string ready to send via Telegram.
    """
    try:
        if not threats:
            return ""

        # Count threats by severity
        severity_counts: dict[str, int] = {}
        for t in threats:
            sev = t.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Get top attacking IPs
        attacking_ips = list({
            t.get("source_ip", "")
            for t in threats
            if t.get("source_ip") and t.get("source_ip") not in ("", "local", "multiple", "N/A")
        })[:5]

        # Build severity summary line
        sev_parts = []
        for sev, icon in [("CRITICAL", "🔴"), ("HIGH", "🟠"), ("MEDIUM", "🟡"), ("LOW", "🔵")]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                sev_parts.append(f"{icon} {sev}: {count}")
        severity_line = "  |  ".join(sev_parts) if sev_parts else "No threats"

        # Build threat type summary
        threat_types = list({t.get("threat_type", "").replace("_", " ") for t in threats})

        hostname_line = f"🖥 <b>Host:</b> {hostname}\n" if hostname else ""

        message = (
            f"🚨 <b>ZEPHYRVEIL THREAT ALERT</b>\n\n"
            f"{hostname_line}"
            f"🆔 <b>Scan ID:</b> <code>{scan_id}</code>\n"
            f"⚡ <b>Threats Detected:</b> {len(threats)}\n\n"
            f"<b>Severity Breakdown:</b>\n{severity_line}\n\n"
            f"<b>Threat Types:</b>\n"
            + "\n".join(f"  • {t}" for t in threat_types[:5])
            + (f"\n\n<b>Top Attacking IPs:</b>\n"
               + "\n".join(f"  • <code>{ip}</code>" for ip in attacking_ips)
               if attacking_ips else "")
            + f"\n\n<i>Run Zephyrveil and check full report for details.</i>"
        )

        return message

    except Exception:
        # Fallback to plain text if formatting fails
        return f"🚨 Zephyrveil Alert: {len(threats)} threats detected in scan {scan_id}"


def send_test_alert(bot_token: str, chat_id: str) -> dict[str, Any]:
    """
    Send a test message to verify Telegram configuration is working.

    Args:
        bot_token: Telegram bot token.
        chat_id: Target chat ID.

    Returns:
        Result dict from send_telegram_message().
    """
    test_message = (
        "✅ <b>Zephyrveil Test Alert</b>\n\n"
        "This is a test message from Zephyrveil.\n"
        "Your Telegram alerts are configured correctly!\n\n"
        "<i>You will receive alerts here when threats are detected during scans.</i>"
    )

    return send_telegram_message(bot_token, chat_id, test_message)
