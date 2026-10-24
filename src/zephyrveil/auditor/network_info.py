"""
auditor/network_info.py — Gather network information for the audit.

Collects:
- Local IP addresses (all interfaces)
- Public IP address (via ipinfo.io/ip — no key needed for this)
- Open listening ports (via ss or netstat)
- Active network connections
- Network interfaces summary

All subprocess calls have timeouts and error handling.
"""

import subprocess
import shutil
import re
import requests
from typing import Any


def get_local_ips() -> list[dict[str, str]]:
    """
    Get all local IP addresses from all network interfaces.

    Uses `ip addr show` which is available on all modern Linux systems.

    Returns:
        List of dicts: {interface, ip, cidr}
    """
    ips = []
    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            return ips

        current_iface = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            # Interface line: "2: eth0: <BROADCAST..."
            iface_match = re.match(r"^\d+:\s+(\S+):", line)
            if iface_match:
                current_iface = iface_match.group(1).rstrip(":")
                continue
            # IP line: "inet 192.168.1.100/24 ..."
            ip_match = re.match(r"^inet\s+([\d.]+/\d+)", line)
            if ip_match and current_iface:
                cidr = ip_match.group(1)
                ip   = cidr.split("/")[0]
                # Skip loopback
                if not ip.startswith("127."):
                    ips.append({
                        "interface": current_iface,
                        "ip":        ip,
                        "cidr":      cidr,
                    })

        return ips

    except subprocess.TimeoutExpired:
        return ips
    except FileNotFoundError:
        return ips
    except Exception:
        return ips


def get_public_ip() -> str:
    """
    Get the public (external) IP address using ipinfo.io.

    No API key needed for this endpoint.
    Uses a short timeout since we don't want to slow down the audit.

    Returns:
        Public IP string, or "" if lookup failed.
    """
    try:
        response = requests.get(
            "https://ipinfo.io/ip",
            timeout=5,
            headers={"Accept": "text/plain"},
        )
        if response.status_code == 200:
            ip = response.text.strip()
            # Basic validation — should look like an IP
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return ip
        return ""
    except requests.Timeout:
        return ""
    except requests.ConnectionError:
        return ""
    except Exception:
        return ""


def get_open_ports() -> list[dict[str, Any]]:
    """
    Get all listening TCP/UDP ports using `ss` (preferred) or `netstat`.

    Returns:
        List of dicts: {port, protocol, address, process, pid}
    """
    ports = []
    try:
        # Prefer `ss` (socket statistics) — faster, always available on modern Linux
        if shutil.which("ss"):
            result = subprocess.run(
                ["ss", "-tlnup"],  # tcp + udp, listening, numeric, with process info
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            output = result.stdout
        elif shutil.which("netstat"):
            # Fallback to netstat on older systems
            result = subprocess.run(
                ["netstat", "-tlnup"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            output = result.stdout
        else:
            return ports

        # Parse ss output — format varies slightly by version
        for line in output.splitlines():
            try:
                line = line.strip()
                if not line or line.startswith("Netid") or line.startswith("State"):
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                # ss output columns: Netid State Recv-Q Send-Q Local_Address:Port Peer ...
                proto     = parts[0].lower()  # tcp, udp, etc.
                local_addr = parts[4] if len(parts) > 4 else ""

                # Extract port from address:port
                if ":" in local_addr:
                    addr_part, port_part = local_addr.rsplit(":", 1)
                    try:
                        port = int(port_part)
                    except ValueError:
                        continue
                else:
                    continue

                # Extract process info (last column)
                process = ""
                pid     = ""
                if len(parts) > 6:
                    proc_part = " ".join(parts[6:])
                    proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc_part)
                    if proc_match:
                        process = proc_match.group(1)
                        pid     = proc_match.group(2)

                ports.append({
                    "port":     port,
                    "protocol": proto,
                    "address":  addr_part,
                    "process":  process,
                    "pid":      pid,
                })

            except Exception:
                continue

        # Sort by port number for readability
        ports.sort(key=lambda x: x.get("port", 0))
        return ports

    except subprocess.TimeoutExpired:
        return ports
    except Exception:
        return ports


def get_active_connections() -> list[dict[str, str]]:
    """
    Get active established network connections.

    Returns:
        List of dicts: {local_addr, remote_addr, state, process}
    """
    connections = []
    try:
        if shutil.which("ss"):
            result = subprocess.run(
                ["ss", "-tnup", "state", "established"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
        elif shutil.which("netstat"):
            result = subprocess.run(
                ["netstat", "-tnup"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
        else:
            return connections

        for line in result.stdout.splitlines():
            try:
                line = line.strip()
                if not line or line.startswith("Netid") or line.startswith("Proto"):
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                local_addr  = parts[3] if len(parts) > 3 else ""
                remote_addr = parts[4] if len(parts) > 4 else ""

                # Skip if no remote address (listening sockets)
                if remote_addr in ("", "*:*", "0.0.0.0:*", ":::*"):
                    continue

                process = ""
                if len(parts) > 6:
                    proc_match = re.search(r'users:\(\("([^"]+)"', " ".join(parts[6:]))
                    if proc_match:
                        process = proc_match.group(1)

                connections.append({
                    "local_addr":  local_addr,
                    "remote_addr": remote_addr,
                    "state":       "ESTABLISHED",
                    "process":     process,
                })
            except Exception:
                continue

        return connections[:50]  # Cap at 50 connections to keep output manageable

    except Exception:
        return connections


def get_network_info() -> dict[str, Any]:
    """
    Main entry point: collect all network information.

    Returns:
        Dict with keys:
        - local_ips: list of local IP dicts
        - public_ip: string
        - open_ports: list of port dicts
        - connections: list of connection dicts
        - errors: list of any errors encountered
    """
    result: dict[str, Any] = {
        "local_ips":   [],
        "public_ip":   "",
        "open_ports":  [],
        "connections": [],
        "errors":      [],
    }

    try:
        result["local_ips"] = get_local_ips()
    except Exception:
        result["errors"].append("Could not get local IPs")

    try:
        result["public_ip"] = get_public_ip()
    except Exception:
        result["errors"].append("Could not get public IP")

    try:
        result["open_ports"] = get_open_ports()
    except Exception:
        result["errors"].append("Could not get open ports")

    try:
        result["connections"] = get_active_connections()
    except Exception:
        result["errors"].append("Could not get active connections")

    return result
