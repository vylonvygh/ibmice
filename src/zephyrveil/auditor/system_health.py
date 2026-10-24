"""
auditor/system_health.py — System health metrics collection.

Collects:
- RAM usage (total, used, free, percentage)
- Disk usage (all mounted filesystems)
- System uptime
- Kernel version
- CPU info (model, cores, usage)
- Load average
- Running process count

Uses /proc filesystem and standard Linux commands — no external deps.
"""

import subprocess
import shutil
import re
from pathlib import Path
from typing import Any


def get_ram_info() -> dict[str, Any]:
    """
    Read memory information from /proc/meminfo.

    Returns:
        Dict with total_mb, used_mb, free_mb, available_mb, percent_used.
    """
    result: dict[str, Any] = {
        "total_mb":     0,
        "used_mb":      0,
        "free_mb":      0,
        "available_mb": 0,
        "percent_used": 0.0,
        "error":        "",
    }

    try:
        meminfo_path = Path("/proc/meminfo")
        if not meminfo_path.exists():
            result["error"] = "/proc/meminfo not found"
            return result

        meminfo: dict[str, int] = {}
        with open(meminfo_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(":")
                        val = int(parts[1])  # values are in kB
                        meminfo[key] = val
                except (ValueError, IndexError):
                    continue

        total_kb     = meminfo.get("MemTotal", 0)
        free_kb      = meminfo.get("MemFree", 0)
        available_kb = meminfo.get("MemAvailable", 0)
        buffers_kb   = meminfo.get("Buffers", 0)
        cached_kb    = meminfo.get("Cached", 0)

        # Used = Total - Available (more accurate than Total - Free)
        used_kb = total_kb - available_kb

        result["total_mb"]     = total_kb // 1024
        result["used_mb"]      = used_kb // 1024
        result["free_mb"]      = free_kb // 1024
        result["available_mb"] = available_kb // 1024

        if total_kb > 0:
            result["percent_used"] = round((used_kb / total_kb) * 100, 1)

        return result

    except PermissionError:
        result["error"] = "Cannot read /proc/meminfo — insufficient permissions"
        return result
    except Exception:
        result["error"] = "Could not read memory info"
        return result


def get_disk_info() -> list[dict[str, Any]]:
    """
    Get disk usage for all mounted filesystems using `df`.

    Returns:
        List of dicts per filesystem: filesystem, total_gb, used_gb, free_gb,
        percent_used, mount_point.
    """
    disks = []
    try:
        result = subprocess.run(
            ["df", "-BG", "--output=source,size,used,avail,pcent,target"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            return disks

        for line in result.stdout.splitlines()[1:]:  # Skip header
            try:
                parts = line.split()
                if len(parts) < 6:
                    continue

                filesystem  = parts[0]
                total_gb    = int(parts[1].rstrip("G"))
                used_gb     = int(parts[2].rstrip("G"))
                free_gb     = int(parts[3].rstrip("G"))
                pct         = parts[4].rstrip("%")
                mount_point = parts[5]

                # Skip pseudo filesystems and very small volumes
                if any(fs in filesystem for fs in ("tmpfs", "devtmpfs", "udev", "run", "sys", "proc")):
                    continue

                disks.append({
                    "filesystem":   filesystem,
                    "total_gb":     total_gb,
                    "used_gb":      used_gb,
                    "free_gb":      free_gb,
                    "percent_used": int(pct) if pct.isdigit() else 0,
                    "mount_point":  mount_point,
                })
            except Exception:
                continue

        return disks

    except subprocess.TimeoutExpired:
        return disks
    except FileNotFoundError:
        return disks
    except Exception:
        return disks


def get_uptime() -> dict[str, Any]:
    """
    Read system uptime from /proc/uptime.

    Returns:
        Dict with: uptime_seconds, uptime_human (formatted string), load_1m, load_5m, load_15m.
    """
    result: dict[str, Any] = {
        "uptime_seconds": 0,
        "uptime_human":   "unknown",
        "load_1m":        0.0,
        "load_5m":        0.0,
        "load_15m":       0.0,
    }

    try:
        # /proc/uptime: "12345.67 234567.89" (uptime_seconds idle_seconds)
        uptime_raw = Path("/proc/uptime").read_text(encoding="utf-8").strip()
        uptime_seconds = float(uptime_raw.split()[0])
        result["uptime_seconds"] = int(uptime_seconds)

        # Format human-readable uptime
        days    = int(uptime_seconds // 86400)
        hours   = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        parts = []
        if days:    parts.append(f"{days}d")
        if hours:   parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        result["uptime_human"] = " ".join(parts) if parts else "< 1 minute"

        # Load average from /proc/loadavg: "1.23 0.45 0.12 2/345 1234"
        loadavg_raw = Path("/proc/loadavg").read_text(encoding="utf-8").strip()
        load_parts  = loadavg_raw.split()
        if len(load_parts) >= 3:
            result["load_1m"]  = float(load_parts[0])
            result["load_5m"]  = float(load_parts[1])
            result["load_15m"] = float(load_parts[2])

        return result

    except Exception:
        return result


def get_kernel_version() -> str:
    """
    Get the running kernel version string.

    Returns:
        Kernel version string like "6.7.5-arch1-1" or "unknown".
    """
    try:
        result = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def get_cpu_info() -> dict[str, Any]:
    """
    Read CPU information from /proc/cpuinfo.

    Returns:
        Dict with: model, cores, threads.
    """
    result: dict[str, Any] = {
        "model":   "unknown",
        "cores":   0,
        "threads": 0,
    }

    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
        threads = cpuinfo.count("processor\t:")
        result["threads"] = threads

        # Get model name from first processor entry
        for line in cpuinfo.splitlines():
            if line.startswith("model name"):
                result["model"] = line.split(":", 1)[-1].strip()
                break

        # Count physical cores (unique core id values)
        core_ids = set(re.findall(r"^core id\s*:\s*(\d+)", cpuinfo, re.MULTILINE))
        result["cores"] = len(core_ids) if core_ids else threads

        return result

    except Exception:
        return result


def get_hostname() -> str:
    """Get system hostname."""
    try:
        result = subprocess.run(
            ["hostname", "-f"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        try:
            return Path("/etc/hostname").read_text(encoding="utf-8").strip()
        except Exception:
            return "unknown"


def get_process_count() -> int:
    """Get the number of currently running processes."""
    try:
        result = subprocess.run(
            ["ps", "aux", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
        )
        return len(result.stdout.splitlines())
    except Exception:
        return 0


def get_system_health() -> dict[str, Any]:
    """
    Main entry point: collect all system health metrics.

    Returns:
        Dict with all system health data combined.
    """
    result: dict[str, Any] = {
        "ram":           {},
        "disks":         [],
        "uptime":        {},
        "kernel":        "",
        "cpu":           {},
        "hostname":      "",
        "process_count": 0,
        "errors":        [],
    }

    try:
        result["ram"] = get_ram_info()
    except Exception:
        result["errors"].append("RAM info unavailable")

    try:
        result["disks"] = get_disk_info()
    except Exception:
        result["errors"].append("Disk info unavailable")

    try:
        result["uptime"] = get_uptime()
    except Exception:
        result["errors"].append("Uptime info unavailable")

    try:
        result["kernel"] = get_kernel_version()
    except Exception:
        result["kernel"] = "unknown"

    try:
        result["cpu"] = get_cpu_info()
    except Exception:
        result["errors"].append("CPU info unavailable")

    try:
        result["hostname"] = get_hostname()
    except Exception:
        result["hostname"] = "unknown"

    try:
        result["process_count"] = get_process_count()
    except Exception:
        pass

    return result
