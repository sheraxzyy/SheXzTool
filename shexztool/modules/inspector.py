"""Process and Network Connection Inspector Module for SheXzTool.

Attributed to developer brand: SheRaXzy Sentinel.
Enumerates active processes, network sockets, and applies explainable anomaly heuristics.
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from shexztool.core.models import ConnectionDetail, ProcessDetail

logger = logging.getLogger("shexztool.inspector")

# Windows system binaries that normally MUST originate from System32 or SysWOW64
STANDARD_SYSTEM32_BINARIES = {
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
    "winlogon.exe",
    "dwm.exe",
    "spoolsv.exe",
}


class ProcessInspector:
    """Inspects live running processes and network connections with transparent heuristics."""

    def __init__(self):
        pass

    def inspect_processes(
        self,
        filter_name: Optional[str] = None,
        sort_by: str = "memory_mb",
        limit: Optional[int] = None,
    ) -> List[ProcessDetail]:
        """Enumerate active processes safely and apply anomaly checks."""
        details: List[ProcessDetail] = []

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "username", "cpu_percent", "memory_info", "status"]
        ):
            try:
                info = proc.info
                name = info.get("name") or "Unknown"
                if filter_name and filter_name.lower() not in name.lower():
                    continue

                pid = info.get("pid", 0)
                exe = info.get("exe")
                username = info.get("username")
                cpu = info.get("cpu_percent") or 0.0
                mem_info = info.get("memory_info")
                mem_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0.0
                status = info.get("status") or "running"

                detail = ProcessDetail(
                    pid=pid,
                    name=name,
                    exe=exe,
                    username=username,
                    cpu_percent=cpu,
                    memory_mb=mem_mb,
                    status=status,
                )

                is_suspicious, reason = self.evaluate_heuristics(detail)
                detail.is_suspicious = is_suspicious
                detail.anomaly_reason = reason

                details.append(detail)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Error inspecting process: %s", e)
                continue

        # Sort
        if sort_by == "memory_mb":
            details.sort(key=lambda p: p.memory_mb, reverse=True)
        elif sort_by == "cpu_percent":
            details.sort(key=lambda p: p.cpu_percent, reverse=True)
        elif sort_by == "pid":
            details.sort(key=lambda p: p.pid)
        elif sort_by == "name":
            details.sort(key=lambda p: p.name.lower())

        if limit and limit > 0:
            return details[:limit]
        return details

    def evaluate_heuristics(self, proc: ProcessDetail) -> Tuple[bool, Optional[str]]:
        """Evaluate explainable heuristic indicators.

        Never asserts malware without cryptographic or behavioral proof.
        """
        name_lower = proc.name.lower()

        # Check 1: System binary masquerading outside Windows/System32
        if name_lower in STANDARD_SYSTEM32_BINARIES and proc.exe:
            exe_path_lower = proc.exe.lower()
            valid_dirs = ["c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\servicing"]
            if not any(exe_path_lower.startswith(vd) for vd in valid_dirs):
                return True, f"Heuristic: Critical system binary '{proc.name}' is running from non-standard directory: '{proc.exe}'"

        # Check 2: Process executing directly out of Temp directory
        if proc.exe:
            exe_path_lower = proc.exe.lower()
            if "\\temp\\" in exe_path_lower or "\\appdata\\local\\temp" in exe_path_lower:
                return True, f"Heuristic: Executable is running from a temporary staging directory: '{proc.exe}'"

        # Check 3: Elevated memory usage anomaly (> 2500 MB)
        if proc.memory_mb > 2500.0:
            return True, f"Resource: Abnormally high memory footprint ({proc.memory_mb:.1f} MB)"

        return False, None

    def inspect_active_connections(self) -> List[ConnectionDetail]:
        """Collect active network connections and link with process names."""
        connections: List[ConnectionDetail] = []

        # Build quick PID -> name cache
        pid_names: Dict[int, str] = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[p.info["pid"]] = p.info["name"] or "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Access denied when reading all network connections.")
            return connections
        except Exception as e:
            logger.error("Error reading network connections: %s", e)
            return connections

        for c in conns:
            laddr_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
            raddr_str = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
            protocol = "TCP" if c.type == psutil.SOCK_STREAM else "UDP"
            p_name = pid_names.get(c.pid, "Unknown") if c.pid else "System/Kernel"

            connections.append(ConnectionDetail(
                laddr=laddr_str,
                raddr=raddr_str,
                status=c.status,
                pid=c.pid,
                process_name=p_name,
                protocol=protocol,
            ))

        return connections
