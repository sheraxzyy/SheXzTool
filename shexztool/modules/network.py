"""Network Diagnostics and Targeted Port Connectivity Checker for SheXzTool.

Attributed to developer brand: SheRaXzy Sentinel.
Provides safe, transparent network information, DNS diagnostics, and user-confirmed TCP checks.
"""

from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import logging
import platform
import re
import socket
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

from shexztool.core.validator import Validator

logger = logging.getLogger("shexztool.network")

# Well-known service mappings for common diagnostic ports
WELL_KNOWN_SERVICES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Login)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web)",
    110: "POP3 (Mail)",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP (Mail)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Server Message Block)",
    1433: "MS-SQL Server",
    1521: "Oracle DB",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Display",
    8080: "HTTP-Proxy / Alternate Web",
    8443: "HTTPS Alternate",
}


class NetworkDiagnostics:
    """Safely gathers network configuration and executes bounded TCP connectivity tests."""

    def __init__(self, default_timeout: float = 2.0, max_workers: int = 15):
        self.default_timeout = default_timeout
        self.max_workers = max_workers

    def get_interface_details(self) -> List[Dict[str, Any]]:
        """Retrieve local network adapters, IP addresses, MACs, and operational status."""
        interfaces: List[Dict[str, Any]] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as e:
            logger.error("Failed to read network interfaces: %s", e)
            return interfaces

        for iface_name, addr_list in addrs.items():
            iface_stat = stats.get(iface_name)
            is_up = iface_stat.isup if iface_stat else False
            speed = iface_stat.speed if iface_stat else 0

            ipv4_list = []
            ipv6_list = []
            mac = "N/A"

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4_list.append({
                        "ip": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    })
                elif hasattr(socket, "AF_INET6") and addr.family == socket.AF_INET6:
                    ipv6_list.append(addr.address.split("%")[0])  # remove scope ID
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    mac = addr.address

            interfaces.append({
                "name": iface_name,
                "is_up": is_up,
                "speed_mbps": speed,
                "mac": mac,
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
            })

        return interfaces

    def get_routing_and_dns(self) -> Dict[str, Any]:
        """Extract default gateway and active DNS configuration on Windows."""
        result: Dict[str, Any] = {
            "default_gateway": None,
            "active_interface_ip": None,
            "dns_servers": [],
        }

        if platform.system().lower() != "windows":
            return result

        # 1. Default Gateway via 'route print 0.0.0.0'
        try:
            cmd = ["route", "print", "0.0.0.0"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        result["default_gateway"] = parts[2]
                        result["active_interface_ip"] = parts[3]
                        break
        except Exception as e:
            logger.debug("route print failed: %s", e)

        # 2. DNS servers via 'netsh interface ipv4 show dnsservers'
        try:
            cmd = ["netsh", "interface", "ipv4", "show", "dnsservers"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
            if res.returncode == 0:
                dns_ips: set[str] = set()
                ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
                for line in res.stdout.splitlines():
                    if "DNS servers" in line or "Statically" in line or "DHCP" in line or line.strip().startswith(""):
                        found = ip_pattern.findall(line)
                        for ip in found:
                            if ip != "0.0.0.0" and Validator.is_valid_ip(ip):
                                dns_ips.add(ip)
                result["dns_servers"] = sorted(list(dns_ips))
        except Exception as e:
            logger.debug("netsh dnsservers failed: %s", e)

        return result

    def diagnose_dns_resolution(self, domain: str) -> Dict[str, Any]:
        """Perform forward DNS resolution and measure lookup latency."""
        domain = domain.strip()
        if not Validator.is_valid_hostname(domain) and not Validator.is_valid_ip(domain):
            return {"domain": domain, "success": False, "error": "Invalid domain/target format."}

        start_t = time.perf_counter()
        try:
            resolved_info = socket.getaddrinfo(domain, None)
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            
            ipv4_results: set[str] = set()
            ipv6_results: set[str] = set()

            for entry in resolved_info:
                fam, _, _, _, sockaddr = entry
                ip = sockaddr[0]
                if fam == socket.AF_INET:
                    ipv4_results.add(ip)
                elif fam == socket.AF_INET6:
                    ipv6_results.add(ip)

            return {
                "domain": domain,
                "success": True,
                "latency_ms": round(duration_ms, 2),
                "ipv4": sorted(list(ipv4_results)),
                "ipv6": sorted(list(ipv6_results)),
                "error": None,
            }
        except socket.gaierror as e:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            return {
                "domain": domain,
                "success": False,
                "latency_ms": round(duration_ms, 2),
                "ipv4": [],
                "ipv6": [],
                "error": f"Resolution failed: {e.strerror or str(e)}",
            }
        except Exception as e:
            return {
                "domain": domain,
                "success": False,
                "latency_ms": 0.0,
                "ipv4": [],
                "ipv6": [],
                "error": str(e),
            }

    @staticmethod
    def classify_target_scope(target: str) -> Dict[str, Any]:
        """Classify target address as Local, RFC1918 Private, or External Public."""
        try:
            ip = target
            if not Validator.is_valid_ip(target):
                ip = socket.gethostbyname(target)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                scope = "LOCAL_LOOPBACK"
                desc = "Localhost loopback interface (Current Machine only)"
            elif ip_obj.is_private:
                scope = "PRIVATE_LAN"
                desc = "Private local area network (RFC 1918 / Local Subnet)"
            else:
                scope = "EXTERNAL_PUBLIC"
                desc = "External Internet public host"
            return {"ip": str(ip_obj), "scope": scope, "description": desc, "is_external": not (ip_obj.is_loopback or ip_obj.is_private)}
        except Exception:
            return {"ip": target, "scope": "UNKNOWN", "description": "Unable to resolve target scope", "is_external": True}

    def check_tcp_port(self, target_ip: str, port: int, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Attempt a standard TCP three-way handshake on a specific port.

        Non-destructive, safe connect-scan only.
        """
        t_out = timeout if timeout is not None else self.default_timeout
        start_t = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(t_out)

        service_guess = WELL_KNOWN_SERVICES.get(port, "Unknown / Dynamic Service")
        status = "CLOSED"
        latency_ms = None

        try:
            res = sock.connect_ex((target_ip, port))
            duration = (time.perf_counter() - start_t) * 1000.0
            if res == 0:
                status = "OPEN"
                latency_ms = round(duration, 2)
            elif res in (10035, 10060, 11):  # WSAEWOULDBLOCK, WSAETIMEDOUT, EWOULDBLOCK
                status = "FILTERED/TIMEOUT"
            else:
                status = "CLOSED"
        except socket.timeout:
            status = "TIMEOUT"
        except socket.gaierror:
            status = "DNS_ERROR"
        except Exception as e:
            status = f"ERROR ({type(e).__name__})"
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return {
            "port": port,
            "status": status,
            "service": service_guess,
            "latency_ms": latency_ms,
        }

    def scan_target_ports(
        self,
        target: str,
        ports: List[int],
        timeout: Optional[float] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan a pre-validated, bounded list of ports on a specified target."""
        valid, sanitized_target = Validator.validate_target(target)
        if not valid:
            raise ValueError(f"Invalid target: '{target}'")

        # Resolve IP
        try:
            target_ip = socket.gethostbyname(sanitized_target)
        except Exception as e:
            raise ValueError(f"Could not resolve host '{sanitized_target}': {e}")

        results: List[Dict[str, Any]] = []
        total = len(ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=min(self.max_workers, total or 1)) as executor:
            future_to_port = {
                executor.submit(self.check_tcp_port, target_ip, p, timeout): p
                for p in ports
            }

            for future in as_completed(future_to_port):
                res = future.result()
                results.append(res)
                completed += 1
                if on_progress:
                    on_progress(completed, total)

        results.sort(key=lambda x: x["port"])
        return results
