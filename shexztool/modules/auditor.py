"""System Security Auditor Module for SheXzTool.

Inspects Windows Firewall, Defender/Antivirus status, OS info, UAC, and listening ports
using transparent, safe, read-only methods.
Attributed to developer brand: SheRaXzy Sentinel.
"""

from __future__ import annotations
import ctypes
import datetime
import getpass
import json
import logging
import platform
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

import psutil

from shexztool.core.models import Finding, ScanResult, Severity

logger = logging.getLogger("shexztool.auditor")

HIGH_RISK_PORTS = {
    21: ("FTP", "Unencrypted File Transfer Protocol transmits credentials in cleartext.", Severity.HIGH),
    23: ("Telnet", "Legacy unencrypted remote terminal exposes passwords to eavesdropping.", Severity.HIGH),
    69: ("TFTP", "Trivial File Transfer Protocol lacks authentication.", Severity.HIGH),
    135: ("MS-RPC", "Microsoft RPC endpoint mapper exposed to network connections.", Severity.MEDIUM),
    137: ("NetBIOS Name", "NetBIOS name service can expose host identity and vulnerabilities.", Severity.LOW),
    139: ("NetBIOS Session", "Legacy NetBIOS session service exposed to local/external subnet.", Severity.LOW),
    445: ("SMB", "Server Message Block exposed. Susceptible to lateral movement and exploit attempts.", Severity.HIGH),
    3389: ("RDP", "Remote Desktop Protocol listener detected on all interfaces.", Severity.MEDIUM),
    5900: ("VNC", "Virtual Network Computing remote frame buffer listener exposed.", Severity.MEDIUM),
    5985: ("WinRM HTTP", "Windows Remote Management listener over unencrypted HTTP.", Severity.MEDIUM),
    5986: ("WinRM HTTPS", "Windows Remote Management listener over HTTPS.", Severity.LOW),
}


class SystemAuditor:
    """Executes read-only security posture assessments on Windows systems."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.limitations: List[str] = []

    def run_full_audit(self) -> ScanResult:
        """Run all enabled audit checks and return consolidated ScanResult."""
        logger.info("Starting System Security Audit...")
        self.limitations.clear()
        
        sys_info = self.get_system_information()
        findings: List[Finding] = []

        # 1. Firewall check
        fw_findings = self.audit_firewall_status()
        findings.extend(fw_findings)

        # 2. Antivirus & Defender check
        av_findings = self.audit_antivirus_status()
        findings.extend(av_findings)

        # 3. UAC check
        uac_findings = self.audit_uac_status()
        findings.extend(uac_findings)

        # 4. Listening ports security check
        port_findings, port_metrics = self.audit_listening_ports()
        findings.extend(port_findings)

        # 5. OS & Context observations
        context_findings = self.audit_user_context(sys_info)
        findings.extend(context_findings)

        metrics = {
            "checks_executed": 5,
            "total_findings": len(findings),
            "open_listening_ports": port_metrics.get("listening_count", 0),
            "elevated_scan": sys_info.get("is_elevated", False),
        }

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return ScanResult(
            scan_type="System Security Audit",
            timestamp=timestamp,
            system_info=sys_info,
            findings=findings,
            metrics=metrics,
            limitations=list(self.limitations),
        )

    def get_system_information(self) -> Dict[str, Any]:
        """Collect local system metadata using standard library and psutil."""
        is_elevated = False
        try:
            is_elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.debug("Failed to check admin token: %s", e)

        uptime_seconds: Optional[float] = None
        boot_time_str = "Unknown"
        try:
            boot_timestamp = psutil.boot_time()
            uptime_seconds = time.time() - boot_timestamp
            boot_time_str = datetime.datetime.fromtimestamp(boot_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.debug("Failed to calculate boot time: %s", e)

        uptime_formatted = "Unknown"
        if uptime_seconds is not None:
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            uptime_formatted = f"{days}d {hours}h {minutes}m"

        return {
            "hostname": socket.gethostname(),
            "user_context": getpass.getuser(),
            "is_elevated": is_elevated,
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "os_build": platform.win32_ver()[1] if hasattr(platform, "win32_ver") else "",
            "architecture": platform.machine(),
            "boot_time": boot_time_str,
            "uptime": uptime_formatted,
        }

    def audit_firewall_status(self) -> List[Finding]:
        """Inspect Windows Firewall profile states using netsh."""
        findings: List[Finding] = []
        if platform.system().lower() != "windows":
            self.limitations.append("Windows Firewall checks are only supported on Windows OS.")
            return findings

        cmd = ["netsh", "advfirewall", "show", "allprofiles", "state"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8, shell=False)
            if res.returncode != 0:
                self.limitations.append(f"Firewall state query exited with code {res.returncode}: {res.stderr.strip()}")
                return findings

            output = res.stdout
            profiles = {
                "Domain Profile": re.search(r"Domain Profile Settings:.*?\nState\s+([A-Z]+)", output, re.S),
                "Private Profile": re.search(r"Private Profile Settings:.*?\nState\s+([A-Z]+)", output, re.S),
                "Public Profile": re.search(r"Public Profile Settings:.*?\nState\s+([A-Z]+)", output, re.S),
            }

            for profile_name, match in profiles.items():
                if match:
                    state = match.group(1).upper()
                    if state != "ON":
                        findings.append(Finding(
                            id=f"FW-{profile_name.split()[0].upper()}-DISABLED",
                            title=f"Windows Firewall {profile_name} is Disabled",
                            category="Firewall",
                            severity=Severity.HIGH if "Public" in profile_name else Severity.MEDIUM,
                            description=f"The {profile_name} state is currently set to '{state}'.",
                            evidence=f"netsh reports: {profile_name} State = {state}",
                            remediation=f"Enable the {profile_name} using: 'netsh advfirewall set {profile_name.split()[0].lower()}profile state on' or Windows Security app.",
                            references=["https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"]
                        ))
                    else:
                        findings.append(Finding(
                            id=f"FW-{profile_name.split()[0].upper()}-ACTIVE",
                            title=f"Windows Firewall {profile_name} is Active",
                            category="Firewall",
                            severity=Severity.INFO,
                            description=f"The {profile_name} is enabled and filtering inbound/outbound network traffic.",
                            evidence=f"{profile_name} State = ON",
                            remediation="Maintain default blocking rules for unsolicited inbound traffic.",
                            references=[]
                        ))
                else:
                    self.limitations.append(f"Could not parse state for {profile_name}.")
        except Exception as e:
            logger.warning("Firewall audit error: %s", e)
            self.limitations.append(f"Failed to query Windows Firewall: {e}")

        return findings

    def audit_antivirus_status(self) -> List[Finding]:
        """Inspect Windows Defender and registered Antivirus providers."""
        findings: List[Finding] = []
        if platform.system().lower() != "windows":
            return findings

        # Method A: Try PowerShell Get-MpComputerStatus
        defender_parsed = False
        cmd_mp = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled, BehaviorMonitorEnabled | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd_mp, capture_output=True, text=True, timeout=10, shell=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                defender_parsed = True
                rt_enabled = data.get("RealTimeProtectionEnabled", False)
                av_enabled = data.get("AntivirusEnabled", False)

                if not av_enabled:
                    findings.append(Finding(
                        id="DEFENDER-AV-DISABLED",
                        title="Windows Defender Antivirus Engine Disabled",
                        category="Antivirus",
                        severity=Severity.HIGH,
                        description="Windows Defender Antivirus protection is reported as inactive.",
                        evidence=f"AntivirusEnabled: {av_enabled}",
                        remediation="Turn on Microsoft Defender Antivirus or ensure a recognized third-party antivirus is active.",
                        references=["https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows"]
                    ))
                elif not rt_enabled:
                    findings.append(Finding(
                        id="DEFENDER-REALTIME-DISABLED",
                        title="Windows Defender Real-Time Protection Disabled",
                        category="Antivirus",
                        severity=Severity.HIGH,
                        description="Real-Time Protection is deactivated, meaning files are not scanned when accessed.",
                        evidence=f"RealTimeProtectionEnabled: {rt_enabled}",
                        remediation="Enable Real-Time Protection via Windows Security > Virus & threat protection settings.",
                        references=[]
                    ))
                else:
                    findings.append(Finding(
                        id="DEFENDER-ACTIVE",
                        title="Windows Defender Real-Time Protection Active",
                        category="Antivirus",
                        severity=Severity.INFO,
                        description="Windows Defender Antivirus and real-time monitoring are operational.",
                        evidence=f"AntivirusEnabled={av_enabled}, RealTimeProtectionEnabled={rt_enabled}",
                        remediation="Keep virus definition updates enabled via Windows Update.",
                        references=[]
                    ))
        except Exception as e:
            logger.debug("Get-MpComputerStatus attempt failed: %s", e)

        # Method B: WMI SecurityCenter2 query (especially effective when 3rd party AV or Defender WMI class differs)
        if not defender_parsed:
            cmd_wmi = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json"
            ]
            try:
                res = subprocess.run(cmd_wmi, capture_output=True, text=True, timeout=10, shell=False)
                if res.returncode == 0 and res.stdout.strip():
                    raw = json.loads(res.stdout.strip())
                    products = raw if isinstance(raw, list) else [raw]
                    if products:
                        for p in products:
                            name = p.get("displayName", "Unknown Antivirus")
                            findings.append(Finding(
                                id=f"AV-PRODUCT-{re.sub(r'[^A-Z0-9]', '', name.upper())}",
                                title=f"Registered Antivirus: {name}",
                                category="Antivirus",
                                severity=Severity.INFO,
                                description=f"Security provider '{name}' is registered with Windows Security Center.",
                                evidence=f"Product: {name}, StateCode: {p.get('productState', 'N/A')}",
                                remediation="Ensure real-time shields and signature definitions are up to date.",
                                references=[]
                            ))
                    else:
                        findings.append(Finding(
                            id="AV-NO-PRODUCTS-FOUND",
                            title="No Antivirus Products Registered in SecurityCenter",
                            category="Antivirus",
                            severity=Severity.HIGH,
                            description="No registered antivirus product was found in Windows SecurityCenter2.",
                            evidence="SecurityCenter2 AntiVirusProduct returned empty list.",
                            remediation="Install or activate an approved antivirus solution (e.g. Microsoft Defender).",
                            references=[]
                        ))
                else:
                    self.limitations.append("Unable to query Antivirus status via SecurityCenter2 WMI.")
            except Exception as e:
                logger.debug("SecurityCenter2 query failed: %s", e)
                self.limitations.append(f"Antivirus inspection restricted: {e}")

        return findings

    def audit_uac_status(self) -> List[Finding]:
        """Inspect User Account Control (UAC) status via registry query."""
        findings: List[Finding] = []
        if platform.system().lower() != "windows":
            return findings

        cmd = ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=6, shell=False)
            if res.returncode == 0:
                match = re.search(r"EnableLUA\s+REG_DWORD\s+(0x[0-9a-fA-F]+)", res.stdout)
                if match:
                    val = int(match.group(1), 16)
                    if val == 0:
                        findings.append(Finding(
                            id="UAC-DISABLED",
                            title="User Account Control (UAC) is Disabled",
                            category="UAC",
                            severity=Severity.HIGH,
                            description="UAC (EnableLUA) is deactivated. Any program running under an administrator account executes with full admin privileges without prompting.",
                            evidence="Registry HKLM\\...\\Policies\\System\\EnableLUA = 0x0",
                            remediation="Enable UAC in Control Panel > User Accounts > Change User Account Control Settings (recommended level: Always notify or default).",
                            references=["https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/"]
                        ))
                    else:
                        findings.append(Finding(
                            id="UAC-ENABLED",
                            title="User Account Control (UAC) is Enabled",
                            category="UAC",
                            severity=Severity.INFO,
                            description="UAC is active, prompting for elevation when standard processes attempt administrative operations.",
                            evidence="Registry HKLM\\...\\Policies\\System\\EnableLUA = 0x1",
                            remediation="Maintain UAC slider at default or higher to prevent silent privilege escalation.",
                            references=[]
                        ))
            else:
                self.limitations.append(f"UAC registry check failed with return code {res.returncode}")
        except Exception as e:
            logger.debug("UAC check error: %s", e)
            self.limitations.append(f"UAC check encountered error: {e}")

        return findings

    def audit_listening_ports(self) -> tuple[List[Finding], Dict[str, Any]]:
        """Inspect local listening TCP/UDP sockets for exposed high-risk services."""
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {"listening_count": 0}

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            self.limitations.append("Full network socket inspection requires Administrator privileges (Access Denied).")
            return findings, metrics
        except Exception as e:
            self.limitations.append(f"Socket inspection failed: {e}")
            return findings, metrics

        listening_ports = []
        for conn in connections:
            if conn.status == "LISTEN" or (conn.type == socket.SOCK_DGRAM and not conn.raddr):
                metrics["listening_count"] += 1
                laddr = conn.laddr
                port = laddr.port
                ip = laddr.ip
                is_wildcard = ip in ("0.0.0.0", "::", "")

                if port in HIGH_RISK_PORTS:
                    service_name, desc, default_severity = HIGH_RISK_PORTS[port]
                    # If listening strictly on localhost (127.0.0.1 or ::1), reduce severity
                    is_localhost = ip in ("127.0.0.1", "::1")
                    actual_severity = Severity.LOW if is_localhost else default_severity

                    findings.append(Finding(
                        id=f"RISK-PORT-{port}-{ip}",
                        title=f"Exposed Service Detected: {service_name} (Port {port})",
                        category="Network Attack Surface",
                        severity=actual_severity,
                        description=(
                            f"{desc} Listening on {ip}:{port} "
                            + ("(Bound to all interfaces / wildcard - exposed to network)." if is_wildcard else f"(Bound specifically to {ip}).")
                        ),
                        evidence=f"Local Address: {ip}:{port}, Status: {conn.status}, PID: {conn.pid or 'N/A'}",
                        remediation=(
                            f"If {service_name} is not required, disable or stop the associated service. "
                            f"If required, ensure Windows Firewall blocks external access to port {port}."
                        ),
                        references=["https://www.cisa.gov/resources-tools/resources/securing-network-infrastructure"]
                    ))

        return findings, metrics

    def audit_user_context(self, sys_info: Dict[str, Any]) -> List[Finding]:
        """Examine current execution context and provide advisory guidance."""
        findings: List[Finding] = []
        if sys_info.get("is_elevated"):
            findings.append(Finding(
                id="CTX-ADMIN-SESSION",
                title="Audit Executed in Elevated Administrator Context",
                category="Privilege Context",
                severity=Severity.INFO,
                description="Toolkit has full administrative visibility into kernel drivers, protected sockets, and security policies.",
                evidence="Token check: IsUserAnAdmin() returned True",
                remediation="Only execute utilities with elevation when diagnostic inspection of protected resources is required.",
                references=[]
            ))
        else:
            findings.append(Finding(
                id="CTX-STANDARD-SESSION",
                title="Audit Executed in Standard User Context",
                category="Privilege Context",
                severity=Severity.LOW,
                description="The tool is running under a non-elevated user token. Some protected process paths and kernel sockets may be inaccessible.",
                evidence="Token check: IsUserAnAdmin() returned False",
                remediation="To perform deep inspection of all system services and firewall rules, right-click PowerShell and select 'Run as Administrator'.",
                references=[]
            ))
        return findings
