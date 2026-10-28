# SheXzTool // SheRaXzy Sentinel
### Defensive Windows Cybersecurity Toolkit & Audit Utility

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-dc2626?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0f172a?style=flat-square&logo=windows)](https://microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-be123c?style=flat-square)](LICENSE)
[![Theme](https://img.shields.io/badge/Theme-Black%20%26%20Crimson-e11d48?style=flat-square)](https://github.com)

**SheXzTool** is a functional defensive cybersecurity utility and educational audit toolkit engineered for Windows 10/11 and attributed to developer brand **SheRaXzy** (*SheRaXzy Sentinel*).

The application features a futuristic **Black-and-Crimson** terminal dashboard, robust input validation, transparent heuristics, and an HTML/JSON reporting engine.

---

## Table of Contents
1. [Core Modules](#core-modules)
2. [Prerequisites](#prerequisites)
3. [Installation & Setup](#installation--setup)
4. [Running the Application](#running-the-application)
5. [CLI Non-Interactive Mode](#cli-non-interactive-mode)
6. [Administrator Privileges: When & Why](#administrator-privileges-when--why)
7. [Running the Automated Test Suite](#running-the-automated-test-suite)
8. [Configuration](#configuration)
9. [Defensive Architecture & Safety Boundaries](#defensive-architecture--safety-boundaries)
10. [Troubleshooting](#troubleshooting)

---

## Core Modules

### 1. System Security Auditor
* **Windows Firewall Profile Auditing**: Safe read-only inspection of Domain, Private, and Public profiles via `netsh advfirewall show allprofiles state`.
* **Antivirus & Windows Defender Verification**: Safe status queries via `Get-MpComputerStatus` and fallback inspection of `root/SecurityCenter2 AntiVirusProduct`.
* **User Account Control (UAC) Inspector**: Inspects registry key `EnableLUA` to flag whether silent privilege escalation is permitted.
* **Exposed Ports Assessment**: Detects listening services bound to wildcard (`0.0.0.0` or `::`) such as SMB (445), RPC (135), NetBIOS (137/139), and RDP (3389).
* **Explainable Findings**: Categorizes risks as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`, providing concrete remediation steps and documentation links.

### 2. Network Diagnostics & Targeted Port Connectivity
* **Local Adapters & Routing**: Lists network interfaces, MAC addresses, IPv4/IPv6 assignments, default gateway, and DNS servers.
* **DNS Resolution & Latency**: Measures lookup latency and forward resolution for any specified domain.
* **Targeted TCP Port Checker**: Bounded connect-scan across user-specified ports (e.g. `80,443,8000-8010`).
* **Explicit Scope & Confirmation**: Discloses target scope (`LOCAL_LOOPBACK`, `PRIVATE_LAN`, or `EXTERNAL_PUBLIC`) and requires explicit confirmation before checking external targets.
* **Defensive Boundaries**: Strictly non-destructive; no stealth scans, no exploitation, and no Denial of Service.

### 3. Process & Connection Inspector
* **Live Process Enumerator**: Displays active processes sorted by memory or CPU usage, along with PID and user context.
* **Explainable Anomaly Heuristics**:
  * Flags system binaries (e.g. `svchost.exe`, `lsass.exe`, `csrss.exe`) executing from non-standard directories outside `System32` or `SysWOW64`.
  * Flags binaries executing out of temporary staging paths (e.g. `AppData\Local\Temp`).
  * Flags excessive resource consumption (>2500 MB RAM).
  * *Note:* Never labels unknown processes as malware without verifiable cryptographic proof.
* **Active Sockets**: Links open network connections to associated process names and PIDs.

### 4. File Integrity Monitor (FIM)
* **Cryptographic Baselines**: Generates SHA-256 snapshots of directory trees or single files, streaming in 64KB chunks.
* **Zero Modification Guarantee**: Strictly read-only; never deletes, encrypts, or touches monitored files.
* **Change Detection**: Categorizes differences as `New Files`, `Modified Files` (hash mismatch), `Missing Files` (deleted), and `Unchanged Files`.
* **Symlink & Ignore Protection**: Prevents circular symlink traversal (`followlinks=False`) and ignores noisy build directories (`.git`, `node_modules`, `__pycache__`, `.venv`).
* **Trusted Baseline Principle**: Clearly notes that a hash baseline is only trustworthy if established on a known-clean system.

### 5. Security Reporting Engine
* **Dark Black-and-Crimson HTML Reports**: Audit-ready HTML reports styled with CSS tokens, cards, and severity badge pills.
* **HTML Escaping**: Prevents Cross-Site Scripting (XSS) by running all dynamic host and scan data through `html.escape()`.
* **Structured JSON Reports**: Machine-readable output for integration into SIEMs or CI pipelines.
* **Dedicated Archive**: Stored in `reports/` without recording credentials or secrets.

---

## Prerequisites
* **Operating System**: Windows 10 or Windows 11 (64-bit)
* **Python**: Python 3.11, 3.12, 3.13, or 3.14+
* **PowerShell**: Windows PowerShell 5.1+ or PowerShell 7+

---

## Installation & Setup

Open **Windows PowerShell** and run the following commands:

```powershell
# 1. Clone or navigate to the SheRaXzySentinel directory
cd "C:\Users\SheRaX\Desktop\SheRaXzySentinel"

# 2. Create a virtual environment (optional but recommended)
python -m venv .venv

# 3. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

### Interactive Crimson Dashboard (Default)
Launch the full interactive command center:

```powershell
python main.py
```

You will be greeted by the **SheXzTool** banner:
```
  ███████╗██╗  ██╗███████╗██╗  ██╗███████╗████████╗ ██████╗  ██████╗ ██╗     
  ██╔════╝██║  ██║██╔════╝╚██╗██╔╝╚══███╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
  ███████╗███████║█████╗   ╚███╔╝   ███╔╝    ██║   ██║   ██║██║   ██║██║     
  ╚════██║██╔══██║██╔══╝   ██╔██╗  ███╔╝     ██║   ██║   ██║██║   ██║██║     
  ███████║██║  ██║███████╗██╔╝ ██╗███████╗   ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                     S h e R a X z y   S e n t i n e l
```

Use keys `1` through `7` to navigate modules, or `0` to exit.

---

## CLI Non-Interactive Mode

SheXzTool can be scripted or executed directly from the terminal without interactive prompts:

```powershell
# Run full system security audit and export HTML + JSON reports
python main.py --audit --export-html --export-json

# Inspect network interfaces, routing, and DNS
python main.py --network

# Targeted TCP port connectivity check (e.g. localhost)
python main.py --check-ports 127.0.0.1 --ports 80,443,135,445

# Inspect active processes with anomaly heuristics
python main.py --processes

# Create an integrity baseline for a folder
python main.py --fim-baseline shexztool --baseline-name my_baseline

# Compare live files against an existing baseline
python main.py --fim-compare baselines\my_baseline_XXXXXX.json --export-json

# View CLI options
python main.py --help
```

---

## Administrator Privileges: When & Why

SheXzTool is designed to be functional even without administrative elevation:

| Feature / Inspection | Standard User | Administrator (Elevated) | Why Elevation is Needed |
| :--- | :---: | :---: | :--- |
| **User Process List** | Accessible | Full Visibility | Standard users cannot inspect kernel processes or token details of other user sessions. |
| **Local Network Adapters & DNS** | Accessible | Accessible | Windows allows standard accounts to query local IP addresses. |
| **Targeted TCP Port Testing** | Accessible | Accessible | Standard user-space sockets are used for TCP handshake checks. |
| **File Integrity Monitoring (FIM)** | User Files Only | System & Program Files | Hashing files in `C:\Windows` or `Program Files` requires read permissions for protected trees. |
| **Windows Firewall Profile Audit** | Accessible | Accessible | `netsh advfirewall show allprofiles state` is readable by standard users. |
| **All Active Kernel Socket Connections** | Partial | Complete | Non-elevated accounts receive `AccessDenied` on select listening sockets owned by SYSTEM. |
| **Windows Defender WMI Inspection** | Partial | Complete | Certain `root/Microsoft/Windows/Defender` WMI classes require administrator security tokens. |

> **How to run elevated**: Right-click **PowerShell** or **Windows Terminal** and select **Run as Administrator**, then launch `python main.py`.

---

## Running the Automated Test Suite

SheXzTool includes a test suite covering models, validation, heuristics, FIM hashing, and HTML escaping:

```powershell
# Run tests with pytest
python -m pytest tests/ -v

# Or use the built-in test runner
python run_tests.py
```

### Verified Test Suite Results
* **`tests/test_auditor.py`**:
  * `test_firewall_audit_disabled_profile` -> **PASSED**
  * `test_uac_audit_disabled` -> **PASSED**
  * `test_uac_audit_enabled` -> **PASSED**
  * `test_firewall_graceful_command_failure` -> **PASSED**
* **`tests/test_fim.py`**:
  * `test_sha256_computation` -> **PASSED**
  * `test_baseline_creation_and_comparison` -> **PASSED**
  * `test_unreadable_file_handling` -> **PASSED**
* **`tests/test_inspector.py`**:
  * `test_svchost_masquerade_detected` -> **PASSED**
  * `test_svchost_legitimate_normal` -> **PASSED**
  * `test_temp_directory_execution` -> **PASSED**
  * `test_high_memory_footprint` -> **PASSED**
* **`tests/test_models.py`**:
  * `test_severity_from_string` -> **PASSED**
  * `test_finding_to_dict` -> **PASSED**
  * `test_scan_result_severity_counts` -> **PASSED**
  * `test_fim_comparison_has_changes` -> **PASSED**
* **`tests/test_reporter.py`**:
  * `test_html_report_escaping` -> **PASSED** (Strict XSS injection prevention)
  * `test_json_report_export` -> **PASSED**
  * `test_list_reports` -> **PASSED**
* **`tests/test_validator.py`**:
  * `test_ip_validation` -> **PASSED**
  * `test_hostname_validation` -> **PASSED**
  * `test_port_validation` -> **PASSED**
  * `test_port_specification_parser` -> **PASSED**
  * `test_sanitize_filename` -> **PASSED**

**Total: 23 passed in 0.07s (100% passing)**.

---

## Configuration

Configurations are stored in `config.default.json` and can be customized by adding overrides in `config.json`:

```json
{
  "network": {
    "default_timeout_seconds": 2.0,
    "max_ports_per_scan": 100,
    "max_concurrent_workers": 20
  },
  "auditor": {
    "include_firewall_check": true,
    "include_defender_check": true,
    "include_uac_check": true,
    "include_listening_ports_check": true
  },
  "fim": {
    "hash_algorithm": "sha256",
    "ignored_directories": [".git", "node_modules", "__pycache__", ".venv"],
    "ignored_extensions": [".tmp", ".bak", ".log"]
  },
  "reporting": {
    "output_dir": "reports"
  }
}
```

---

## Defensive Architecture & Safety Boundaries

* **No Arbitrary Command Execution**: All external Windows tools are invoked with `shell=False` and structured argument lists (e.g., `["netsh", "advfirewall", ...]`).
* **Zero System Alteration**: The toolkit operates in read-only diagnostic mode. It does not reconfigure firewalls or terminate processes without authorization.
* **Bounded Concurrency**: Port checking utilizes a `ThreadPoolExecutor` capped at 15-20 workers to prevent network saturation.
* **Privacy & Sanitization**: Reports contain system configurations and security posture observations without embedding passwords or authentication tokens.

---

## Troubleshooting

1. **`Get-MpComputerStatus` fails or returns `Invalid class`**:
   * *Cause*: On certain Windows editions or environments with third-party endpoint security, Defender WMI classes may not be registered.
   * *Resolution*: SheXzTool automatically falls back to querying `root/SecurityCenter2 AntiVirusProduct`.
2. **`UnicodeEncodeError` in standard Windows cmd.exe**:
   * *Cause*: Legacy Windows code pages (such as CP1252) lack glyphs for some Unicode symbols.
   * *Resolution*: SheXzTool automatically configures `sys.stdout.reconfigure(encoding='utf-8')` and utilizes ASCII-safe status tags (`[OK]`, `[!]`, `[X]`).
3. **`AccessDenied` on sockets**:
   * *Cause*: Windows restricts access to PID bindings of protected system services for non-administrator accounts.
   * *Resolution*: Launch PowerShell as Administrator.

---

**Developed for SheRaXzy Sentinel** | Ethical Cybersecurity Education & Defensive Auditing.
