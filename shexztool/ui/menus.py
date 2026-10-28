"""Interactive Dashboard and Menu Navigation for SheXzTool.

Attributed to developer brand: SheRaXzy Sentinel.
"""

from __future__ import annotations
import ctypes
import getpass
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from shexztool.banner import (
    COLOR_CRIMSON,
    COLOR_CRIMSON_BRIGHT,
    COLOR_CRIMSON_DARK,
    COLOR_OBSIDIAN,
    get_banner_panel,
)
from shexztool.config import load_config, save_user_config
from shexztool.core.models import ScanResult
from shexztool.core.validator import Validator
from shexztool.modules.auditor import SystemAuditor
from shexztool.modules.fim import FileIntegrityMonitor
from shexztool.modules.inspector import ProcessInspector
from shexztool.modules.network import NetworkDiagnostics
from shexztool.modules.reporter import SecurityReporter
from shexztool.ui.console import (
    console,
    display_connection_table,
    display_fim_comparison,
    display_findings_table,
    display_network_table,
    display_port_scan_table,
    display_process_table,
    display_reports_table,
    print_section_header,
    prompt_confirmation,
)

logger = logging.getLogger("shexztool.ui.menus")


class MainMenu:
    """Controls the interactive black-and-crimson terminal dashboard."""

    def __init__(self):
        self.config = load_config()
        self.auditor = SystemAuditor(self.config)
        self.network = NetworkDiagnostics(
            default_timeout=self.config.get("network", {}).get("default_timeout_seconds", 2.0),
            max_workers=self.config.get("network", {}).get("max_concurrent_workers", 15),
        )
        self.inspector = ProcessInspector()
        self.fim = FileIntegrityMonitor()
        self.reporter = SecurityReporter()

        self.user_context = getpass.getuser()
        try:
            self.is_elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            self.is_elevated = False

    def display_banner(self) -> None:
        """Render brand banner with elevation status."""
        console.clear()
        console.print(get_banner_panel(self.user_context, self.is_elevated))

    def run(self) -> None:
        """Main dashboard interaction loop."""
        while True:
            self.display_banner()
            self.render_menu_options()

            try:
                choice = Prompt.ask(
                    f"\n[bold {COLOR_CRIMSON_BRIGHT}]SheRaXzy-Sentinel[/]>> Select option",
                    choices=["1", "2", "3", "4", "5", "6", "7", "0"],
                    default="1",
                )
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session terminated by user. Exiting safely.[/]")
                break

            if choice == "1":
                self.handle_system_audit()
            elif choice == "2":
                self.handle_network_diagnostics()
            elif choice == "3":
                self.handle_process_inspector()
            elif choice == "4":
                self.handle_fim()
            elif choice == "5":
                self.handle_view_reports()
            elif choice == "6":
                self.handle_configuration()
            elif choice == "7":
                self.handle_help()
            elif choice == "0":
                console.print("\n[bold #ff2a5f]Shutting down SheXzTool. Stay vigilant, defender.[/]")
                break

            self.pause_for_user()

    def render_menu_options(self) -> None:
        """Display styled menu navigation grid."""
        menu_table = Table(
            box=None,
            show_header=False,
            padding=(0, 2),
            style=f"on {COLOR_OBSIDIAN}",
        )
        menu_table.add_column("Key", style=f"bold {COLOR_CRIMSON_BRIGHT}", width=5)
        menu_table.add_column("Module", style="bold white", width=34)
        menu_table.add_column("Description", style="dim")

        menu_table.add_row("[1]", "System Security Auditor", "Firewall, Defender, UAC, listening ports, policy checks")
        menu_table.add_row("[2]", "Network Diagnostics", "NICs, Gateway, DNS latency, targeted TCP port tester")
        menu_table.add_row("[3]", "Process & Connection Inspector", "Live processes, resource telemetry, heuristic anomaly checks")
        menu_table.add_row("[4]", "File Integrity Monitor (FIM)", "SHA-256 baseline creation & cryptographic change detection")
        menu_table.add_row("[5]", "Security Reports Archive", "Inspect and browse generated HTML and JSON audit reports")
        menu_table.add_row("[6]", "Toolkit Configuration", "Manage timeouts, port thresholds, ignored paths & output dirs")
        menu_table.add_row("[7]", "Help & Defensive Guidelines", "Usage guide, ethical boundaries & Windows elevation context")
        menu_table.add_row("[0]", "Exit SheXzTool", "Terminate session and close terminal toolkit")

        console.print(Panel(menu_table, title="[bold #ff2a5f]COMMAND CENTER[/]", border_style=COLOR_CRIMSON_DARK))

    def pause_for_user(self) -> None:
        """Wait for keypress before clearing screen."""
        console.print()
        Prompt.ask("[dim]Press Enter to return to main dashboard...[/]", default="")

    # -------------------------------------------------------------
    # Option 1: System Security Audit
    # -------------------------------------------------------------
    def handle_system_audit(self) -> None:
        """Execute full system audit with progress indicator."""
        print_section_header("SYSTEM SECURITY AUDIT", "Real-Time Defensive Posture Evaluation")

        with Progress(
            SpinnerColumn(spinner_name="dots", style="crimson.bright"),
            TextColumn("[bold white]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Gathering host telemetry and evaluating security policies...", total=None)
            scan_result: ScanResult = self.auditor.run_full_audit()
            progress.update(task, completed=True)

        display_findings_table(scan_result.findings)

        if scan_result.limitations:
            console.print("\n[bold yellow]>> DIAGNOSTIC NOTICES & LIMITATIONS:[/]")
            for lim in scan_result.limitations:
                console.print(f"  [dim]* {lim}[/]")

        # Ask to save reports
        console.print()
        if prompt_confirmation("Would you like to export this audit report to HTML and JSON?", default=True):
            html_path = self.reporter.export_scan_html(scan_result)
            json_path = self.reporter.export_scan_json(scan_result)
            console.print(f"[bold green][OK] HTML Report saved:[/] [cyan]{html_path}[/]")
            console.print(f"[bold green][OK] JSON Report saved:[/] [cyan]{json_path}[/]")

    # -------------------------------------------------------------
    # Option 2: Network Diagnostics
    # -------------------------------------------------------------
    def handle_network_diagnostics(self) -> None:
        """Show adapters, gateway, DNS, and targeted TCP connectivity."""
        print_section_header("NETWORK DIAGNOSTICS & CONNECTIVITY", "Local Adapters, Routing, and Targeted Checks")

        interfaces = self.network.get_interface_details()
        routing = self.network.get_routing_and_dns()
        display_network_table(interfaces, routing)

        console.print("\n[bold #ff2a5f]Select a Network Diagnostic Tool:[/]")
        console.print("  [1] DNS Resolution & Latency Diagnostic")
        console.print("  [2] Targeted TCP Port Connectivity Checker")
        console.print("  [0] Return to Menu")

        sub_choice = Prompt.ask("\nChoose action", choices=["1", "2", "0"], default="1")
        if sub_choice == "1":
            domain = Prompt.ask("\nEnter hostname or domain to test (e.g. cloudflare.com, google.com)").strip()
            if not domain:
                return
            with console.status(f"[bold white]Resolving {domain}...[/]", spinner="dots"):
                res = self.network.diagnose_dns_resolution(domain)
            if res["success"]:
                console.print(f"[bold green][OK] DNS Resolution Succeeded[/] in [bold white]{res['latency_ms']} ms[/]")
                if res["ipv4"]:
                    console.print(f"  [bold cyan]IPv4:[/] {', '.join(res['ipv4'])}")
                if res["ipv6"]:
                    console.print(f"  [dim]IPv6:[/] {', '.join(res['ipv6'])}")
            else:
                console.print(f"[bold red][X] Resolution Failed:[/] {res['error']}")

        elif sub_choice == "2":
            target = Prompt.ask("\nEnter target hostname or IP address (e.g. 127.0.0.1 or test machine)").strip()
            valid, sanitized = Validator.validate_target(target)
            if not valid:
                console.print(f"[bold red][X] Invalid target syntax: '{target}'. Aborting.[/]")
                return

            scope_info = self.network.classify_target_scope(sanitized)
            console.print(f"\n[bold #ff2a5f]Target Scope Classification:[/] [bold white]{scope_info['scope']}[/] - {scope_info['description']}")
            
            if scope_info.get("is_external"):
                console.print("[bold red][!] NOTICE:[/] You have specified an EXTERNAL public IP or host. Only test hosts you own or have explicit authorization to audit!")
                if not prompt_confirmation("Do you certify you have authorization to test connectivity on this target?", default=False):
                    console.print("[yellow]Connectivity check cancelled by user.[/]")
                    return

            port_input = Prompt.ask(
                "Enter port(s) to check (e.g. '80,443', '20-25', or '8080')",
                default="80,443,3389,8080",
            )
            ports, err = Validator.parse_port_specification(port_input, max_ports=100)
            if err:
                console.print(f"[bold red][X] {err}[/]")
                return

            console.print(f"[dim]Initiating safe TCP connection tests across {len(ports)} port(s)...[/]")
            with Progress(
                SpinnerColumn(spinner_name="dots", style="crimson.bright"),
                TextColumn("[bold white]{task.description}"),
                transient=True,
            ) as progress:
                t = progress.add_task(f"Scanning {sanitized}...", total=len(ports))

                def on_progress(done: int, total: int):
                    progress.update(t, completed=done, description=f"Checked {done}/{total} ports...")

                try:
                    results = self.network.scan_target_ports(sanitized, ports, on_progress=on_progress)
                except Exception as e:
                    console.print(f"[bold red]Scan error: {e}[/]")
                    return

            display_port_scan_table(sanitized, scope_info, results)

    # -------------------------------------------------------------
    # Option 3: Process & Connection Inspector
    # -------------------------------------------------------------
    def handle_process_inspector(self) -> None:
        """Inspect running processes, memory, and sockets."""
        print_section_header("PROCESS & CONNECTION INSPECTOR", "Real-Time Telemetry and Heuristics")

        console.print("  [1] View Top Processes by Memory (Apply Anomaly Heuristics)")
        console.print("  [2] View Top Processes by CPU Usage")
        console.print("  [3] Search Process by Name")
        console.print("  [4] Inspect Active Network Connections (Sockets)")
        console.print("  [0] Return to Menu")

        sub_choice = Prompt.ask("\nChoose inspector view", choices=["1", "2", "3", "4", "0"], default="1")
        if sub_choice == "0":
            return

        if sub_choice in ("1", "2", "3"):
            sort_by = "memory_mb" if sub_choice == "1" else "cpu_percent"
            filter_name = None
            if sub_choice == "3":
                filter_name = Prompt.ask("Enter process name filter (e.g. 'python', 'chrome', 'svchost')").strip()

            with console.status("[bold white]Inspecting active processes...[/]", spinner="dots"):
                processes = self.inspector.inspect_processes(filter_name=filter_name, sort_by=sort_by, limit=25)

            display_process_table(processes)

        elif sub_choice == "4":
            with console.status("[bold white]Enumerating network sockets and linking PIDs...[/]", spinner="dots"):
                conns = self.inspector.inspect_active_connections()
            display_connection_table(conns, limit=40)

    # -------------------------------------------------------------
    # Option 4: File Integrity Monitor (FIM)
    # -------------------------------------------------------------
    def handle_fim(self) -> None:
        """Create baseline, compare baseline, and list existing baselines."""
        print_section_header("FILE INTEGRITY MONITOR (FIM)", "Cryptographic SHA-256 State Verification")

        console.print("  [1] Create New Integrity Baseline (Directory or File)")
        console.print("  [2] Compare Live Files Against a Baseline")
        console.print("  [3] List Existing Saved Baselines")
        console.print("  [0] Return to Menu")

        sub = Prompt.ask("\nChoose action", choices=["1", "2", "3", "0"], default="1")
        if sub == "0":
            return

        if sub == "1":
            console.print("\n[bold #f59e0b]SECURITY PRINCIPLE:[/] A hash baseline represents your trusted reference point.")
            console.print("[dim]Only establish a baseline when you trust the current integrity of the files.[/]\n")

            target_path_str = Prompt.ask("Enter path to file or directory to baseline", default=".")
            valid, path_obj, err = Validator.validate_path_exists(target_path_str)
            if not valid or path_obj is None:
                console.print(f"[bold red][X] {err}[/]")
                return

            base_name = Prompt.ask("Enter a friendly name for this baseline", default=path_obj.name)

            with Progress(
                SpinnerColumn(spinner_name="dots", style="crimson.bright"),
                TextColumn("[bold white]{task.description}"),
                transient=True,
            ) as progress:
                t = progress.add_task("Calculating SHA-256 hashes...", total=None)

                def on_prog(count: int, file_rel: str):
                    progress.update(t, description=f"Hashed {count} files: {file_rel[:40]}...")

                try:
                    dest_file, payload = self.fim.create_baseline(path_obj, base_name, on_progress=on_prog)
                except Exception as e:
                    console.print(f"[bold red][X] Baseline creation failed: {e}[/]")
                    return

            console.print(f"\n[bold green][OK] Baseline successfully created![/]")
            console.print(f"  [bold #ff2a5f]Saved to:[/] {dest_file}")
            console.print(f"  [bold #ff2a5f]Total Files Tracked:[/] {payload['total_files']}")
            if payload.get("errors"):
                console.print(f"  [bold yellow]Warnings / Skipped Files:[/] {len(payload['errors'])}")

        elif sub == "2":
            baselines = self.fim.list_baselines()
            if not baselines:
                console.print("[dim]No baselines found. Create one first![/]")
                return

            console.print("\n[bold #ff2a5f]Select a baseline to compare against:[/]")
            for idx, b in enumerate(baselines, 1):
                console.print(f"  [{idx}] {b['baseline_name']} ({b['created_at']}) - {b['total_files']} files [dim]Path: {b['root_path']}[/]")

            choice_idx = Prompt.ask("Choose baseline #", choices=[str(i) for i in range(1, len(baselines) + 1)])
            selected = baselines[int(choice_idx) - 1]

            with Progress(
                SpinnerColumn(spinner_name="dots", style="crimson.bright"),
                TextColumn("[bold white]{task.description}"),
                transient=True,
            ) as progress:
                t = progress.add_task("Hashing current files and comparing against baseline...", total=None)
                try:
                    res = self.fim.compare_baseline(Path(selected["file_path"]))
                except Exception as e:
                    console.print(f"[bold red][X] Comparison error: {e}[/]")
                    return

            display_fim_comparison(res)

            if res.has_changes:
                if prompt_confirmation("Would you like to export this FIM report to JSON?", default=True):
                    rep_path = self.reporter.export_fim_json(res)
                    console.print(f"[bold green][OK] FIM JSON report saved:[/] [cyan]{rep_path}[/]")

        elif sub == "3":
            baselines = self.fim.list_baselines()
            if not baselines:
                console.print("[dim]No saved baselines found in baselines/ directory.[/]")
                return

            table = Table(title="[bold #ff2a5f]SAVED FIM BASELINES[/]", border_style=COLOR_CRIMSON_DARK)
            table.add_column("Baseline Name", style="bold white")
            table.add_column("Created At", style="dim")
            table.add_column("Root Target Path", style="#38bdf8")
            table.add_column("Files Tracked", justify="right", style="green")

            for b in baselines:
                table.add_row(b["baseline_name"], b["created_at"], b["root_path"], str(b["total_files"]))
            console.print(table)

    # -------------------------------------------------------------
    # Option 5: View Previous Reports
    # -------------------------------------------------------------
    def handle_view_reports(self) -> None:
        """List and inspect previously generated reports."""
        print_section_header("SECURITY REPORTS ARCHIVE", "Generated HTML and JSON Security Audits")
        reports = self.reporter.list_reports()
        display_reports_table(reports)

        if not reports:
            return

        choice = Prompt.ask(
            "\nEnter report # to view details or launch in browser (or 0 to cancel)",
            choices=[str(i) for i in range(len(reports) + 1)],
            default="0",
        )
        if choice != "0":
            target = reports[int(choice) - 1]
            console.print(f"\n[bold #ff2a5f]Selected Report:[/] {target['filename']}")
            console.print(f"  [dim]Absolute Path:[/] [cyan]{target['path']}[/]")
            if target["type"] == "HTML":
                if prompt_confirmation("Open this HTML report in your default web browser?", default=True):
                    try:
                        os.startfile(target["path"])
                        console.print("[bold green][OK] Opened report in default browser.[/]")
                    except Exception as e:
                        console.print(f"[bold red]Could not launch browser: {e}[/]")

    # -------------------------------------------------------------
    # Option 6: Configuration
    # -------------------------------------------------------------
    def handle_configuration(self) -> None:
        """Inspect and safely modify tool configuration."""
        print_section_header("TOOLKIT CONFIGURATION", "Safe Parameters & Paths")

        conf_str = json.dumps(self.config, indent=2)
        console.print(f"[dim]{conf_str}[/]\n")
        console.print("[dim]Configuration is persisted in config.json and config.default.json.[/]")

    # -------------------------------------------------------------
    # Option 7: Help & Defensive Guidelines
    # -------------------------------------------------------------
    def handle_help(self) -> None:
        """Explain tool concepts, ethics, and Windows defensive posture."""
        print_section_header("HELP, ETHICS & DEFENSIVE GUIDELINES", "Ethical Framework & Operation")

        help_text = """
[bold #ff2a5f]1. BRAND & PURPOSE[/]
SheXzTool is attributed to the developer brand [bold white]SheRaXzy Sentinel[/].
It is an educational and defensive cybersecurity toolkit built to help learners and practitioners
safely audit local Windows configurations, inspect processes, verify network posture, and monitor file integrity.

[bold #ff2a5f]2. DEFENSIVE ETHICS & BOUNDARIES[/]
* [bold white]Strictly Read-Only:[/] Normal tool operations do not alter firewall rules, kill processes, or modify inspected files.
* [bold white]No Exploitation:[/] This tool contains NO exploits, payload delivery, password crackers, or stealth scanners.
* [bold white]Target Authorization:[/] Targeted port checks require explicit confirmation. Always obtain written authorization before scanning remote machines.

[bold #ff2a5f]3. WINDOWS ELEVATION CONTEXT[/]
* [bold white]Standard User Context:[/] Inspects current user processes, local interface addresses, and safe system registry settings.
* [bold white]Elevated Context (Administrator):[/] Required for full inspection of all system services, kernel-bound listening sockets, and Windows Defender WMI classes.
* To run elevated: Right-click your terminal / PowerShell and select 'Run as Administrator'.

[bold #ff2a5f]4. COMPONENT OVERVIEW[/]
* [bold white]System Auditor:[/] Queries Windows Firewall profiles, Defender real-time protection, UAC status, and exposed high-risk ports.
* [bold white]Network Diagnostics:[/] Checks NICs, default gateway, DNS latency, and performs bounded TCP connectivity tests.
* [bold white]Process Inspector:[/] Highlights processes with transparent heuristics (e.g. system binaries executing from non-system directories).
* [bold white]File Integrity Monitor:[/] Takes cryptographic SHA-256 snapshots. Remember: A baseline is only as trustworthy as the system was when it was taken!
* [bold white]Reporting Engine:[/] Exports beautiful, dark black-and-crimson HTML dashboards and structured JSON reports.
        """
        console.print(Panel(help_text, border_style=COLOR_CRIMSON_DARK, style=f"on {COLOR_OBSIDIAN}"))
