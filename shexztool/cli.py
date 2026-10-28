"""Command-line interface (CLI) entry point for SheXzTool.

Supports both interactive terminal dashboard and headless scriptable flags.
Attributed to developer brand: SheRaXzy Sentinel.
"""

from __future__ import annotations
import argparse
from pathlib import Path
import sys
from typing import Optional

# Ensure UTF-8 output encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from shexztool import __brand__, __version__
from shexztool.core.logger import setup_logging
from shexztool.core.validator import Validator
from shexztool.modules.auditor import SystemAuditor
from shexztool.modules.fim import FileIntegrityMonitor
from shexztool.modules.inspector import ProcessInspector
from shexztool.modules.network import NetworkDiagnostics
from shexztool.modules.reporter import SecurityReporter
from shexztool.ui.console import (
    console,
    display_fim_comparison,
    display_findings_table,
    display_network_table,
    display_port_scan_table,
    display_process_table,
)
from shexztool.ui.menus import MainMenu


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="shexztool",
        description=f"SheXzTool - Defensive Windows Cybersecurity Toolkit (Brand: {__brand__})",
        epilog="Run without arguments to launch the interactive crimson dashboard.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"SheXzTool v{__version__} ({__brand__})")
    parser.add_argument("--audit", action="store_true", help="Execute full system security audit non-interactively")
    parser.add_argument("--network", action="store_true", help="Display local network interfaces, routing, and DNS")
    parser.add_argument("--check-ports", metavar="TARGET", help="Target hostname or IP for TCP connectivity testing")
    parser.add_argument("--ports", default="80,443", help="Comma-separated ports or range (e.g. '80,443,8000-8010', max 100)")
    parser.add_argument("--processes", action="store_true", help="List active processes with heuristic analysis")
    parser.add_argument("--fim-baseline", metavar="PATH", help="Generate a new SHA-256 integrity baseline for PATH")
    parser.add_argument("--baseline-name", help="Custom name for the generated baseline")
    parser.add_argument("--fim-compare", metavar="BASELINE_FILE", help="Compare current files against recorded BASELINE_FILE")
    parser.add_argument("--export-html", action="store_true", help="Automatically export scan result to HTML in reports/")
    parser.add_argument("--export-json", action="store_true", help="Automatically export scan result to JSON in reports/")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Primary execution entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Initialize structured logging
    setup_logging(level=args.log_level)

    # If no functional arguments provided, launch interactive dashboard
    non_interactive = any([
        args.audit,
        args.network,
        args.check_ports,
        args.processes,
        args.fim_baseline,
        args.fim_compare,
    ])

    if not non_interactive:
        menu = MainMenu()
        menu.run()
        return 0

    reporter = SecurityReporter()

    # 1. System Audit
    if args.audit:
        auditor = SystemAuditor()
        scan_res = auditor.run_full_audit()
        display_findings_table(scan_res.findings)
        if args.export_html:
            p = reporter.export_scan_html(scan_res)
            console.print(f"[bold green][OK] HTML Report saved to:[/] {p}")
        if args.export_json:
            p = reporter.export_scan_json(scan_res)
            console.print(f"[bold green][OK] JSON Report saved to:[/] {p}")

    # 2. Network Diagnostics
    if args.network:
        net = NetworkDiagnostics()
        ifaces = net.get_interface_details()
        routing = net.get_routing_and_dns()
        display_network_table(ifaces, routing)

    # 3. Port Connectivity Checker
    if args.check_ports:
        target = args.check_ports.strip()
        valid, sanitized = Validator.validate_target(target)
        if not valid:
            console.print(f"[bold red][X] Invalid target format: '{target}'[/]")
            return 1

        ports, err = Validator.parse_port_specification(args.ports, max_ports=100)
        if err:
            console.print(f"[bold red][X] {err}[/]")
            return 1

        net = NetworkDiagnostics()
        scope_info = net.classify_target_scope(sanitized)
        console.print(f"[dim]Initiating non-destructive TCP checks against {sanitized}...[/]")
        results = net.scan_target_ports(sanitized, ports)
        display_port_scan_table(sanitized, scope_info, results)

    # 4. Process Inspection
    if args.processes:
        inspector = ProcessInspector()
        procs = inspector.inspect_processes(limit=40)
        display_process_table(procs)

    # 5. FIM Baseline Creation
    if args.fim_baseline:
        target_path = Path(args.fim_baseline).resolve()
        if not target_path.exists():
            console.print(f"[bold red][X] Path does not exist: {target_path}[/]")
            return 1
        fim = FileIntegrityMonitor()
        dest, payload = fim.create_baseline(target_path, args.baseline_name)
        console.print(f"[bold green][OK] Baseline generated:[/] {dest} ({payload['total_files']} files tracked)")

    # 6. FIM Baseline Comparison
    if args.fim_compare:
        baseline_file = Path(args.fim_compare).resolve()
        if not baseline_file.exists():
            console.print(f"[bold red][X] Baseline file not found: {baseline_file}[/]")
            return 1
        fim = FileIntegrityMonitor()
        res = fim.compare_baseline(baseline_file)
        display_fim_comparison(res)
        if args.export_json and res.has_changes:
            p = reporter.export_fim_json(res)
            console.print(f"[bold green][OK] FIM JSON report saved to:[/] {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
