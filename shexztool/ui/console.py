"""Terminal display and formatting helpers with black-and-crimson styling.

Attributed to developer brand: SheRaXzy Sentinel.
"""

from __future__ import annotations
import sys
from typing import Any, Dict, List, Optional

# Ensure UTF-8 output encoding on Windows consoles
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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from shexztool.banner import (
    COLOR_CRIMSON,
    COLOR_CRIMSON_BRIGHT,
    COLOR_CRIMSON_DARK,
    COLOR_OBSIDIAN,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_MUTED,
    format_severity_badge,
)
from shexztool.core.models import ConnectionDetail, Finding, FimComparisonResult, ProcessDetail

# Custom Black & Crimson Rich Theme
custom_theme = Theme({
    "crimson": COLOR_CRIMSON,
    "crimson.bright": COLOR_CRIMSON_BRIGHT,
    "crimson.dark": COLOR_CRIMSON_DARK,
    "muted": COLOR_TEXT_MUTED,
    "text": COLOR_TEXT_PRIMARY,
})

console = Console(theme=custom_theme, color_system="auto", legacy_windows=False)


def print_section_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print an eye-catching crimson-bordered section header."""
    text = Text()
    text.append(f">> {title.upper()}", style=f"bold {COLOR_CRIMSON_BRIGHT}")
    if subtitle:
        text.append(f"  // {subtitle}", style="dim")
    
    console.print()
    console.print(Panel(text, border_style=COLOR_CRIMSON, style=f"on {COLOR_OBSIDIAN}", padding=(0, 1)))


def display_findings_table(findings: List[Finding]) -> None:
    """Format and print audit findings in a clear, readable table."""
    if not findings:
        console.print("[bold green][OK] No security findings reported. All checks passed standard baseline.[/]")
        return

    table = Table(
        title="[bold #ff2a5f]SECURITY AUDIT FINDINGS[/]",
        border_style=COLOR_CRIMSON_DARK,
        header_style=f"bold {COLOR_CRIMSON_BRIGHT}",
        show_lines=True,
    )
    table.add_column("Severity", justify="center", width=12)
    table.add_column("ID / Category", style="dim", width=18)
    table.add_column("Finding Title & Description", style="text")
    table.add_column("Remediation Guidance", style="#38bdf8")

    for f in findings:
        badge = format_severity_badge(f.severity.value)
        id_cat = f"[bold white]{f.id}[/]\n[dim]{f.category}[/]"
        desc_block = f"[bold white]{f.title}[/]\n[dim]{f.description}[/]"
        if f.evidence:
            desc_block += f"\n[bold #f59e0b]Evidence:[/] [dim]{f.evidence}[/]"

        rem_block = f.remediation if f.remediation else "[dim]No action required.[/]"
        table.add_row(badge, id_cat, desc_block, rem_block)

    console.print(table)


def display_network_table(interfaces: List[Dict[str, Any]], routing: Dict[str, Any]) -> None:
    """Format local network configuration and interface metrics."""
    # Summary Table for Default Route and DNS
    sum_table = Table(title="[bold #ff2a5f]ROUTING & DNS CONFIGURATION[/]", border_style=COLOR_CRIMSON_DARK)
    sum_table.add_column("Property", style="bold #ff2a5f", width=22)
    sum_table.add_column("Configured Value", style="bold white")

    gateway = routing.get("default_gateway") or "None / Unconfigured"
    active_ip = routing.get("active_interface_ip") or "None"
    dns_list = ", ".join(routing.get("dns_servers", [])) or "None detected"

    sum_table.add_row("Default Gateway", gateway)
    sum_table.add_row("Primary Interface IP", active_ip)
    sum_table.add_row("Configured DNS Servers", dns_list)
    console.print(sum_table)

    console.print()

    # Interfaces Table
    if_table = Table(title="[bold #ff2a5f]LOCAL NETWORK ADAPTERS[/]", border_style=COLOR_CRIMSON_DARK, show_lines=True)
    if_table.add_column("Interface", style="bold white", width=24)
    if_table.add_column("Status", justify="center", width=10)
    if_table.add_column("MAC Address", style="dim", width=18)
    if_table.add_column("IPv4 Addresses", style="#38bdf8")
    if_table.add_column("IPv6 Addresses", style="dim")

    for iface in interfaces:
        status_badge = "[bold green]UP[/]" if iface["is_up"] else "[dim]DOWN[/]"
        ipv4_strs = [f"{item['ip']} (/{item.get('netmask', '')})" for item in iface["ipv4"]]
        ipv4_text = "\n".join(ipv4_strs) if ipv4_strs else "[dim]None[/]"
        ipv6_text = "\n".join(iface["ipv6"]) if iface["ipv6"] else "[dim]None[/]"

        if_table.add_row(
            iface["name"],
            status_badge,
            iface.get("mac", "N/A"),
            ipv4_text,
            ipv6_text,
        )

    console.print(if_table)


def display_process_table(processes: List[ProcessDetail]) -> None:
    """Print process list with highlight on heuristic anomalies."""
    table = Table(
        title="[bold #ff2a5f]PROCESS MONITOR & ANOMALY HEURISTICS[/]",
        border_style=COLOR_CRIMSON_DARK,
        header_style=f"bold {COLOR_CRIMSON_BRIGHT}",
        show_lines=False,
    )
    table.add_column("PID", justify="right", style="dim", width=8)
    table.add_column("Process Name", style="bold white", width=20)
    table.add_column("CPU %", justify="right", width=8)
    table.add_column("RAM (MB)", justify="right", width=10)
    table.add_column("User Context", style="dim", width=18)
    table.add_column("Heuristic Status / Anomaly Notice", style="bold")

    for p in processes:
        cpu_str = f"{p.cpu_percent:.1f}%"
        mem_str = f"{p.memory_mb:.1f}"

        if p.is_suspicious:
            status_str = f"[bold #ff2a5f][!] {p.anomaly_reason}[/]"
        else:
            status_str = "[bold green]Normal[/]"

        table.add_row(
            str(p.pid),
            p.name,
            cpu_str,
            mem_str,
            p.username or "[dim]Access Denied[/]",
            status_str,
        )

    console.print(table)


def display_connection_table(connections: List[ConnectionDetail], limit: int = 50) -> None:
    """Print active network sockets."""
    table = Table(
        title=f"[bold #ff2a5f]ACTIVE NETWORK SOCKETS (Showing Top {min(len(connections), limit)})[/]",
        border_style=COLOR_CRIMSON_DARK,
        header_style=f"bold {COLOR_CRIMSON_BRIGHT}",
    )
    table.add_column("Proto", width=6, style="dim")
    table.add_column("Local Address", style="bold white", width=24)
    table.add_column("Foreign Address", style="#38bdf8", width=24)
    table.add_column("State", justify="center", width=14)
    table.add_column("PID", justify="right", width=8)
    table.add_column("Process Name", style="dim")

    for c in connections[:limit]:
        state_styled = f"[bold green]{c.status}[/]" if c.status == "LISTEN" else f"[dim]{c.status}[/]"
        table.add_row(
            c.protocol,
            c.laddr,
            c.raddr,
            state_styled,
            str(c.pid or "-"),
            c.process_name or "Unknown",
        )

    console.print(table)


def display_port_scan_table(target: str, target_scope: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    """Print results of targeted port connectivity scan."""
    scope_badge = f"[bold #ff2a5f]{target_scope['scope']}[/]" if target_scope.get("is_external") else f"[bold green]{target_scope['scope']}[/]"
    console.print(f"\n[bold #ff2a5f]TARGET:[/] [bold white]{target}[/]  |  [bold #ff2a5f]RESOLVED IP:[/] {target_scope.get('ip')}  |  [bold #ff2a5f]SCOPE:[/] {scope_badge} ({target_scope.get('description')})")

    table = Table(
        title="[bold #ff2a5f]PORT CONNECTIVITY OUTCOMES[/]",
        border_style=COLOR_CRIMSON_DARK,
        header_style=f"bold {COLOR_CRIMSON_BRIGHT}",
    )
    table.add_column("Port", justify="right", style="bold white", width=8)
    table.add_column("State", justify="center", width=16)
    table.add_column("Identified Service", style="#38bdf8", width=30)
    table.add_column("Latency (ms)", justify="right", style="dim", width=14)

    for r in results:
        status = r["status"]
        if status == "OPEN":
            status_style = "[bold white on #059669] OPEN [/]"
        elif "FILTERED" in status or status == "TIMEOUT":
            status_style = "[bold black on #f59e0b] FILTERED [/]"
        else:
            status_style = "[dim]CLOSED[/]"

        lat_str = f"{r['latency_ms']:.1f} ms" if r["latency_ms"] is not None else "-"
        table.add_row(str(r["port"]), status_style, r["service"], lat_str)

    console.print(table)


def display_fim_comparison(result: FimComparisonResult) -> None:
    """Display file integrity comparison findings."""
    print_section_header("FILE INTEGRITY COMPARISON RESULTS", f"Root: {result.root_path}")
    console.print(f"[dim]Baseline Timestamp:[/] [bold white]{result.baseline_timestamp}[/]  |  [dim]Comparison Timestamp:[/] [bold white]{result.scan_timestamp}[/]\n")

    summary_table = Table(border_style=COLOR_CRIMSON_DARK)
    summary_table.add_column("Integrity Status", style="bold #ff2a5f")
    summary_table.add_column("Count", justify="right", style="bold white")

    summary_table.add_row("Unchanged Files", f"[green]{result.unchanged_count}[/]")
    summary_table.add_row("New Files Detected", f"[bold cyan]{len(result.new_files)}[/]" if result.new_files else "0")
    summary_table.add_row("Modified Files Detected", f"[bold red]{len(result.modified_files)}[/]" if result.modified_files else "0")
    summary_table.add_row("Missing Files (Deleted)", f"[bold yellow]{len(result.missing_files)}[/]" if result.missing_files else "0")
    summary_table.add_row("Read Errors", f"[red]{len(result.errors)}[/]" if result.errors else "0")
    console.print(summary_table)

    if result.modified_files:
        console.print("\n[bold red]>> MODIFIED FILES DETECTED (Cryptographic Hash Mismatch):[/]")
        mod_table = Table(border_style="#dc2626")
        mod_table.add_column("File Path", style="bold white")
        mod_table.add_column("Baseline SHA-256", style="dim")
        mod_table.add_column("Current SHA-256", style="bold red")
        for m in result.modified_files:
            mod_table.add_row(m["path"], m["old_hash"][:16] + "...", m["new_hash"][:16] + "...")
        console.print(mod_table)

    if result.new_files:
        console.print("\n[bold cyan]>> NEW FILES INTRODUCED (Not in Baseline):[/]")
        for nf in result.new_files[:20]:
            console.print(f"  [cyan]+ {nf}[/]")
        if len(result.new_files) > 20:
            console.print(f"  [dim]... and {len(result.new_files) - 20} more new files[/]")

    if result.missing_files:
        console.print("\n[bold yellow]>> MISSING / DELETED FILES (Present in Baseline, absent now):[/]")
        for mf in result.missing_files[:20]:
            console.print(f"  [yellow]- {mf}[/]")
        if len(result.missing_files) > 20:
            console.print(f"  [dim]... and {len(result.missing_files) - 20} more missing files[/]")


def display_reports_table(reports: List[Dict[str, Any]]) -> None:
    """Print available generated reports."""
    if not reports:
        console.print("[dim]No generated reports found in reports/ directory.[/]")
        return

    table = Table(
        title="[bold #ff2a5f]AVAILABLE SECURITY REPORTS[/]",
        border_style=COLOR_CRIMSON_DARK,
        header_style=f"bold {COLOR_CRIMSON_BRIGHT}",
    )
    table.add_column("#", justify="right", width=4)
    table.add_column("Format", justify="center", width=8)
    table.add_column("Report Filename", style="bold white")
    table.add_column("Size (KB)", justify="right", width=10)
    table.add_column("Generated At", style="dim", width=20)

    for idx, r in enumerate(reports, 1):
        fmt_badge = "[bold cyan]HTML[/]" if r["type"] == "HTML" else "[bold yellow]JSON[/]"
        table.add_row(str(idx), fmt_badge, r["filename"], str(r["size_kb"]), r["created_at"])

    console.print(table)


def prompt_confirmation(prompt_text: str, default: bool = False) -> bool:
    """Ask for explicit user confirmation with default fallback."""
    opts = "[y/N]" if not default else "[Y/n]"
    console.print(f"[bold #f59e0b][!]  {prompt_text}[/] {opts}: ", end="")
    try:
        resp = input().strip().lower()
        if not resp:
            return default
        return resp in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False
