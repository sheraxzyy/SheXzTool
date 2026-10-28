"""Futuristic Black-and-Crimson Terminal Banner and Aesthetic Constants.

Developer Brand: SheRaXzy Sentinel
Toolkit: SheXzTool
"""

from rich.panel import Panel
from rich.text import Text
from rich.table import Table

# Crimson and Obsidian Color Palette Constants
COLOR_CRIMSON_BRIGHT = "#ff2a5f"
COLOR_CRIMSON = "#e11d48"
COLOR_CRIMSON_DARK = "#881337"
COLOR_OBSIDIAN = "#0f0f12"
COLOR_SLATE_DARK = "#1e1e24"
COLOR_TEXT_PRIMARY = "#f8fafc"
COLOR_TEXT_MUTED = "#94a3b8"
COLOR_ACCENT_CYAN = "#06b6d4"
COLOR_ACCENT_GREEN = "#10b981"
COLOR_ACCENT_AMBER = "#f59e0b"

BANNER_ASCII = r"""
 [bold #ff2a5f] ███████╗██╗  ██╗███████╗██╗  ██╗███████╗████████╗ ██████╗  ██████╗ ██╗     [/]
 [bold #e11d48] ██╔════╝██║  ██║██╔════╝╚██╗██╔╝╚══███╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     [/]
 [bold #be123c] ███████╗███████║█████╗   ╚███╔╝   ███╔╝    ██║   ██║   ██║██║   ██║██║     [/]
 [bold #9f1239] ╚════██║██╔══██║██╔══╝   ██╔██╗  ███╔╝     ██║   ██║   ██║██║   ██║██║     [/]
 [bold #881337] ███████║██║  ██║███████╗██╔╝ ██╗███████╗   ██║   ╚██████╔╝╚██████╔╝███████╗[/]
 [bold #4c0519] ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝[/]
"""

BRAND_SUBTITLE = "[bold #f8fafc]S h e R a X z y   S e n t i n e l[/] [dim]|[/] [bold #ff2a5f]DEFENSIVE CYBERSECURITY TOOLKIT v1.0[/]"
BRAND_TAGLINE = "[dim #94a3b8]Ethical Reconnaissance | Local Security Auditing | Process & File Integrity[/]"


def get_banner_panel(user_info: str = "", elevated: bool = False) -> Panel:
    """Build a styled Rich Panel containing the brand ASCII header and status."""
    content = Text.from_markup(f"{BANNER_ASCII}\n{BRAND_SUBTITLE}\n{BRAND_TAGLINE}\n")
    
    status_markup = (
        f"[bold #10b981][*] SYSTEM ACTIVE[/]  "
        f"[dim]|[/]  User: [bold #f8fafc]{user_info or 'Unknown'}[/]  "
        f"[dim]|[/]  Privilege: "
        + ("[bold #ff2a5f][*] ELEVATED (Admin)[/]" if elevated else "[bold #f59e0b][o] STANDARD (User)[/]")
    )
    content.append("\n")
    content.append_text(Text.from_markup(status_markup))

    return Panel(
        content,
        border_style=COLOR_CRIMSON,
        padding=(0, 2),
        style=f"on {COLOR_OBSIDIAN}",
        subtitle="[bold #94a3b8]SheRaXzy Cyber Defense Framework[/]",
        subtitle_align="right",
    )


def format_severity_badge(severity: str) -> str:
    """Return a styled severity badge for console outputs."""
    s = severity.upper()
    if s == "CRITICAL":
        return f"[bold white on #be123c] CRITICAL [/]"
    elif s == "HIGH":
        return f"[bold white on #e11d48] HIGH [/]"
    elif s == "MEDIUM":
        return f"[bold black on #f59e0b] MEDIUM [/]"
    elif s == "LOW":
        return f"[bold black on #06b6d4] LOW [/]"
    elif s == "INFO":
        return f"[bold white on #334155] INFO [/]"
    elif s in ("PASS", "SECURE", "OK"):
        return f"[bold white on #059669] {s} [/]"
    elif s in ("FAIL", "VULNERABLE", "RISK"):
        return f"[bold white on #dc2626] {s} [/]"
    return f"[bold white on #475569] {s} [/]"
