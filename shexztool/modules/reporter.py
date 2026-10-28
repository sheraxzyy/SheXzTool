"""Security Reporting Module for SheXzTool.

Attributed to developer brand: SheRaXzy Sentinel.
Generates polished, escaped, audit-ready HTML and JSON security reports.
"""

from __future__ import annotations
import datetime
import html
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from shexztool.core.models import Finding, FimComparisonResult, ScanResult, Severity
from shexztool.core.validator import Validator

logger = logging.getLogger("shexztool.reporter")


class SecurityReporter:
    """Exports structured vulnerability and integrity assessments into JSON and HTML formats."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or (Path(__file__).resolve().parent.parent.parent / "reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_scan_json(self, scan_result: ScanResult, filename: Optional[str] = None) -> Path:
        """Export ScanResult to formatted JSON file."""
        ts_clean = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = Validator.sanitize_filename(scan_result.scan_type.lower())
        fname = filename or f"{prefix}_{ts_clean}.json"
        dest_path = self.output_dir / fname

        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(scan_result.to_json(indent=2))

        logger.info("JSON report written: %s", dest_path)
        return dest_path

    def export_fim_json(self, fim_result: FimComparisonResult, filename: Optional[str] = None) -> Path:
        """Export FIM comparison to JSON file."""
        ts_clean = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = filename or f"fim_comparison_{ts_clean}.json"
        dest_path = self.output_dir / fname

        with open(dest_path, "w", encoding="utf-8") as f:
            json.dump(fim_result.to_dict(), f, indent=2)

        logger.info("FIM JSON report written: %s", dest_path)
        return dest_path

    def export_scan_html(self, scan_result: ScanResult, filename: Optional[str] = None) -> Path:
        """Generate a sleek, futuristic black-and-crimson cybersecurity HTML report.

        All untrusted strings are explicitly escaped using html.escape().
        """
        ts_clean = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = Validator.sanitize_filename(scan_result.scan_type.lower())
        fname = filename or f"{prefix}_{ts_clean}.html"
        dest_path = self.output_dir / fname

        counts = scan_result.severity_counts
        sys_info = scan_result.system_info

        # Render cards for findings
        findings_html = []
        if not scan_result.findings:
            findings_html.append("""
            <div class="empty-state">
                <div class="empty-icon">✓</div>
                <h3>No Security Risks Detected</h3>
                <p>All evaluated policies and interfaces met the baseline security criteria.</p>
            </div>
            """)
        else:
            for idx, f in enumerate(scan_result.findings, 1):
                sev_class = f.severity.value.lower()
                evidence_block = ""
                if f.evidence:
                    evidence_block = f"""
                    <div class="evidence-box">
                        <strong>Observed Evidence:</strong>
                        <pre><code>{html.escape(f.evidence)}</code></pre>
                    </div>
                    """
                
                remediation_block = ""
                if f.remediation:
                    remediation_block = f"""
                    <div class="remediation-box">
                        <span class="rem-title">Remediation Guidance:</span>
                        <p>{html.escape(f.remediation)}</p>
                    </div>
                    """

                refs_block = ""
                if f.references:
                    safe_links = "".join([f'<li><a href="{html.escape(r)}" target="_blank" rel="noopener">{html.escape(r)}</a></li>' for r in f.references])
                    refs_block = f"""
                    <div class="refs-box">
                        <span class="ref-title">References & Documentation:</span>
                        <ul>{safe_links}</ul>
                    </div>
                    """

                findings_html.append(f"""
                <div class="finding-card border-{sev_class}">
                    <div class="finding-header">
                        <div class="finding-title-group">
                            <span class="finding-id">#{idx:02d} [{html.escape(f.id)}]</span>
                            <h3 class="finding-title">{html.escape(f.title)}</h3>
                            <span class="finding-category">{html.escape(f.category)}</span>
                        </div>
                        <span class="badge badge-{sev_class}">{html.escape(f.severity.value)}</span>
                    </div>
                    <div class="finding-body">
                        <p class="finding-desc">{html.escape(f.description)}</p>
                        {evidence_block}
                        {remediation_block}
                        {refs_block}
                    </div>
                </div>
                """)

        # Render Limitations
        limitations_html = ""
        if scan_result.limitations:
            items = "".join([f"<li>{html.escape(lim)}</li>" for lim in scan_result.limitations])
            limitations_html = f"""
            <div class="limitations-container">
                <h4>Diagnostic Scope & Limitations</h4>
                <ul>{items}</ul>
            </div>
            """

        # System info items
        sys_rows = []
        for k, v in sys_info.items():
            sys_rows.append(f"""
            <div class="sys-item">
                <span class="sys-key">{html.escape(str(k).replace('_', ' ').title())}</span>
                <span class="sys-val">{html.escape(str(v))}</span>
            </div>
            """)

        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SheXzTool Audit Report - {html.escape(scan_result.scan_type)}</title>
    <style>
        :root {{
            --bg-base: #0a0a0d;
            --bg-surface: #121217;
            --bg-card: #181820;
            --bg-card-hover: #1f1f2a;
            --border-dim: #272733;
            --crimson-bright: #ff2a5f;
            --crimson: #e11d48;
            --crimson-dark: #881337;
            --crimson-glow: rgba(225, 29, 72, 0.25);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --badge-critical: #be123c;
            --badge-high: #e11d48;
            --badge-medium: #f59e0b;
            --badge-low: #06b6d4;
            --badge-info: #475569;
            --badge-pass: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        /* Header */
        .header {{
            background: linear-gradient(135deg, #161118 0%, #1a101b 100%);
            border: 1px solid var(--crimson-dark);
            border-top: 4px solid var(--crimson);
            border-radius: 8px;
            padding: 24px 30px;
            margin-bottom: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px var(--crimson-glow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--crimson-bright);
            text-transform: uppercase;
        }}
        .brand-subtitle {{
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 500;
            margin-top: 4px;
        }}
        .report-meta {{
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .report-meta strong {{
            color: var(--text-main);
        }}
        /* Stats Summary Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 28px;
            font-weight: 700;
            line-height: 1.1;
        }}
        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-top: 6px;
        }}
        /* System Info Grid */
        .sys-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            color: var(--crimson-bright);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .sys-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
        }}
        .sys-item {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 4px;
            padding: 10px 14px;
            display: flex;
            flex-direction: column;
        }}
        .sys-key {{
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
        }}
        .sys-val {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-main);
            margin-top: 2px;
            word-break: break-word;
        }}
        /* Findings Cards */
        .finding-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-dim);
            border-left: 4px solid var(--border-dim);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 16px;
            transition: transform 0.15s ease;
        }}
        .finding-card:hover {{
            background: var(--bg-card-hover);
        }}
        .border-critical {{ border-left-color: var(--badge-critical) !important; }}
        .border-high {{ border-left-color: var(--badge-high) !important; }}
        .border-medium {{ border-left-color: var(--badge-medium) !important; }}
        .border-low {{ border-left-color: var(--badge-low) !important; }}
        .border-info {{ border-left-color: var(--badge-info) !important; }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 15px;
            margin-bottom: 12px;
        }}
        .finding-id {{
            font-size: 11px;
            font-family: monospace;
            color: var(--text-muted);
            margin-right: 6px;
        }}
        .finding-title {{
            font-size: 17px;
            font-weight: 700;
            color: #ffffff;
            display: inline;
        }}
        .finding-category {{
            display: block;
            font-size: 12px;
            color: var(--crimson-bright);
            margin-top: 4px;
            font-weight: 600;
        }}
        .finding-desc {{
            font-size: 14px;
            color: #cbd5e1;
            margin-bottom: 14px;
        }}
        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-radius: 4px;
            white-space: nowrap;
        }}
        .badge-critical {{ background: var(--badge-critical); color: #fff; }}
        .badge-high {{ background: var(--badge-high); color: #fff; }}
        .badge-medium {{ background: var(--badge-medium); color: #000; }}
        .badge-low {{ background: var(--badge-low); color: #000; }}
        .badge-info {{ background: var(--badge-info); color: #fff; }}
        
        .evidence-box {{
            background: #09090c;
            border: 1px solid #23232d;
            border-radius: 4px;
            padding: 10px 14px;
            margin-bottom: 12px;
            font-size: 13px;
        }}
        .evidence-box strong {{
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            display: block;
            margin-bottom: 4px;
        }}
        .evidence-box code {{
            font-family: "Cascadia Code", Consolas, Monaco, monospace;
            color: #38bdf8;
            font-size: 12px;
            white-space: pre-wrap;
        }}
        .remediation-box {{
            background: rgba(225, 29, 72, 0.08);
            border-left: 3px solid var(--crimson);
            border-radius: 0 4px 4px 0;
            padding: 12px 14px;
            margin-bottom: 10px;
        }}
        .rem-title {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--crimson-bright);
            display: block;
            margin-bottom: 4px;
        }}
        .remediation-box p {{
            font-size: 13px;
            color: #e2e8f0;
        }}
        .refs-box {{
            font-size: 12px;
            margin-top: 8px;
            padding-left: 5px;
        }}
        .ref-title {{
            color: var(--text-muted);
            font-weight: 600;
            display: block;
            margin-bottom: 2px;
        }}
        .refs-box a {{
            color: #38bdf8;
            text-decoration: none;
        }}
        .refs-box a:hover {{
            text-decoration: underline;
        }}
        /* Limitations */
        .limitations-container {{
            background: #15151e;
            border: 1px dashed #3f3f50;
            border-radius: 6px;
            padding: 16px 20px;
            margin-top: 25px;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .limitations-container h4 {{
            color: #fbbf24;
            font-size: 13px;
            margin-bottom: 6px;
            text-transform: uppercase;
        }}
        .limitations-container ul {{
            padding-left: 20px;
        }}
        /* Footer */
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 40px;
            border-top: 1px solid var(--border-dim);
            padding-top: 20px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .header {{ background: #eee; border: 1px solid #ccc; }}
            .finding-card {{ border: 1px solid #ccc; page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Brand Header -->
        <header class="header">
            <div>
                <div class="brand-title">SheXzTool // Security Audit</div>
                <div class="brand-subtitle">Developer Brand: SheRaXzy Sentinel • Defensive Cybersecurity Suite</div>
            </div>
            <div class="report-meta">
                <div>Scan Type: <strong>{html.escape(scan_result.scan_type)}</strong></div>
                <div>Generated: <strong>{html.escape(scan_result.timestamp)}</strong></div>
                <div>Hostname: <strong>{html.escape(str(sys_info.get("hostname", "Unknown")))}</strong></div>
            </div>
        </header>

        <!-- Stats Overview -->
        <section class="stats-grid">
            <div class="stat-card" style="border-top: 3px solid var(--badge-critical);">
                <div class="stat-num" style="color: var(--badge-critical);">{counts.get("CRITICAL", 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid var(--badge-high);">
                <div class="stat-num" style="color: var(--badge-high);">{counts.get("HIGH", 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid var(--badge-medium);">
                <div class="stat-num" style="color: var(--badge-medium);">{counts.get("MEDIUM", 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid var(--badge-low);">
                <div class="stat-num" style="color: var(--badge-low);">{counts.get("LOW", 0)}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid var(--badge-info);">
                <div class="stat-num" style="color: var(--text-muted);">{counts.get("INFO", 0)}</div>
                <div class="stat-label">Informational</div>
            </div>
        </section>

        <!-- System & Context Profile -->
        <section class="sys-card">
            <h3 class="section-title">Target Environment Specification</h3>
            <div class="sys-grid">
                {''.join(sys_rows)}
            </div>
        </section>

        <!-- Audit Findings -->
        <section>
            <h3 class="section-title">Security Findings & Observations ({len(scan_result.findings)})</h3>
            {''.join(findings_html)}
        </section>

        <!-- Limitations & Scope -->
        {limitations_html}

        <!-- Footer -->
        <footer class="footer">
            <p>Generated by <strong>SheXzTool</strong> (SheRaXzy Sentinel) • Read-only Defensive Security Utility.</p>
            <p>This assessment represents the configuration state observed at scan time and does not guarantee complete absence of vulnerabilities.</p>
        </footer>
    </div>
</body>
</html>
"""
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(full_html)

        logger.info("HTML report written: %s", dest_path)
        return dest_path

    def list_reports(self) -> List[Dict[str, Any]]:
        """List generated reports in reports directory."""
        items: List[Dict[str, Any]] = []
        if not self.output_dir.exists():
            return items

        for f in self.output_dir.iterdir():
            if f.suffix.lower() in (".html", ".json") and f.name != ".gitkeep":
                try:
                    stat = f.stat()
                    items.append({
                        "filename": f.name,
                        "path": str(f),
                        "type": "HTML" if f.suffix.lower() == ".html" else "JSON",
                        "size_kb": round(stat.st_size / 1024, 1),
                        "created_at": datetime.datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except Exception as e:
                    logger.debug("Failed reading report file stat %s: %s", f, e)

        items.sort(key=lambda x: x["created_at"], reverse=True)
        return items
