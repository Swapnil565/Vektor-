"""
Report generation: terminal, JSON, and HTML output.

This is the presentation layer — it consumes the results dict
from scanner.scan() and renders it in multiple formats.
"""
import json
from datetime import datetime
from typing import Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


class Reporter:
    """Multi-format report generator."""

    def print_terminal(self, results: Dict, console: Console):
        """Rich terminal output — this is what people screenshot."""
        vulns = results.get("vulnerabilities", [])
        summary = results.get("summary", {})

        # Vulnerability table
        if vulns:
            table = Table(show_header=True, header_style="bold cyan", title="Vulnerabilities Found")
            table.add_column("Attack", min_width=30)
            table.add_column("Severity", justify="center", min_width=10)
            table.add_column("Success Rate", justify="right", min_width=12)

            for v in sorted(vulns, key=lambda x: _severity_rank(x["severity"])):
                color = SEVERITY_COLORS.get(v["severity"], "white")
                table.add_row(
                    v["attack_name"],
                    f"[{color}]{v['severity']}[/{color}]",
                    f"{v['success_rate']:.0%}",
                )
            console.print(table)
        else:
            console.print("[green]No vulnerabilities found![/green]")

        # Summary panel
        risk = summary.get("risk_score", 0)
        risk_color = "red" if risk >= 60 else "yellow" if risk >= 30 else "green"
        by_sev = summary.get("by_severity", {})
        sev_str = ", ".join(f"{count} {sev}" for sev, count in by_sev.items()) if by_sev else "None"
        cost = summary.get("total_cost", 0)
        total_run = summary.get("total_attacks_run", 0)
        recommendation = summary.get("recommendation", "")

        console.print(Panel(
            f"[bold]Risk Score: [{risk_color}]{risk}/100[/{risk_color}][/bold]\n"
            f"Vulnerabilities: {summary.get('total_vulnerabilities', 0)} ({sev_str})\n"
            f"Cost: ${cost:.4f}  |  Attacks Run: {total_run}\n\n"
            f"{recommendation}",
            title="Summary",
            border_style=risk_color,
        ))

    def save_json(self, results: Dict, output_path: str):
        """Save results as JSON."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

    def save_html(self, results: Dict, output_path: str):
        """Save results as a self-contained HTML report."""
        vulns = results.get("vulnerabilities", [])
        summary = results.get("summary", {})
        risk = summary.get("risk_score", 0)

        risk_color = "#e74c3c" if risk >= 60 else "#f39c12" if risk >= 30 else "#2ecc71"

        vuln_rows = ""
        for v in sorted(vulns, key=lambda x: _severity_rank(x["severity"])):
            sev_color = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#3498db"}.get(v["severity"], "#95a5a6")
            vuln_rows += f"""
            <tr>
                <td>{v['attack_name']}</td>
                <td><span style="color:{sev_color};font-weight:bold">{v['severity']}</span></td>
                <td>{v['success_rate']:.0%}</td>
                <td>{v.get('category', 'N/A')}</td>
                <td style="font-size:0.85em">{v.get('remediation', 'N/A')}</td>
            </tr>"""

        by_sev = summary.get("by_severity", {})
        sev_str = ", ".join(f"{count} {sev}" for sev, count in by_sev.items()) if by_sev else "None"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LLMGuard Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #1a1a2e; color: #eee; }}
  h1 {{ color: #00d4ff; }}
  .badge {{ display: inline-block; padding: 12px 24px; border-radius: 8px; font-size: 1.5em; font-weight: bold; color: white; background: {risk_color}; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th {{ background: #16213e; color: #00d4ff; padding: 12px; text-align: left; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #2a2a4a; }}
  tr:hover {{ background: #16213e; }}
  .summary {{ background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }}
  .meta {{ color: #888; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>LLMGuard Security Report</h1>
<p class="meta">Target: {results.get('target', 'N/A')} | Model: {results.get('model', 'N/A')} | Generated: {results.get('timestamp', datetime.utcnow().isoformat()+'Z')}</p>

<div class="summary">
  <div class="badge">{risk}/100</div>
  <p><strong>Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)} ({sev_str})</p>
  <p><strong>Attacks Run:</strong> {summary.get('total_attacks_run', 0)} | <strong>Cost:</strong> ${summary.get('total_cost', 0):.4f}</p>
  <p><strong>Recommendation:</strong> {summary.get('recommendation', 'N/A')}</p>
</div>

<h2>Vulnerabilities</h2>
{'<p style="color:#2ecc71">No vulnerabilities found.</p>' if not vulns else f"""
<table>
<tr><th>Attack</th><th>Severity</th><th>Success Rate</th><th>Category</th><th>Remediation</th></tr>
{vuln_rows}
</table>"""}

<hr style="border-color:#2a2a4a">
<p class="meta">Generated by LLMGuard-Lite v{results.get('model', '0.1.0')} | <a href="https://github.com/yourusername/llmguard-lite" style="color:#00d4ff">GitHub</a></p>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)


def _severity_rank(severity: str) -> int:
    """Lower number = higher severity (for sorting)."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)
