"""
Report generation: terminal, JSON, and HTML output.

This is the presentation layer — it consumes the results dict
from scanner.scan() and renders it in multiple formats.
"""
import json
import html as html_module
from datetime import datetime, timezone
from typing import Dict, List
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

SEVERITY_EXPLANATIONS = {
    "CRITICAL": "Attacker can fully override model behavior, exfiltrate secrets, or execute arbitrary tool calls",
    "HIGH": "Attacker can influence model output or leak internal configuration details",
    "MEDIUM": "Partial information leakage or partial instruction bypass detected",
    "LOW": "Minor signals present; exploitability requires significant additional access",
    "INFO": "Informational finding; not directly exploitable",
}


class Reporter:
    """Multi-format report generator."""

    def print_terminal(self, results: Dict, console: Console, skip_vuln_table: bool = False):
        """Premium minimal terminal report."""
        summary     = results.get("summary", {})
        by_sev      = summary.get("by_severity", {})
        cats        = summary.get("finding_categories", {})
        risk        = summary.get("risk_score", 0)
        cost        = summary.get("total_cost", 0)
        total_run   = summary.get("total_attacks_run", 0)
        total_vulns = summary.get("total_vulnerabilities", 0)
        mode        = summary.get("mode", "standard")

        risk_color = "bold red" if risk >= 60 else "yellow" if risk >= 30 else "bold green"
        div = "  " + "━" * 46

        console.print()
        console.print(div)
        console.print(f"  🚨  [{risk_color}]Risk Score   {risk} / 100[/{risk_color}]")
        console.print(div)
        console.print()

        # Aligned severity counts
        crit = by_sev.get("CRITICAL", 0)
        high = by_sev.get("HIGH", 0)
        med  = by_sev.get("MEDIUM", 0)
        safe = total_run - total_vulns
        if crit: console.print(f"  [bold red]{'Critical':<12}  {crit}[/bold red]")
        if high: console.print(f"  [yellow]{'High':<12}  {high}[/yellow]")
        if med:  console.print(f"  [yellow]{'Medium':<12}  {med}[/yellow]")
        console.print(f"  [dim]{'Safe':<12}  {safe}[/dim]")
        console.print()

        # Top Issues (non-zero categories only, max 3)
        issues = [
            ("Prompt Injection",   cats.get("Prompt Injection", 0)),
            ("Data Leakage",       cats.get("Data Leakage", 0)),
            ("Error Disclosure",   cats.get("Error Disclosure", 0)),
            ("System Fingerprint", cats.get("System Fingerprinting", 0)),
        ]
        issues = [(k, v) for k, v in issues if v > 0][:3]
        if issues:
            console.print("  [dim]Top Issues[/dim]")
            for k, v in issues:
                console.print(f"  [cyan]•[/cyan] [dim]{k:<22}[/dim]  ({v})")
            console.print()

        console.print(f"  [dim]Cost: ${cost:.4f}   •   {total_run} attacks[/dim]")
        console.print()
        console.print(div)

        # ONE insight — template-based from dominant category
        pi = cats.get("Prompt Injection", 0)
        dl = cats.get("Data Leakage", 0)
        ed = cats.get("Error Disclosure", 0)
        sf = cats.get("System Fingerprinting", 0)
        if total_vulns == 0:
            insight = "No significant vulnerabilities detected across the attack surface."
        elif pi and pi >= max(dl, ed, sf):
            insight = "Model is vulnerable to prompt injection due to weak instruction isolation."
        elif dl and dl >= max(pi, ed, sf):
            insight = "System prompt and internal data are exposed through targeted probing."
        elif ed > 0:
            insight = "Backend errors are leaking implementation details in model responses."
        else:
            insight = "Provider and infrastructure signals are visible in model output."

        console.print()
        console.print("  [dim]💡 Insight[/dim]")
        console.print(f"  [dim]{insight}[/dim]")
        console.print()

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
        risk_label = (
            "CRITICAL RISK" if risk >= 80
            else "HIGH RISK" if risk >= 60
            else "MEDIUM RISK" if risk >= 30
            else "LOW RISK" if risk > 0
            else "SECURE"
        )

        vuln_rows = ""
        for v in sorted(vulns, key=lambda x: _severity_rank(x["severity"])):
            sev_color = {
                "CRITICAL": "#e74c3c", "HIGH": "#e67e22",
                "MEDIUM": "#f1c40f", "LOW": "#3498db"
            }.get(v["severity"], "#95a5a6")
            sev_explain = SEVERITY_EXPLANATIONS.get(v["severity"], "")
            evidence_html = _build_evidence_html(v)
            vuln_rows += f"""
            <tr>
                <td class="attack-name">{html_module.escape(v['attack_name'])}</td>
                <td>
                    <span class="sev-badge" style="background:{sev_color}" title="{html_module.escape(sev_explain)}">
                        {v['severity']}
                    </span>
                    <div class="sev-explain">{html_module.escape(sev_explain)}</div>
                </td>
                <td>
                    <div class="rate-bar-wrap">
                        <div class="rate-bar" style="width:{int(v['success_rate']*100)}%;background:{sev_color}"></div>
                        <span class="rate-text">{v['success_rate']:.0%}</span>
                    </div>
                </td>
                <td>{html_module.escape(v.get('category', 'N/A'))}</td>
                <td class="remediation">{html_module.escape(v.get('remediation', 'N/A'))}</td>
            </tr>
            {evidence_html}"""

        by_sev = summary.get("by_severity", {})
        sev_str = ", ".join(f"{count} {sev}" for sev, count in by_sev.items()) if by_sev else "None"
        finding_categories = summary.get("finding_categories", {})
        categories_html = "".join(
            f"<li><strong>{name}:</strong> {finding_categories.get(name, 0)}</li>"
            for name in ("Prompt Injection", "Data Leakage", "Error Disclosure", "System Fingerprinting")
        )

        attack_graph_html = _build_attack_graph(vulns)

        if not vulns:
            vuln_section = '<p style="color:#2ecc71;font-size:1.1em">&#10003; No vulnerabilities found.</p>'
        else:
            vuln_section = f"""
            <table>
            <colgroup>
                <col style="width:22%">
                <col style="width:18%">
                <col style="width:12%">
                <col style="width:16%">
                <col style="width:32%">
            </colgroup>
            <tr><th>Attack</th><th>Severity</th><th>Success Rate</th><th>Category</th><th>Remediation</th></tr>
            {vuln_rows}
            </table>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vektor Security Report</title>
<style>
  :root {{
    --bg: #0f0f1a;
    --surface: #16213e;
    --surface2: #1a1a2e;
    --accent: #00d4ff;
    --accent2: #7b61ff;
    --text: #e8e8f0;
    --muted: #888;
    --border: #2a2a4a;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    max-width: 980px; margin: 40px auto; padding: 0 24px;
    background: var(--bg); color: var(--text); line-height: 1.5;
  }}
  h1 {{ color: var(--accent); font-size: 1.8em; margin-bottom: 4px; letter-spacing: -0.5px; }}
  h2 {{ color: var(--accent); font-size: 1.2em; margin: 28px 0 12px; }}
  .meta {{ color: var(--muted); font-size: 0.82em; margin-bottom: 20px; }}

  /* Risk badge */
  .risk-badge {{
    display: inline-flex; align-items: center; gap: 12px;
    padding: 14px 24px; border-radius: 10px; margin-bottom: 16px;
    background: {risk_color}22; border: 2px solid {risk_color};
  }}
  .risk-score {{ font-size: 2.2em; font-weight: 800; color: {risk_color}; }}
  .risk-label {{ font-size: 1em; font-weight: 600; color: {risk_color}; opacity: 0.9; }}

  /* Summary */
  .summary {{
    background: var(--surface); padding: 20px; border-radius: 10px;
    margin-bottom: 24px; border: 1px solid var(--border);
  }}
  .summary p {{ margin: 6px 0; font-size: 0.92em; }}
  .summary ul {{ margin: 6px 0 0 18px; font-size: 0.92em; }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; margin: 0; font-size: 0.88em; }}
  th {{
    background: var(--surface); color: var(--accent);
    padding: 11px 12px; text-align: left; font-weight: 600;
    border-bottom: 2px solid var(--border);
  }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover > td {{ background: var(--surface); }}
  tr.evidence-row > td {{ background: #0d1a2d; padding: 0; }}
  .attack-name {{ font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 0.9em; color: #c8d0e0; }}

  /* Severity badge */
  .sev-badge {{
    display: inline-block; padding: 3px 9px; border-radius: 4px;
    font-size: 0.78em; font-weight: 700; color: #fff; cursor: help;
    letter-spacing: 0.5px;
  }}
  .sev-explain {{
    font-size: 0.75em; color: var(--muted); margin-top: 4px; line-height: 1.3;
  }}

  /* Rate bar */
  .rate-bar-wrap {{ display: flex; align-items: center; gap: 8px; }}
  .rate-bar {{ height: 6px; border-radius: 3px; min-width: 2px; opacity: 0.8; }}
  .rate-text {{ font-size: 0.85em; font-weight: 600; white-space: nowrap; }}

  /* Remediation */
  .remediation {{ font-size: 0.82em; color: #aab; line-height: 1.4; }}

  /* Evidence panel */
  .evidence-panel {{
    border-left: 3px solid var(--accent2);
    margin: 0; padding: 12px 16px;
    background: #0d1a2d;
  }}
  .evidence-panel summary {{
    cursor: pointer; color: var(--accent2); font-size: 0.82em;
    font-weight: 600; list-style: none; padding: 2px 0;
  }}
  .evidence-panel summary::before {{ content: '▶  '; font-size: 0.8em; }}
  .evidence-panel[open] summary::before {{ content: '▼  '; }}
  .evidence-panel summary:hover {{ color: var(--accent); }}
  .evidence-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px; }}
  .evidence-box {{ background: #091525; border-radius: 6px; padding: 10px; }}
  .evidence-box label {{
    display: block; font-size: 0.72em; font-weight: 700;
    color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;
  }}
  .evidence-box pre {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.78em; color: #c8d8f0; white-space: pre-wrap;
    word-break: break-word; line-height: 1.45; max-height: 120px; overflow-y: auto;
  }}

  /* Attack graph */
  .attack-graph {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px; margin-bottom: 24px;
  }}
  .graph-title {{ color: var(--accent2); font-size: 0.8em; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }}
  .graph-chain {{
    display: flex; align-items: center; flex-wrap: wrap; gap: 0;
  }}
  .graph-node {{
    background: #0f1f35; border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 14px; min-width: 120px;
    text-align: center; position: relative;
  }}
  .graph-node.hit {{ border-color: #e74c3c; background: #1a0a0a; }}
  .graph-node.medium {{ border-color: #f1c40f; background: #1a1600; }}
  .graph-node.low {{ border-color: #3498db; background: #0a1520; }}
  .graph-node .node-label {{ font-size: 0.72em; color: var(--muted); margin-bottom: 3px; }}
  .graph-node .node-name {{ font-size: 0.82em; font-weight: 600; }}
  .graph-node.hit .node-name {{ color: #ff6b6b; }}
  .graph-node.medium .node-name {{ color: #f1c40f; }}
  .graph-node.low .node-name {{ color: #74b9ff; }}
  .graph-arrow {{
    font-size: 1.3em; color: var(--border); padding: 0 6px;
    flex-shrink: 0; align-self: center;
  }}
  .graph-arrow.active {{ color: #e74c3c; }}
  .graph-legend {{
    display: flex; gap: 16px; margin-top: 14px; flex-wrap: wrap;
  }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.77em; color: var(--muted); }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}

  /* Footer */
  hr {{ border: none; border-top: 1px solid var(--border); margin: 28px 0 16px; }}
  .footer {{ color: var(--muted); font-size: 0.8em; }}
  .footer a {{ color: var(--accent); text-decoration: none; }}
  .footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>&#x1F6E1; vektor Security Report</h1>
<p class="meta">
  Target: <strong>{html_module.escape(results.get('target', 'N/A'))}</strong>
  &nbsp;|&nbsp; Model: <strong>{html_module.escape(str(results.get('model', 'N/A')))}</strong>
  &nbsp;|&nbsp; Generated: {html_module.escape(results.get('timestamp', datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')))}
</p>

<div class="summary">
  <div class="risk-badge">
    <span class="risk-score">{risk}/100</span>
    <span class="risk-label">{risk_label}</span>
  </div>
  <p><strong>Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)} ({html_module.escape(sev_str)})</p>
  <p><strong>Attacks Run:</strong> {summary.get('total_attacks_run', 0)} &nbsp;|&nbsp; <strong>Cost:</strong> ${summary.get('total_cost', 0):.4f} &nbsp;|&nbsp; <strong>Mode:</strong> {html_module.escape(summary.get('mode', 'standard'))}</p>
  <p style="margin-top:10px"><strong>Finding Categories:</strong></p>
  <ul>{categories_html}</ul>
  <p style="margin-top:10px"><strong>Recommendation:</strong> {html_module.escape(summary.get('recommendation', 'N/A'))}</p>
</div>

{attack_graph_html}

<h2>Vulnerabilities</h2>
{vuln_section}

<hr>
<p class="footer">Generated by <strong>vektor</strong> &nbsp;|&nbsp; <a href="https://github.com/swapnilwankhede23/vektor-lite">GitHub</a></p>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_evidence_html(vuln: Dict) -> str:
    """Build a collapsible evidence row showing the first payload + model response."""
    details = vuln.get("details") or {}
    test_results = details.get("test_results") or []

    # Find first successful test case for evidence
    first_hit = None
    for tr in test_results:
        if tr.get("vulnerable") or tr.get("is_vulnerable"):
            first_hit = tr
            break
    if first_hit is None and test_results:
        first_hit = test_results[0]
    if first_hit is None:
        return ""

    prompt = first_hit.get("prompt") or first_hit.get("turn2") or ""
    response = first_hit.get("response") or ""
    if not prompt and not response:
        return ""

    prompt_escaped = html_module.escape(str(prompt)[:400])
    response_escaped = html_module.escape(str(response)[:400])

    return f"""<tr class="evidence-row">
        <td colspan="5">
            <details class="evidence-panel">
                <summary>Evidence — payload &amp; model response</summary>
                <div class="evidence-grid">
                    <div class="evidence-box">
                        <label>Payload sent</label>
                        <pre>{prompt_escaped}</pre>
                    </div>
                    <div class="evidence-box">
                        <label>Model response</label>
                        <pre>{response_escaped}</pre>
                    </div>
                </div>
            </details>
        </td>
    </tr>"""


def _build_attack_graph(vulns: List[Dict]) -> str:
    """Build a visual attack chain diagram from found vulnerabilities."""
    if not vulns:
        return ""

    # Categorize findings
    categories = {v.get("category", "").lower() for v in vulns}
    severities = {v.get("attack_name", ""): v.get("severity", "INFO") for v in vulns}

    def _node_class(condition: bool, sev: str = "CRITICAL") -> str:
        if not condition:
            return ""
        return "hit" if sev in ("CRITICAL", "HIGH") else "medium" if sev == "MEDIUM" else "low"

    has_injection = any("prompt injection" in c or "instruction hijacking" in c for c in categories)
    has_system_leak = any("data extraction" in c for c in categories)
    has_tool_misuse = any("agent" in c or "tool" in c for c in categories)
    has_pii = any(v.get("attack_name", "").startswith("pii") for v in vulns)

    # Pick representative severity for each node
    injection_sev = next(
        (v["severity"] for v in vulns if "prompt injection" in v.get("category", "").lower()), "INFO"
    )
    data_sev = next(
        (v["severity"] for v in vulns if "data extraction" in v.get("category", "").lower()), "INFO"
    )

    arrow_class = lambda active: "active" if active else ""

    nodes_html = f"""
    <div class="graph-chain">
      <div class="graph-node">
        <div class="node-label">Entry Point</div>
        <div class="node-name">User Input</div>
      </div>
      <div class="graph-arrow {arrow_class(has_injection)}">&#x2192;</div>
      <div class="graph-node {_node_class(has_injection, injection_sev)}">
        <div class="node-label">Attack Surface</div>
        <div class="node-name">Prompt Injection</div>
      </div>
      <div class="graph-arrow {arrow_class(has_injection and has_system_leak)}">&#x2192;</div>
      <div class="graph-node {_node_class(has_system_leak, data_sev)}">
        <div class="node-label">Impact</div>
        <div class="node-name">System Prompt Exposure</div>
      </div>
      <div class="graph-arrow {arrow_class(has_tool_misuse)}">&#x2192;</div>
      <div class="graph-node {_node_class(has_tool_misuse)}">
        <div class="node-label">Escalation</div>
        <div class="node-name">Tool Misuse</div>
      </div>
      <div class="graph-arrow {arrow_class(has_pii)}">&#x2192;</div>
      <div class="graph-node {_node_class(has_pii)}">
        <div class="node-label">Outcome</div>
        <div class="node-name">PII Exfiltration</div>
      </div>
    </div>
    <div class="graph-legend">
      <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div>Confirmed CRITICAL/HIGH</div>
      <div class="legend-item"><div class="legend-dot" style="background:#f1c40f"></div>Confirmed MEDIUM</div>
      <div class="legend-item"><div class="legend-dot" style="background:#2a2a4a"></div>Not detected</div>
    </div>"""

    return f"""
<h2>Attack Graph</h2>
<div class="attack-graph">
  <div class="graph-title">Vulnerability propagation chain</div>
  {nodes_html}
</div>"""


def _severity_rank(severity: str) -> int:
    """Lower number = higher severity (for sorting)."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)
