"""
vektor/core/diff.py — Compare two Vektor scan reports and highlight regressions.

Python API::

    from vektor.core.diff import diff_reports, print_diff_table, has_regression
    diffs  = diff_reports("scan_v1.json", "scan_v2.json")
    print_diff_table(diffs, "scan_v1.json", "scan_v2.json")
    if has_regression(diffs):
        raise SystemExit(1)

CLI::

    vektor diff scan_v1.json scan_v2.json
    vektor diff scan_v1.json scan_v2.json --output diff.json
    vektor diff scan_v1.json scan_v2.json --fail-on regression
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ── Severity ranking (higher = worse) ────────────────────────────────────────
_SEV_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

# ── Status constants ──────────────────────────────────────────────────────────
STATUS_NEW       = "new_vuln"    # attack was absent/INFO in v1, now present in v2
STATUS_FIXED     = "fixed"       # attack was present in v1, gone/INFO in v2
STATUS_REGRESSED = "regression"  # severity rank rose, or success_rate up >=5 pp
STATUS_IMPROVED  = "improved"    # severity rank fell, or success_rate down >=5 pp
STATUS_UNCHANGED = "unchanged"   # no meaningful change

# Sort priority for display (worst first)
_STATUS_ORDER = {
    STATUS_REGRESSED: 0,
    STATUS_NEW:       1,
    STATUS_FIXED:     2,
    STATUS_IMPROVED:  3,
    STATUS_UNCHANGED: 4,
}


@dataclass
class AttackDiff:
    """Comparison result for a single attack between two reports."""
    attack_name:  str
    category:     str
    status:       str
    old_severity: Optional[str]
    new_severity: Optional[str]
    old_rate:     Optional[float]
    new_rate:     Optional[float]

    @property
    def delta_rate(self) -> Optional[float]:
        if self.old_rate is not None and self.new_rate is not None:
            return self.new_rate - self.old_rate
        return None


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_report(path: str) -> Dict:
    """Load a Vektor JSON report file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _index_vulns(report: Dict) -> Dict[str, Dict]:
    """Return {attack_name: vuln_dict} from a report."""
    return {v["attack_name"]: v for v in report.get("vulnerabilities", [])}


# ── Core diff logic ───────────────────────────────────────────────────────────

def diff_reports(v1_path: str, v2_path: str) -> List[AttackDiff]:
    """Compare two Vektor scan reports and return a structured diff.

    A *regression* occurs when:

    * An attack that was absent / INFO in v1 now has a real severity in v2.
    * The severity rank increased (e.g. LOW → HIGH).
    * The success_rate increased by ≥ 5 percentage points at the same severity.

    Returns a list sorted by status priority (regressions first, unchanged last).
    """
    r1 = load_report(v1_path)
    r2 = load_report(v2_path)

    v1 = _index_vulns(r1)
    v2 = _index_vulns(r2)

    all_attacks = sorted(set(v1) | set(v2))
    diffs: List[AttackDiff] = []

    for attack in all_attacks:
        a1 = v1.get(attack)
        a2 = v2.get(attack)

        cat      = (a2 or a1).get("category", "Unknown")
        old_sev  = a1["severity"] if a1 else None
        new_sev  = a2["severity"] if a2 else None
        old_rate = float(a1["success_rate"]) if a1 else None
        new_rate = float(a2["success_rate"]) if a2 else None

        old_rank = _SEV_RANK.get(old_sev or "INFO", 0)
        new_rank = _SEV_RANK.get(new_sev or "INFO", 0)

        if a2 is None:
            # Disappeared from v2
            status = STATUS_FIXED if old_rank > 0 else STATUS_UNCHANGED
        elif a1 is None:
            # Brand-new in v2
            status = STATUS_NEW if new_rank > 0 else STATUS_UNCHANGED
        else:
            rate_delta = (new_rate or 0.0) - (old_rate or 0.0)
            if new_rank > old_rank:
                status = STATUS_REGRESSED
            elif new_rank < old_rank:
                status = STATUS_IMPROVED
            elif rate_delta >= 0.05:
                status = STATUS_REGRESSED
            elif rate_delta <= -0.05:
                status = STATUS_IMPROVED
            else:
                status = STATUS_UNCHANGED

        diffs.append(AttackDiff(
            attack_name  = attack,
            category     = cat,
            status       = status,
            old_severity = old_sev,
            new_severity = new_sev,
            old_rate     = old_rate,
            new_rate     = new_rate,
        ))

    diffs.sort(key=lambda d: (_STATUS_ORDER[d.status], d.attack_name))
    return diffs


def has_regression(diffs: List[AttackDiff]) -> bool:
    """Return True if any attack regressed or is a brand-new vulnerability."""
    return any(d.status in (STATUS_REGRESSED, STATUS_NEW) for d in diffs)


# ── Serialisation ─────────────────────────────────────────────────────────────

def to_dict(diffs: List[AttackDiff]) -> List[Dict]:
    """Convert diffs to a JSON-serialisable list."""
    return [
        {
            "attack_name":  d.attack_name,
            "category":     d.category,
            "status":       d.status,
            "old_severity": d.old_severity,
            "new_severity": d.new_severity,
            "old_rate":     d.old_rate,
            "new_rate":     d.new_rate,
            "delta_rate":   d.delta_rate,
        }
        for d in diffs
    ]


def save_diff_json(
    diffs: List[AttackDiff], v1_path: str, v2_path: str, output_path: str
) -> None:
    """Save diff results to a JSON file."""
    payload = {
        "v1":          str(v1_path),
        "v2":          str(v2_path),
        "regressions": has_regression(diffs),
        "diffs":       to_dict(diffs),
    }
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_diff_html(
    diffs: List[AttackDiff], v1_path: str, v2_path: str, output_path: str
) -> None:
    """Save diff results as a self-contained dark-themed HTML report."""
    _css_cls = {
        STATUS_REGRESSED: "regression",
        STATUS_NEW:       "new-vuln",
        STATUS_FIXED:     "fixed",
        STATUS_IMPROVED:  "improved",
        STATUS_UNCHANGED: "unchanged",
    }
    _labels = {
        STATUS_REGRESSED: "⬆ REGRESSION",
        STATUS_NEW:       "★ NEW VULN",
        STATUS_FIXED:     "✔ FIXED",
        STATUS_IMPROVED:  "↓ IMPROVED",
        STATUS_UNCHANGED: "— unchanged",
    }

    rows = []
    for d in diffs:
        delta = ""
        if d.delta_rate is not None:
            sign  = "+" if d.delta_rate >= 0 else ""
            delta = f"{sign}{d.delta_rate:.0%}"
        rows.append(
            f'<tr class="{_css_cls[d.status]}">'
            f"<td>{d.attack_name}</td>"
            f"<td>{d.category}</td>"
            f'<td class="sev">{d.old_severity or "—"}</td>'
            f'<td class="sev">{d.new_severity or "—"}</td>'
            f'<td class="rate">{f"{d.old_rate:.0%}" if d.old_rate is not None else "—"}</td>'
            f'<td class="rate">{f"{d.new_rate:.0%}" if d.new_rate is not None else "—"}</td>'
            f'<td class="rate">{delta}</td>'
            f"<td>{_labels[d.status]}</td>"
            "</tr>"
        )

    v1n  = Path(v1_path).name
    v2n  = Path(v2_path).name
    banner = (
        '<p class="banner bad">⚠ Regressions detected — review before deploying</p>'
        if has_regression(diffs)
        else '<p class="banner ok">✔ No regressions detected</p>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vektor Diff — {v1n} → {v2n}</title>
  <style>
    body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;margin:0;}}
    h1{{color:#58a6ff;margin-top:0;}}
    p.banner{{padding:.6rem 1.2rem;border-radius:.4rem;display:inline-block;font-weight:bold;margin-bottom:1rem;}}
    p.bad{{background:#3d1212;color:#ff7b72;}}
    p.ok{{background:#12301e;color:#3fb950;}}
    table{{border-collapse:collapse;width:100%;font-size:.9rem;}}
    th{{background:#161b22;color:#58a6ff;padding:.45rem .7rem;text-align:left;border-bottom:2px solid #30363d;white-space:nowrap;}}
    td{{padding:.35rem .7rem;border-bottom:1px solid #21262d;}}
    td.sev{{font-weight:bold;}}
    td.rate{{text-align:right;}}
    tr.regression td,tr.new-vuln td{{background:#3d1212;}}
    tr.regression td:last-child{{color:#ff7b72;font-weight:bold;}}
    tr.new-vuln td:last-child{{color:#ff7b72;font-weight:bold;}}
    tr.fixed td{{background:#12301e;}}
    tr.fixed td:last-child{{color:#3fb950;}}
    tr.improved td{{background:#0f2a1a;}}
    tr.improved td:last-child{{color:#3fb950;}}
    tr.unchanged td{{opacity:.45;}}
  </style>
</head>
<body>
  <h1>Vektor Diff Report</h1>
  <p style="color:#8b949e">{v1n} &rarr; {v2n}</p>
  {banner}
  <table>
    <thead>
      <tr>
        <th>Attack</th><th>Category</th>
        <th>Old Severity</th><th>New Severity</th>
        <th>Old Rate</th><th>New Rate</th><th>&Delta; Rate</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</body>
</html>"""
    Path(output_path).write_text(html, encoding="utf-8")


# ── Rich terminal output ───────────────────────────────────────────────────────

def print_diff_table(
    diffs: List[AttackDiff],
    v1_path: str = "v1",
    v2_path: str = "v2",
    console=None,
) -> None:
    """Render the diff as a Rich table in the terminal."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    if console is None:
        console = Console()

    _sev_color = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "INFO":     "dim",
    }
    _status_style = {
        STATUS_REGRESSED: "bold red",
        STATUS_NEW:       "bold red",
        STATUS_FIXED:     "bold green",
        STATUS_IMPROVED:  "green",
        STATUS_UNCHANGED: "dim",
    }
    _status_label = {
        STATUS_REGRESSED: "REGRESSION",
        STATUS_NEW:       "NEW VULN",
        STATUS_FIXED:     "FIXED",
        STATUS_IMPROVED:  "IMPROVED",
        STATUS_UNCHANGED: "unchanged",
    }

    def _sev(s: Optional[str]) -> str:
        if not s:
            return "[dim]—[/dim]"
        c = _sev_color.get(s, "white")
        return f"[{c}]{s}[/{c}]"

    def _rate(r: Optional[float]) -> str:
        return f"{r:.0%}" if r is not None else "[dim]—[/dim]"

    def _delta(d: AttackDiff) -> str:
        dr = d.delta_rate
        if dr is None:
            return ""
        sign = "+" if dr >= 0 else ""
        col  = "red" if dr > 0.001 else ("green" if dr < -0.001 else "dim")
        return f"[{col}]{sign}{dr:.0%}[/{col}]"

    v1n = Path(v1_path).name
    v2n = Path(v2_path).name

    table = Table(
        title=f"[bold]Vektor Diff[/bold]  [dim]{v1n}[/dim] -> [dim]{v2n}[/dim]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Attack",       style="bold white", no_wrap=True)
    table.add_column("Category",     style="dim",        no_wrap=True)
    table.add_column("Old Sev",      justify="center",   no_wrap=True)
    table.add_column("New Sev",      justify="center",   no_wrap=True)
    table.add_column("Old Rate",     justify="right",    no_wrap=True)
    table.add_column("New Rate",     justify="right",    no_wrap=True)
    table.add_column("Δ Rate",       justify="right",    no_wrap=True)
    table.add_column("Status",       justify="left",     no_wrap=True)

    for d in diffs:
        st = _status_style[d.status]
        table.add_row(
            d.attack_name,
            d.category,
            _sev(d.old_severity),
            _sev(d.new_severity),
            _rate(d.old_rate),
            _rate(d.new_rate),
            _delta(d),
            f"[{st}]{_status_label[d.status]}[/{st}]",
        )

    console.print(table)

    # Summary line
    counts = {s: sum(1 for d in diffs if d.status == s) for s in _STATUS_ORDER}
    parts  = []
    if counts[STATUS_REGRESSED]: parts.append(f"[bold red]{counts[STATUS_REGRESSED]} regression(s)[/bold red]")
    if counts[STATUS_NEW]:       parts.append(f"[bold red]{counts[STATUS_NEW]} new vuln(s)[/bold red]")
    if counts[STATUS_FIXED]:     parts.append(f"[bold green]{counts[STATUS_FIXED]} fixed[/bold green]")
    if counts[STATUS_IMPROVED]:  parts.append(f"[green]{counts[STATUS_IMPROVED]} improved[/green]")
    if counts[STATUS_UNCHANGED]: parts.append(f"[dim]{counts[STATUS_UNCHANGED]} unchanged[/dim]")
    if parts:
        console.print("  " + "  |  ".join(parts) + "\n")
