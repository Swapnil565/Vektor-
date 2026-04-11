"""
scripts/scan_local_app.py
=========================
Vektor scan campaign against the local health/fitness AI app.

Covers 4 distinct attack surfaces:
  S1  /api/events/parse?text=PAYLOAD        (NLP endpoint, param injection)
  S2  /api/events          feeling=PAYLOAD   (stored injection via feeling field)
  S3  /api/onboarding/complete goals=ARRAY  (stored injection via goals array)
  S4  /api/forecast  /api/insights/generate  (agent pipelines)

Usage:
    python scripts/scan_local_app.py               # full campaign
    python scripts/scan_local_app.py --surface 1   # only S1
    python scripts/scan_local_app.py --dry-run     # show plan without scanning
    python scripts/scan_local_app.py --combine     # combine existing JSONs only

Rate-limit awareness:
    Default request_delay=12.0s -> 5 req/min (cap-safe mode).
    Each surface runs its own batch; if one surface fails due to 429, others
    can still proceed.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# ── Ensure vektor is importable from repo root ────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

BASE_URL    = "http://127.0.0.1:8000"
OUTPUT_DIR  = Path("outputs")
DELAY       = 12.0  # seconds between requests (5 req/min cap-safe)

# ── Attack sets per surface ───────────────────────────────────────────────────
# Chosen for highest expected success rate on NLP/LLM-backed endpoints.
# No RAG or agent attacks on S1–S3 (no document/tool support).

ATTACKS_NLP = [
    "direct_injection",       # 0.80 — baseline override
    "system_override",        # 0.60 — role/system boundary
    "delimiter_confusion",    # 0.70 — structural injection
    "role_manipulation",      # 0.50 — persona override
    "system_prompt_reveal",   # 0.50 — data extraction
    "training_data_probe",     # 0.30 — membership inference
    "multi_turn_attack",      # 0.40 — conversation manipulation
]

ATTACKS_STORED = [
    "direct_injection",       # stored → executed when LLM processes feeling
    "system_override",
    "delimiter_confusion",
    "pii_leakage",            # 0.20 — reveal PII about other users
    "training_data_probe",
]

ATTACKS_GOALS = [
    "direct_injection",       # injected into goals array element
    "system_override",
    "role_manipulation",
    "system_prompt_reveal",
]

ATTACKS_AGENT = [
    "tool_injection",              # 0.60
    "agent_instruction_override",  # 0.55
    "function_call_hijack",        # 0.50
    "tool_parameter_injection",    # 0.50
]


# ── Auth ──────────────────────────────────────────────────────────────────────

def register_and_login(email: str, password: str, username: str) -> str:
    """Register (idempotent) and login; return JWT access token."""
    try:
        import httpx
    except ImportError:
        import requests as httpx  # fallback

    reg_body = {"email": email, "username": username, "password": password}
    try:
        r = httpx.post(f"{BASE_URL}/api/v1/auth/register",
                       json=reg_body, timeout=10)
        # 400 = already registered — that's fine
        if hasattr(r, 'status_code'):
            status = r.status_code
        else:
            status = 200
    except Exception as e:
        print(f"  [register] {e} — continuing (may already exist)")

    login_body = {"email": email, "password": password}
    try:
        r = httpx.post(f"{BASE_URL}/api/v1/auth/login",
                       json=login_body, timeout=10)
        if hasattr(r, 'json'):
            data = r.json()
        else:
            data = r
        token = data.get("access_token") or data.get("token") or data.get("jwt")
        if not token:
            raise ValueError(f"No token in login response: {data}")
        return token
    except Exception as e:
        raise RuntimeError(f"Login failed: {e}")


# ── Scan helpers ──────────────────────────────────────────────────────────────

def run_surface(
    label:          str,
    url:            str,
    attacks:        List[str],
    auth_header:    Dict,
    request_field:  str = "message",
    response_field: str = "message",
    param_field:    Optional[str] = None,
    request_template: Optional[Dict] = None,
    output_path:    Optional[Path] = None,
    dry_run:        bool = False,
) -> Optional[Dict]:
    """Run Vektor against one attack surface and save results."""
    from vektor.targets.http_endpoint import HTTPEndpointTarget
    from vektor.core.engine import VektorScanner

    print(f"\n{'='*60}")
    print(f"  Surface: {label}")
    print(f"  URL    : {url}")
    print(f"  Attacks: {', '.join(attacks)}")
    if param_field:
        print(f"  Mode   : query-param  ?{param_field}=PAYLOAD")
    elif request_template:
        print(f"  Mode   : template     {json.dumps(request_template)[:60]}...")
    else:
        print(f"  Mode   : json-body    field={request_field}")
    # Estimate request count (rough: most attacks have ~3 test cases)
    est = len(attacks) * 3
    est_time = est * DELAY
    print(f"  ~{est} requests  |  ~{est_time:.0f}s at {DELAY}s delay")
    print(f"{'='*60}")

    if dry_run:
        print("  [DRY RUN — skipping]")
        return None

    target = HTTPEndpointTarget(
        url              = url,
        headers          = auth_header,
        request_field    = request_field,
        response_field   = response_field,
        param_field      = param_field,
        request_template = request_template,
        request_delay    = DELAY,
    )

    scanner = VektorScanner(target, budget_limit=5.0)  # HTTP = $0 cost

    print("  Scanning ", end="", flush=True)
    start = time.time()

    results = scanner.scan(attacks=attacks)

    elapsed = time.time() - start
    vulns   = results.get("vulnerabilities", [])
    print(f"\r  Done in {elapsed:.0f}s — {len(vulns)} vulnerabilities found")

    for v in vulns:
        print(f"    [{v['severity']}] {v['attack_name']}  rate={v['success_rate']:.0%}")

    # Annotate with surface metadata
    results["_surface"] = label
    results["_url"]     = url

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"  Saved -> {output_path}")

    return results


# ── Combine reports ───────────────────────────────────────────────────────────

def combine_reports(surface_results: List[Dict], output_path: Path) -> Dict:
    """Merge per-surface results into one publishable master report."""
    all_vulns:   List[Dict] = []
    all_results: List[Dict] = []

    for sr in surface_results:
        if not sr:
            continue
        surface = sr.get("_surface", "unknown")
        for v in sr.get("vulnerabilities", []):
            v2 = dict(v)
            v2["surface"] = surface
            all_vulns.append(v2)
        for r in sr.get("all_results", []):
            r2 = dict(r)
            r2["surface"] = surface
            all_results.append(r2)

    # Risk score: average of per-surface risk scores weighted by vuln count
    scores = [sr["summary"]["risk_score"]
               for sr in surface_results
               if sr and sr.get("summary", {}).get("risk_score") is not None]
    overall_risk = round(sum(scores) / len(scores), 1) if scores else 0.0

    by_severity: Dict[str, int] = {}
    for v in all_vulns:
        sev = v.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    master = {
        "generated_by":    "Vektor — AI Security Testing Framework",
        "version":         "0.2.0",
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "target_app":      BASE_URL,
        "surfaces_tested": [sr["_surface"] for sr in surface_results if sr],
        "summary": {
            "overall_risk_score":   overall_risk,
            "total_vulnerabilities": len(all_vulns),
            "by_severity":          by_severity,
            "surfaces": [
                {
                    "surface":    sr.get("_surface"),
                    "url":        sr.get("_url"),
                    "risk_score": sr.get("summary", {}).get("risk_score", 0),
                    "vuln_count": len(sr.get("vulnerabilities", [])),
                }
                for sr in surface_results if sr
            ],
        },
        "vulnerabilities": all_vulns,
        "all_results":     all_results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(master, indent=2), encoding="utf-8")
    return master


def combine_existing(output_dir: Path) -> None:
    """Re-combine previously saved surface JSONs into a master report."""
    pattern = "localapp_surface_*.json"
    files   = sorted(output_dir.glob(pattern))
    if not files:
        print(f"No surface files matching {pattern} in {output_dir}/")
        return

    results = []
    for f in files:
        print(f"  Loading {f.name}")
        results.append(json.loads(f.read_text(encoding="utf-8")))

    master_path = output_dir / "localapp_MASTER.json"
    master = combine_reports(results, master_path)
    _print_master_summary(master, master_path)


# ── HTML report ───────────────────────────────────────────────────────────────

def save_master_html(master: Dict, path: Path) -> None:
    """Generate a publishable dark-themed HTML master report."""
    sev_color = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff7b72",
        "MEDIUM":   "#e3b341",
        "LOW":      "#58a6ff",
        "INFO":     "#8b949e",
    }

    def sev_badge(sev: str) -> str:
        col = sev_color.get(sev, "#8b949e")
        return f'<span style="color:{col};font-weight:bold">{sev}</span>'

    surfaces_html = ""
    for s in master["summary"]["surfaces"]:
        surfaces_html += (
            f"<tr><td>{s['surface']}</td><td style='color:#58a6ff'>{s['url']}</td>"
            f"<td style='text-align:right'>{s['risk_score']}</td>"
            f"<td style='text-align:right'>{s['vuln_count']}</td></tr>"
        )

    vuln_rows = ""
    for v in master["vulnerabilities"]:
        rate = v.get("success_rate", 0)
        vuln_rows += (
            f"<tr><td>{v['surface']}</td>"
            f"<td style='font-weight:bold'>{v['attack_name']}</td>"
            f"<td>{v['category']}</td>"
            f"<td>{sev_badge(v['severity'])}</td>"
            f"<td style='text-align:right'>{rate:.0%}</td></tr>"
        )

    risk  = master["summary"]["overall_risk_score"]
    total = master["summary"]["total_vulnerabilities"]
    by_sev = master["summary"]["by_severity"]
    severity_pills = " ".join(
        f'<span style="color:{sev_color.get(s,"#fff")};margin-right:1rem">'
        f'<strong>{c}</strong> {s}</span>'
        for s, c in by_sev.items()
    )

    ts  = master["timestamp"][:19].replace("T", " ") + " UTC"
    app = master["target_app"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vektor Master Report — {app}</title>
  <style>
    *{{box-sizing:border-box}}
    body{{font-family:system-ui,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}}
    h1{{color:#58a6ff;font-size:1.6rem;margin-bottom:.25rem}}
    h2{{color:#58a6ff;font-size:1.1rem;border-bottom:1px solid #30363d;padding-bottom:.4rem;margin-top:2rem}}
    .meta{{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}}
    .risk-badge{{display:inline-block;padding:.4rem 1.2rem;border-radius:2rem;font-size:1.4rem;font-weight:bold;
      background:{'#3d1212' if risk>=70 else '#2a1f00' if risk>=40 else '#12301e'};
      color:{'#ff4444' if risk>=70 else '#e3b341' if risk>=40 else '#3fb950'}}}
    .pills{{margin:1rem 0;font-size:.95rem}}
    table{{border-collapse:collapse;width:100%;font-size:.88rem;margin-top:.5rem}}
    th{{background:#161b22;color:#58a6ff;padding:.4rem .7rem;text-align:left;border-bottom:2px solid #30363d}}
    td{{padding:.35rem .7rem;border-bottom:1px solid #21262d;vertical-align:top}}
    tr:hover td{{background:#161b22}}
    .badge-vuln{{background:#3d1212;color:#ff7b72;padding:.15rem .5rem;border-radius:.3rem;font-size:.8rem;font-weight:bold}}
    footer{{color:#444;font-size:.75rem;margin-top:3rem;border-top:1px solid #21262d;padding-top:1rem}}
  </style>
</head>
<body>
  <h1>Vektor — AI Security Scan Report</h1>
  <p class="meta">Target: <strong>{app}</strong> &nbsp;|&nbsp; Scanned: {ts} &nbsp;|&nbsp; Generated by Vektor v0.2.0</p>

  <h2>Overall Risk</h2>
  <div class="risk-badge">{risk}/100</div>
  <div class="pills">{severity_pills}</div>
  <p style="color:#8b949e;font-size:.85rem">
    <strong style="color:#c9d1d9">{total}</strong> exploitable vulnerabilities found across
    <strong style="color:#c9d1d9">{len(master['summary']['surfaces'])}</strong> attack surfaces.
  </p>

  <h2>Attack Surfaces</h2>
  <table>
    <thead><tr><th>Surface</th><th>URL</th><th>Risk Score</th><th>Vulns</th></tr></thead>
    <tbody>{surfaces_html}</tbody>
  </table>

  <h2>Vulnerabilities Found</h2>
  <table>
    <thead><tr><th>Surface</th><th>Attack</th><th>Category</th><th>Severity</th><th>Success Rate</th></tr></thead>
    <tbody>{vuln_rows if vuln_rows else "<tr><td colspan='5' style='color:#3fb950;text-align:center'>No vulnerabilities found</td></tr>"}</tbody>
  </table>

  <footer>
    Generated by <a href="https://github.com/Swapnil565/Llmgaurd-lite" style="color:#58a6ff">Vektor</a>
    &mdash; Open-source AI Security Testing Framework.
    Surfaces: {", ".join(master["surfaces_tested"])}.
  </footer>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")


# ── Summary printer ───────────────────────────────────────────────────────────

def _print_master_summary(master: Dict, master_path: Path) -> None:
    s   = master["summary"]
    print(f"\n{'#'*60}")
    print(f"  MASTER REPORT SUMMARY")
    print(f"  Overall risk score : {s['overall_risk_score']}/100")
    print(f"  Total vulns        : {s['total_vulnerabilities']}")
    print(f"  By severity        : {s['by_severity']}")
    print(f"  Saved              : {master_path}")
    html_path = master_path.with_suffix(".html")
    print(f"                       {html_path}")
    print(f"{'#'*60}")


# ── Main campaign ─────────────────────────────────────────────────────────────

def main():
    global DELAY   # declare first — used in argparse defaults AND reassigned later
    parser = argparse.ArgumentParser(description="Vektor scan campaign — local AI app")
    parser.add_argument("--surface", type=int, choices=[1, 2, 3, 4],
                        help="Run only this surface number (1-4)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the plan without running any scans")
    parser.add_argument("--combine", action="store_true",
                        help="Combine existing surface JSONs into master report")
    parser.add_argument("--delay", type=float, default=DELAY,
                        help=f"Request delay in seconds (default: {DELAY})")
    parser.add_argument("--email",    default="vektor@test.local")
    parser.add_argument("--password", default="VektorTest2026!")
    parser.add_argument("--username", default="vektor_scanner")
    args = parser.parse_args()

    DELAY = args.delay

    OUTPUT_DIR.mkdir(exist_ok=True)

    if args.combine:
        combine_existing(OUTPUT_DIR)
        return

    # ── Auth ──────────────────────────────────────────────────────────────────
    if not args.dry_run:
        print("Authenticating with local app...")
        try:
            token = register_and_login(args.email, args.password, args.username)
            print(f"  JWT obtained: {token[:20]}...")
        except Exception as e:
            print(f"  [ERROR] {e}")
            print("  Make sure the app is running at http://127.0.0.1:8000")
            sys.exit(1)
        auth_header = {"Authorization": f"Bearer {token}"}
    else:
        auth_header = {"Authorization": "Bearer <dry-run>"}

    surfaces_to_run = [args.surface] if args.surface else [1, 2, 3, 4]

    all_results = []

    # ── Surface 1: /api/events/parse?text=PAYLOAD ─────────────────────────────
    if 1 in surfaces_to_run:
        r = run_surface(
            label          = "S1-events-parse (NLP param injection)",
            url            = f"{BASE_URL}/api/events/parse",
            attacks        = ATTACKS_NLP,
            auth_header    = auth_header,
            param_field    = "text",          # prompt goes as ?text=PAYLOAD
            response_field = "message",
            output_path    = OUTPUT_DIR / "localapp_surface_1_events_parse.json",
            dry_run        = args.dry_run,
        )
        all_results.append(r)

    # ── Surface 2: /api/events  feeling=PAYLOAD ───────────────────────────────
    if 2 in surfaces_to_run:
        r = run_surface(
            label          = "S2-events-feeling (stored injection)",
            url            = f"{BASE_URL}/api/events",
            attacks        = ATTACKS_STORED,
            auth_header    = auth_header,
            # Full request body: need category/event_type + injected feeling field
            request_template = {
                "category":   "physical",
                "event_type": "workout",
                "feeling":    "{{prompt}}",
            },
            response_field = "message",
            output_path    = OUTPUT_DIR / "localapp_surface_2_events_feeling.json",
            dry_run        = args.dry_run,
        )
        all_results.append(r)

    # ── Surface 3: /api/onboarding/complete  goals=[PAYLOAD] ─────────────────
    if 3 in surfaces_to_run:
        r = run_surface(
            label          = "S3-onboarding-goals (goals array injection)",
            url            = f"{BASE_URL}/api/onboarding/complete",
            attacks        = ATTACKS_GOALS,
            auth_header    = auth_header,
            request_template = {
                "goals":      ["{{prompt}}", "stay healthy"],
                "work_hours": 8,
            },
            response_field = "message",
            output_path    = OUTPUT_DIR / "localapp_surface_3_onboarding.json",
            dry_run        = args.dry_run,
        )
        all_results.append(r)

    # ── Surface 4: /api/forecast (agent pipeline) ─────────────────────────────
    if 4 in surfaces_to_run:
        r = run_surface(
            label          = "S4-forecast (agent pipeline injection)",
            url            = f"{BASE_URL}/api/forecast",
            attacks        = ATTACKS_AGENT,
            auth_header    = auth_header,
            request_field  = "message",
            response_field = "message",
            output_path    = OUTPUT_DIR / "localapp_surface_4_agent.json",
            dry_run        = args.dry_run,
        )
        all_results.append(r)

    # ── Combine & publish ─────────────────────────────────────────────────────
    real_results = [r for r in all_results if r is not None]
    if real_results and not args.dry_run:
        master_path = OUTPUT_DIR / "localapp_MASTER.json"
        print("\nCombining surface results into master report...")
        master = combine_reports(real_results, master_path)
        html_path = master_path.with_suffix(".html")
        save_master_html(master, html_path)
        _print_master_summary(master, master_path)

    elif args.dry_run:
        total_attacks = (
            len(ATTACKS_NLP)    * (1 in surfaces_to_run) +
            len(ATTACKS_STORED) * (2 in surfaces_to_run) +
            len(ATTACKS_GOALS)  * (3 in surfaces_to_run) +
            len(ATTACKS_AGENT)  * (4 in surfaces_to_run)
        )
        est_requests = total_attacks * 3
        est_time_min = est_requests * DELAY / 60
        print(f"\nDRY RUN SUMMARY:")
        print(f"  Surfaces  : {len(surfaces_to_run)}")
        print(f"  Attacks   : {total_attacks} total")
        print(f"  ~Requests : {est_requests}  (~3 tests/attack)")
        print(f"  ~Time     : {est_time_min:.1f} min at {DELAY}s delay")
        print(f"  Rate      : {60/DELAY:.0f} req/min  (configured cap: 5/min)")


if __name__ == "__main__":
    main()

