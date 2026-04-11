import json, sys

fname = sys.argv[1] if len(sys.argv) > 1 else "openai_report.json"
r = json.load(open(fname))
s = r["summary"]

print(f"Target:          {r['target']}")
print(f"Model:           {r.get('model', 'N/A')}")
print(f"Cost:            ${s.get('total_cost', 0):.4f}")
print(f"Risk Score:      {s.get('risk_score', 0)}/100")
print(f"Vulnerabilities: {s.get('total_vulnerabilities', 0)}")
print(f"Attacks Run:     {s.get('total_attacks_run', 0)}")
print()

all_attacks = r.get("vulnerabilities", [])
if not all_attacks:
    print("No vulnerabilities found in output.")
else:
    print("--- Findings ---")
    for v in all_attacks:
        print(f"  [{v['severity']:<8}] {v['attack_name']:<35} {v['success_rate']*100:.0f}%  vulnerable={v['is_vulnerable']}")

# Also show non-vulnerable attacks from details if present
print()
print(f"Recommendation: {s.get('recommendation', 'N/A')}")
