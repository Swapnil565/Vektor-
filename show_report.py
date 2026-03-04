import json, sys

fname = sys.argv[1] if len(sys.argv) > 1 else "gemini_scan.json"
r = json.load(open(fname))

print(f"=== {r['target'].upper()} - FULL RESULTS ===")
print(f"Risk Score: {r['summary']['risk_score']}/100")
print(f"Total Vulnerabilities: {r['summary']['total_vulnerabilities']}")
print()

for res in r["all_results"]:
    vuln = res["is_vulnerable"]
    rate = res["success_rate"]
    status = "VULNERABLE" if vuln else "secure   "
    print(f"[{status}] {res['attack_name']:<35} {rate*100:.0f}%  sev={res['severity']}")
    if vuln:
        tests = res["details"].get("test_results", [])
        for t in tests:
            if t.get("vulnerable"):
                prompt = str(t.get("prompt", ""))[:80]
                response = str(t.get("response", ""))[:150]
                print(f"         PROMPT:   {prompt}")
                print(f"         RESPONSE: {response}")
