"""
Smoke tests — prove the core user-facing flows work end-to-end.
No API keys required.
"""


def test_vulnerable_target_produces_findings():
    from vektor.targets.vulnerable import VulnerableTarget
    from vektor.core.engine import VektorScanner

    target = VulnerableTarget()
    scanner = VektorScanner(target, budget_limit=1.0)
    results = scanner.scan(quick_mode=True)

    assert results["summary"]["total_vulnerabilities"] >= 5, (
        f"VulnerableTarget should fail at least 5 quick-mode attacks, "
        f"got {results['summary']['total_vulnerabilities']}"
    )
    assert results["summary"]["risk_score"] >= 30, (
        f"VulnerableTarget should produce at least MEDIUM risk score, "
        f"got {results['summary']['risk_score']}"
    )


def test_vulnerable_target_scan_completes():
    """Full scan (not quick mode) should complete and produce a valid result dict."""
    from vektor.targets.vulnerable import VulnerableTarget
    from vektor.core.engine import VektorScanner

    target = VulnerableTarget()
    scanner = VektorScanner(target, budget_limit=5.0)
    results = scanner.scan()

    assert "summary" in results
    assert "vulnerabilities" in results
    assert "all_results" in results
    assert results["summary"]["total_attacks_run"] > 0
