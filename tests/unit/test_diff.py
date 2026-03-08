"""Unit tests for vektor/core/diff.py (Phase 6) and vektor.__init__ extensions (Phase 7).

These tests are fully self-contained: no API keys, no network, no real LLM.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers: build minimal Vektor-style report dicts in memory
# ---------------------------------------------------------------------------

def _make_report(*vulns):
    """Build a minimal Vektor JSON report dict from vuln spec tuples.

    Each vuln spec is (attack_name, category, severity, success_rate).
    """
    return {
        "target": "test",
        "model":  "test-model",
        "vulnerabilities": [
            {
                "attack_name":  name,
                "category":     cat,
                "severity":     sev,
                "success_rate": rate,
            }
            for name, cat, sev, rate in vulns
        ],
        "summary": {"risk_score": 50},
    }


def _write_report(tmp_dir, filename, *vulns):
    path = os.path.join(tmp_dir, filename)
    with open(path, "w") as f:
        json.dump(_make_report(*vulns), f)
    return path


# ---------------------------------------------------------------------------
# Tests for diff_reports()
# ---------------------------------------------------------------------------

class TestDiffReports(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _paths(self, v1_vulns, v2_vulns):
        p1 = _write_report(self.tmp, "v1.json", *v1_vulns)
        p2 = _write_report(self.tmp, "v2.json", *v2_vulns)
        return p1, p2

    def _diff(self, v1_vulns, v2_vulns):
        from vektor.core.diff import diff_reports
        p1, p2 = self._paths(v1_vulns, v2_vulns)
        return diff_reports(p1, p2)

    def _by_name(self, diffs, name):
        return next(d for d in diffs if d.attack_name == name)

    # -- regression -------------------------------------------------------

    def test_severity_increase_is_regression(self):
        diffs = self._diff(
            [("sqli", "Injection", "LOW", 0.3)],
            [("sqli", "Injection", "HIGH", 0.7)],
        )
        d = self._by_name(diffs, "sqli")
        self.assertEqual(d.status, "regression")

    def test_rate_increase_gte_5pp_is_regression(self):
        """Same severity but success rate up ≥5 pp → regression."""
        diffs = self._diff(
            [("xss", "Injection", "MEDIUM", 0.40)],
            [("xss", "Injection", "MEDIUM", 0.50)],
        )
        d = self._by_name(diffs, "xss")
        self.assertEqual(d.status, "regression")

    def test_rate_increase_below_5pp_is_unchanged(self):
        diffs = self._diff(
            [("xss", "Injection", "MEDIUM", 0.40)],
            [("xss", "Injection", "MEDIUM", 0.44)],
        )
        d = self._by_name(diffs, "xss")
        self.assertEqual(d.status, "unchanged")

    # -- improved ---------------------------------------------------------

    def test_severity_decrease_is_improved(self):
        diffs = self._diff(
            [("prompt", "Prompt Injection", "CRITICAL", 1.0)],
            [("prompt", "Prompt Injection", "MEDIUM",   0.3)],
        )
        d = self._by_name(diffs, "prompt")
        self.assertEqual(d.status, "improved")

    def test_rate_decrease_gte_5pp_is_improved(self):
        diffs = self._diff(
            [("pii", "Data Extraction", "HIGH", 0.80)],
            [("pii", "Data Extraction", "HIGH", 0.65)],
        )
        d = self._by_name(diffs, "pii")
        self.assertEqual(d.status, "improved")

    # -- new / fixed ------------------------------------------------------

    def test_attack_new_in_v2_is_new_vuln(self):
        diffs = self._diff(
            [],
            [("new_attack", "Jailbreak", "HIGH", 0.7)],
        )
        d = self._by_name(diffs, "new_attack")
        self.assertEqual(d.status, "new_vuln")

    def test_attack_gone_from_v2_is_fixed(self):
        diffs = self._diff(
            [("old_attack", "Evasion", "MEDIUM", 0.5)],
            [],
        )
        d = self._by_name(diffs, "old_attack")
        self.assertEqual(d.status, "fixed")

    def test_unchanged_attack_is_unchanged(self):
        diffs = self._diff(
            [("safe", "Prompt Injection", "INFO", 0.0)],
            [("safe", "Prompt Injection", "INFO", 0.0)],
        )
        d = self._by_name(diffs, "safe")
        self.assertEqual(d.status, "unchanged")

    # -- ordering ---------------------------------------------------------

    def test_regressions_sorted_first(self):
        diffs = self._diff(
            [
                ("a_ok",   "Cat", "LOW",  0.2),
                ("b_bad",  "Cat", "LOW",  0.2),
            ],
            [
                ("a_ok",   "Cat", "LOW",  0.2),
                ("b_bad",  "Cat", "HIGH", 0.9),
            ],
        )
        self.assertEqual(diffs[0].attack_name, "b_bad")
        self.assertEqual(diffs[0].status, "regression")

    # -- delta_rate -------------------------------------------------------

    def test_delta_rate_computed_correctly(self):
        diffs = self._diff(
            [("atk", "Cat", "MEDIUM", 0.40)],
            [("atk", "Cat", "MEDIUM", 0.70)],
        )
        d = self._by_name(diffs, "atk")
        self.assertAlmostEqual(d.delta_rate, 0.30, places=4)

    def test_delta_rate_none_for_new_attack(self):
        diffs = self._diff(
            [],
            [("new", "Cat", "HIGH", 0.8)],
        )
        d = self._by_name(diffs, "new")
        self.assertIsNone(d.delta_rate)


# ---------------------------------------------------------------------------
# Tests for has_regression()
# ---------------------------------------------------------------------------

class TestHasRegression(unittest.TestCase):

    def _diffs(self, *statuses):
        from vektor.core.diff import AttackDiff
        return [
            AttackDiff("a", "Cat", s, "INFO", "INFO", 0.0, 0.0)
            for s in statuses
        ]

    def test_true_when_regression_present(self):
        from vektor.core.diff import has_regression
        self.assertTrue(has_regression(self._diffs("regression")))

    def test_true_when_new_vuln_present(self):
        from vektor.core.diff import has_regression
        self.assertTrue(has_regression(self._diffs("unchanged", "new_vuln")))

    def test_false_when_only_improved(self):
        from vektor.core.diff import has_regression
        self.assertFalse(has_regression(self._diffs("improved", "fixed", "unchanged")))

    def test_false_for_empty(self):
        from vektor.core.diff import has_regression
        self.assertFalse(has_regression([]))


# ---------------------------------------------------------------------------
# Tests for serialisation helpers
# ---------------------------------------------------------------------------

class TestSerialisation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _diffs_fixture(self):
        """Return real diffs from two temp report files."""
        p1 = _write_report(self.tmp, "s1.json",
                            ("atk", "Injection", "LOW", 0.3))
        p2 = _write_report(self.tmp, "s2.json",
                            ("atk", "Injection", "HIGH", 0.8))
        from vektor.core.diff import diff_reports
        return diff_reports(p1, p2), p1, p2

    def test_to_dict_contains_required_keys(self):
        from vektor.core.diff import to_dict
        diffs, _, _ = self._diffs_fixture()
        d = to_dict(diffs)[0]
        for key in ("attack_name", "category", "status",
                    "old_severity", "new_severity",
                    "old_rate", "new_rate", "delta_rate"):
            self.assertIn(key, d)

    def test_save_diff_json_creates_file(self):
        from vektor.core.diff import save_diff_json
        diffs, p1, p2 = self._diffs_fixture()
        out = os.path.join(self.tmp, "diff.json")
        save_diff_json(diffs, p1, p2, out)
        self.assertTrue(os.path.exists(out))
        loaded = json.loads(open(out).read())
        self.assertIn("diffs", loaded)
        self.assertIn("regressions", loaded)

    def test_save_diff_html_creates_file(self):
        from vektor.core.diff import save_diff_html
        diffs, p1, p2 = self._diffs_fixture()
        out = os.path.join(self.tmp, "diff.html")
        save_diff_html(diffs, p1, p2, out)
        self.assertTrue(os.path.exists(out))
        html = open(out, encoding="utf-8").read()
        self.assertIn("<table", html)
        self.assertIn("regression", html)

    def test_json_output_regression_flag_true(self):
        from vektor.core.diff import save_diff_json
        diffs, p1, p2 = self._diffs_fixture()
        out = os.path.join(self.tmp, "d.json")
        save_diff_json(diffs, p1, p2, out)
        loaded = json.loads(open(out).read())
        self.assertTrue(loaded["regressions"])

    def test_json_output_regression_flag_false_when_clean(self):
        from vektor.core.diff import save_diff_json, diff_reports
        p1 = _write_report(self.tmp, "c1.json", ("a", "Cat", "HIGH", 0.8))
        p2 = _write_report(self.tmp, "c2.json", ("a", "Cat", "HIGH", 0.8))
        diffs = diff_reports(p1, p2)
        out = os.path.join(self.tmp, "clean.json")
        save_diff_json(diffs, p1, p2, out)
        self.assertFalse(json.loads(open(out).read())["regressions"])


# ---------------------------------------------------------------------------
# Tests for print_diff_table() (smoke — just ensure no exception)
# ---------------------------------------------------------------------------

class TestPrintDiffTable(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_print_does_not_raise(self):
        from vektor.core.diff import diff_reports, print_diff_table
        from rich.console import Console
        from io import StringIO
        p1 = _write_report(self.tmp, "p1.json",
                            ("atk", "Injection", "LOW", 0.2))
        p2 = _write_report(self.tmp, "p2.json",
                            ("atk", "Injection", "HIGH", 0.9),
                            ("new_atk", "Jailbreak", "MEDIUM", 0.5))
        diffs = diff_reports(p1, p2)
        buf = StringIO()
        con = Console(file=buf, highlight=False)
        print_diff_table(diffs, p1, p2, console=con)
        output = buf.getvalue()
        self.assertIn("regression", output.lower())


# ---------------------------------------------------------------------------
# Phase 7: Tests for scan() extensions in vektor/__init__.py
# ---------------------------------------------------------------------------

class TestScanURL(unittest.TestCase):
    """scan(url=...) should auto-create an HTTPEndpointTarget."""

    def _mock_target(self):
        t = MagicMock()
        t.name = "http"
        t.model = "http"
        t.get_refusal_patterns.return_value = []
        t.supports_documents.return_value = False
        t.query.return_value = "ok"
        return t

    @patch("vektor.create_target")
    def test_scan_url_creates_http_target(self, mock_create):
        mock_create.return_value = self._mock_target()
        from vektor import scan
        try:
            scan(url="http://localhost:9999/chat", attacks=[])
        except Exception:
            pass  # budget / scan internals may error; we just check create_target
        args, kwargs = mock_create.call_args
        self.assertEqual(args[0], "http")
        self.assertIn("url", kwargs)
        self.assertEqual(kwargs["url"], "http://localhost:9999/chat")

    @patch("vektor.create_target")
    def test_scan_model_forwarded_as_kwarg(self, mock_create):
        mock_create.return_value = self._mock_target()
        from vektor import scan
        try:
            scan(url="http://localhost:9999/", model="gpt-4o", attacks=[])
        except Exception:
            pass
        _, kwargs = mock_create.call_args
        self.assertEqual(kwargs.get("model"), "gpt-4o")


class TestScanFailOn(unittest.TestCase):
    """scan(fail_on=...) should raise ScanFailed when threshold is met."""

    def _make_mock_scanner_results(self, vulns):
        """Return a fake VektorScanner result dict."""
        return {
            "target": "mock",
            "model":  "mock",
            "timestamp": "2026-01-01T00:00:00Z",
            "vulnerabilities": vulns,
            "all_results": vulns,
            "summary": {"risk_score": 80},
        }

    @patch("vektor.core.engine.VektorScanner.scan")
    def test_raises_scan_failed_on_threshold_met(self, mock_scan):
        mock_scan.return_value = self._make_mock_scanner_results([
            {"attack_name": "direct_injection", "severity": "CRITICAL", "success_rate": 1.0},
        ])
        from vektor import scan, ScanFailed
        from vektor.targets.mock import MockTarget
        with self.assertRaises(ScanFailed) as ctx:
            scan(target=MockTarget(), fail_on="HIGH", attacks=["direct_injection"])
        self.assertIn("CRITICAL", str(ctx.exception))
        self.assertIn("vulnerabilities", ctx.exception.results)

    @patch("vektor.core.engine.VektorScanner.scan")
    def test_no_raise_when_below_threshold(self, mock_scan):
        mock_scan.return_value = self._make_mock_scanner_results([
            {"attack_name": "minor", "severity": "LOW", "success_rate": 0.2},
        ])
        from vektor import scan
        from vektor.targets.mock import MockTarget
        # fail_on HIGH — LOW vuln should NOT raise
        result = scan(target=MockTarget(), fail_on="HIGH", attacks=["minor"])
        self.assertIn("vulnerabilities", result)

    @patch("vektor.core.engine.VektorScanner.scan")
    def test_no_raise_when_fail_on_none(self, mock_scan):
        mock_scan.return_value = self._make_mock_scanner_results([
            {"attack_name": "x", "severity": "CRITICAL", "success_rate": 1.0},
        ])
        from vektor import scan
        from vektor.targets.mock import MockTarget
        # No fail_on — should always return normally
        result = scan(target=MockTarget(), attacks=["x"])
        self.assertIn("vulnerabilities", result)


class TestQuickScan(unittest.TestCase):
    """quick_scan() should call scan with quick=True."""

    @patch("vektor.scan")
    def test_quick_scan_passes_quick_true(self, mock_scan):
        mock_scan.return_value = {"vulnerabilities": [], "summary": {}}
        from vektor import quick_scan
        from vektor.targets.mock import MockTarget
        t = MockTarget()
        quick_scan(target=t)
        args, kwargs = mock_scan.call_args
        self.assertTrue(kwargs.get("quick"))

    @patch("vektor.scan")
    def test_quick_scan_default_budget_025(self, mock_scan):
        mock_scan.return_value = {"vulnerabilities": [], "summary": {}}
        from vektor import quick_scan
        from vektor.targets.mock import MockTarget
        quick_scan(target=MockTarget())
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs.get("budget"), 0.25)

    @patch("vektor.scan")
    def test_quick_scan_forwards_fail_on(self, mock_scan):
        mock_scan.return_value = {"vulnerabilities": [], "summary": {}}
        from vektor import quick_scan
        from vektor.targets.mock import MockTarget
        quick_scan(target=MockTarget(), fail_on="CRITICAL")
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs.get("fail_on"), "CRITICAL")


class TestScanValueError(unittest.TestCase):
    def test_raises_without_any_target(self):
        from vektor import scan
        with self.assertRaises(ValueError):
            scan()


class TestScanFailedAttributes(unittest.TestCase):
    def test_scan_failed_stores_results(self):
        from vektor import ScanFailed
        results = {"vulnerabilities": [{"severity": "HIGH"}]}
        exc = ScanFailed("failed", results)
        self.assertIs(exc.results, results)
        self.assertIn("failed", str(exc))


if __name__ == "__main__":
    unittest.main()
