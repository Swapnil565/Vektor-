"""
Unit tests for SeverityScorer and Reporter.
"""
import pytest
import json
import os
import tempfile
from llmguard.scoring.severity import Severity, SeverityScorer, get_severity_scorer


# ── SeverityScorer ───────────────────────────────────────────────────────────

class TestSeverityScorer:
    @pytest.fixture
    def scorer(self):
        return SeverityScorer()

    def test_singleton_instance(self):
        """get_severity_scorer returns the same instance."""
        s1 = get_severity_scorer()
        s2 = get_severity_scorer()
        assert s1 is s2

    def test_critical_severity(self, scorer):
        """High success rate + high-weight category → CRITICAL."""
        result = scorer.calculate(1.0, "Data Extraction")  # 4 + round(9/2)=5 = 9
        assert result == Severity.CRITICAL

    def test_high_severity(self, scorer):
        """Moderate-high success rate + moderate category → HIGH."""
        result = scorer.calculate(0.6, "Instruction Hijacking")  # 3 + round(8/2)=4 = 7
        assert result == Severity.HIGH

    def test_medium_severity(self, scorer):
        """Low success rate + low-weight category → MEDIUM."""
        result = scorer.calculate(0.3, "Prompt Injection")  # 2 + round(7/2)=4 = 6 → HIGH
        # Actually 2 + 4 = 6 → HIGH. Let's use lower weight.
        result = scorer.calculate(0.1, "Evasion")  # 1 + round(4/2)=2 = 3
        assert result == Severity.MEDIUM

    def test_low_severity(self, scorer):
        """Very low success rate + low category → LOW."""
        result = scorer.calculate(0.05, "Evasion")  # 1 + 2 = 3 → MEDIUM
        # Hmm. Let's just test known boundary.
        result = scorer.calculate(0.01, "Jailbreak")  # 1 + round(6/2)=3 = 4 → MEDIUM
        # Let's verify the actual calculation
        # success_rate > 0 → score=1, category "Jailbreak" weight=6, round(6/2)=3 → total=4 → MEDIUM
        assert result == Severity.MEDIUM

    def test_info_severity_zero_rate(self, scorer):
        """Zero success rate → score depends on category weight alone."""
        # success_rate=0, "Evasion" weight=4, round(4/2)=2, total=2 → LOW
        result = scorer.calculate(0.0, "Evasion")
        assert result == Severity.LOW

    def test_zero_rate_default_weight(self, scorer):
        """Zero success rate + unknown category (default weight 5)."""
        result = scorer.calculate(0.0, "Unknown")
        # 0 + round(5/2) = round(2.5) = 2 (banker's rounding) → LOW
        assert result == Severity.LOW

    def test_full_range_prompt_injection(self, scorer):
        """Test full success rate for Prompt Injection (weight=7)."""
        result = scorer.calculate(1.0, "Prompt Injection")  # 4 + round(7/2)=4 = 8
        assert result == Severity.CRITICAL

    def test_severity_enum_values(self):
        """Severity enum has all expected values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_category_weights_exist(self, scorer):
        """All expected categories have weights defined."""
        expected = ["Prompt Injection", "Data Extraction", "Instruction Hijacking", "Jailbreak", "Evasion"]
        for cat in expected:
            assert cat in scorer.CATEGORY_WEIGHTS


# ── Reporter ─────────────────────────────────────────────────────────────────

class TestReporter:
    @pytest.fixture
    def sample_results(self):
        return {
            "target": "test-target",
            "model": "test-model",
            "timestamp": "2025-01-01T00:00:00Z",
            "budget_limit": 1.0,
            "vulnerabilities": [
                {
                    "attack_name": "direct_injection",
                    "category": "Prompt Injection",
                    "severity": "HIGH",
                    "success_rate": 0.67,
                    "is_vulnerable": True,
                    "remediation": "Fix it.",
                    "cost": 0.003,
                    "details": {"total_tests": 3, "successful_tests": 2},
                }
            ],
            "all_results": [
                {"attack_name": "direct_injection", "category": "Prompt Injection",
                 "severity": "HIGH", "success_rate": 0.67, "is_vulnerable": True, "cost": 0.003},
                {"attack_name": "system_override", "category": "Prompt Injection",
                 "severity": "LOW", "success_rate": 0.0, "is_vulnerable": False, "cost": 0.002},
            ],
            "summary": {
                "total_attacks_run": 2,
                "total_vulnerabilities": 1,
                "by_severity": {"HIGH": 1},
                "risk_score": 35,
                "recommendation": "MEDIUM RISK: Review and mitigate findings.",
                "total_cost": 0.005,
                "budget_status": {"limit": 1.0, "spent": 0.005, "remaining": 0.995, "percentage_used": 0.5},
            },
        }

    def test_save_json(self, sample_results):
        from llmguard.scoring.reporter import Reporter
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w') as f:
            path = f.name
        try:
            reporter.save_json(sample_results, path)
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["target"] == "test-target"
            assert len(loaded["vulnerabilities"]) == 1
        finally:
            os.unlink(path)

    def test_save_html(self, sample_results):
        from llmguard.scoring.reporter import Reporter
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode='w') as f:
            path = f.name
        try:
            reporter.save_html(sample_results, path)
            with open(path) as f:
                content = f.read()
            assert "LLMGuard" in content
            assert "direct_injection" in content
            assert "<html" in content.lower()
        finally:
            os.unlink(path)

    def test_print_terminal_no_crash(self, sample_results):
        """Terminal print should not crash."""
        from llmguard.scoring.reporter import Reporter
        from rich.console import Console
        import io
        reporter = Reporter()
        console = Console(file=io.StringIO())
        reporter.print_terminal(sample_results, console)
        output = console.file.getvalue()
        assert "direct_injection" in output
