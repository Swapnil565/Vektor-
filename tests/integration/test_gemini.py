"""
Integration tests for Gemini target.
Requires GEMINI_API_KEY environment variable.
Run with: pytest tests/integration/ -v --run-integration
"""
import os
import pytest
from llmguard.targets.gemini import GeminiTarget

# Skip entire module if no API key
pytestmark = pytest.mark.skipif(
    not os.getenv("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set"
)

@pytest.fixture(scope="module")
def gemini_target():
    return GeminiTarget(
        api_key=os.getenv("GEMINI_API_KEY"),
        model="models/gemini-2.5-flash",
        system_prompt="You are a helpful assistant."
    )

class TestGeminiTarget:
    def test_basic_query(self, gemini_target):
        """Target can send a query and get a response."""
        response = gemini_target.query("Say 'hello' and nothing else.")
        assert len(response) > 0
        assert gemini_target.request_count >= 1

    def test_cost_tracking(self, gemini_target):
        """Cost tracking (always 0.0 for gemini-2.5-flash free tier)."""
        cost_before = gemini_target.total_cost
        gemini_target.query("What is 2 + 2?")
        assert gemini_target.total_cost >= cost_before

    def test_refusal_patterns_exist(self, gemini_target):
        """Gemini target has refusal patterns defined."""
        patterns = gemini_target.get_refusal_patterns()
        assert len(patterns) > 0
        assert "i cannot" in patterns or "i am unable to" in patterns

    def test_stateful_conversation(self, gemini_target):
        """Multi-turn conversation maintains context."""
        gemini_target.clear_conversation()
        gemini_target.query("My name is TestUser123.", stateful=True)
        response = gemini_target.query("What is my name?", stateful=True)
        # Gemini usually executes instructions well
        assert "TestUser123" in response or "testuser" in response.lower()
