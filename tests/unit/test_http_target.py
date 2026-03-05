"""
Unit tests for vektor.targets.http_endpoint.HTTPEndpointTarget.

All HTTP calls are mocked — no server required.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from vektor.targets.http_endpoint import HTTPEndpointTarget
from vektor.targets.factory import create_target


# ── Shape detection ──────────────────────────────────────────────────────────

class TestShapeDetection:
    def test_openai_completions_url(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/v1/chat/completions")
        assert t._shape == HTTPEndpointTarget.SHAPE_OPENAI

    def test_openai_short_url(self):
        t = HTTPEndpointTarget(url="http://my-proxy.io/chat/completions")
        assert t._shape == HTTPEndpointTarget.SHAPE_OPENAI

    def test_anthropic_messages_url(self):
        t = HTTPEndpointTarget(url="https://api.anthropic.com/v1/messages")
        assert t._shape == HTTPEndpointTarget.SHAPE_ANTHROPIC

    def test_simple_shape_default(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/chat")
        assert t._shape == HTTPEndpointTarget.SHAPE_SIMPLE

    def test_simple_shape_arbitrary_path(self):
        t = HTTPEndpointTarget(url="http://my-app.com/api/ask")
        assert t._shape == HTTPEndpointTarget.SHAPE_SIMPLE


# ── Request body building ────────────────────────────────────────────────────

class TestRequestBuilding:
    def test_simple_default_field(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/chat")
        body = t._build_request_body("hello")
        assert body == {"message": "hello"}

    def test_simple_custom_field(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/chat", request_field="input")
        body = t._build_request_body("hello")
        assert body == {"input": "hello"}

    def test_simple_with_system_prompt(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/chat", system_prompt="You are helpful.")
        body = t._build_request_body("hello")
        assert body["message"] == "hello"
        assert body["system_prompt"] == "You are helpful."

    def test_openai_shape_no_system(self):
        t = HTTPEndpointTarget(url="http://host/v1/chat/completions")
        body = t._build_request_body("hello")
        assert body["messages"] == [{"role": "user", "content": "hello"}]

    def test_openai_shape_with_system(self):
        t = HTTPEndpointTarget(
            url="http://host/v1/chat/completions",
            system_prompt="Be terse.",
            model="gpt-4o-mini",
        )
        body = t._build_request_body("hello")
        assert body["messages"][0] == {"role": "system", "content": "Be terse."}
        assert body["messages"][1] == {"role": "user", "content": "hello"}
        assert body["model"] == "gpt-4o-mini"

    def test_anthropic_shape(self):
        t = HTTPEndpointTarget(url="http://host/v1/messages", model="claude-3-haiku-20240307")
        body = t._build_request_body("hello")
        assert body["messages"] == [{"role": "user", "content": "hello"}]
        assert body["model"] == "claude-3-haiku-20240307"
        assert body["max_tokens"] == 1024

    def test_anthropic_shape_with_system(self):
        t = HTTPEndpointTarget(url="http://host/v1/messages", system_prompt="Be helpful.")
        body = t._build_request_body("hello")
        assert body["system"] == "Be helpful."

    def test_request_template_placeholder(self):
        template = {"query": "{{prompt}}", "stream": False}
        t = HTTPEndpointTarget(url="http://host/ask", request_template=template)
        body = t._build_request_body("test input")
        assert body == {"query": "test input", "stream": False}

    def test_request_template_escapes_quotes(self):
        template = {"q": "{{prompt}}"}
        t = HTTPEndpointTarget(url="http://host/ask", request_template=template)
        body = t._build_request_body('say "hello"')
        assert body["q"] == 'say "hello"'


# ── Response extraction ──────────────────────────────────────────────────────

class TestResponseExtraction:
    def _target(self, **kwargs):
        return HTTPEndpointTarget(url="http://localhost:8000/chat", **kwargs)

    def test_openai_choices_shape(self):
        t = self._target()
        data = {"choices": [{"message": {"content": "OpenAI reply"}}]}
        assert t._extract_response(data) == "OpenAI reply"

    def test_anthropic_content_shape(self):
        t = self._target()
        data = {"content": [{"type": "text", "text": "Anthropic reply"}]}
        assert t._extract_response(data) == "Anthropic reply"

    def test_custom_response_field(self):
        t = self._target(response_field="output")
        data = {"output": "custom reply"}
        assert t._extract_response(data) == "custom reply"

    def test_default_message_field(self):
        t = self._target()
        data = {"message": "simple reply"}
        assert t._extract_response(data) == "simple reply"

    def test_fallback_response_key(self):
        t = self._target(response_field="nonexistent")
        data = {"response": "fallback reply"}
        assert t._extract_response(data) == "fallback reply"

    def test_fallback_text_key(self):
        t = self._target(response_field="nonexistent")
        data = {"text": "text reply"}
        assert t._extract_response(data) == "text reply"

    def test_non_dict_response(self):
        t = self._target()
        assert t._extract_response("raw string") == "raw string"

    def test_unknown_shape_returns_json_dump(self):
        t = self._target(response_field="nonexistent")
        data = {"weird_key": "some value"}
        result = t._extract_response(data)
        assert "weird_key" in result


# ── Full query flow (mocked HTTP) ────────────────────────────────────────────

class TestQueryFlow:
    def _make_target(self, **kwargs):
        return HTTPEndpointTarget(url="http://localhost:8000/chat", **kwargs)

    def test_query_simple_shape(self):
        t = self._make_target()
        mock_response = {"message": "I'm an AI assistant."}
        with patch.object(t, "_http_request", return_value=mock_response):
            result = t.query("Who are you?")
        assert result == "I'm an AI assistant."
        assert t.request_count == 1

    def test_query_openai_shape(self):
        t = HTTPEndpointTarget(url="http://localhost:8000/v1/chat/completions")
        mock_response = {"choices": [{"message": {"content": "GPT says hi"}}]}
        with patch.object(t, "_http_request", return_value=mock_response):
            result = t.query("Say hi")
        assert result == "GPT says hi"

    def test_request_count_increments(self):
        t = self._make_target()
        with patch.object(t, "_http_request", return_value={"message": "ok"}):
            t.query("a")
            t.query("b")
            t.query("c")
        assert t.request_count == 3

    def test_estimate_cost_is_zero(self):
        t = self._make_target()
        assert t.estimate_cost("anything") == 0.0

    def test_headers_set_correctly(self):
        t = HTTPEndpointTarget(
            url="http://host/chat",
            headers={"Authorization": "Bearer tok_abc"},
        )
        assert t.headers["Authorization"] == "Bearer tok_abc"
        assert t.headers["Content-Type"] == "application/json"

    def test_default_headers_content_type(self):
        t = self._make_target()
        assert t.headers["Content-Type"] == "application/json"

    def test_get_refusal_patterns_non_empty(self):
        t = self._make_target()
        patterns = t.get_refusal_patterns()
        assert len(patterns) > 0
        assert all(isinstance(p, str) for p in patterns)

    def test_http_request_body_passed_correctly(self):
        t = self._make_target()
        captured = {}

        def fake_request(body):
            captured["body"] = body
            return {"message": "ok"}

        with patch.object(t, "_http_request", side_effect=fake_request):
            t.query("test payload")

        assert captured["body"] == {"message": "test payload"}


# ── Factory registration ─────────────────────────────────────────────────────

class TestFactory:
    def test_factory_creates_http_target(self):
        target = create_target("http", url="http://localhost:8000/chat")
        assert isinstance(target, HTTPEndpointTarget)
        assert target.url == "http://localhost:8000/chat"

    def test_factory_passes_headers(self):
        target = create_target(
            "http",
            url="http://localhost:8000/chat",
            headers={"Authorization": "Bearer tok"},
        )
        assert target.headers["Authorization"] == "Bearer tok"

    def test_factory_passes_request_response_field(self):
        target = create_target(
            "http",
            url="http://localhost:8000/chat",
            request_field="input",
            response_field="output",
        )
        assert target.request_field == "input"
        assert target.response_field == "output"

    def test_factory_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            create_target("not_a_real_provider")


# ── CLI --url flag ────────────────────────────────────────────────────────────

class TestCLI:
    def test_scan_no_target_no_url_fails(self):
        from vektor.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "Provide --target" in result.output or "Error" in result.output

    def test_scan_url_without_target_routes_to_http(self):
        from vektor.cli import cli
        runner = CliRunner()

        with patch("vektor.targets.factory.create_target") as mock_factory, \
             patch("vektor.core.engine.VektorScanner") as mock_scanner_cls:

            mock_target = MagicMock()
            mock_factory.return_value = mock_target

            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = {
                "all_results": [],
                "summary": {"risk_score": 0, "total_vulns": 0, "cost": 0.0},
            }
            mock_scanner_cls.return_value = mock_scanner

            result = runner.invoke(cli, [
                "scan",
                "--url", "http://localhost:8000/chat",
                "--quick",
            ])

        mock_factory.assert_called_once()
        call_args = mock_factory.call_args
        assert call_args[0][0] == "http"
        assert call_args[1]["url"] == "http://localhost:8000/chat"

    def test_scan_url_with_header_parsed(self):
        from vektor.cli import cli
        runner = CliRunner()

        with patch("vektor.targets.factory.create_target") as mock_factory, \
             patch("vektor.core.engine.VektorScanner") as mock_scanner_cls:

            mock_target = MagicMock()
            mock_factory.return_value = mock_target

            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = {
                "all_results": [],
                "summary": {"risk_score": 0, "total_vulns": 0, "cost": 0.0},
            }
            mock_scanner_cls.return_value = mock_scanner

            result = runner.invoke(cli, [
                "scan",
                "--url", "http://localhost:8000/chat",
                "--header", "Authorization: Bearer tok_abc",
                "--quick",
            ])

        call_kwargs = mock_factory.call_args[1]
        assert "headers" in call_kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer tok_abc"
