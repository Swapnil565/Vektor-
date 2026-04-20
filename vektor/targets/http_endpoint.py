"""
HTTP Endpoint Target — scan any deployed AI app via its REST API.

Supports:
  - OpenAI Chat Completions shape  (/v1/chat/completions)
  - Anthropic Messages shape       (/v1/messages)
  - Simple JSON shape              ({request_field: prompt} → {response_field: "..."})
  - Custom shapes via request_template (use {{prompt}} placeholder)

Usage:
    target = HTTPEndpointTarget(url="http://localhost:8000/chat")
    target = HTTPEndpointTarget(
        url="https://my-app.com/api/chat",
        headers={"Authorization": "Bearer tok_xxx"},
        request_field="input",
        response_field="output",
    )
"""
import json
from typing import Optional, Dict, List, Any

from vektor.targets.base import BaseTarget


# URL fragments used to auto-detect API shape
_OPENAI_SHAPE_INDICATORS = {"/v1/chat/completions", "/chat/completions"}
_ANTHROPIC_SHAPE_INDICATORS = {"/v1/messages", "/messages"}


class HTTPEndpointTarget(BaseTarget):
    """
    Generic HTTP endpoint target — POST requests to any REST AI API.

    Shape auto-detection (priority order):
    1.  URL contains /v1/chat/completions → OpenAI Chat Completions shape
    2.  URL contains /v1/messages         → Anthropic Messages shape
    3.  Otherwise                         → Simple {request_field: prompt}

    Override detection by passing ``request_template`` (a dict with
    ``{{prompt}}`` as the placeholder for the attack payload).
    """

    SHAPE_OPENAI = "openai"
    SHAPE_ANTHROPIC = "anthropic"
    SHAPE_SIMPLE = "simple"

    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        request_template: Optional[Dict] = None,
        request_field: str = "message",
        response_field: str = "message",
        param_field: Optional[str] = None,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        timeout: int = 30,
        request_delay: float = 0.0,
    ):
        super().__init__(name="http")
        self.url = url
        self.method = method.upper()
        # Don't set Content-Type if using query-param mode (no body sent)
        self.headers = ({} if param_field else {"Content-Type": "application/json"})
        self.headers.update(headers or {})
        self.request_template = request_template
        self.request_field = request_field
        self.response_field = response_field
        self.param_field = param_field  # if set, prompt goes as ?param_field=... instead of JSON body
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.request_delay = request_delay  # seconds to sleep between requests (for rate-limited APIs)
        self.request_count = 0
        self._shape = self._detect_shape(url)

    # ── Shape detection ──────────────────────────────────────────────────────

    def _detect_shape(self, url: str) -> str:
        url_lower = url.lower()
        for indicator in _OPENAI_SHAPE_INDICATORS:
            if indicator in url_lower:
                return self.SHAPE_OPENAI
        for indicator in _ANTHROPIC_SHAPE_INDICATORS:
            if indicator in url_lower:
                return self.SHAPE_ANTHROPIC
        return self.SHAPE_SIMPLE

    # ── Request building ─────────────────────────────────────────────────────

    def _build_request_body(self, prompt: str) -> Dict[str, Any]:
        """Build the POST body for the given prompt."""
        if self.request_template:
            rendered = json.dumps(self.request_template)
            rendered = rendered.replace("{{prompt}}", prompt.replace('"', '\\"'))
            return json.loads(rendered)

        if self._shape == self.SHAPE_OPENAI:
            messages: List[Dict] = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": prompt})
            body: Dict[str, Any] = {"messages": messages}
            if self.model:
                body["model"] = self.model
            return body

        if self._shape == self.SHAPE_ANTHROPIC:
            body = {
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            }
            if self.model:
                body["model"] = self.model
            if self.system_prompt:
                body["system"] = self.system_prompt
            return body

        # Simple shape: {request_field: prompt, ...}
        body = {self.request_field: prompt}
        if self.system_prompt:
            body["system_prompt"] = self.system_prompt
        return body

    # ── Response extraction ──────────────────────────────────────────────────

    def _extract_response(self, data: Any) -> str:
        """Pull text out of a JSON response, trying known shapes first."""
        if not isinstance(data, dict):
            return str(data)

        # OpenAI Chat Completions
        if "choices" in data:
            try:
                return data["choices"][0]["message"]["content"]
            except (KeyError, IndexError):
                pass

        # Anthropic Messages
        if "content" in data and isinstance(data["content"], list):
            try:
                return data["content"][0]["text"]
            except (KeyError, IndexError):
                pass

        # User-specified response field
        if self.response_field in data:
            return str(data[self.response_field])

        # Common single-key fallbacks
        for key in ("response", "output", "text", "answer", "result", "generated_text", "reply"):
            if key in data:
                return str(data[key])

        # Raw body fallback (returned when server gives non-JSON or error)
        if "_raw" in data:
            return str(data["_raw"])

        return json.dumps(data)

    # ── HTTP transport ───────────────────────────────────────────────────────

    def _http_request(self, body: Dict, prompt: str = "") -> Any:
        """Send the request using httpx (preferred) or requests.

        Never raises on 4xx/5xx — returns the parsed response body regardless,
        so the scanner sees exactly what the server replied (error messages,
        content-filter rejections, etc.).
        """
        # Query-param mode: prompt goes in the URL, no body
        params = {self.param_field: prompt} if self.param_field else None
        json_body = None if self.param_field else body

        try:
            import httpx
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.request(
                    self.method, self.url, headers=self.headers,
                    json=json_body, params=params,
                )
                try:
                    return resp.json()
                except Exception:
                    return {"_raw": resp.text, "_status": resp.status_code}
        except ImportError:
            pass

        try:
            import requests
            resp = requests.request(
                self.method, self.url, headers=self.headers,
                json=json_body, params=params, timeout=self.timeout,
            )
            try:
                return resp.json()
            except Exception:
                return {"_raw": resp.text, "_status": resp.status_code}
        except ImportError:
            pass

        raise RuntimeError(
            "No HTTP library available. Install one: pip install httpx"
        )

    # ── BaseTarget interface ─────────────────────────────────────────────────

    def query(self, prompt: str, stateful: bool = False, use_documents: bool = True, **kwargs) -> str:
        import time
        if self.request_delay > 0 and self.request_count > 0:
            time.sleep(self.request_delay)
        self.request_count += 1
        # Synthetic cost so budget limits still apply to HTTP targets
        self.total_cost += 0.0001
        body = self._build_request_body(prompt)
        data = self._http_request(body, prompt=prompt)
        return self._extract_response(data)

    def estimate_cost(self, prompt: str, response: Optional[str] = None) -> float:
        return 0.0  # Self-hosted — no API cost

    def get_refusal_patterns(self) -> List[str]:
        return [
            "i cannot", "i can't", "i'm unable", "i am unable",
            "i'm not able", "i will not", "i refuse",
            "that's not something i", "i don't think i should",
        ]

