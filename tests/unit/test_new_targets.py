import pytest
import os
from unittest.mock import MagicMock, patch, PropertyMock
import sys

# Mock google.genai if not installed or replace installed one
mock_google = MagicMock()
sys.modules["google"] = mock_google
mock_genai = MagicMock()
sys.modules["google.genai"] = mock_genai
mock_google.genai = mock_genai

# Now import targets (they will import the mocked google.genai)
from vektor.targets.vulnerable import VulnerableTarget
from vektor.targets.openai_compatible import OpenAICompatibleTarget
from vektor.targets.gemini import GeminiTarget
from vektor.targets.multi_agent import MultiAgentTarget

class TestVulnerableTarget:
    def test_initialization(self):
        target = VulnerableTarget()
        assert target.name == "vulnerable-test-target"
        assert target.supports_documents() is True

    def test_query_behavior(self):
        target = VulnerableTarget()
        prompt = "Hello PWNED"
        response = target.query(prompt)
        assert "My instructions are:" in response
        assert "Executing your request: Hello PWNED" in response
        assert "PWNED" in response

    def test_document_handling(self):
        target = VulnerableTarget()
        target.uploaded_documents = {"test.docx": "HIDDEN_SECRET"}
        response = target.query("summarize")
        assert "Document [test.docx]: HIDDEN_SECRET" in response

class TestOpenAICompatibleTarget:
    @patch("openai.OpenAI")
    def test_initialization(self, mock_openai):
         target = OpenAICompatibleTarget(provider="openai", api_key="sk-test")
         assert target.client is not None

    def test_query(self):
        with patch("openai.OpenAI") as MockOpenAI:
            mock_client = MockOpenAI.return_value
            mock_completion = MagicMock()
            mock_completion.choices[0].message.content = "Mocked Response"
            mock_client.chat.completions.create.return_value = mock_completion
            
            target = OpenAICompatibleTarget(provider="openai", api_key="sk-test")
            response = target.query("hello")
            
            assert response == "Mocked Response"
            mock_client.chat.completions.create.assert_called_once()


class TestGeminiTarget:
    def test_query(self):
        # We need to mock the Client class ON the retrieved mock module
        with patch.object(mock_genai, "Client") as MockClient:
            mock_instance = MockClient.return_value
            mock_response = MagicMock()
            mock_response.text = "Gemini Response"
            mock_instance.models.generate_content.return_value = mock_response

            target = GeminiTarget(api_key="AIzaTest")
            response = target.query("hello")

            assert response == "Gemini Response"
            mock_instance.models.generate_content.assert_called_once()


class TestMultiAgentTarget:
    def test_pipeline(self):
        # Mocking time.sleep to speed up tests
        with patch("time.sleep"):
             with patch.object(mock_genai, "Client") as MockClient:
                mock_instance = MockClient.return_value
                mock_response = MagicMock()
                mock_response.text = "Agent Output"
                mock_instance.models.generate_content.return_value = mock_response

                target = MultiAgentTarget(api_key="AIzaTest")
                response = target.query("task")

                # Should call user prompt -> orchestrator -> analyst -> generator
                # 3 calls total
                assert mock_instance.models.generate_content.call_count == 3
                assert response == "Agent Output"
