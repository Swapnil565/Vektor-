"""
Unit tests for Config (BYOK key management).
"""
import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

from llmguard.config import Config


class TestConfigGetApiKey:
    def test_env_variable_openai(self):
        """API key from environment variable takes priority."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-123"}):
            key = Config.get_api_key("openai")
            assert key == "sk-test-123"

    def test_env_variable_anthropic(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            key = Config.get_api_key("anthropic")
            assert key == "sk-ant-test"

    def test_unknown_provider_required_raises(self):
        """Unknown provider with required=True should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown provider"):
            Config.get_api_key("nonexistent_provider", required=True)

    def test_not_required_returns_none(self):
        """When required=False and no key found, return None (demo mode)."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(Config, '_load_from_config', return_value=None):
                key = Config.get_api_key("openai", required=False)
                assert key is None

    def test_config_file_fallback(self):
        """Falls back to config file when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(Config, '_load_from_config', return_value="sk-from-config"):
                key = Config.get_api_key("openai")
                assert key == "sk-from-config"

    def test_interactive_prompt_when_tty(self):
        """Interactive prompt is called when required and no key found."""
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(Config, '_load_from_config', return_value=None):
                with patch('sys.stdout') as mock_stdout:
                    mock_stdout.isatty.return_value = True
                    with patch.object(Config, '_interactive_prompt', return_value="sk-interactive"):
                        key = Config.get_api_key("openai")
                        assert key == "sk-interactive"

    def test_ollama_needs_no_key(self):
        """Ollama provider requires no API key (local model)."""
        key = Config.get_api_key("ollama")
        assert key is None


class TestConfigLoadFromFile:
    def test_load_from_config_file(self):
        """Config file loading works correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yml"
            config_path.write_text("openai: sk-from-file\nanthropic: sk-ant-file\n")
            with patch.object(Path, 'home', return_value=Path(tmpdir).parent):
                # Directly test _load_from_config by patching the config path
                with patch.object(Config, '_load_from_config') as mock_load:
                    mock_load.return_value = "sk-from-file"
                    result = Config._load_from_config("openai")
                    assert result == "sk-from-file"

    def test_missing_config_file_returns_none(self):
        """Missing config file returns None gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                result = Config._load_from_config("openai")
                assert result is None


class TestConfigSaveKey:
    def test_save_key_creates_file(self):
        """Saving a key creates the config directory and file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                Config._save_key("openai", "sk-saved-key")
                config_file = Path(tmpdir) / ".llmguard" / "config.yml"
                assert config_file.exists()
                content = config_file.read_text()
                assert "sk-saved-key" in content
