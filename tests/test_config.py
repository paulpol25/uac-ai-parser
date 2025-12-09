"""
Tests for the configuration module.
"""

import pytest
import tempfile
from pathlib import Path

from uac_ai_parser.config import Config


class TestConfig:
    """Tests for Config dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.llm_provider == "ollama"
        assert config.llm_model == "llama3"
        assert config.temperature >= 0 and config.temperature <= 1
    
    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        config_dict = {
            "llm_provider": "openai",
            "llm_model": "gpt-4",
            "temperature": 0.5,
        }
        
        config = Config.from_dict(config_dict)
        
        assert config.llm_provider == "openai"
        assert config.llm_model == "gpt-4"
        assert config.temperature == 0.5
    
    def test_config_from_yaml(self, tmp_path):
        """Test loading config from YAML file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
llm_provider: openai
llm_model: gpt-4-turbo
temperature: 0.2
chroma_persist_dir: /custom/path
max_chunk_size: 200
""")
        
        config = Config.from_yaml(config_file)
        
        assert config.llm_provider == "openai"
        assert config.llm_model == "gpt-4-turbo"
        assert config.temperature == 0.2
        assert config.chroma_persist_dir == "/custom/path"
        assert config.max_chunk_size == 200
    
    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        config = Config(
            llm_provider="openai",
            llm_model="gpt-4",
            temperature=0.3,
        )
        
        config_dict = config.to_dict()
        
        assert config_dict["llm_provider"] == "openai"
        assert config_dict["llm_model"] == "gpt-4"
        assert config_dict["temperature"] == 0.3
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid providers
        for provider in ["ollama", "openai"]:
            config = Config(llm_provider=provider)
            assert config.llm_provider == provider
    
    def test_config_update(self):
        """Test updating configuration."""
        config = Config()
        original_model = config.llm_model
        
        config = Config(
            llm_provider=config.llm_provider,
            llm_model="new-model",
            temperature=config.temperature,
        )
        
        assert config.llm_model == "new-model"
        assert config.llm_model != original_model
    
    def test_missing_yaml_file(self, tmp_path):
        """Test handling of missing YAML file."""
        nonexistent = tmp_path / "nonexistent.yaml"
        
        with pytest.raises(FileNotFoundError):
            Config.from_yaml(nonexistent)
    
    def test_invalid_yaml(self, tmp_path):
        """Test handling of invalid YAML."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("{{{{invalid yaml content")
        
        with pytest.raises(Exception):  # Could be yaml.YAMLError or similar
            Config.from_yaml(config_file)
    
    def test_partial_config(self, tmp_path):
        """Test loading partial config (uses defaults for missing)."""
        config_file = tmp_path / "partial.yaml"
        config_file.write_text("""
temperature: 0.8
""")
        
        config = Config.from_yaml(config_file)
        
        # Should use default for llm_provider
        assert config.llm_provider == "ollama"
        # Should use specified temperature
        assert config.temperature == 0.8


class TestConfigOptions:
    """Tests for specific configuration options."""
    
    def test_ollama_config(self):
        """Test Ollama-specific configuration."""
        config = Config(
            llm_provider="ollama",
            llm_model="llama3:8b",
            ollama_base_url="http://localhost:11434",
        )
        
        assert config.llm_provider == "ollama"
        assert config.ollama_base_url == "http://localhost:11434"
    
    def test_openai_config(self):
        """Test OpenAI-specific configuration."""
        config = Config(
            llm_provider="openai",
            llm_model="gpt-4",
            openai_api_key="test-key",
        )
        
        assert config.llm_provider == "openai"
        assert config.openai_api_key == "test-key"
    
    def test_vectorstore_config(self):
        """Test vector store configuration."""
        config = Config(
            chroma_persist_dir="/custom/chroma",
            embedding_model="all-MiniLM-L6-v2",
        )
        
        assert config.chroma_persist_dir == "/custom/chroma"
        assert config.embedding_model == "all-MiniLM-L6-v2"
    
    def test_plaso_config(self):
        """Test Plaso integration configuration."""
        config = Config(
            plaso_docker_image="log2timeline/plaso:latest",
            plaso_timeout=7200,
        )
        
        assert config.plaso_docker_image == "log2timeline/plaso:latest"
        assert config.plaso_timeout == 7200


class TestConfigProfiles:
    """Tests for configuration profiles."""
    
    def test_development_profile(self, tmp_path):
        """Test development profile."""
        config_file = tmp_path / "dev.yaml"
        config_file.write_text("""
# Development profile
llm_provider: ollama
llm_model: llama3
temperature: 0.7
max_chunk_size: 50
debug: true
""")
        
        config = Config.from_yaml(config_file)
        
        assert config.llm_provider == "ollama"
        assert config.temperature == 0.7
    
    def test_production_profile(self, tmp_path):
        """Test production profile."""
        config_file = tmp_path / "prod.yaml"
        config_file.write_text("""
# Production profile
llm_provider: openai
llm_model: gpt-4-turbo
temperature: 0.1
max_chunk_size: 200
""")
        
        config = Config.from_yaml(config_file)
        
        assert config.llm_provider == "openai"
        assert config.temperature == 0.1
