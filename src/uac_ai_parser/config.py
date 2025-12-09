"""
Configuration management for UAC AI Parser.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LLMSettings:
    """LLM configuration settings."""
    
    provider: str = "ollama"
    model: str = "llama3"
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 4096
    num_ctx: int = 8192


@dataclass
class VectorStoreSettings:
    """Vector store configuration."""
    
    type: str = "chroma"
    persist_directory: str = "~/.uac-ai/chroma"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"


@dataclass
class AnalysisSettings:
    """Analysis configuration."""
    
    chunk_size: int = 2000
    chunk_overlap: int = 200
    max_tokens: int = 4096


@dataclass
class AnomalySettings:
    """Anomaly detection configuration."""
    
    score_threshold: float = 0.7
    enabled_detectors: list[str] = field(default_factory=lambda: [
        "deleted_binaries",
        "suspicious_cron",
        "hidden_processes",
        "unusual_network",
        "privilege_changes",
    ])


@dataclass
class PlasoSettings:
    """Plaso integration settings."""
    
    docker_image: str = "log2timeline/plaso:latest"
    timeout: int = 3600


@dataclass
class OutputSettings:
    """Output configuration."""
    
    default_format: str = "json"
    include_raw_artifacts: bool = False
    timestamp_format: str = "%Y-%m-%d %H:%M:%S UTC"


@dataclass
class Config:
    """Main configuration container."""
    
    llm: LLMSettings = field(default_factory=LLMSettings)
    vector_store: VectorStoreSettings = field(default_factory=VectorStoreSettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    anomaly: AnomalySettings = field(default_factory=AnomalySettings)
    plaso: PlasoSettings = field(default_factory=PlasoSettings)
    output: OutputSettings = field(default_factory=OutputSettings)
    
    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Config":
        """
        Load configuration from file.
        
        Searches in order:
        1. Provided path
        2. Current directory (./uac-ai.yaml)
        3. User config (~/.uac-ai/config.yaml)
        4. Default values
        """
        config = cls()
        
        # Determine config file path
        paths_to_try = []
        
        if config_path:
            paths_to_try.append(Path(config_path))
        
        paths_to_try.extend([
            Path("./uac-ai.yaml"),
            Path("./uac-ai.yml"),
            Path.home() / ".uac-ai" / "config.yaml",
            Path.home() / ".uac-ai" / "config.yml",
        ])
        
        # Find and load config file
        for path in paths_to_try:
            if path.exists():
                config._load_from_file(path)
                break
        
        # Override with environment variables
        config._load_from_env()
        
        return config
    
    def _load_from_file(self, path: Path) -> None:
        """Load settings from YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        
        if "llm" in data:
            for key, value in data["llm"].items():
                if hasattr(self.llm, key):
                    setattr(self.llm, key, value)
        
        if "vector_store" in data:
            for key, value in data["vector_store"].items():
                if hasattr(self.vector_store, key):
                    setattr(self.vector_store, key, value)
        
        if "analysis" in data:
            for key, value in data["analysis"].items():
                if hasattr(self.analysis, key):
                    setattr(self.analysis, key, value)
        
        if "anomaly" in data:
            for key, value in data["anomaly"].items():
                if hasattr(self.anomaly, key):
                    setattr(self.anomaly, key, value)
        
        if "plaso" in data:
            for key, value in data["plaso"].items():
                if hasattr(self.plaso, key):
                    setattr(self.plaso, key, value)
        
        if "output" in data:
            for key, value in data["output"].items():
                if hasattr(self.output, key):
                    setattr(self.output, key, value)
    
    def _load_from_env(self) -> None:
        """Load settings from environment variables."""
        env_mappings = {
            "UAC_AI_LLM_PROVIDER": ("llm", "provider"),
            "UAC_AI_LLM_MODEL": ("llm", "model"),
            "UAC_AI_LLM_URL": ("llm", "base_url"),
            "UAC_AI_API_KEY": ("llm", "api_key"),
            "OPENAI_API_KEY": ("llm", "api_key"),
            "UAC_AI_TEMPERATURE": ("llm", "temperature"),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                section_obj = getattr(self, section)
                
                # Type conversion
                current = getattr(section_obj, key)
                if isinstance(current, float):
                    value = float(value)
                elif isinstance(current, int):
                    value = int(value)
                elif isinstance(current, bool):
                    value = value.lower() in ("true", "1", "yes")
                
                setattr(section_obj, key, value)
    
    def save(self, path: str | Path) -> None:
        """Save configuration to file."""
        data = {
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "base_url": self.llm.base_url,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
            },
            "vector_store": {
                "type": self.vector_store.type,
                "persist_directory": self.vector_store.persist_directory,
                "embedding_model": self.vector_store.embedding_model,
            },
            "analysis": {
                "chunk_size": self.analysis.chunk_size,
                "chunk_overlap": self.analysis.chunk_overlap,
                "max_tokens": self.analysis.max_tokens,
            },
            "anomaly": {
                "score_threshold": self.anomaly.score_threshold,
                "enabled_detectors": self.anomaly.enabled_detectors,
            },
            "plaso": {
                "docker_image": self.plaso.docker_image,
                "timeout": self.plaso.timeout,
            },
            "output": {
                "default_format": self.output.default_format,
                "include_raw_artifacts": self.output.include_raw_artifacts,
                "timestamp_format": self.output.timestamp_format,
            },
        }
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Default config file template
DEFAULT_CONFIG_TEMPLATE = """# UAC AI Parser Configuration

# LLM Configuration
llm:
  provider: ollama  # ollama, openai, anthropic
  model: llama3.1
  base_url: http://localhost:11434
  temperature: 0.1
  
# Vector Store Configuration
vector_store:
  type: chroma
  persist_directory: ~/.uac-ai/chroma
  embedding_model: sentence-transformers/all-MiniLM-L6-v2

# Analysis Configuration
analysis:
  chunk_size: 2000
  chunk_overlap: 200
  max_tokens: 4096
  
# Anomaly Detection
anomaly:
  score_threshold: 0.7
  enabled_detectors:
    - deleted_binaries
    - suspicious_cron
    - hidden_processes
    - unusual_network
    - privilege_changes
    
# Plaso Integration
plaso:
  docker_image: log2timeline/plaso:latest
  timeout: 3600
  
# Output Configuration
output:
  default_format: json
  include_raw_artifacts: false
  timestamp_format: "%Y-%m-%d %H:%M:%S UTC"
"""


def create_default_config(path: str | Path | None = None) -> Path:
    """Create default configuration file."""
    if path is None:
        path = Path.home() / ".uac-ai" / "config.yaml"
    
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, "w") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)
    
    return path
