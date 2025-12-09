"""
LLM Client for UAC AI Parser.

Provides abstraction over different LLM providers (Ollama, OpenAI, etc.)
with support for streaming and structured outputs.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterator

import httpx

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM."""
    
    content: str
    model: str
    tokens_used: int | None = None
    finish_reason: str | None = None
    raw_response: dict[str, Any] | None = None


@dataclass  
class LLMConfig:
    """Configuration for LLM client."""
    
    provider: str = "ollama"
    model: str = "llama3"
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: float = 120.0
    
    # Ollama-specific
    num_ctx: int = 8192  # Context window
    
    # OpenAI-specific
    organization: str | None = None


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate a response from the LLM."""
        pass
    
    @abstractmethod
    def generate_stream(
        self, 
        prompt: str, 
        system_prompt: str | None = None
    ) -> Iterator[str]:
        """Generate a streaming response."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the LLM service is available."""
        pass


class OllamaClient(BaseLLMClient):
    """
    Client for Ollama local LLM server.
    
    Ollama provides easy local LLM inference with models like
    Llama3, Mistral, etc.
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self._client = httpx.Client(timeout=config.timeout)
    
    def is_available(self) -> bool:
        """Check if Ollama server is running."""
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:
            return False
    
    def list_models(self) -> list[str]:
        """List available models in Ollama."""
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.warning(f"Failed to list Ollama models: {e}")
        return []
    
    def pull_model(self, model: str) -> bool:
        """Pull a model if not available."""
        try:
            response = self._client.post(
                f"{self.base_url}/api/pull",
                json={"name": model},
                timeout=600.0,  # Models can take a while to download
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False
    
    def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate a response using Ollama."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
            }
        }
        
        try:
            response = self._client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()
            
            data = response.json()
            
            return LLMResponse(
                content=data.get("message", {}).get("content", ""),
                model=self.config.model,
                tokens_used=data.get("eval_count"),
                finish_reason=data.get("done_reason"),
                raw_response=data,
            )
            
        except httpx.HTTPError as e:
            logger.error(f"Ollama API error: {e}")
            raise RuntimeError(f"Ollama API error: {e}")
    
    def generate_stream(
        self, 
        prompt: str, 
        system_prompt: str | None = None
    ) -> Iterator[str]:
        """Generate a streaming response."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
            }
        }
        
        try:
            with self._client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as response:
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line)
                        content = data.get("message", {}).get("content", "")
                        if content:
                            yield content
                        
                        if data.get("done"):
                            break
                            
        except httpx.HTTPError as e:
            logger.error(f"Ollama streaming error: {e}")
            raise RuntimeError(f"Ollama streaming error: {e}")
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


class OpenAIClient(BaseLLMClient):
    """
    Client for OpenAI API.
    
    Can also be used with OpenAI-compatible APIs like
    Azure OpenAI, LocalAI, etc.
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        
        headers = {
            "Content-Type": "application/json",
        }
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        if config.organization:
            headers["OpenAI-Organization"] = config.organization
        
        self._client = httpx.Client(
            timeout=config.timeout,
            headers=headers,
        )
    
    def is_available(self) -> bool:
        """Check if OpenAI API is accessible."""
        try:
            response = self._client.get(f"{self.base_url}/models")
            return response.status_code == 200
        except Exception:
            return False
    
    def generate(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        """Generate a response using OpenAI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        
        try:
            response = self._client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
            )
            response.raise_for_status()
            
            data = response.json()
            choice = data.get("choices", [{}])[0]
            usage = data.get("usage", {})
            
            return LLMResponse(
                content=choice.get("message", {}).get("content", ""),
                model=self.config.model,
                tokens_used=usage.get("total_tokens"),
                finish_reason=choice.get("finish_reason"),
                raw_response=data,
            )
            
        except httpx.HTTPError as e:
            logger.error(f"OpenAI API error: {e}")
            raise RuntimeError(f"OpenAI API error: {e}")
    
    def generate_stream(
        self, 
        prompt: str, 
        system_prompt: str | None = None
    ) -> Iterator[str]:
        """Generate a streaming response."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        
        try:
            with self._client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                json=payload,
            ) as response:
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        
                        data = json.loads(data_str)
                        content = data.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if content:
                            yield content
                            
        except httpx.HTTPError as e:
            logger.error(f"OpenAI streaming error: {e}")
            raise RuntimeError(f"OpenAI streaming error: {e}")
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


class LLMClient:
    """
    Factory class for creating LLM clients.
    
    Example:
        ```python
        config = LLMConfig(provider="ollama", model="llama3.1")
        client = LLMClient.create(config)
        
        response = client.generate("Analyze this process list...")
        print(response.content)
        ```
    """
    
    @staticmethod
    def create(config: LLMConfig) -> BaseLLMClient:
        """Create an LLM client based on configuration."""
        provider = config.provider.lower()
        
        if provider == "ollama":
            return OllamaClient(config)
        elif provider in ("openai", "azure"):
            return OpenAIClient(config)
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")
    
    @staticmethod
    def from_env() -> BaseLLMClient:
        """Create client from environment variables."""
        import os
        
        provider = os.getenv("UAC_AI_LLM_PROVIDER", "ollama")
        model = os.getenv("UAC_AI_LLM_MODEL", "llama3.1")
        base_url = os.getenv(
            "UAC_AI_LLM_URL",
            "http://localhost:11434" if provider == "ollama" else "https://api.openai.com/v1"
        )
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("UAC_AI_API_KEY")
        
        config = LLMConfig(
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key,
        )
        
        return LLMClient.create(config)
