"""
TestAI Agent - Base LLM Provider

Abstract base class for all LLM providers.
Designed for human-like QA responses.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Literal
from enum import Enum


class ModelCapability(Enum):
    """What the model is good at."""
    CLASSIFICATION = "classification"      # Quick categorization
    GENERATION = "generation"              # Creative content
    ANALYSIS = "analysis"                  # Deep understanding
    CODE = "code"                          # Code generation
    REASONING = "reasoning"                # Complex logic
    CONVERSATION = "conversation"          # Natural dialogue


@dataclass
class Message:
    """A message in a conversation."""
    role: Literal["system", "user", "assistant"]
    content: str

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class LLMResponse:
    """Response from an LLM - human readable."""
    content: str
    model: str
    provider: str
    tokens_used: int = 0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: float = 0.0
    cost_estimate: float = 0.0
    finish_reason: str = "stop"
    raw_response: Optional[Dict[str, Any]] = None

    @property
    def is_complete(self) -> bool:
        """Check if response completed normally."""
        return self.finish_reason == "stop"

    def summarize(self) -> str:
        """Human-friendly summary."""
        return (
            f"Response from {self.provider}/{self.model} "
            f"({self.tokens_used} tokens, ${self.cost_estimate:.4f})"
        )


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""
    api_key: str
    base_url: Optional[str] = None
    default_model: str = ""
    max_retries: int = 3
    timeout_seconds: int = 60
    temperature: float = 0.7
    max_tokens: int = 4096


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All providers must implement:
    - complete(): Single message completion
    - chat(): Multi-turn conversation
    - get_capabilities(): What this model does well
    """

    def __init__(self, config: ProviderConfig):
        self.config = config
        self._name = self.__class__.__name__.replace("Provider", "")

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Simple completion - single prompt in, response out.

        Args:
            prompt: The user's request
            system: Optional system prompt for context
            temperature: Creativity (0-1)
            max_tokens: Max response length

        Returns:
            LLMResponse with the completion
        """
        pass

    @abstractmethod
    async def chat(
        self,
        messages: List[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Multi-turn conversation.

        Args:
            messages: List of Message objects
            temperature: Creativity (0-1)
            max_tokens: Max response length

        Returns:
            LLMResponse with the assistant's reply
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> List[ModelCapability]:
        """What this model is good at."""
        pass

    @abstractmethod
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost in USD for this usage."""
        pass

    def supports(self, capability: ModelCapability) -> bool:
        """Check if model supports a capability."""
        return capability in self.get_capabilities()

    def get_status(self) -> Dict[str, Any]:
        """Get provider status."""
        return {
            "name": self.name,
            "model": self.config.default_model,
            "capabilities": [c.value for c in self.get_capabilities()],
            "ready": bool(self.config.api_key),
        }


# Registry of available providers
_PROVIDER_REGISTRY: Dict[str, type] = {}


def register_provider(name: str):
    """Decorator to register a provider class."""
    def decorator(cls):
        _PROVIDER_REGISTRY[name.lower()] = cls
        return cls
    return decorator


def get_provider(name: str, config: ProviderConfig) -> LLMProvider:
    """Get a provider instance by name."""
    name_lower = name.lower()
    if name_lower not in _PROVIDER_REGISTRY:
        available = ", ".join(_PROVIDER_REGISTRY.keys())
        raise ValueError(f"Unknown provider: {name}. Available: {available}")
    return _PROVIDER_REGISTRY[name_lower](config)


def list_providers() -> List[str]:
    """List all registered providers."""
    return list(_PROVIDER_REGISTRY.keys())
