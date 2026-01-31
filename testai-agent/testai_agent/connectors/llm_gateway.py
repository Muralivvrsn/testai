"""
TestAI Agent - Model-Agnostic LLM Gateway

Supports multiple LLM providers with unified interface:
- DeepSeek (primary, cost-effective)
- OpenAI (GPT-4, GPT-3.5)
- Anthropic Claude
- Google Gemini

Features:
- Strict usage limits per provider
- Automatic fallback on failure
- Cost tracking
- Human-readable errors
"""

import os
import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
import aiohttp


class LLMProvider(Enum):
    """Supported LLM providers."""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


@dataclass
class LLMMessage:
    """A message in a conversation."""
    role: str  # system, user, assistant
    content: str

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class LLMResponse:
    """Response from an LLM call."""
    content: str
    provider: LLMProvider
    model: str
    tokens_used: int
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    finish_reason: str = "stop"
    raw_response: Optional[Dict] = None


@dataclass
class UsageTracker:
    """Tracks API usage with limits."""
    provider: LLMProvider
    max_calls: int
    calls_made: int = 0
    tokens_used: int = 0
    total_cost: float = 0.0
    errors: int = 0

    @property
    def remaining_calls(self) -> int:
        return max(0, self.max_calls - self.calls_made)

    @property
    def is_exhausted(self) -> bool:
        return self.calls_made >= self.max_calls

    def record_call(self, tokens: int, cost: float):
        self.calls_made += 1
        self.tokens_used += tokens
        self.total_cost += cost

    def record_error(self):
        self.errors += 1

    def get_status(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.value,
            "calls": f"{self.calls_made}/{self.max_calls}",
            "remaining": self.remaining_calls,
            "tokens_used": self.tokens_used,
            "total_cost": f"${self.total_cost:.4f}",
            "errors": self.errors,
            "status": "Exhausted" if self.is_exhausted else "Active"
        }


class BaseLLMConnector(ABC):
    """Base class for LLM connectors."""

    def __init__(
        self,
        api_key: str,
        model: str,
        max_calls: int = 50,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        timeout: int = 60
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.usage = UsageTracker(
            provider=self.provider,
            max_calls=max_calls
        )

    @property
    @abstractmethod
    def provider(self) -> LLMProvider:
        """Return the provider enum."""
        pass

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Complete a prompt."""
        pass

    @abstractmethod
    async def chat(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """Multi-turn chat."""
        pass

    def check_limits(self) -> bool:
        """Check if we can make another call."""
        if self.usage.is_exhausted:
            raise UsageLimitExceeded(
                f"{self.provider.value} usage limit reached "
                f"({self.usage.calls_made}/{self.usage.max_calls} calls)"
            )
        return True


class UsageLimitExceeded(Exception):
    """Raised when API usage limit is exceeded."""
    pass


class DeepSeekConnector(BaseLLMConnector):
    """
    DeepSeek API connector.

    Pricing (per 1M tokens):
    - Input: $0.14
    - Output: $0.28
    """

    BASE_URL = "https://api.deepseek.com/v1"
    PRICING = {"input": 0.14, "output": 0.28}

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.DEEPSEEK

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        messages = []
        if system:
            messages.append(LLMMessage(role="system", content=system))
        messages.append(LLMMessage(role="user", content=prompt))

        return await self.chat(messages, **kwargs)

    async def chat(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        self.check_limits()

        temp = kwargs.get('temperature', self.temperature)
        max_tok = kwargs.get('max_tokens', self.max_tokens)

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temp,
            "max_tokens": max_tok,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        start = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.BASE_URL}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    data = await response.json()

                    if response.status != 200:
                        self.usage.record_error()
                        error_msg = data.get("error", {}).get("message", str(data))
                        raise Exception(f"DeepSeek API error: {error_msg}")

                    latency = (time.time() - start) * 1000

                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                    total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

                    # Calculate cost
                    cost = (
                        (prompt_tokens / 1_000_000) * self.PRICING["input"] +
                        (completion_tokens / 1_000_000) * self.PRICING["output"]
                    )

                    # Record usage
                    self.usage.record_call(total_tokens, cost)

                    choice = data.get("choices", [{}])[0]

                    return LLMResponse(
                        content=choice.get("message", {}).get("content", ""),
                        provider=self.provider,
                        model=self.model,
                        tokens_used=total_tokens,
                        tokens_prompt=prompt_tokens,
                        tokens_completion=completion_tokens,
                        latency_ms=latency,
                        cost_usd=cost,
                        finish_reason=choice.get("finish_reason", "stop"),
                        raw_response=data
                    )

        except asyncio.TimeoutError:
            self.usage.record_error()
            raise Exception("DeepSeek API request timed out")

        except aiohttp.ClientError as e:
            self.usage.record_error()
            raise Exception(f"Network error: {str(e)}")


class OpenAIConnector(BaseLLMConnector):
    """
    OpenAI API connector.

    Pricing varies by model (GPT-4, GPT-3.5-turbo).
    """

    BASE_URL = "https://api.openai.com/v1"
    PRICING = {
        "gpt-4": {"input": 30.0, "output": 60.0},
        "gpt-4-turbo": {"input": 10.0, "output": 30.0},
        "gpt-3.5-turbo": {"input": 0.5, "output": 1.5},
    }

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OPENAI

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        messages = []
        if system:
            messages.append(LLMMessage(role="system", content=system))
        messages.append(LLMMessage(role="user", content=prompt))

        return await self.chat(messages, **kwargs)

    async def chat(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        self.check_limits()

        temp = kwargs.get('temperature', self.temperature)
        max_tok = kwargs.get('max_tokens', self.max_tokens)

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temp,
            "max_tokens": max_tok,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        start = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.BASE_URL}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    data = await response.json()

                    if response.status != 200:
                        self.usage.record_error()
                        error_msg = data.get("error", {}).get("message", str(data))
                        raise Exception(f"OpenAI API error: {error_msg}")

                    latency = (time.time() - start) * 1000

                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                    total_tokens = prompt_tokens + completion_tokens

                    # Get pricing for model
                    pricing = self.PRICING.get(self.model, self.PRICING["gpt-3.5-turbo"])
                    cost = (
                        (prompt_tokens / 1_000_000) * pricing["input"] +
                        (completion_tokens / 1_000_000) * pricing["output"]
                    )

                    self.usage.record_call(total_tokens, cost)

                    choice = data.get("choices", [{}])[0]

                    return LLMResponse(
                        content=choice.get("message", {}).get("content", ""),
                        provider=self.provider,
                        model=self.model,
                        tokens_used=total_tokens,
                        tokens_prompt=prompt_tokens,
                        tokens_completion=completion_tokens,
                        latency_ms=latency,
                        cost_usd=cost,
                        finish_reason=choice.get("finish_reason", "stop"),
                        raw_response=data
                    )

        except asyncio.TimeoutError:
            self.usage.record_error()
            raise Exception("OpenAI API request timed out")


class AnthropicConnector(BaseLLMConnector):
    """
    Anthropic Claude API connector.
    """

    BASE_URL = "https://api.anthropic.com/v1"
    PRICING = {
        "claude-3-opus": {"input": 15.0, "output": 75.0},
        "claude-3-sonnet": {"input": 3.0, "output": 15.0},
        "claude-3-haiku": {"input": 0.25, "output": 1.25},
    }

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.ANTHROPIC

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        messages = [LLMMessage(role="user", content=prompt)]
        return await self.chat(messages, system=system, **kwargs)

    async def chat(
        self,
        messages: List[LLMMessage],
        system: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        self.check_limits()

        temp = kwargs.get('temperature', self.temperature)
        max_tok = kwargs.get('max_tokens', self.max_tokens)

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages if m.role != "system"],
            "temperature": temp,
            "max_tokens": max_tok,
        }

        if system:
            payload["system"] = system

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }

        start = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.BASE_URL}/messages",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    data = await response.json()

                    if response.status != 200:
                        self.usage.record_error()
                        error_msg = data.get("error", {}).get("message", str(data))
                        raise Exception(f"Anthropic API error: {error_msg}")

                    latency = (time.time() - start) * 1000

                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("input_tokens", 0)
                    completion_tokens = usage.get("output_tokens", 0)
                    total_tokens = prompt_tokens + completion_tokens

                    pricing = self.PRICING.get(self.model, self.PRICING["claude-3-sonnet"])
                    cost = (
                        (prompt_tokens / 1_000_000) * pricing["input"] +
                        (completion_tokens / 1_000_000) * pricing["output"]
                    )

                    self.usage.record_call(total_tokens, cost)

                    content = ""
                    for block in data.get("content", []):
                        if block.get("type") == "text":
                            content += block.get("text", "")

                    return LLMResponse(
                        content=content,
                        provider=self.provider,
                        model=self.model,
                        tokens_used=total_tokens,
                        tokens_prompt=prompt_tokens,
                        tokens_completion=completion_tokens,
                        latency_ms=latency,
                        cost_usd=cost,
                        finish_reason=data.get("stop_reason", "end_turn"),
                        raw_response=data
                    )

        except asyncio.TimeoutError:
            self.usage.record_error()
            raise Exception("Anthropic API request timed out")


class LLMGateway:
    """
    Model-Agnostic LLM Gateway.

    Manages multiple providers with:
    - Usage limits per provider
    - Automatic fallback
    - Cost tracking
    - Unified interface

    Usage:
        gateway = LLMGateway()
        gateway.add_provider(
            DeepSeekConnector(api_key="sk-xxx", model="deepseek-chat", max_calls=10)
        )

        response = await gateway.complete("Generate test cases for login")
    """

    def __init__(self, default_provider: Optional[LLMProvider] = None):
        self.connectors: Dict[LLMProvider, BaseLLMConnector] = {}
        self.default_provider = default_provider
        self._callbacks: List[Callable] = []

    def add_provider(self, connector: BaseLLMConnector):
        """Add a provider connector."""
        self.connectors[connector.provider] = connector
        if self.default_provider is None:
            self.default_provider = connector.provider

    def set_default(self, provider: LLMProvider):
        """Set the default provider."""
        if provider not in self.connectors:
            raise ValueError(f"Provider {provider.value} not configured")
        self.default_provider = provider

    def get_connector(self, provider: Optional[LLMProvider] = None) -> BaseLLMConnector:
        """Get a connector by provider."""
        provider = provider or self.default_provider
        if provider not in self.connectors:
            raise ValueError(f"Provider {provider.value} not configured")
        return self.connectors[provider]

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        provider: Optional[LLMProvider] = None,
        fallback: bool = True,
        **kwargs
    ) -> LLMResponse:
        """
        Complete a prompt with optional fallback.
        """
        target_provider = provider or self.default_provider
        errors = []

        # Try requested provider first
        if target_provider in self.connectors:
            try:
                connector = self.connectors[target_provider]
                return await connector.complete(prompt, system, **kwargs)
            except UsageLimitExceeded as e:
                errors.append(str(e))
            except Exception as e:
                errors.append(f"{target_provider.value}: {str(e)}")

        # Fallback to other providers
        if fallback:
            for prov, connector in self.connectors.items():
                if prov == target_provider:
                    continue
                if connector.usage.is_exhausted:
                    continue

                try:
                    return await connector.complete(prompt, system, **kwargs)
                except Exception as e:
                    errors.append(f"{prov.value}: {str(e)}")

        raise Exception(f"All providers failed: {'; '.join(errors)}")

    async def chat(
        self,
        messages: List[LLMMessage],
        provider: Optional[LLMProvider] = None,
        fallback: bool = True,
        **kwargs
    ) -> LLMResponse:
        """Multi-turn chat with optional fallback."""
        target_provider = provider or self.default_provider
        errors = []

        if target_provider in self.connectors:
            try:
                connector = self.connectors[target_provider]
                return await connector.chat(messages, **kwargs)
            except UsageLimitExceeded as e:
                errors.append(str(e))
            except Exception as e:
                errors.append(f"{target_provider.value}: {str(e)}")

        if fallback:
            for prov, connector in self.connectors.items():
                if prov == target_provider:
                    continue
                if connector.usage.is_exhausted:
                    continue

                try:
                    return await connector.chat(messages, **kwargs)
                except Exception as e:
                    errors.append(f"{prov.value}: {str(e)}")

        raise Exception(f"All providers failed: {'; '.join(errors)}")

    def get_usage_status(self) -> Dict[str, Any]:
        """Get usage status for all providers."""
        return {
            provider.value: connector.usage.get_status()
            for provider, connector in self.connectors.items()
        }

    def get_total_cost(self) -> float:
        """Get total cost across all providers."""
        return sum(c.usage.total_cost for c in self.connectors.values())


def create_gateway(
    deepseek_key: Optional[str] = None,
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    deepseek_max_calls: int = 10,
    openai_max_calls: int = 50,
    anthropic_max_calls: int = 50
) -> LLMGateway:
    """
    Create a gateway with configured providers.

    Environment variables:
    - DEEPSEEK_API_KEY
    - OPENAI_API_KEY
    - ANTHROPIC_API_KEY
    """
    gateway = LLMGateway()

    # DeepSeek (primary)
    ds_key = deepseek_key or os.getenv("DEEPSEEK_API_KEY")
    if ds_key:
        gateway.add_provider(DeepSeekConnector(
            api_key=ds_key,
            model="deepseek-chat",
            max_calls=deepseek_max_calls
        ))

    # OpenAI
    oai_key = openai_key or os.getenv("OPENAI_API_KEY")
    if oai_key:
        gateway.add_provider(OpenAIConnector(
            api_key=oai_key,
            model="gpt-3.5-turbo",
            max_calls=openai_max_calls
        ))

    # Anthropic
    ant_key = anthropic_key or os.getenv("ANTHROPIC_API_KEY")
    if ant_key:
        gateway.add_provider(AnthropicConnector(
            api_key=ant_key,
            model="claude-3-sonnet-20240229",
            max_calls=anthropic_max_calls
        ))

    return gateway
