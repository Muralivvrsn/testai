"""
TestAI Agent - Unified LLM Gateway

Model-agnostic gateway supporting multiple LLM providers.
Implements strict usage limits and citation tracking.

Design Philosophy:
- Cost efficiency: DeepSeek primary (cheap but good)
- Fallback support: Switch providers if one fails
- Zero hallucination: Track Brain citations in every response
- Hard limits: Max 10 calls for DeepSeek (budget protection)

Supported Providers:
- DeepSeek (primary, key: sk-c104455631bb433b801fc4a16042419c)
- OpenAI (fallback)
- Claude/Anthropic (fallback)
- Gemini/Google (fallback)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Literal, Callable
from enum import Enum
from datetime import datetime, timedelta
import asyncio
import json
import os

# Import existing gateway components
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.base import LLMProvider, LLMResponse, Message, ProviderConfig, ModelCapability
from gateway.deepseek import DeepSeekProvider


class ProviderName(Enum):
    """Supported LLM providers."""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


@dataclass
class UsageLimit:
    """Usage limits for a provider."""
    max_calls: int
    max_tokens: int = 100000
    reset_period_hours: int = 24

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_calls": self.max_calls,
            "max_tokens": self.max_tokens,
            "reset_period_hours": self.reset_period_hours,
        }


@dataclass
class UsageRecord:
    """Track usage for a provider."""
    calls: int = 0
    tokens: int = 0
    cost: float = 0.0
    last_reset: datetime = field(default_factory=datetime.now)
    history: List[Dict[str, Any]] = field(default_factory=list)

    def record_call(self, tokens_used: int, cost: float, context: str = ""):
        """Record an API call."""
        self.calls += 1
        self.tokens += tokens_used
        self.cost += cost
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "tokens": tokens_used,
            "cost": cost,
            "context": context[:100] if context else "",
        })

    def needs_reset(self, period_hours: int) -> bool:
        """Check if usage should be reset."""
        return datetime.now() - self.last_reset > timedelta(hours=period_hours)

    def reset(self):
        """Reset usage counters."""
        self.calls = 0
        self.tokens = 0
        self.cost = 0.0
        self.last_reset = datetime.now()
        # Keep last 10 history entries for debugging
        self.history = self.history[-10:]


class UsageTracker:
    """
    Tracks API usage across all providers.

    Enforces hard limits to prevent runaway costs.
    """

    # Default limits per provider
    DEFAULT_LIMITS = {
        ProviderName.DEEPSEEK: UsageLimit(max_calls=10, max_tokens=50000),
        ProviderName.OPENAI: UsageLimit(max_calls=20, max_tokens=100000),
        ProviderName.ANTHROPIC: UsageLimit(max_calls=20, max_tokens=100000),
        ProviderName.GEMINI: UsageLimit(max_calls=30, max_tokens=150000),
    }

    def __init__(self, custom_limits: Optional[Dict[ProviderName, UsageLimit]] = None):
        """
        Initialize usage tracker.

        Args:
            custom_limits: Override default limits for specific providers
        """
        self.limits = {**self.DEFAULT_LIMITS}
        if custom_limits:
            self.limits.update(custom_limits)

        self.usage: Dict[ProviderName, UsageRecord] = {
            provider: UsageRecord() for provider in ProviderName
        }

    def check_limit(self, provider: ProviderName) -> tuple[bool, str]:
        """
        Check if we can make another call to this provider.

        Returns:
            (can_call, reason) - True if allowed, with reason string
        """
        record = self.usage[provider]
        limit = self.limits[provider]

        # Auto-reset if period elapsed
        if record.needs_reset(limit.reset_period_hours):
            record.reset()

        if record.calls >= limit.max_calls:
            return False, f"Call limit reached ({record.calls}/{limit.max_calls})"

        if record.tokens >= limit.max_tokens:
            return False, f"Token limit reached ({record.tokens}/{limit.max_tokens})"

        return True, f"OK ({record.calls}/{limit.max_calls} calls used)"

    def record(self, provider: ProviderName, tokens: int, cost: float, context: str = ""):
        """Record a completed API call."""
        self.usage[provider].record_call(tokens, cost, context)

    def get_remaining(self, provider: ProviderName) -> Dict[str, int]:
        """Get remaining quota for a provider."""
        record = self.usage[provider]
        limit = self.limits[provider]
        return {
            "calls_remaining": max(0, limit.max_calls - record.calls),
            "tokens_remaining": max(0, limit.max_tokens - record.tokens),
            "calls_used": record.calls,
            "tokens_used": record.tokens,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get usage status for all providers."""
        status = {}
        for provider in ProviderName:
            record = self.usage[provider]
            limit = self.limits[provider]
            status[provider.value] = {
                "calls": f"{record.calls}/{limit.max_calls}",
                "tokens": f"{record.tokens}/{limit.max_tokens}",
                "cost": f"${record.cost:.4f}",
                "can_call": self.check_limit(provider)[0],
            }
        return status

    def format_status(self) -> str:
        """Human-readable status string."""
        lines = ["📊 API Usage Status:"]
        for provider in ProviderName:
            remaining = self.get_remaining(provider)
            can_call, reason = self.check_limit(provider)
            emoji = "✅" if can_call else "❌"
            lines.append(
                f"  {emoji} {provider.value}: "
                f"{remaining['calls_used']}/{self.limits[provider].max_calls} calls, "
                f"${self.usage[provider].cost:.4f}"
            )
        return "\n".join(lines)


@dataclass
class Citation:
    """Track where information came from (for zero-hallucination)."""
    source: str  # e.g., "Brain: Section 7.1 - Email Validation"
    chunk_id: str  # ChromaDB document ID
    confidence: float  # 0-1 relevance score
    excerpt: str = ""  # Short excerpt from source

    def format(self) -> str:
        """Format citation for display."""
        conf_pct = int(self.confidence * 100)
        return f"[Source: {self.source} ({conf_pct}% match)]"


@dataclass
class GatewayResponse:
    """
    Response from the gateway with citation tracking.

    Enhanced response that includes:
    - Standard LLM response content
    - Citations from Brain (for zero-hallucination)
    - Usage info for monitoring
    """
    content: str
    provider: ProviderName
    model: str
    tokens_used: int
    cost: float
    citations: List[Citation] = field(default_factory=list)
    thinking: str = ""  # Visible reasoning (if any)
    finish_reason: str = "stop"
    latency_ms: float = 0.0

    @property
    def is_complete(self) -> bool:
        return self.finish_reason == "stop"

    @property
    def has_citations(self) -> bool:
        return len(self.citations) > 0

    def format_with_citations(self) -> str:
        """Format response with citations appended."""
        result = self.content
        if self.citations:
            result += "\n\n---\n📚 Sources:\n"
            for i, citation in enumerate(self.citations, 1):
                result += f"  {i}. {citation.format()}\n"
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "provider": self.provider.value,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "cost": self.cost,
            "citations": [
                {"source": c.source, "confidence": c.confidence}
                for c in self.citations
            ],
            "finish_reason": self.finish_reason,
        }


class LLMGateway:
    """
    Unified gateway for multiple LLM providers.

    Features:
    - Multi-provider support with automatic fallback
    - Strict usage limits (max 10 calls for DeepSeek)
    - Citation tracking for zero-hallucination
    - Cost monitoring and budget protection

    Usage:
        gateway = LLMGateway(
            deepseek_key="sk-xxx",
            max_deepseek_calls=10,
        )

        response = await gateway.complete(
            prompt="Generate tests for login",
            citations=[Citation(source="Section 7.1", ...)],
        )

        print(response.format_with_citations())
    """

    def __init__(
        self,
        deepseek_key: Optional[str] = None,
        openai_key: Optional[str] = None,
        anthropic_key: Optional[str] = None,
        gemini_key: Optional[str] = None,
        max_deepseek_calls: int = 10,
        primary_provider: ProviderName = ProviderName.DEEPSEEK,
    ):
        """
        Initialize the gateway.

        Args:
            deepseek_key: DeepSeek API key (primary)
            openai_key: OpenAI API key (fallback)
            anthropic_key: Anthropic/Claude API key (fallback)
            gemini_key: Google Gemini API key (fallback)
            max_deepseek_calls: Max calls to DeepSeek (default: 10)
            primary_provider: Which provider to use first
        """
        # Store API keys
        self.api_keys = {
            ProviderName.DEEPSEEK: deepseek_key or os.getenv("DEEPSEEK_API_KEY"),
            ProviderName.OPENAI: openai_key or os.getenv("OPENAI_API_KEY"),
            ProviderName.ANTHROPIC: anthropic_key or os.getenv("ANTHROPIC_API_KEY"),
            ProviderName.GEMINI: gemini_key or os.getenv("GEMINI_API_KEY"),
        }

        self.primary_provider = primary_provider

        # Initialize usage tracker with custom DeepSeek limit
        custom_limits = {
            ProviderName.DEEPSEEK: UsageLimit(max_calls=max_deepseek_calls),
        }
        self.usage_tracker = UsageTracker(custom_limits)

        # Provider instances (created on demand)
        self._providers: Dict[ProviderName, LLMProvider] = {}

        # Fallback order
        self.fallback_order = [
            ProviderName.DEEPSEEK,
            ProviderName.OPENAI,
            ProviderName.ANTHROPIC,
            ProviderName.GEMINI,
        ]

        # Move primary to front
        if primary_provider in self.fallback_order:
            self.fallback_order.remove(primary_provider)
            self.fallback_order.insert(0, primary_provider)

    def _get_provider(self, name: ProviderName) -> Optional[LLMProvider]:
        """Get or create a provider instance."""
        if name in self._providers:
            return self._providers[name]

        api_key = self.api_keys.get(name)
        if not api_key:
            return None

        if name == ProviderName.DEEPSEEK:
            config = ProviderConfig(
                api_key=api_key,
                default_model="deepseek-chat",
            )
            self._providers[name] = DeepSeekProvider(config)
            return self._providers[name]

        # TODO: Implement other providers
        # For now, only DeepSeek is fully implemented
        return None

    def _select_provider(self) -> Optional[tuple[ProviderName, LLMProvider]]:
        """
        Select the best available provider.

        Checks limits and availability in fallback order.
        """
        for provider_name in self.fallback_order:
            # Check if we have an API key
            if not self.api_keys.get(provider_name):
                continue

            # Check usage limits
            can_call, reason = self.usage_tracker.check_limit(provider_name)
            if not can_call:
                continue

            # Try to get provider
            provider = self._get_provider(provider_name)
            if provider:
                return provider_name, provider

        return None

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        citations: Optional[List[Citation]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        force_provider: Optional[ProviderName] = None,
    ) -> GatewayResponse:
        """
        Complete a prompt with automatic provider selection.

        Args:
            prompt: The user's request
            system: System prompt for context
            citations: Brain citations to attach (for tracking)
            temperature: Creativity level (0-1)
            max_tokens: Maximum response length
            force_provider: Override automatic selection

        Returns:
            GatewayResponse with content and citations
        """
        citations = citations or []

        # Select provider
        if force_provider:
            can_call, reason = self.usage_tracker.check_limit(force_provider)
            if not can_call:
                return GatewayResponse(
                    content=f"Cannot use {force_provider.value}: {reason}",
                    provider=force_provider,
                    model="none",
                    tokens_used=0,
                    cost=0.0,
                    finish_reason="limit_reached",
                )
            provider = self._get_provider(force_provider)
            provider_name = force_provider
        else:
            selection = self._select_provider()
            if not selection:
                # No providers available
                status = self.usage_tracker.format_status()
                return GatewayResponse(
                    content=f"No providers available.\n\n{status}",
                    provider=ProviderName.DEEPSEEK,
                    model="none",
                    tokens_used=0,
                    cost=0.0,
                    finish_reason="no_provider",
                )
            provider_name, provider = selection

        # Make the API call
        try:
            import time
            start_time = time.time()

            response = await provider.complete(
                prompt=prompt,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            latency_ms = (time.time() - start_time) * 1000

            # Record usage
            self.usage_tracker.record(
                provider_name,
                response.tokens_used,
                response.cost_estimate,
                context=prompt[:50],
            )

            return GatewayResponse(
                content=response.content,
                provider=provider_name,
                model=response.model,
                tokens_used=response.tokens_used,
                cost=response.cost_estimate,
                citations=citations,
                finish_reason=response.finish_reason,
                latency_ms=latency_ms,
            )

        except Exception as e:
            # Record the failed attempt
            self.usage_tracker.record(provider_name, 0, 0.0, context=f"ERROR: {str(e)[:50]}")

            return GatewayResponse(
                content=f"Error calling {provider_name.value}: {str(e)}",
                provider=provider_name,
                model="error",
                tokens_used=0,
                cost=0.0,
                finish_reason="error",
            )

    async def chat(
        self,
        messages: List[Message],
        citations: Optional[List[Citation]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> GatewayResponse:
        """
        Multi-turn conversation with automatic provider selection.

        Args:
            messages: Conversation history
            citations: Brain citations to attach
            temperature: Creativity level
            max_tokens: Maximum response length

        Returns:
            GatewayResponse with assistant's reply
        """
        citations = citations or []

        selection = self._select_provider()
        if not selection:
            return GatewayResponse(
                content="No providers available. Check usage limits.",
                provider=ProviderName.DEEPSEEK,
                model="none",
                tokens_used=0,
                cost=0.0,
                finish_reason="no_provider",
            )

        provider_name, provider = selection

        try:
            response = await provider.chat(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            self.usage_tracker.record(
                provider_name,
                response.tokens_used,
                response.cost_estimate,
            )

            return GatewayResponse(
                content=response.content,
                provider=provider_name,
                model=response.model,
                tokens_used=response.tokens_used,
                cost=response.cost_estimate,
                citations=citations,
                finish_reason=response.finish_reason,
            )

        except Exception as e:
            return GatewayResponse(
                content=f"Error: {str(e)}",
                provider=provider_name,
                model="error",
                tokens_used=0,
                cost=0.0,
                finish_reason="error",
            )

    def get_usage_status(self) -> Dict[str, Any]:
        """Get current usage status."""
        return self.usage_tracker.get_status()

    def format_usage_status(self) -> str:
        """Get human-readable usage status."""
        return self.usage_tracker.format_status()

    def get_remaining_calls(self, provider: ProviderName = None) -> int:
        """Get remaining API calls for a provider (default: primary)."""
        provider = provider or self.primary_provider
        remaining = self.usage_tracker.get_remaining(provider)
        return remaining["calls_remaining"]

    def can_call(self, provider: ProviderName = None) -> bool:
        """Check if we can make another call."""
        provider = provider or self.primary_provider
        can, _ = self.usage_tracker.check_limit(provider)
        return can

    def get_status(self) -> Dict[str, Any]:
        """Get gateway status."""
        available = []
        for provider in ProviderName:
            if self.api_keys.get(provider):
                can_call, _ = self.usage_tracker.check_limit(provider)
                if can_call:
                    available.append(provider.value)

        return {
            "primary_provider": self.primary_provider.value,
            "available_providers": available,
            "usage": self.usage_tracker.get_status(),
            "ready": len(available) > 0,
        }


def create_gateway(
    deepseek_key: str = "sk-c104455631bb433b801fc4a16042419c",
    max_calls: int = 10,
) -> LLMGateway:
    """
    Create a pre-configured gateway with DeepSeek.

    Args:
        deepseek_key: DeepSeek API key
        max_calls: Maximum calls allowed (default: 10)

    Returns:
        Configured LLMGateway
    """
    return LLMGateway(
        deepseek_key=deepseek_key,
        max_deepseek_calls=max_calls,
    )


# Convenience function for quick testing
async def quick_test():
    """Quick test of the gateway."""
    gateway = create_gateway()

    print("🚀 TestAI Gateway Quick Test")
    print("=" * 40)
    print(gateway.format_usage_status())
    print()

    if gateway.can_call():
        print("💭 Testing completion...")
        response = await gateway.complete(
            prompt="Say hello in exactly 5 words.",
            system="You are a friendly assistant.",
        )
        print(f"Response: {response.content}")
        print(f"Tokens: {response.tokens_used}, Cost: ${response.cost:.4f}")
        print()
        print(gateway.format_usage_status())
    else:
        print("❌ No calls remaining")


if __name__ == "__main__":
    import asyncio
    asyncio.run(quick_test())
