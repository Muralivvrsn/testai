"""
TestAI Agent - DeepSeek Provider

Primary LLM provider - cost efficient, great for QA tasks.
Uses OpenAI-compatible API format.

Pricing (as of 2024):
- DeepSeek Chat: $0.14 / 1M input, $0.28 / 1M output
- DeepSeek Coder: Same pricing
- ~10x cheaper than GPT-4!
"""

import asyncio
import time
from typing import List, Dict, Optional, Any
import aiohttp

from .base import (
    LLMProvider,
    LLMResponse,
    Message,
    ModelCapability,
    ProviderConfig,
    register_provider,
)


# DeepSeek pricing per 1M tokens (USD)
DEEPSEEK_PRICING = {
    "deepseek-chat": {"input": 0.14, "output": 0.28},
    "deepseek-coder": {"input": 0.14, "output": 0.28},
    "deepseek-reasoner": {"input": 0.55, "output": 2.19},
}

# Default to chat model pricing for unknown models
DEFAULT_PRICING = {"input": 0.14, "output": 0.28}


@register_provider("deepseek")
class DeepSeekProvider(LLMProvider):
    """
    DeepSeek LLM Provider - our primary choice.

    Why DeepSeek?
    1. 10x cheaper than GPT-4
    2. Excellent for coding and analysis
    3. OpenAI-compatible API
    4. Fast response times

    Usage:
        config = ProviderConfig(
            api_key="sk-xxx",
            default_model="deepseek-chat"
        )
        provider = DeepSeekProvider(config)
        response = await provider.complete("Generate login page tests")
    """

    BASE_URL = "https://api.deepseek.com/v1"

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.base_url = config.base_url or self.BASE_URL

        if not config.default_model:
            config.default_model = "deepseek-chat"

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Simple completion with optional system prompt."""
        messages = []

        if system:
            messages.append(Message(role="system", content=system))

        messages.append(Message(role="user", content=prompt))

        return await self.chat(messages, temperature, max_tokens)

    async def chat(
        self,
        messages: List[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Multi-turn conversation."""
        temp = temperature if temperature is not None else self.config.temperature
        tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        payload = {
            "model": self.config.default_model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temp,
            "max_tokens": tokens,
        }

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        start_time = time.time()
        response_data = None
        error_msg = None

        for attempt in range(self.config.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                    ) as response:
                        response_data = await response.json()

                        if response.status != 200:
                            error_msg = response_data.get("error", {}).get("message", str(response_data))
                            if attempt < self.config.max_retries - 1:
                                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                                continue
                            break

                        # Success!
                        latency = (time.time() - start_time) * 1000

                        choice = response_data.get("choices", [{}])[0]
                        usage = response_data.get("usage", {})

                        prompt_tokens = usage.get("prompt_tokens", 0)
                        completion_tokens = usage.get("completion_tokens", 0)
                        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

                        return LLMResponse(
                            content=choice.get("message", {}).get("content", ""),
                            model=self.config.default_model,
                            provider=self.name,
                            tokens_used=total_tokens,
                            tokens_prompt=prompt_tokens,
                            tokens_completion=completion_tokens,
                            latency_ms=latency,
                            cost_estimate=self.estimate_cost(prompt_tokens, completion_tokens),
                            finish_reason=choice.get("finish_reason", "stop"),
                            raw_response=response_data,
                        )

            except asyncio.TimeoutError:
                error_msg = "Request timed out"
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except aiohttp.ClientError as e:
                error_msg = f"Network error: {str(e)}"
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                break

        # All retries failed
        return LLMResponse(
            content=f"Error: {error_msg}",
            model=self.config.default_model,
            provider=self.name,
            tokens_used=0,
            latency_ms=(time.time() - start_time) * 1000,
            finish_reason="error",
            raw_response=response_data,
        )

    def get_capabilities(self) -> List[ModelCapability]:
        """DeepSeek excels at analysis, code, and reasoning."""
        model = self.config.default_model.lower()

        if "coder" in model:
            return [
                ModelCapability.CODE,
                ModelCapability.ANALYSIS,
                ModelCapability.REASONING,
                ModelCapability.GENERATION,
            ]
        elif "reasoner" in model:
            return [
                ModelCapability.REASONING,
                ModelCapability.ANALYSIS,
                ModelCapability.GENERATION,
            ]
        else:  # chat model
            return [
                ModelCapability.CONVERSATION,
                ModelCapability.ANALYSIS,
                ModelCapability.GENERATION,
                ModelCapability.CODE,
                ModelCapability.REASONING,
                ModelCapability.CLASSIFICATION,
            ]

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost in USD."""
        pricing = DEEPSEEK_PRICING.get(self.config.default_model, DEFAULT_PRICING)

        input_cost = (prompt_tokens / 1_000_000) * pricing["input"]
        output_cost = (completion_tokens / 1_000_000) * pricing["output"]

        return input_cost + output_cost


def create_deepseek_provider(
    api_key: str,
    model: str = "deepseek-chat",
    temperature: float = 0.7,
) -> DeepSeekProvider:
    """
    Convenience function to create a DeepSeek provider.

    Args:
        api_key: Your DeepSeek API key
        model: Model to use (deepseek-chat, deepseek-coder, deepseek-reasoner)
        temperature: Creativity level (0-1)

    Returns:
        Configured DeepSeekProvider
    """
    config = ProviderConfig(
        api_key=api_key,
        default_model=model,
        temperature=temperature,
    )
    return DeepSeekProvider(config)
