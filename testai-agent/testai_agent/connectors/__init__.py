"""
TestAI Agent - Connectors Module

Multi-provider LLM Gateway supporting:
- DeepSeek (primary)
- OpenAI (fallback)
- Anthropic (fallback)
- Google Gemini (fallback)

Features:
- Usage tracking with limits
- Automatic fallback on failure
- Provider-agnostic interface
"""

from .llm_gateway import (
    LLMGateway,
    LLMProvider,
    BaseLLMConnector,
    DeepSeekConnector,
    create_gateway
)

__all__ = [
    'LLMGateway',
    'LLMProvider',
    'BaseLLMConnector',
    'DeepSeekConnector',
    'create_gateway',
]
