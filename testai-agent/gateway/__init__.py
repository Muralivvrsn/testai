"""
TestAI Agent - Gateway Module

Model-agnostic LLM interface with smart routing.
DeepSeek is primary (cost efficient), others as fallback.
"""

from .base import LLMProvider, LLMResponse, Message, ModelCapability
from .deepseek import DeepSeekProvider
from .router import ModelRouter, create_router

__all__ = [
    'LLMProvider',
    'LLMResponse',
    'Message',
    'ModelCapability',
    'DeepSeekProvider',
    'ModelRouter',
    'create_router',
]
