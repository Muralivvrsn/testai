"""
TestAI Agent - Interface Module

Human-centric interfaces:
- CLI: Rich console with colors and visible thinking
- Web: Browser-based chat interface

Both behave like a Senior European QA Consultant.
"""

from .cli import ConsoleUI, create_thinking_callback
from .web import WebServer

__all__ = [
    'ConsoleUI',
    'create_thinking_callback',
    'WebServer',
]
