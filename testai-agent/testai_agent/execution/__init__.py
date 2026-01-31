"""
TestAI Agent - Execution Module

Future home of Playwright-based test execution.
Currently provides stubs and interfaces.
"""

from .playwright_adapter import (
    PlaywrightAdapter,
    TestExecutionResult,
    ElementLocator,
)

__all__ = [
    'PlaywrightAdapter',
    'TestExecutionResult',
    'ElementLocator',
]
