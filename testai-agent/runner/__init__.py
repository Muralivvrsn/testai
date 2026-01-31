"""
TestAI Agent - Test Runner Module

Provides intelligent test execution with browser automation,
smart waiting strategies, and adaptive retry mechanisms.

Includes:
- TestRunner: Simulated test execution framework
- PlaywrightRunner: Real browser automation using Playwright
"""

from .engine import (
    TestRunner,
    RunnerConfig,
    RunResult,
    StepResult,
    create_test_runner,
)

from .browser import (
    BrowserManager,
    BrowserConfig,
    BrowserType,
    create_browser_manager,
)

from .actions import (
    ActionExecutor,
    ActionType,
    ActionResult,
    create_action_executor,
)

# Real Playwright automation
try:
    from .playwright_runner import (
        PlaywrightRunner,
        TestCase,
        TestResult as PlaywrightTestResult,
        TestStatus,
        run_test_on_page,
    )
    PLAYWRIGHT_RUNNER_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_RUNNER_AVAILABLE = False
    PlaywrightRunner = None
    TestCase = None
    PlaywrightTestResult = None
    TestStatus = None
    run_test_on_page = None

__all__ = [
    # Runner
    "TestRunner",
    "RunnerConfig",
    "RunResult",
    "StepResult",
    "create_test_runner",
    # Browser
    "BrowserManager",
    "BrowserConfig",
    "BrowserType",
    "create_browser_manager",
    # Actions
    "ActionExecutor",
    "ActionType",
    "ActionResult",
    "create_action_executor",
    # Playwright Runner
    "PlaywrightRunner",
    "TestCase",
    "PlaywrightTestResult",
    "TestStatus",
    "run_test_on_page",
    "PLAYWRIGHT_RUNNER_AVAILABLE",
]
