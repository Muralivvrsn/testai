"""
TestAI Agent - Real Playwright Browser Runner

This module provides ACTUAL browser automation using Playwright,
not just code generation or simulation. It executes tests against
real web pages with screenshots, traces, and comprehensive reporting.

Usage:
    from runner.playwright_runner import PlaywrightRunner, TestCase

    runner = PlaywrightRunner()
    await runner.start()

    test = TestCase(
        name="Login Test",
        url="https://example.com/login",
        steps=[
            {"action": "fill", "selector": "#email", "value": "test@example.com"},
            {"action": "fill", "selector": "#password", "value": "password123"},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "assert_url", "value": "/dashboard"},
        ]
    )

    result = await runner.run_test(test)
    print(f"Test {result.status}: {result.duration_ms}ms")

    await runner.stop()
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class ActionType(Enum):
    """Supported action types."""
    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    TYPE = "type"
    PRESS = "press"
    SELECT = "select"
    CHECK = "check"
    UNCHECK = "uncheck"
    HOVER = "hover"
    SCREENSHOT = "screenshot"
    WAIT = "wait"
    WAIT_FOR = "wait_for"
    ASSERT_VISIBLE = "assert_visible"
    ASSERT_HIDDEN = "assert_hidden"
    ASSERT_TEXT = "assert_text"
    ASSERT_VALUE = "assert_value"
    ASSERT_URL = "assert_url"
    ASSERT_TITLE = "assert_title"
    EVALUATE = "evaluate"


@dataclass
class Step:
    """A single test step."""
    action: str
    selector: Optional[str] = None
    value: Optional[Any] = None
    timeout_ms: int = 30000
    description: str = ""
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StepResult:
    """Result of a step execution."""
    step: Step
    status: TestStatus
    duration_ms: int
    error: Optional[str] = None
    screenshot_path: Optional[str] = None


@dataclass
class TestCase:
    """A test case definition."""
    name: str
    url: str
    steps: List[Dict[str, Any]]
    description: str = ""
    tags: List[str] = field(default_factory=list)
    timeout_ms: int = 60000
    viewport_width: int = 1920
    viewport_height: int = 1080


@dataclass
class TestResult:
    """Result of a test execution."""
    test_name: str
    status: TestStatus
    duration_ms: int
    steps: List[StepResult]
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    screenshot_path: Optional[str] = None
    trace_path: Optional[str] = None
    browser: str = "chromium"
    viewport: str = "1920x1080"

    @property
    def passed(self) -> bool:
        return self.status == TestStatus.PASSED

    @property
    def failed_steps(self) -> List[StepResult]:
        return [s for s in self.steps if s.status == TestStatus.FAILED]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_name": self.test_name,
            "status": self.status.value,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "steps": [
                {
                    "action": s.step.action,
                    "selector": s.step.selector,
                    "status": s.status.value,
                    "duration_ms": s.duration_ms,
                    "error": s.error,
                }
                for s in self.steps
            ],
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "screenshot_path": self.screenshot_path,
            "trace_path": self.trace_path,
            "browser": self.browser,
            "viewport": self.viewport,
        }


class PlaywrightRunner:
    """
    Real Playwright browser automation runner.

    This class actually launches browsers and executes tests,
    not just generating code or simulating actions.
    """

    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chromium",
        slow_mo: int = 0,
        screenshot_dir: str = "./screenshots",
        trace_dir: str = "./traces",
        timeout_ms: int = 30000,
    ):
        """
        Initialize the Playwright runner.

        Args:
            headless: Run browser in headless mode
            browser_type: Browser to use (chromium, firefox, webkit)
            slow_mo: Slow down actions by this many ms
            screenshot_dir: Directory for screenshots
            trace_dir: Directory for Playwright traces
            timeout_ms: Default timeout for actions
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is not installed. Install with: pip install playwright && playwright install"
            )

        self.headless = headless
        self.browser_type = browser_type
        self.slow_mo = slow_mo
        self.screenshot_dir = Path(screenshot_dir)
        self.trace_dir = Path(trace_dir)
        self.timeout_ms = timeout_ms

        self._playwright = None
        self._browser: Optional[Browser] = None
        self._results: List[TestResult] = []
        self._before_hooks: List[Callable] = []
        self._after_hooks: List[Callable] = []

        # Create directories
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)

    async def start(self):
        """Start the Playwright browser."""
        self._playwright = await async_playwright().start()

        browser_launch = {
            "chromium": self._playwright.chromium,
            "firefox": self._playwright.firefox,
            "webkit": self._playwright.webkit,
        }

        launcher = browser_launch.get(self.browser_type, self._playwright.chromium)

        self._browser = await launcher.launch(
            headless=self.headless,
            slow_mo=self.slow_mo,
        )

        return self

    async def stop(self):
        """Stop the Playwright browser."""
        if self._browser:
            await self._browser.close()
            self._browser = None

        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def run_test(
        self,
        test: TestCase,
        record_trace: bool = True,
        screenshot_on_failure: bool = True,
    ) -> TestResult:
        """
        Run a single test case.

        Args:
            test: The test case to run
            record_trace: Whether to record a Playwright trace
            screenshot_on_failure: Take screenshot on failure

        Returns:
            TestResult with execution details
        """
        if not self._browser:
            await self.start()

        started_at = datetime.now()
        step_results: List[StepResult] = []
        overall_status = TestStatus.RUNNING
        error_msg: Optional[str] = None
        screenshot_path: Optional[str] = None
        trace_path: Optional[str] = None

        # Create context with viewport
        context = await self._browser.new_context(
            viewport={"width": test.viewport_width, "height": test.viewport_height},
        )

        # Start tracing if requested
        if record_trace:
            trace_name = f"{test.name.replace(' ', '_')}_{int(time.time())}"
            await context.tracing.start(screenshots=True, snapshots=True)

        page = await context.new_page()

        try:
            # Run before hooks
            for hook in self._before_hooks:
                await hook(test, page)

            # Navigate to the URL
            nav_start = time.time()
            await page.goto(test.url, timeout=test.timeout_ms)
            nav_duration = int((time.time() - nav_start) * 1000)

            step_results.append(StepResult(
                step=Step(action="navigate", value=test.url),
                status=TestStatus.PASSED,
                duration_ms=nav_duration,
            ))

            # Execute each step
            for step_dict in test.steps:
                step = Step(
                    action=step_dict.get("action", "click"),
                    selector=step_dict.get("selector"),
                    value=step_dict.get("value"),
                    timeout_ms=step_dict.get("timeout", self.timeout_ms),
                    description=step_dict.get("description", ""),
                    options=step_dict.get("options", {}),
                )

                step_result = await self._execute_step(page, step)
                step_results.append(step_result)

                if step_result.status == TestStatus.FAILED:
                    overall_status = TestStatus.FAILED
                    error_msg = step_result.error

                    # Take screenshot on failure
                    if screenshot_on_failure:
                        screenshot_name = f"failure_{test.name.replace(' ', '_')}_{int(time.time())}.png"
                        screenshot_path = str(self.screenshot_dir / screenshot_name)
                        await page.screenshot(path=screenshot_path, full_page=True)
                        step_result.screenshot_path = screenshot_path

                    break

            if overall_status != TestStatus.FAILED:
                overall_status = TestStatus.PASSED

            # Run after hooks
            for hook in self._after_hooks:
                await hook(test, page, overall_status)

        except Exception as e:
            overall_status = TestStatus.ERROR
            error_msg = str(e)

            # Take screenshot on error
            if screenshot_on_failure:
                try:
                    screenshot_name = f"error_{test.name.replace(' ', '_')}_{int(time.time())}.png"
                    screenshot_path = str(self.screenshot_dir / screenshot_name)
                    await page.screenshot(path=screenshot_path, full_page=True)
                except Exception:
                    pass

        finally:
            # Save trace
            if record_trace:
                trace_name = f"{test.name.replace(' ', '_')}_{int(time.time())}.zip"
                trace_path = str(self.trace_dir / trace_name)
                await context.tracing.stop(path=trace_path)

            # Cleanup
            await page.close()
            await context.close()

        completed_at = datetime.now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        result = TestResult(
            test_name=test.name,
            status=overall_status,
            duration_ms=duration_ms,
            steps=step_results,
            started_at=started_at,
            completed_at=completed_at,
            error=error_msg,
            screenshot_path=screenshot_path,
            trace_path=trace_path,
            browser=self.browser_type,
            viewport=f"{test.viewport_width}x{test.viewport_height}",
        )

        self._results.append(result)
        return result

    async def _execute_step(self, page: "Page", step: Step) -> StepResult:
        """Execute a single test step."""
        start_time = time.time()
        status = TestStatus.PASSED
        error_msg: Optional[str] = None

        try:
            action = step.action.lower()

            if action == "click":
                await page.click(step.selector, timeout=step.timeout_ms)

            elif action == "fill":
                await page.fill(step.selector, step.value or "", timeout=step.timeout_ms)

            elif action == "type":
                await page.type(step.selector, step.value or "", timeout=step.timeout_ms)

            elif action == "press":
                await page.press(step.selector, step.value or "Enter", timeout=step.timeout_ms)

            elif action == "select":
                await page.select_option(step.selector, step.value, timeout=step.timeout_ms)

            elif action == "check":
                await page.check(step.selector, timeout=step.timeout_ms)

            elif action == "uncheck":
                await page.uncheck(step.selector, timeout=step.timeout_ms)

            elif action == "hover":
                await page.hover(step.selector, timeout=step.timeout_ms)

            elif action == "screenshot":
                path = step.value or f"screenshot_{int(time.time())}.png"
                await page.screenshot(path=str(self.screenshot_dir / path))

            elif action == "wait":
                await page.wait_for_timeout(int(step.value or 1000))

            elif action == "wait_for":
                await page.wait_for_selector(step.selector, timeout=step.timeout_ms)

            elif action == "assert_visible":
                element = await page.query_selector(step.selector)
                if not element or not await element.is_visible():
                    raise AssertionError(f"Element {step.selector} is not visible")

            elif action == "assert_hidden":
                element = await page.query_selector(step.selector)
                if element and await element.is_visible():
                    raise AssertionError(f"Element {step.selector} is visible but should be hidden")

            elif action == "assert_text":
                element = await page.query_selector(step.selector)
                if not element:
                    raise AssertionError(f"Element {step.selector} not found")
                text = await element.text_content()
                expected = step.value or ""
                if expected not in (text or ""):
                    raise AssertionError(f"Expected text '{expected}' not found in '{text}'")

            elif action == "assert_value":
                value = await page.input_value(step.selector)
                expected = step.value or ""
                if value != expected:
                    raise AssertionError(f"Expected value '{expected}', got '{value}'")

            elif action == "assert_url":
                current_url = page.url
                expected = step.value or ""
                if expected not in current_url:
                    raise AssertionError(f"Expected URL to contain '{expected}', got '{current_url}'")

            elif action == "assert_title":
                title = await page.title()
                expected = step.value or ""
                if expected not in title:
                    raise AssertionError(f"Expected title to contain '{expected}', got '{title}'")

            elif action == "evaluate":
                result = await page.evaluate(step.value or "")
                # Store result in step options for later use
                step.options["result"] = result

            else:
                # Unknown action - try as a generic click
                if step.selector:
                    await page.click(step.selector, timeout=step.timeout_ms)

        except AssertionError as e:
            status = TestStatus.FAILED
            error_msg = str(e)

        except Exception as e:
            status = TestStatus.FAILED
            error_msg = f"{type(e).__name__}: {str(e)}"

        duration_ms = int((time.time() - start_time) * 1000)

        return StepResult(
            step=step,
            status=status,
            duration_ms=duration_ms,
            error=error_msg,
        )

    async def run_tests(
        self,
        tests: List[TestCase],
        stop_on_failure: bool = False,
    ) -> List[TestResult]:
        """Run multiple test cases."""
        results = []

        for test in tests:
            result = await self.run_test(test)
            results.append(result)

            if stop_on_failure and not result.passed:
                break

        return results

    def add_before_hook(self, hook: Callable):
        """Add a before test hook. Hook receives (test, page)."""
        self._before_hooks.append(hook)

    def add_after_hook(self, hook: Callable):
        """Add an after test hook. Hook receives (test, page, status)."""
        self._after_hooks.append(hook)

    def get_results(self) -> List[TestResult]:
        """Get all test results."""
        return list(self._results)

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self._results if r.status == TestStatus.FAILED)
        errored = sum(1 for r in self._results if r.status == TestStatus.ERROR)

        total_duration = sum(r.duration_ms for r in self._results)
        avg_duration = total_duration / total if total > 0 else 0

        total_steps = sum(len(r.steps) for r in self._results)
        passed_steps = sum(
            sum(1 for s in r.steps if s.status == TestStatus.PASSED)
            for r in self._results
        )

        return {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "errored": errored,
            "pass_rate": passed / total if total > 0 else 0,
            "total_duration_ms": total_duration,
            "avg_duration_ms": avg_duration,
            "total_steps": total_steps,
            "passed_steps": passed_steps,
        }

    def format_results(self) -> str:
        """Format results as readable text."""
        stats = self.get_statistics()

        lines = [
            "=" * 60,
            "  PLAYWRIGHT TEST RESULTS",
            "=" * 60,
            "",
            f"  Total Tests: {stats['total_tests']}",
            f"  Passed: {stats['passed']} | Failed: {stats['failed']} | Errors: {stats['errored']}",
            f"  Pass Rate: {stats['pass_rate']:.1%}",
            f"  Total Duration: {stats['total_duration_ms']}ms",
            f"  Total Steps: {stats['total_steps']} ({stats['passed_steps']} passed)",
            "",
        ]

        for result in self._results:
            status_icon = {
                TestStatus.PASSED: "✅",
                TestStatus.FAILED: "❌",
                TestStatus.ERROR: "💥",
                TestStatus.SKIPPED: "⏭️",
            }.get(result.status, "⚪")

            lines.extend([
                "-" * 60,
                f"  {status_icon} {result.test_name}",
                f"     Duration: {result.duration_ms}ms | Steps: {len(result.steps)}",
                f"     Browser: {result.browser} | Viewport: {result.viewport}",
            ])

            if result.error:
                lines.append(f"     Error: {result.error[:60]}")

            if result.screenshot_path:
                lines.append(f"     Screenshot: {result.screenshot_path}")

            if result.trace_path:
                lines.append(f"     Trace: {result.trace_path}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


# Convenience function
async def run_test_on_page(
    url: str,
    steps: List[Dict[str, Any]],
    headless: bool = True,
    browser: str = "chromium",
) -> TestResult:
    """
    Quick way to run a test on a single page.

    Args:
        url: URL to test
        steps: List of step dictionaries
        headless: Run headless
        browser: Browser type

    Returns:
        TestResult
    """
    runner = PlaywrightRunner(headless=headless, browser_type=browser)
    await runner.start()

    test = TestCase(
        name=f"Test on {url}",
        url=url,
        steps=steps,
    )

    result = await runner.run_test(test)
    await runner.stop()

    return result


# Demo / Test
if __name__ == "__main__":
    async def demo():
        print("=" * 60)
        print("  TestAI - Real Playwright Runner Demo")
        print("=" * 60)
        print()

        runner = PlaywrightRunner(headless=True)
        await runner.start()

        # Test on a real website
        test = TestCase(
            name="Example.com Homepage Test",
            url="https://example.com",
            description="Verify example.com loads correctly",
            steps=[
                {"action": "assert_title", "value": "Example Domain"},
                {"action": "assert_visible", "selector": "h1"},
                {"action": "assert_text", "selector": "h1", "value": "Example Domain"},
                {"action": "screenshot", "value": "example_homepage.png"},
            ],
        )

        print(f"Running test: {test.name}")
        print(f"URL: {test.url}")
        print(f"Steps: {len(test.steps)}")
        print()

        result = await runner.run_test(test)

        print(runner.format_results())

        await runner.stop()

        return result

    # Run the demo
    result = asyncio.run(demo())
    print(f"\nFinal Status: {result.status.value}")
