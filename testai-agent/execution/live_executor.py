"""
TestAI Agent - Live Test Executor

Connects the TestAI test generation system with real Playwright browser execution.
This is the bridge between AI-generated test cases and actual browser automation.

Usage:
    from execution.live_executor import LiveExecutor

    executor = LiveExecutor()

    # Generate and execute tests
    results = await executor.generate_and_execute(
        feature="login page",
        url="https://example.com/login",
    )

    print(executor.format_results())
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import test generation
try:
    from generators.cited_generator import LoginPageGenerator, create_generator_for_page_type
    from cortex.prioritizer import TestPrioritizer
    from understanding.feature_analyzer import FeatureAnalyzer
    GENERATOR_AVAILABLE = True
except ImportError:
    GENERATOR_AVAILABLE = False

# Import Playwright runner
try:
    from runner.playwright_runner import (
        PlaywrightRunner,
        TestCase,
        TestResult,
        TestStatus,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    try:
        # Try absolute import from parent
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from runner.playwright_runner import (
            PlaywrightRunner,
            TestCase,
            TestResult,
            TestStatus,
        )
        PLAYWRIGHT_AVAILABLE = True
    except ImportError:
        PLAYWRIGHT_AVAILABLE = False


@dataclass
class ExecutionResult:
    """Result of generating and executing tests."""
    feature: str
    url: str
    total_generated: int
    total_executed: int
    passed: int
    failed: int
    skipped: int
    duration_ms: int
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    generation_time_ms: int = 0
    execution_time_ms: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def pass_rate(self) -> float:
        if self.total_executed == 0:
            return 0.0
        return self.passed / self.total_executed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "url": self.url,
            "total_generated": self.total_generated,
            "total_executed": self.total_executed,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "pass_rate": self.pass_rate,
            "duration_ms": self.duration_ms,
            "generation_time_ms": self.generation_time_ms,
            "execution_time_ms": self.execution_time_ms,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "test_results": self.test_results,
            "error": self.error,
        }


class LiveExecutor:
    """
    Generates tests using TestAI and executes them with Playwright.

    This executor:
    1. Analyzes the feature request
    2. Generates test cases using the Brain/Cortex
    3. Converts them to executable Playwright steps
    4. Runs them in a real browser
    5. Reports results with screenshots and traces
    """

    # Selector mapping for common elements
    ELEMENT_SELECTORS = {
        "email": [
            "input[type='email']",
            "input[name='email']",
            "input[id='email']",
            "#email",
            "[placeholder*='email' i]",
        ],
        "password": [
            "input[type='password']",
            "input[name='password']",
            "#password",
        ],
        "username": [
            "input[name='username']",
            "input[id='username']",
            "#username",
        ],
        "submit": [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Submit')",
            "button:has-text('Login')",
            "button:has-text('Sign In')",
        ],
        "login_button": [
            "button:has-text('Login')",
            "button:has-text('Sign In')",
            "button:has-text('Log In')",
            "#login-btn",
            ".login-button",
        ],
        "signup_button": [
            "button:has-text('Sign Up')",
            "button:has-text('Register')",
            "button:has-text('Create Account')",
        ],
        "search": [
            "input[type='search']",
            "input[name='search']",
            "input[name='q']",
            "#search",
            ".search-input",
        ],
    }

    # Test data for form filling
    TEST_DATA = {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "username": "testuser",
        "name": "Test User",
        "phone": "555-123-4567",
        "search": "test search query",
    }

    # Invalid test data for negative tests
    INVALID_DATA = {
        "email": "invalid-email",
        "password": "123",
        "username": "",
        "phone": "invalid",
    }

    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chromium",
        screenshot_dir: str = "./screenshots",
        trace_dir: str = "./traces",
        timeout_ms: int = 30000,
    ):
        """Initialize the live executor."""
        self.headless = headless
        self.browser_type = browser_type
        self.screenshot_dir = Path(screenshot_dir)
        self.trace_dir = Path(trace_dir)
        self.timeout_ms = timeout_ms

        self._runner: Optional[PlaywrightRunner] = None
        self._results: List[ExecutionResult] = []

        # Create directories
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)

    async def start(self):
        """Start the browser."""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is not available. Install with: pip install playwright")

        self._runner = PlaywrightRunner(
            headless=self.headless,
            browser_type=self.browser_type,
            screenshot_dir=str(self.screenshot_dir),
            trace_dir=str(self.trace_dir),
            timeout_ms=self.timeout_ms,
        )
        await self._runner.start()
        return self

    async def stop(self):
        """Stop the browser."""
        if self._runner:
            await self._runner.stop()
            self._runner = None

    async def generate_and_execute(
        self,
        feature: str,
        url: str,
        page_type: Optional[str] = None,
        max_tests: int = 10,
        stop_on_failure: bool = False,
    ) -> ExecutionResult:
        """
        Generate tests for a feature and execute them.

        Args:
            feature: Feature description (e.g., "login page")
            url: URL to test
            page_type: Page type (login, signup, checkout, search)
            max_tests: Maximum number of tests to run
            stop_on_failure: Stop execution on first failure

        Returns:
            ExecutionResult with test outcomes
        """
        started_at = datetime.now()

        result = ExecutionResult(
            feature=feature,
            url=url,
            total_generated=0,
            total_executed=0,
            passed=0,
            failed=0,
            skipped=0,
            duration_ms=0,
            started_at=started_at,
        )

        try:
            # Start browser if needed
            if not self._runner:
                await self.start()

            # Step 1: Analyze the feature
            gen_start = datetime.now()

            if GENERATOR_AVAILABLE:
                # Detect page type
                analyzer = FeatureAnalyzer()
                context = analyzer.from_request(feature)
                detected_type = page_type or context.page_type or "login"

                # Generate tests
                generator = create_generator_for_page_type(detected_type)
                test_plan = generator.generate()
                generated_tests = test_plan.tests[:max_tests]
            else:
                # Fallback: generate basic tests
                detected_type = page_type or "login"
                generated_tests = self._generate_basic_tests(detected_type)[:max_tests]

            result.total_generated = len(generated_tests)
            result.generation_time_ms = int((datetime.now() - gen_start).total_seconds() * 1000)

            # Step 2: Convert to executable test cases
            test_cases = []
            for test in generated_tests:
                test_case = self._convert_to_test_case(test, url)
                if test_case:
                    test_cases.append(test_case)

            # Step 3: Execute tests
            exec_start = datetime.now()

            for test_case in test_cases:
                try:
                    test_result = await self._runner.run_test(test_case)
                    result.total_executed += 1

                    if test_result.passed:
                        result.passed += 1
                    else:
                        result.failed += 1

                    result.test_results.append(test_result.to_dict())

                    if stop_on_failure and not test_result.passed:
                        # Skip remaining tests
                        result.skipped = len(test_cases) - result.total_executed
                        break

                except Exception as e:
                    result.failed += 1
                    result.test_results.append({
                        "test_name": test_case.name,
                        "status": "error",
                        "error": str(e),
                    })

            result.execution_time_ms = int((datetime.now() - exec_start).total_seconds() * 1000)

        except Exception as e:
            result.error = str(e)

        result.completed_at = datetime.now()
        result.duration_ms = int((result.completed_at - started_at).total_seconds() * 1000)

        self._results.append(result)
        return result

    def _generate_basic_tests(self, page_type: str) -> List[Dict[str, Any]]:
        """Generate basic tests when generator not available."""
        if page_type == "login":
            return [
                {
                    "id": "TC-001",
                    "title": "Page loads correctly",
                    "category": "functional",
                    "priority": "high",
                    "steps": ["Navigate to the page", "Verify page loads"],
                },
                {
                    "id": "TC-002",
                    "title": "Email field present",
                    "category": "functional",
                    "priority": "high",
                    "steps": ["Verify email field is visible"],
                },
                {
                    "id": "TC-003",
                    "title": "Password field present",
                    "category": "functional",
                    "priority": "high",
                    "steps": ["Verify password field is visible"],
                },
                {
                    "id": "TC-004",
                    "title": "Submit button present",
                    "category": "functional",
                    "priority": "high",
                    "steps": ["Verify submit button is visible"],
                },
                {
                    "id": "TC-005",
                    "title": "Can enter email",
                    "category": "functional",
                    "priority": "medium",
                    "steps": ["Fill email field with test data"],
                },
            ]
        else:
            return [
                {
                    "id": "TC-001",
                    "title": "Page loads correctly",
                    "category": "functional",
                    "priority": "high",
                    "steps": ["Navigate to the page", "Verify page loads"],
                },
            ]

    def _convert_to_test_case(
        self,
        test: Dict[str, Any],
        url: str,
    ) -> Optional[Any]:
        """Convert a generated test to an executable test case."""
        title = test.get("title", "Test")
        category = test.get("category", "functional")
        steps_text = test.get("steps", [])

        # Parse steps into Playwright actions
        playwright_steps = []

        for step_text in steps_text:
            step_lower = step_text.lower()

            # Navigate
            if "navigate" in step_lower or "go to" in step_lower:
                continue  # Navigation is handled separately

            # Verify/Assert visible
            elif "verify" in step_lower or "visible" in step_lower or "present" in step_lower:
                selector = self._detect_selector(step_text)
                if selector:
                    playwright_steps.append({
                        "action": "assert_visible",
                        "selector": selector,
                        "description": step_text,
                    })

            # Fill/Enter
            elif "fill" in step_lower or "enter" in step_lower or "type" in step_lower:
                element_type = self._detect_element_type(step_text)
                selector = self._detect_selector(step_text)
                if selector:
                    value = self.TEST_DATA.get(element_type, "test input")
                    playwright_steps.append({
                        "action": "fill",
                        "selector": selector,
                        "value": value,
                        "description": step_text,
                    })

            # Click
            elif "click" in step_lower or "press" in step_lower or "submit" in step_lower:
                selector = self._detect_selector(step_text)
                if selector:
                    playwright_steps.append({
                        "action": "click",
                        "selector": selector,
                        "description": step_text,
                    })

            # Wait
            elif "wait" in step_lower:
                playwright_steps.append({
                    "action": "wait",
                    "value": 1000,
                    "description": step_text,
                })

        # Only create test case if we have steps
        if playwright_steps:
            return TestCase(
                name=title,
                url=url,
                description=test.get("description", ""),
                steps=playwright_steps,
                tags=[category, test.get("priority", "medium")],
            )

        return None

    def _detect_selector(self, text: str) -> Optional[str]:
        """Detect element selector from step text."""
        text_lower = text.lower()

        for element_type, selectors in self.ELEMENT_SELECTORS.items():
            if element_type in text_lower:
                return selectors[0]  # Return first selector

        return None

    def _detect_element_type(self, text: str) -> str:
        """Detect element type from step text."""
        text_lower = text.lower()

        for element_type in self.ELEMENT_SELECTORS.keys():
            if element_type in text_lower:
                return element_type

        return "text"

    def get_results(self) -> List[ExecutionResult]:
        """Get all execution results."""
        return list(self._results)

    def format_results(self) -> str:
        """Format all results as readable text."""
        lines = [
            "=" * 60,
            "  LIVE EXECUTION RESULTS",
            "=" * 60,
            "",
        ]

        for result in self._results:
            status = "PASSED" if result.pass_rate == 1.0 else (
                "FAILED" if result.failed > 0 else "PARTIAL"
            )
            icon = "✅" if status == "PASSED" else ("❌" if status == "FAILED" else "⚠️")

            lines.extend([
                f"  {icon} {result.feature}",
                f"     URL: {result.url}",
                f"     Generated: {result.total_generated} | Executed: {result.total_executed}",
                f"     Passed: {result.passed} | Failed: {result.failed}",
                f"     Pass Rate: {result.pass_rate:.1%}",
                f"     Duration: {result.duration_ms}ms",
                "",
            ])

            if result.error:
                lines.append(f"     Error: {result.error}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def export_results(self, path: str):
        """Export results to JSON file."""
        data = [r.to_dict() for r in self._results]
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)


# Demo
async def demo():
    """Demonstrate live execution."""
    print("=" * 60)
    print("  TestAI - Live Executor Demo")
    print("=" * 60)
    print()

    executor = LiveExecutor(headless=True)
    await executor.start()

    # Test a real page
    result = await executor.generate_and_execute(
        feature="example homepage",
        url="https://example.com",
        page_type="login",  # Use login type for now
        max_tests=3,
    )

    print(executor.format_results())
    print()
    print(f"Total execution time: {result.duration_ms}ms")
    print(f"Tests generated: {result.total_generated}")
    print(f"Tests executed: {result.total_executed}")
    print(f"Pass rate: {result.pass_rate:.1%}")

    await executor.stop()


if __name__ == "__main__":
    asyncio.run(demo())
