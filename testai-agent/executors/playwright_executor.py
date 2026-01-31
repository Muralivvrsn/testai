"""
TestAI Agent - Playwright Test Executor

Translates generated test cases into executable Playwright tests.
This is a stub/framework for future implementation with actual browser automation.

Design Philosophy:
- Generate human-readable test code
- Support multiple output formats (Python, TypeScript)
- Dry-run mode for validation
- Extensible action mapping
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from datetime import datetime
import json
import re


class StepStatus(Enum):
    """Status of a test step execution."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class OutputFormat(Enum):
    """Output format for generated test code."""
    PYTHON_PYTEST = "python_pytest"
    PYTHON_UNITTEST = "python_unittest"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"


@dataclass
class TestStep:
    """A single executable test step."""
    action: str              # Action type: navigate, click, fill, assert, wait
    target: Optional[str]    # Selector or URL
    value: Optional[str]     # Input value or expected value
    description: str         # Human-readable description
    timeout_ms: int = 5000   # Timeout for this step

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action": self.action,
            "target": self.target,
            "value": self.value,
            "description": self.description,
            "timeout_ms": self.timeout_ms,
        }


@dataclass
class StepResult:
    """Result of executing a test step."""
    step: TestStep
    status: StepStatus
    duration_ms: float
    error_message: Optional[str] = None
    screenshot_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step": self.step.to_dict(),
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "screenshot_path": self.screenshot_path,
        }


@dataclass
class TestExecutionResult:
    """Result of executing a complete test case."""
    test_id: str
    test_title: str
    status: StepStatus
    steps: List[StepResult]
    total_duration_ms: float
    started_at: datetime
    completed_at: datetime
    browser: str = "chromium"
    viewport: Dict[str, int] = field(default_factory=lambda: {"width": 1280, "height": 720})

    @property
    def passed(self) -> bool:
        """Check if test passed."""
        return self.status == StepStatus.PASSED

    @property
    def step_summary(self) -> Dict[str, int]:
        """Get summary of step statuses."""
        summary = {}
        for step in self.steps:
            status = step.status.value
            summary[status] = summary.get(status, 0) + 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "test_title": self.test_title,
            "status": self.status.value,
            "passed": self.passed,
            "steps": [s.to_dict() for s in self.steps],
            "step_summary": self.step_summary,
            "total_duration_ms": self.total_duration_ms,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "browser": self.browser,
            "viewport": self.viewport,
        }


class PlaywrightExecutor:
    """
    Translates TestAI generated test cases into Playwright tests.

    This executor can:
    1. Convert natural language steps to Playwright actions
    2. Generate executable test code in multiple formats
    3. Run tests in dry-run mode (no browser)
    4. Execute tests with actual Playwright (when available)

    Usage:
        executor = PlaywrightExecutor()

        # Generate test code
        code = executor.generate_code(test_case, format=OutputFormat.PYTHON_PYTEST)
        print(code)

        # Dry run (validate steps)
        result = executor.dry_run(test_case)
        print(f"Validation: {result.status}")

        # Execute (requires Playwright)
        result = await executor.execute(test_case)
        print(f"Result: {result.status}")
    """

    # Action patterns for step interpretation
    ACTION_PATTERNS = {
        "navigate": [
            r"navigate\s+to",
            r"go\s+to",
            r"open\s+(?:the\s+)?(?:url|page|site)",
            r"visit",
        ],
        "click": [
            r"click\s+(?:on\s+)?(?:the\s+)?",
            r"press\s+(?:the\s+)?",
            r"tap\s+(?:on\s+)?",
            r"select\s+(?:the\s+)?",
        ],
        "fill": [
            r"enter\s+",
            r"type\s+",
            r"input\s+",
            r"fill\s+(?:in\s+)?",
            r"set\s+",
        ],
        "assert": [
            r"verify\s+(?:that\s+)?",
            r"check\s+(?:that\s+)?",
            r"ensure\s+(?:that\s+)?",
            r"confirm\s+(?:that\s+)?",
            r"observe\s+",
            r"should\s+",
        ],
        "wait": [
            r"wait\s+(?:for\s+)?",
            r"pause\s+",
        ],
    }

    # Selector hints for common elements
    SELECTOR_HINTS = {
        "email": ["input[type=email]", "input[name*=email]", "#email", ".email-input"],
        "password": ["input[type=password]", "input[name*=password]", "#password"],
        "username": ["input[name*=user]", "#username", ".username-input"],
        "submit": ["button[type=submit]", "input[type=submit]", "button:has-text('Submit')"],
        "login": ["button:has-text('Login')", "button:has-text('Sign In')", "#login-btn"],
        "search": ["input[type=search]", "input[name*=search]", "#search", ".search-input"],
    }

    def __init__(
        self,
        base_url: Optional[str] = None,
        browser: str = "chromium",
        headless: bool = True,
        timeout_ms: int = 30000,
    ):
        """
        Initialize executor.

        Args:
            base_url: Base URL for relative navigation
            browser: Browser to use (chromium, firefox, webkit)
            headless: Run in headless mode
            timeout_ms: Default timeout for actions
        """
        self.base_url = base_url
        self.browser = browser
        self.headless = headless
        self.timeout_ms = timeout_ms

    def parse_step(self, step_text: str) -> TestStep:
        """
        Parse a natural language step into a TestStep.

        Args:
            step_text: Natural language test step

        Returns:
            TestStep with action, target, value
        """
        step_lower = step_text.lower()

        # Detect action type
        action = "assert"  # Default
        for action_type, patterns in self.ACTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, step_lower):
                    action = action_type
                    break

        # Extract target (selector hint)
        target = None
        for element, selectors in self.SELECTOR_HINTS.items():
            if element in step_lower:
                target = selectors[0]  # Use first selector
                break

        # Extract value if it's a fill action
        value = None
        if action == "fill":
            # Look for quoted values or common patterns
            quoted = re.search(r'"([^"]+)"', step_text) or re.search(r"'([^']+)'", step_text)
            if quoted:
                value = quoted.group(1)
            elif "test data" in step_lower:
                value = "test_value"

        return TestStep(
            action=action,
            target=target,
            value=value,
            description=step_text,
            timeout_ms=self.timeout_ms,
        )

    def translate_test_case(self, test_case: Dict[str, Any]) -> List[TestStep]:
        """
        Translate a TestAI test case into executable steps.

        Args:
            test_case: Test case dictionary with steps

        Returns:
            List of TestStep objects
        """
        steps = []

        for step_text in test_case.get("steps", []):
            step = self.parse_step(step_text)
            steps.append(step)

        return steps

    def generate_code(
        self,
        test_case: Dict[str, Any],
        format: OutputFormat = OutputFormat.PYTHON_PYTEST,
    ) -> str:
        """
        Generate executable test code from a test case.

        Args:
            test_case: Test case dictionary
            format: Output format

        Returns:
            Generated test code as string
        """
        steps = self.translate_test_case(test_case)

        if format == OutputFormat.PYTHON_PYTEST:
            return self._generate_pytest(test_case, steps)
        elif format == OutputFormat.TYPESCRIPT:
            return self._generate_typescript(test_case, steps)
        else:
            return self._generate_pytest(test_case, steps)

    def _generate_pytest(self, test_case: Dict[str, Any], steps: List[TestStep]) -> str:
        """Generate pytest code."""
        test_id = test_case.get("id", "TC-001")
        test_title = test_case.get("title", "Test Case")
        func_name = self._to_function_name(test_title)

        lines = [
            '"""',
            f'Test: {test_title}',
            f'ID: {test_id}',
            '',
            'Generated by TestAI Agent',
            '"""',
            '',
            'import pytest',
            'from playwright.sync_api import Page, expect',
            '',
            '',
            f'def test_{func_name}(page: Page):',
            f'    """',
            f'    {test_case.get("description", test_title)}',
            '',
            f'    Priority: {test_case.get("priority", "medium").upper()}',
            f'    Category: {test_case.get("category", "functional")}',
            f'    """',
        ]

        for i, step in enumerate(steps, 1):
            lines.append(f'    # Step {i}: {step.description}')
            lines.append(self._step_to_pytest(step))
            lines.append('')

        # Add assertion for expected result
        expected = test_case.get("expected_result", "Test should pass")
        lines.append(f'    # Expected: {expected}')
        lines.append('    # Add specific assertions based on expected result')
        lines.append('')

        return '\n'.join(lines)

    def _step_to_pytest(self, step: TestStep) -> str:
        """Convert a step to pytest/playwright code."""
        if step.action == "navigate":
            url = step.target or step.value or "/"
            return f'    page.goto("{url}")'

        elif step.action == "click":
            selector = step.target or "button"
            return f'    page.locator("{selector}").click()'

        elif step.action == "fill":
            selector = step.target or "input"
            value = step.value or "test_value"
            return f'    page.locator("{selector}").fill("{value}")'

        elif step.action == "assert":
            return f'    # Assertion: {step.description}'

        elif step.action == "wait":
            return f'    page.wait_for_timeout({step.timeout_ms})'

        return f'    # {step.description}'

    def _generate_typescript(self, test_case: Dict[str, Any], steps: List[TestStep]) -> str:
        """Generate TypeScript code."""
        test_id = test_case.get("id", "TC-001")
        test_title = test_case.get("title", "Test Case")

        lines = [
            '/**',
            f' * Test: {test_title}',
            f' * ID: {test_id}',
            ' *',
            ' * Generated by TestAI Agent',
            ' */',
            '',
            "import { test, expect } from '@playwright/test';",
            '',
            f"test('{test_title}', async ({{ page }}) => {{",
        ]

        for i, step in enumerate(steps, 1):
            lines.append(f'  // Step {i}: {step.description}')
            lines.append(self._step_to_typescript(step))
            lines.append('')

        lines.append('});')
        lines.append('')

        return '\n'.join(lines)

    def _step_to_typescript(self, step: TestStep) -> str:
        """Convert a step to TypeScript/Playwright code."""
        if step.action == "navigate":
            url = step.target or step.value or "/"
            return f'  await page.goto("{url}");'

        elif step.action == "click":
            selector = step.target or "button"
            return f'  await page.locator("{selector}").click();'

        elif step.action == "fill":
            selector = step.target or "input"
            value = step.value or "test_value"
            return f'  await page.locator("{selector}").fill("{value}");'

        elif step.action == "assert":
            return f'  // Assertion: {step.description}'

        elif step.action == "wait":
            return f'  await page.waitForTimeout({step.timeout_ms});'

        return f'  // {step.description}'

    def _to_function_name(self, title: str) -> str:
        """Convert title to valid function name."""
        # Remove special characters, convert to snake_case
        name = re.sub(r'[^\w\s]', '', title.lower())
        name = re.sub(r'\s+', '_', name)
        return name[:50]  # Limit length

    def dry_run(self, test_case: Dict[str, Any]) -> TestExecutionResult:
        """
        Validate a test case without executing (dry run).

        Args:
            test_case: Test case dictionary

        Returns:
            TestExecutionResult with validation status
        """
        start_time = datetime.now()
        steps = self.translate_test_case(test_case)

        step_results = []
        all_passed = True

        for step in steps:
            # Validate step
            status = StepStatus.PASSED
            error = None

            if step.action == "fill" and not step.target:
                status = StepStatus.SKIPPED
                error = "No selector found for fill action"

            if step.action == "click" and not step.target:
                status = StepStatus.SKIPPED
                error = "No selector found for click action"

            step_results.append(StepResult(
                step=step,
                status=status,
                duration_ms=0.0,
                error_message=error,
            ))

            if status == StepStatus.FAILED:
                all_passed = False

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() * 1000

        return TestExecutionResult(
            test_id=test_case.get("id", "TC-001"),
            test_title=test_case.get("title", "Test Case"),
            status=StepStatus.PASSED if all_passed else StepStatus.FAILED,
            steps=step_results,
            total_duration_ms=duration,
            started_at=start_time,
            completed_at=end_time,
            browser="dry_run",
        )

    async def execute(
        self,
        test_case: Dict[str, Any],
        page=None,
    ) -> TestExecutionResult:
        """
        Execute a test case with Playwright.

        Note: This requires Playwright to be installed and a page object.
        In stub mode, this performs a dry run.

        Args:
            test_case: Test case dictionary
            page: Playwright page object (optional)

        Returns:
            TestExecutionResult
        """
        # If no page provided, do dry run
        if page is None:
            return self.dry_run(test_case)

        # Full execution would go here
        # This is a stub for future implementation
        return self.dry_run(test_case)


def create_executor(
    base_url: Optional[str] = None,
    browser: str = "chromium",
    headless: bool = True,
) -> PlaywrightExecutor:
    """Create a Playwright executor."""
    return PlaywrightExecutor(
        base_url=base_url,
        browser=browser,
        headless=headless,
    )


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def generate_pytest_suite(
    test_cases: List[Dict[str, Any]],
    module_name: str = "test_generated",
) -> str:
    """
    Generate a complete pytest test file from multiple test cases.

    Args:
        test_cases: List of test case dictionaries
        module_name: Name for the test module

    Returns:
        Complete pytest file content
    """
    executor = PlaywrightExecutor()

    lines = [
        '"""',
        f'Generated Test Suite: {module_name}',
        '',
        'Auto-generated by TestAI Agent',
        f'Tests: {len(test_cases)}',
        '"""',
        '',
        'import pytest',
        'from playwright.sync_api import Page, expect',
        '',
        '',
        '@pytest.fixture(scope="module")',
        'def browser_context(browser):',
        '    """Create browser context for test module."""',
        '    context = browser.new_context(',
        '        viewport={"width": 1280, "height": 720}',
        '    )',
        '    yield context',
        '    context.close()',
        '',
        '',
    ]

    for test_case in test_cases:
        code = executor.generate_code(test_case, OutputFormat.PYTHON_PYTEST)
        # Skip the imports and header (already added)
        code_lines = code.split('\n')
        test_start = next((i for i, line in enumerate(code_lines) if line.startswith('def test_')), 0)
        lines.extend(code_lines[test_start:])
        lines.append('')
        lines.append('')

    return '\n'.join(lines)


if __name__ == "__main__":
    # Demo
    test_case = {
        "id": "TC-001",
        "title": "Login with valid credentials",
        "description": "Verify user can login with valid email and password",
        "category": "functional",
        "priority": "critical",
        "steps": [
            "Navigate to the login page",
            "Enter valid email in the email field",
            "Enter valid password in the password field",
            "Click the login button",
            "Verify successful login redirect",
        ],
        "expected_result": "User should be redirected to dashboard",
    }

    executor = create_executor()

    print("=" * 60)
    print("Generated Pytest Code:")
    print("=" * 60)
    print(executor.generate_code(test_case, OutputFormat.PYTHON_PYTEST))

    print("\n" + "=" * 60)
    print("Generated TypeScript Code:")
    print("=" * 60)
    print(executor.generate_code(test_case, OutputFormat.TYPESCRIPT))

    print("\n" + "=" * 60)
    print("Dry Run Result:")
    print("=" * 60)
    result = executor.dry_run(test_case)
    print(json.dumps(result.to_dict(), indent=2, default=str))
