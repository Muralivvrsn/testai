"""
TestAI Agent - Test Generator

Generates executable test code from parsed
natural language descriptions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional

from .parser import ParsedTest, ParsedStep, ActionIntent, ParsedAssertion, AssertionType


class OutputFormat(Enum):
    """Output format for generated tests."""
    PLAYWRIGHT_PYTHON = "playwright_python"
    PLAYWRIGHT_JS = "playwright_js"
    CYPRESS = "cypress"
    SELENIUM = "selenium"
    PUPPETEER = "puppeteer"
    TESTAI_JSON = "testai_json"


@dataclass
class GenerationConfig:
    """Configuration for test generation."""
    output_format: OutputFormat = OutputFormat.PLAYWRIGHT_PYTHON
    include_comments: bool = True
    include_screenshots: bool = False
    add_waits: bool = True
    default_timeout_ms: int = 30000
    base_url: str = ""
    add_assertions: bool = True


@dataclass
class GeneratedTest:
    """A generated test."""
    name: str
    code: str
    format: OutputFormat
    steps_count: int
    assertions_count: int
    generated_at: datetime = field(default_factory=datetime.now)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestGenerator:
    """
    Generates test code from parsed natural language.

    Features:
    - Multiple output formats
    - Automatic wait insertion
    - Comment generation
    - Best practices enforcement
    """

    def __init__(self, config: Optional[GenerationConfig] = None):
        """Initialize the test generator."""
        self.config = config or GenerationConfig()
        self._generators = {
            OutputFormat.PLAYWRIGHT_PYTHON: self._generate_playwright_python,
            OutputFormat.PLAYWRIGHT_JS: self._generate_playwright_js,
            OutputFormat.CYPRESS: self._generate_cypress,
            OutputFormat.SELENIUM: self._generate_selenium,
            OutputFormat.TESTAI_JSON: self._generate_json,
        }

    def generate(
        self,
        parsed: ParsedTest,
        output_format: Optional[OutputFormat] = None,
    ) -> GeneratedTest:
        """Generate test code from parsed test."""
        format_to_use = output_format or self.config.output_format

        generator = self._generators.get(format_to_use, self._generate_json)
        code, warnings = generator(parsed)

        # Count assertions
        assertion_count = sum(len(s.assertions) for s in parsed.steps)

        return GeneratedTest(
            name=parsed.name,
            code=code,
            format=format_to_use,
            steps_count=len(parsed.steps),
            assertions_count=assertion_count,
            warnings=warnings,
            metadata={
                "original_confidence": parsed.parse_confidence,
                "tags": parsed.tags,
            },
        )

    def _generate_playwright_python(
        self,
        parsed: ParsedTest,
    ) -> tuple[str, List[str]]:
        """Generate Playwright Python test code."""
        warnings = []
        lines = []

        # Imports
        lines.extend([
            "import pytest",
            "from playwright.sync_api import Page, expect",
            "",
            "",
        ])

        # Test function
        test_name = self._to_function_name(parsed.name)
        lines.append(f"def test_{test_name}(page: Page):")

        # Docstring
        if parsed.description:
            lines.extend([
                f'    """',
                f"    {parsed.description}",
            ])
            if parsed.tags:
                lines.append(f"    Tags: {', '.join(parsed.tags)}")
            lines.append(f'    """')

        # Preconditions
        if parsed.preconditions:
            lines.append("    # Preconditions")
            for pre in parsed.preconditions:
                lines.append(f"    # - {pre}")
            lines.append("")

        # Steps
        for step in parsed.steps:
            step_lines, step_warnings = self._generate_step_python(step)
            lines.extend(step_lines)
            warnings.extend(step_warnings)

        return "\n".join(lines), warnings

    def _generate_step_python(
        self,
        step: ParsedStep,
    ) -> tuple[List[str], List[str]]:
        """Generate Python code for a step."""
        lines = []
        warnings = []

        if self.config.include_comments:
            lines.append(f"    # Step {step.step_number}: {step.original_text[:60]}")

        # Generate action code
        action_code, action_warning = self._action_to_python(step)
        if action_warning:
            warnings.append(action_warning)

        lines.append(f"    {action_code}")

        # Generate assertions
        for assertion in step.assertions:
            assertion_code = self._assertion_to_python(assertion)
            lines.append(f"    {assertion_code}")

        lines.append("")
        return lines, warnings

    def _action_to_python(self, step: ParsedStep) -> tuple[str, Optional[str]]:
        """Convert action to Python code."""
        target = step.target or "SELECTOR_NEEDED"
        value = step.value or ""
        warning = None

        if step.target is None and step.action not in [ActionIntent.NAVIGATE, ActionIntent.WAIT, ActionIntent.SCROLL]:
            warning = f"Step {step.step_number}: No target found - manual selector needed"

        # Handle wait with numeric value
        wait_ms = 1000
        if step.action == ActionIntent.WAIT and value:
            try:
                wait_ms = int(value)
            except (ValueError, TypeError):
                wait_ms = 1000

        action_map = {
            ActionIntent.NAVIGATE: f'page.goto("{value or self.config.base_url}")',
            ActionIntent.CLICK: f'page.click("{target}")',
            ActionIntent.TYPE: f'page.fill("{target}", "{value}")',
            ActionIntent.SELECT: f'page.select_option("{target}", "{value}")',
            ActionIntent.HOVER: f'page.hover("{target}")',
            ActionIntent.WAIT: f'page.wait_for_timeout({wait_ms})',
            ActionIntent.SCROLL: f'page.evaluate("window.scrollTo(0, document.body.scrollHeight)")',
            ActionIntent.SCREENSHOT: f'page.screenshot(path="{value or "screenshot.png"}")',
        }

        code = action_map.get(
            step.action,
            f'page.locator("{target}").click()  # Action: {step.action.value}',
        )

        return code, warning

    def _assertion_to_python(self, assertion: ParsedAssertion) -> str:
        """Convert assertion to Python code."""
        target = assertion.target or "SELECTOR_NEEDED"
        expected = assertion.expected_value or ""

        assertion_map = {
            AssertionType.VISIBLE: f'expect(page.locator("{target}")).to_be_visible()',
            AssertionType.HIDDEN: f'expect(page.locator("{target}")).to_be_hidden()',
            AssertionType.TEXT_CONTAINS: f'expect(page.locator("{target}")).to_contain_text("{expected}")',
            AssertionType.TEXT_EQUALS: f'expect(page.locator("{target}")).to_have_text("{expected}")',
            AssertionType.ENABLED: f'expect(page.locator("{target}")).to_be_enabled()',
            AssertionType.DISABLED: f'expect(page.locator("{target}")).to_be_disabled()',
            AssertionType.URL_CONTAINS: f'expect(page).to_have_url(re.compile(".*{expected}.*"))',
            AssertionType.URL_EQUALS: f'expect(page).to_have_url("{expected}")',
        }

        return assertion_map.get(
            assertion.assertion_type,
            f'# TODO: Assertion - {assertion.original_text[:50]}',
        )

    def _generate_playwright_js(
        self,
        parsed: ParsedTest,
    ) -> tuple[str, List[str]]:
        """Generate Playwright JavaScript test code."""
        warnings = []
        lines = []

        # Imports
        lines.extend([
            "const { test, expect } = require('@playwright/test');",
            "",
        ])

        # Test
        test_name = parsed.name
        lines.append(f"test('{test_name}', async ({{ page }}) => {{")

        # Steps
        for step in parsed.steps:
            step_lines, step_warnings = self._generate_step_js(step)
            lines.extend(step_lines)
            warnings.extend(step_warnings)

        lines.append("});")

        return "\n".join(lines), warnings

    def _generate_step_js(
        self,
        step: ParsedStep,
    ) -> tuple[List[str], List[str]]:
        """Generate JavaScript code for a step."""
        lines = []
        warnings = []

        if self.config.include_comments:
            lines.append(f"  // Step {step.step_number}: {step.original_text[:60]}")

        target = step.target or "SELECTOR_NEEDED"
        value = step.value or ""

        if step.target is None:
            warnings.append(f"Step {step.step_number}: No target found")

        action_map = {
            ActionIntent.NAVIGATE: f'  await page.goto("{value}");',
            ActionIntent.CLICK: f'  await page.click("{target}");',
            ActionIntent.TYPE: f'  await page.fill("{target}", "{value}");',
            ActionIntent.SELECT: f'  await page.selectOption("{target}", "{value}");',
            ActionIntent.HOVER: f'  await page.hover("{target}");',
            ActionIntent.WAIT: f'  await page.waitForTimeout({int(value or 1000)});',
        }

        lines.append(action_map.get(
            step.action,
            f'  await page.locator("{target}").click();',
        ))

        # Assertions
        for assertion in step.assertions:
            assertion_code = self._assertion_to_js(assertion)
            lines.append(f"  {assertion_code}")

        lines.append("")
        return lines, warnings

    def _assertion_to_js(self, assertion: ParsedAssertion) -> str:
        """Convert assertion to JavaScript code."""
        target = assertion.target or "SELECTOR_NEEDED"
        expected = assertion.expected_value or ""

        assertion_map = {
            AssertionType.VISIBLE: f'await expect(page.locator("{target}")).toBeVisible();',
            AssertionType.HIDDEN: f'await expect(page.locator("{target}")).toBeHidden();',
            AssertionType.TEXT_CONTAINS: f'await expect(page.locator("{target}")).toContainText("{expected}");',
        }

        return assertion_map.get(
            assertion.assertion_type,
            f'// TODO: Assertion - {assertion.original_text[:50]}',
        )

    def _generate_cypress(
        self,
        parsed: ParsedTest,
    ) -> tuple[str, List[str]]:
        """Generate Cypress test code."""
        warnings = []
        lines = []

        lines.extend([
            f"describe('{parsed.name}', () => {{",
            f"  it('should pass', () => {{",
        ])

        for step in parsed.steps:
            target = step.target or "SELECTOR_NEEDED"
            value = step.value or ""

            if step.target is None:
                warnings.append(f"Step {step.step_number}: No target found")

            action_map = {
                ActionIntent.NAVIGATE: f'    cy.visit("{value}");',
                ActionIntent.CLICK: f'    cy.get("{target}").click();',
                ActionIntent.TYPE: f'    cy.get("{target}").type("{value}");',
                ActionIntent.SELECT: f'    cy.get("{target}").select("{value}");',
            }

            lines.append(action_map.get(
                step.action,
                f'    cy.get("{target}").click();',
            ))

        lines.extend([
            "  });",
            "});",
        ])

        return "\n".join(lines), warnings

    def _generate_selenium(
        self,
        parsed: ParsedTest,
    ) -> tuple[str, List[str]]:
        """Generate Selenium Python test code."""
        warnings = []
        lines = []

        lines.extend([
            "import pytest",
            "from selenium import webdriver",
            "from selenium.webdriver.common.by import By",
            "from selenium.webdriver.support.ui import WebDriverWait",
            "from selenium.webdriver.support import expected_conditions as EC",
            "",
            "",
        ])

        test_name = self._to_function_name(parsed.name)
        lines.append(f"def test_{test_name}(driver):")

        for step in parsed.steps:
            target = step.target or "SELECTOR_NEEDED"
            value = step.value or ""

            if step.target is None:
                warnings.append(f"Step {step.step_number}: No target found")

            action_map = {
                ActionIntent.NAVIGATE: f'    driver.get("{value}")',
                ActionIntent.CLICK: f'    driver.find_element(By.CSS_SELECTOR, "{target}").click()',
                ActionIntent.TYPE: f'    driver.find_element(By.CSS_SELECTOR, "{target}").send_keys("{value}")',
            }

            if self.config.include_comments:
                lines.append(f"    # {step.original_text[:60]}")

            lines.append(action_map.get(
                step.action,
                f'    driver.find_element(By.CSS_SELECTOR, "{target}").click()',
            ))

        return "\n".join(lines), warnings

    def _generate_json(
        self,
        parsed: ParsedTest,
    ) -> tuple[str, List[str]]:
        """Generate TestAI JSON format."""
        import json

        test_data = {
            "name": parsed.name,
            "description": parsed.description,
            "priority": parsed.priority,
            "tags": parsed.tags,
            "preconditions": parsed.preconditions,
            "steps": [
                {
                    "step": step.step_number,
                    "action": step.action.value,
                    "target": step.target,
                    "value": step.value,
                    "assertions": [
                        {
                            "type": a.assertion_type.value,
                            "target": a.target,
                            "expected": a.expected_value,
                        }
                        for a in step.assertions
                    ],
                }
                for step in parsed.steps
            ],
        }

        return json.dumps(test_data, indent=2), []

    def _to_function_name(self, name: str) -> str:
        """Convert name to valid function name."""
        import re
        # Remove special characters and convert to snake_case
        clean = re.sub(r"[^\w\s]", "", name.lower())
        return re.sub(r"\s+", "_", clean)

    def generate_batch(
        self,
        parsed_tests: List[ParsedTest],
        output_format: Optional[OutputFormat] = None,
    ) -> List[GeneratedTest]:
        """Generate multiple tests."""
        return [self.generate(p, output_format) for p in parsed_tests]

    def format_generated(self, generated: GeneratedTest) -> str:
        """Format generated test for display."""
        lines = [
            "=" * 60,
            f"  GENERATED TEST: {generated.name}",
            "=" * 60,
            "",
            f"  Format: {generated.format.value}",
            f"  Steps: {generated.steps_count}",
            f"  Assertions: {generated.assertions_count}",
            f"  Generated: {generated.generated_at.strftime('%Y-%m-%d %H:%M')}",
            "",
        ]

        if generated.warnings:
            lines.append("  Warnings:")
            for warning in generated.warnings:
                lines.append(f"    ⚠️ {warning}")
            lines.append("")

        lines.extend([
            "-" * 60,
            "  CODE",
            "-" * 60,
            "",
            generated.code,
            "",
            "=" * 60,
        ])

        return "\n".join(lines)


def create_test_generator(
    config: Optional[GenerationConfig] = None,
) -> TestGenerator:
    """Create a test generator instance."""
    return TestGenerator(config)
