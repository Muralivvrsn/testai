"""
TestAI Agent - Test Runner Engine

Orchestrates test execution with intelligent scheduling,
parallel execution, and comprehensive result tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time
import uuid

from .browser import BrowserManager, BrowserConfig, BrowserType, create_browser_manager
from .actions import ActionExecutor, ActionType, ActionDefinition, ActionResult, ActionStatus, create_action_executor


class RunStatus(Enum):
    """Test run status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class RunPhase(Enum):
    """Test run phases."""
    SETUP = "setup"
    EXECUTION = "execution"
    TEARDOWN = "teardown"
    COMPLETE = "complete"


@dataclass
class StepResult:
    """Result of a test step."""
    step_id: str
    name: str
    description: str
    status: RunStatus
    duration_ms: int
    actions: List[ActionResult]
    error: Optional[str] = None
    screenshot_path: Optional[str] = None
    logs: List[str] = field(default_factory=list)


@dataclass
class RunResult:
    """Result of a test run."""
    run_id: str
    test_id: str
    test_name: str
    status: RunStatus
    phase: RunPhase
    duration_ms: int
    steps: List[StepResult]
    browser_type: BrowserType
    viewport: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    screenshot_paths: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def passed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == RunStatus.PASSED)

    @property
    def failed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == RunStatus.FAILED)


@dataclass
class TestDefinition:
    """Definition of a test to execute."""
    test_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    tags: List[str] = field(default_factory=list)
    priority: int = 5
    timeout_ms: int = 60000
    setup_steps: List[Dict[str, Any]] = field(default_factory=list)
    teardown_steps: List[Dict[str, Any]] = field(default_factory=list)
    browser_config: Optional[BrowserConfig] = None


@dataclass
class RunnerConfig:
    """Test runner configuration."""
    parallel_tests: int = 1
    retry_failed: int = 0
    timeout_ms: int = 60000
    screenshot_on_failure: bool = True
    screenshot_on_success: bool = False
    video_recording: bool = False
    slow_mo_ms: int = 0
    headless: bool = True
    default_browser: BrowserType = BrowserType.CHROMIUM
    viewport_width: int = 1920
    viewport_height: int = 1080
    base_url: str = ""


class TestRunner:
    """
    Orchestrates test execution.

    Features:
    - Intelligent test scheduling
    - Parallel execution
    - Automatic retries
    - Screenshot capture
    - Detailed reporting
    """

    def __init__(self, config: Optional[RunnerConfig] = None):
        """Initialize the test runner."""
        self.config = config or RunnerConfig()
        self._browser_manager = create_browser_manager(
            max_instances=self.config.parallel_tests
        )
        self._action_executor = create_action_executor()
        self._run_counter = 0
        self._step_counter = 0
        self._results: Dict[str, RunResult] = {}
        self._before_test_hooks: List[Callable] = []
        self._after_test_hooks: List[Callable] = []
        self._before_step_hooks: List[Callable] = []
        self._after_step_hooks: List[Callable] = []

    def run_test(
        self,
        test: TestDefinition,
        browser_type: Optional[BrowserType] = None,
    ) -> RunResult:
        """Run a single test."""
        self._run_counter += 1
        run_id = f"run-{self._run_counter:05d}-{uuid.uuid4().hex[:8]}"

        browser_type = browser_type or self.config.default_browser

        result = RunResult(
            run_id=run_id,
            test_id=test.test_id,
            test_name=test.name,
            status=RunStatus.PENDING,
            phase=RunPhase.SETUP,
            duration_ms=0,
            steps=[],
            browser_type=browser_type,
            viewport=f"{self.config.viewport_width}x{self.config.viewport_height}",
            started_at=datetime.now(),
        )

        # Run before test hooks
        for hook in self._before_test_hooks:
            try:
                hook(test, result)
            except Exception:
                pass

        start_time = time.time()

        try:
            # Create browser instance
            browser_config = test.browser_config or BrowserConfig(
                browser_type=browser_type,
                headless=self.config.headless,
                slow_mo_ms=self.config.slow_mo_ms,
            )
            instance = self._browser_manager.create_instance(browser_config)
            context = self._browser_manager.create_context(instance.instance_id)

            result.status = RunStatus.RUNNING

            # Run setup steps
            if test.setup_steps:
                result.phase = RunPhase.SETUP
                setup_result = self._run_steps(
                    test.setup_steps, "Setup", context
                )
                result.steps.extend(setup_result)

                if any(s.status == RunStatus.FAILED for s in setup_result):
                    result.status = RunStatus.FAILED
                    result.error = "Setup failed"
                    return self._finalize_result(result, start_time)

            # Run test steps
            result.phase = RunPhase.EXECUTION
            test_results = self._run_steps(
                test.steps, "Test", context
            )
            result.steps.extend(test_results)

            # Determine status
            if any(s.status == RunStatus.FAILED for s in test_results):
                result.status = RunStatus.FAILED
            else:
                result.status = RunStatus.PASSED

            # Run teardown steps
            if test.teardown_steps:
                result.phase = RunPhase.TEARDOWN
                teardown_result = self._run_steps(
                    test.teardown_steps, "Teardown", context
                )
                result.steps.extend(teardown_result)

            # Cleanup browser
            self._browser_manager.close_context(context.context_id)
            self._browser_manager.close_instance(instance.instance_id)

        except Exception as e:
            result.status = RunStatus.ERRORED
            result.error = str(e)

        return self._finalize_result(result, start_time)

    def _run_steps(
        self,
        steps: List[Dict[str, Any]],
        prefix: str,
        context: Any,
    ) -> List[StepResult]:
        """Run a list of steps."""
        results = []

        for i, step_def in enumerate(steps):
            self._step_counter += 1
            step_id = f"step-{self._step_counter:05d}"

            step_name = step_def.get("name", f"{prefix} Step {i + 1}")
            step_desc = step_def.get("description", "")

            # Run before step hooks
            for hook in self._before_step_hooks:
                try:
                    hook(step_def)
                except Exception:
                    pass

            start_time = time.time()

            # Convert step to actions
            actions = self._step_to_actions(step_def)
            action_results = self._action_executor.execute_sequence(
                actions, context
            )

            # Determine step status
            if any(a.status == ActionStatus.FAILED for a in action_results):
                status = RunStatus.FAILED
                error = next(
                    (a.error for a in action_results if a.error),
                    "Step failed"
                )
            elif any(a.status == ActionStatus.TIMEOUT for a in action_results):
                status = RunStatus.FAILED
                error = "Step timed out"
            else:
                status = RunStatus.PASSED
                error = None

            duration_ms = int((time.time() - start_time) * 1000)

            step_result = StepResult(
                step_id=step_id,
                name=step_name,
                description=step_desc,
                status=status,
                duration_ms=duration_ms,
                actions=action_results,
                error=error,
            )

            results.append(step_result)

            # Run after step hooks
            for hook in self._after_step_hooks:
                try:
                    hook(step_def, step_result)
                except Exception:
                    pass

            # Stop on failure if configured
            if status == RunStatus.FAILED:
                break

        return results

    def _step_to_actions(self, step: Dict[str, Any]) -> List[ActionDefinition]:
        """Convert a step definition to actions."""
        actions = []

        action_type_str = step.get("action", "click")
        selector = step.get("selector")
        value = step.get("value")
        url = step.get("url")

        # Map string to ActionType
        action_map = {
            "navigate": ActionType.NAVIGATE,
            "click": ActionType.CLICK,
            "type": ActionType.TYPE,
            "fill": ActionType.FILL,
            "clear": ActionType.CLEAR,
            "select": ActionType.SELECT,
            "check": ActionType.CHECK,
            "uncheck": ActionType.UNCHECK,
            "hover": ActionType.HOVER,
            "press": ActionType.PRESS,
            "wait": ActionType.WAIT_FOR_SELECTOR,
            "wait_timeout": ActionType.WAIT_FOR_TIMEOUT,
            "assert_visible": ActionType.ASSERT_VISIBLE,
            "assert_text": ActionType.ASSERT_TEXT,
            "assert_value": ActionType.ASSERT_VALUE,
            "assert_url": ActionType.ASSERT_URL,
            "screenshot": ActionType.SCREENSHOT,
            "evaluate": ActionType.EVALUATE,
        }

        action_type = action_map.get(action_type_str, ActionType.CLICK)

        # Handle navigation specially
        if action_type == ActionType.NAVIGATE:
            value = url or value

        actions.append(ActionDefinition(
            action_type=action_type,
            selector=selector,
            value=value,
            options=step.get("options", {}),
            timeout_ms=step.get("timeout", 30000),
            description=step.get("description", ""),
        ))

        return actions

    def _finalize_result(
        self,
        result: RunResult,
        start_time: float,
    ) -> RunResult:
        """Finalize a run result."""
        result.duration_ms = int((time.time() - start_time) * 1000)
        result.completed_at = datetime.now()
        result.phase = RunPhase.COMPLETE

        self._results[result.run_id] = result

        # Run after test hooks
        for hook in self._after_test_hooks:
            try:
                hook(result)
            except Exception:
                pass

        return result

    def run_tests(
        self,
        tests: List[TestDefinition],
        browser_type: Optional[BrowserType] = None,
    ) -> List[RunResult]:
        """Run multiple tests."""
        results = []

        for test in tests:
            result = self.run_test(test, browser_type)
            results.append(result)

            # Retry failed tests
            if result.status == RunStatus.FAILED and self.config.retry_failed > 0:
                for retry in range(self.config.retry_failed):
                    retry_result = self.run_test(test, browser_type)
                    retry_result.metadata["retry"] = retry + 1

                    if retry_result.status == RunStatus.PASSED:
                        results[-1] = retry_result
                        break

        return results

    def run_in_browsers(
        self,
        test: TestDefinition,
        browser_types: List[BrowserType],
    ) -> Dict[BrowserType, RunResult]:
        """Run a test in multiple browsers."""
        results = {}

        for browser_type in browser_types:
            result = self.run_test(test, browser_type)
            results[browser_type] = result

        return results

    def get_result(self, run_id: str) -> Optional[RunResult]:
        """Get a run result by ID."""
        return self._results.get(run_id)

    def get_results(self) -> List[RunResult]:
        """Get all run results."""
        return list(self._results.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get runner statistics."""
        results = list(self._results.values())
        total = len(results)
        passed = sum(1 for r in results if r.status == RunStatus.PASSED)
        failed = sum(1 for r in results if r.status == RunStatus.FAILED)
        errored = sum(1 for r in results if r.status == RunStatus.ERRORED)

        total_duration = sum(r.duration_ms for r in results)
        avg_duration = total_duration / total if total > 0 else 0

        total_steps = sum(r.step_count for r in results)
        passed_steps = sum(r.passed_steps for r in results)

        by_browser = {}
        for result in results:
            b = result.browser_type.value
            if b not in by_browser:
                by_browser[b] = {"total": 0, "passed": 0, "failed": 0}
            by_browser[b]["total"] += 1
            if result.status == RunStatus.PASSED:
                by_browser[b]["passed"] += 1
            elif result.status == RunStatus.FAILED:
                by_browser[b]["failed"] += 1

        return {
            "total_runs": total,
            "passed": passed,
            "failed": failed,
            "errored": errored,
            "pass_rate": passed / total if total > 0 else 0,
            "total_duration_ms": total_duration,
            "avg_duration_ms": avg_duration,
            "total_steps": total_steps,
            "passed_steps": passed_steps,
            "by_browser": by_browser,
        }

    def add_before_test_hook(self, hook: Callable):
        """Add a before test hook."""
        self._before_test_hooks.append(hook)

    def add_after_test_hook(self, hook: Callable):
        """Add an after test hook."""
        self._after_test_hooks.append(hook)

    def add_before_step_hook(self, hook: Callable):
        """Add a before step hook."""
        self._before_step_hooks.append(hook)

    def add_after_step_hook(self, hook: Callable):
        """Add an after step hook."""
        self._after_step_hooks.append(hook)

    def cleanup(self):
        """Cleanup resources."""
        self._browser_manager.cleanup()

    def format_results(self) -> str:
        """Format results as readable text."""
        stats = self.get_statistics()

        lines = [
            "=" * 60,
            "  TEST RUNNER RESULTS",
            "=" * 60,
            "",
            f"  Total Runs: {stats['total_runs']}",
            f"  Passed: {stats['passed']} | Failed: {stats['failed']} | Errors: {stats['errored']}",
            f"  Pass Rate: {stats['pass_rate']:.1%}",
            f"  Total Duration: {stats['total_duration_ms']}ms",
            f"  Total Steps: {stats['total_steps']} ({stats['passed_steps']} passed)",
            "",
        ]

        if stats["by_browser"]:
            lines.append("  By Browser:")
            for browser, data in stats["by_browser"].items():
                rate = data["passed"] / data["total"] if data["total"] > 0 else 0
                lines.append(
                    f"    {browser}: {data['passed']}/{data['total']} ({rate:.1%})"
                )

        if self._results:
            lines.extend(["", "-" * 60, "  RECENT RUNS", "-" * 60])

            for result in list(self._results.values())[-10:]:
                status_icon = {
                    RunStatus.PASSED: "✅",
                    RunStatus.FAILED: "❌",
                    RunStatus.ERRORED: "💥",
                    RunStatus.SKIPPED: "⏭️",
                }.get(result.status, "⚪")

                lines.extend([
                    "",
                    f"  {status_icon} {result.test_name}",
                    f"     Browser: {result.browser_type.value} | Steps: {result.passed_steps}/{result.step_count}",
                    f"     Duration: {result.duration_ms}ms",
                ])

                if result.error:
                    lines.append(f"     Error: {result.error[:60]}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_runner(config: Optional[RunnerConfig] = None) -> TestRunner:
    """Create a test runner instance."""
    return TestRunner(config)
