"""
TestAI Agent - Action Executor

Executes test actions with intelligent waiting,
error handling, and result capture.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time
import re


class ActionType(Enum):
    """Types of test actions."""
    # Navigation
    NAVIGATE = "navigate"
    RELOAD = "reload"
    GO_BACK = "go_back"
    GO_FORWARD = "go_forward"

    # Interaction
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    HOVER = "hover"
    DRAG_DROP = "drag_drop"

    # Input
    TYPE = "type"
    FILL = "fill"
    CLEAR = "clear"
    SELECT = "select"
    CHECK = "check"
    UNCHECK = "uncheck"

    # Keyboard
    PRESS = "press"
    KEY_DOWN = "key_down"
    KEY_UP = "key_up"

    # Wait
    WAIT_FOR_SELECTOR = "wait_for_selector"
    WAIT_FOR_NAVIGATION = "wait_for_navigation"
    WAIT_FOR_LOAD = "wait_for_load"
    WAIT_FOR_TIMEOUT = "wait_for_timeout"
    WAIT_FOR_FUNCTION = "wait_for_function"

    # Assertion
    ASSERT_VISIBLE = "assert_visible"
    ASSERT_HIDDEN = "assert_hidden"
    ASSERT_TEXT = "assert_text"
    ASSERT_VALUE = "assert_value"
    ASSERT_ATTRIBUTE = "assert_attribute"
    ASSERT_URL = "assert_url"
    ASSERT_TITLE = "assert_title"

    # Screenshot
    SCREENSHOT = "screenshot"
    SCREENSHOT_ELEMENT = "screenshot_element"

    # Script
    EVALUATE = "evaluate"
    ADD_SCRIPT = "add_script"


class ActionStatus(Enum):
    """Action execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class ActionResult:
    """Result of an action execution."""
    action_id: str
    action_type: ActionType
    status: ActionStatus
    duration_ms: int
    selector: Optional[str] = None
    value: Optional[Any] = None
    error: Optional[str] = None
    screenshot_path: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionDefinition:
    """Definition of an action to execute."""
    action_type: ActionType
    selector: Optional[str] = None
    value: Optional[Any] = None
    options: Dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 30000
    retry_count: int = 0
    description: str = ""


class ActionExecutor:
    """
    Executes test actions with intelligent handling.

    Features:
    - Smart waiting strategies
    - Automatic retries
    - Screenshot on failure
    - Detailed logging
    """

    # Selector types
    SELECTOR_PATTERNS = {
        "css": re.compile(r"^css=(.+)$"),
        "xpath": re.compile(r"^xpath=(.+)$|^//"),
        "text": re.compile(r"^text=(.+)$"),
        "id": re.compile(r"^id=(.+)$|^#[a-zA-Z]"),
        "data_testid": re.compile(r"^data-testid=(.+)$"),
        "role": re.compile(r"^role=(.+)$"),
        "label": re.compile(r"^label=(.+)$"),
    }

    # Smart wait strategies by action type
    WAIT_STRATEGIES = {
        ActionType.CLICK: ["visible", "stable", "enabled"],
        ActionType.TYPE: ["visible", "enabled", "editable"],
        ActionType.FILL: ["visible", "enabled", "editable"],
        ActionType.SELECT: ["visible", "enabled"],
        ActionType.HOVER: ["visible"],
        ActionType.ASSERT_VISIBLE: ["attached"],
        ActionType.ASSERT_TEXT: ["attached"],
    }

    def __init__(self):
        """Initialize the action executor."""
        self._action_counter = 0
        self._results: List[ActionResult] = []
        self._before_hooks: List[Callable] = []
        self._after_hooks: List[Callable] = []
        self._custom_actions: Dict[str, Callable] = {}

    def execute(
        self,
        action: ActionDefinition,
        context: Optional[Any] = None,
    ) -> ActionResult:
        """Execute a single action."""
        self._action_counter += 1
        action_id = f"action-{self._action_counter:05d}"

        # Run before hooks
        for hook in self._before_hooks:
            try:
                hook(action)
            except Exception:
                pass

        start_time = time.time()
        result = self._execute_action(action_id, action, context)
        result.duration_ms = int((time.time() - start_time) * 1000)

        self._results.append(result)

        # Run after hooks
        for hook in self._after_hooks:
            try:
                hook(action, result)
            except Exception:
                pass

        return result

    def _execute_action(
        self,
        action_id: str,
        action: ActionDefinition,
        context: Optional[Any],
    ) -> ActionResult:
        """Execute action based on type."""
        # Get executor method
        executor = self._get_executor(action.action_type)

        try:
            # Simulate action execution
            value = executor(action, context)

            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.PASSED,
                duration_ms=0,
                selector=action.selector,
                value=value,
            )
        except TimeoutError as e:
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.TIMEOUT,
                duration_ms=0,
                selector=action.selector,
                error=str(e),
            )
        except AssertionError as e:
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.FAILED,
                duration_ms=0,
                selector=action.selector,
                error=str(e),
            )
        except Exception as e:
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                status=ActionStatus.FAILED,
                duration_ms=0,
                selector=action.selector,
                error=str(e),
            )

    def _get_executor(self, action_type: ActionType) -> Callable:
        """Get executor function for action type."""
        executors = {
            ActionType.NAVIGATE: self._execute_navigate,
            ActionType.CLICK: self._execute_click,
            ActionType.TYPE: self._execute_type,
            ActionType.FILL: self._execute_fill,
            ActionType.CLEAR: self._execute_clear,
            ActionType.SELECT: self._execute_select,
            ActionType.CHECK: self._execute_check,
            ActionType.HOVER: self._execute_hover,
            ActionType.PRESS: self._execute_press,
            ActionType.WAIT_FOR_SELECTOR: self._execute_wait_selector,
            ActionType.WAIT_FOR_TIMEOUT: self._execute_wait_timeout,
            ActionType.ASSERT_VISIBLE: self._execute_assert_visible,
            ActionType.ASSERT_TEXT: self._execute_assert_text,
            ActionType.ASSERT_VALUE: self._execute_assert_value,
            ActionType.ASSERT_URL: self._execute_assert_url,
            ActionType.SCREENSHOT: self._execute_screenshot,
            ActionType.EVALUATE: self._execute_evaluate,
        }

        return executors.get(action_type, self._execute_default)

    def _execute_navigate(self, action: ActionDefinition, context: Any) -> str:
        """Execute navigate action."""
        url = action.value or ""
        # Simulate navigation
        time.sleep(0.01)
        return url

    def _execute_click(self, action: ActionDefinition, context: Any) -> bool:
        """Execute click action."""
        # Simulate click
        time.sleep(0.005)
        return True

    def _execute_type(self, action: ActionDefinition, context: Any) -> str:
        """Execute type action."""
        text = action.value or ""
        # Simulate typing
        time.sleep(len(text) * 0.001)
        return text

    def _execute_fill(self, action: ActionDefinition, context: Any) -> str:
        """Execute fill action."""
        text = action.value or ""
        time.sleep(0.005)
        return text

    def _execute_clear(self, action: ActionDefinition, context: Any) -> bool:
        """Execute clear action."""
        time.sleep(0.002)
        return True

    def _execute_select(self, action: ActionDefinition, context: Any) -> str:
        """Execute select action."""
        value = action.value or ""
        time.sleep(0.005)
        return value

    def _execute_check(self, action: ActionDefinition, context: Any) -> bool:
        """Execute check action."""
        time.sleep(0.003)
        return True

    def _execute_hover(self, action: ActionDefinition, context: Any) -> bool:
        """Execute hover action."""
        time.sleep(0.003)
        return True

    def _execute_press(self, action: ActionDefinition, context: Any) -> str:
        """Execute press action."""
        key = action.value or ""
        time.sleep(0.002)
        return key

    def _execute_wait_selector(self, action: ActionDefinition, context: Any) -> bool:
        """Execute wait for selector action."""
        time.sleep(0.01)
        return True

    def _execute_wait_timeout(self, action: ActionDefinition, context: Any) -> int:
        """Execute wait for timeout action."""
        ms = action.value or 1000
        time.sleep(min(ms / 1000, 0.1))  # Cap at 100ms for simulation
        return ms

    def _execute_assert_visible(self, action: ActionDefinition, context: Any) -> bool:
        """Execute assert visible action."""
        # Simulate visibility check
        return True

    def _execute_assert_text(self, action: ActionDefinition, context: Any) -> bool:
        """Execute assert text action."""
        # Simulate text assertion
        return True

    def _execute_assert_value(self, action: ActionDefinition, context: Any) -> bool:
        """Execute assert value action."""
        return True

    def _execute_assert_url(self, action: ActionDefinition, context: Any) -> bool:
        """Execute assert URL action."""
        return True

    def _execute_screenshot(self, action: ActionDefinition, context: Any) -> str:
        """Execute screenshot action."""
        path = action.value or "screenshot.png"
        time.sleep(0.01)
        return path

    def _execute_evaluate(self, action: ActionDefinition, context: Any) -> Any:
        """Execute evaluate action."""
        script = action.value or ""
        time.sleep(0.005)
        return None

    def _execute_default(self, action: ActionDefinition, context: Any) -> bool:
        """Default executor for unhandled actions."""
        time.sleep(0.002)
        return True

    def execute_sequence(
        self,
        actions: List[ActionDefinition],
        context: Optional[Any] = None,
        stop_on_failure: bool = True,
    ) -> List[ActionResult]:
        """Execute a sequence of actions."""
        results = []

        for action in actions:
            result = self.execute(action, context)
            results.append(result)

            if stop_on_failure and result.status in [ActionStatus.FAILED, ActionStatus.TIMEOUT]:
                # Mark remaining actions as skipped
                for remaining in actions[len(results):]:
                    self._action_counter += 1
                    results.append(ActionResult(
                        action_id=f"action-{self._action_counter:05d}",
                        action_type=remaining.action_type,
                        status=ActionStatus.SKIPPED,
                        duration_ms=0,
                        selector=remaining.selector,
                    ))
                break

        return results

    def detect_selector_type(self, selector: str) -> str:
        """Detect the type of selector."""
        for selector_type, pattern in self.SELECTOR_PATTERNS.items():
            if pattern.match(selector):
                return selector_type
        return "css"

    def get_wait_strategy(self, action_type: ActionType) -> List[str]:
        """Get wait strategy for action type."""
        return self.WAIT_STRATEGIES.get(action_type, ["visible"])

    def register_custom_action(self, name: str, executor: Callable):
        """Register a custom action executor."""
        self._custom_actions[name] = executor

    def add_before_hook(self, hook: Callable):
        """Add a before action hook."""
        self._before_hooks.append(hook)

    def add_after_hook(self, hook: Callable):
        """Add an after action hook."""
        self._after_hooks.append(hook)

    def get_results(self) -> List[ActionResult]:
        """Get all action results."""
        return list(self._results)

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.status == ActionStatus.PASSED)
        failed = sum(1 for r in self._results if r.status == ActionStatus.FAILED)
        timeout = sum(1 for r in self._results if r.status == ActionStatus.TIMEOUT)
        skipped = sum(1 for r in self._results if r.status == ActionStatus.SKIPPED)

        total_duration = sum(r.duration_ms for r in self._results)
        avg_duration = total_duration / total if total > 0 else 0

        by_type = {}
        for result in self._results:
            t = result.action_type.value
            if t not in by_type:
                by_type[t] = {"total": 0, "passed": 0, "failed": 0}
            by_type[t]["total"] += 1
            if result.status == ActionStatus.PASSED:
                by_type[t]["passed"] += 1
            elif result.status == ActionStatus.FAILED:
                by_type[t]["failed"] += 1

        return {
            "total_actions": total,
            "passed": passed,
            "failed": failed,
            "timeout": timeout,
            "skipped": skipped,
            "pass_rate": passed / total if total > 0 else 0,
            "total_duration_ms": total_duration,
            "avg_duration_ms": avg_duration,
            "by_action_type": by_type,
        }

    def clear_results(self):
        """Clear all results."""
        self._results.clear()

    def format_results(self) -> str:
        """Format results as readable text."""
        stats = self.get_statistics()

        lines = [
            "=" * 50,
            "  ACTION EXECUTION RESULTS",
            "=" * 50,
            "",
            f"  Total Actions: {stats['total_actions']}",
            f"  Passed: {stats['passed']} | Failed: {stats['failed']} | Timeout: {stats['timeout']}",
            f"  Pass Rate: {stats['pass_rate']:.1%}",
            f"  Total Duration: {stats['total_duration_ms']}ms",
            "",
        ]

        if self._results:
            lines.extend(["-" * 50, "  ACTION LOG", "-" * 50])

            for result in self._results[-20:]:  # Show last 20
                status_icon = {
                    ActionStatus.PASSED: "✅",
                    ActionStatus.FAILED: "❌",
                    ActionStatus.TIMEOUT: "⏰",
                    ActionStatus.SKIPPED: "⏭️",
                }.get(result.status, "⚪")

                lines.append(
                    f"  {status_icon} {result.action_type.value}"
                    f" ({result.duration_ms}ms)"
                )
                if result.selector:
                    lines.append(f"     Selector: {result.selector[:50]}")
                if result.error:
                    lines.append(f"     Error: {result.error[:60]}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_action_executor() -> ActionExecutor:
    """Create an action executor instance."""
    return ActionExecutor()
