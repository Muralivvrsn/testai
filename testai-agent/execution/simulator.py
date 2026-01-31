"""
TestAI Agent - Test Simulator

Simulates realistic test execution with configurable failure rates,
timing variations, and execution scenarios.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import random
import asyncio


class ExecutionStatus(Enum):
    """Status of a test execution."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"
    FLAKY = "flaky"


@dataclass
class SimulationConfig:
    """Configuration for test simulation."""
    # Base timing (ms)
    min_execution_time: int = 100
    max_execution_time: int = 5000

    # Failure rates (0.0 - 1.0)
    failure_rate: float = 0.1
    flaky_rate: float = 0.05
    timeout_rate: float = 0.02
    error_rate: float = 0.03
    skip_rate: float = 0.01

    # Timing multipliers by category
    category_timing: Dict[str, float] = field(default_factory=lambda: {
        "security": 1.5,
        "performance": 2.0,
        "e2e": 3.0,
        "integration": 2.5,
        "functional": 1.0,
        "ui": 1.2,
        "accessibility": 1.3,
    })

    # Failure likelihood by priority
    priority_failure_modifier: Dict[str, float] = field(default_factory=lambda: {
        "critical": 0.5,  # Critical tests fail less (more stable)
        "high": 0.8,
        "medium": 1.0,
        "low": 1.5,  # Low priority tests fail more
    })

    # Randomness seed for reproducibility
    seed: Optional[int] = None


@dataclass
class StepResult:
    """Result of executing a single test step."""
    step_number: int
    step_text: str
    status: ExecutionStatus
    duration_ms: int
    error_message: Optional[str] = None
    screenshot_path: Optional[str] = None


@dataclass
class SimulationResult:
    """Result of simulating a single test."""
    test_id: str
    test_title: str
    status: ExecutionStatus
    duration_ms: int
    started_at: datetime
    finished_at: datetime
    step_results: List[StepResult] = field(default_factory=list)
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    retry_count: int = 0
    assertions_passed: int = 0
    assertions_failed: int = 0
    logs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestSimulator:
    """
    Simulates realistic test execution.

    This provides a way to test the full pipeline without
    actually running tests against a real application.
    """

    # Common error messages by type
    ERROR_MESSAGES = {
        "timeout": [
            "Timeout waiting for element '.submit-btn' to be visible",
            "Page load timeout exceeded (30000ms)",
            "Network request timed out after 10000ms",
            "Element interaction timed out",
        ],
        "assertion": [
            "Expected 'Success' but got 'Error'",
            "Element text mismatch: expected 'Welcome' received 'Login failed'",
            "Status code assertion failed: expected 200, got 500",
            "Validation message not displayed",
        ],
        "element": [
            "Element '.login-form' not found in the DOM",
            "Stale element reference: element is no longer attached to the DOM",
            "Element is obscured by another element",
            "Cannot interact with disabled element",
        ],
        "network": [
            "Network request failed: ERR_CONNECTION_REFUSED",
            "API returned 502 Bad Gateway",
            "CORS policy blocked the request",
            "SSL certificate verification failed",
        ],
        "script": [
            "JavaScript error: Cannot read property 'click' of null",
            "TypeError: undefined is not a function",
            "ReferenceError: loginForm is not defined",
            "Script execution failed",
        ],
    }

    def __init__(self, config: Optional[SimulationConfig] = None):
        """Initialize the simulator."""
        self.config = config or SimulationConfig()
        if self.config.seed is not None:
            random.seed(self.config.seed)
        self._execution_history: List[SimulationResult] = []

    def simulate_test(self, test: Dict[str, Any]) -> SimulationResult:
        """Simulate execution of a single test."""
        test_id = test.get("id", "unknown")
        test_title = test.get("title", "Untitled Test")
        category = test.get("category", "functional")
        priority = test.get("priority", "medium")
        steps = test.get("steps", [])

        started_at = datetime.now()

        # Determine execution status
        status = self._determine_status(category, priority)

        # Calculate execution time
        base_time = random.randint(
            self.config.min_execution_time,
            self.config.max_execution_time
        )
        timing_multiplier = self.config.category_timing.get(category, 1.0)
        duration_ms = int(base_time * timing_multiplier)

        # Simulate step results
        step_results = self._simulate_steps(steps, status, duration_ms)

        # Generate error details if failed
        error_message = None
        error_type = None
        if status in [ExecutionStatus.FAILED, ExecutionStatus.ERROR, ExecutionStatus.TIMEOUT]:
            error_type, error_message = self._generate_error(status)

        finished_at = datetime.now()

        # Calculate assertions
        assertions_passed = len(steps) if status == ExecutionStatus.PASSED else len(steps) - 1
        assertions_failed = 0 if status == ExecutionStatus.PASSED else 1

        # Generate logs
        logs = self._generate_logs(test_title, status, step_results)

        result = SimulationResult(
            test_id=test_id,
            test_title=test_title,
            status=status,
            duration_ms=duration_ms,
            started_at=started_at,
            finished_at=finished_at,
            step_results=step_results,
            error_message=error_message,
            error_type=error_type,
            retry_count=1 if status == ExecutionStatus.FLAKY else 0,
            assertions_passed=assertions_passed,
            assertions_failed=assertions_failed,
            logs=logs,
            metadata={
                "category": category,
                "priority": priority,
                "step_count": len(steps),
            }
        )

        self._execution_history.append(result)
        return result

    async def simulate_test_async(self, test: Dict[str, Any]) -> SimulationResult:
        """Simulate test execution asynchronously with realistic delays."""
        # Determine timing first
        category = test.get("category", "functional")
        base_time = random.randint(
            self.config.min_execution_time // 10,
            self.config.max_execution_time // 10
        )
        timing_multiplier = self.config.category_timing.get(category, 1.0)
        delay_ms = int(base_time * timing_multiplier)

        # Simulate the delay (scaled down for demo)
        await asyncio.sleep(delay_ms / 1000)

        return self.simulate_test(test)

    def simulate_suite(
        self,
        tests: List[Dict[str, Any]],
        parallel: bool = False,
    ) -> List[SimulationResult]:
        """Simulate execution of a test suite."""
        results = []
        for test in tests:
            result = self.simulate_test(test)
            results.append(result)
        return results

    async def simulate_suite_async(
        self,
        tests: List[Dict[str, Any]],
        parallel: bool = True,
        max_parallel: int = 5,
    ) -> List[SimulationResult]:
        """Simulate suite execution asynchronously."""
        if parallel:
            # Run tests in parallel batches
            results = []
            for i in range(0, len(tests), max_parallel):
                batch = tests[i:i + max_parallel]
                batch_results = await asyncio.gather(
                    *[self.simulate_test_async(test) for test in batch]
                )
                results.extend(batch_results)
            return results
        else:
            # Run tests sequentially
            results = []
            for test in tests:
                result = await self.simulate_test_async(test)
                results.append(result)
            return results

    def _determine_status(self, category: str, priority: str) -> ExecutionStatus:
        """Determine the execution status based on configured rates."""
        roll = random.random()
        failure_modifier = self.config.priority_failure_modifier.get(priority, 1.0)

        # Check each outcome in order
        cumulative = 0.0

        cumulative += self.config.skip_rate
        if roll < cumulative:
            return ExecutionStatus.SKIPPED

        cumulative += self.config.timeout_rate * failure_modifier
        if roll < cumulative:
            return ExecutionStatus.TIMEOUT

        cumulative += self.config.error_rate * failure_modifier
        if roll < cumulative:
            return ExecutionStatus.ERROR

        cumulative += self.config.flaky_rate * failure_modifier
        if roll < cumulative:
            return ExecutionStatus.FLAKY

        cumulative += self.config.failure_rate * failure_modifier
        if roll < cumulative:
            return ExecutionStatus.FAILED

        return ExecutionStatus.PASSED

    def _simulate_steps(
        self,
        steps: List[str],
        overall_status: ExecutionStatus,
        total_duration_ms: int,
    ) -> List[StepResult]:
        """Simulate individual step executions."""
        if not steps:
            return []

        step_results = []
        remaining_duration = total_duration_ms
        fail_at_step = len(steps) - 1 if overall_status != ExecutionStatus.PASSED else -1

        for i, step_text in enumerate(steps):
            # Calculate step duration
            if i == len(steps) - 1:
                step_duration = remaining_duration
            else:
                step_duration = random.randint(
                    remaining_duration // (len(steps) - i) // 2,
                    remaining_duration // (len(steps) - i) * 2
                )
                step_duration = max(50, min(step_duration, remaining_duration - 50))
                remaining_duration -= step_duration

            # Determine step status
            if overall_status == ExecutionStatus.PASSED:
                step_status = ExecutionStatus.PASSED
                error_msg = None
            elif i == fail_at_step:
                step_status = overall_status
                _, error_msg = self._generate_error(overall_status)
            else:
                step_status = ExecutionStatus.PASSED
                error_msg = None

            step_results.append(StepResult(
                step_number=i + 1,
                step_text=step_text,
                status=step_status,
                duration_ms=step_duration,
                error_message=error_msg,
            ))

        return step_results

    def _generate_error(self, status: ExecutionStatus) -> tuple:
        """Generate an appropriate error message."""
        if status == ExecutionStatus.TIMEOUT:
            error_type = "timeout"
        elif status == ExecutionStatus.ERROR:
            error_type = random.choice(["script", "network"])
        else:
            error_type = random.choice(["assertion", "element"])

        messages = self.ERROR_MESSAGES.get(error_type, ["Unknown error"])
        return error_type, random.choice(messages)

    def _generate_logs(
        self,
        test_title: str,
        status: ExecutionStatus,
        step_results: List[StepResult],
    ) -> List[str]:
        """Generate realistic test execution logs."""
        logs = [
            f"[INFO] Starting test: {test_title}",
            "[INFO] Browser initialized",
        ]

        for step in step_results:
            logs.append(f"[STEP {step.step_number}] {step.step_text[:50]}...")
            if step.status == ExecutionStatus.PASSED:
                logs.append(f"[PASS] Step {step.step_number} completed ({step.duration_ms}ms)")
            else:
                logs.append(f"[FAIL] Step {step.step_number} failed: {step.error_message}")

        if status == ExecutionStatus.PASSED:
            logs.append("[PASS] Test completed successfully")
        elif status == ExecutionStatus.FLAKY:
            logs.append("[WARN] Test passed on retry (flaky)")
        else:
            logs.append(f"[FAIL] Test failed with status: {status.value}")

        logs.append("[INFO] Browser closed")
        return logs

    def get_execution_history(self) -> List[SimulationResult]:
        """Get all execution results from this session."""
        return self._execution_history

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for all executed tests."""
        if not self._execution_history:
            return {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "flaky": 0,
                "pass_rate": 0.0,
                "avg_duration_ms": 0,
            }

        total = len(self._execution_history)
        passed = sum(1 for r in self._execution_history if r.status == ExecutionStatus.PASSED)
        failed = sum(1 for r in self._execution_history if r.status == ExecutionStatus.FAILED)
        skipped = sum(1 for r in self._execution_history if r.status == ExecutionStatus.SKIPPED)
        flaky = sum(1 for r in self._execution_history if r.status == ExecutionStatus.FLAKY)
        timeout = sum(1 for r in self._execution_history if r.status == ExecutionStatus.TIMEOUT)
        error = sum(1 for r in self._execution_history if r.status == ExecutionStatus.ERROR)

        total_duration = sum(r.duration_ms for r in self._execution_history)

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "flaky": flaky,
            "timeout": timeout,
            "error": error,
            "pass_rate": passed / total if total > 0 else 0.0,
            "avg_duration_ms": total_duration // total if total > 0 else 0,
            "total_duration_ms": total_duration,
        }

    def reset(self):
        """Reset execution history."""
        self._execution_history = []


def create_simulator(config: Optional[SimulationConfig] = None) -> TestSimulator:
    """Create a test simulator instance."""
    return TestSimulator(config)
