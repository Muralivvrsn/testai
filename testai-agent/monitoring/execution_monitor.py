"""
TestAI Agent - Execution Monitor

Real-time monitoring of test execution with event tracking,
failure detection, and intelligent control capabilities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import threading
import time


class EventType(Enum):
    """Types of execution events."""
    TEST_STARTED = "test_started"
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    TEST_SKIPPED = "test_skipped"
    TEST_FLAKY = "test_flaky"
    SUITE_STARTED = "suite_started"
    SUITE_COMPLETED = "suite_completed"
    ERROR = "error"
    WARNING = "warning"
    PROGRESS = "progress"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    PAUSE_REQUESTED = "pause_requested"
    RESUME_REQUESTED = "resume_requested"


class MonitorState(Enum):
    """States of the monitor."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ExecutionEvent:
    """An event during test execution."""
    event_type: EventType
    timestamp: datetime
    test_id: Optional[str] = None
    test_title: Optional[str] = None
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class MonitorConfig:
    """Configuration for the execution monitor."""
    # Thresholds
    failure_threshold: float = 0.3  # Pause if failure rate exceeds this
    consecutive_failures: int = 5  # Pause after this many consecutive failures
    max_test_duration_ms: int = 60000  # Flag tests exceeding this

    # Behavior
    auto_pause_on_threshold: bool = True
    auto_pause_on_consecutive: bool = True
    collect_screenshots: bool = False

    # Callbacks
    on_event_callback: Optional[Callable[[ExecutionEvent], None]] = None
    on_state_change_callback: Optional[Callable[[MonitorState], None]] = None


@dataclass
class ExecutionStats:
    """Real-time execution statistics."""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    flaky: int = 0
    in_progress: int = 0
    pass_rate: float = 0.0
    failure_rate: float = 0.0
    avg_duration_ms: float = 0.0
    elapsed_time_ms: int = 0
    estimated_remaining_ms: int = 0
    consecutive_failures: int = 0


class ExecutionMonitor:
    """
    Real-time monitor for test execution.

    Tracks progress, detects patterns, and can intelligently
    pause execution based on configurable thresholds.
    """

    def __init__(self, config: Optional[MonitorConfig] = None):
        """Initialize the monitor."""
        self.config = config or MonitorConfig()
        self._state = MonitorState.IDLE
        self._events: List[ExecutionEvent] = []
        self._stats = ExecutionStats()
        self._start_time: Optional[datetime] = None
        self._durations: List[int] = []
        self._lock = threading.Lock()
        self._listeners: List[Callable[[ExecutionEvent], None]] = []

        if self.config.on_event_callback:
            self._listeners.append(self.config.on_event_callback)

    @property
    def state(self) -> MonitorState:
        """Get current monitor state."""
        return self._state

    @property
    def stats(self) -> ExecutionStats:
        """Get current execution statistics."""
        return self._stats

    def add_listener(self, callback: Callable[[ExecutionEvent], None]):
        """Add an event listener."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[ExecutionEvent], None]):
        """Remove an event listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def start_suite(self, total_tests: int, suite_name: str = "Test Suite"):
        """Signal the start of a test suite."""
        with self._lock:
            self._state = MonitorState.RUNNING
            self._start_time = datetime.now()
            self._stats = ExecutionStats(total_tests=total_tests)
            self._events = []
            self._durations = []

            event = ExecutionEvent(
                event_type=EventType.SUITE_STARTED,
                timestamp=datetime.now(),
                message=f"Started execution of {suite_name} with {total_tests} tests",
                details={"suite_name": suite_name, "total_tests": total_tests},
            )
            self._record_event(event)
            self._notify_state_change()

    def test_started(self, test_id: str, test_title: str):
        """Signal the start of a test."""
        with self._lock:
            self._stats.in_progress += 1

            event = ExecutionEvent(
                event_type=EventType.TEST_STARTED,
                timestamp=datetime.now(),
                test_id=test_id,
                test_title=test_title,
                message=f"Started: {test_title}",
            )
            self._record_event(event)

    def test_passed(self, test_id: str, test_title: str, duration_ms: int = 0):
        """Signal a passed test."""
        with self._lock:
            self._stats.passed += 1
            self._stats.in_progress = max(0, self._stats.in_progress - 1)
            self._stats.consecutive_failures = 0
            self._durations.append(duration_ms)
            self._update_rates()

            event = ExecutionEvent(
                event_type=EventType.TEST_PASSED,
                timestamp=datetime.now(),
                test_id=test_id,
                test_title=test_title,
                message=f"Passed: {test_title} ({duration_ms}ms)",
                duration_ms=duration_ms,
            )
            self._record_event(event)

            # Check for slow test
            if duration_ms > self.config.max_test_duration_ms:
                self._record_warning(test_id, test_title, f"Slow test: {duration_ms}ms")

    def test_failed(
        self,
        test_id: str,
        test_title: str,
        error_message: str = "",
        duration_ms: int = 0,
    ):
        """Signal a failed test."""
        with self._lock:
            self._stats.failed += 1
            self._stats.in_progress = max(0, self._stats.in_progress - 1)
            self._stats.consecutive_failures += 1
            self._durations.append(duration_ms)
            self._update_rates()

            event = ExecutionEvent(
                event_type=EventType.TEST_FAILED,
                timestamp=datetime.now(),
                test_id=test_id,
                test_title=test_title,
                message=f"Failed: {test_title}",
                details={"error": error_message},
                duration_ms=duration_ms,
            )
            self._record_event(event)

            # Check thresholds
            self._check_thresholds()

    def test_skipped(self, test_id: str, test_title: str, reason: str = ""):
        """Signal a skipped test."""
        with self._lock:
            self._stats.skipped += 1
            self._stats.in_progress = max(0, self._stats.in_progress - 1)
            self._update_rates()

            event = ExecutionEvent(
                event_type=EventType.TEST_SKIPPED,
                timestamp=datetime.now(),
                test_id=test_id,
                test_title=test_title,
                message=f"Skipped: {test_title}",
                details={"reason": reason},
            )
            self._record_event(event)

    def test_flaky(self, test_id: str, test_title: str, retries: int = 0):
        """Signal a flaky test (passed on retry)."""
        with self._lock:
            self._stats.flaky += 1
            self._stats.passed += 1  # Flaky counts as passed
            self._stats.in_progress = max(0, self._stats.in_progress - 1)
            self._stats.consecutive_failures = 0
            self._update_rates()

            event = ExecutionEvent(
                event_type=EventType.TEST_FLAKY,
                timestamp=datetime.now(),
                test_id=test_id,
                test_title=test_title,
                message=f"Flaky (passed on retry {retries}): {test_title}",
                details={"retries": retries},
            )
            self._record_event(event)

    def complete_suite(self):
        """Signal the completion of the test suite."""
        with self._lock:
            self._state = MonitorState.STOPPED

            elapsed = 0
            if self._start_time:
                elapsed = int((datetime.now() - self._start_time).total_seconds() * 1000)
            self._stats.elapsed_time_ms = elapsed

            event = ExecutionEvent(
                event_type=EventType.SUITE_COMPLETED,
                timestamp=datetime.now(),
                message=f"Suite completed: {self._stats.passed}/{self._stats.total_tests} passed",
                details={
                    "passed": self._stats.passed,
                    "failed": self._stats.failed,
                    "skipped": self._stats.skipped,
                    "flaky": self._stats.flaky,
                    "elapsed_ms": elapsed,
                },
            )
            self._record_event(event)
            self._notify_state_change()

    def pause(self, reason: str = "Manual pause"):
        """Pause the execution."""
        with self._lock:
            if self._state == MonitorState.RUNNING:
                self._state = MonitorState.PAUSED

                event = ExecutionEvent(
                    event_type=EventType.PAUSE_REQUESTED,
                    timestamp=datetime.now(),
                    message=f"Execution paused: {reason}",
                    details={"reason": reason},
                )
                self._record_event(event)
                self._notify_state_change()

    def resume(self):
        """Resume the execution."""
        with self._lock:
            if self._state == MonitorState.PAUSED:
                self._state = MonitorState.RUNNING

                event = ExecutionEvent(
                    event_type=EventType.RESUME_REQUESTED,
                    timestamp=datetime.now(),
                    message="Execution resumed",
                )
                self._record_event(event)
                self._notify_state_change()

    def stop(self, reason: str = "Manual stop"):
        """Stop the execution."""
        with self._lock:
            self._state = MonitorState.STOPPED

            event = ExecutionEvent(
                event_type=EventType.ERROR,
                timestamp=datetime.now(),
                message=f"Execution stopped: {reason}",
                details={"reason": reason},
            )
            self._record_event(event)
            self._notify_state_change()

    def _update_rates(self):
        """Update pass/failure rates and timing estimates."""
        completed = self._stats.passed + self._stats.failed + self._stats.skipped
        if completed > 0:
            self._stats.pass_rate = self._stats.passed / completed
            self._stats.failure_rate = self._stats.failed / completed

        if self._durations:
            self._stats.avg_duration_ms = sum(self._durations) / len(self._durations)

        # Update elapsed time
        if self._start_time:
            self._stats.elapsed_time_ms = int(
                (datetime.now() - self._start_time).total_seconds() * 1000
            )

        # Estimate remaining time
        remaining = self._stats.total_tests - completed
        if remaining > 0 and self._stats.avg_duration_ms > 0:
            self._stats.estimated_remaining_ms = int(remaining * self._stats.avg_duration_ms)

    def _check_thresholds(self):
        """Check if thresholds are exceeded and take action."""
        # Check failure rate threshold
        if self.config.auto_pause_on_threshold:
            if self._stats.failure_rate > self.config.failure_threshold:
                self._record_threshold_exceeded(
                    f"Failure rate ({self._stats.failure_rate:.1%}) exceeds threshold "
                    f"({self.config.failure_threshold:.1%})"
                )
                self._state = MonitorState.PAUSED

        # Check consecutive failures
        if self.config.auto_pause_on_consecutive:
            if self._stats.consecutive_failures >= self.config.consecutive_failures:
                self._record_threshold_exceeded(
                    f"Consecutive failures ({self._stats.consecutive_failures}) "
                    f"reached threshold ({self.config.consecutive_failures})"
                )
                self._state = MonitorState.PAUSED

    def _record_event(self, event: ExecutionEvent):
        """Record an event and notify listeners."""
        self._events.append(event)
        for listener in self._listeners:
            try:
                listener(event)
            except Exception:
                pass  # Don't let listener errors affect monitor

    def _record_warning(self, test_id: str, test_title: str, message: str):
        """Record a warning event."""
        event = ExecutionEvent(
            event_type=EventType.WARNING,
            timestamp=datetime.now(),
            test_id=test_id,
            test_title=test_title,
            message=message,
        )
        self._record_event(event)

    def _record_threshold_exceeded(self, message: str):
        """Record a threshold exceeded event."""
        event = ExecutionEvent(
            event_type=EventType.THRESHOLD_EXCEEDED,
            timestamp=datetime.now(),
            message=message,
        )
        self._record_event(event)

    def _notify_state_change(self):
        """Notify listeners of state change."""
        if self.config.on_state_change_callback:
            try:
                self.config.on_state_change_callback(self._state)
            except Exception:
                pass

    def get_events(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 100,
    ) -> List[ExecutionEvent]:
        """Get recorded events, optionally filtered by type."""
        with self._lock:
            events = self._events
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            return events[-limit:]

    def get_failures(self) -> List[ExecutionEvent]:
        """Get all failure events."""
        return self.get_events(EventType.TEST_FAILED)

    def get_progress_summary(self) -> Dict[str, Any]:
        """Get a summary of current progress."""
        with self._lock:
            completed = self._stats.passed + self._stats.failed + self._stats.skipped
            remaining = self._stats.total_tests - completed

            return {
                "state": self._state.value,
                "total_tests": self._stats.total_tests,
                "completed": completed,
                "remaining": remaining,
                "progress_pct": completed / max(self._stats.total_tests, 1),
                "passed": self._stats.passed,
                "failed": self._stats.failed,
                "skipped": self._stats.skipped,
                "flaky": self._stats.flaky,
                "pass_rate": self._stats.pass_rate,
                "failure_rate": self._stats.failure_rate,
                "consecutive_failures": self._stats.consecutive_failures,
                "elapsed_ms": self._stats.elapsed_time_ms,
                "estimated_remaining_ms": self._stats.estimated_remaining_ms,
                "avg_duration_ms": self._stats.avg_duration_ms,
            }

    def format_progress(self) -> str:
        """Format progress as a string."""
        summary = self.get_progress_summary()
        completed = summary["completed"]
        total = summary["total_tests"]
        progress_pct = summary["progress_pct"]

        # Progress bar
        bar_width = 30
        filled = int(bar_width * progress_pct)
        bar = "█" * filled + "░" * (bar_width - filled)

        elapsed_sec = summary["elapsed_ms"] / 1000
        remaining_sec = summary["estimated_remaining_ms"] / 1000

        lines = [
            f"[{bar}] {progress_pct:.0%}",
            f"Progress: {completed}/{total} tests",
            f"✅ Passed: {summary['passed']}  ❌ Failed: {summary['failed']}  ⏭️ Skipped: {summary['skipped']}",
            f"Pass Rate: {summary['pass_rate']:.1%}",
            f"Elapsed: {elapsed_sec:.1f}s  Remaining: {remaining_sec:.1f}s (est)",
            f"State: {summary['state'].upper()}",
        ]

        if summary["consecutive_failures"] > 0:
            lines.append(f"⚠️ Consecutive failures: {summary['consecutive_failures']}")

        return "\n".join(lines)


def create_monitor(config: Optional[MonitorConfig] = None) -> ExecutionMonitor:
    """Create an execution monitor instance."""
    return ExecutionMonitor(config)
