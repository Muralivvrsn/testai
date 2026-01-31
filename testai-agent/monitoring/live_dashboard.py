"""
TestAI Agent - Live Dashboard

Real-time dashboard for monitoring test execution with
live updates and visual progress indicators.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
import threading
import time

from .execution_monitor import ExecutionMonitor, ExecutionEvent, EventType, MonitorState


@dataclass
class DashboardUpdate:
    """An update to be displayed on the dashboard."""
    timestamp: datetime
    update_type: str
    content: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # info, success, warning, error


class LiveDashboard:
    """
    Live dashboard for real-time test execution monitoring.

    Provides formatted output suitable for terminal display
    or integration with UI frameworks.
    """

    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
    }

    def __init__(
        self,
        monitor: ExecutionMonitor,
        use_color: bool = True,
        max_history: int = 50,
    ):
        """Initialize the dashboard."""
        self.monitor = monitor
        self.use_color = use_color
        self.max_history = max_history
        self._updates: List[DashboardUpdate] = []
        self._callbacks: List[Callable[[DashboardUpdate], None]] = []

        # Register as listener on monitor
        monitor.add_listener(self._on_event)

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if enabled."""
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def _on_event(self, event: ExecutionEvent):
        """Handle events from the monitor."""
        update = self._event_to_update(event)
        if update:
            self._updates.append(update)
            if len(self._updates) > self.max_history:
                self._updates.pop(0)

            for callback in self._callbacks:
                try:
                    callback(update)
                except Exception:
                    pass

    def _event_to_update(self, event: ExecutionEvent) -> Optional[DashboardUpdate]:
        """Convert an execution event to a dashboard update."""
        if event.event_type == EventType.TEST_STARTED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="test_start",
                content=f"▶️ {event.test_title}",
                severity="info",
            )

        elif event.event_type == EventType.TEST_PASSED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="test_pass",
                content=f"✅ {event.test_title} ({event.duration_ms}ms)",
                severity="success",
            )

        elif event.event_type == EventType.TEST_FAILED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="test_fail",
                content=f"❌ {event.test_title}",
                details=event.details,
                severity="error",
            )

        elif event.event_type == EventType.TEST_SKIPPED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="test_skip",
                content=f"⏭️ {event.test_title}",
                severity="warning",
            )

        elif event.event_type == EventType.TEST_FLAKY:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="test_flaky",
                content=f"⚠️ Flaky: {event.test_title}",
                severity="warning",
            )

        elif event.event_type == EventType.SUITE_STARTED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="suite_start",
                content=f"🚀 {event.message}",
                severity="info",
            )

        elif event.event_type == EventType.SUITE_COMPLETED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="suite_complete",
                content=f"🏁 {event.message}",
                details=event.details,
                severity="success" if event.details.get("failed", 0) == 0 else "warning",
            )

        elif event.event_type == EventType.THRESHOLD_EXCEEDED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="threshold",
                content=f"⚠️ {event.message}",
                severity="error",
            )

        elif event.event_type == EventType.PAUSE_REQUESTED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="pause",
                content=f"⏸️ {event.message}",
                severity="warning",
            )

        elif event.event_type == EventType.RESUME_REQUESTED:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="resume",
                content=f"▶️ {event.message}",
                severity="info",
            )

        elif event.event_type == EventType.WARNING:
            return DashboardUpdate(
                timestamp=event.timestamp,
                update_type="warning",
                content=f"⚠️ {event.message}",
                severity="warning",
            )

        return None

    def add_callback(self, callback: Callable[[DashboardUpdate], None]):
        """Add a callback for dashboard updates."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[DashboardUpdate], None]):
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_updates(self, limit: int = 20) -> List[DashboardUpdate]:
        """Get recent updates."""
        return self._updates[-limit:]

    def render_header(self) -> str:
        """Render the dashboard header."""
        summary = self.monitor.get_progress_summary()
        state = summary["state"]
        total = summary["total_tests"]
        completed = summary["completed"]
        progress_pct = summary["progress_pct"]

        state_colors = {
            "idle": "white",
            "running": "green",
            "paused": "yellow",
            "stopped": "red",
            "error": "red",
        }
        state_color = state_colors.get(state, "white")

        lines = [
            self._color("=" * 60, "cyan"),
            self._color("  TESTAI LIVE EXECUTION DASHBOARD", "bold"),
            self._color("=" * 60, "cyan"),
            "",
            f"  State: {self._color(state.upper(), state_color)}",
            "",
        ]

        return "\n".join(lines)

    def render_progress_bar(self) -> str:
        """Render the progress bar."""
        summary = self.monitor.get_progress_summary()
        progress_pct = summary["progress_pct"]
        completed = summary["completed"]
        total = summary["total_tests"]

        bar_width = 40
        filled = int(bar_width * progress_pct)
        bar = "█" * filled + "░" * (bar_width - filled)

        # Color based on pass rate
        pass_rate = summary["pass_rate"]
        if pass_rate >= 0.9:
            bar_color = "green"
        elif pass_rate >= 0.7:
            bar_color = "yellow"
        else:
            bar_color = "red"

        colored_bar = self._color(bar, bar_color)

        return f"  [{colored_bar}] {progress_pct:.0%} ({completed}/{total})"

    def render_stats(self) -> str:
        """Render execution statistics."""
        summary = self.monitor.get_progress_summary()

        passed = summary["passed"]
        failed = summary["failed"]
        skipped = summary["skipped"]
        flaky = summary["flaky"]
        pass_rate = summary["pass_rate"]
        elapsed_sec = summary["elapsed_ms"] / 1000
        remaining_sec = summary["estimated_remaining_ms"] / 1000
        avg_duration = summary["avg_duration_ms"]

        lines = [
            "",
            self._color("-" * 60, "cyan"),
            "  STATISTICS",
            self._color("-" * 60, "cyan"),
            "",
            f"  {self._color('✅ Passed:', 'green')} {passed:4}    "
            f"{self._color('❌ Failed:', 'red')} {failed:4}    "
            f"{self._color('⏭️ Skipped:', 'yellow')} {skipped:4}",
            "",
            f"  Pass Rate: {self._color(f'{pass_rate:.1%}', 'green' if pass_rate >= 0.9 else 'yellow' if pass_rate >= 0.7 else 'red')}",
            "",
            f"  ⏱️ Elapsed: {elapsed_sec:.1f}s    "
            f"Est. Remaining: {remaining_sec:.1f}s    "
            f"Avg: {avg_duration:.0f}ms",
            "",
        ]

        # Warnings
        if summary["consecutive_failures"] > 0:
            consecutive = summary["consecutive_failures"]
            warning_text = f"⚠️ Consecutive failures: {consecutive}"
            lines.append(f"  {self._color(warning_text, 'red')}")

        if flaky > 0:
            flaky_text = f"⚠️ Flaky tests: {flaky}"
            lines.append(f"  {self._color(flaky_text, 'yellow')}")

        return "\n".join(lines)

    def render_recent_updates(self, limit: int = 10) -> str:
        """Render recent updates."""
        updates = self.get_updates(limit)

        lines = [
            "",
            self._color("-" * 60, "cyan"),
            "  RECENT ACTIVITY",
            self._color("-" * 60, "cyan"),
            "",
        ]

        if not updates:
            lines.append("  No activity yet.")
        else:
            for update in reversed(updates):
                time_str = update.timestamp.strftime("%H:%M:%S")
                severity_colors = {
                    "info": "white",
                    "success": "green",
                    "warning": "yellow",
                    "error": "red",
                }
                color = severity_colors.get(update.severity, "white")
                lines.append(f"  {self._color(time_str, 'cyan')} {self._color(update.content, color)}")

        return "\n".join(lines)

    def render_failures(self, limit: int = 5) -> str:
        """Render failure details."""
        failures = self.monitor.get_failures()

        if not failures:
            return ""

        lines = [
            "",
            self._color("-" * 60, "red"),
            f"  {self._color('FAILURES', 'red')} ({len(failures)} total)",
            self._color("-" * 60, "red"),
            "",
        ]

        for failure in failures[-limit:]:
            lines.append(f"  {self._color('❌', 'red')} {failure.test_title}")
            if failure.details.get("error"):
                error = failure.details["error"][:60]
                lines.append(f"     {self._color(error, 'yellow')}")

        if len(failures) > limit:
            lines.append(f"  ... and {len(failures) - limit} more")

        return "\n".join(lines)

    def render_full_dashboard(self) -> str:
        """Render the complete dashboard."""
        parts = [
            self.render_header(),
            self.render_progress_bar(),
            self.render_stats(),
            self.render_recent_updates(),
        ]

        # Only show failures section if there are any
        failures = self.render_failures()
        if failures:
            parts.append(failures)

        parts.append("")
        parts.append(self._color("=" * 60, "cyan"))

        return "\n".join(parts)

    def render_compact(self) -> str:
        """Render a compact single-line status."""
        summary = self.monitor.get_progress_summary()
        state = summary["state"]
        progress_pct = summary["progress_pct"]
        passed = summary["passed"]
        failed = summary["failed"]

        state_indicator = {
            "idle": "⏹",
            "running": "▶",
            "paused": "⏸",
            "stopped": "⏹",
            "error": "⚠",
        }.get(state, "?")

        return (
            f"{state_indicator} [{progress_pct:.0%}] "
            f"✅{passed} ❌{failed} "
            f"({summary['elapsed_ms']//1000}s elapsed)"
        )


def create_live_dashboard(
    monitor: ExecutionMonitor,
    use_color: bool = True,
) -> LiveDashboard:
    """Create a live dashboard instance."""
    return LiveDashboard(monitor, use_color)
