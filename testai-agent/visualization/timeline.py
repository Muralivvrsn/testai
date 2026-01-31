"""
TestAI Agent - Timeline Generator

Creates execution timeline visualizations for test runs
showing temporal patterns and execution flow.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict


class EventType(Enum):
    """Types of timeline events."""
    TEST_START = "test_start"
    TEST_END = "test_end"
    TEST_PASS = "test_pass"
    TEST_FAIL = "test_fail"
    TEST_SKIP = "test_skip"
    SUITE_START = "suite_start"
    SUITE_END = "suite_end"
    RETRY = "retry"
    ASSERTION = "assertion"
    ERROR = "error"


class EventStatus(Enum):
    """Status of timeline events."""
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TimelineEvent:
    """A single event on the timeline."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    test_id: Optional[str] = None
    test_title: Optional[str] = None
    duration_ms: Optional[int] = None
    status: Optional[EventStatus] = None
    message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimelineTrack:
    """A track (lane) in the timeline."""
    track_id: str
    label: str
    events: List[TimelineEvent]
    color: str = "#6366f1"
    order: int = 0


@dataclass
class Timeline:
    """A complete execution timeline."""
    tracks: List[TimelineTrack]
    start_time: datetime
    end_time: datetime
    total_duration_ms: int
    summary: Dict[str, Any]


class TimelineGenerator:
    """
    Generates execution timelines for test runs.

    Creates visualizations showing:
    - Test execution order and duration
    - Parallel execution tracks
    - Failure patterns over time
    - Performance bottlenecks
    """

    # Colors for different statuses
    STATUS_COLORS = {
        EventStatus.PASSED: "#10b981",   # Green
        EventStatus.FAILED: "#ef4444",   # Red
        EventStatus.SKIPPED: "#6b7280",  # Gray
        EventStatus.ERROR: "#f59e0b",    # Amber
        EventStatus.RUNNING: "#3b82f6",  # Blue
    }

    # Track colors for parallel execution
    TRACK_COLORS = [
        "#6366f1",  # Indigo
        "#8b5cf6",  # Violet
        "#a855f7",  # Purple
        "#d946ef",  # Fuchsia
        "#ec4899",  # Pink
        "#f43f5e",  # Rose
    ]

    def __init__(self):
        """Initialize the timeline generator."""
        self._events: List[TimelineEvent] = []
        self._tracks: Dict[str, TimelineTrack] = {}
        self._event_counter = 0

    def record_event(
        self,
        event_type: EventType,
        test_id: Optional[str] = None,
        test_title: Optional[str] = None,
        duration_ms: Optional[int] = None,
        status: Optional[EventStatus] = None,
        message: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        track_id: Optional[str] = None,
        **metadata,
    ) -> TimelineEvent:
        """Record a timeline event."""
        self._event_counter += 1

        event = TimelineEvent(
            event_id=f"EVT-{self._event_counter:05d}",
            event_type=event_type,
            timestamp=timestamp or datetime.now(),
            test_id=test_id,
            test_title=test_title,
            duration_ms=duration_ms,
            status=status,
            message=message,
            metadata=metadata,
        )

        self._events.append(event)

        # Add to track if specified
        if track_id:
            if track_id not in self._tracks:
                self._tracks[track_id] = TimelineTrack(
                    track_id=track_id,
                    label=track_id,
                    events=[],
                    color=self.TRACK_COLORS[len(self._tracks) % len(self.TRACK_COLORS)],
                    order=len(self._tracks),
                )
            self._tracks[track_id].events.append(event)

        return event

    def from_execution_results(
        self,
        results: List[Dict[str, Any]],
        parallel_tracks: bool = False,
    ) -> "TimelineGenerator":
        """Build timeline from execution results."""
        # Sort by start time
        sorted_results = sorted(
            results,
            key=lambda r: r.get("started_at", datetime.now())
        )

        if parallel_tracks:
            # Assign to tracks based on overlap
            track_end_times: Dict[str, datetime] = {}

            for result in sorted_results:
                test_id = result.get("id", "unknown")
                title = result.get("title", "Untitled")
                started_at = result.get("started_at", datetime.now())
                duration_ms = result.get("duration_ms", 0)
                status = self._result_to_status(result)

                # Find available track
                track_id = None
                for tid, end_time in track_end_times.items():
                    if started_at >= end_time:
                        track_id = tid
                        break

                if track_id is None:
                    track_id = f"track-{len(track_end_times) + 1}"

                # Update track end time
                end_time = started_at + timedelta(milliseconds=duration_ms)
                track_end_times[track_id] = end_time

                # Record events
                self.record_event(
                    EventType.TEST_START,
                    test_id=test_id,
                    test_title=title,
                    timestamp=started_at,
                    track_id=track_id,
                )

                self.record_event(
                    EventType.TEST_END,
                    test_id=test_id,
                    test_title=title,
                    duration_ms=duration_ms,
                    status=status,
                    timestamp=end_time,
                    track_id=track_id,
                )
        else:
            # Single track
            for result in sorted_results:
                test_id = result.get("id", "unknown")
                title = result.get("title", "Untitled")
                started_at = result.get("started_at", datetime.now())
                duration_ms = result.get("duration_ms", 0)
                status = self._result_to_status(result)
                error = result.get("error")

                end_time = started_at + timedelta(milliseconds=duration_ms)

                self.record_event(
                    EventType.TEST_START,
                    test_id=test_id,
                    test_title=title,
                    timestamp=started_at,
                    track_id="main",
                )

                event_type = {
                    EventStatus.PASSED: EventType.TEST_PASS,
                    EventStatus.FAILED: EventType.TEST_FAIL,
                    EventStatus.SKIPPED: EventType.TEST_SKIP,
                }.get(status, EventType.TEST_END)

                self.record_event(
                    event_type,
                    test_id=test_id,
                    test_title=title,
                    duration_ms=duration_ms,
                    status=status,
                    message=error,
                    timestamp=end_time,
                    track_id="main",
                )

        return self

    def build(self) -> Timeline:
        """Build the final timeline."""
        if not self._events:
            now = datetime.now()
            return Timeline(
                tracks=[],
                start_time=now,
                end_time=now,
                total_duration_ms=0,
                summary={},
            )

        # Sort events by timestamp
        sorted_events = sorted(self._events, key=lambda e: e.timestamp)

        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp
        total_duration = int((end_time - start_time).total_seconds() * 1000)

        # Build tracks
        tracks = list(self._tracks.values())
        if not tracks:
            # Create single track with all events
            tracks = [TimelineTrack(
                track_id="main",
                label="Execution",
                events=sorted_events,
                color=self.TRACK_COLORS[0],
            )]

        # Sort tracks by order
        tracks.sort(key=lambda t: t.order)

        # Calculate summary
        summary = self._calculate_summary(sorted_events)

        return Timeline(
            tracks=tracks,
            start_time=start_time,
            end_time=end_time,
            total_duration_ms=total_duration,
            summary=summary,
        )

    def find_slow_tests(
        self,
        threshold_ms: int = 5000,
    ) -> List[TimelineEvent]:
        """Find tests that exceeded duration threshold."""
        slow = []

        for event in self._events:
            if event.event_type in {EventType.TEST_END, EventType.TEST_PASS, EventType.TEST_FAIL}:
                if event.duration_ms and event.duration_ms > threshold_ms:
                    slow.append(event)

        return sorted(slow, key=lambda e: -(e.duration_ms or 0))

    def find_failure_clusters(
        self,
        window_ms: int = 60000,
    ) -> List[List[TimelineEvent]]:
        """Find clusters of failures within time windows."""
        failures = [
            e for e in self._events
            if e.event_type == EventType.TEST_FAIL
        ]

        if not failures:
            return []

        failures.sort(key=lambda e: e.timestamp)

        clusters = []
        current_cluster = [failures[0]]

        for failure in failures[1:]:
            time_diff = (failure.timestamp - current_cluster[-1].timestamp).total_seconds() * 1000

            if time_diff <= window_ms:
                current_cluster.append(failure)
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [failure]

        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        return clusters

    def get_parallel_utilization(self) -> Dict[str, float]:
        """Calculate parallel execution utilization."""
        if not self._tracks or not self._events:
            return {}

        utilization = {}

        for track_id, track in self._tracks.items():
            total_busy_time = 0
            test_starts: Dict[str, datetime] = {}

            for event in track.events:
                if event.event_type == EventType.TEST_START:
                    test_starts[event.test_id or ""] = event.timestamp
                elif event.event_type in {EventType.TEST_END, EventType.TEST_PASS, EventType.TEST_FAIL}:
                    start = test_starts.get(event.test_id or "")
                    if start:
                        total_busy_time += (event.timestamp - start).total_seconds() * 1000

            # Calculate total timeline duration
            if self._events:
                sorted_events = sorted(self._events, key=lambda e: e.timestamp)
                total_time = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() * 1000

                if total_time > 0:
                    utilization[track_id] = total_busy_time / total_time

        return utilization

    def _result_to_status(self, result: Dict[str, Any]) -> EventStatus:
        """Convert result dict to event status."""
        if result.get("passed"):
            return EventStatus.PASSED
        if result.get("skipped"):
            return EventStatus.SKIPPED
        if result.get("error"):
            return EventStatus.ERROR
        return EventStatus.FAILED

    def _calculate_summary(
        self,
        events: List[TimelineEvent],
    ) -> Dict[str, Any]:
        """Calculate timeline summary statistics."""
        test_events = [
            e for e in events
            if e.event_type in {EventType.TEST_PASS, EventType.TEST_FAIL, EventType.TEST_SKIP}
        ]

        passed = sum(1 for e in test_events if e.status == EventStatus.PASSED)
        failed = sum(1 for e in test_events if e.status == EventStatus.FAILED)
        skipped = sum(1 for e in test_events if e.status == EventStatus.SKIPPED)

        durations = [e.duration_ms for e in test_events if e.duration_ms]
        avg_duration = sum(durations) / len(durations) if durations else 0
        max_duration = max(durations) if durations else 0
        min_duration = min(durations) if durations else 0

        return {
            "total_events": len(events),
            "total_tests": len(test_events),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "pass_rate": passed / len(test_events) if test_events else 0,
            "avg_duration_ms": avg_duration,
            "max_duration_ms": max_duration,
            "min_duration_ms": min_duration,
            "total_duration_ms": sum(durations),
        }

    def to_ascii(self, timeline: Timeline) -> str:
        """Render timeline as ASCII art."""
        if not timeline.tracks or timeline.total_duration_ms == 0:
            return "No events to display"

        width = 60
        lines = []

        # Header
        lines.append("=" * (width + 20))
        lines.append("  EXECUTION TIMELINE")
        lines.append("=" * (width + 20))
        lines.append("")

        # Time scale
        duration_sec = timeline.total_duration_ms / 1000
        scale = f"0s{'-' * (width - 8)}{duration_sec:.1f}s"
        lines.append(f"  Time: {scale}")
        lines.append("")

        # Tracks
        for track in timeline.tracks:
            lines.append(f"  {track.label}:")

            track_line = [" "] * width
            status_chars = {
                EventStatus.PASSED: "█",
                EventStatus.FAILED: "▓",
                EventStatus.SKIPPED: "░",
                EventStatus.ERROR: "▒",
                EventStatus.RUNNING: "▄",
            }

            for event in track.events:
                if event.duration_ms:
                    # Calculate position and width
                    offset = (event.timestamp - timeline.start_time).total_seconds() * 1000
                    start_pos = int((offset - event.duration_ms) / timeline.total_duration_ms * width)
                    end_pos = int(offset / timeline.total_duration_ms * width)

                    start_pos = max(0, min(start_pos, width - 1))
                    end_pos = max(0, min(end_pos, width))

                    char = status_chars.get(event.status, "█")
                    for i in range(start_pos, end_pos):
                        track_line[i] = char

            lines.append(f"  |{''.join(track_line)}|")
            lines.append("")

        # Legend
        lines.append("-" * (width + 20))
        lines.append("  Legend: █ Passed  ▓ Failed  ░ Skipped  ▒ Error")
        lines.append("=" * (width + 20))

        return "\n".join(lines)

    def to_mermaid_gantt(self, timeline: Timeline) -> str:
        """Export timeline as Mermaid Gantt diagram."""
        lines = [
            "gantt",
            "    title Test Execution Timeline",
            f"    dateFormat YYYY-MM-DD HH:mm:ss",
        ]

        for track in timeline.tracks:
            lines.append(f"    section {track.label}")

            # Group consecutive events
            i = 0
            events = sorted(track.events, key=lambda e: e.timestamp)

            while i < len(events):
                event = events[i]
                if event.event_type == EventType.TEST_START:
                    # Find corresponding end
                    end_event = None
                    for j in range(i + 1, len(events)):
                        if events[j].test_id == event.test_id and events[j].event_type in {
                            EventType.TEST_END, EventType.TEST_PASS, EventType.TEST_FAIL
                        }:
                            end_event = events[j]
                            break

                    if end_event and event.test_title:
                        status_class = ""
                        if end_event.status == EventStatus.FAILED:
                            status_class = "crit, "
                        elif end_event.status == EventStatus.SKIPPED:
                            status_class = "done, "

                        safe_title = event.test_title.replace(":", "-")[:30]
                        start_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        duration = end_event.duration_ms or 1000

                        lines.append(
                            f"    {safe_title} :{status_class}{event.test_id}, "
                            f"{start_str}, {duration}ms"
                        )
                i += 1

        return "\n".join(lines)

    def format_summary(self, timeline: Timeline) -> str:
        """Format timeline summary as readable text."""
        summary = timeline.summary

        lines = [
            "=" * 60,
            "  EXECUTION TIMELINE SUMMARY",
            "=" * 60,
            "",
            f"  Duration: {timeline.total_duration_ms / 1000:.2f}s",
            f"  Start: {timeline.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  End: {timeline.end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"  Total Tests: {summary.get('total_tests', 0)}",
            f"  Passed: {summary.get('passed', 0)}",
            f"  Failed: {summary.get('failed', 0)}",
            f"  Skipped: {summary.get('skipped', 0)}",
            f"  Pass Rate: {summary.get('pass_rate', 0):.1%}",
            "",
            f"  Avg Duration: {summary.get('avg_duration_ms', 0):.0f}ms",
            f"  Max Duration: {summary.get('max_duration_ms', 0):.0f}ms",
            f"  Min Duration: {summary.get('min_duration_ms', 0):.0f}ms",
            "",
        ]

        # Parallel utilization
        utilization = self.get_parallel_utilization()
        if utilization and len(utilization) > 1:
            lines.extend([
                "-" * 60,
                "  PARALLEL UTILIZATION",
                "-" * 60,
            ])
            for track_id, util in sorted(utilization.items()):
                bar = "█" * int(util * 20) + "░" * (20 - int(util * 20))
                lines.append(f"  {track_id:<15} {bar} {util:.0%}")
            lines.append("")

        # Slow tests
        slow_tests = self.find_slow_tests(5000)
        if slow_tests:
            lines.extend([
                "-" * 60,
                "  SLOW TESTS (>5s)",
                "-" * 60,
            ])
            for event in slow_tests[:5]:
                lines.append(
                    f"  • {event.test_title or event.test_id}: "
                    f"{(event.duration_ms or 0) / 1000:.1f}s"
                )
            if len(slow_tests) > 5:
                lines.append(f"  ... and {len(slow_tests) - 5} more")
            lines.append("")

        # Failure clusters
        clusters = self.find_failure_clusters(60000)
        if clusters:
            lines.extend([
                "-" * 60,
                "  FAILURE CLUSTERS (within 1 minute)",
                "-" * 60,
            ])
            for i, cluster in enumerate(clusters[:3]):
                lines.append(f"  Cluster {i + 1}: {len(cluster)} failures")
                for event in cluster[:3]:
                    lines.append(f"    - {event.test_title or event.test_id}")
                if len(cluster) > 3:
                    lines.append(f"    ... and {len(cluster) - 3} more")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_timeline_generator() -> TimelineGenerator:
    """Create a timeline generator instance."""
    return TimelineGenerator()
