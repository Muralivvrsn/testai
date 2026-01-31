"""
TestAI Agent - Test Scheduler

Schedules test execution across browsers, devices,
and time windows with intelligent prioritization.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import uuid
import heapq


class ScheduleType(Enum):
    """Types of schedules."""
    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"
    RECURRING = "recurring"
    ON_DEMAND = "on_demand"


class ScheduleStatus(Enum):
    """Schedule status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class RecurrencePattern(Enum):
    """Recurrence patterns."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class ScheduleConfig:
    """Configuration for scheduling."""
    max_parallel_runs: int = 5
    default_timeout_minutes: int = 60
    retry_failed: bool = True
    max_retries: int = 2
    queue_timeout_minutes: int = 120
    priority_boost_on_failure: bool = True


@dataclass
class BrowserTarget:
    """Browser target for execution."""
    browser: str  # chromium, firefox, webkit
    version: Optional[str] = None
    headless: bool = True


@dataclass
class DeviceTarget:
    """Device target for execution."""
    name: str
    width: int
    height: int
    device_scale_factor: float = 1.0
    is_mobile: bool = False
    has_touch: bool = False
    user_agent: Optional[str] = None


@dataclass
class ScheduledRun:
    """A scheduled test run."""
    run_id: str
    test_ids: List[str]
    browsers: List[BrowserTarget]
    devices: List[DeviceTarget]
    schedule_type: ScheduleType
    scheduled_time: datetime
    status: ScheduleStatus
    priority: int  # Lower = higher priority
    tags: List[str]
    environment: str
    timeout_minutes: int = 60
    retry_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other):
        """Compare for priority queue."""
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.scheduled_time < other.scheduled_time


class TestScheduler:
    """
    Schedules test execution across browsers and devices.

    Features:
    - Priority-based scheduling
    - Browser/device matrix
    - Recurring schedules
    - Queue management
    """

    # Default browser targets
    DEFAULT_BROWSERS = [
        BrowserTarget("chromium"),
        BrowserTarget("firefox"),
        BrowserTarget("webkit"),
    ]

    # Default device targets
    DEFAULT_DEVICES = [
        DeviceTarget("Desktop HD", 1920, 1080),
        DeviceTarget("Desktop", 1366, 768),
        DeviceTarget("Tablet", 768, 1024, has_touch=True),
        DeviceTarget("Mobile", 375, 667, 2.0, True, True),
    ]

    def __init__(self, config: Optional[ScheduleConfig] = None):
        """Initialize the scheduler."""
        self.config = config or ScheduleConfig()
        self._run_counter = 0
        self._queue: List[ScheduledRun] = []
        self._running: Dict[str, ScheduledRun] = {}
        self._completed: Dict[str, ScheduledRun] = {}
        self._recurring: Dict[str, ScheduledRun] = {}
        self._hooks: Dict[str, List[Callable]] = {
            "on_scheduled": [],
            "on_started": [],
            "on_completed": [],
            "on_failed": [],
        }

    def schedule(
        self,
        test_ids: List[str],
        browsers: Optional[List[BrowserTarget]] = None,
        devices: Optional[List[DeviceTarget]] = None,
        schedule_time: Optional[datetime] = None,
        priority: int = 5,
        tags: Optional[List[str]] = None,
        environment: str = "default",
        timeout_minutes: Optional[int] = None,
    ) -> ScheduledRun:
        """Schedule a test run."""
        self._run_counter += 1
        run_id = f"sched-{self._run_counter:05d}-{uuid.uuid4().hex[:8]}"

        schedule_type = ScheduleType.SCHEDULED if schedule_time else ScheduleType.IMMEDIATE
        scheduled_time = schedule_time or datetime.now()

        run = ScheduledRun(
            run_id=run_id,
            test_ids=test_ids,
            browsers=browsers or [BrowserTarget("chromium")],
            devices=devices or [DeviceTarget("Desktop", 1366, 768)],
            schedule_type=schedule_type,
            scheduled_time=scheduled_time,
            status=ScheduleStatus.PENDING,
            priority=priority,
            tags=tags or [],
            environment=environment,
            timeout_minutes=timeout_minutes or self.config.default_timeout_minutes,
        )

        heapq.heappush(self._queue, run)

        # Run hooks
        self._run_hooks("on_scheduled", run)

        return run

    def schedule_matrix(
        self,
        test_ids: List[str],
        browsers: Optional[List[BrowserTarget]] = None,
        devices: Optional[List[DeviceTarget]] = None,
        priority: int = 5,
        environment: str = "default",
    ) -> List[ScheduledRun]:
        """Schedule tests across a browser/device matrix."""
        browsers = browsers or self.DEFAULT_BROWSERS
        devices = devices or self.DEFAULT_DEVICES

        runs = []
        for browser in browsers:
            for device in devices:
                run = self.schedule(
                    test_ids=test_ids,
                    browsers=[browser],
                    devices=[device],
                    priority=priority,
                    environment=environment,
                    tags=[browser.browser, device.name.lower().replace(" ", "_")],
                )
                runs.append(run)

        return runs

    def schedule_recurring(
        self,
        test_ids: List[str],
        pattern: RecurrencePattern,
        start_time: Optional[datetime] = None,
        browsers: Optional[List[BrowserTarget]] = None,
        priority: int = 5,
        custom_interval_minutes: Optional[int] = None,
    ) -> ScheduledRun:
        """Schedule a recurring test run."""
        self._run_counter += 1
        run_id = f"recur-{self._run_counter:05d}-{uuid.uuid4().hex[:8]}"

        start = start_time or datetime.now()

        run = ScheduledRun(
            run_id=run_id,
            test_ids=test_ids,
            browsers=browsers or [BrowserTarget("chromium")],
            devices=[DeviceTarget("Desktop", 1366, 768)],
            schedule_type=ScheduleType.RECURRING,
            scheduled_time=start,
            status=ScheduleStatus.PENDING,
            priority=priority,
            tags=["recurring", pattern.value],
            environment="default",
            metadata={
                "pattern": pattern.value,
                "custom_interval": custom_interval_minutes,
            },
        )

        self._recurring[run_id] = run
        heapq.heappush(self._queue, run)

        return run

    def get_next(self) -> Optional[ScheduledRun]:
        """Get the next scheduled run to execute."""
        while self._queue:
            # Check if we can run more
            if len(self._running) >= self.config.max_parallel_runs:
                return None

            run = heapq.heappop(self._queue)

            # Check if it's time
            if run.scheduled_time > datetime.now():
                heapq.heappush(self._queue, run)
                return None

            # Check if cancelled
            if run.status == ScheduleStatus.CANCELLED:
                continue

            return run

        return None

    def start_run(self, run_id: str) -> bool:
        """Mark a run as started."""
        run = self._find_run(run_id)
        if not run:
            return False

        run.status = ScheduleStatus.RUNNING
        run.started_at = datetime.now()
        self._running[run_id] = run

        self._run_hooks("on_started", run)
        return True

    def complete_run(
        self,
        run_id: str,
        result: Dict[str, Any],
        success: bool = True,
    ) -> bool:
        """Mark a run as completed."""
        run = self._running.pop(run_id, None)
        if not run:
            return False

        run.status = ScheduleStatus.COMPLETED if success else ScheduleStatus.FAILED
        run.completed_at = datetime.now()
        run.result = result

        self._completed[run_id] = run

        # Handle failure with retry
        if not success and self.config.retry_failed:
            if run.retry_count < self.config.max_retries:
                self._schedule_retry(run)

        # Schedule next occurrence for recurring
        if run.schedule_type == ScheduleType.RECURRING:
            self._schedule_next_occurrence(run)

        hook = "on_completed" if success else "on_failed"
        self._run_hooks(hook, run)

        return True

    def _schedule_retry(self, run: ScheduledRun):
        """Schedule a retry for a failed run."""
        self._run_counter += 1
        retry_id = f"retry-{self._run_counter:05d}-{uuid.uuid4().hex[:8]}"

        # Boost priority for retries
        new_priority = run.priority
        if self.config.priority_boost_on_failure:
            new_priority = max(1, run.priority - 1)

        retry = ScheduledRun(
            run_id=retry_id,
            test_ids=run.test_ids,
            browsers=run.browsers,
            devices=run.devices,
            schedule_type=ScheduleType.IMMEDIATE,
            scheduled_time=datetime.now() + timedelta(minutes=1),
            status=ScheduleStatus.PENDING,
            priority=new_priority,
            tags=run.tags + ["retry"],
            environment=run.environment,
            timeout_minutes=run.timeout_minutes,
            retry_count=run.retry_count + 1,
            metadata={"original_run": run.run_id},
        )

        heapq.heappush(self._queue, retry)

    def _schedule_next_occurrence(self, run: ScheduledRun):
        """Schedule next occurrence of a recurring run."""
        pattern = run.metadata.get("pattern", "daily")
        custom_interval = run.metadata.get("custom_interval")

        # Calculate next time
        if pattern == RecurrencePattern.HOURLY.value:
            next_time = run.scheduled_time + timedelta(hours=1)
        elif pattern == RecurrencePattern.DAILY.value:
            next_time = run.scheduled_time + timedelta(days=1)
        elif pattern == RecurrencePattern.WEEKLY.value:
            next_time = run.scheduled_time + timedelta(weeks=1)
        elif pattern == RecurrencePattern.MONTHLY.value:
            next_time = run.scheduled_time + timedelta(days=30)
        elif custom_interval:
            next_time = run.scheduled_time + timedelta(minutes=custom_interval)
        else:
            next_time = run.scheduled_time + timedelta(days=1)

        # Create new occurrence
        self._run_counter += 1
        new_id = f"recur-{self._run_counter:05d}-{uuid.uuid4().hex[:8]}"

        new_run = ScheduledRun(
            run_id=new_id,
            test_ids=run.test_ids,
            browsers=run.browsers,
            devices=run.devices,
            schedule_type=ScheduleType.RECURRING,
            scheduled_time=next_time,
            status=ScheduleStatus.PENDING,
            priority=run.priority,
            tags=run.tags,
            environment=run.environment,
            timeout_minutes=run.timeout_minutes,
            metadata=run.metadata,
        )

        self._recurring[new_id] = new_run
        heapq.heappush(self._queue, new_run)

    def cancel_run(self, run_id: str) -> bool:
        """Cancel a scheduled run."""
        run = self._find_run(run_id)
        if not run:
            return False

        if run.status == ScheduleStatus.RUNNING:
            return False  # Can't cancel running

        run.status = ScheduleStatus.CANCELLED
        return True

    def pause_run(self, run_id: str) -> bool:
        """Pause a scheduled run."""
        run = self._find_run(run_id)
        if not run:
            return False

        if run.status != ScheduleStatus.PENDING:
            return False

        run.status = ScheduleStatus.PAUSED
        return True

    def resume_run(self, run_id: str) -> bool:
        """Resume a paused run."""
        run = self._find_run(run_id)
        if not run:
            return False

        if run.status != ScheduleStatus.PAUSED:
            return False

        run.status = ScheduleStatus.PENDING
        return True

    def _find_run(self, run_id: str) -> Optional[ScheduledRun]:
        """Find a run by ID."""
        # Check queue
        for run in self._queue:
            if run.run_id == run_id:
                return run

        # Check running
        if run_id in self._running:
            return self._running[run_id]

        # Check completed
        if run_id in self._completed:
            return self._completed[run_id]

        return None

    def get_run(self, run_id: str) -> Optional[ScheduledRun]:
        """Get a run by ID."""
        return self._find_run(run_id)

    def get_pending(self) -> List[ScheduledRun]:
        """Get all pending runs."""
        return [r for r in self._queue if r.status == ScheduleStatus.PENDING]

    def get_running(self) -> List[ScheduledRun]:
        """Get all running runs."""
        return list(self._running.values())

    def get_completed(self, limit: int = 10) -> List[ScheduledRun]:
        """Get recent completed runs."""
        completed = list(self._completed.values())
        completed.sort(key=lambda r: r.completed_at or datetime.min, reverse=True)
        return completed[:limit]

    def add_hook(self, event: str, callback: Callable):
        """Add a hook for an event."""
        if event in self._hooks:
            self._hooks[event].append(callback)

    def _run_hooks(self, event: str, run: ScheduledRun):
        """Run hooks for an event."""
        for callback in self._hooks.get(event, []):
            try:
                callback(run)
            except Exception:
                pass

    def get_statistics(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        pending = len([r for r in self._queue if r.status == ScheduleStatus.PENDING])
        running = len(self._running)
        completed = len([r for r in self._completed.values() if r.status == ScheduleStatus.COMPLETED])
        failed = len([r for r in self._completed.values() if r.status == ScheduleStatus.FAILED])

        return {
            "pending_runs": pending,
            "running_runs": running,
            "completed_runs": completed,
            "failed_runs": failed,
            "recurring_schedules": len(self._recurring),
            "max_parallel": self.config.max_parallel_runs,
            "capacity_used": running / self.config.max_parallel_runs if self.config.max_parallel_runs > 0 else 0,
        }

    def format_status(self) -> str:
        """Format scheduler status."""
        stats = self.get_statistics()

        lines = [
            "=" * 60,
            "  TEST SCHEDULER STATUS",
            "=" * 60,
            "",
            f"  Pending: {stats['pending_runs']}",
            f"  Running: {stats['running_runs']}/{stats['max_parallel']}",
            f"  Completed: {stats['completed_runs']}",
            f"  Failed: {stats['failed_runs']}",
            f"  Recurring: {stats['recurring_schedules']}",
            "",
        ]

        if self._running:
            lines.extend(["-" * 60, "  RUNNING", "-" * 60])
            for run in self._running.values():
                duration = (datetime.now() - run.started_at).seconds if run.started_at else 0
                lines.append(
                    f"  🔄 {run.run_id} - {len(run.test_ids)} tests ({duration}s)"
                )

        if self._queue:
            pending = [r for r in self._queue if r.status == ScheduleStatus.PENDING][:5]
            if pending:
                lines.extend(["", "-" * 60, "  PENDING", "-" * 60])
                for run in pending:
                    time_str = run.scheduled_time.strftime("%H:%M:%S")
                    lines.append(f"  ⏳ {run.run_id} - scheduled {time_str}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_scheduler(config: Optional[ScheduleConfig] = None) -> TestScheduler:
    """Create a test scheduler instance."""
    return TestScheduler(config)
