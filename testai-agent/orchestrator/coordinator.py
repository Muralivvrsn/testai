"""
TestAI Agent - Test Coordinator

Coordinates the entire test orchestration process,
combining scheduling, distribution, and execution monitoring.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import uuid

from .scheduler import (
    TestScheduler,
    ScheduleConfig,
    ScheduledRun,
    ScheduleStatus,
    BrowserTarget,
    DeviceTarget,
)
from .distributor import (
    TestDistributor,
    DistributionStrategy,
    WorkerNode,
    WorkerCapabilities,
    WorkerStatus,
    DistributionResult,
)


class OrchestrationPhase(Enum):
    """Phases of test orchestration."""
    INITIALIZING = "initializing"
    SCHEDULING = "scheduling"
    DISTRIBUTING = "distributing"
    EXECUTING = "executing"
    COLLECTING = "collecting"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionMode(Enum):
    """Execution modes."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    MATRIX = "matrix"
    SMART = "smart"


@dataclass
class CoordinatorConfig:
    """Configuration for the coordinator."""
    execution_mode: ExecutionMode = ExecutionMode.PARALLEL
    distribution_strategy: DistributionStrategy = DistributionStrategy.LEAST_LOADED
    max_parallel_runs: int = 10
    default_timeout_minutes: int = 60
    retry_failed: bool = True
    max_retries: int = 2
    auto_rebalance: bool = True
    rebalance_interval_seconds: int = 30
    collect_artifacts: bool = True
    fail_fast: bool = False


@dataclass
class TestResult:
    """Result of a single test execution."""
    test_id: str
    run_id: str
    browser: str
    device: str
    status: str  # passed, failed, skipped, error
    duration_ms: int
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    screenshots: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    executed_at: datetime = field(default_factory=datetime.now)


@dataclass
class OrchestrationResult:
    """Result of a complete orchestration."""
    orchestration_id: str
    phase: OrchestrationPhase
    total_tests: int
    passed: int
    failed: int
    skipped: int
    errors: int
    duration_ms: int
    browser_results: Dict[str, Dict[str, int]]
    device_results: Dict[str, Dict[str, int]]
    test_results: List[TestResult]
    started_at: datetime
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.passed + self.failed + self.errors
        return self.passed / total if total > 0 else 0.0

    @property
    def is_successful(self) -> bool:
        """Check if orchestration was successful."""
        return self.failed == 0 and self.errors == 0


@dataclass
class OrchestrationRun:
    """An active orchestration run."""
    orchestration_id: str
    test_ids: List[str]
    browsers: List[BrowserTarget]
    devices: List[DeviceTarget]
    mode: ExecutionMode
    phase: OrchestrationPhase
    scheduled_runs: List[ScheduledRun]
    distributions: Dict[str, DistributionResult]
    results: List[TestResult]
    started_at: datetime
    config: CoordinatorConfig
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestCoordinator:
    """
    Coordinates test orchestration across browsers and devices.

    Features:
    - Combines scheduling and distribution
    - Multiple execution modes
    - Result aggregation
    - Artifact collection
    - Progress monitoring
    """

    def __init__(self, config: Optional[CoordinatorConfig] = None):
        """Initialize the coordinator."""
        self.config = config or CoordinatorConfig()

        # Create scheduler
        schedule_config = ScheduleConfig(
            max_parallel_runs=self.config.max_parallel_runs,
            default_timeout_minutes=self.config.default_timeout_minutes,
            retry_failed=self.config.retry_failed,
            max_retries=self.config.max_retries,
        )
        self.scheduler = TestScheduler(schedule_config)

        # Create distributor
        self.distributor = TestDistributor(self.config.distribution_strategy)

        # State
        self._orchestration_counter = 0
        self._active_runs: Dict[str, OrchestrationRun] = {}
        self._completed_runs: Dict[str, OrchestrationResult] = {}
        self._hooks: Dict[str, List[Callable]] = {
            "on_phase_change": [],
            "on_test_complete": [],
            "on_orchestration_complete": [],
            "on_error": [],
        }

    def register_worker(
        self,
        name: str,
        browsers: List[str],
        devices: List[str],
        max_parallel: int = 5,
        tags: Optional[List[str]] = None,
    ) -> WorkerNode:
        """Register a worker node."""
        capabilities = WorkerCapabilities(
            browsers=browsers,
            devices=devices,
            max_parallel=max_parallel,
            tags=tags or [],
        )
        return self.distributor.register_node(name, capabilities, max_parallel)

    def orchestrate(
        self,
        test_ids: List[str],
        browsers: Optional[List[BrowserTarget]] = None,
        devices: Optional[List[DeviceTarget]] = None,
        mode: Optional[ExecutionMode] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """
        Start a test orchestration.

        Returns the orchestration ID.
        """
        self._orchestration_counter += 1
        orch_id = f"orch-{self._orchestration_counter:05d}-{uuid.uuid4().hex[:8]}"

        browsers = browsers or [BrowserTarget("chromium")]
        devices = devices or [DeviceTarget("Desktop", 1366, 768)]
        mode = mode or self.config.execution_mode

        # Create orchestration run
        run = OrchestrationRun(
            orchestration_id=orch_id,
            test_ids=test_ids,
            browsers=browsers,
            devices=devices,
            mode=mode,
            phase=OrchestrationPhase.INITIALIZING,
            scheduled_runs=[],
            distributions={},
            results=[],
            started_at=datetime.now(),
            config=self.config,
            metadata={"tags": tags or []},
        )

        self._active_runs[orch_id] = run

        # Start orchestration process
        self._process_orchestration(run)

        return orch_id

    def _process_orchestration(self, run: OrchestrationRun):
        """Process an orchestration through its phases."""
        try:
            # Phase 1: Scheduling
            self._update_phase(run, OrchestrationPhase.SCHEDULING)
            self._schedule_tests(run)

            # Phase 2: Distribution
            self._update_phase(run, OrchestrationPhase.DISTRIBUTING)
            self._distribute_tests(run)

            # Phase 3: Ready for execution
            self._update_phase(run, OrchestrationPhase.EXECUTING)

        except Exception as e:
            self._update_phase(run, OrchestrationPhase.FAILED)
            self._run_hooks("on_error", run, str(e))

    def _update_phase(self, run: OrchestrationRun, phase: OrchestrationPhase):
        """Update orchestration phase."""
        run.phase = phase
        self._run_hooks("on_phase_change", run, phase)

    def _schedule_tests(self, run: OrchestrationRun):
        """Schedule tests based on execution mode."""
        if run.mode == ExecutionMode.MATRIX:
            # Schedule all browser/device combinations
            runs = self.scheduler.schedule_matrix(
                test_ids=run.test_ids,
                browsers=run.browsers,
                devices=run.devices,
                priority=5,
            )
            run.scheduled_runs = runs

        elif run.mode == ExecutionMode.PARALLEL:
            # Schedule tests in parallel batches
            for browser in run.browsers:
                for device in run.devices:
                    scheduled = self.scheduler.schedule(
                        test_ids=run.test_ids,
                        browsers=[browser],
                        devices=[device],
                        priority=5,
                    )
                    run.scheduled_runs.append(scheduled)

        elif run.mode == ExecutionMode.SEQUENTIAL:
            # Schedule tests sequentially
            for test_id in run.test_ids:
                scheduled = self.scheduler.schedule(
                    test_ids=[test_id],
                    browsers=run.browsers[:1],
                    devices=run.devices[:1],
                    priority=5,
                )
                run.scheduled_runs.append(scheduled)

        else:  # SMART mode
            # Intelligent scheduling based on test metadata
            self._smart_schedule(run)

    def _smart_schedule(self, run: OrchestrationRun):
        """Intelligently schedule tests based on patterns."""
        # Group tests by priority (simulated)
        high_priority = run.test_ids[:len(run.test_ids)//3]
        medium_priority = run.test_ids[len(run.test_ids)//3:2*len(run.test_ids)//3]
        low_priority = run.test_ids[2*len(run.test_ids)//3:]

        # Schedule high priority first across all browsers
        if high_priority:
            for browser in run.browsers:
                scheduled = self.scheduler.schedule(
                    test_ids=high_priority,
                    browsers=[browser],
                    devices=run.devices[:1],
                    priority=1,
                )
                run.scheduled_runs.append(scheduled)

        # Medium priority on primary browser/device
        if medium_priority:
            scheduled = self.scheduler.schedule(
                test_ids=medium_priority,
                browsers=run.browsers[:1],
                devices=run.devices[:1],
                priority=5,
            )
            run.scheduled_runs.append(scheduled)

        # Low priority last
        if low_priority:
            scheduled = self.scheduler.schedule(
                test_ids=low_priority,
                browsers=run.browsers[:1],
                devices=run.devices[:1],
                priority=10,
            )
            run.scheduled_runs.append(scheduled)

    def _distribute_tests(self, run: OrchestrationRun):
        """Distribute scheduled tests to workers."""
        for scheduled in run.scheduled_runs:
            if scheduled.status != ScheduleStatus.PENDING:
                continue

            browser = scheduled.browsers[0].browser if scheduled.browsers else "chromium"
            device = scheduled.devices[0].name if scheduled.devices else "Desktop"

            distribution = self.distributor.distribute(
                run_id=scheduled.run_id,
                test_ids=scheduled.test_ids,
                browser=browser,
                device=device,
                tags=scheduled.tags,
            )

            if distribution:
                run.distributions[scheduled.run_id] = distribution

    def report_result(
        self,
        orchestration_id: str,
        test_id: str,
        run_id: str,
        status: str,
        duration_ms: int,
        browser: str,
        device: str,
        error_message: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Report a test result."""
        run = self._active_runs.get(orchestration_id)
        if not run:
            return False

        result = TestResult(
            test_id=test_id,
            run_id=run_id,
            browser=browser,
            device=device,
            status=status,
            duration_ms=duration_ms,
            error_message=error_message,
            artifacts=artifacts or {},
        )

        run.results.append(result)

        # Check for fail-fast
        if self.config.fail_fast and status in ["failed", "error"]:
            self._complete_orchestration(run, early_termination=True)
            return True

        # Check if all tests complete
        expected_results = sum(
            len(s.test_ids) for s in run.scheduled_runs
        )

        if len(run.results) >= expected_results:
            self._complete_orchestration(run)

        self._run_hooks("on_test_complete", run, result)
        return True

    def _complete_orchestration(
        self,
        run: OrchestrationRun,
        early_termination: bool = False,
    ):
        """Complete an orchestration and create result."""
        self._update_phase(run, OrchestrationPhase.COLLECTING)

        # Aggregate results
        passed = sum(1 for r in run.results if r.status == "passed")
        failed = sum(1 for r in run.results if r.status == "failed")
        skipped = sum(1 for r in run.results if r.status == "skipped")
        errors = sum(1 for r in run.results if r.status == "error")

        # Browser breakdown
        browser_results: Dict[str, Dict[str, int]] = {}
        for result in run.results:
            if result.browser not in browser_results:
                browser_results[result.browser] = {"passed": 0, "failed": 0, "errors": 0}
            if result.status == "passed":
                browser_results[result.browser]["passed"] += 1
            elif result.status == "failed":
                browser_results[result.browser]["failed"] += 1
            else:
                browser_results[result.browser]["errors"] += 1

        # Device breakdown
        device_results: Dict[str, Dict[str, int]] = {}
        for result in run.results:
            if result.device not in device_results:
                device_results[result.device] = {"passed": 0, "failed": 0, "errors": 0}
            if result.status == "passed":
                device_results[result.device]["passed"] += 1
            elif result.status == "failed":
                device_results[result.device]["failed"] += 1
            else:
                device_results[result.device]["errors"] += 1

        # Calculate duration
        duration_ms = int(
            (datetime.now() - run.started_at).total_seconds() * 1000
        )

        # Create result
        result = OrchestrationResult(
            orchestration_id=run.orchestration_id,
            phase=OrchestrationPhase.COMPLETED,
            total_tests=len(run.results),
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration_ms,
            browser_results=browser_results,
            device_results=device_results,
            test_results=run.results,
            started_at=run.started_at,
            completed_at=datetime.now(),
            metadata={
                "early_termination": early_termination,
                "mode": run.mode.value,
                **run.metadata,
            },
        )

        # Move to completed
        del self._active_runs[run.orchestration_id]
        self._completed_runs[run.orchestration_id] = result

        self._update_phase(run, OrchestrationPhase.COMPLETED)
        self._run_hooks("on_orchestration_complete", run, result)

    def get_status(self, orchestration_id: str) -> Optional[Dict[str, Any]]:
        """Get orchestration status."""
        # Check active
        if orchestration_id in self._active_runs:
            run = self._active_runs[orchestration_id]
            return {
                "orchestration_id": orchestration_id,
                "phase": run.phase.value,
                "total_tests": len(run.test_ids),
                "scheduled": len(run.scheduled_runs),
                "distributed": len(run.distributions),
                "completed": len(run.results),
                "mode": run.mode.value,
                "started_at": run.started_at.isoformat(),
            }

        # Check completed
        if orchestration_id in self._completed_runs:
            result = self._completed_runs[orchestration_id]
            return {
                "orchestration_id": orchestration_id,
                "phase": result.phase.value,
                "total_tests": result.total_tests,
                "passed": result.passed,
                "failed": result.failed,
                "errors": result.errors,
                "success_rate": result.success_rate,
                "duration_ms": result.duration_ms,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            }

        return None

    def get_result(self, orchestration_id: str) -> Optional[OrchestrationResult]:
        """Get orchestration result."""
        return self._completed_runs.get(orchestration_id)

    def cancel(self, orchestration_id: str) -> bool:
        """Cancel an active orchestration."""
        if orchestration_id not in self._active_runs:
            return False

        run = self._active_runs[orchestration_id]

        # Cancel scheduled runs
        for scheduled in run.scheduled_runs:
            self.scheduler.cancel_run(scheduled.run_id)

        # Mark as failed
        self._update_phase(run, OrchestrationPhase.FAILED)
        self._complete_orchestration(run, early_termination=True)

        return True

    def add_hook(self, event: str, callback: Callable):
        """Add a hook for an event."""
        if event in self._hooks:
            self._hooks[event].append(callback)

    def _run_hooks(self, event: str, *args):
        """Run hooks for an event."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args)
            except Exception:
                pass

    def get_statistics(self) -> Dict[str, Any]:
        """Get coordinator statistics."""
        scheduler_stats = self.scheduler.get_statistics()
        distributor_stats = self.distributor.get_statistics()

        completed_results = list(self._completed_runs.values())
        total_passed = sum(r.passed for r in completed_results)
        total_failed = sum(r.failed for r in completed_results)

        return {
            "active_orchestrations": len(self._active_runs),
            "completed_orchestrations": len(self._completed_runs),
            "total_passed": total_passed,
            "total_failed": total_failed,
            "overall_success_rate": total_passed / (total_passed + total_failed) if (total_passed + total_failed) > 0 else 0,
            "scheduler": scheduler_stats,
            "distributor": distributor_stats,
            "config": {
                "execution_mode": self.config.execution_mode.value,
                "distribution_strategy": self.config.distribution_strategy.value,
                "max_parallel_runs": self.config.max_parallel_runs,
            },
        }

    def format_status(self) -> str:
        """Format coordinator status."""
        stats = self.get_statistics()

        lines = [
            "=" * 60,
            "  TEST COORDINATOR STATUS",
            "=" * 60,
            "",
            f"  Mode: {stats['config']['execution_mode']}",
            f"  Strategy: {stats['config']['distribution_strategy']}",
            f"  Max Parallel: {stats['config']['max_parallel_runs']}",
            "",
            f"  Active Orchestrations: {stats['active_orchestrations']}",
            f"  Completed: {stats['completed_orchestrations']}",
            f"  Overall Success Rate: {stats['overall_success_rate']:.1%}",
            "",
        ]

        # Active orchestrations
        if self._active_runs:
            lines.extend(["-" * 60, "  ACTIVE ORCHESTRATIONS", "-" * 60])
            for orch_id, run in self._active_runs.items():
                phase_icon = {
                    OrchestrationPhase.INITIALIZING: "⚙️",
                    OrchestrationPhase.SCHEDULING: "📅",
                    OrchestrationPhase.DISTRIBUTING: "📤",
                    OrchestrationPhase.EXECUTING: "🔄",
                    OrchestrationPhase.COLLECTING: "📥",
                }.get(run.phase, "⏳")

                lines.extend([
                    "",
                    f"  {phase_icon} {orch_id}",
                    f"     Phase: {run.phase.value}",
                    f"     Tests: {len(run.test_ids)}",
                    f"     Results: {len(run.results)}",
                ])

        # Recent completions
        recent = list(self._completed_runs.values())[-3:]
        if recent:
            lines.extend(["", "-" * 60, "  RECENT COMPLETIONS", "-" * 60])
            for result in recent:
                status_icon = "✅" if result.is_successful else "❌"
                lines.extend([
                    "",
                    f"  {status_icon} {result.orchestration_id}",
                    f"     Passed: {result.passed} | Failed: {result.failed}",
                    f"     Success Rate: {result.success_rate:.1%}",
                ])

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_coordinator(
    config: Optional[CoordinatorConfig] = None,
) -> TestCoordinator:
    """Create a test coordinator instance."""
    return TestCoordinator(config)
