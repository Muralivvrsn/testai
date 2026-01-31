"""
TestAI Agent - Test Orchestrator Module

Provides cross-browser and cross-device test orchestration
with intelligent scheduling and parallel execution.
"""

from .scheduler import (
    TestScheduler,
    ScheduleConfig,
    ScheduledRun,
    create_scheduler,
)

from .distributor import (
    TestDistributor,
    DistributionStrategy,
    WorkerNode,
    create_distributor,
)

from .coordinator import (
    TestCoordinator,
    CoordinatorConfig,
    OrchestrationResult,
    create_coordinator,
)

__all__ = [
    # Scheduler
    "TestScheduler",
    "ScheduleConfig",
    "ScheduledRun",
    "create_scheduler",
    # Distributor
    "TestDistributor",
    "DistributionStrategy",
    "WorkerNode",
    "create_distributor",
    # Coordinator
    "TestCoordinator",
    "CoordinatorConfig",
    "OrchestrationResult",
    "create_coordinator",
]
