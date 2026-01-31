"""
TestAI Agent - Execution Module

Provides both simulated and real test execution:
- TestSimulator: Simulates test execution for testing/demos
- LiveExecutor: Real browser automation using Playwright
"""

from .simulator import (
    TestSimulator,
    SimulationConfig,
    SimulationResult,
    ExecutionStatus,
    create_simulator,
)

from .reporter import (
    TestReporter,
    ReportFormat,
    TestReport,
    SuiteReport,
    create_reporter,
)

# Live execution with Playwright
try:
    from .live_executor import (
        LiveExecutor,
        ExecutionResult,
    )
    LIVE_EXECUTOR_AVAILABLE = True
except ImportError:
    LIVE_EXECUTOR_AVAILABLE = False
    LiveExecutor = None
    ExecutionResult = None

__all__ = [
    # Simulator
    "TestSimulator",
    "SimulationConfig",
    "SimulationResult",
    "ExecutionStatus",
    "create_simulator",
    # Reporter
    "TestReporter",
    "ReportFormat",
    "TestReport",
    "SuiteReport",
    "create_reporter",
    # Live Executor
    "LiveExecutor",
    "ExecutionResult",
    "LIVE_EXECUTOR_AVAILABLE",
]
