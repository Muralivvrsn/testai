"""
TestAI Agent - Monitoring Module

Real-time test execution monitoring with live updates,
failure detection, and intelligent execution control.
"""

from .execution_monitor import (
    ExecutionMonitor,
    MonitorConfig,
    ExecutionEvent,
    EventType,
    MonitorState,
    create_monitor,
)

from .live_dashboard import (
    LiveDashboard,
    DashboardUpdate,
    create_live_dashboard,
)

__all__ = [
    # Execution Monitor
    "ExecutionMonitor",
    "MonitorConfig",
    "ExecutionEvent",
    "EventType",
    "MonitorState",
    "create_monitor",
    # Live Dashboard
    "LiveDashboard",
    "DashboardUpdate",
    "create_live_dashboard",
]
