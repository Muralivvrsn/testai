"""
TestAI Agent - Test Maintenance Module

Smart detection of tests needing maintenance, selector
health monitoring, and automated update suggestions.
"""

from .detector import (
    MaintenanceDetector,
    MaintenanceIssue,
    MaintenanceType,
    MaintenancePriority,
    create_maintenance_detector,
)

from .selector_health import (
    SelectorHealthMonitor,
    SelectorHealth,
    SelectorRisk,
    create_selector_monitor,
)

from .updater import (
    TestUpdater,
    UpdateSuggestion,
    UpdateType,
    create_test_updater,
)

__all__ = [
    # Detector
    "MaintenanceDetector",
    "MaintenanceIssue",
    "MaintenanceType",
    "MaintenancePriority",
    "create_maintenance_detector",
    # Selector Health
    "SelectorHealthMonitor",
    "SelectorHealth",
    "SelectorRisk",
    "create_selector_monitor",
    # Updater
    "TestUpdater",
    "UpdateSuggestion",
    "UpdateType",
    "create_test_updater",
]
