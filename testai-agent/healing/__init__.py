"""
TestAI Agent - Self-Healing Test Maintenance

Intelligent self-healing system that automatically detects,
diagnoses, and repairs broken tests through selector healing,
UI change detection, and adaptive repair strategies.
"""

from .selector_healer import (
    SelectorHealer,
    SelectorType,
    HealingStrategy,
    SelectorCandidate,
    HealingResult,
    create_selector_healer,
)

from .change_detector import (
    ChangeDetector,
    ChangeType,
    UIChange,
    ChangeReport,
    create_change_detector,
)

from .repair_engine import (
    RepairEngine,
    RepairStrategy,
    RepairAction,
    RepairResult,
    create_repair_engine,
)

__all__ = [
    # Selector Healer
    "SelectorHealer",
    "SelectorType",
    "HealingStrategy",
    "SelectorCandidate",
    "HealingResult",
    "create_selector_healer",
    # Change Detector
    "ChangeDetector",
    "ChangeType",
    "UIChange",
    "ChangeReport",
    "create_change_detector",
    # Repair Engine
    "RepairEngine",
    "RepairStrategy",
    "RepairAction",
    "RepairResult",
    "create_repair_engine",
]
