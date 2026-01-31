"""
TestAI Agent - Visual Regression Testing

Perceptual image comparison, screenshot management,
and visual diff analysis for UI testing.
"""

from .comparator import (
    VisualComparator,
    ComparisonMethod,
    ComparisonResult,
    DiffRegion,
    create_visual_comparator,
)

from .screenshots import (
    ScreenshotManager,
    Screenshot,
    ScreenshotSet,
    create_screenshot_manager,
)

from .reporter import (
    VisualReporter,
    VisualReport,
    VisualDiff,
    ReportFormat,
    DiffDisplayMode,
    create_visual_reporter,
)

__all__ = [
    # Comparator
    "VisualComparator",
    "ComparisonMethod",
    "ComparisonResult",
    "DiffRegion",
    "create_visual_comparator",
    # Screenshots
    "ScreenshotManager",
    "Screenshot",
    "ScreenshotSet",
    "create_screenshot_manager",
    # Reporter
    "VisualReporter",
    "VisualReport",
    "VisualDiff",
    "ReportFormat",
    "DiffDisplayMode",
    "create_visual_reporter",
]
