"""
TestAI Agent - Screenshot Manager

Capture, organize, and manage screenshots
for visual regression testing.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import uuid


class CaptureMode(Enum):
    """Screenshot capture modes."""
    FULL_PAGE = "full_page"
    VIEWPORT = "viewport"
    ELEMENT = "element"
    REGION = "region"


class ScreenshotStatus(Enum):
    """Status of a screenshot."""
    PENDING = "pending"
    CAPTURED = "captured"
    BASELINE = "baseline"
    COMPARED = "compared"
    ARCHIVED = "archived"


@dataclass
class Screenshot:
    """A captured screenshot."""
    screenshot_id: str
    name: str
    test_id: str
    mode: CaptureMode
    width: int
    height: int
    status: ScreenshotStatus
    captured_at: datetime
    file_path: Optional[str] = None
    element_selector: Optional[str] = None
    region: Optional[Tuple[int, int, int, int]] = None  # x, y, w, h
    viewport_size: Optional[Tuple[int, int]] = None
    device: Optional[str] = None
    browser: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScreenshotSet:
    """A set of related screenshots."""
    set_id: str
    name: str
    description: str
    screenshots: List[Screenshot]
    created_at: datetime
    tags: List[str] = field(default_factory=list)


class ScreenshotManager:
    """
    Screenshot management for visual testing.

    Features:
    - Multi-mode capture (full page, viewport, element)
    - Baseline management
    - Version history
    - Organization with sets
    """

    # Supported device presets
    DEVICE_PRESETS = {
        "desktop": (1920, 1080),
        "laptop": (1366, 768),
        "tablet": (768, 1024),
        "mobile": (375, 667),
        "iphone-12": (390, 844),
        "ipad-pro": (1024, 1366),
    }

    def __init__(
        self,
        storage_path: str = "./screenshots",
        keep_history: int = 10,
    ):
        """Initialize the manager."""
        self._storage_path = storage_path
        self._keep_history = keep_history

        self._screenshots: Dict[str, Screenshot] = {}
        self._sets: Dict[str, ScreenshotSet] = {}
        self._baselines: Dict[str, str] = {}  # name -> screenshot_id
        self._history: Dict[str, List[str]] = {}  # name -> [screenshot_ids]

        self._screenshot_counter = 0
        self._set_counter = 0

    def capture(
        self,
        name: str,
        test_id: str,
        width: int,
        height: int,
        mode: CaptureMode = CaptureMode.VIEWPORT,
        element_selector: Optional[str] = None,
        region: Optional[Tuple[int, int, int, int]] = None,
        device: Optional[str] = None,
        browser: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Screenshot:
        """Capture a screenshot."""
        self._screenshot_counter += 1
        screenshot_id = f"SS-{self._screenshot_counter:05d}"

        # Resolve device preset
        if device and device in self.DEVICE_PRESETS:
            viewport_size = self.DEVICE_PRESETS[device]
        else:
            viewport_size = (width, height)

        # Generate file path
        file_path = f"{self._storage_path}/{screenshot_id}_{name.replace(' ', '_')}.png"

        screenshot = Screenshot(
            screenshot_id=screenshot_id,
            name=name,
            test_id=test_id,
            mode=mode,
            width=width,
            height=height,
            status=ScreenshotStatus.CAPTURED,
            captured_at=datetime.now(),
            file_path=file_path,
            element_selector=element_selector,
            region=region,
            viewport_size=viewport_size,
            device=device,
            browser=browser,
            metadata=metadata or {},
        )

        self._screenshots[screenshot_id] = screenshot

        # Add to history
        if name not in self._history:
            self._history[name] = []
        self._history[name].append(screenshot_id)

        # Prune old history
        if len(self._history[name]) > self._keep_history:
            old_id = self._history[name].pop(0)
            if old_id in self._screenshots:
                self._screenshots[old_id].status = ScreenshotStatus.ARCHIVED

        return screenshot

    def set_as_baseline(
        self,
        screenshot_id: str,
    ) -> Screenshot:
        """Set a screenshot as the baseline."""
        screenshot = self._screenshots.get(screenshot_id)
        if not screenshot:
            raise ValueError(f"Screenshot {screenshot_id} not found")

        screenshot.status = ScreenshotStatus.BASELINE
        self._baselines[screenshot.name] = screenshot_id

        return screenshot

    def get_baseline(
        self,
        name: str,
    ) -> Optional[Screenshot]:
        """Get the baseline screenshot for a name."""
        baseline_id = self._baselines.get(name)
        if baseline_id:
            return self._screenshots.get(baseline_id)
        return None

    def create_set(
        self,
        name: str,
        description: str = "",
        screenshot_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> ScreenshotSet:
        """Create a screenshot set."""
        self._set_counter += 1
        set_id = f"SSSET-{self._set_counter:05d}"

        screenshots = []
        if screenshot_ids:
            for sid in screenshot_ids:
                if sid in self._screenshots:
                    screenshots.append(self._screenshots[sid])

        ss_set = ScreenshotSet(
            set_id=set_id,
            name=name,
            description=description,
            screenshots=screenshots,
            created_at=datetime.now(),
            tags=tags or [],
        )

        self._sets[set_id] = ss_set
        return ss_set

    def add_to_set(
        self,
        set_id: str,
        screenshot_id: str,
    ) -> ScreenshotSet:
        """Add a screenshot to a set."""
        ss_set = self._sets.get(set_id)
        if not ss_set:
            raise ValueError(f"Set {set_id} not found")

        screenshot = self._screenshots.get(screenshot_id)
        if not screenshot:
            raise ValueError(f"Screenshot {screenshot_id} not found")

        if screenshot not in ss_set.screenshots:
            ss_set.screenshots.append(screenshot)

        return ss_set

    def capture_for_devices(
        self,
        name: str,
        test_id: str,
        devices: Optional[List[str]] = None,
    ) -> ScreenshotSet:
        """Capture screenshots for multiple devices."""
        if devices is None:
            devices = list(self.DEVICE_PRESETS.keys())

        screenshots = []
        for device in devices:
            if device in self.DEVICE_PRESETS:
                width, height = self.DEVICE_PRESETS[device]
                ss = self.capture(
                    name=f"{name}_{device}",
                    test_id=test_id,
                    width=width,
                    height=height,
                    device=device,
                )
                screenshots.append(ss)

        # Create a set
        ss_set = self.create_set(
            name=f"{name}_responsive",
            description=f"Responsive screenshots for {name}",
            screenshot_ids=[ss.screenshot_id for ss in screenshots],
            tags=["responsive", "multi-device"],
        )

        return ss_set

    def get_screenshot(
        self,
        screenshot_id: str,
    ) -> Optional[Screenshot]:
        """Get a screenshot by ID."""
        return self._screenshots.get(screenshot_id)

    def get_screenshots_for_test(
        self,
        test_id: str,
    ) -> List[Screenshot]:
        """Get all screenshots for a test."""
        return [
            ss for ss in self._screenshots.values()
            if ss.test_id == test_id
        ]

    def get_history(
        self,
        name: str,
        limit: int = 10,
    ) -> List[Screenshot]:
        """Get screenshot history for a name."""
        history_ids = self._history.get(name, [])
        screenshots = []

        for sid in reversed(history_ids[-limit:]):
            if sid in self._screenshots:
                screenshots.append(self._screenshots[sid])

        return screenshots

    def compare_with_baseline(
        self,
        screenshot_id: str,
    ) -> Optional[Tuple[Screenshot, Screenshot]]:
        """Get screenshot and its baseline for comparison."""
        screenshot = self._screenshots.get(screenshot_id)
        if not screenshot:
            return None

        baseline = self.get_baseline(screenshot.name)
        if not baseline:
            return None

        return (baseline, screenshot)

    def mark_compared(
        self,
        screenshot_id: str,
    ) -> Screenshot:
        """Mark a screenshot as compared."""
        screenshot = self._screenshots.get(screenshot_id)
        if not screenshot:
            raise ValueError(f"Screenshot {screenshot_id} not found")

        screenshot.status = ScreenshotStatus.COMPARED
        return screenshot

    def archive(
        self,
        screenshot_id: str,
    ) -> Screenshot:
        """Archive a screenshot."""
        screenshot = self._screenshots.get(screenshot_id)
        if not screenshot:
            raise ValueError(f"Screenshot {screenshot_id} not found")

        screenshot.status = ScreenshotStatus.ARCHIVED
        return screenshot

    def cleanup_archived(
        self,
        days_old: int = 30,
    ) -> int:
        """Remove archived screenshots older than specified days."""
        cutoff = datetime.now()
        removed = 0

        for sid in list(self._screenshots.keys()):
            ss = self._screenshots[sid]
            if ss.status == ScreenshotStatus.ARCHIVED:
                age_days = (cutoff - ss.captured_at).days
                if age_days > days_old:
                    del self._screenshots[sid]
                    removed += 1

        return removed

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        status_counts = {}
        for status in ScreenshotStatus:
            status_counts[status.value] = sum(
                1 for ss in self._screenshots.values()
                if ss.status == status
            )

        return {
            "total_screenshots": len(self._screenshots),
            "total_sets": len(self._sets),
            "baselines": len(self._baselines),
            "status_breakdown": status_counts,
            "unique_names": len(self._history),
        }

    def format_screenshot(self, screenshot: Screenshot) -> str:
        """Format a screenshot for display."""
        status_emoji = {
            ScreenshotStatus.PENDING: "⏳",
            ScreenshotStatus.CAPTURED: "📸",
            ScreenshotStatus.BASELINE: "🎯",
            ScreenshotStatus.COMPARED: "✅",
            ScreenshotStatus.ARCHIVED: "📦",
        }

        lines = [
            "=" * 50,
            f"  {status_emoji[screenshot.status]} SCREENSHOT",
            "=" * 50,
            "",
            f"  ID: {screenshot.screenshot_id}",
            f"  Name: {screenshot.name}",
            f"  Test: {screenshot.test_id}",
            "",
            f"  Size: {screenshot.width}x{screenshot.height}",
            f"  Mode: {screenshot.mode.value}",
            f"  Status: {screenshot.status.value}",
            "",
        ]

        if screenshot.device:
            lines.append(f"  Device: {screenshot.device}")
        if screenshot.browser:
            lines.append(f"  Browser: {screenshot.browser}")
        if screenshot.element_selector:
            lines.append(f"  Element: {screenshot.element_selector}")

        lines.extend([
            "",
            f"  Captured: {screenshot.captured_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=" * 50,
        ])

        return "\n".join(lines)

    def format_set(self, ss_set: ScreenshotSet) -> str:
        """Format a screenshot set for display."""
        lines = [
            "=" * 50,
            "  📁 SCREENSHOT SET",
            "=" * 50,
            "",
            f"  ID: {ss_set.set_id}",
            f"  Name: {ss_set.name}",
            f"  Screenshots: {len(ss_set.screenshots)}",
            "",
        ]

        if ss_set.description:
            lines.append(f"  Description: {ss_set.description}")

        if ss_set.tags:
            lines.append(f"  Tags: {', '.join(ss_set.tags)}")

        lines.append("")
        lines.append("-" * 50)
        lines.append("  SCREENSHOTS")
        lines.append("-" * 50)

        for ss in ss_set.screenshots[:5]:
            lines.append(f"  • {ss.name} ({ss.width}x{ss.height})")

        if len(ss_set.screenshots) > 5:
            lines.append(f"  ... and {len(ss_set.screenshots) - 5} more")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_screenshot_manager(
    storage_path: str = "./screenshots",
    keep_history: int = 10,
) -> ScreenshotManager:
    """Create a screenshot manager instance."""
    return ScreenshotManager(
        storage_path=storage_path,
        keep_history=keep_history,
    )
