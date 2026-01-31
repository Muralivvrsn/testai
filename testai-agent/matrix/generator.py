"""
TestAI Agent - Test Matrix Generator

Generates cross-browser and cross-device test matrices
with comprehensive coverage options.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict


class BrowserType(Enum):
    """Supported browser types."""
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"
    IE = "ie"
    OPERA = "opera"


class DeviceType(Enum):
    """Device types for testing."""
    DESKTOP = "desktop"
    TABLET = "tablet"
    MOBILE = "mobile"


class OSType(Enum):
    """Operating system types."""
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    IOS = "ios"
    ANDROID = "android"


@dataclass
class BrowserConfig:
    """Browser configuration for testing."""
    browser: BrowserType
    version: str
    headless: bool = False
    viewport_width: int = 1920
    viewport_height: int = 1080
    user_agent: Optional[str] = None
    locale: str = "en-US"
    timezone: Optional[str] = None


@dataclass
class DeviceConfig:
    """Device configuration for testing."""
    device_type: DeviceType
    os: OSType
    os_version: str
    screen_width: int
    screen_height: int
    pixel_ratio: float = 1.0
    touch_enabled: bool = False
    name: str = ""


@dataclass
class MatrixCell:
    """A single cell in the test matrix."""
    test_id: str
    browser: BrowserConfig
    device: Optional[DeviceConfig] = None
    enabled: bool = True
    priority: int = 1
    tags: List[str] = field(default_factory=list)
    estimated_duration_ms: int = 0


@dataclass
class TestMatrix:
    """A complete test matrix."""
    name: str
    tests: List[str]
    browsers: List[BrowserConfig]
    devices: Optional[List[DeviceConfig]] = None
    cells: List[MatrixCell] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    total_combinations: int = 0
    estimated_total_duration_ms: int = 0


class MatrixGenerator:
    """
    Generates test matrices for cross-browser testing.

    Features:
    - Browser/version combinations
    - Device emulation configs
    - Viewport presets
    - OS-specific settings
    - Priority-based selection
    """

    # Common browser versions
    BROWSER_VERSIONS = {
        BrowserType.CHROME: ["120", "119", "118", "100"],
        BrowserType.FIREFOX: ["120", "115", "102"],
        BrowserType.SAFARI: ["17", "16", "15"],
        BrowserType.EDGE: ["120", "119", "118"],
        BrowserType.IE: ["11"],
        BrowserType.OPERA: ["105", "100"],
    }

    # Common devices
    COMMON_DEVICES = {
        "iPhone 15 Pro": DeviceConfig(
            device_type=DeviceType.MOBILE,
            os=OSType.IOS,
            os_version="17",
            screen_width=393,
            screen_height=852,
            pixel_ratio=3.0,
            touch_enabled=True,
            name="iPhone 15 Pro",
        ),
        "iPhone SE": DeviceConfig(
            device_type=DeviceType.MOBILE,
            os=OSType.IOS,
            os_version="17",
            screen_width=375,
            screen_height=667,
            pixel_ratio=2.0,
            touch_enabled=True,
            name="iPhone SE",
        ),
        "iPad Pro": DeviceConfig(
            device_type=DeviceType.TABLET,
            os=OSType.IOS,
            os_version="17",
            screen_width=1024,
            screen_height=1366,
            pixel_ratio=2.0,
            touch_enabled=True,
            name="iPad Pro",
        ),
        "Galaxy S23": DeviceConfig(
            device_type=DeviceType.MOBILE,
            os=OSType.ANDROID,
            os_version="14",
            screen_width=360,
            screen_height=780,
            pixel_ratio=3.0,
            touch_enabled=True,
            name="Galaxy S23",
        ),
        "Pixel 7": DeviceConfig(
            device_type=DeviceType.MOBILE,
            os=OSType.ANDROID,
            os_version="14",
            screen_width=412,
            screen_height=915,
            pixel_ratio=2.625,
            touch_enabled=True,
            name="Pixel 7",
        ),
        "Desktop 1080p": DeviceConfig(
            device_type=DeviceType.DESKTOP,
            os=OSType.WINDOWS,
            os_version="11",
            screen_width=1920,
            screen_height=1080,
            pixel_ratio=1.0,
            name="Desktop 1080p",
        ),
        "Desktop 1440p": DeviceConfig(
            device_type=DeviceType.DESKTOP,
            os=OSType.WINDOWS,
            os_version="11",
            screen_width=2560,
            screen_height=1440,
            pixel_ratio=1.0,
            name="Desktop 1440p",
        ),
        "MacBook Pro": DeviceConfig(
            device_type=DeviceType.DESKTOP,
            os=OSType.MACOS,
            os_version="14",
            screen_width=1440,
            screen_height=900,
            pixel_ratio=2.0,
            name="MacBook Pro",
        ),
    }

    # Viewport presets
    VIEWPORTS = {
        "mobile-small": (320, 568),
        "mobile": (375, 667),
        "mobile-large": (414, 896),
        "tablet": (768, 1024),
        "tablet-landscape": (1024, 768),
        "laptop": (1366, 768),
        "desktop": (1920, 1080),
        "desktop-large": (2560, 1440),
    }

    def __init__(self):
        """Initialize the matrix generator."""
        self._test_durations: Dict[str, int] = {}

    def generate(
        self,
        tests: List[str],
        browsers: Optional[List[BrowserType]] = None,
        browser_versions: Optional[Dict[BrowserType, List[str]]] = None,
        devices: Optional[List[str]] = None,
        viewports: Optional[List[str]] = None,
        include_headless: bool = True,
    ) -> TestMatrix:
        """Generate a test matrix."""
        # Default browsers
        if browsers is None:
            browsers = [BrowserType.CHROME, BrowserType.FIREFOX]

        # Build browser configs
        browser_configs = self._build_browser_configs(
            browsers,
            browser_versions,
            viewports,
            include_headless,
        )

        # Build device configs
        device_configs = None
        if devices:
            device_configs = [
                self.COMMON_DEVICES[d]
                for d in devices
                if d in self.COMMON_DEVICES
            ]

        # Generate cells
        cells = []
        for test_id in tests:
            for browser in browser_configs:
                # Add cell for each browser
                cells.append(MatrixCell(
                    test_id=test_id,
                    browser=browser,
                    enabled=True,
                    priority=self._get_browser_priority(browser),
                    estimated_duration_ms=self._test_durations.get(test_id, 5000),
                ))

                # Add cells for devices if specified
                if device_configs:
                    for device in device_configs:
                        cells.append(MatrixCell(
                            test_id=test_id,
                            browser=browser,
                            device=device,
                            enabled=True,
                            priority=self._get_device_priority(device),
                            estimated_duration_ms=self._test_durations.get(test_id, 5000),
                        ))

        # Calculate totals
        total_combinations = len(cells)
        estimated_duration = sum(c.estimated_duration_ms for c in cells)

        return TestMatrix(
            name=f"Matrix-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            tests=tests,
            browsers=browser_configs,
            devices=device_configs,
            cells=cells,
            total_combinations=total_combinations,
            estimated_total_duration_ms=estimated_duration,
        )

    def generate_responsive(
        self,
        tests: List[str],
        browser: BrowserType = BrowserType.CHROME,
        version: str = "120",
    ) -> TestMatrix:
        """Generate a matrix focused on responsive testing."""
        browser_configs = []

        for viewport_name, (width, height) in self.VIEWPORTS.items():
            browser_configs.append(BrowserConfig(
                browser=browser,
                version=version,
                viewport_width=width,
                viewport_height=height,
            ))

        cells = []
        for test_id in tests:
            for browser_config in browser_configs:
                cells.append(MatrixCell(
                    test_id=test_id,
                    browser=browser_config,
                    tags=[f"viewport-{browser_config.viewport_width}"],
                ))

        return TestMatrix(
            name=f"Responsive-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            tests=tests,
            browsers=browser_configs,
            cells=cells,
            total_combinations=len(cells),
            estimated_total_duration_ms=len(cells) * 5000,
        )

    def generate_mobile(
        self,
        tests: List[str],
        include_ios: bool = True,
        include_android: bool = True,
    ) -> TestMatrix:
        """Generate a matrix focused on mobile testing."""
        devices = []

        if include_ios:
            devices.extend([
                self.COMMON_DEVICES["iPhone 15 Pro"],
                self.COMMON_DEVICES["iPhone SE"],
                self.COMMON_DEVICES["iPad Pro"],
            ])

        if include_android:
            devices.extend([
                self.COMMON_DEVICES["Galaxy S23"],
                self.COMMON_DEVICES["Pixel 7"],
            ])

        # Use Chrome for Android, Safari for iOS
        cells = []
        for test_id in tests:
            for device in devices:
                browser = BrowserType.SAFARI if device.os == OSType.IOS else BrowserType.CHROME
                browser_config = BrowserConfig(
                    browser=browser,
                    version="latest",
                    viewport_width=device.screen_width,
                    viewport_height=device.screen_height,
                )

                cells.append(MatrixCell(
                    test_id=test_id,
                    browser=browser_config,
                    device=device,
                    tags=[device.os.value, device.device_type.value],
                ))

        return TestMatrix(
            name=f"Mobile-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            tests=tests,
            browsers=[],  # Browser per device
            devices=devices,
            cells=cells,
            total_combinations=len(cells),
            estimated_total_duration_ms=len(cells) * 8000,  # Mobile tests often slower
        )

    def set_test_duration(self, test_id: str, duration_ms: int):
        """Set estimated duration for a test."""
        self._test_durations[test_id] = duration_ms

    def get_available_browsers(self) -> List[BrowserType]:
        """Get available browser types."""
        return list(BrowserType)

    def get_available_devices(self) -> List[str]:
        """Get available device names."""
        return list(self.COMMON_DEVICES.keys())

    def get_available_viewports(self) -> Dict[str, Tuple[int, int]]:
        """Get available viewport presets."""
        return self.VIEWPORTS.copy()

    def _build_browser_configs(
        self,
        browsers: List[BrowserType],
        versions: Optional[Dict[BrowserType, List[str]]],
        viewports: Optional[List[str]],
        include_headless: bool,
    ) -> List[BrowserConfig]:
        """Build browser configurations."""
        configs = []
        versions = versions or {}
        viewport_sizes = [(1920, 1080)]  # Default

        if viewports:
            viewport_sizes = [
                self.VIEWPORTS[v]
                for v in viewports
                if v in self.VIEWPORTS
            ]

        for browser in browsers:
            browser_versions = versions.get(
                browser,
                self.BROWSER_VERSIONS.get(browser, ["latest"])[:2]  # Latest 2 versions
            )

            for version in browser_versions:
                for width, height in viewport_sizes:
                    # Regular mode
                    configs.append(BrowserConfig(
                        browser=browser,
                        version=version,
                        viewport_width=width,
                        viewport_height=height,
                        headless=False,
                    ))

                    # Headless mode
                    if include_headless:
                        configs.append(BrowserConfig(
                            browser=browser,
                            version=version,
                            viewport_width=width,
                            viewport_height=height,
                            headless=True,
                        ))

        return configs

    def _get_browser_priority(self, browser: BrowserConfig) -> int:
        """Get priority for a browser config."""
        priorities = {
            BrowserType.CHROME: 1,
            BrowserType.FIREFOX: 2,
            BrowserType.SAFARI: 2,
            BrowserType.EDGE: 3,
            BrowserType.OPERA: 4,
            BrowserType.IE: 5,
        }
        return priorities.get(browser.browser, 3)

    def _get_device_priority(self, device: DeviceConfig) -> int:
        """Get priority for a device config."""
        # Mobile and modern devices have higher priority
        if device.device_type == DeviceType.MOBILE:
            return 1
        elif device.device_type == DeviceType.TABLET:
            return 2
        return 3

    def format_matrix(self, matrix: TestMatrix) -> str:
        """Format matrix as readable text."""
        lines = [
            "=" * 60,
            f"  TEST MATRIX: {matrix.name}",
            "=" * 60,
            "",
            f"  Tests: {len(matrix.tests)}",
            f"  Browsers: {len(matrix.browsers)}",
            f"  Devices: {len(matrix.devices) if matrix.devices else 0}",
            f"  Total Combinations: {matrix.total_combinations}",
            f"  Est. Duration: {matrix.estimated_total_duration_ms / 1000 / 60:.1f} minutes",
            "",
        ]

        # Browser breakdown
        lines.extend([
            "-" * 60,
            "  BROWSERS",
            "-" * 60,
        ])
        browser_counts: Dict[str, int] = defaultdict(int)
        for browser in matrix.browsers:
            key = f"{browser.browser.value} {browser.version}"
            browser_counts[key] += 1

        for browser, count in sorted(browser_counts.items()):
            lines.append(f"  • {browser}: {count} configs")

        # Device breakdown
        if matrix.devices:
            lines.extend([
                "",
                "-" * 60,
                "  DEVICES",
                "-" * 60,
            ])
            for device in matrix.devices:
                lines.append(
                    f"  • {device.name}: {device.screen_width}x{device.screen_height} "
                    f"({device.os.value})"
                )

        # Test coverage
        lines.extend([
            "",
            "-" * 60,
            "  TEST COVERAGE",
            "-" * 60,
        ])
        for test_id in matrix.tests[:10]:
            cell_count = sum(1 for c in matrix.cells if c.test_id == test_id)
            lines.append(f"  • {test_id}: {cell_count} combinations")

        if len(matrix.tests) > 10:
            lines.append(f"  ... and {len(matrix.tests) - 10} more tests")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_matrix_generator() -> MatrixGenerator:
    """Create a matrix generator instance."""
    return MatrixGenerator()
