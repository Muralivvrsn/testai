"""
TestAI Agent - Browser Manager

Manages browser instances with intelligent configuration,
viewport management, and connection pooling.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time


class BrowserType(Enum):
    """Supported browser types."""
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class BrowserState(Enum):
    """Browser instance state."""
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    CLOSED = "closed"


@dataclass
class ViewportConfig:
    """Viewport configuration."""
    width: int
    height: int
    device_scale_factor: float = 1.0
    is_mobile: bool = False
    has_touch: bool = False

    @classmethod
    def desktop(cls, width: int = 1920, height: int = 1080) -> "ViewportConfig":
        """Create desktop viewport."""
        return cls(width=width, height=height)

    @classmethod
    def tablet(cls) -> "ViewportConfig":
        """Create tablet viewport."""
        return cls(width=768, height=1024, has_touch=True)

    @classmethod
    def mobile(cls) -> "ViewportConfig":
        """Create mobile viewport."""
        return cls(
            width=375,
            height=667,
            device_scale_factor=2.0,
            is_mobile=True,
            has_touch=True,
        )


@dataclass
class BrowserConfig:
    """Browser configuration."""
    browser_type: BrowserType = BrowserType.CHROMIUM
    headless: bool = True
    viewport: ViewportConfig = field(default_factory=ViewportConfig.desktop)
    timeout_ms: int = 30000
    slow_mo_ms: int = 0
    user_agent: Optional[str] = None
    locale: str = "en-US"
    timezone: str = "America/New_York"
    geolocation: Optional[Dict[str, float]] = None
    permissions: List[str] = field(default_factory=list)
    extra_http_headers: Dict[str, str] = field(default_factory=dict)
    ignore_https_errors: bool = False
    record_video: bool = False
    record_har: bool = False


@dataclass
class BrowserInstance:
    """A browser instance."""
    instance_id: str
    browser_type: BrowserType
    config: BrowserConfig
    state: BrowserState
    created_at: datetime
    last_used: datetime
    page_count: int = 0
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PageContext:
    """A page context within a browser."""
    context_id: str
    instance_id: str
    url: str
    title: str
    state: BrowserState
    created_at: datetime
    navigation_count: int = 0
    action_count: int = 0


class BrowserManager:
    """
    Manages browser instances for test execution.

    Features:
    - Browser pooling
    - Viewport management
    - Context isolation
    - Resource cleanup
    """

    # Default device presets
    DEVICE_PRESETS = {
        "desktop_hd": ViewportConfig(1920, 1080),
        "desktop_standard": ViewportConfig(1366, 768),
        "laptop": ViewportConfig(1280, 800),
        "tablet_portrait": ViewportConfig(768, 1024, has_touch=True),
        "tablet_landscape": ViewportConfig(1024, 768, has_touch=True),
        "iphone_12": ViewportConfig(390, 844, 3.0, True, True),
        "iphone_se": ViewportConfig(375, 667, 2.0, True, True),
        "pixel_5": ViewportConfig(393, 851, 2.75, True, True),
        "galaxy_s20": ViewportConfig(360, 800, 3.0, True, True),
    }

    def __init__(self, max_instances: int = 5):
        """Initialize the browser manager."""
        self._max_instances = max_instances
        self._instances: Dict[str, BrowserInstance] = {}
        self._contexts: Dict[str, PageContext] = {}
        self._instance_counter = 0
        self._context_counter = 0
        self._launch_hooks: List[Callable] = []
        self._close_hooks: List[Callable] = []

    def create_instance(
        self,
        config: Optional[BrowserConfig] = None,
    ) -> BrowserInstance:
        """Create a new browser instance."""
        if len(self._instances) >= self._max_instances:
            # Find and close oldest idle instance
            idle = [
                i for i in self._instances.values()
                if i.state == BrowserState.IDLE
            ]
            if idle:
                oldest = min(idle, key=lambda x: x.last_used)
                self.close_instance(oldest.instance_id)
            else:
                raise RuntimeError("Maximum browser instances reached")

        self._instance_counter += 1
        config = config or BrowserConfig()

        instance = BrowserInstance(
            instance_id=f"browser-{self._instance_counter:04d}",
            browser_type=config.browser_type,
            config=config,
            state=BrowserState.IDLE,
            created_at=datetime.now(),
            last_used=datetime.now(),
        )

        self._instances[instance.instance_id] = instance

        # Run launch hooks
        for hook in self._launch_hooks:
            try:
                hook(instance)
            except Exception:
                pass

        return instance

    def get_instance(self, instance_id: str) -> Optional[BrowserInstance]:
        """Get a browser instance by ID."""
        return self._instances.get(instance_id)

    def get_available_instance(
        self,
        browser_type: Optional[BrowserType] = None,
    ) -> Optional[BrowserInstance]:
        """Get an available browser instance."""
        for instance in self._instances.values():
            if instance.state != BrowserState.IDLE:
                continue
            if browser_type and instance.browser_type != browser_type:
                continue
            return instance
        return None

    def close_instance(self, instance_id: str) -> bool:
        """Close a browser instance."""
        instance = self._instances.get(instance_id)
        if not instance:
            return False

        # Close all contexts
        context_ids = [
            c.context_id for c in self._contexts.values()
            if c.instance_id == instance_id
        ]
        for context_id in context_ids:
            self.close_context(context_id)

        # Run close hooks
        for hook in self._close_hooks:
            try:
                hook(instance)
            except Exception:
                pass

        instance.state = BrowserState.CLOSED
        del self._instances[instance_id]
        return True

    def create_context(
        self,
        instance_id: str,
        url: str = "about:blank",
    ) -> Optional[PageContext]:
        """Create a new page context."""
        instance = self._instances.get(instance_id)
        if not instance:
            return None

        self._context_counter += 1

        context = PageContext(
            context_id=f"ctx-{self._context_counter:04d}",
            instance_id=instance_id,
            url=url,
            title="",
            state=BrowserState.IDLE,
            created_at=datetime.now(),
        )

        self._contexts[context.context_id] = context
        instance.page_count += 1
        instance.last_used = datetime.now()

        return context

    def get_context(self, context_id: str) -> Optional[PageContext]:
        """Get a page context by ID."""
        return self._contexts.get(context_id)

    def close_context(self, context_id: str) -> bool:
        """Close a page context."""
        context = self._contexts.get(context_id)
        if not context:
            return False

        instance = self._instances.get(context.instance_id)
        if instance:
            instance.page_count -= 1

        context.state = BrowserState.CLOSED
        del self._contexts[context_id]
        return True

    def navigate(
        self,
        context_id: str,
        url: str,
        wait_until: str = "load",
    ) -> bool:
        """Navigate a context to a URL."""
        context = self._contexts.get(context_id)
        if not context:
            return False

        context.url = url
        context.navigation_count += 1
        context.state = BrowserState.BUSY

        # Simulate navigation delay
        time.sleep(0.01)

        context.state = BrowserState.IDLE
        return True

    def set_viewport(
        self,
        instance_id: str,
        viewport: ViewportConfig,
    ) -> bool:
        """Set viewport for a browser instance."""
        instance = self._instances.get(instance_id)
        if not instance:
            return False

        instance.config.viewport = viewport
        return True

    def set_viewport_preset(
        self,
        instance_id: str,
        preset: str,
    ) -> bool:
        """Set viewport from a preset."""
        if preset not in self.DEVICE_PRESETS:
            return False

        return self.set_viewport(instance_id, self.DEVICE_PRESETS[preset])

    def get_viewport_presets(self) -> Dict[str, ViewportConfig]:
        """Get all viewport presets."""
        return dict(self.DEVICE_PRESETS)

    def add_launch_hook(self, hook: Callable):
        """Add a browser launch hook."""
        self._launch_hooks.append(hook)

    def add_close_hook(self, hook: Callable):
        """Add a browser close hook."""
        self._close_hooks.append(hook)

    def get_statistics(self) -> Dict[str, Any]:
        """Get browser manager statistics."""
        active = [i for i in self._instances.values() if i.state != BrowserState.CLOSED]
        idle = [i for i in active if i.state == BrowserState.IDLE]
        busy = [i for i in active if i.state == BrowserState.BUSY]

        by_type = {}
        for instance in active:
            t = instance.browser_type.value
            by_type[t] = by_type.get(t, 0) + 1

        return {
            "total_instances": len(active),
            "idle_instances": len(idle),
            "busy_instances": len(busy),
            "total_contexts": len(self._contexts),
            "by_browser_type": by_type,
            "max_instances": self._max_instances,
        }

    def cleanup(self):
        """Close all browser instances."""
        instance_ids = list(self._instances.keys())
        for instance_id in instance_ids:
            self.close_instance(instance_id)

    def format_status(self) -> str:
        """Format browser manager status."""
        stats = self.get_statistics()

        lines = [
            "=" * 50,
            "  BROWSER MANAGER STATUS",
            "=" * 50,
            "",
            f"  Active Instances: {stats['total_instances']}/{stats['max_instances']}",
            f"  Idle: {stats['idle_instances']} | Busy: {stats['busy_instances']}",
            f"  Active Contexts: {stats['total_contexts']}",
            "",
        ]

        if stats["by_browser_type"]:
            lines.append("  By Browser Type:")
            for browser_type, count in stats["by_browser_type"].items():
                lines.append(f"    - {browser_type}: {count}")

        if self._instances:
            lines.extend(["", "-" * 50, "  INSTANCES", "-" * 50])
            for instance in self._instances.values():
                status_icon = {
                    BrowserState.IDLE: "🟢",
                    BrowserState.BUSY: "🟡",
                    BrowserState.ERROR: "🔴",
                }.get(instance.state, "⚪")

                lines.extend([
                    "",
                    f"  {status_icon} {instance.instance_id}",
                    f"     Type: {instance.browser_type.value}",
                    f"     Pages: {instance.page_count}",
                    f"     Viewport: {instance.config.viewport.width}x{instance.config.viewport.height}",
                ])

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_browser_manager(max_instances: int = 5) -> BrowserManager:
    """Create a browser manager instance."""
    return BrowserManager(max_instances=max_instances)
