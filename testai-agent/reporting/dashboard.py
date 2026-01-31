"""
TestAI Agent - Dashboard Manager

Manages test dashboards with configurable widgets
for real-time monitoring and historical analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable


class WidgetType(Enum):
    """Types of dashboard widgets."""
    PASS_RATE = "pass_rate"
    FAILURE_TREND = "failure_trend"
    COVERAGE_GAUGE = "coverage_gauge"
    DURATION_CHART = "duration_chart"
    FLAKY_TESTS = "flaky_tests"
    TOP_FAILURES = "top_failures"
    RECENT_RUNS = "recent_runs"
    SUITE_HEALTH = "suite_health"
    PERFORMANCE_TREND = "performance_trend"
    TEST_DISTRIBUTION = "test_distribution"
    CUSTOM = "custom"


class RefreshInterval(Enum):
    """Widget refresh intervals."""
    REALTIME = 5
    FAST = 15
    NORMAL = 60
    SLOW = 300
    MANUAL = 0


@dataclass
class WidgetData:
    """Data for a widget."""
    widget_id: str
    data: Dict[str, Any]
    updated_at: datetime
    error: Optional[str] = None


@dataclass
class DashboardWidget:
    """Configuration for a dashboard widget."""
    widget_id: str
    name: str
    widget_type: WidgetType
    position: Dict[str, int]  # x, y, width, height
    config: Dict[str, Any] = field(default_factory=dict)
    refresh_interval: RefreshInterval = RefreshInterval.NORMAL
    visible: bool = True
    data: Optional[WidgetData] = None


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    dashboard_id: str
    name: str
    description: str
    widgets: List[DashboardWidget]
    layout: str  # "grid" or "freeform"
    columns: int
    created_at: datetime
    updated_at: datetime
    owner: Optional[str] = None
    shared: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class DashboardManager:
    """
    Manages test dashboards.

    Features:
    - Configurable widgets
    - Real-time updates
    - Historical trends
    - Exportable views
    """

    def __init__(
        self,
        default_columns: int = 12,
        default_refresh: RefreshInterval = RefreshInterval.NORMAL,
    ):
        """Initialize the manager."""
        self._default_columns = default_columns
        self._default_refresh = default_refresh
        self._dashboards: Dict[str, DashboardConfig] = {}
        self._widget_data: Dict[str, WidgetData] = {}
        self._data_providers: Dict[WidgetType, Callable] = {}
        self._dashboard_counter = 0
        self._widget_counter = 0

        # Register default data providers
        self._register_default_providers()

    def _register_default_providers(self) -> None:
        """Register default widget data providers."""
        self._data_providers[WidgetType.PASS_RATE] = self._provide_pass_rate
        self._data_providers[WidgetType.FAILURE_TREND] = self._provide_failure_trend
        self._data_providers[WidgetType.COVERAGE_GAUGE] = self._provide_coverage
        self._data_providers[WidgetType.DURATION_CHART] = self._provide_duration
        self._data_providers[WidgetType.FLAKY_TESTS] = self._provide_flaky
        self._data_providers[WidgetType.TOP_FAILURES] = self._provide_top_failures
        self._data_providers[WidgetType.RECENT_RUNS] = self._provide_recent_runs
        self._data_providers[WidgetType.SUITE_HEALTH] = self._provide_suite_health

    def create_dashboard(
        self,
        name: str,
        description: str = "",
        layout: str = "grid",
        columns: Optional[int] = None,
        owner: Optional[str] = None,
    ) -> DashboardConfig:
        """Create a new dashboard."""
        self._dashboard_counter += 1
        dashboard_id = f"DASH-{self._dashboard_counter:05d}"

        now = datetime.now()
        dashboard = DashboardConfig(
            dashboard_id=dashboard_id,
            name=name,
            description=description,
            widgets=[],
            layout=layout,
            columns=columns or self._default_columns,
            created_at=now,
            updated_at=now,
            owner=owner,
        )

        self._dashboards[dashboard_id] = dashboard
        return dashboard

    def add_widget(
        self,
        dashboard_id: str,
        name: str,
        widget_type: WidgetType,
        x: int = 0,
        y: int = 0,
        width: int = 4,
        height: int = 3,
        config: Optional[Dict[str, Any]] = None,
        refresh_interval: Optional[RefreshInterval] = None,
    ) -> Optional[DashboardWidget]:
        """Add a widget to a dashboard."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return None

        self._widget_counter += 1
        widget_id = f"WGT-{self._widget_counter:05d}"

        widget = DashboardWidget(
            widget_id=widget_id,
            name=name,
            widget_type=widget_type,
            position={"x": x, "y": y, "width": width, "height": height},
            config=config or {},
            refresh_interval=refresh_interval or self._default_refresh,
        )

        dashboard.widgets.append(widget)
        dashboard.updated_at = datetime.now()

        # Initial data fetch
        self.refresh_widget(dashboard_id, widget_id)

        return widget

    def remove_widget(
        self,
        dashboard_id: str,
        widget_id: str,
    ) -> bool:
        """Remove a widget from a dashboard."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return False

        original_count = len(dashboard.widgets)
        dashboard.widgets = [
            w for w in dashboard.widgets
            if w.widget_id != widget_id
        ]

        if len(dashboard.widgets) < original_count:
            dashboard.updated_at = datetime.now()
            return True
        return False

    def update_widget_position(
        self,
        dashboard_id: str,
        widget_id: str,
        x: int,
        y: int,
        width: Optional[int] = None,
        height: Optional[int] = None,
    ) -> bool:
        """Update widget position."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return False

        for widget in dashboard.widgets:
            if widget.widget_id == widget_id:
                widget.position["x"] = x
                widget.position["y"] = y
                if width is not None:
                    widget.position["width"] = width
                if height is not None:
                    widget.position["height"] = height
                dashboard.updated_at = datetime.now()
                return True
        return False

    def refresh_widget(
        self,
        dashboard_id: str,
        widget_id: str,
    ) -> Optional[WidgetData]:
        """Refresh widget data."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return None

        widget = next(
            (w for w in dashboard.widgets if w.widget_id == widget_id),
            None
        )
        if not widget:
            return None

        # Get data provider
        provider = self._data_providers.get(widget.widget_type)
        if not provider:
            data = WidgetData(
                widget_id=widget_id,
                data={},
                updated_at=datetime.now(),
                error="No data provider for widget type",
            )
        else:
            try:
                raw_data = provider(widget.config)
                data = WidgetData(
                    widget_id=widget_id,
                    data=raw_data,
                    updated_at=datetime.now(),
                )
            except Exception as e:
                data = WidgetData(
                    widget_id=widget_id,
                    data={},
                    updated_at=datetime.now(),
                    error=str(e),
                )

        widget.data = data
        self._widget_data[widget_id] = data
        return data

    def refresh_dashboard(
        self,
        dashboard_id: str,
    ) -> List[WidgetData]:
        """Refresh all widgets in a dashboard."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return []

        results = []
        for widget in dashboard.widgets:
            if widget.visible:
                data = self.refresh_widget(dashboard_id, widget.widget_id)
                if data:
                    results.append(data)
        return results

    # Default data providers (simulated)
    def _provide_pass_rate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide pass rate data."""
        return {
            "current": 94.5,
            "previous": 92.3,
            "change": 2.2,
            "total_tests": 1250,
            "passed": 1181,
            "failed": 69,
            "trend": "up",
        }

    def _provide_failure_trend(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide failure trend data."""
        days = config.get("days", 7)
        return {
            "period": f"{days}d",
            "data": [
                {"date": "2024-01-01", "failures": 12},
                {"date": "2024-01-02", "failures": 8},
                {"date": "2024-01-03", "failures": 15},
                {"date": "2024-01-04", "failures": 10},
                {"date": "2024-01-05", "failures": 7},
                {"date": "2024-01-06", "failures": 5},
                {"date": "2024-01-07", "failures": 4},
            ],
            "trend": "improving",
        }

    def _provide_coverage(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide coverage data."""
        return {
            "overall": 78.5,
            "line": 82.3,
            "branch": 71.2,
            "function": 85.1,
            "target": 80.0,
            "delta": -1.5,
        }

    def _provide_duration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide duration data."""
        return {
            "average_sec": 45.2,
            "p50_sec": 32.1,
            "p90_sec": 85.4,
            "p99_sec": 142.8,
            "trend": "stable",
            "slowest_tests": [
                {"name": "test_full_checkout_flow", "duration": 142.8},
                {"name": "test_data_migration", "duration": 98.5},
                {"name": "test_performance_load", "duration": 87.2},
            ],
        }

    def _provide_flaky(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide flaky test data."""
        return {
            "count": 8,
            "tests": [
                {"name": "test_async_upload", "flake_rate": 15.2},
                {"name": "test_websocket_reconnect", "flake_rate": 12.8},
                {"name": "test_concurrent_writes", "flake_rate": 8.5},
            ],
            "trend": "stable",
        }

    def _provide_top_failures(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide top failures data."""
        limit = config.get("limit", 5)
        return {
            "failures": [
                {"name": "test_payment_validation", "count": 15, "last_fail": "2h ago"},
                {"name": "test_user_permissions", "count": 12, "last_fail": "4h ago"},
                {"name": "test_api_rate_limit", "count": 8, "last_fail": "1d ago"},
            ][:limit],
        }

    def _provide_recent_runs(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide recent runs data."""
        limit = config.get("limit", 10)
        return {
            "runs": [
                {"id": "RUN-001", "status": "passed", "duration": "12m", "tests": 1250},
                {"id": "RUN-002", "status": "failed", "duration": "15m", "tests": 1250},
                {"id": "RUN-003", "status": "passed", "duration": "11m", "tests": 1248},
            ][:limit],
        }

    def _provide_suite_health(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Provide suite health data."""
        return {
            "suites": [
                {"name": "Unit Tests", "health": 98, "tests": 850},
                {"name": "Integration Tests", "health": 92, "tests": 280},
                {"name": "E2E Tests", "health": 85, "tests": 120},
            ],
            "overall_health": 93,
        }

    def register_data_provider(
        self,
        widget_type: WidgetType,
        provider: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        """Register a custom data provider."""
        self._data_providers[widget_type] = provider

    def get_dashboard(self, dashboard_id: str) -> Optional[DashboardConfig]:
        """Get a dashboard by ID."""
        return self._dashboards.get(dashboard_id)

    def list_dashboards(self) -> List[DashboardConfig]:
        """List all dashboards."""
        return list(self._dashboards.values())

    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete a dashboard."""
        if dashboard_id in self._dashboards:
            del self._dashboards[dashboard_id]
            return True
        return False

    def clone_dashboard(
        self,
        dashboard_id: str,
        new_name: str,
    ) -> Optional[DashboardConfig]:
        """Clone an existing dashboard."""
        source = self._dashboards.get(dashboard_id)
        if not source:
            return None

        new_dashboard = self.create_dashboard(
            name=new_name,
            description=f"Clone of {source.name}",
            layout=source.layout,
            columns=source.columns,
        )

        # Clone widgets
        for widget in source.widgets:
            self.add_widget(
                dashboard_id=new_dashboard.dashboard_id,
                name=widget.name,
                widget_type=widget.widget_type,
                x=widget.position["x"],
                y=widget.position["y"],
                width=widget.position["width"],
                height=widget.position["height"],
                config=widget.config.copy(),
                refresh_interval=widget.refresh_interval,
            )

        return new_dashboard

    def export_dashboard(
        self,
        dashboard_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Export dashboard configuration."""
        dashboard = self._dashboards.get(dashboard_id)
        if not dashboard:
            return None

        return {
            "name": dashboard.name,
            "description": dashboard.description,
            "layout": dashboard.layout,
            "columns": dashboard.columns,
            "widgets": [
                {
                    "name": w.name,
                    "type": w.widget_type.value,
                    "position": w.position,
                    "config": w.config,
                    "refresh_interval": w.refresh_interval.value,
                }
                for w in dashboard.widgets
            ],
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        widget_counts: Dict[str, int] = {}
        for dashboard in self._dashboards.values():
            for widget in dashboard.widgets:
                type_name = widget.widget_type.value
                widget_counts[type_name] = widget_counts.get(type_name, 0) + 1

        return {
            "total_dashboards": len(self._dashboards),
            "total_widgets": sum(len(d.widgets) for d in self._dashboards.values()),
            "widgets_by_type": widget_counts,
            "data_providers": len(self._data_providers),
        }

    def format_dashboard(self, dashboard: DashboardConfig) -> str:
        """Format a dashboard for display."""
        lines = [
            "=" * 55,
            f"  DASHBOARD: {dashboard.name}",
            "=" * 55,
            "",
            f"  ID: {dashboard.dashboard_id}",
            f"  Layout: {dashboard.layout} ({dashboard.columns} columns)",
            f"  Widgets: {len(dashboard.widgets)}",
            "",
            "-" * 55,
            "  WIDGETS",
            "-" * 55,
            "",
        ]

        for widget in dashboard.widgets:
            pos = widget.position
            lines.append(
                f"  • {widget.name} ({widget.widget_type.value})"
            )
            lines.append(
                f"    Position: ({pos['x']}, {pos['y']}) "
                f"Size: {pos['width']}x{pos['height']}"
            )

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_dashboard_manager(
    default_columns: int = 12,
    default_refresh: RefreshInterval = RefreshInterval.NORMAL,
) -> DashboardManager:
    """Create a dashboard manager instance."""
    return DashboardManager(
        default_columns=default_columns,
        default_refresh=default_refresh,
    )
