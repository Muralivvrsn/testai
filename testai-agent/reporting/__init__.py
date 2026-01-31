"""
TestAI Agent - Test Reporting and Analytics

Comprehensive reporting and analytics for test results
including dashboards, trend analysis, and executive summaries.
"""

from .dashboard import (
    DashboardManager,
    DashboardWidget,
    WidgetType,
    DashboardConfig,
    create_dashboard_manager,
)

from .analytics import (
    TestAnalytics,
    AnalyticsMetric,
    TrendDirection,
    AnalyticsReport,
    MetricType,
    create_analytics,
)

from .reports import (
    ReportGenerator,
    ReportFormat,
    ReportSection,
    ReportType,
    TestReport,
    create_report_generator,
)

__all__ = [
    # Dashboard
    "DashboardManager",
    "DashboardWidget",
    "WidgetType",
    "DashboardConfig",
    "create_dashboard_manager",
    # Analytics
    "TestAnalytics",
    "AnalyticsMetric",
    "TrendDirection",
    "AnalyticsReport",
    "MetricType",
    "create_analytics",
    # Reports
    "ReportGenerator",
    "ReportFormat",
    "ReportSection",
    "ReportType",
    "TestReport",
    "create_report_generator",
]
