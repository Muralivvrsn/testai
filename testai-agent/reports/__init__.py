"""
TestAI Agent - Reports Module

Visual report generation for test plans and execution results.
Produces stakeholder-friendly HTML reports with charts and summaries.
"""

from .visual_report import (
    VisualReportGenerator,
    ReportTheme,
    ChartType,
    VisualReport,
    create_visual_reporter,
)

from .export import (
    ReportExporter,
    ExportFormat,
    export_report,
)

__all__ = [
    # Visual Report Generator
    "VisualReportGenerator",
    "ReportTheme",
    "ChartType",
    "VisualReport",
    "create_visual_reporter",
    # Export
    "ReportExporter",
    "ExportFormat",
    "export_report",
]
