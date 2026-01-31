"""
TestAI Agent - Visual Report Generator

Generates beautiful, stakeholder-friendly HTML reports
with charts, summaries, and actionable insights.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json


class ReportTheme(Enum):
    """Report color themes."""
    LIGHT = "light"
    DARK = "dark"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class ChartType(Enum):
    """Types of charts available."""
    PIE = "pie"
    BAR = "bar"
    LINE = "line"
    DONUT = "donut"
    STACKED_BAR = "stacked_bar"


@dataclass
class ChartData:
    """Data for a chart."""
    chart_type: ChartType
    title: str
    labels: List[str]
    values: List[float]
    colors: List[str] = field(default_factory=list)


@dataclass
class ReportSection:
    """A section of the report."""
    title: str
    content: str
    chart: Optional[ChartData] = None
    table_data: Optional[Dict[str, List[Any]]] = None
    priority: int = 0


@dataclass
class VisualReport:
    """A complete visual report."""
    title: str
    subtitle: str
    generated_at: datetime
    theme: ReportTheme
    sections: List[ReportSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    html_content: str = ""


class VisualReportGenerator:
    """
    Generates beautiful HTML reports from test data.
    """

    # Color palettes by theme
    COLORS = {
        ReportTheme.LIGHT: {
            "primary": "#3498db",
            "success": "#27ae60",
            "warning": "#f39c12",
            "danger": "#e74c3c",
            "info": "#9b59b6",
            "background": "#ffffff",
            "text": "#2c3e50",
            "border": "#ecf0f1",
        },
        ReportTheme.DARK: {
            "primary": "#3498db",
            "success": "#2ecc71",
            "warning": "#f1c40f",
            "danger": "#e74c3c",
            "info": "#9b59b6",
            "background": "#1a1a2e",
            "text": "#eaeaea",
            "border": "#16213e",
        },
        ReportTheme.EXECUTIVE: {
            "primary": "#2c3e50",
            "success": "#1abc9c",
            "warning": "#e67e22",
            "danger": "#c0392b",
            "info": "#3498db",
            "background": "#fafafa",
            "text": "#2c3e50",
            "border": "#bdc3c7",
        },
        ReportTheme.TECHNICAL: {
            "primary": "#00b894",
            "success": "#00cec9",
            "warning": "#fdcb6e",
            "danger": "#d63031",
            "info": "#6c5ce7",
            "background": "#ffffff",
            "text": "#2d3436",
            "border": "#dfe6e9",
        },
    }

    def __init__(self, theme: ReportTheme = ReportTheme.EXECUTIVE):
        """Initialize the generator."""
        self.theme = theme
        self.colors = self.COLORS[theme]

    def generate_test_plan_report(
        self,
        tests: List[Dict[str, Any]],
        feature: str,
        page_type: str = "generic",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VisualReport:
        """Generate a visual report for a test plan."""
        sections = []

        # Executive Summary
        sections.append(self._create_executive_summary(tests, feature))

        # Coverage Overview (with pie chart)
        sections.append(self._create_coverage_section(tests))

        # Priority Distribution (with bar chart)
        sections.append(self._create_priority_section(tests))

        # Test Cases Table
        sections.append(self._create_test_table_section(tests))

        # Risk Assessment
        sections.append(self._create_risk_section(tests, page_type))

        # Generate HTML
        report = VisualReport(
            title=f"Test Plan: {feature}",
            subtitle=f"Comprehensive test coverage for {page_type} functionality",
            generated_at=datetime.now(),
            theme=self.theme,
            sections=sections,
            metadata=metadata or {},
        )

        report.html_content = self._render_html(report)
        return report

    def generate_execution_report(
        self,
        results: List[Dict[str, Any]],
        suite_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VisualReport:
        """Generate a visual report for test execution results."""
        sections = []

        # Results Summary
        sections.append(self._create_results_summary(results, suite_name))

        # Pass/Fail Chart
        sections.append(self._create_pass_fail_chart(results))

        # Failures Detail
        failures = [r for r in results if r.get("status") != "passed"]
        if failures:
            sections.append(self._create_failures_section(failures))

        # Timing Analysis
        sections.append(self._create_timing_section(results))

        report = VisualReport(
            title=f"Execution Report: {suite_name}",
            subtitle=f"Test run completed at {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            generated_at=datetime.now(),
            theme=self.theme,
            sections=sections,
            metadata=metadata or {},
        )

        report.html_content = self._render_html(report)
        return report

    def _create_executive_summary(
        self,
        tests: List[Dict[str, Any]],
        feature: str,
    ) -> ReportSection:
        """Create executive summary section."""
        total = len(tests)
        critical = sum(1 for t in tests if t.get("priority") == "critical")
        high = sum(1 for t in tests if t.get("priority") == "high")
        security = sum(1 for t in tests if t.get("category") == "security")

        # Determine ship readiness
        if security >= 3 and critical >= 2:
            readiness = "✅ Ready for Testing"
            readiness_color = self.colors["success"]
        elif security >= 1 or critical >= 1:
            readiness = "⚠️ Partial Coverage"
            readiness_color = self.colors["warning"]
        else:
            readiness = "❌ Needs More Tests"
            readiness_color = self.colors["danger"]

        content = f"""
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{total}</div>
                <div class="summary-label">Total Tests</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-value">{critical}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-value">{high}</div>
                <div class="summary-label">High Priority</div>
            </div>
            <div class="summary-card security">
                <div class="summary-value">{security}</div>
                <div class="summary-label">Security Tests</div>
            </div>
        </div>
        <div class="readiness-badge" style="background: {readiness_color}">
            {readiness}
        </div>
        <p class="summary-text">
            This test plan covers the <strong>{feature}</strong> functionality with {total} test cases
            designed to ensure comprehensive coverage across functional, security, and edge-case scenarios.
        </p>
        """

        return ReportSection(
            title="Executive Summary",
            content=content,
            priority=1,
        )

    def _create_coverage_section(
        self,
        tests: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create coverage overview section."""
        # Count by category
        categories: Dict[str, int] = {}
        for test in tests:
            cat = test.get("category", "other")
            categories[cat] = categories.get(cat, 0) + 1

        labels = list(categories.keys())
        values = [float(categories[l]) for l in labels]
        colors = [
            self.colors["primary"],
            self.colors["success"],
            self.colors["warning"],
            self.colors["danger"],
            self.colors["info"],
        ][:len(labels)]

        chart = ChartData(
            chart_type=ChartType.DONUT,
            title="Test Coverage by Category",
            labels=labels,
            values=values,
            colors=colors,
        )

        content = "<p>Distribution of test cases across different testing categories.</p>"

        return ReportSection(
            title="Coverage Overview",
            content=content,
            chart=chart,
            priority=2,
        )

    def _create_priority_section(
        self,
        tests: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create priority distribution section."""
        priorities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for test in tests:
            p = test.get("priority", "medium")
            priorities[p] = priorities.get(p, 0) + 1

        labels = list(priorities.keys())
        values = [float(priorities[l]) for l in labels]
        colors = [
            self.colors["danger"],
            self.colors["warning"],
            self.colors["primary"],
            self.colors["success"],
        ]

        chart = ChartData(
            chart_type=ChartType.BAR,
            title="Tests by Priority",
            labels=labels,
            values=values,
            colors=colors,
        )

        content = "<p>Priority distribution helps focus testing efforts on critical paths first.</p>"

        return ReportSection(
            title="Priority Distribution",
            content=content,
            chart=chart,
            priority=3,
        )

    def _create_test_table_section(
        self,
        tests: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create test cases table section."""
        table_data = {
            "ID": [t.get("id", "N/A") for t in tests],
            "Title": [t.get("title", "Untitled")[:50] for t in tests],
            "Category": [t.get("category", "other") for t in tests],
            "Priority": [t.get("priority", "medium") for t in tests],
        }

        content = "<p>Complete list of test cases in this plan.</p>"

        return ReportSection(
            title="Test Cases",
            content=content,
            table_data=table_data,
            priority=4,
        )

    def _create_risk_section(
        self,
        tests: List[Dict[str, Any]],
        page_type: str,
    ) -> ReportSection:
        """Create risk assessment section."""
        # Calculate risk factors
        security_tests = sum(1 for t in tests if t.get("category") == "security")
        critical_tests = sum(1 for t in tests if t.get("priority") == "critical")
        total = len(tests)

        security_coverage = security_tests / max(total, 1)
        critical_coverage = critical_tests / max(total, 1)

        # Determine risk level
        if security_coverage >= 0.2 and critical_coverage >= 0.1:
            risk_level = "Low"
            risk_color = self.colors["success"]
        elif security_coverage >= 0.1 or critical_coverage >= 0.05:
            risk_level = "Medium"
            risk_color = self.colors["warning"]
        else:
            risk_level = "High"
            risk_color = self.colors["danger"]

        content = f"""
        <div class="risk-assessment">
            <div class="risk-indicator" style="border-color: {risk_color}">
                <span class="risk-level" style="color: {risk_color}">{risk_level} Risk</span>
            </div>
            <div class="risk-factors">
                <h4>Risk Factors</h4>
                <ul>
                    <li>Security test coverage: <strong>{security_coverage:.0%}</strong></li>
                    <li>Critical path coverage: <strong>{critical_coverage:.0%}</strong></li>
                    <li>Page type: <strong>{page_type}</strong></li>
                </ul>
            </div>
            <div class="risk-recommendations">
                <h4>Recommendations</h4>
                <ul>
                    {'<li>Add more security tests for better vulnerability coverage</li>' if security_coverage < 0.2 else ''}
                    {'<li>Increase critical priority test coverage</li>' if critical_coverage < 0.1 else ''}
                    {'<li>Consider adding edge case tests</li>' if total < 10 else ''}
                    <li>Current coverage appears {"adequate" if risk_level == "Low" else "needs improvement"}</li>
                </ul>
            </div>
        </div>
        """

        return ReportSection(
            title="Risk Assessment",
            content=content,
            priority=5,
        )

    def _create_results_summary(
        self,
        results: List[Dict[str, Any]],
        suite_name: str,
    ) -> ReportSection:
        """Create results summary for execution report."""
        total = len(results)
        passed = sum(1 for r in results if r.get("status") == "passed")
        failed = sum(1 for r in results if r.get("status") == "failed")
        skipped = sum(1 for r in results if r.get("status") == "skipped")

        pass_rate = passed / max(total, 1)

        if pass_rate >= 0.9:
            status = "✅ Passed"
            status_color = self.colors["success"]
        elif pass_rate >= 0.7:
            status = "⚠️ Partial"
            status_color = self.colors["warning"]
        else:
            status = "❌ Failed"
            status_color = self.colors["danger"]

        content = f"""
        <div class="results-header" style="border-left: 4px solid {status_color}">
            <span class="results-status">{status}</span>
            <span class="pass-rate">{pass_rate:.0%} Pass Rate</span>
        </div>
        <div class="results-grid">
            <div class="result-card passed">
                <div class="result-value">{passed}</div>
                <div class="result-label">Passed</div>
            </div>
            <div class="result-card failed">
                <div class="result-value">{failed}</div>
                <div class="result-label">Failed</div>
            </div>
            <div class="result-card skipped">
                <div class="result-value">{skipped}</div>
                <div class="result-label">Skipped</div>
            </div>
        </div>
        """

        return ReportSection(
            title="Results Summary",
            content=content,
            priority=1,
        )

    def _create_pass_fail_chart(
        self,
        results: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create pass/fail chart."""
        passed = sum(1 for r in results if r.get("status") == "passed")
        failed = sum(1 for r in results if r.get("status") == "failed")
        skipped = sum(1 for r in results if r.get("status") == "skipped")
        other = len(results) - passed - failed - skipped

        chart = ChartData(
            chart_type=ChartType.DONUT,
            title="Test Results",
            labels=["Passed", "Failed", "Skipped", "Other"],
            values=[float(passed), float(failed), float(skipped), float(other)],
            colors=[self.colors["success"], self.colors["danger"], self.colors["warning"], self.colors["info"]],
        )

        return ReportSection(
            title="Results Distribution",
            content="",
            chart=chart,
            priority=2,
        )

    def _create_failures_section(
        self,
        failures: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create failures detail section."""
        content = "<div class='failures-list'>"
        for f in failures[:10]:  # Limit to 10
            content += f"""
            <div class="failure-item">
                <div class="failure-title">{f.get('title', 'Unknown Test')}</div>
                <div class="failure-error">{f.get('error_message', 'No error message')[:100]}</div>
            </div>
            """
        if len(failures) > 10:
            content += f"<p class='more-failures'>... and {len(failures) - 10} more failures</p>"
        content += "</div>"

        return ReportSection(
            title=f"Failures ({len(failures)})",
            content=content,
            priority=3,
        )

    def _create_timing_section(
        self,
        results: List[Dict[str, Any]],
    ) -> ReportSection:
        """Create timing analysis section."""
        durations = [r.get("duration_ms", 0) for r in results if r.get("duration_ms")]

        if not durations:
            content = "<p>No timing data available.</p>"
        else:
            avg_duration = sum(durations) / len(durations)
            max_duration = max(durations)
            min_duration = min(durations)
            total_duration = sum(durations)

            content = f"""
            <div class="timing-grid">
                <div class="timing-card">
                    <div class="timing-value">{total_duration/1000:.1f}s</div>
                    <div class="timing-label">Total</div>
                </div>
                <div class="timing-card">
                    <div class="timing-value">{avg_duration:.0f}ms</div>
                    <div class="timing-label">Average</div>
                </div>
                <div class="timing-card">
                    <div class="timing-value">{min_duration}ms</div>
                    <div class="timing-label">Fastest</div>
                </div>
                <div class="timing-card">
                    <div class="timing-value">{max_duration}ms</div>
                    <div class="timing-label">Slowest</div>
                </div>
            </div>
            """

        return ReportSection(
            title="Timing Analysis",
            content=content,
            priority=4,
        )

    def _render_html(self, report: VisualReport) -> str:
        """Render the report as HTML."""
        colors = self.colors

        # CSS styles
        styles = f"""
        :root {{
            --primary: {colors['primary']};
            --success: {colors['success']};
            --warning: {colors['warning']};
            --danger: {colors['danger']};
            --info: {colors['info']};
            --background: {colors['background']};
            --text: {colors['text']};
            --border: {colors['border']};
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--background);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            padding: 40px 20px;
            border-bottom: 3px solid var(--primary);
            margin-bottom: 40px;
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: var(--primary);
        }}

        .subtitle {{
            font-size: 1.1rem;
            color: #666;
        }}

        .meta {{
            font-size: 0.9rem;
            color: #888;
            margin-top: 10px;
        }}

        section {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border);
            color: var(--primary);
        }}

        .summary-grid, .results-grid, .timing-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .summary-card, .result-card, .timing-card {{
            background: var(--background);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .summary-value, .result-value, .timing-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary);
        }}

        .summary-label, .result-label, .timing-label {{
            font-size: 0.9rem;
            color: #666;
            margin-top: 5px;
        }}

        .summary-card.critical .summary-value {{ color: var(--danger); }}
        .summary-card.high .summary-value {{ color: var(--warning); }}
        .summary-card.security .summary-value {{ color: var(--info); }}

        .result-card.passed .result-value {{ color: var(--success); }}
        .result-card.failed .result-value {{ color: var(--danger); }}
        .result-card.skipped .result-value {{ color: var(--warning); }}

        .readiness-badge {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            margin: 20px 0;
        }}

        .summary-text {{
            color: #555;
            margin-top: 20px;
        }}

        .chart-container {{
            width: 100%;
            max-width: 400px;
            margin: 20px auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}

        th {{
            background: var(--primary);
            color: white;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .risk-assessment {{
            display: grid;
            grid-template-columns: auto 1fr 1fr;
            gap: 30px;
            align-items: start;
        }}

        .risk-indicator {{
            padding: 30px;
            border: 4px solid;
            border-radius: 50%;
            text-align: center;
        }}

        .risk-level {{
            font-size: 1.2rem;
            font-weight: bold;
        }}

        .risk-factors ul, .risk-recommendations ul {{
            list-style: none;
            padding: 0;
        }}

        .risk-factors li, .risk-recommendations li {{
            padding: 5px 0;
        }}

        .failures-list {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}

        .failure-item {{
            background: #fff5f5;
            border-left: 4px solid var(--danger);
            padding: 15px;
            border-radius: 4px;
        }}

        .failure-title {{
            font-weight: bold;
            color: var(--danger);
        }}

        .failure-error {{
            font-size: 0.9rem;
            color: #666;
            margin-top: 5px;
        }}

        .results-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }}

        .results-status {{
            font-size: 1.5rem;
            font-weight: bold;
        }}

        .pass-rate {{
            font-size: 1.2rem;
            color: #666;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .risk-assessment {{
                grid-template-columns: 1fr;
            }}
        }}
        """

        # Build sections HTML
        sections_html = ""
        for section in sorted(report.sections, key=lambda s: s.priority):
            section_html = f"""
            <section>
                <h2>{section.title}</h2>
                {section.content}
            """

            # Add chart if present
            if section.chart:
                section_html += self._render_chart(section.chart)

            # Add table if present
            if section.table_data:
                section_html += self._render_table(section.table_data)

            section_html += "</section>"
            sections_html += section_html

        # Complete HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>{styles}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>{report.title}</h1>
            <p class="subtitle">{report.subtitle}</p>
            <p class="meta">Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        {sections_html}

        <footer>
            <p>Generated by TestAI Agent | {datetime.now().year}</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _render_chart(self, chart: ChartData) -> str:
        """Render a chart as HTML/JS."""
        chart_id = f"chart_{id(chart)}"

        # Prepare data for Chart.js
        chart_config = {
            "type": "doughnut" if chart.chart_type == ChartType.DONUT else chart.chart_type.value,
            "data": {
                "labels": chart.labels,
                "datasets": [{
                    "data": chart.values,
                    "backgroundColor": chart.colors if chart.colors else [
                        "#3498db", "#27ae60", "#f39c12", "#e74c3c", "#9b59b6"
                    ][:len(chart.values)],
                }]
            },
            "options": {
                "responsive": True,
                "plugins": {
                    "legend": {"position": "bottom"},
                    "title": {"display": True, "text": chart.title}
                }
            }
        }

        return f"""
        <div class="chart-container">
            <canvas id="{chart_id}"></canvas>
        </div>
        <script>
            new Chart(document.getElementById('{chart_id}'), {json.dumps(chart_config)});
        </script>
        """

    def _render_table(self, table_data: Dict[str, List[Any]]) -> str:
        """Render a table as HTML."""
        if not table_data:
            return ""

        headers = list(table_data.keys())
        num_rows = len(list(table_data.values())[0]) if table_data else 0

        html = "<table><thead><tr>"
        for header in headers:
            html += f"<th>{header}</th>"
        html += "</tr></thead><tbody>"

        for i in range(num_rows):
            html += "<tr>"
            for header in headers:
                value = table_data[header][i] if i < len(table_data[header]) else ""
                html += f"<td>{value}</td>"
            html += "</tr>"

        html += "</tbody></table>"
        return html


def create_visual_reporter(
    theme: ReportTheme = ReportTheme.EXECUTIVE,
) -> VisualReportGenerator:
    """Create a visual report generator instance."""
    return VisualReportGenerator(theme)
