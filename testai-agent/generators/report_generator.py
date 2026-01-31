"""
TestAI Agent - Professional Test Report Generator

Generates beautiful, stakeholder-ready test reports.
European design: clean, minimal, scannable, professional.

Output Formats:
- Markdown (.md) - For documentation, GitHub, Confluence
- HTML (.html) - For email, presentations, web viewing
- JSON (.json) - For integration with test management tools
- Text (.txt) - For terminal output, quick sharing

Key Features:
- Executive summary at top (for managers)
- Priority-based organization (critical first)
- Visual indicators (icons, colors)
- Risk assessment section
- Test coverage metrics
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import json
from pathlib import Path


class ReportFormat(Enum):
    """Supported report formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class ReportMetadata:
    """Metadata for the report."""
    title: str
    feature: str
    page_type: Optional[str] = None
    generated_at: datetime = field(default_factory=datetime.now)
    generated_by: str = "TestAI Agent"
    version: str = "1.0"


@dataclass
class TestReport:
    """
    Complete test report with all sections.
    """
    metadata: ReportMetadata
    tests: List[Dict[str, Any]]

    # Computed on initialization
    summary: Dict[str, Any] = field(default_factory=dict)
    by_priority: Dict[str, List[Dict]] = field(default_factory=dict)
    by_category: Dict[str, List[Dict]] = field(default_factory=dict)

    def __post_init__(self):
        """Compute summary statistics."""
        self._compute_statistics()

    def _compute_statistics(self):
        """Calculate all statistics for the report."""
        # Initialize
        self.by_priority = {"critical": [], "high": [], "medium": [], "low": []}
        self.by_category = {}

        for test in self.tests:
            # By priority
            pri = test.get("priority", "medium").lower()
            if pri in self.by_priority:
                self.by_priority[pri].append(test)
            else:
                self.by_priority["medium"].append(test)

            # By category
            cat = test.get("category", "general").lower()
            if cat not in self.by_category:
                self.by_category[cat] = []
            self.by_category[cat].append(test)

        # Summary
        self.summary = {
            "total_tests": len(self.tests),
            "critical_count": len(self.by_priority["critical"]),
            "high_count": len(self.by_priority["high"]),
            "medium_count": len(self.by_priority["medium"]),
            "low_count": len(self.by_priority["low"]),
            "categories": list(self.by_category.keys()),
            "category_counts": {k: len(v) for k, v in self.by_category.items()},
        }


class ReportGenerator:
    """
    Generates professional test reports in multiple formats.

    Usage:
        generator = ReportGenerator()

        # Create report
        report = generator.create_report(
            tests=my_tests,
            feature="User Login",
            page_type="login"
        )

        # Export in different formats
        markdown = generator.to_markdown(report)
        html = generator.to_html(report)
        generator.save(report, "login_tests.md", ReportFormat.MARKDOWN)
    """

    # Priority icons and colors
    PRIORITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }

    CATEGORY_ICONS = {
        "happy_path": "✅",
        "edge_case": "🔄",
        "negative": "❌",
        "security": "🔒",
        "accessibility": "♿",
        "boundary": "📏",
        "error_handling": "⚠️",
        "general": "📋",
    }

    HTML_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
    }

    def create_report(
        self,
        tests: List[Dict[str, Any]],
        feature: str,
        page_type: Optional[str] = None,
        title: Optional[str] = None,
    ) -> TestReport:
        """
        Create a test report from test cases.

        Args:
            tests: List of test case dictionaries
            feature: Feature being tested
            page_type: Type of page (login, signup, etc.)
            title: Custom report title

        Returns:
            TestReport object
        """
        metadata = ReportMetadata(
            title=title or f"Test Report: {feature}",
            feature=feature,
            page_type=page_type,
        )

        return TestReport(
            metadata=metadata,
            tests=tests,
        )

    def to_markdown(self, report: TestReport) -> str:
        """
        Generate Markdown format report.

        Args:
            report: TestReport to format

        Returns:
            Markdown string
        """
        lines = []
        m = report.metadata
        s = report.summary

        # Header
        lines.append(f"# {m.title}")
        lines.append("")
        lines.append(f"**Feature:** {m.feature}")
        if m.page_type:
            lines.append(f"**Page Type:** {m.page_type.title()}")
        lines.append(f"**Generated:** {m.generated_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"**Generator:** {m.generated_by}")
        lines.append("")

        # Executive Summary
        lines.append("---")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"This report contains **{s['total_tests']} test cases** for the {m.feature} feature.")
        lines.append("")
        lines.append("### Priority Breakdown")
        lines.append("")
        lines.append(f"| Priority | Count | Percentage |")
        lines.append(f"|----------|-------|------------|")
        for pri in ["critical", "high", "medium", "low"]:
            count = s[f"{pri}_count"]
            pct = (count / s['total_tests'] * 100) if s['total_tests'] > 0 else 0
            icon = self.PRIORITY_ICONS[pri]
            lines.append(f"| {icon} {pri.title()} | {count} | {pct:.0f}% |")
        lines.append("")

        # Category Breakdown
        lines.append("### Test Categories")
        lines.append("")
        for cat, count in s['category_counts'].items():
            icon = self.CATEGORY_ICONS.get(cat, "📋")
            lines.append(f"- {icon} **{cat.replace('_', ' ').title()}**: {count} tests")
        lines.append("")

        # Risk Assessment
        if s['critical_count'] > 0:
            lines.append("### ⚠️ Risk Assessment")
            lines.append("")
            lines.append(f"**{s['critical_count']} critical** test cases identified. ")
            lines.append("These tests cover scenarios that could cause:")
            lines.append("- Data loss or corruption")
            lines.append("- Security vulnerabilities")
            lines.append("- Complete feature failure")
            lines.append("")
            lines.append("**Recommendation:** Execute critical tests first and ensure 100% pass rate before release.")
            lines.append("")

        # Test Cases by Priority
        lines.append("---")
        lines.append("## Test Cases")
        lines.append("")

        for priority in ["critical", "high", "medium", "low"]:
            tests_in_priority = report.by_priority[priority]
            if not tests_in_priority:
                continue

            icon = self.PRIORITY_ICONS[priority]
            lines.append(f"### {icon} {priority.title()} Priority ({len(tests_in_priority)})")
            lines.append("")

            for test in tests_in_priority:
                lines.extend(self._format_test_markdown(test))
                lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated by {m.generated_by} v{m.version}*")

        return "\n".join(lines)

    def _format_test_markdown(self, test: Dict[str, Any]) -> List[str]:
        """Format a single test case for Markdown."""
        lines = []

        test_id = test.get("id", "TC-XXX")
        title = test.get("title", "Untitled Test")
        description = test.get("description", "")
        category = test.get("category", "general")
        preconditions = test.get("preconditions", [])
        steps = test.get("steps", [])
        expected = test.get("expected_result", "")
        test_data = test.get("test_data", {})

        cat_icon = self.CATEGORY_ICONS.get(category, "📋")

        lines.append(f"#### {test_id}: {title}")
        lines.append("")
        lines.append(f"*{cat_icon} {category.replace('_', ' ').title()}*")
        lines.append("")

        if description:
            lines.append(f"> {description}")
            lines.append("")

        if preconditions:
            lines.append("**Preconditions:**")
            for pre in preconditions:
                lines.append(f"- {pre}")
            lines.append("")

        if steps:
            lines.append("**Steps:**")
            for i, step in enumerate(steps, 1):
                # Handle steps that already have numbers
                if step.strip().startswith(f"{i}.") or step.strip().startswith(f"{i})"):
                    lines.append(f"{step}")
                else:
                    lines.append(f"{i}. {step}")
            lines.append("")

        if expected:
            lines.append(f"**Expected Result:** {expected}")
            lines.append("")

        if test_data:
            lines.append("**Test Data:**")
            lines.append("```json")
            lines.append(json.dumps(test_data, indent=2))
            lines.append("```")

        return lines

    def to_html(self, report: TestReport) -> str:
        """
        Generate HTML format report.

        Args:
            report: TestReport to format

        Returns:
            HTML string
        """
        m = report.metadata
        s = report.summary

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{m.title}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-600: #4b5563;
            --gray-800: #1f2937;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            background: var(--gray-50);
        }}

        h1 {{ color: var(--gray-800); border-bottom: 2px solid var(--gray-200); padding-bottom: 0.5rem; }}
        h2 {{ color: var(--gray-600); margin-top: 2rem; }}
        h3 {{ color: var(--gray-600); }}

        .metadata {{ color: var(--gray-600); font-size: 0.9rem; margin-bottom: 2rem; }}
        .metadata span {{ margin-right: 1.5rem; }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}

        .stat-card {{
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}

        .stat-card .number {{ font-size: 2rem; font-weight: bold; }}
        .stat-card .label {{ color: var(--gray-600); font-size: 0.85rem; text-transform: uppercase; }}

        .stat-critical .number {{ color: var(--critical); }}
        .stat-high .number {{ color: var(--high); }}
        .stat-medium .number {{ color: var(--medium); }}
        .stat-low .number {{ color: var(--low); }}

        .test-case {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 1rem 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid var(--gray-200);
        }}

        .test-case.critical {{ border-left-color: var(--critical); }}
        .test-case.high {{ border-left-color: var(--high); }}
        .test-case.medium {{ border-left-color: var(--medium); }}
        .test-case.low {{ border-left-color: var(--low); }}

        .test-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem; }}
        .test-title {{ font-weight: 600; font-size: 1.1rem; }}
        .test-id {{ color: var(--gray-600); font-size: 0.85rem; }}
        .test-meta {{ color: var(--gray-600); font-size: 0.85rem; margin-bottom: 1rem; }}

        .test-description {{ color: var(--gray-600); margin-bottom: 1rem; font-style: italic; }}

        .test-section {{ margin: 1rem 0; }}
        .test-section h4 {{ font-size: 0.85rem; text-transform: uppercase; color: var(--gray-600); margin-bottom: 0.5rem; }}

        .test-section ol, .test-section ul {{ margin: 0; padding-left: 1.5rem; }}
        .test-section li {{ margin: 0.25rem 0; }}

        .expected {{ background: var(--gray-100); padding: 0.75rem; border-radius: 4px; }}

        .test-data {{ background: var(--gray-800); color: #e5e7eb; padding: 1rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; overflow-x: auto; }}

        .priority-section {{ margin: 2rem 0; }}
        .priority-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }}
        .priority-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
        .priority-dot.critical {{ background: var(--critical); }}
        .priority-dot.high {{ background: var(--high); }}
        .priority-dot.medium {{ background: var(--medium); }}
        .priority-dot.low {{ background: var(--low); }}

        .risk-alert {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 8px;
            padding: 1rem;
            margin: 1.5rem 0;
        }}
        .risk-alert h3 {{ color: var(--critical); margin-top: 0; }}

        footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--gray-200); color: var(--gray-600); font-size: 0.85rem; }}
    </style>
</head>
<body>
    <h1>{m.title}</h1>

    <div class="metadata">
        <span><strong>Feature:</strong> {m.feature}</span>
        {"<span><strong>Page Type:</strong> " + m.page_type.title() + "</span>" if m.page_type else ""}
        <span><strong>Generated:</strong> {m.generated_at.strftime('%Y-%m-%d %H:%M')}</span>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="stat-card">
            <div class="number">{s['total_tests']}</div>
            <div class="label">Total Tests</div>
        </div>
        <div class="stat-card stat-critical">
            <div class="number">{s['critical_count']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card stat-high">
            <div class="number">{s['high_count']}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card stat-medium">
            <div class="number">{s['medium_count']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card stat-low">
            <div class="number">{s['low_count']}</div>
            <div class="label">Low</div>
        </div>
    </div>
"""

        # Risk Alert
        if s['critical_count'] > 0:
            html += f"""
    <div class="risk-alert">
        <h3>⚠️ Risk Assessment</h3>
        <p><strong>{s['critical_count']} critical</strong> test cases identified. These cover scenarios that could cause data loss, security vulnerabilities, or complete feature failure.</p>
        <p><strong>Recommendation:</strong> Execute critical tests first and ensure 100% pass rate before release.</p>
    </div>
"""

        html += """
    <h2>Test Cases</h2>
"""

        # Tests by priority
        for priority in ["critical", "high", "medium", "low"]:
            tests_in_priority = report.by_priority[priority]
            if not tests_in_priority:
                continue

            html += f"""
    <div class="priority-section">
        <div class="priority-header">
            <span class="priority-dot {priority}"></span>
            <h3>{priority.title()} Priority ({len(tests_in_priority)})</h3>
        </div>
"""

            for test in tests_in_priority:
                html += self._format_test_html(test, priority)

            html += """
    </div>
"""

        # Footer
        html += f"""
    <footer>
        Report generated by {m.generated_by} v{m.version}
    </footer>
</body>
</html>
"""

        return html

    def _format_test_html(self, test: Dict[str, Any], priority: str) -> str:
        """Format a single test case for HTML."""
        test_id = test.get("id", "TC-XXX")
        title = test.get("title", "Untitled Test")
        description = test.get("description", "")
        category = test.get("category", "general")
        preconditions = test.get("preconditions", [])
        steps = test.get("steps", [])
        expected = test.get("expected_result", "")
        test_data = test.get("test_data", {})

        html = f"""
        <div class="test-case {priority}">
            <div class="test-header">
                <span class="test-title">{title}</span>
                <span class="test-id">{test_id}</span>
            </div>
            <div class="test-meta">
                Category: {category.replace('_', ' ').title()}
            </div>
"""

        if description:
            html += f"""
            <div class="test-description">{description}</div>
"""

        if preconditions:
            html += """
            <div class="test-section">
                <h4>Preconditions</h4>
                <ul>
"""
            for pre in preconditions:
                html += f"                    <li>{pre}</li>\n"
            html += """
                </ul>
            </div>
"""

        if steps:
            html += """
            <div class="test-section">
                <h4>Steps</h4>
                <ol>
"""
            for step in steps:
                # Remove leading numbers if present
                step_text = step
                if step.strip()[0].isdigit() and '.' in step[:5]:
                    step_text = step.split('.', 1)[1].strip() if '.' in step else step
                html += f"                    <li>{step_text}</li>\n"
            html += """
                </ol>
            </div>
"""

        if expected:
            html += f"""
            <div class="test-section">
                <h4>Expected Result</h4>
                <div class="expected">{expected}</div>
            </div>
"""

        if test_data:
            html += f"""
            <div class="test-section">
                <h4>Test Data</h4>
                <pre class="test-data">{json.dumps(test_data, indent=2)}</pre>
            </div>
"""

        html += """
        </div>
"""

        return html

    def to_json(self, report: TestReport) -> str:
        """
        Generate JSON format report.

        Args:
            report: TestReport to format

        Returns:
            JSON string
        """
        data = {
            "metadata": {
                "title": report.metadata.title,
                "feature": report.metadata.feature,
                "page_type": report.metadata.page_type,
                "generated_at": report.metadata.generated_at.isoformat(),
                "generated_by": report.metadata.generated_by,
                "version": report.metadata.version,
            },
            "summary": report.summary,
            "tests": report.tests,
        }

        return json.dumps(data, indent=2)

    def to_text(self, report: TestReport) -> str:
        """
        Generate plain text format report.

        Args:
            report: TestReport to format

        Returns:
            Text string
        """
        lines = []
        m = report.metadata
        s = report.summary

        # Header
        lines.append("=" * 60)
        lines.append(m.title.center(60))
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Feature: {m.feature}")
        if m.page_type:
            lines.append(f"Page Type: {m.page_type.title()}")
        lines.append(f"Generated: {m.generated_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append("")

        # Summary
        lines.append("-" * 60)
        lines.append("SUMMARY")
        lines.append("-" * 60)
        lines.append(f"Total Tests: {s['total_tests']}")
        lines.append(f"  Critical: {s['critical_count']}")
        lines.append(f"  High:     {s['high_count']}")
        lines.append(f"  Medium:   {s['medium_count']}")
        lines.append(f"  Low:      {s['low_count']}")
        lines.append("")

        # Tests
        lines.append("-" * 60)
        lines.append("TEST CASES")
        lines.append("-" * 60)

        for priority in ["critical", "high", "medium", "low"]:
            tests_in_priority = report.by_priority[priority]
            if not tests_in_priority:
                continue

            lines.append("")
            lines.append(f"[{priority.upper()}]")
            lines.append("")

            for test in tests_in_priority:
                lines.extend(self._format_test_text(test))
                lines.append("")

        # Footer
        lines.append("-" * 60)
        lines.append(f"Generated by {m.generated_by}")

        return "\n".join(lines)

    def _format_test_text(self, test: Dict[str, Any]) -> List[str]:
        """Format a single test case for plain text."""
        lines = []

        test_id = test.get("id", "TC-XXX")
        title = test.get("title", "Untitled Test")
        description = test.get("description", "")
        category = test.get("category", "general")
        preconditions = test.get("preconditions", [])
        steps = test.get("steps", [])
        expected = test.get("expected_result", "")

        lines.append(f"{test_id}: {title}")
        lines.append(f"  Category: {category}")

        if description:
            lines.append(f"  Description: {description}")

        if preconditions:
            lines.append("  Preconditions:")
            for pre in preconditions:
                lines.append(f"    - {pre}")

        if steps:
            lines.append("  Steps:")
            for i, step in enumerate(steps, 1):
                if step.strip()[0].isdigit():
                    lines.append(f"    {step}")
                else:
                    lines.append(f"    {i}. {step}")

        if expected:
            lines.append(f"  Expected: {expected}")

        return lines

    def save(
        self,
        report: TestReport,
        filename: str,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> Path:
        """
        Save report to file.

        Args:
            report: TestReport to save
            filename: Output filename
            format: Output format

        Returns:
            Path to saved file
        """
        # Generate content
        if format == ReportFormat.MARKDOWN:
            content = self.to_markdown(report)
        elif format == ReportFormat.HTML:
            content = self.to_html(report)
        elif format == ReportFormat.JSON:
            content = self.to_json(report)
        else:
            content = self.to_text(report)

        # Ensure correct extension
        path = Path(filename)
        expected_ext = {
            ReportFormat.MARKDOWN: ".md",
            ReportFormat.HTML: ".html",
            ReportFormat.JSON: ".json",
            ReportFormat.TEXT: ".txt",
        }

        if path.suffix != expected_ext[format]:
            path = path.with_suffix(expected_ext[format])

        # Write file
        path.write_text(content, encoding="utf-8")

        return path


def generate_report(
    tests: List[Dict[str, Any]],
    feature: str,
    page_type: Optional[str] = None,
    format: ReportFormat = ReportFormat.MARKDOWN,
) -> str:
    """
    Quick helper to generate a report.

    Args:
        tests: Test cases
        feature: Feature name
        page_type: Page type
        format: Output format

    Returns:
        Formatted report string
    """
    generator = ReportGenerator()
    report = generator.create_report(tests, feature, page_type)

    if format == ReportFormat.MARKDOWN:
        return generator.to_markdown(report)
    elif format == ReportFormat.HTML:
        return generator.to_html(report)
    elif format == ReportFormat.JSON:
        return generator.to_json(report)
    else:
        return generator.to_text(report)
