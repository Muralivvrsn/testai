"""
TestAI Agent - Report Generator

Generates test reports in multiple formats
including HTML, JSON, JUnit XML, and Markdown.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json


class ReportFormat(Enum):
    """Supported report formats."""
    HTML = "html"
    JSON = "json"
    JUNIT_XML = "junit_xml"
    MARKDOWN = "markdown"
    TEXT = "text"
    CSV = "csv"


class ReportType(Enum):
    """Types of test reports."""
    SUMMARY = "summary"
    DETAILED = "detailed"
    EXECUTIVE = "executive"
    DEVELOPER = "developer"
    COVERAGE = "coverage"
    PERFORMANCE = "performance"


@dataclass
class TestResultEntry:
    """A single test result entry."""
    test_id: str
    test_name: str
    status: str  # "passed", "failed", "skipped", "error"
    duration_sec: float
    suite: str
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportSection:
    """A section of a report."""
    section_id: str
    title: str
    content: str
    order: int
    visible: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestReport:
    """A complete test report."""
    report_id: str
    title: str
    report_type: ReportType
    format: ReportFormat
    generated_at: datetime
    sections: List[ReportSection]
    results: List[TestResultEntry]
    summary: Dict[str, Any]
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReportGenerator:
    """
    Generates test reports.

    Features:
    - Multiple output formats
    - Customizable sections
    - Templates support
    - Aggregated summaries
    """

    def __init__(
        self,
        default_format: ReportFormat = ReportFormat.HTML,
        include_stack_traces: bool = True,
        max_failures_shown: int = 50,
    ):
        """Initialize the generator."""
        self._default_format = default_format
        self._include_stack_traces = include_stack_traces
        self._max_failures = max_failures_shown
        self._results: List[TestResultEntry] = []
        self._reports: Dict[str, TestReport] = {}
        self._templates: Dict[str, str] = {}
        self._result_counter = 0
        self._report_counter = 0
        self._section_counter = 0

        # Load default templates
        self._load_default_templates()

    def _load_default_templates(self) -> None:
        """Load default report templates."""
        self._templates["html_summary"] = """
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .passed {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
        .skipped {{ color: #ffc107; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="summary">
        <p><strong>Generated:</strong> {generated_at}</p>
        <p><strong>Total Tests:</strong> {total}</p>
        <p class="passed"><strong>Passed:</strong> {passed}</p>
        <p class="failed"><strong>Failed:</strong> {failed}</p>
        <p class="skipped"><strong>Skipped:</strong> {skipped}</p>
        <p><strong>Pass Rate:</strong> {pass_rate}%</p>
        <p><strong>Duration:</strong> {duration}s</p>
    </div>
    {sections}
</body>
</html>
"""

        self._templates["markdown_summary"] = """
# {title}

**Generated:** {generated_at}

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {total} |
| Passed | {passed} |
| Failed | {failed} |
| Skipped | {skipped} |
| Pass Rate | {pass_rate}% |
| Duration | {duration}s |

{sections}
"""

    def add_result(
        self,
        test_name: str,
        status: str,
        duration_sec: float,
        suite: str = "default",
        error_message: Optional[str] = None,
        stack_trace: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestResultEntry:
        """Add a test result."""
        self._result_counter += 1
        test_id = f"TEST-{self._result_counter:05d}"

        entry = TestResultEntry(
            test_id=test_id,
            test_name=test_name,
            status=status,
            duration_sec=duration_sec,
            suite=suite,
            error_message=error_message,
            stack_trace=stack_trace if self._include_stack_traces else None,
            metadata=metadata or {},
        )

        self._results.append(entry)
        return entry

    def add_results_batch(
        self,
        results: List[Dict[str, Any]],
    ) -> List[TestResultEntry]:
        """Add multiple results at once."""
        entries = []
        for result in results:
            entry = self.add_result(
                test_name=result.get("name", "Unknown"),
                status=result.get("status", "unknown"),
                duration_sec=result.get("duration", 0.0),
                suite=result.get("suite", "default"),
                error_message=result.get("error"),
                stack_trace=result.get("stack_trace"),
                metadata=result.get("metadata"),
            )
            entries.append(entry)
        return entries

    def create_section(
        self,
        title: str,
        content: str,
        order: int = 0,
    ) -> ReportSection:
        """Create a report section."""
        self._section_counter += 1
        section_id = f"SEC-{self._section_counter:05d}"

        return ReportSection(
            section_id=section_id,
            title=title,
            content=content,
            order=order,
        )

    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.status == "passed")
        failed = sum(1 for r in self._results if r.status == "failed")
        skipped = sum(1 for r in self._results if r.status == "skipped")
        errors = sum(1 for r in self._results if r.status == "error")

        total_duration = sum(r.duration_sec for r in self._results)

        pass_rate = (passed / total * 100) if total > 0 else 0.0

        # Group by suite
        suites: Dict[str, Dict[str, int]] = {}
        for result in self._results:
            if result.suite not in suites:
                suites[result.suite] = {"total": 0, "passed": 0, "failed": 0}
            suites[result.suite]["total"] += 1
            if result.status == "passed":
                suites[result.suite]["passed"] += 1
            elif result.status in ("failed", "error"):
                suites[result.suite]["failed"] += 1

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "errors": errors,
            "pass_rate": round(pass_rate, 2),
            "duration": round(total_duration, 2),
            "suites": suites,
        }

    def generate_report(
        self,
        title: str,
        report_type: ReportType = ReportType.SUMMARY,
        format: Optional[ReportFormat] = None,
        custom_sections: Optional[List[ReportSection]] = None,
    ) -> TestReport:
        """Generate a test report."""
        self._report_counter += 1
        report_id = f"RPT-{self._report_counter:05d}"

        format = format or self._default_format
        summary = self.generate_summary()
        sections = custom_sections or []

        # Generate content based on format
        content = self._generate_content(
            title, report_type, format, summary, sections
        )

        report = TestReport(
            report_id=report_id,
            title=title,
            report_type=report_type,
            format=format,
            generated_at=datetime.now(),
            sections=sections,
            results=self._results.copy(),
            summary=summary,
            content=content,
        )

        self._reports[report_id] = report
        return report

    def _generate_content(
        self,
        title: str,
        report_type: ReportType,
        format: ReportFormat,
        summary: Dict[str, Any],
        sections: List[ReportSection],
    ) -> str:
        """Generate report content."""
        if format == ReportFormat.HTML:
            return self._generate_html(title, summary, sections)
        elif format == ReportFormat.JSON:
            return self._generate_json(title, summary)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(title, summary, sections)
        elif format == ReportFormat.JUNIT_XML:
            return self._generate_junit_xml(summary)
        elif format == ReportFormat.TEXT:
            return self._generate_text(title, summary)
        elif format == ReportFormat.CSV:
            return self._generate_csv()
        else:
            return self._generate_text(title, summary)

    def _generate_html(
        self,
        title: str,
        summary: Dict[str, Any],
        sections: List[ReportSection],
    ) -> str:
        """Generate HTML report."""
        template = self._templates.get("html_summary", "")

        # Generate sections HTML
        sections_html = ""
        for section in sorted(sections, key=lambda s: s.order):
            if section.visible:
                sections_html += f"<h2>{section.title}</h2>\n"
                sections_html += f"<div>{section.content}</div>\n"

        # Add failures section
        failures = [r for r in self._results if r.status in ("failed", "error")]
        if failures:
            sections_html += "<h2>Failed Tests</h2>\n<table>\n"
            sections_html += "<tr><th>Test</th><th>Suite</th><th>Error</th></tr>\n"
            for fail in failures[:self._max_failures]:
                error = fail.error_message or "No message"
                sections_html += f"<tr><td>{fail.test_name}</td><td>{fail.suite}</td><td>{error}</td></tr>\n"
            sections_html += "</table>\n"

        return template.format(
            title=title,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=summary["total"],
            passed=summary["passed"],
            failed=summary["failed"],
            skipped=summary["skipped"],
            pass_rate=summary["pass_rate"],
            duration=summary["duration"],
            sections=sections_html,
        )

    def _generate_json(
        self,
        title: str,
        summary: Dict[str, Any],
    ) -> str:
        """Generate JSON report."""
        data = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "results": [
                {
                    "id": r.test_id,
                    "name": r.test_name,
                    "status": r.status,
                    "duration": r.duration_sec,
                    "suite": r.suite,
                    "error": r.error_message,
                }
                for r in self._results
            ],
        }
        return json.dumps(data, indent=2)

    def _generate_markdown(
        self,
        title: str,
        summary: Dict[str, Any],
        sections: List[ReportSection],
    ) -> str:
        """Generate Markdown report."""
        template = self._templates.get("markdown_summary", "")

        # Generate sections markdown
        sections_md = ""
        for section in sorted(sections, key=lambda s: s.order):
            if section.visible:
                sections_md += f"\n## {section.title}\n\n"
                sections_md += f"{section.content}\n"

        # Add failures
        failures = [r for r in self._results if r.status in ("failed", "error")]
        if failures:
            sections_md += "\n## Failed Tests\n\n"
            sections_md += "| Test | Suite | Error |\n"
            sections_md += "|------|-------|-------|\n"
            for fail in failures[:self._max_failures]:
                error = (fail.error_message or "No message")[:50]
                sections_md += f"| {fail.test_name} | {fail.suite} | {error} |\n"

        return template.format(
            title=title,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=summary["total"],
            passed=summary["passed"],
            failed=summary["failed"],
            skipped=summary["skipped"],
            pass_rate=summary["pass_rate"],
            duration=summary["duration"],
            sections=sections_md,
        )

    def _generate_junit_xml(
        self,
        summary: Dict[str, Any],
    ) -> str:
        """Generate JUnit XML report."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuites tests="{summary["total"]}" failures="{summary["failed"]}" '
            f'errors="{summary["errors"]}" time="{summary["duration"]}">',
        ]

        # Group by suite
        suites: Dict[str, List[TestResultEntry]] = {}
        for result in self._results:
            if result.suite not in suites:
                suites[result.suite] = []
            suites[result.suite].append(result)

        for suite_name, results in suites.items():
            suite_failures = sum(1 for r in results if r.status == "failed")
            suite_errors = sum(1 for r in results if r.status == "error")
            suite_time = sum(r.duration_sec for r in results)

            lines.append(
                f'  <testsuite name="{suite_name}" tests="{len(results)}" '
                f'failures="{suite_failures}" errors="{suite_errors}" time="{suite_time:.3f}">'
            )

            for result in results:
                lines.append(
                    f'    <testcase name="{result.test_name}" time="{result.duration_sec:.3f}">'
                )
                if result.status == "failed":
                    msg = result.error_message or "Test failed"
                    lines.append(f'      <failure message="{msg}"/>')
                elif result.status == "error":
                    msg = result.error_message or "Test error"
                    lines.append(f'      <error message="{msg}"/>')
                elif result.status == "skipped":
                    lines.append('      <skipped/>')
                lines.append('    </testcase>')

            lines.append('  </testsuite>')

        lines.append('</testsuites>')
        return "\n".join(lines)

    def _generate_text(
        self,
        title: str,
        summary: Dict[str, Any],
    ) -> str:
        """Generate plain text report."""
        lines = [
            "=" * 60,
            f"  {title}",
            "=" * 60,
            "",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            "",
            f"  Total Tests:  {summary['total']}",
            f"  Passed:       {summary['passed']}",
            f"  Failed:       {summary['failed']}",
            f"  Skipped:      {summary['skipped']}",
            f"  Pass Rate:    {summary['pass_rate']}%",
            f"  Duration:     {summary['duration']}s",
            "",
        ]

        failures = [r for r in self._results if r.status in ("failed", "error")]
        if failures:
            lines.append("-" * 60)
            lines.append("  FAILURES")
            lines.append("-" * 60)
            lines.append("")
            for fail in failures[:self._max_failures]:
                lines.append(f"  ✗ {fail.test_name}")
                if fail.error_message:
                    lines.append(f"    {fail.error_message[:80]}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _generate_csv(self) -> str:
        """Generate CSV report."""
        lines = ["test_id,test_name,status,duration,suite,error"]
        for result in self._results:
            error = (result.error_message or "").replace(",", ";").replace("\n", " ")
            lines.append(
                f"{result.test_id},{result.test_name},{result.status},"
                f"{result.duration_sec},{result.suite},{error}"
            )
        return "\n".join(lines)

    def get_report(self, report_id: str) -> Optional[TestReport]:
        """Get a report by ID."""
        return self._reports.get(report_id)

    def list_reports(self) -> List[TestReport]:
        """List all generated reports."""
        return list(self._reports.values())

    def clear_results(self) -> None:
        """Clear all results."""
        self._results.clear()
        self._result_counter = 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics."""
        status_counts: Dict[str, int] = {}
        for result in self._results:
            status_counts[result.status] = status_counts.get(result.status, 0) + 1

        return {
            "total_results": len(self._results),
            "total_reports": len(self._reports),
            "results_by_status": status_counts,
            "templates_loaded": len(self._templates),
        }

    def format_report_preview(self, report: TestReport) -> str:
        """Format a report preview."""
        lines = [
            "=" * 55,
            f"  REPORT: {report.title}",
            "=" * 55,
            "",
            f"  ID: {report.report_id}",
            f"  Type: {report.report_type.value}",
            f"  Format: {report.format.value}",
            f"  Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M')}",
            "",
            "-" * 55,
            "  SUMMARY",
            "-" * 55,
            "",
            f"  Total: {report.summary['total']}",
            f"  Passed: {report.summary['passed']}",
            f"  Failed: {report.summary['failed']}",
            f"  Pass Rate: {report.summary['pass_rate']}%",
            "",
            "-" * 55,
            "  CONTENT PREVIEW",
            "-" * 55,
            "",
        ]

        # Show first 500 chars of content
        preview = report.content[:500]
        if len(report.content) > 500:
            preview += "\n... (truncated)"
        lines.append(preview)

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_report_generator(
    default_format: ReportFormat = ReportFormat.HTML,
    include_stack_traces: bool = True,
    max_failures_shown: int = 50,
) -> ReportGenerator:
    """Create a report generator instance."""
    return ReportGenerator(
        default_format=default_format,
        include_stack_traces=include_stack_traces,
        max_failures_shown=max_failures_shown,
    )
