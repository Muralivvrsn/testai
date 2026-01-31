"""
TestAI Agent - Accessibility Reporter

Generate accessibility reports in multiple formats
with violation summaries and remediation guides.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import json


class A11yReportFormat(Enum):
    """Report output formats."""
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"
    SARIF = "sarif"


@dataclass
class AccessibilityReport:
    """An accessibility test report."""
    report_id: str
    title: str
    pages_checked: int
    total_violations: int
    violations_by_impact: Dict[str, int]
    violations_by_wcag: Dict[str, int]
    overall_score: float
    pass_rate: float
    created_at: datetime
    pages: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AccessibilityReporter:
    """
    Accessibility report generator.

    Features:
    - Multiple output formats
    - Violation summaries
    - Remediation guides
    - WCAG mapping
    - Trend tracking
    """

    def __init__(
        self,
        output_dir: str = "./a11y-reports",
        default_format: A11yReportFormat = A11yReportFormat.HTML,
    ):
        """Initialize the reporter."""
        self._output_dir = output_dir
        self._default_format = default_format
        self._reports: List[AccessibilityReport] = []
        self._report_counter = 0

    def create_report(
        self,
        title: str,
        results: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AccessibilityReport:
        """Create an accessibility report from results."""
        self._report_counter += 1
        report_id = f"A11YREP-{self._report_counter:05d}"

        # Aggregate violations
        total_violations = 0
        violations_by_impact: Dict[str, int] = {}
        violations_by_wcag: Dict[str, int] = {}
        total_score = 0
        pages = []

        for result in results:
            violations = result.get("violations", [])
            total_violations += len(violations)

            for v in violations:
                impact = v.get("impact", "unknown")
                violations_by_impact[impact] = violations_by_impact.get(impact, 0) + 1

                for criterion in v.get("wcag_criteria", []):
                    violations_by_wcag[criterion] = violations_by_wcag.get(criterion, 0) + 1

            total_score += result.get("score", 0)

            pages.append({
                "url": result.get("page_url", ""),
                "score": result.get("score", 0),
                "violations": len(violations),
                "passes": result.get("passes", 0),
            })

        avg_score = total_score / len(results) if results else 0
        pass_rate = sum(1 for p in pages if p["violations"] == 0) / len(pages) if pages else 0

        report = AccessibilityReport(
            report_id=report_id,
            title=title,
            pages_checked=len(results),
            total_violations=total_violations,
            violations_by_impact=violations_by_impact,
            violations_by_wcag=violations_by_wcag,
            overall_score=round(avg_score, 1),
            pass_rate=pass_rate,
            created_at=datetime.now(),
            pages=pages,
            metadata=metadata or {},
        )

        self._reports.append(report)
        return report

    def generate(
        self,
        report: AccessibilityReport,
        format: Optional[A11yReportFormat] = None,
    ) -> str:
        """Generate report in specified format."""
        format = format or self._default_format

        if format == A11yReportFormat.HTML:
            return self._generate_html(report)
        elif format == A11yReportFormat.JSON:
            return self._generate_json(report)
        elif format == A11yReportFormat.MARKDOWN:
            return self._generate_markdown(report)
        elif format == A11yReportFormat.SARIF:
            return self._generate_sarif(report)
        else:
            return self._generate_text(report)

    def _generate_html(self, report: AccessibilityReport) -> str:
        """Generate HTML report."""
        status_class = "pass" if report.overall_score >= 90 else "warn" if report.overall_score >= 70 else "fail"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{report.title} - Accessibility Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 40px; }}
        .header {{ border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat {{ text-align: center; padding: 20px; border-radius: 8px; background: #f5f5f5; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .pass {{ color: #22c55e; }}
        .warn {{ color: #f59e0b; }}
        .fail {{ color: #ef4444; }}
        .section {{ margin: 30px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; }}
        .impact-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
        .critical {{ background: #ef4444; color: white; }}
        .serious {{ background: #f59e0b; color: white; }}
        .moderate {{ background: #fbbf24; color: black; }}
        .minor {{ background: #22c55e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report.title}</h1>
        <p>Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <div class="stat">
            <div class="stat-value {status_class}">{report.overall_score}</div>
            <div>Score</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report.pages_checked}</div>
            <div>Pages</div>
        </div>
        <div class="stat">
            <div class="stat-value fail">{report.total_violations}</div>
            <div>Violations</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report.pass_rate:.0%}</div>
            <div>Pass Rate</div>
        </div>
    </div>

    <div class="section">
        <h2>Violations by Impact</h2>
        <table>
            <tr><th>Impact</th><th>Count</th></tr>
"""

        for impact, count in sorted(report.violations_by_impact.items()):
            html += f"            <tr><td><span class='impact-badge {impact}'>{impact}</span></td><td>{count}</td></tr>\n"

        html += """        </table>
    </div>

    <div class="section">
        <h2>Violations by WCAG Criterion</h2>
        <table>
            <tr><th>Criterion</th><th>Count</th></tr>
"""

        for wcag, count in sorted(report.violations_by_wcag.items()):
            html += f"            <tr><td>{wcag}</td><td>{count}</td></tr>\n"

        html += """        </table>
    </div>

    <div class="section">
        <h2>Pages</h2>
        <table>
            <tr><th>URL</th><th>Score</th><th>Violations</th><th>Passes</th></tr>
"""

        for page in report.pages:
            score_class = "pass" if page["score"] >= 90 else "warn" if page["score"] >= 70 else "fail"
            html += f"            <tr><td>{page['url']}</td><td class='{score_class}'>{page['score']}</td><td>{page['violations']}</td><td>{page['passes']}</td></tr>\n"

        html += """        </table>
    </div>
</body>
</html>"""

        return html

    def _generate_json(self, report: AccessibilityReport) -> str:
        """Generate JSON report."""
        data = {
            "report_id": report.report_id,
            "title": report.title,
            "created_at": report.created_at.isoformat(),
            "summary": {
                "overall_score": report.overall_score,
                "pages_checked": report.pages_checked,
                "total_violations": report.total_violations,
                "pass_rate": report.pass_rate,
            },
            "violations_by_impact": report.violations_by_impact,
            "violations_by_wcag": report.violations_by_wcag,
            "pages": report.pages,
            "metadata": report.metadata,
        }

        return json.dumps(data, indent=2)

    def _generate_markdown(self, report: AccessibilityReport) -> str:
        """Generate Markdown report."""
        status = "✅" if report.overall_score >= 90 else "⚠️" if report.overall_score >= 70 else "❌"

        lines = [
            f"# {report.title}",
            "",
            f"**Status:** {status} Score: {report.overall_score}/100",
            f"**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Pages Checked | {report.pages_checked} |",
            f"| Total Violations | {report.total_violations} |",
            f"| Pass Rate | {report.pass_rate:.0%} |",
            f"| Overall Score | {report.overall_score} |",
            "",
            "## Violations by Impact",
            "",
            "| Impact | Count |",
            "|--------|-------|",
        ]

        for impact, count in sorted(report.violations_by_impact.items()):
            lines.append(f"| {impact} | {count} |")

        lines.extend([
            "",
            "## Violations by WCAG Criterion",
            "",
            "| Criterion | Count |",
            "|-----------|-------|",
        ])

        for wcag, count in sorted(report.violations_by_wcag.items()):
            lines.append(f"| {wcag} | {count} |")

        lines.extend([
            "",
            "## Pages",
            "",
            "| URL | Score | Violations |",
            "|-----|-------|------------|",
        ])

        for page in report.pages:
            lines.append(f"| {page['url']} | {page['score']} | {page['violations']} |")

        return "\n".join(lines)

    def _generate_text(self, report: AccessibilityReport) -> str:
        """Generate text report."""
        status = "PASS" if report.overall_score >= 90 else "NEEDS WORK" if report.overall_score >= 70 else "FAIL"

        lines = [
            "=" * 60,
            f"  ACCESSIBILITY REPORT: {status}",
            "=" * 60,
            "",
            f"  Title: {report.title}",
            f"  Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            "",
            f"  Score: {report.overall_score}/100",
            f"  Pages: {report.pages_checked}",
            f"  Violations: {report.total_violations}",
            f"  Pass Rate: {report.pass_rate:.0%}",
            "",
            "-" * 60,
            "  VIOLATIONS BY IMPACT",
            "-" * 60,
            "",
        ]

        for impact, count in sorted(report.violations_by_impact.items()):
            lines.append(f"  {impact}: {count}")

        lines.extend([
            "",
            "-" * 60,
            "  VIOLATIONS BY WCAG",
            "-" * 60,
            "",
        ])

        for wcag, count in sorted(report.violations_by_wcag.items()):
            lines.append(f"  {wcag}: {count}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)

    def _generate_sarif(self, report: AccessibilityReport) -> str:
        """Generate SARIF format report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestAI Accessibility Checker",
                            "version": "1.0.0",
                            "informationUri": "https://testai.example.com",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def get_trend(
        self,
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Get accessibility score trend."""
        recent = self._reports[-limit:] if len(self._reports) >= limit else self._reports

        if not recent:
            return {"trend": "no_data", "data_points": 0}

        scores = [r.overall_score for r in recent]

        if len(scores) < 2:
            trend = "insufficient_data"
        else:
            first_avg = sum(scores[:len(scores)//2]) / (len(scores)//2)
            second_avg = sum(scores[len(scores)//2:]) / (len(scores) - len(scores)//2)

            if second_avg > first_avg + 5:
                trend = "improving"
            elif second_avg < first_avg - 5:
                trend = "degrading"
            else:
                trend = "stable"

        return {
            "trend": trend,
            "data_points": len(scores),
            "recent_scores": scores,
            "avg_score": sum(scores) / len(scores),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get reporter statistics."""
        if not self._reports:
            return {
                "total_reports": 0,
                "avg_score": 0,
            }

        return {
            "total_reports": len(self._reports),
            "avg_score": sum(r.overall_score for r in self._reports) / len(self._reports),
            "total_pages_checked": sum(r.pages_checked for r in self._reports),
            "total_violations_found": sum(r.total_violations for r in self._reports),
        }

    def format_report(self, report: AccessibilityReport) -> str:
        """Format report summary for display."""
        return self._generate_text(report)


def create_accessibility_reporter(
    output_dir: str = "./a11y-reports",
    default_format: A11yReportFormat = A11yReportFormat.HTML,
) -> AccessibilityReporter:
    """Create an accessibility reporter instance."""
    return AccessibilityReporter(
        output_dir=output_dir,
        default_format=default_format,
    )
