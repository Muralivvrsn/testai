"""
TestAI Agent - Visual Reporter

Generate visual regression reports with
diff overlays, side-by-side comparisons,
and trend analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid


class ReportFormat(Enum):
    """Report output formats."""
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"


class DiffDisplayMode(Enum):
    """How to display visual diffs."""
    SIDE_BY_SIDE = "side_by_side"
    OVERLAY = "overlay"
    SLIDER = "slider"
    HIGHLIGHT = "highlight"


@dataclass
class VisualDiff:
    """A visual diff entry in a report."""
    diff_id: str
    name: str
    baseline_path: str
    current_path: str
    diff_path: Optional[str]
    match_percentage: float
    passed: bool
    diff_regions: List[Dict[str, Any]]
    created_at: datetime


@dataclass
class VisualReport:
    """A visual regression report."""
    report_id: str
    title: str
    run_id: str
    diffs: List[VisualDiff]
    total_comparisons: int
    passed_count: int
    failed_count: int
    overall_match: float
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class VisualReporter:
    """
    Visual regression report generator.

    Features:
    - Multiple output formats
    - Diff visualization
    - Trend tracking
    - Interactive reports
    """

    def __init__(
        self,
        output_dir: str = "./visual-reports",
        default_format: ReportFormat = ReportFormat.HTML,
        diff_display: DiffDisplayMode = DiffDisplayMode.SIDE_BY_SIDE,
    ):
        """Initialize the reporter."""
        self._output_dir = output_dir
        self._default_format = default_format
        self._diff_display = diff_display

        self._reports: List[VisualReport] = []
        self._diffs: Dict[str, VisualDiff] = {}

        self._report_counter = 0
        self._diff_counter = 0

    def create_diff(
        self,
        name: str,
        baseline_path: str,
        current_path: str,
        match_percentage: float,
        passed: bool,
        diff_regions: Optional[List[Dict[str, Any]]] = None,
        diff_path: Optional[str] = None,
    ) -> VisualDiff:
        """Create a visual diff entry."""
        self._diff_counter += 1
        diff_id = f"VDIFF-{self._diff_counter:05d}"

        diff = VisualDiff(
            diff_id=diff_id,
            name=name,
            baseline_path=baseline_path,
            current_path=current_path,
            diff_path=diff_path,
            match_percentage=match_percentage,
            passed=passed,
            diff_regions=diff_regions or [],
            created_at=datetime.now(),
        )

        self._diffs[diff_id] = diff
        return diff

    def create_report(
        self,
        title: str,
        run_id: str,
        diff_ids: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VisualReport:
        """Create a visual report."""
        self._report_counter += 1
        report_id = f"VREP-{self._report_counter:05d}"

        diffs = [
            self._diffs[did] for did in diff_ids
            if did in self._diffs
        ]

        passed_count = sum(1 for d in diffs if d.passed)
        failed_count = len(diffs) - passed_count

        overall_match = (
            sum(d.match_percentage for d in diffs) / len(diffs)
            if diffs else 1.0
        )

        report = VisualReport(
            report_id=report_id,
            title=title,
            run_id=run_id,
            diffs=diffs,
            total_comparisons=len(diffs),
            passed_count=passed_count,
            failed_count=failed_count,
            overall_match=overall_match,
            created_at=datetime.now(),
            metadata=metadata or {},
        )

        self._reports.append(report)
        return report

    def generate_report(
        self,
        report: VisualReport,
        format: Optional[ReportFormat] = None,
    ) -> str:
        """Generate report in specified format."""
        format = format or self._default_format

        if format == ReportFormat.HTML:
            return self._generate_html(report)
        elif format == ReportFormat.JSON:
            return self._generate_json(report)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(report)
        else:
            return self._generate_text(report)

    def _generate_html(self, report: VisualReport) -> str:
        """Generate HTML report."""
        status_class = "passed" if report.failed_count == 0 else "failed"
        status_text = "PASSED" if report.failed_count == 0 else "FAILED"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 40px; }}
        .header {{ border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .summary {{ display: flex; gap: 40px; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .passed {{ color: #22c55e; }}
        .failed {{ color: #ef4444; }}
        .diff-card {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; }}
        .diff-images {{ display: flex; gap: 20px; }}
        .diff-image {{ flex: 1; text-align: center; }}
        .region {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report.title}</h1>
        <p>Run: {report.run_id} | Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <div class="stat">
            <div class="stat-value {status_class}">{status_text}</div>
            <div>Status</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report.total_comparisons}</div>
            <div>Comparisons</div>
        </div>
        <div class="stat">
            <div class="stat-value passed">{report.passed_count}</div>
            <div>Passed</div>
        </div>
        <div class="stat">
            <div class="stat-value failed">{report.failed_count}</div>
            <div>Failed</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report.overall_match:.1%}</div>
            <div>Match</div>
        </div>
    </div>

    <h2>Visual Diffs</h2>
"""

        for diff in report.diffs:
            diff_status = "passed" if diff.passed else "failed"
            html += f"""
    <div class="diff-card">
        <h3 class="{diff_status}">{diff.name}</h3>
        <p>Match: {diff.match_percentage:.1%} | Regions: {len(diff.diff_regions)}</p>
        <div class="diff-images">
            <div class="diff-image">
                <p><strong>Baseline</strong></p>
                <p class="region">{diff.baseline_path}</p>
            </div>
            <div class="diff-image">
                <p><strong>Current</strong></p>
                <p class="region">{diff.current_path}</p>
            </div>
        </div>
    </div>
"""

        html += """
</body>
</html>"""

        return html

    def _generate_json(self, report: VisualReport) -> str:
        """Generate JSON report."""
        import json

        data = {
            "report_id": report.report_id,
            "title": report.title,
            "run_id": report.run_id,
            "created_at": report.created_at.isoformat(),
            "summary": {
                "total_comparisons": report.total_comparisons,
                "passed": report.passed_count,
                "failed": report.failed_count,
                "overall_match": report.overall_match,
            },
            "diffs": [
                {
                    "diff_id": d.diff_id,
                    "name": d.name,
                    "match_percentage": d.match_percentage,
                    "passed": d.passed,
                    "baseline_path": d.baseline_path,
                    "current_path": d.current_path,
                    "diff_path": d.diff_path,
                    "regions": d.diff_regions,
                }
                for d in report.diffs
            ],
            "metadata": report.metadata,
        }

        return json.dumps(data, indent=2)

    def _generate_markdown(self, report: VisualReport) -> str:
        """Generate Markdown report."""
        status = "✅ PASSED" if report.failed_count == 0 else "❌ FAILED"

        lines = [
            f"# {report.title}",
            "",
            f"**Status:** {status}",
            f"**Run:** {report.run_id}",
            f"**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Comparisons | {report.total_comparisons} |",
            f"| Passed | {report.passed_count} |",
            f"| Failed | {report.failed_count} |",
            f"| Overall Match | {report.overall_match:.1%} |",
            "",
            "## Visual Diffs",
            "",
        ]

        for diff in report.diffs:
            status_icon = "✅" if diff.passed else "❌"
            lines.extend([
                f"### {status_icon} {diff.name}",
                "",
                f"- **Match:** {diff.match_percentage:.1%}",
                f"- **Baseline:** `{diff.baseline_path}`",
                f"- **Current:** `{diff.current_path}`",
                f"- **Diff Regions:** {len(diff.diff_regions)}",
                "",
            ])

        return "\n".join(lines)

    def _generate_text(self, report: VisualReport) -> str:
        """Generate text report."""
        status = "PASSED" if report.failed_count == 0 else "FAILED"

        lines = [
            "=" * 60,
            f"  VISUAL REGRESSION REPORT: {status}",
            "=" * 60,
            "",
            f"  Title: {report.title}",
            f"  Run: {report.run_id}",
            f"  Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "  SUMMARY",
            "-" * 60,
            "",
            f"  Comparisons: {report.total_comparisons}",
            f"  Passed: {report.passed_count}",
            f"  Failed: {report.failed_count}",
            f"  Overall Match: {report.overall_match:.1%}",
            "",
            "-" * 60,
            "  VISUAL DIFFS",
            "-" * 60,
            "",
        ]

        for diff in report.diffs:
            status_icon = "✅" if diff.passed else "❌"
            lines.append(f"  {status_icon} {diff.name}")
            lines.append(f"     Match: {diff.match_percentage:.1%}")
            lines.append(f"     Regions: {len(diff.diff_regions)}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def get_trend(
        self,
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Get visual regression trend."""
        recent = self._reports[-limit:] if len(self._reports) >= limit else self._reports

        if not recent:
            return {"trend": "no_data", "data_points": 0}

        match_rates = [r.overall_match for r in recent]
        pass_rates = [r.passed_count / max(1, r.total_comparisons) for r in recent]

        if len(match_rates) < 2:
            trend = "insufficient_data"
        else:
            first_half = sum(match_rates[:len(match_rates)//2]) / (len(match_rates)//2)
            second_half = sum(match_rates[len(match_rates)//2:]) / (len(match_rates) - len(match_rates)//2)

            if second_half > first_half + 0.02:
                trend = "improving"
            elif second_half < first_half - 0.02:
                trend = "degrading"
            else:
                trend = "stable"

        return {
            "trend": trend,
            "data_points": len(recent),
            "avg_match_rate": sum(match_rates) / len(match_rates),
            "avg_pass_rate": sum(pass_rates) / len(pass_rates),
            "recent_matches": match_rates,
        }

    def get_failing_diffs(
        self,
        limit: int = 20,
    ) -> List[VisualDiff]:
        """Get recent failing diffs."""
        failing = [d for d in self._diffs.values() if not d.passed]
        failing.sort(key=lambda d: d.created_at, reverse=True)
        return failing[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get reporter statistics."""
        total_diffs = len(self._diffs)
        passed_diffs = sum(1 for d in self._diffs.values() if d.passed)

        return {
            "total_reports": len(self._reports),
            "total_diffs": total_diffs,
            "passed_diffs": passed_diffs,
            "failed_diffs": total_diffs - passed_diffs,
            "pass_rate": passed_diffs / max(1, total_diffs),
        }

    def format_diff(self, diff: VisualDiff) -> str:
        """Format a diff for display."""
        status = "✅ PASSED" if diff.passed else "❌ FAILED"

        lines = [
            "=" * 50,
            f"  {status} VISUAL DIFF",
            "=" * 50,
            "",
            f"  Name: {diff.name}",
            f"  Match: {diff.match_percentage:.1%}",
            "",
            f"  Baseline: {diff.baseline_path}",
            f"  Current: {diff.current_path}",
            "",
        ]

        if diff.diff_regions:
            lines.append("-" * 50)
            lines.append(f"  DIFF REGIONS ({len(diff.diff_regions)})")
            lines.append("-" * 50)

            for region in diff.diff_regions[:5]:
                x = region.get("x", 0)
                y = region.get("y", 0)
                w = region.get("width", 0)
                h = region.get("height", 0)
                lines.append(f"  • ({x}, {y}) {w}x{h}")

            if len(diff.diff_regions) > 5:
                lines.append(f"  ... and {len(diff.diff_regions) - 5} more")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_visual_reporter(
    output_dir: str = "./visual-reports",
    default_format: ReportFormat = ReportFormat.HTML,
    diff_display: DiffDisplayMode = DiffDisplayMode.SIDE_BY_SIDE,
) -> VisualReporter:
    """Create a visual reporter instance."""
    return VisualReporter(
        output_dir=output_dir,
        default_format=default_format,
        diff_display=diff_display,
    )
