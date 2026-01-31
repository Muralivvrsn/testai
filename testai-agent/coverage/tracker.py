"""
TestAI Agent - Coverage Tracker

Tracks code coverage metrics including line, branch,
and function coverage with historical trends.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class CoverageType(Enum):
    """Types of code coverage."""
    LINE = "line"
    BRANCH = "branch"
    FUNCTION = "function"
    STATEMENT = "statement"
    PATH = "path"


@dataclass
class FileCoverage:
    """Coverage data for a single file."""
    file_path: str
    total_lines: int
    covered_lines: int
    missed_lines: List[int]
    total_branches: int = 0
    covered_branches: int = 0
    total_functions: int = 0
    covered_functions: int = 0
    uncovered_functions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def line_coverage(self) -> float:
        """Calculate line coverage percentage."""
        if self.total_lines == 0:
            return 100.0
        return (self.covered_lines / self.total_lines) * 100

    @property
    def branch_coverage(self) -> float:
        """Calculate branch coverage percentage."""
        if self.total_branches == 0:
            return 100.0
        return (self.covered_branches / self.total_branches) * 100

    @property
    def function_coverage(self) -> float:
        """Calculate function coverage percentage."""
        if self.total_functions == 0:
            return 100.0
        return (self.covered_functions / self.total_functions) * 100


@dataclass
class CoverageMetrics:
    """Aggregated coverage metrics."""
    total_files: int
    total_lines: int
    covered_lines: int
    total_branches: int
    covered_branches: int
    total_functions: int
    covered_functions: int
    line_coverage_pct: float
    branch_coverage_pct: float
    function_coverage_pct: float


@dataclass
class CoverageReport:
    """A complete coverage report."""
    report_id: str
    name: str
    timestamp: datetime
    files: List[FileCoverage]
    metrics: CoverageMetrics
    coverage_by_directory: Dict[str, float]
    uncovered_critical: List[str]
    trend: Optional[Dict[str, float]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CoverageTracker:
    """
    Track code coverage metrics.

    Features:
    - Multi-type coverage (line, branch, function)
    - Historical tracking
    - Directory-level aggregation
    - Trend analysis
    """

    def __init__(
        self,
        coverage_threshold: float = 80.0,
        critical_paths: Optional[List[str]] = None,
    ):
        """Initialize the tracker."""
        self._threshold = coverage_threshold
        self._critical_paths = critical_paths or []
        self._reports: List[CoverageReport] = []
        self._current_files: Dict[str, FileCoverage] = {}
        self._report_counter = 0

    def record_file_coverage(
        self,
        file_path: str,
        total_lines: int,
        covered_lines: int,
        missed_lines: Optional[List[int]] = None,
        total_branches: int = 0,
        covered_branches: int = 0,
        total_functions: int = 0,
        covered_functions: int = 0,
        uncovered_functions: Optional[List[str]] = None,
    ) -> FileCoverage:
        """Record coverage for a single file."""
        coverage = FileCoverage(
            file_path=file_path,
            total_lines=total_lines,
            covered_lines=covered_lines,
            missed_lines=missed_lines or [],
            total_branches=total_branches,
            covered_branches=covered_branches,
            total_functions=total_functions,
            covered_functions=covered_functions,
            uncovered_functions=uncovered_functions or [],
        )

        self._current_files[file_path] = coverage
        return coverage

    def record_from_lcov(self, lcov_data: str) -> List[FileCoverage]:
        """Parse LCOV format coverage data."""
        files = []
        current_file = None
        current_lines: Dict[int, int] = {}
        current_functions: Dict[str, int] = {}

        for line in lcov_data.strip().split("\n"):
            line = line.strip()

            if line.startswith("SF:"):
                current_file = line[3:]
                current_lines = {}
                current_functions = {}

            elif line.startswith("DA:"):
                parts = line[3:].split(",")
                line_num = int(parts[0])
                hits = int(parts[1])
                current_lines[line_num] = hits

            elif line.startswith("FN:"):
                # Function name
                parts = line[3:].split(",")
                func_name = parts[1] if len(parts) > 1 else parts[0]
                current_functions[func_name] = 0

            elif line.startswith("FNDA:"):
                parts = line[5:].split(",")
                hits = int(parts[0])
                func_name = parts[1]
                current_functions[func_name] = hits

            elif line == "end_of_record" and current_file:
                total_lines = len(current_lines)
                covered_lines = sum(1 for h in current_lines.values() if h > 0)
                missed = [ln for ln, h in current_lines.items() if h == 0]

                total_funcs = len(current_functions)
                covered_funcs = sum(1 for h in current_functions.values() if h > 0)
                uncovered = [f for f, h in current_functions.items() if h == 0]

                coverage = self.record_file_coverage(
                    file_path=current_file,
                    total_lines=total_lines,
                    covered_lines=covered_lines,
                    missed_lines=sorted(missed),
                    total_functions=total_funcs,
                    covered_functions=covered_funcs,
                    uncovered_functions=uncovered,
                )
                files.append(coverage)
                current_file = None

        return files

    def record_from_istanbul(self, istanbul_json: Dict[str, Any]) -> List[FileCoverage]:
        """Parse Istanbul/NYC JSON coverage data."""
        files = []

        for file_path, data in istanbul_json.items():
            # Statement coverage
            statements = data.get("s", {})
            total_stmts = len(statements)
            covered_stmts = sum(1 for v in statements.values() if v > 0)

            # Branch coverage
            branches = data.get("b", {})
            total_branches = sum(len(b) for b in branches.values())
            covered_branches = sum(sum(1 for v in b if v > 0) for b in branches.values())

            # Function coverage
            functions = data.get("f", {})
            func_map = data.get("fnMap", {})
            total_funcs = len(functions)
            covered_funcs = sum(1 for v in functions.values() if v > 0)
            uncovered = [
                func_map.get(k, {}).get("name", k)
                for k, v in functions.items()
                if v == 0
            ]

            # Line mapping
            statement_map = data.get("statementMap", {})
            line_hits: Dict[int, int] = {}
            for stmt_id, hits in statements.items():
                stmt_info = statement_map.get(stmt_id, {})
                start_line = stmt_info.get("start", {}).get("line", 0)
                if start_line:
                    line_hits[start_line] = line_hits.get(start_line, 0) + hits

            total_lines = len(line_hits)
            covered_lines = sum(1 for v in line_hits.values() if v > 0)
            missed = [ln for ln, h in line_hits.items() if h == 0]

            coverage = self.record_file_coverage(
                file_path=file_path,
                total_lines=total_lines,
                covered_lines=covered_lines,
                missed_lines=sorted(missed),
                total_branches=total_branches,
                covered_branches=covered_branches,
                total_functions=total_funcs,
                covered_functions=covered_funcs,
                uncovered_functions=uncovered,
            )
            files.append(coverage)

        return files

    def generate_report(
        self,
        name: str = "Coverage Report",
    ) -> CoverageReport:
        """Generate a coverage report from current data."""
        self._report_counter += 1
        report_id = f"COV-{self._report_counter:05d}"

        files = list(self._current_files.values())

        # Calculate aggregate metrics
        total_lines = sum(f.total_lines for f in files)
        covered_lines = sum(f.covered_lines for f in files)
        total_branches = sum(f.total_branches for f in files)
        covered_branches = sum(f.covered_branches for f in files)
        total_functions = sum(f.total_functions for f in files)
        covered_functions = sum(f.covered_functions for f in files)

        metrics = CoverageMetrics(
            total_files=len(files),
            total_lines=total_lines,
            covered_lines=covered_lines,
            total_branches=total_branches,
            covered_branches=covered_branches,
            total_functions=total_functions,
            covered_functions=covered_functions,
            line_coverage_pct=(covered_lines / total_lines * 100) if total_lines else 100.0,
            branch_coverage_pct=(covered_branches / total_branches * 100) if total_branches else 100.0,
            function_coverage_pct=(covered_functions / total_functions * 100) if total_functions else 100.0,
        )

        # Coverage by directory
        dir_coverage: Dict[str, Dict[str, int]] = {}
        for f in files:
            parts = f.file_path.split("/")
            dir_path = "/".join(parts[:-1]) if len(parts) > 1 else "."

            if dir_path not in dir_coverage:
                dir_coverage[dir_path] = {"total": 0, "covered": 0}

            dir_coverage[dir_path]["total"] += f.total_lines
            dir_coverage[dir_path]["covered"] += f.covered_lines

        coverage_by_directory = {
            d: (data["covered"] / data["total"] * 100) if data["total"] else 100.0
            for d, data in dir_coverage.items()
        }

        # Find uncovered critical paths
        uncovered_critical = []
        for critical in self._critical_paths:
            for f in files:
                if critical in f.file_path and f.line_coverage < self._threshold:
                    uncovered_critical.append(f.file_path)

        # Calculate trend if we have history
        trend = None
        if self._reports:
            last_report = self._reports[-1]
            trend = {
                "line_change": metrics.line_coverage_pct - last_report.metrics.line_coverage_pct,
                "branch_change": metrics.branch_coverage_pct - last_report.metrics.branch_coverage_pct,
                "function_change": metrics.function_coverage_pct - last_report.metrics.function_coverage_pct,
            }

        report = CoverageReport(
            report_id=report_id,
            name=name,
            timestamp=datetime.now(),
            files=files,
            metrics=metrics,
            coverage_by_directory=coverage_by_directory,
            uncovered_critical=uncovered_critical,
            trend=trend,
        )

        self._reports.append(report)
        return report

    def get_file_coverage(self, file_path: str) -> Optional[FileCoverage]:
        """Get coverage for a specific file."""
        return self._current_files.get(file_path)

    def get_low_coverage_files(self, threshold: Optional[float] = None) -> List[FileCoverage]:
        """Get files below coverage threshold."""
        threshold = threshold or self._threshold
        return [
            f for f in self._current_files.values()
            if f.line_coverage < threshold
        ]

    def get_uncovered_lines(self, file_path: str) -> List[int]:
        """Get uncovered line numbers for a file."""
        coverage = self._current_files.get(file_path)
        return coverage.missed_lines if coverage else []

    def get_history(self, limit: int = 10) -> List[CoverageReport]:
        """Get historical coverage reports."""
        return self._reports[-limit:]

    def get_trend(self, periods: int = 5) -> Dict[str, List[float]]:
        """Get coverage trend over time."""
        reports = self._reports[-periods:]

        return {
            "timestamps": [r.timestamp.isoformat() for r in reports],
            "line_coverage": [r.metrics.line_coverage_pct for r in reports],
            "branch_coverage": [r.metrics.branch_coverage_pct for r in reports],
            "function_coverage": [r.metrics.function_coverage_pct for r in reports],
        }

    def clear(self):
        """Clear current coverage data."""
        self._current_files.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracker statistics."""
        return {
            "tracked_files": len(self._current_files),
            "total_reports": len(self._reports),
            "coverage_threshold": self._threshold,
            "critical_paths": len(self._critical_paths),
        }

    def format_report(self, report: CoverageReport) -> str:
        """Format a coverage report for display."""
        lines = [
            "=" * 60,
            f"  COVERAGE REPORT: {report.name}",
            "=" * 60,
            "",
            f"  Report ID: {report.report_id}",
            f"  Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "  METRICS",
            "-" * 60,
            "",
            f"  Files Analyzed: {report.metrics.total_files}",
            "",
            f"  Line Coverage:     {report.metrics.line_coverage_pct:.1f}%",
            f"    ({report.metrics.covered_lines}/{report.metrics.total_lines} lines)",
            "",
            f"  Branch Coverage:   {report.metrics.branch_coverage_pct:.1f}%",
            f"    ({report.metrics.covered_branches}/{report.metrics.total_branches} branches)",
            "",
            f"  Function Coverage: {report.metrics.function_coverage_pct:.1f}%",
            f"    ({report.metrics.covered_functions}/{report.metrics.total_functions} functions)",
            "",
        ]

        if report.trend:
            lines.append("-" * 60)
            lines.append("  TREND (vs previous)")
            lines.append("-" * 60)
            lines.append("")
            for metric, change in report.trend.items():
                symbol = "↑" if change > 0 else "↓" if change < 0 else "→"
                lines.append(f"  {metric}: {symbol} {abs(change):.1f}%")
            lines.append("")

        # Low coverage files
        low_coverage = [f for f in report.files if f.line_coverage < self._threshold]
        if low_coverage:
            lines.append("-" * 60)
            lines.append(f"  LOW COVERAGE FILES (< {self._threshold}%)")
            lines.append("-" * 60)
            lines.append("")
            for f in sorted(low_coverage, key=lambda x: x.line_coverage)[:5]:
                lines.append(f"  {f.file_path}: {f.line_coverage:.1f}%")
            if len(low_coverage) > 5:
                lines.append(f"  ... and {len(low_coverage) - 5} more")
            lines.append("")

        if report.uncovered_critical:
            lines.append("-" * 60)
            lines.append("  ⚠️  UNCOVERED CRITICAL PATHS")
            lines.append("-" * 60)
            lines.append("")
            for path in report.uncovered_critical[:5]:
                lines.append(f"  • {path}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_coverage_tracker(
    coverage_threshold: float = 80.0,
    critical_paths: Optional[List[str]] = None,
) -> CoverageTracker:
    """Create a coverage tracker instance."""
    return CoverageTracker(
        coverage_threshold=coverage_threshold,
        critical_paths=critical_paths,
    )
