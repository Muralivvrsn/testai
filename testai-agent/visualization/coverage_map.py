"""
TestAI Agent - Coverage Map Generator

Creates visual coverage heatmaps showing test coverage
across features and components.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict


class CoverageLevel(Enum):
    """Coverage levels for heatmap."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    COMPLETE = "complete"


@dataclass
class CoverageCell:
    """A single cell in the coverage map."""
    row_id: str
    col_id: str
    test_count: int
    coverage_level: CoverageLevel
    tests: List[str]
    color: str = "#ffffff"


@dataclass
class CoverageHeatmap:
    """A coverage heatmap visualization."""
    rows: List[str]  # Features/components
    cols: List[str]  # Test categories/types
    cells: Dict[Tuple[str, str], CoverageCell]
    summary: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)


class CoverageMapGenerator:
    """
    Generates coverage heatmaps for test suites.

    Visualizes:
    - Feature vs test type coverage
    - Component vs test category coverage
    - Risk vs test priority coverage
    """

    # Colors for coverage levels
    COVERAGE_COLORS = {
        CoverageLevel.NONE: "#fee2e2",      # Red-100
        CoverageLevel.LOW: "#fef3c7",       # Amber-100
        CoverageLevel.MEDIUM: "#fef9c3",    # Yellow-100
        CoverageLevel.HIGH: "#d1fae5",      # Emerald-100
        CoverageLevel.COMPLETE: "#a7f3d0",  # Emerald-200
    }

    # Thresholds for coverage levels
    THRESHOLDS = {
        0: CoverageLevel.NONE,
        1: CoverageLevel.LOW,
        3: CoverageLevel.MEDIUM,
        5: CoverageLevel.HIGH,
        10: CoverageLevel.COMPLETE,
    }

    def __init__(
        self,
        custom_thresholds: Optional[Dict[int, CoverageLevel]] = None,
    ):
        """Initialize the coverage map generator."""
        self.thresholds = custom_thresholds or self.THRESHOLDS

    def generate_feature_coverage(
        self,
        tests: List[Dict[str, Any]],
        features: List[str],
        categories: Optional[List[str]] = None,
    ) -> CoverageHeatmap:
        """Generate coverage map for features vs test categories."""
        # Auto-detect categories if not provided
        if categories is None:
            categories = list(set(
                t.get("category", "uncategorized")
                for t in tests
            ))
            categories.sort()

        # Build coverage matrix
        coverage: Dict[Tuple[str, str], List[str]] = defaultdict(list)

        for test in tests:
            test_id = test.get("id", "unknown")
            category = test.get("category", "uncategorized")
            test_features = test.get("features", [])

            # Also check title/description for feature mentions
            title = test.get("title", "").lower()
            description = test.get("description", "").lower()

            for feature in features:
                feature_lower = feature.lower()
                if (feature in test_features or
                    feature_lower in title or
                    feature_lower in description):
                    coverage[(feature, category)].append(test_id)

        # Create cells
        cells = {}
        for feature in features:
            for category in categories:
                key = (feature, category)
                test_list = coverage.get(key, [])
                level = self._count_to_level(len(test_list))

                cells[key] = CoverageCell(
                    row_id=feature,
                    col_id=category,
                    test_count=len(test_list),
                    coverage_level=level,
                    tests=test_list,
                    color=self.COVERAGE_COLORS[level],
                )

        # Calculate summary
        summary = self._calculate_summary(features, categories, cells)

        return CoverageHeatmap(
            rows=features,
            cols=categories,
            cells=cells,
            summary=summary,
        )

    def generate_component_coverage(
        self,
        tests: List[Dict[str, Any]],
        components: List[str],
    ) -> CoverageHeatmap:
        """Generate coverage map for components vs test types."""
        # Define test types
        test_types = ["functional", "integration", "unit", "e2e", "security", "performance"]

        # Build coverage matrix
        coverage: Dict[Tuple[str, str], List[str]] = defaultdict(list)

        for test in tests:
            test_id = test.get("id", "unknown")
            test_type = self._detect_test_type(test)
            component = test.get("component", self._detect_component(test, components))

            if component and component in components:
                coverage[(component, test_type)].append(test_id)

        # Create cells
        cells = {}
        for component in components:
            for test_type in test_types:
                key = (component, test_type)
                test_list = coverage.get(key, [])
                level = self._count_to_level(len(test_list))

                cells[key] = CoverageCell(
                    row_id=component,
                    col_id=test_type,
                    test_count=len(test_list),
                    coverage_level=level,
                    tests=test_list,
                    color=self.COVERAGE_COLORS[level],
                )

        # Calculate summary
        summary = self._calculate_summary(components, test_types, cells)

        return CoverageHeatmap(
            rows=components,
            cols=test_types,
            cells=cells,
            summary=summary,
        )

    def generate_risk_priority_map(
        self,
        tests: List[Dict[str, Any]],
    ) -> CoverageHeatmap:
        """Generate coverage map for risk areas vs test priorities."""
        risk_areas = ["critical", "high", "medium", "low"]
        priorities = ["critical", "high", "medium", "low"]

        # Build coverage matrix
        coverage: Dict[Tuple[str, str], List[str]] = defaultdict(list)

        for test in tests:
            test_id = test.get("id", "unknown")
            priority = test.get("priority", "medium").lower()
            risk_area = test.get("risk_area", priority)  # Default to priority

            if risk_area in risk_areas and priority in priorities:
                coverage[(risk_area, priority)].append(test_id)

        # Create cells
        cells = {}
        for risk in risk_areas:
            for priority in priorities:
                key = (risk, priority)
                test_list = coverage.get(key, [])
                level = self._count_to_level(len(test_list))

                cells[key] = CoverageCell(
                    row_id=risk,
                    col_id=priority,
                    test_count=len(test_list),
                    coverage_level=level,
                    tests=test_list,
                    color=self.COVERAGE_COLORS[level],
                )

        # Calculate summary
        summary = self._calculate_summary(risk_areas, priorities, cells)

        return CoverageHeatmap(
            rows=risk_areas,
            cols=priorities,
            cells=cells,
            summary=summary,
        )

    def find_gaps(
        self,
        heatmap: CoverageHeatmap,
    ) -> List[Tuple[str, str, CoverageLevel]]:
        """Find coverage gaps in the heatmap."""
        gaps = []

        for (row, col), cell in heatmap.cells.items():
            if cell.coverage_level in {CoverageLevel.NONE, CoverageLevel.LOW}:
                gaps.append((row, col, cell.coverage_level))

        # Sort by severity (NONE before LOW)
        gaps.sort(key=lambda g: (0 if g[2] == CoverageLevel.NONE else 1, g[0], g[1]))

        return gaps

    def suggest_tests(
        self,
        heatmap: CoverageHeatmap,
        max_suggestions: int = 10,
    ) -> List[Dict[str, Any]]:
        """Suggest tests to improve coverage."""
        suggestions = []
        gaps = self.find_gaps(heatmap)

        for row, col, level in gaps[:max_suggestions]:
            priority = "high" if level == CoverageLevel.NONE else "medium"

            suggestions.append({
                "feature": row,
                "category": col,
                "current_level": level.value,
                "priority": priority,
                "suggestion": f"Add {col} tests for {row}",
            })

        return suggestions

    def _count_to_level(self, count: int) -> CoverageLevel:
        """Convert test count to coverage level."""
        level = CoverageLevel.NONE

        for threshold, coverage_level in sorted(self.thresholds.items()):
            if count >= threshold:
                level = coverage_level
            else:
                break

        return level

    def _detect_test_type(self, test: Dict[str, Any]) -> str:
        """Detect test type from metadata."""
        # Check explicit type
        if "type" in test:
            return test["type"].lower()

        # Check category
        category = test.get("category", "").lower()
        if category in {"unit", "integration", "e2e", "security", "performance"}:
            return category

        # Infer from title
        title = test.get("title", "").lower()
        if "unit" in title:
            return "unit"
        if "integration" in title or "api" in title:
            return "integration"
        if "e2e" in title or "end-to-end" in title or "flow" in title:
            return "e2e"
        if "security" in title or "injection" in title or "xss" in title:
            return "security"
        if "performance" in title or "load" in title:
            return "performance"

        return "functional"

    def _detect_component(
        self,
        test: Dict[str, Any],
        components: List[str],
    ) -> Optional[str]:
        """Detect which component a test belongs to."""
        title = test.get("title", "").lower()
        description = test.get("description", "").lower()

        for component in components:
            if component.lower() in title or component.lower() in description:
                return component

        return None

    def _calculate_summary(
        self,
        rows: List[str],
        cols: List[str],
        cells: Dict[Tuple[str, str], CoverageCell],
    ) -> Dict[str, Any]:
        """Calculate coverage summary statistics."""
        total_cells = len(rows) * len(cols)
        covered_cells = sum(
            1 for cell in cells.values()
            if cell.coverage_level not in {CoverageLevel.NONE}
        )
        fully_covered = sum(
            1 for cell in cells.values()
            if cell.coverage_level in {CoverageLevel.HIGH, CoverageLevel.COMPLETE}
        )

        total_tests = sum(cell.test_count for cell in cells.values())

        # Row coverage
        row_coverage = {}
        for row in rows:
            row_cells = [cells[(row, col)] for col in cols if (row, col) in cells]
            covered = sum(1 for c in row_cells if c.coverage_level != CoverageLevel.NONE)
            row_coverage[row] = covered / len(cols) if cols else 0

        # Column coverage
        col_coverage = {}
        for col in cols:
            col_cells = [cells[(row, col)] for row in rows if (row, col) in cells]
            covered = sum(1 for c in col_cells if c.coverage_level != CoverageLevel.NONE)
            col_coverage[col] = covered / len(rows) if rows else 0

        return {
            "total_cells": total_cells,
            "covered_cells": covered_cells,
            "coverage_percentage": covered_cells / total_cells if total_cells > 0 else 0,
            "fully_covered_cells": fully_covered,
            "total_tests": total_tests,
            "row_coverage": row_coverage,
            "col_coverage": col_coverage,
            "gaps": total_cells - covered_cells,
        }

    def to_ascii(self, heatmap: CoverageHeatmap) -> str:
        """Render heatmap as ASCII table."""
        # Calculate column widths
        col_width = max(12, max(len(c) for c in heatmap.cols) + 2) if heatmap.cols else 12
        row_width = max(15, max(len(r) for r in heatmap.rows) + 2) if heatmap.rows else 15

        lines = []

        # Header row
        header = " " * row_width + "|"
        for col in heatmap.cols:
            header += f" {col[:col_width-2]:^{col_width-2}} |"
        lines.append(header)
        lines.append("-" * len(header))

        # Data rows
        level_chars = {
            CoverageLevel.NONE: "  -  ",
            CoverageLevel.LOW: " [*] ",
            CoverageLevel.MEDIUM: "[**] ",
            CoverageLevel.HIGH: "[***]",
            CoverageLevel.COMPLETE: "[++++]",
        }

        for row in heatmap.rows:
            line = f" {row[:row_width-2]:<{row_width-2}} |"
            for col in heatmap.cols:
                cell = heatmap.cells.get((row, col))
                if cell:
                    char = level_chars.get(cell.coverage_level, "  ?  ")
                    count_str = f"{cell.test_count:^{col_width-2}}"
                    line += f" {count_str} |"
                else:
                    line += f" {'':^{col_width-2}} |"
            lines.append(line)

        return "\n".join(lines)

    def to_html(self, heatmap: CoverageHeatmap) -> str:
        """Render heatmap as HTML table."""
        html = ['<table class="coverage-heatmap" style="border-collapse: collapse;">']

        # Header row
        html.append("<tr>")
        html.append('<th style="border: 1px solid #ddd; padding: 8px;"></th>')
        for col in heatmap.cols:
            html.append(f'<th style="border: 1px solid #ddd; padding: 8px;">{col}</th>')
        html.append("</tr>")

        # Data rows
        for row in heatmap.rows:
            html.append("<tr>")
            html.append(f'<th style="border: 1px solid #ddd; padding: 8px; text-align: left;">{row}</th>')
            for col in heatmap.cols:
                cell = heatmap.cells.get((row, col))
                if cell:
                    color = cell.color
                    count = cell.test_count
                    title = f"{len(cell.tests)} tests: {', '.join(cell.tests[:5])}"
                    if len(cell.tests) > 5:
                        title += f" and {len(cell.tests) - 5} more"
                    html.append(
                        f'<td style="border: 1px solid #ddd; padding: 8px; '
                        f'background-color: {color}; text-align: center;" '
                        f'title="{title}">{count}</td>'
                    )
                else:
                    html.append('<td style="border: 1px solid #ddd; padding: 8px;">-</td>')
            html.append("</tr>")

        html.append("</table>")
        return "\n".join(html)

    def format_summary(self, heatmap: CoverageHeatmap) -> str:
        """Format heatmap summary as readable text."""
        summary = heatmap.summary

        lines = [
            "=" * 60,
            "  COVERAGE HEATMAP SUMMARY",
            "=" * 60,
            "",
            f"  Total Tests: {summary['total_tests']}",
            f"  Coverage: {summary['coverage_percentage']:.1%}",
            f"  Covered Cells: {summary['covered_cells']}/{summary['total_cells']}",
            f"  Gaps: {summary['gaps']}",
            "",
        ]

        # Row coverage
        lines.extend([
            "-" * 60,
            "  ROW COVERAGE (Features/Components)",
            "-" * 60,
        ])
        for row, pct in sorted(summary['row_coverage'].items(), key=lambda x: -x[1]):
            bar = "█" * int(pct * 20) + "░" * (20 - int(pct * 20))
            lines.append(f"  {row[:20]:<20} {bar} {pct:.0%}")

        # Column coverage
        lines.extend([
            "",
            "-" * 60,
            "  COLUMN COVERAGE (Categories/Types)",
            "-" * 60,
        ])
        for col, pct in sorted(summary['col_coverage'].items(), key=lambda x: -x[1]):
            bar = "█" * int(pct * 20) + "░" * (20 - int(pct * 20))
            lines.append(f"  {col[:20]:<20} {bar} {pct:.0%}")

        # Gaps
        gaps = self.find_gaps(heatmap)
        if gaps:
            lines.extend([
                "",
                "-" * 60,
                "  COVERAGE GAPS",
                "-" * 60,
            ])
            for row, col, level in gaps[:10]:
                icon = "🔴" if level == CoverageLevel.NONE else "🟡"
                lines.append(f"  {icon} {row} × {col}")
            if len(gaps) > 10:
                lines.append(f"  ... and {len(gaps) - 10} more gaps")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_coverage_map_generator(
    custom_thresholds: Optional[Dict[int, CoverageLevel]] = None,
) -> CoverageMapGenerator:
    """Create a coverage map generator instance."""
    return CoverageMapGenerator(custom_thresholds)
