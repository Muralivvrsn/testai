"""
TestAI Agent - Matrix Optimizer

Optimizes test matrices to reduce execution time while
maintaining adequate coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from .generator import TestMatrix, MatrixCell, BrowserType, DeviceType


class CoverageStrategy(Enum):
    """Strategies for matrix optimization."""
    FULL = "full"  # All combinations
    PAIRWISE = "pairwise"  # Each pair covered at least once
    RISK_BASED = "risk_based"  # Focus on high-risk combinations
    TIME_BUDGET = "time_budget"  # Fit within time constraint
    CRITICAL_PATH = "critical_path"  # Only critical browsers/devices


@dataclass
class OptimizedMatrix:
    """An optimized test matrix."""
    original_combinations: int
    optimized_combinations: int
    reduction_percentage: float
    cells: List[MatrixCell]
    strategy: CoverageStrategy
    coverage_report: Dict[str, float]
    estimated_duration_ms: int


class MatrixOptimizer:
    """
    Optimizes test matrices for efficiency.

    Strategies:
    - Pairwise: Ensure each pair is covered
    - Risk-based: Prioritize high-risk combinations
    - Time budget: Fit within execution time limit
    - Critical path: Focus on most important configs
    """

    # Risk weights for browsers
    BROWSER_RISK = {
        BrowserType.CHROME: 0.9,   # Most common
        BrowserType.FIREFOX: 0.7,
        BrowserType.SAFARI: 0.8,   # Important for iOS
        BrowserType.EDGE: 0.6,
        BrowserType.IE: 0.4,       # Legacy
        BrowserType.OPERA: 0.3,
    }

    # Risk weights for device types
    DEVICE_RISK = {
        DeviceType.MOBILE: 1.0,    # Most important
        DeviceType.DESKTOP: 0.8,
        DeviceType.TABLET: 0.6,
    }

    def __init__(
        self,
        default_strategy: CoverageStrategy = CoverageStrategy.PAIRWISE,
    ):
        """Initialize the optimizer."""
        self.default_strategy = default_strategy

        # Historical data
        self._failure_rates: Dict[str, float] = {}  # config_key -> rate
        self._test_priorities: Dict[str, int] = {}

    def optimize(
        self,
        matrix: TestMatrix,
        strategy: Optional[CoverageStrategy] = None,
        time_budget_ms: Optional[int] = None,
        min_coverage: float = 0.8,
    ) -> OptimizedMatrix:
        """Optimize the test matrix."""
        strategy = strategy or self.default_strategy

        if strategy == CoverageStrategy.FULL:
            cells = matrix.cells
        elif strategy == CoverageStrategy.PAIRWISE:
            cells = self._pairwise_selection(matrix, min_coverage)
        elif strategy == CoverageStrategy.RISK_BASED:
            cells = self._risk_based_selection(matrix, min_coverage)
        elif strategy == CoverageStrategy.TIME_BUDGET:
            cells = self._time_budget_selection(matrix, time_budget_ms or 3600000)
        elif strategy == CoverageStrategy.CRITICAL_PATH:
            cells = self._critical_path_selection(matrix)
        else:
            cells = matrix.cells

        # Calculate coverage
        coverage = self._calculate_coverage(matrix.cells, cells)

        original = len(matrix.cells)
        optimized = len(cells)
        reduction = ((original - optimized) / original * 100) if original > 0 else 0

        return OptimizedMatrix(
            original_combinations=original,
            optimized_combinations=optimized,
            reduction_percentage=reduction,
            cells=cells,
            strategy=strategy,
            coverage_report=coverage,
            estimated_duration_ms=sum(c.estimated_duration_ms for c in cells),
        )

    def set_failure_rate(self, config_key: str, rate: float):
        """Set historical failure rate for a configuration."""
        self._failure_rates[config_key] = rate

    def set_test_priority(self, test_id: str, priority: int):
        """Set priority for a test."""
        self._test_priorities[test_id] = priority

    def _pairwise_selection(
        self,
        matrix: TestMatrix,
        min_coverage: float,
    ) -> List[MatrixCell]:
        """Select cells ensuring pairwise coverage."""
        selected = []
        covered_pairs: Set[Tuple[str, str]] = set()

        # Group cells by test
        cells_by_test: Dict[str, List[MatrixCell]] = defaultdict(list)
        for cell in matrix.cells:
            cells_by_test[cell.test_id].append(cell)

        # For each test, ensure coverage of browser pairs
        for test_id, cells in cells_by_test.items():
            test_pairs: Set[Tuple[str, str]] = set()

            # Sort by priority
            sorted_cells = sorted(cells, key=lambda c: c.priority)

            for cell in sorted_cells:
                browser_key = f"{cell.browser.browser.value}-{cell.browser.version}"
                device_key = cell.device.name if cell.device else "desktop"

                # Create pairs
                new_pairs = {
                    (test_id, browser_key),
                    (test_id, device_key),
                    (browser_key, device_key),
                }

                # Check if this cell adds new coverage
                if new_pairs - test_pairs:
                    selected.append(cell)
                    test_pairs.update(new_pairs)
                    covered_pairs.update(new_pairs)

        return selected

    def _risk_based_selection(
        self,
        matrix: TestMatrix,
        min_coverage: float,
    ) -> List[MatrixCell]:
        """Select cells based on risk assessment."""
        # Calculate risk score for each cell
        scored_cells = []

        for cell in matrix.cells:
            browser_risk = self.BROWSER_RISK.get(cell.browser.browser, 0.5)
            device_risk = self.DEVICE_RISK.get(
                cell.device.device_type if cell.device else DeviceType.DESKTOP,
                0.5
            )

            # Check historical failure rate
            config_key = self._get_config_key(cell)
            failure_risk = self._failure_rates.get(config_key, 0.5)

            # Test priority
            test_priority = self._test_priorities.get(cell.test_id, 5)
            test_risk = (10 - test_priority) / 10  # Higher priority = higher risk

            # Combined risk score
            risk_score = (
                browser_risk * 0.3 +
                device_risk * 0.2 +
                failure_risk * 0.3 +
                test_risk * 0.2
            )

            scored_cells.append((risk_score, cell))

        # Sort by risk (descending) and select until coverage met
        scored_cells.sort(key=lambda x: -x[0])

        selected = []
        coverage_target = int(len(matrix.cells) * min_coverage)

        for score, cell in scored_cells:
            if len(selected) >= coverage_target:
                break
            selected.append(cell)

        return selected

    def _time_budget_selection(
        self,
        matrix: TestMatrix,
        budget_ms: int,
    ) -> List[MatrixCell]:
        """Select cells to fit within time budget."""
        # Sort by priority (lower is better) then by duration
        sorted_cells = sorted(
            matrix.cells,
            key=lambda c: (c.priority, c.estimated_duration_ms)
        )

        selected = []
        total_duration = 0

        for cell in sorted_cells:
            if total_duration + cell.estimated_duration_ms <= budget_ms:
                selected.append(cell)
                total_duration += cell.estimated_duration_ms

        return selected

    def _critical_path_selection(
        self,
        matrix: TestMatrix,
    ) -> List[MatrixCell]:
        """Select only critical path configurations."""
        # Critical: latest Chrome, Firefox, Safari + mobile
        critical_browsers = {BrowserType.CHROME, BrowserType.FIREFOX, BrowserType.SAFARI}
        critical_devices = {"iPhone 15 Pro", "Galaxy S23", "Desktop 1080p"}

        selected = []

        for cell in matrix.cells:
            is_critical_browser = cell.browser.browser in critical_browsers
            is_latest_version = cell.browser.version in ["120", "latest", "17"]

            is_critical_device = (
                cell.device is None or  # Desktop default
                cell.device.name in critical_devices
            )

            if is_critical_browser and is_latest_version and is_critical_device:
                selected.append(cell)

        return selected

    def _get_config_key(self, cell: MatrixCell) -> str:
        """Get unique key for a configuration."""
        browser_key = f"{cell.browser.browser.value}-{cell.browser.version}"
        device_key = cell.device.name if cell.device else "desktop"
        return f"{browser_key}:{device_key}"

    def _calculate_coverage(
        self,
        original: List[MatrixCell],
        selected: List[MatrixCell],
    ) -> Dict[str, float]:
        """Calculate coverage statistics."""
        # Test coverage
        original_tests = {c.test_id for c in original}
        selected_tests = {c.test_id for c in selected}
        test_coverage = len(selected_tests) / len(original_tests) if original_tests else 1.0

        # Browser coverage
        original_browsers = {c.browser.browser for c in original}
        selected_browsers = {c.browser.browser for c in selected}
        browser_coverage = len(selected_browsers) / len(original_browsers) if original_browsers else 1.0

        # Device coverage
        original_devices = {c.device.name for c in original if c.device}
        selected_devices = {c.device.name for c in selected if c.device}
        device_coverage = len(selected_devices) / len(original_devices) if original_devices else 1.0

        # Version coverage
        original_versions = {(c.browser.browser, c.browser.version) for c in original}
        selected_versions = {(c.browser.browser, c.browser.version) for c in selected}
        version_coverage = len(selected_versions) / len(original_versions) if original_versions else 1.0

        return {
            "test_coverage": test_coverage,
            "browser_coverage": browser_coverage,
            "device_coverage": device_coverage,
            "version_coverage": version_coverage,
            "overall_coverage": (test_coverage + browser_coverage + device_coverage + version_coverage) / 4,
        }

    def suggest_optimization(
        self,
        matrix: TestMatrix,
    ) -> Dict[str, Any]:
        """Suggest optimization strategy based on matrix characteristics."""
        total_cells = len(matrix.cells)
        total_duration = matrix.estimated_total_duration_ms

        suggestions = []

        # Check if matrix is very large
        if total_cells > 100:
            suggestions.append({
                "strategy": CoverageStrategy.PAIRWISE,
                "reason": f"Large matrix ({total_cells} combinations) - pairwise would reduce significantly",
                "estimated_reduction": "40-60%",
            })

        # Check if duration is too long
        if total_duration > 3600000:  # 1 hour
            suggestions.append({
                "strategy": CoverageStrategy.TIME_BUDGET,
                "reason": f"Long duration ({total_duration / 60000:.0f} minutes) - use time budget",
                "recommended_budget_ms": 1800000,  # 30 minutes
            })

        # Check browser diversity
        unique_browsers = len(set(c.browser.browser for c in matrix.cells))
        if unique_browsers > 4:
            suggestions.append({
                "strategy": CoverageStrategy.CRITICAL_PATH,
                "reason": f"Many browsers ({unique_browsers}) - focus on critical path",
            })

        # Check for high-risk tests
        high_priority_tests = sum(
            1 for t in matrix.tests
            if self._test_priorities.get(t, 5) <= 2
        )
        if high_priority_tests > 0:
            suggestions.append({
                "strategy": CoverageStrategy.RISK_BASED,
                "reason": f"{high_priority_tests} high-priority tests - use risk-based selection",
            })

        return {
            "matrix_stats": {
                "total_combinations": total_cells,
                "estimated_duration_minutes": total_duration / 60000,
                "unique_browsers": unique_browsers,
            },
            "suggestions": suggestions,
            "recommended": suggestions[0]["strategy"].value if suggestions else CoverageStrategy.FULL.value,
        }

    def format_result(self, result: OptimizedMatrix) -> str:
        """Format optimization result as readable text."""
        lines = [
            "=" * 60,
            "  MATRIX OPTIMIZATION RESULT",
            "=" * 60,
            "",
            f"  Strategy: {result.strategy.value}",
            f"  Original: {result.original_combinations} combinations",
            f"  Optimized: {result.optimized_combinations} combinations",
            f"  Reduction: {result.reduction_percentage:.1f}%",
            f"  Est. Duration: {result.estimated_duration_ms / 60000:.1f} minutes",
            "",
        ]

        # Coverage breakdown
        lines.extend([
            "-" * 60,
            "  COVERAGE REPORT",
            "-" * 60,
        ])

        for metric, value in result.coverage_report.items():
            bar = "█" * int(value * 20) + "░" * (20 - int(value * 20))
            lines.append(f"  {metric:<20} {bar} {value:.0%}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_matrix_optimizer(
    strategy: CoverageStrategy = CoverageStrategy.PAIRWISE,
) -> MatrixOptimizer:
    """Create a matrix optimizer instance."""
    return MatrixOptimizer(strategy)
