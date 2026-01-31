"""
TestAI Agent - Test Selector

Intelligent test selection based on code changes,
impact analysis, and historical data.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class SelectionStrategy(Enum):
    """Strategies for test selection."""
    ALL = "all"
    CHANGED_ONLY = "changed_only"
    AFFECTED_ONLY = "affected_only"
    RISK_BASED = "risk_based"
    TIME_BASED = "time_based"
    COVERAGE_BASED = "coverage_based"
    HYBRID = "hybrid"


@dataclass
class TestCandidate:
    """A candidate test for selection."""
    test_id: str
    test_name: str
    file_path: str
    suite: str
    duration_sec: float
    last_run: Optional[datetime]
    last_status: Optional[str]
    failure_rate: float
    coverage_files: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SelectionResult:
    """Result of test selection."""
    result_id: str
    strategy: SelectionStrategy
    selected_tests: List[TestCandidate]
    excluded_tests: List[TestCandidate]
    total_duration_sec: float
    coverage_estimate: float
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestSelector:
    """
    Selects tests based on various strategies.

    Features:
    - Impact-based selection
    - Risk-based prioritization
    - Time-boxed selection
    - Coverage optimization
    """

    def __init__(
        self,
        default_strategy: SelectionStrategy = SelectionStrategy.AFFECTED_ONLY,
        time_budget_sec: Optional[float] = None,
        min_coverage_pct: float = 80.0,
    ):
        """Initialize the selector."""
        self._default_strategy = default_strategy
        self._time_budget = time_budget_sec
        self._min_coverage = min_coverage_pct
        self._candidates: Dict[str, TestCandidate] = {}
        self._changed_files: Set[str] = set()
        self._file_test_map: Dict[str, Set[str]] = {}
        self._result_counter = 0
        self._candidate_counter = 0

    def register_test(
        self,
        test_name: str,
        file_path: str,
        suite: str = "default",
        duration_sec: float = 1.0,
        coverage_files: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        failure_rate: float = 0.0,
    ) -> TestCandidate:
        """Register a test candidate."""
        self._candidate_counter += 1
        test_id = f"TC-{self._candidate_counter:05d}"

        candidate = TestCandidate(
            test_id=test_id,
            test_name=test_name,
            file_path=file_path,
            suite=suite,
            duration_sec=duration_sec,
            last_run=None,
            last_status=None,
            failure_rate=failure_rate,
            coverage_files=coverage_files or [],
            tags=tags or [],
        )

        self._candidates[test_id] = candidate

        # Build coverage map
        for covered_file in candidate.coverage_files:
            if covered_file not in self._file_test_map:
                self._file_test_map[covered_file] = set()
            self._file_test_map[covered_file].add(test_id)

        return candidate

    def set_changed_files(self, files: List[str]) -> None:
        """Set the list of changed files."""
        self._changed_files = set(files)

    def select(
        self,
        strategy: Optional[SelectionStrategy] = None,
        time_budget_sec: Optional[float] = None,
    ) -> SelectionResult:
        """Select tests based on strategy."""
        self._result_counter += 1
        result_id = f"SEL-{self._result_counter:05d}"

        strategy = strategy or self._default_strategy
        budget = time_budget_sec or self._time_budget

        if strategy == SelectionStrategy.ALL:
            selected, excluded = self._select_all()
            reason = "Selected all tests"
        elif strategy == SelectionStrategy.CHANGED_ONLY:
            selected, excluded = self._select_changed_only()
            reason = f"Selected tests in changed files ({len(self._changed_files)} files changed)"
        elif strategy == SelectionStrategy.AFFECTED_ONLY:
            selected, excluded = self._select_affected()
            reason = f"Selected tests affected by changes ({len(self._changed_files)} files changed)"
        elif strategy == SelectionStrategy.RISK_BASED:
            selected, excluded = self._select_risk_based()
            reason = "Selected high-risk tests (high failure rate or recent failures)"
        elif strategy == SelectionStrategy.TIME_BASED:
            selected, excluded = self._select_time_based(budget or 300)
            reason = f"Selected tests within time budget ({budget}s)"
        elif strategy == SelectionStrategy.COVERAGE_BASED:
            selected, excluded = self._select_coverage_based()
            reason = f"Selected for minimum {self._min_coverage}% coverage"
        elif strategy == SelectionStrategy.HYBRID:
            selected, excluded = self._select_hybrid(budget)
            reason = "Hybrid selection: affected + risk + time"
        else:
            selected, excluded = self._select_all()
            reason = "Fallback to all tests"

        total_duration = sum(t.duration_sec for t in selected)

        # Estimate coverage
        covered_files: Set[str] = set()
        for test in selected:
            covered_files.update(test.coverage_files)
        all_files: Set[str] = set()
        for test in self._candidates.values():
            all_files.update(test.coverage_files)
        coverage_est = (len(covered_files) / len(all_files) * 100) if all_files else 100.0

        return SelectionResult(
            result_id=result_id,
            strategy=strategy,
            selected_tests=selected,
            excluded_tests=excluded,
            total_duration_sec=total_duration,
            coverage_estimate=round(coverage_est, 1),
            reason=reason,
        )

    def _select_all(self) -> tuple:
        """Select all tests."""
        return list(self._candidates.values()), []

    def _select_changed_only(self) -> tuple:
        """Select tests in changed files only."""
        selected = []
        excluded = []

        for candidate in self._candidates.values():
            if candidate.file_path in self._changed_files:
                selected.append(candidate)
            else:
                excluded.append(candidate)

        return selected, excluded

    def _select_affected(self) -> tuple:
        """Select tests affected by changed files."""
        affected_test_ids: Set[str] = set()

        # Find tests that cover changed files
        for changed_file in self._changed_files:
            if changed_file in self._file_test_map:
                affected_test_ids.update(self._file_test_map[changed_file])

        # Also include tests in changed files
        for candidate in self._candidates.values():
            if candidate.file_path in self._changed_files:
                affected_test_ids.add(candidate.test_id)

        selected = [
            self._candidates[tid] for tid in affected_test_ids
            if tid in self._candidates
        ]
        excluded = [
            c for c in self._candidates.values()
            if c.test_id not in affected_test_ids
        ]

        return selected, excluded

    def _select_risk_based(self) -> tuple:
        """Select high-risk tests."""
        # Sort by failure rate (descending)
        sorted_tests = sorted(
            self._candidates.values(),
            key=lambda t: t.failure_rate,
            reverse=True,
        )

        # Select top 30% or tests with >5% failure rate
        threshold = max(len(sorted_tests) * 0.3, 1)
        selected = []
        excluded = []

        for i, test in enumerate(sorted_tests):
            if i < threshold or test.failure_rate > 5.0:
                selected.append(test)
            else:
                excluded.append(test)

        return selected, excluded

    def _select_time_based(self, budget_sec: float) -> tuple:
        """Select tests within time budget."""
        # Sort by duration (ascending) to maximize test count
        sorted_tests = sorted(
            self._candidates.values(),
            key=lambda t: t.duration_sec,
        )

        selected = []
        excluded = []
        total_time = 0.0

        for test in sorted_tests:
            if total_time + test.duration_sec <= budget_sec:
                selected.append(test)
                total_time += test.duration_sec
            else:
                excluded.append(test)

        return selected, excluded

    def _select_coverage_based(self) -> tuple:
        """Select tests to achieve minimum coverage."""
        all_files: Set[str] = set()
        for test in self._candidates.values():
            all_files.update(test.coverage_files)

        target_file_count = len(all_files) * (self._min_coverage / 100)

        # Greedy selection by coverage contribution
        covered_files: Set[str] = set()
        selected = []
        remaining = list(self._candidates.values())

        while len(covered_files) < target_file_count and remaining:
            # Find test that adds most coverage
            best_test = None
            best_contribution = 0

            for test in remaining:
                new_files = set(test.coverage_files) - covered_files
                if len(new_files) > best_contribution:
                    best_contribution = len(new_files)
                    best_test = test

            if best_test:
                selected.append(best_test)
                covered_files.update(best_test.coverage_files)
                remaining.remove(best_test)
            else:
                break

        excluded = remaining
        return selected, excluded

    def _select_hybrid(self, budget_sec: Optional[float]) -> tuple:
        """Hybrid selection combining multiple strategies."""
        # Start with affected tests
        affected, _ = self._select_affected()
        affected_ids = {t.test_id for t in affected}

        # Add high-risk tests
        risk_based, _ = self._select_risk_based()
        for test in risk_based:
            if test.test_id not in affected_ids:
                affected.append(test)
                affected_ids.add(test.test_id)

        # Apply time budget if specified
        if budget_sec:
            affected = sorted(affected, key=lambda t: t.duration_sec)
            selected = []
            total_time = 0.0
            for test in affected:
                if total_time + test.duration_sec <= budget_sec:
                    selected.append(test)
                    total_time += test.duration_sec
        else:
            selected = affected

        excluded = [
            c for c in self._candidates.values()
            if c.test_id not in {t.test_id for t in selected}
        ]

        return selected, excluded

    def get_candidate(self, test_id: str) -> Optional[TestCandidate]:
        """Get a test candidate by ID."""
        return self._candidates.get(test_id)

    def list_candidates(self) -> List[TestCandidate]:
        """List all test candidates."""
        return list(self._candidates.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get selector statistics."""
        total_duration = sum(c.duration_sec for c in self._candidates.values())
        suites = set(c.suite for c in self._candidates.values())

        return {
            "total_candidates": len(self._candidates),
            "total_duration_sec": round(total_duration, 2),
            "suites": len(suites),
            "changed_files": len(self._changed_files),
            "mapped_files": len(self._file_test_map),
        }

    def format_result(self, result: SelectionResult) -> str:
        """Format a selection result for display."""
        lines = [
            "=" * 55,
            f"  TEST SELECTION: {result.strategy.value}",
            "=" * 55,
            "",
            f"  ID: {result.result_id}",
            f"  Selected: {len(result.selected_tests)} tests",
            f"  Excluded: {len(result.excluded_tests)} tests",
            f"  Duration: {result.total_duration_sec:.1f}s",
            f"  Coverage: {result.coverage_estimate}%",
            "",
            f"  Reason: {result.reason}",
            "",
            "-" * 55,
            "  SELECTED TESTS",
            "-" * 55,
            "",
        ]

        for test in result.selected_tests[:10]:
            lines.append(f"  • {test.test_name} ({test.duration_sec:.1f}s)")

        if len(result.selected_tests) > 10:
            lines.append(f"  ... and {len(result.selected_tests) - 10} more")

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_test_selector(
    default_strategy: SelectionStrategy = SelectionStrategy.AFFECTED_ONLY,
    time_budget_sec: Optional[float] = None,
    min_coverage_pct: float = 80.0,
) -> TestSelector:
    """Create a test selector instance."""
    return TestSelector(
        default_strategy=default_strategy,
        time_budget_sec=time_budget_sec,
        min_coverage_pct=min_coverage_pct,
    )
