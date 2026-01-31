"""
TestAI Agent - Test Prioritizer

Intelligent test prioritization based on
failure probability, risk, and business impact.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class PriorityFactor(Enum):
    """Factors that influence test priority."""
    FAILURE_HISTORY = "failure_history"
    RECENT_CHANGE = "recent_change"
    CODE_COMPLEXITY = "code_complexity"
    BUSINESS_CRITICAL = "business_critical"
    FLAKINESS = "flakiness"
    DURATION = "duration"
    COVERAGE = "coverage"


@dataclass
class PriorityScore:
    """Priority score for a test."""
    test_id: str
    test_name: str
    total_score: float
    factor_scores: Dict[str, float]
    rank: int
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestEntry:
    """A test entry for prioritization."""
    test_id: str
    test_name: str
    suite: str
    duration_sec: float
    failure_count: int
    run_count: int
    last_failure: Optional[datetime]
    is_flaky: bool
    is_critical: bool
    code_changes: int
    complexity_score: float
    coverage_contribution: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PrioritizationResult:
    """Result of test prioritization."""
    result_id: str
    scores: List[PriorityScore]
    factors_used: List[PriorityFactor]
    generated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestPrioritizer:
    """
    Prioritizes tests based on multiple factors.

    Features:
    - Multi-factor scoring
    - Configurable weights
    - Failure probability
    - Business impact
    """

    def __init__(
        self,
        weights: Optional[Dict[PriorityFactor, float]] = None,
    ):
        """Initialize the prioritizer."""
        self._weights = weights or {
            PriorityFactor.FAILURE_HISTORY: 3.0,
            PriorityFactor.RECENT_CHANGE: 2.5,
            PriorityFactor.BUSINESS_CRITICAL: 2.0,
            PriorityFactor.CODE_COMPLEXITY: 1.5,
            PriorityFactor.FLAKINESS: 1.0,
            PriorityFactor.COVERAGE: 1.0,
            PriorityFactor.DURATION: 0.5,
        }
        self._entries: Dict[str, TestEntry] = {}
        self._results: List[PrioritizationResult] = []
        self._entry_counter = 0
        self._result_counter = 0

    def add_test(
        self,
        test_name: str,
        suite: str = "default",
        duration_sec: float = 1.0,
        failure_count: int = 0,
        run_count: int = 0,
        last_failure: Optional[datetime] = None,
        is_flaky: bool = False,
        is_critical: bool = False,
        code_changes: int = 0,
        complexity_score: float = 1.0,
        coverage_contribution: float = 0.0,
    ) -> TestEntry:
        """Add a test for prioritization."""
        self._entry_counter += 1
        test_id = f"PRI-{self._entry_counter:05d}"

        entry = TestEntry(
            test_id=test_id,
            test_name=test_name,
            suite=suite,
            duration_sec=duration_sec,
            failure_count=failure_count,
            run_count=run_count,
            last_failure=last_failure,
            is_flaky=is_flaky,
            is_critical=is_critical,
            code_changes=code_changes,
            complexity_score=complexity_score,
            coverage_contribution=coverage_contribution,
        )

        self._entries[test_id] = entry
        return entry

    def set_weight(self, factor: PriorityFactor, weight: float) -> None:
        """Set weight for a factor."""
        self._weights[factor] = weight

    def prioritize(
        self,
        factors: Optional[List[PriorityFactor]] = None,
    ) -> PrioritizationResult:
        """Prioritize all registered tests."""
        self._result_counter += 1
        result_id = f"PRIO-{self._result_counter:05d}"

        factors = factors or list(self._weights.keys())

        scores = []
        for entry in self._entries.values():
            score = self._calculate_score(entry, factors)
            scores.append(score)

        # Sort by total score (descending)
        scores.sort(key=lambda s: s.total_score, reverse=True)

        # Assign ranks
        for i, score in enumerate(scores):
            score.rank = i + 1

        result = PrioritizationResult(
            result_id=result_id,
            scores=scores,
            factors_used=factors,
            generated_at=datetime.now(),
        )

        self._results.append(result)
        return result

    def _calculate_score(
        self,
        entry: TestEntry,
        factors: List[PriorityFactor],
    ) -> PriorityScore:
        """Calculate priority score for a test."""
        factor_scores: Dict[str, float] = {}
        total = 0.0
        reasons = []

        for factor in factors:
            weight = self._weights.get(factor, 1.0)
            raw_score = self._get_factor_score(entry, factor)
            weighted = raw_score * weight
            factor_scores[factor.value] = round(weighted, 2)
            total += weighted

            if weighted > 1.0:
                reasons.append(f"{factor.value}: {weighted:.1f}")

        reason = ", ".join(reasons[:3]) if reasons else "No significant factors"

        return PriorityScore(
            test_id=entry.test_id,
            test_name=entry.test_name,
            total_score=round(total, 2),
            factor_scores=factor_scores,
            rank=0,  # Will be set after sorting
            reason=reason,
        )

    def _get_factor_score(
        self,
        entry: TestEntry,
        factor: PriorityFactor,
    ) -> float:
        """Get raw score for a factor."""
        if factor == PriorityFactor.FAILURE_HISTORY:
            if entry.run_count == 0:
                return 0.0
            failure_rate = entry.failure_count / entry.run_count
            return min(failure_rate * 10, 10.0)

        elif factor == PriorityFactor.RECENT_CHANGE:
            if entry.code_changes == 0:
                return 0.0
            return min(entry.code_changes * 2, 10.0)

        elif factor == PriorityFactor.BUSINESS_CRITICAL:
            return 10.0 if entry.is_critical else 0.0

        elif factor == PriorityFactor.CODE_COMPLEXITY:
            return min(entry.complexity_score * 2, 10.0)

        elif factor == PriorityFactor.FLAKINESS:
            return 5.0 if entry.is_flaky else 0.0

        elif factor == PriorityFactor.COVERAGE:
            return min(entry.coverage_contribution * 10, 10.0)

        elif factor == PriorityFactor.DURATION:
            # Shorter tests score higher (inverse)
            if entry.duration_sec <= 0:
                return 0.0
            return max(0, 10 - min(entry.duration_sec, 10))

        return 0.0

    def get_top_priority(
        self,
        n: int = 10,
        result: Optional[PrioritizationResult] = None,
    ) -> List[PriorityScore]:
        """Get top N priority tests."""
        if result:
            return result.scores[:n]

        if not self._results:
            return []

        return self._results[-1].scores[:n]

    def get_test(self, test_id: str) -> Optional[TestEntry]:
        """Get a test entry by ID."""
        return self._entries.get(test_id)

    def list_tests(self) -> List[TestEntry]:
        """List all test entries."""
        return list(self._entries.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get prioritizer statistics."""
        critical_count = sum(1 for e in self._entries.values() if e.is_critical)
        flaky_count = sum(1 for e in self._entries.values() if e.is_flaky)

        return {
            "total_tests": len(self._entries),
            "total_results": len(self._results),
            "critical_tests": critical_count,
            "flaky_tests": flaky_count,
            "weights": {f.value: w for f, w in self._weights.items()},
        }

    def format_result(self, result: PrioritizationResult) -> str:
        """Format a prioritization result for display."""
        lines = [
            "=" * 55,
            f"  TEST PRIORITIZATION",
            "=" * 55,
            "",
            f"  ID: {result.result_id}",
            f"  Tests Ranked: {len(result.scores)}",
            f"  Factors: {len(result.factors_used)}",
            "",
            "-" * 55,
            "  TOP PRIORITY TESTS",
            "-" * 55,
            "",
        ]

        for score in result.scores[:10]:
            lines.append(
                f"  #{score.rank} {score.test_name} "
                f"(score: {score.total_score:.1f})"
            )
            lines.append(f"      {score.reason}")

        if len(result.scores) > 10:
            lines.append(f"  ... and {len(result.scores) - 10} more")

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_test_prioritizer(
    weights: Optional[Dict[PriorityFactor, float]] = None,
) -> TestPrioritizer:
    """Create a test prioritizer instance."""
    return TestPrioritizer(weights=weights)
