"""
TestAI Agent - Test Optimizer

Optimizes test execution using ML-based strategies
for maximum efficiency and coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import math


class OptimizationStrategy(Enum):
    """Test optimization strategies."""
    RISK_BASED = "risk_based"
    COVERAGE_BASED = "coverage_based"
    TIME_BASED = "time_based"
    CHANGE_BASED = "change_based"
    HYBRID = "hybrid"


class OptimizationType(Enum):
    """Types of optimizations."""
    REORDER = "reorder"
    SKIP = "skip"
    PARALLELIZE = "parallelize"
    MERGE = "merge"
    SPLIT = "split"
    PRIORITIZE = "prioritize"


@dataclass
class OptimizationResult:
    """Result of test optimization."""
    strategy: OptimizationStrategy
    optimization_type: OptimizationType
    original_tests: List[str]
    optimized_tests: List[str]
    skipped_tests: List[str]
    estimated_time_saved_ms: int
    coverage_impact: float
    confidence: float
    recommendations: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestInfo:
    """Information about a test for optimization."""
    test_id: str
    name: str
    duration_ms: int
    failure_probability: float
    coverage: Set[str]  # Set of covered features/files
    dependencies: List[str]  # Other tests this depends on
    last_run: Optional[datetime] = None
    last_status: str = "unknown"
    priority: int = 5
    tags: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)


@dataclass
class OptimizationConfig:
    """Configuration for optimization."""
    time_budget_ms: Optional[int] = None
    min_coverage: float = 0.8
    max_skip_rate: float = 0.3
    risk_threshold: float = 0.3
    parallel_groups: int = 4
    prefer_fast_tests: bool = True


class TestOptimizer:
    """
    Optimizes test execution order and selection.

    Features:
    - Risk-based prioritization
    - Coverage optimization
    - Time budget management
    - Parallel grouping
    """

    def __init__(self, config: Optional[OptimizationConfig] = None):
        """Initialize the test optimizer."""
        self.config = config or OptimizationConfig()
        self._tests: Dict[str, TestInfo] = {}
        self._optimization_history: List[OptimizationResult] = []

    def register_test(self, test: TestInfo):
        """Register a test for optimization."""
        self._tests[test.test_id] = test

    def register_tests(self, tests: List[TestInfo]):
        """Register multiple tests."""
        for test in tests:
            self.register_test(test)

    def optimize(
        self,
        strategy: OptimizationStrategy = OptimizationStrategy.HYBRID,
        test_ids: Optional[List[str]] = None,
    ) -> OptimizationResult:
        """Optimize test selection and ordering."""
        # Get tests to optimize
        if test_ids:
            tests = [self._tests[tid] for tid in test_ids if tid in self._tests]
        else:
            tests = list(self._tests.values())

        if not tests:
            return OptimizationResult(
                strategy=strategy,
                optimization_type=OptimizationType.REORDER,
                original_tests=[],
                optimized_tests=[],
                skipped_tests=[],
                estimated_time_saved_ms=0,
                coverage_impact=0,
                confidence=0,
                recommendations=[],
            )

        # Apply strategy
        if strategy == OptimizationStrategy.RISK_BASED:
            result = self._optimize_risk_based(tests)
        elif strategy == OptimizationStrategy.COVERAGE_BASED:
            result = self._optimize_coverage_based(tests)
        elif strategy == OptimizationStrategy.TIME_BASED:
            result = self._optimize_time_based(tests)
        elif strategy == OptimizationStrategy.CHANGE_BASED:
            result = self._optimize_change_based(tests)
        else:
            result = self._optimize_hybrid(tests)

        self._optimization_history.append(result)
        return result

    def _optimize_risk_based(self, tests: List[TestInfo]) -> OptimizationResult:
        """Prioritize tests by failure risk."""
        # Sort by failure probability (highest first)
        sorted_tests = sorted(
            tests,
            key=lambda t: t.failure_probability,
            reverse=True,
        )

        optimized_ids = [t.test_id for t in sorted_tests]
        skipped = []

        # Optionally skip low-risk tests if over time budget
        if self.config.time_budget_ms:
            total_time = 0
            final_list = []
            for test in sorted_tests:
                if total_time + test.duration_ms <= self.config.time_budget_ms:
                    final_list.append(test.test_id)
                    total_time += test.duration_ms
                elif test.failure_probability < self.config.risk_threshold:
                    skipped.append(test.test_id)
                else:
                    final_list.append(test.test_id)
                    total_time += test.duration_ms

            optimized_ids = final_list

        # Calculate time saved
        original_order = [t.test_id for t in tests]
        time_saved = self._estimate_time_saved(tests, optimized_ids)

        return OptimizationResult(
            strategy=OptimizationStrategy.RISK_BASED,
            optimization_type=OptimizationType.PRIORITIZE,
            original_tests=original_order,
            optimized_tests=optimized_ids,
            skipped_tests=skipped,
            estimated_time_saved_ms=time_saved,
            coverage_impact=len(skipped) / len(tests) if tests else 0,
            confidence=0.8,
            recommendations=[
                "Run high-risk tests first to detect failures early",
                f"Prioritized {len([t for t in tests if t.failure_probability > 0.5])} high-risk tests",
            ],
        )

    def _optimize_coverage_based(self, tests: List[TestInfo]) -> OptimizationResult:
        """Select tests for maximum coverage."""
        # Greedy set cover algorithm
        covered: Set[str] = set()
        selected = []
        remaining = tests.copy()

        while remaining:
            # Find test that covers most uncovered items
            best = None
            best_new_coverage = 0

            for test in remaining:
                new_coverage = len(test.coverage - covered)
                if new_coverage > best_new_coverage:
                    best = test
                    best_new_coverage = new_coverage

            if best is None or best_new_coverage == 0:
                break

            selected.append(best)
            covered.update(best.coverage)
            remaining.remove(best)

            # Check if we've hit minimum coverage
            total_coverage = set()
            for t in tests:
                total_coverage.update(t.coverage)

            if len(covered) / len(total_coverage) >= self.config.min_coverage:
                break

        optimized_ids = [t.test_id for t in selected]
        skipped = [t.test_id for t in tests if t.test_id not in optimized_ids]

        return OptimizationResult(
            strategy=OptimizationStrategy.COVERAGE_BASED,
            optimization_type=OptimizationType.SKIP,
            original_tests=[t.test_id for t in tests],
            optimized_tests=optimized_ids,
            skipped_tests=skipped,
            estimated_time_saved_ms=sum(
                t.duration_ms for t in tests if t.test_id in skipped
            ),
            coverage_impact=1.0 - (len(covered) / len(set().union(*[t.coverage for t in tests])) if tests else 1),
            confidence=0.75,
            recommendations=[
                f"Selected {len(selected)} tests covering {len(covered)} items",
                f"Skipping {len(skipped)} redundant tests",
            ],
        )

    def _optimize_time_based(self, tests: List[TestInfo]) -> OptimizationResult:
        """Optimize for time budget."""
        if not self.config.time_budget_ms:
            # No budget - just sort by duration
            sorted_tests = sorted(tests, key=lambda t: t.duration_ms)
            return OptimizationResult(
                strategy=OptimizationStrategy.TIME_BASED,
                optimization_type=OptimizationType.REORDER,
                original_tests=[t.test_id for t in tests],
                optimized_tests=[t.test_id for t in sorted_tests],
                skipped_tests=[],
                estimated_time_saved_ms=0,
                coverage_impact=0,
                confidence=0.9,
                recommendations=["Running fast tests first for quicker feedback"],
            )

        # Knapsack-style selection
        # Sort by value (priority / duration ratio)
        sorted_tests = sorted(
            tests,
            key=lambda t: (10 - t.priority) / max(t.duration_ms, 1),
            reverse=True,
        )

        selected = []
        total_time = 0
        skipped = []

        for test in sorted_tests:
            if total_time + test.duration_ms <= self.config.time_budget_ms:
                selected.append(test)
                total_time += test.duration_ms
            else:
                skipped.append(test.test_id)

        return OptimizationResult(
            strategy=OptimizationStrategy.TIME_BASED,
            optimization_type=OptimizationType.SKIP,
            original_tests=[t.test_id for t in tests],
            optimized_tests=[t.test_id for t in selected],
            skipped_tests=skipped,
            estimated_time_saved_ms=sum(
                t.duration_ms for t in tests if t.test_id in skipped
            ),
            coverage_impact=len(skipped) / len(tests) if tests else 0,
            confidence=0.85,
            recommendations=[
                f"Selected {len(selected)} tests within {self.config.time_budget_ms}ms budget",
            ],
        )

    def _optimize_change_based(self, tests: List[TestInfo]) -> OptimizationResult:
        """Prioritize tests affected by code changes."""
        # Find tests with changed files
        changed_tests = [t for t in tests if t.changed_files]
        unchanged_tests = [t for t in tests if not t.changed_files]

        # Sort changed tests by number of changes
        changed_tests.sort(key=lambda t: len(t.changed_files), reverse=True)

        optimized = changed_tests + unchanged_tests
        optimized_ids = [t.test_id for t in optimized]

        # Optionally skip unchanged if over budget
        skipped = []
        if self.config.time_budget_ms:
            total_time = sum(t.duration_ms for t in changed_tests)
            for test in unchanged_tests:
                if total_time + test.duration_ms <= self.config.time_budget_ms:
                    total_time += test.duration_ms
                else:
                    skipped.append(test.test_id)
                    optimized_ids.remove(test.test_id)

        return OptimizationResult(
            strategy=OptimizationStrategy.CHANGE_BASED,
            optimization_type=OptimizationType.PRIORITIZE,
            original_tests=[t.test_id for t in tests],
            optimized_tests=optimized_ids,
            skipped_tests=skipped,
            estimated_time_saved_ms=sum(
                t.duration_ms for t in tests if t.test_id in skipped
            ),
            coverage_impact=len(skipped) / len(tests) if tests else 0,
            confidence=0.8,
            recommendations=[
                f"Prioritized {len(changed_tests)} tests affected by changes",
            ],
        )

    def _optimize_hybrid(self, tests: List[TestInfo]) -> OptimizationResult:
        """Combine multiple strategies."""
        # Calculate composite score
        scored_tests = []
        for test in tests:
            score = 0

            # Risk factor (0-40 points)
            score += test.failure_probability * 40

            # Change factor (0-30 points)
            if test.changed_files:
                score += min(len(test.changed_files) * 10, 30)

            # Priority factor (0-20 points)
            score += (10 - test.priority) * 2

            # Speed bonus (0-10 points) - faster tests get bonus
            max_duration = max(t.duration_ms for t in tests) or 1
            speed_ratio = 1 - (test.duration_ms / max_duration)
            score += speed_ratio * 10

            scored_tests.append((test, score))

        # Sort by score
        scored_tests.sort(key=lambda x: x[1], reverse=True)

        optimized = [t for t, _ in scored_tests]
        optimized_ids = [t.test_id for t in optimized]
        skipped = []

        # Apply time budget
        if self.config.time_budget_ms:
            total_time = 0
            final_list = []
            for test in optimized:
                if total_time + test.duration_ms <= self.config.time_budget_ms:
                    final_list.append(test.test_id)
                    total_time += test.duration_ms
                else:
                    skipped.append(test.test_id)
            optimized_ids = final_list

        time_saved = self._estimate_time_saved(tests, optimized_ids)

        return OptimizationResult(
            strategy=OptimizationStrategy.HYBRID,
            optimization_type=OptimizationType.PRIORITIZE,
            original_tests=[t.test_id for t in tests],
            optimized_tests=optimized_ids,
            skipped_tests=skipped,
            estimated_time_saved_ms=time_saved,
            coverage_impact=len(skipped) / len(tests) if tests else 0,
            confidence=0.85,
            recommendations=[
                "Using hybrid strategy combining risk, coverage, and time factors",
                f"Optimized order for {len(optimized_ids)} tests",
            ],
            metadata={
                "top_scores": [(t.test_id, s) for t, s in scored_tests[:5]],
            },
        )

    def _estimate_time_saved(
        self,
        tests: List[TestInfo],
        optimized_order: List[str],
    ) -> int:
        """Estimate time saved by early failure detection."""
        # Assume high-risk tests catch failures early
        high_risk = [t for t in tests if t.failure_probability > 0.5]

        if not high_risk:
            return 0

        # Estimate: if a failure is found, remaining tests might be skipped
        avg_position_original = len(tests) / 2
        avg_position_optimized = 0

        for i, test_id in enumerate(optimized_order):
            test = self._tests.get(test_id)
            if test and test.failure_probability > 0.5:
                avg_position_optimized = i
                break

        position_improvement = avg_position_original - avg_position_optimized
        avg_test_duration = sum(t.duration_ms for t in tests) / len(tests)

        return int(position_improvement * avg_test_duration * 0.3)

    def create_parallel_groups(
        self,
        test_ids: List[str],
        num_groups: Optional[int] = None,
    ) -> List[List[str]]:
        """Create parallel test groups."""
        num_groups = num_groups or self.config.parallel_groups
        tests = [self._tests[tid] for tid in test_ids if tid in self._tests]

        if not tests:
            return []

        # Check dependencies
        groups: List[List[str]] = [[] for _ in range(num_groups)]
        group_times = [0] * num_groups

        # Sort by duration (longest first for better distribution)
        tests.sort(key=lambda t: t.duration_ms, reverse=True)

        for test in tests:
            # Find group with shortest total time
            min_group = min(range(num_groups), key=lambda i: group_times[i])

            # Check if dependencies are satisfied
            deps = test.dependencies
            if deps:
                # Find a group where dependencies are already scheduled
                for i, group in enumerate(groups):
                    if all(d in group for d in deps):
                        min_group = i
                        break

            groups[min_group].append(test.test_id)
            group_times[min_group] += test.duration_ms

        return groups

    def get_optimization_summary(self) -> Dict[str, Any]:
        """Get optimization summary."""
        if not self._optimization_history:
            return {"optimizations": 0}

        total_time_saved = sum(r.estimated_time_saved_ms for r in self._optimization_history)
        total_skipped = sum(len(r.skipped_tests) for r in self._optimization_history)

        by_strategy = {}
        for result in self._optimization_history:
            s = result.strategy.value
            if s not in by_strategy:
                by_strategy[s] = 0
            by_strategy[s] += 1

        return {
            "optimizations": len(self._optimization_history),
            "total_time_saved_ms": total_time_saved,
            "total_tests_skipped": total_skipped,
            "by_strategy": by_strategy,
        }

    def format_optimization(self, result: OptimizationResult) -> str:
        """Format optimization result as readable text."""
        lines = [
            "=" * 60,
            "  TEST OPTIMIZATION RESULT",
            "=" * 60,
            "",
            f"  Strategy: {result.strategy.value}",
            f"  Type: {result.optimization_type.value}",
            f"  Confidence: {result.confidence:.1%}",
            "",
            f"  Original Tests: {len(result.original_tests)}",
            f"  Optimized Tests: {len(result.optimized_tests)}",
            f"  Skipped Tests: {len(result.skipped_tests)}",
            f"  Time Saved: {result.estimated_time_saved_ms}ms",
            "",
        ]

        if result.recommendations:
            lines.append("  Recommendations:")
            for rec in result.recommendations:
                lines.append(f"    • {rec}")

        if result.skipped_tests:
            lines.extend(["", "  Skipped:"])
            for test_id in result.skipped_tests[:5]:
                lines.append(f"    - {test_id}")
            if len(result.skipped_tests) > 5:
                lines.append(f"    ... and {len(result.skipped_tests) - 5} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_optimizer(
    config: Optional[OptimizationConfig] = None,
) -> TestOptimizer:
    """Create a test optimizer instance."""
    return TestOptimizer(config)
