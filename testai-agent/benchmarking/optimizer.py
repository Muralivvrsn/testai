"""
TestAI Agent - Test Optimizer

Intelligent test optimization with parallelization,
resource management, and execution strategies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import statistics


class OptimizationType(Enum):
    """Types of optimizations."""
    PARALLELIZATION = "parallelization"
    SELECTOR_OPTIMIZATION = "selector_optimization"
    WAIT_REDUCTION = "wait_reduction"
    RESOURCE_CACHING = "resource_caching"
    TEST_REORDERING = "test_reordering"
    STEP_MERGING = "step_merging"
    ASSERTION_BATCHING = "assertion_batching"
    NETWORK_MOCKING = "network_mocking"


class OptimizationImpact(Enum):
    """Expected impact of an optimization."""
    HIGH = "high"  # > 50% improvement
    MEDIUM = "medium"  # 20-50% improvement
    LOW = "low"  # 5-20% improvement
    MINIMAL = "minimal"  # < 5% improvement


@dataclass
class OptimizationRecommendation:
    """A specific optimization recommendation."""
    recommendation_id: str
    optimization_type: OptimizationType
    target: str  # What to optimize (test, step, selector, etc.)
    description: str
    current_state: str
    optimized_state: str
    expected_improvement_pct: float
    impact: OptimizationImpact
    effort: str  # low, medium, high
    auto_applicable: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizationResult:
    """Result of applying optimizations."""
    result_id: str
    test_id: str
    optimizations_applied: int
    before_duration_ms: float
    after_duration_ms: float
    improvement_pct: float
    recommendations: List[OptimizationRecommendation]
    optimized_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParallelGroup:
    """A group of tests that can run in parallel."""
    group_id: str
    test_ids: List[str]
    max_parallelism: int
    resource_requirements: Dict[str, Any]
    estimated_duration_ms: float


@dataclass
class ExecutionPlan:
    """Optimized execution plan."""
    plan_id: str
    total_tests: int
    parallel_groups: List[ParallelGroup]
    sequential_tests: List[str]
    estimated_duration_ms: float
    parallelization_factor: float
    created_at: datetime


class TestOptimizer:
    """
    Test optimization engine.

    Features:
    - Parallelization analysis
    - Selector optimization
    - Wait time reduction
    - Resource caching suggestions
    - Execution planning
    """

    def __init__(self, max_parallelism: int = 4):
        """Initialize the optimizer."""
        self.max_parallelism = max_parallelism
        self._recommendation_counter = 0
        self._result_counter = 0
        self._plan_counter = 0

        self._optimization_history: List[OptimizationResult] = []

        # Test metadata for optimization
        self._test_metadata: Dict[str, Dict[str, Any]] = {}

    def register_test(
        self,
        test_id: str,
        steps: List[Dict[str, Any]],
        dependencies: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
        estimated_duration_ms: float = 5000,
    ):
        """Register a test for optimization analysis."""
        self._test_metadata[test_id] = {
            "steps": steps,
            "dependencies": dependencies or [],
            "resources": resources or [],
            "estimated_duration_ms": estimated_duration_ms,
            "registered_at": datetime.now(),
        }

    def analyze(
        self,
        test_id: str,
        profiling_data: Optional[Dict[str, Any]] = None,
    ) -> List[OptimizationRecommendation]:
        """Analyze a test for optimization opportunities."""
        recommendations = []

        metadata = self._test_metadata.get(test_id, {})
        steps = metadata.get("steps", [])

        # Analyze each optimization type
        recommendations.extend(self._analyze_selectors(test_id, steps))
        recommendations.extend(self._analyze_waits(test_id, steps))
        recommendations.extend(self._analyze_assertions(test_id, steps))
        recommendations.extend(self._analyze_steps(test_id, steps))

        return recommendations

    def _analyze_selectors(
        self,
        test_id: str,
        steps: List[Dict[str, Any]],
    ) -> List[OptimizationRecommendation]:
        """Analyze selector optimization opportunities."""
        recommendations = []

        for i, step in enumerate(steps):
            selector = step.get("selector", "")

            # Detect complex XPath
            if selector.startswith("//") and len(selector) > 50:
                self._recommendation_counter += 1
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                    optimization_type=OptimizationType.SELECTOR_OPTIMIZATION,
                    target=f"Step {i + 1}",
                    description="Complex XPath selector can be simplified",
                    current_state=selector[:50] + "...",
                    optimized_state="Use data-testid attribute instead",
                    expected_improvement_pct=30,
                    impact=OptimizationImpact.MEDIUM,
                    effort="low",
                    auto_applicable=False,
                ))

            # Detect CSS with many classes
            if "." in selector and selector.count(".") > 3:
                self._recommendation_counter += 1
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                    optimization_type=OptimizationType.SELECTOR_OPTIMIZATION,
                    target=f"Step {i + 1}",
                    description="Multi-class selector is fragile and slow",
                    current_state=selector,
                    optimized_state="Use ID or data-testid",
                    expected_improvement_pct=20,
                    impact=OptimizationImpact.LOW,
                    effort="low",
                    auto_applicable=False,
                ))

        return recommendations

    def _analyze_waits(
        self,
        test_id: str,
        steps: List[Dict[str, Any]],
    ) -> List[OptimizationRecommendation]:
        """Analyze wait optimization opportunities."""
        recommendations = []

        total_explicit_waits = 0
        wait_steps = []

        for i, step in enumerate(steps):
            action = step.get("action", "")

            if "wait" in action.lower() or "sleep" in action.lower():
                wait_steps.append(i)
                wait_time = step.get("timeout", step.get("duration", 1000))
                total_explicit_waits += wait_time

        if total_explicit_waits > 5000:
            self._recommendation_counter += 1
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                optimization_type=OptimizationType.WAIT_REDUCTION,
                target="Test overall",
                description="Excessive explicit waits slow down test",
                current_state=f"{total_explicit_waits}ms in explicit waits",
                optimized_state="Use condition-based waits instead",
                expected_improvement_pct=40,
                impact=OptimizationImpact.HIGH,
                effort="medium",
                auto_applicable=False,
            ))

        # Detect consecutive waits
        for i in range(len(wait_steps) - 1):
            if wait_steps[i + 1] - wait_steps[i] == 1:
                self._recommendation_counter += 1
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                    optimization_type=OptimizationType.WAIT_REDUCTION,
                    target=f"Steps {wait_steps[i] + 1}-{wait_steps[i + 1] + 1}",
                    description="Consecutive waits can be combined",
                    current_state="Multiple sequential wait statements",
                    optimized_state="Single combined wait",
                    expected_improvement_pct=15,
                    impact=OptimizationImpact.LOW,
                    effort="low",
                    auto_applicable=True,
                ))

        return recommendations

    def _analyze_assertions(
        self,
        test_id: str,
        steps: List[Dict[str, Any]],
    ) -> List[OptimizationRecommendation]:
        """Analyze assertion optimization opportunities."""
        recommendations = []

        consecutive_assertions = 0
        assertion_groups = []
        current_group_start = None

        for i, step in enumerate(steps):
            action = step.get("action", "")

            if "assert" in action.lower() or "expect" in action.lower():
                if current_group_start is None:
                    current_group_start = i
                consecutive_assertions += 1
            else:
                if consecutive_assertions >= 3:
                    assertion_groups.append((current_group_start, i - 1, consecutive_assertions))
                current_group_start = None
                consecutive_assertions = 0

        # Check for trailing assertions
        if consecutive_assertions >= 3:
            assertion_groups.append((current_group_start, len(steps) - 1, consecutive_assertions))

        for start, end, count in assertion_groups:
            self._recommendation_counter += 1
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                optimization_type=OptimizationType.ASSERTION_BATCHING,
                target=f"Steps {start + 1}-{end + 1}",
                description=f"Batch {count} consecutive assertions",
                current_state=f"{count} individual assertions",
                optimized_state="Single batch assertion with soft asserts",
                expected_improvement_pct=25,
                impact=OptimizationImpact.MEDIUM,
                effort="medium",
                auto_applicable=True,
            ))

        return recommendations

    def _analyze_steps(
        self,
        test_id: str,
        steps: List[Dict[str, Any]],
    ) -> List[OptimizationRecommendation]:
        """Analyze step optimization opportunities."""
        recommendations = []

        # Detect redundant navigations
        last_navigation = None
        for i, step in enumerate(steps):
            action = step.get("action", "")
            url = step.get("url", "")

            if "navigate" in action.lower() or "goto" in action.lower():
                if last_navigation and url == last_navigation:
                    self._recommendation_counter += 1
                    recommendations.append(OptimizationRecommendation(
                        recommendation_id=f"OPT-{self._recommendation_counter:05d}",
                        optimization_type=OptimizationType.STEP_MERGING,
                        target=f"Step {i + 1}",
                        description="Redundant navigation detected",
                        current_state=f"Navigate to {url} again",
                        optimized_state="Remove duplicate navigation",
                        expected_improvement_pct=50,
                        impact=OptimizationImpact.HIGH,
                        effort="low",
                        auto_applicable=True,
                    ))
                last_navigation = url

        return recommendations

    def create_execution_plan(
        self,
        test_ids: List[str],
    ) -> ExecutionPlan:
        """Create an optimized execution plan."""
        self._plan_counter += 1
        plan_id = f"PLAN-{self._plan_counter:05d}"

        # Analyze dependencies
        dependency_graph = self._build_dependency_graph(test_ids)

        # Find independent tests
        independent = [t for t in test_ids if not dependency_graph.get(t, [])]
        dependent = [t for t in test_ids if dependency_graph.get(t, [])]

        # Create parallel groups from independent tests
        parallel_groups = self._create_parallel_groups(independent)

        # Estimate total duration
        parallel_duration = max(
            (g.estimated_duration_ms for g in parallel_groups),
            default=0
        )
        sequential_duration = sum(
            self._test_metadata.get(t, {}).get("estimated_duration_ms", 5000)
            for t in dependent
        )
        total_estimated = parallel_duration + sequential_duration

        # Calculate parallelization factor
        serial_duration = sum(
            self._test_metadata.get(t, {}).get("estimated_duration_ms", 5000)
            for t in test_ids
        )
        parallelization_factor = serial_duration / total_estimated if total_estimated > 0 else 1.0

        return ExecutionPlan(
            plan_id=plan_id,
            total_tests=len(test_ids),
            parallel_groups=parallel_groups,
            sequential_tests=dependent,
            estimated_duration_ms=total_estimated,
            parallelization_factor=parallelization_factor,
            created_at=datetime.now(),
        )

    def _build_dependency_graph(self, test_ids: List[str]) -> Dict[str, List[str]]:
        """Build dependency graph for tests."""
        graph = {}

        for test_id in test_ids:
            metadata = self._test_metadata.get(test_id, {})
            deps = metadata.get("dependencies", [])
            graph[test_id] = [d for d in deps if d in test_ids]

        return graph

    def _create_parallel_groups(
        self,
        test_ids: List[str],
    ) -> List[ParallelGroup]:
        """Create parallel execution groups."""
        if not test_ids:
            return []

        # Group by resource requirements
        resource_groups: Dict[str, List[str]] = {}

        for test_id in test_ids:
            metadata = self._test_metadata.get(test_id, {})
            resources = tuple(sorted(metadata.get("resources", [])))
            key = str(resources) if resources else "no_resources"

            if key not in resource_groups:
                resource_groups[key] = []
            resource_groups[key].append(test_id)

        # Create parallel groups
        groups = []
        group_num = 0

        for resource_key, tests in resource_groups.items():
            # Split into groups of max_parallelism
            for i in range(0, len(tests), self.max_parallelism):
                group_num += 1
                batch = tests[i:i + self.max_parallelism]

                # Estimate duration as max of batch
                duration = max(
                    self._test_metadata.get(t, {}).get("estimated_duration_ms", 5000)
                    for t in batch
                )

                groups.append(ParallelGroup(
                    group_id=f"GROUP-{group_num:03d}",
                    test_ids=batch,
                    max_parallelism=len(batch),
                    resource_requirements={"key": resource_key},
                    estimated_duration_ms=duration,
                ))

        return groups

    def apply_optimizations(
        self,
        test_id: str,
        recommendations: List[OptimizationRecommendation],
        before_duration_ms: float = 0,
    ) -> OptimizationResult:
        """Apply recommended optimizations."""
        self._result_counter += 1
        result_id = f"OPTRESULT-{self._result_counter:05d}"

        # Filter auto-applicable recommendations
        auto_applicable = [r for r in recommendations if r.auto_applicable]

        # Simulate improvement
        total_improvement = sum(r.expected_improvement_pct for r in auto_applicable)
        improvement_factor = 1 - (total_improvement / 100)
        after_duration = before_duration_ms * improvement_factor

        result = OptimizationResult(
            result_id=result_id,
            test_id=test_id,
            optimizations_applied=len(auto_applicable),
            before_duration_ms=before_duration_ms,
            after_duration_ms=after_duration,
            improvement_pct=total_improvement,
            recommendations=recommendations,
            optimized_at=datetime.now(),
        )

        self._optimization_history.append(result)

        return result

    def get_history(
        self,
        test_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[OptimizationResult]:
        """Get optimization history."""
        results = self._optimization_history

        if test_id:
            results = [r for r in results if r.test_id == test_id]

        return results[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get optimizer statistics."""
        if not self._optimization_history:
            return {
                "total_optimizations": 0,
                "avg_improvement_pct": 0,
                "registered_tests": len(self._test_metadata),
            }

        improvements = [r.improvement_pct for r in self._optimization_history]

        type_counts: Dict[str, int] = {}
        for result in self._optimization_history:
            for rec in result.recommendations:
                opt_type = rec.optimization_type.value
                type_counts[opt_type] = type_counts.get(opt_type, 0) + 1

        return {
            "total_optimizations": len(self._optimization_history),
            "total_recommendations": self._recommendation_counter,
            "avg_improvement_pct": statistics.mean(improvements) if improvements else 0,
            "max_improvement_pct": max(improvements) if improvements else 0,
            "registered_tests": len(self._test_metadata),
            "optimization_type_distribution": type_counts,
        }

    def format_plan(self, plan: ExecutionPlan) -> str:
        """Format an execution plan."""
        lines = [
            "=" * 70,
            "  OPTIMIZED EXECUTION PLAN",
            "=" * 70,
            "",
            f"  Plan ID: {plan.plan_id}",
            f"  Total Tests: {plan.total_tests}",
            f"  Estimated Duration: {plan.estimated_duration_ms:.0f}ms",
            f"  Parallelization Factor: {plan.parallelization_factor:.2f}x",
            "",
        ]

        if plan.parallel_groups:
            lines.extend([
                "-" * 70,
                f"  PARALLEL GROUPS ({len(plan.parallel_groups)})",
                "-" * 70,
                "",
            ])

            for group in plan.parallel_groups:
                lines.extend([
                    f"  {group.group_id} ({len(group.test_ids)} tests)",
                    f"    Tests: {', '.join(group.test_ids[:3])}{'...' if len(group.test_ids) > 3 else ''}",
                    f"    Parallelism: {group.max_parallelism}",
                    f"    Duration: {group.estimated_duration_ms:.0f}ms",
                    "",
                ])

        if plan.sequential_tests:
            lines.extend([
                "-" * 70,
                f"  SEQUENTIAL TESTS ({len(plan.sequential_tests)})",
                "-" * 70,
                "",
            ])

            for test_id in plan.sequential_tests[:10]:
                lines.append(f"  • {test_id}")

            if len(plan.sequential_tests) > 10:
                lines.append(f"  ... and {len(plan.sequential_tests) - 10} more")

        lines.extend(["", "=" * 70])
        return "\n".join(lines)

    def format_result(self, result: OptimizationResult) -> str:
        """Format an optimization result."""
        lines = [
            "=" * 70,
            "  OPTIMIZATION RESULT",
            "=" * 70,
            "",
            f"  Result ID: {result.result_id}",
            f"  Test ID: {result.test_id}",
            "",
            f"  Before: {result.before_duration_ms:.0f}ms",
            f"  After: {result.after_duration_ms:.0f}ms",
            f"  Improvement: {result.improvement_pct:.1f}%",
            "",
            f"  Optimizations Applied: {result.optimizations_applied}",
            "",
        ]

        if result.recommendations:
            lines.extend([
                "-" * 70,
                "  RECOMMENDATIONS",
                "-" * 70,
                "",
            ])

            impact_icons = {
                OptimizationImpact.HIGH: "🔴",
                OptimizationImpact.MEDIUM: "🟠",
                OptimizationImpact.LOW: "🟡",
                OptimizationImpact.MINIMAL: "🟢",
            }

            for rec in result.recommendations:
                icon = impact_icons.get(rec.impact, "?")
                auto = "✓" if rec.auto_applicable else "○"

                lines.extend([
                    f"  {icon} [{auto}] {rec.optimization_type.value}",
                    f"    {rec.description}",
                    f"    Expected improvement: {rec.expected_improvement_pct:.0f}%",
                    f"    Effort: {rec.effort}",
                    "",
                ])

        lines.extend(["=" * 70])
        return "\n".join(lines)


def create_test_optimizer(max_parallelism: int = 4) -> TestOptimizer:
    """Create a test optimizer instance."""
    return TestOptimizer(max_parallelism)
