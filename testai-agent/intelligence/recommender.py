"""
TestAI Agent - Test Recommender

AI-powered recommendations for test improvements,
prioritization, and strategic testing decisions.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import uuid


class RecommendationType(Enum):
    """Types of recommendations."""
    PRIORITY = "priority"
    OPTIMIZATION = "optimization"
    COVERAGE = "coverage"
    MAINTENANCE = "maintenance"
    STRATEGY = "strategy"
    RISK_MITIGATION = "risk_mitigation"


class RecommendationImpact(Enum):
    """Expected impact of a recommendation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RecommendationEffort(Enum):
    """Effort required to implement."""
    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    COMPLEX = "complex"


@dataclass
class TestRecommendation:
    """A recommendation for test improvement."""
    recommendation_id: str
    recommendation_type: RecommendationType
    title: str
    description: str
    impact: RecommendationImpact
    effort: RecommendationEffort
    priority_score: float  # 0.0 to 1.0
    affected_tests: List[str]
    action_items: List[str]
    expected_benefits: List[str]
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestProfile:
    """Profile of a test for recommendation analysis."""
    test_id: str
    name: str
    duration_ms: float
    pass_rate: float
    flaky_rate: float
    last_failure: Optional[datetime]
    failure_count: int
    coverage_areas: Set[str]
    dependencies: List[str]
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class TestSuiteProfile:
    """Profile of a test suite."""
    suite_id: str
    name: str
    total_tests: int
    total_duration_ms: float
    avg_pass_rate: float
    coverage_score: float
    test_profiles: List[TestProfile]


class TestRecommender:
    """
    AI-powered test recommendation engine.

    Features:
    - Test prioritization
    - Optimization suggestions
    - Coverage gap detection
    - Maintenance recommendations
    - Strategic guidance
    """

    # Weights for priority scoring
    PRIORITY_WEIGHTS = {
        "failure_rate": 0.25,
        "flakiness": 0.20,
        "impact": 0.20,
        "recency": 0.15,
        "duration": 0.10,
        "coverage": 0.10,
    }

    # Impact/effort thresholds
    QUICK_WIN_EFFORT = {RecommendationEffort.TRIVIAL, RecommendationEffort.LOW}
    HIGH_IMPACT = {RecommendationImpact.CRITICAL, RecommendationImpact.HIGH}

    def __init__(
        self,
        max_recommendations: int = 20,
    ):
        """Initialize the recommender."""
        self._max_recommendations = max_recommendations
        self._test_profiles: Dict[str, TestProfile] = {}
        self._suite_profiles: Dict[str, TestSuiteProfile] = {}
        self._recommendations: List[TestRecommendation] = []
        self._recommendation_counter = 0

    def register_test(
        self,
        test_id: str,
        name: str,
        duration_ms: float = 0,
        pass_rate: float = 1.0,
        flaky_rate: float = 0.0,
        last_failure: Optional[datetime] = None,
        failure_count: int = 0,
        coverage_areas: Optional[Set[str]] = None,
        dependencies: Optional[List[str]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> TestProfile:
        """Register a test for recommendation analysis."""
        profile = TestProfile(
            test_id=test_id,
            name=name,
            duration_ms=duration_ms,
            pass_rate=pass_rate,
            flaky_rate=flaky_rate,
            last_failure=last_failure,
            failure_count=failure_count,
            coverage_areas=coverage_areas or set(),
            dependencies=dependencies or [],
            tags=tags or {},
        )

        self._test_profiles[test_id] = profile
        return profile

    def register_suite(
        self,
        suite_id: str,
        name: str,
        test_ids: List[str],
        coverage_score: float = 0.0,
    ) -> TestSuiteProfile:
        """Register a test suite."""
        test_profiles = [
            self._test_profiles[tid]
            for tid in test_ids
            if tid in self._test_profiles
        ]

        total_duration = sum(p.duration_ms for p in test_profiles)
        avg_pass_rate = (
            sum(p.pass_rate for p in test_profiles) / len(test_profiles)
            if test_profiles else 1.0
        )

        suite = TestSuiteProfile(
            suite_id=suite_id,
            name=name,
            total_tests=len(test_profiles),
            total_duration_ms=total_duration,
            avg_pass_rate=avg_pass_rate,
            coverage_score=coverage_score,
            test_profiles=test_profiles,
        )

        self._suite_profiles[suite_id] = suite
        return suite

    def generate_recommendations(
        self,
        focus_areas: Optional[List[RecommendationType]] = None,
    ) -> List[TestRecommendation]:
        """Generate all recommendations."""
        recommendations = []

        if not focus_areas:
            focus_areas = list(RecommendationType)

        if RecommendationType.PRIORITY in focus_areas:
            recommendations.extend(self._generate_priority_recommendations())

        if RecommendationType.OPTIMIZATION in focus_areas:
            recommendations.extend(self._generate_optimization_recommendations())

        if RecommendationType.COVERAGE in focus_areas:
            recommendations.extend(self._generate_coverage_recommendations())

        if RecommendationType.MAINTENANCE in focus_areas:
            recommendations.extend(self._generate_maintenance_recommendations())

        if RecommendationType.RISK_MITIGATION in focus_areas:
            recommendations.extend(self._generate_risk_recommendations())

        # Sort by priority score
        recommendations.sort(key=lambda r: r.priority_score, reverse=True)

        # Store and limit
        self._recommendations = recommendations[:self._max_recommendations]
        return self._recommendations

    def get_quick_wins(self) -> List[TestRecommendation]:
        """Get quick win recommendations (high impact, low effort)."""
        return [
            r for r in self._recommendations
            if r.impact in self.HIGH_IMPACT and r.effort in self.QUICK_WIN_EFFORT
        ]

    def get_recommendations_by_type(
        self,
        recommendation_type: RecommendationType,
    ) -> List[TestRecommendation]:
        """Get recommendations of a specific type."""
        return [
            r for r in self._recommendations
            if r.recommendation_type == recommendation_type
        ]

    def get_recommendations_for_test(
        self,
        test_id: str,
    ) -> List[TestRecommendation]:
        """Get recommendations affecting a specific test."""
        return [
            r for r in self._recommendations
            if test_id in r.affected_tests
        ]

    def prioritize_tests(
        self,
        test_ids: Optional[List[str]] = None,
        time_budget_ms: Optional[float] = None,
    ) -> List[Tuple[str, float]]:
        """Prioritize tests for execution."""
        if test_ids is None:
            test_ids = list(self._test_profiles.keys())

        scored_tests = []
        for test_id in test_ids:
            profile = self._test_profiles.get(test_id)
            if profile:
                score = self._calculate_priority_score(profile)
                scored_tests.append((test_id, score))

        # Sort by score (highest priority first)
        scored_tests.sort(key=lambda x: x[1], reverse=True)

        # Apply time budget if specified
        if time_budget_ms:
            selected = []
            total_time = 0
            for test_id, score in scored_tests:
                profile = self._test_profiles.get(test_id)
                if profile and total_time + profile.duration_ms <= time_budget_ms:
                    selected.append((test_id, score))
                    total_time += profile.duration_ms
            return selected

        return scored_tests

    def _create_recommendation(
        self,
        recommendation_type: RecommendationType,
        title: str,
        description: str,
        impact: RecommendationImpact,
        effort: RecommendationEffort,
        affected_tests: List[str],
        action_items: List[str],
        expected_benefits: List[str],
    ) -> TestRecommendation:
        """Create a new recommendation."""
        self._recommendation_counter += 1

        # Calculate priority score
        impact_scores = {
            RecommendationImpact.CRITICAL: 1.0,
            RecommendationImpact.HIGH: 0.75,
            RecommendationImpact.MEDIUM: 0.5,
            RecommendationImpact.LOW: 0.25,
        }
        effort_scores = {
            RecommendationEffort.TRIVIAL: 1.0,
            RecommendationEffort.LOW: 0.8,
            RecommendationEffort.MEDIUM: 0.5,
            RecommendationEffort.HIGH: 0.3,
            RecommendationEffort.COMPLEX: 0.1,
        }

        priority_score = (impact_scores[impact] + effort_scores[effort]) / 2

        return TestRecommendation(
            recommendation_id=f"REC-{self._recommendation_counter:05d}",
            recommendation_type=recommendation_type,
            title=title,
            description=description,
            impact=impact,
            effort=effort,
            priority_score=priority_score,
            affected_tests=affected_tests,
            action_items=action_items,
            expected_benefits=expected_benefits,
            created_at=datetime.now(),
        )

    def _calculate_priority_score(self, profile: TestProfile) -> float:
        """Calculate priority score for a test."""
        scores = {}

        # Failure rate (higher failure = higher priority)
        scores["failure_rate"] = 1 - profile.pass_rate

        # Flakiness (higher = higher priority)
        scores["flakiness"] = min(1.0, profile.flaky_rate * 2)

        # Recency of failure (recent = higher priority)
        if profile.last_failure:
            days_since = (datetime.now() - profile.last_failure).days
            scores["recency"] = max(0, 1 - days_since / 30)
        else:
            scores["recency"] = 0

        # Duration (moderate - extremes get priority)
        # Very fast or very slow tests are prioritized differently
        scores["duration"] = 0.5  # Default

        # Coverage (more coverage areas = higher priority)
        scores["coverage"] = min(1.0, len(profile.coverage_areas) / 5)

        # Impact based on dependencies
        scores["impact"] = min(1.0, len(profile.dependencies) / 3)

        # Weighted sum
        total = sum(
            scores.get(key, 0) * weight
            for key, weight in self.PRIORITY_WEIGHTS.items()
        )

        return round(total, 3)

    def _generate_priority_recommendations(self) -> List[TestRecommendation]:
        """Generate priority-related recommendations."""
        recommendations = []

        # Find tests that should run first
        high_priority = []
        for test_id, profile in self._test_profiles.items():
            score = self._calculate_priority_score(profile)
            if score > 0.6:
                high_priority.append((test_id, score))

        if high_priority:
            high_priority.sort(key=lambda x: x[1], reverse=True)
            top_tests = [t[0] for t in high_priority[:5]]

            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.PRIORITY,
                title="Prioritize Critical Tests",
                description=f"{len(high_priority)} tests identified as high priority for early execution",
                impact=RecommendationImpact.HIGH,
                effort=RecommendationEffort.TRIVIAL,
                affected_tests=top_tests,
                action_items=[
                    "Run high-priority tests first in CI/CD pipeline",
                    "Set up fast feedback loop for critical tests",
                ],
                expected_benefits=[
                    "Faster feedback on critical functionality",
                    "Earlier detection of regressions",
                ],
            ))

        # Find tests with high failure impact
        impact_tests = [
            tid for tid, p in self._test_profiles.items()
            if len(p.dependencies) >= 3 and p.pass_rate < 0.95
        ]

        if impact_tests:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.PRIORITY,
                title="Stabilize High-Impact Tests",
                description=f"{len(impact_tests)} tests with many dependents need stabilization",
                impact=RecommendationImpact.HIGH,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=impact_tests[:5],
                action_items=[
                    "Review and fix failing high-impact tests",
                    "Add retry logic for transient failures",
                ],
                expected_benefits=[
                    "Reduced cascade failures",
                    "More stable test runs",
                ],
            ))

        return recommendations

    def _generate_optimization_recommendations(self) -> List[TestRecommendation]:
        """Generate optimization recommendations."""
        recommendations = []

        # Find slow tests
        slow_threshold_ms = 5000
        slow_tests = [
            (tid, p) for tid, p in self._test_profiles.items()
            if p.duration_ms > slow_threshold_ms
        ]

        if slow_tests:
            total_time = sum(p.duration_ms for _, p in slow_tests)
            test_ids = [tid for tid, _ in slow_tests[:5]]

            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.OPTIMIZATION,
                title="Optimize Slow Tests",
                description=f"{len(slow_tests)} tests exceed {slow_threshold_ms}ms (total: {total_time/1000:.1f}s)",
                impact=RecommendationImpact.MEDIUM,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=test_ids,
                action_items=[
                    "Profile slow tests to identify bottlenecks",
                    "Optimize selectors and waits",
                    "Consider mocking slow external services",
                ],
                expected_benefits=[
                    "Faster test suite execution",
                    "Quicker CI/CD feedback",
                ],
            ))

        # Find parallelization opportunities
        independent_tests = [
            tid for tid, p in self._test_profiles.items()
            if not p.dependencies and p.pass_rate >= 0.95
        ]

        if len(independent_tests) >= 5:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.OPTIMIZATION,
                title="Enable Test Parallelization",
                description=f"{len(independent_tests)} independent tests can run in parallel",
                impact=RecommendationImpact.HIGH,
                effort=RecommendationEffort.LOW,
                affected_tests=independent_tests[:10],
                action_items=[
                    "Configure test runner for parallel execution",
                    "Ensure tests don't share mutable state",
                ],
                expected_benefits=[
                    "Significantly reduced total execution time",
                    "Better resource utilization",
                ],
            ))

        return recommendations

    def _generate_coverage_recommendations(self) -> List[TestRecommendation]:
        """Generate coverage recommendations."""
        recommendations = []

        # Analyze coverage gaps
        all_areas: Set[str] = set()
        covered_areas: Set[str] = set()

        for profile in self._test_profiles.values():
            all_areas.update(profile.coverage_areas)
            if profile.pass_rate >= 0.8:
                covered_areas.update(profile.coverage_areas)

        # Note: In real implementation, all_areas would come from requirements
        # For now, we'll look for tests without coverage areas

        uncovered_tests = [
            tid for tid, p in self._test_profiles.items()
            if not p.coverage_areas
        ]

        if uncovered_tests:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.COVERAGE,
                title="Define Coverage Areas",
                description=f"{len(uncovered_tests)} tests lack coverage area annotations",
                impact=RecommendationImpact.MEDIUM,
                effort=RecommendationEffort.LOW,
                affected_tests=uncovered_tests[:10],
                action_items=[
                    "Tag tests with feature/area coverage",
                    "Map tests to requirements",
                ],
                expected_benefits=[
                    "Better visibility into test coverage",
                    "Easier gap identification",
                ],
            ))

        # Find areas with only one test
        area_counts: Dict[str, int] = {}
        for profile in self._test_profiles.values():
            for area in profile.coverage_areas:
                area_counts[area] = area_counts.get(area, 0) + 1

        single_coverage = [area for area, count in area_counts.items() if count == 1]

        if single_coverage:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.COVERAGE,
                title="Improve Coverage Depth",
                description=f"{len(single_coverage)} areas have only single-test coverage",
                impact=RecommendationImpact.MEDIUM,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=[],
                action_items=[
                    "Add additional tests for under-covered areas",
                    "Consider edge cases and error scenarios",
                ],
                expected_benefits=[
                    "More robust coverage",
                    "Reduced risk of missed regressions",
                ],
            ))

        return recommendations

    def _generate_maintenance_recommendations(self) -> List[TestRecommendation]:
        """Generate maintenance recommendations."""
        recommendations = []

        # Find flaky tests
        flaky_tests = [
            (tid, p) for tid, p in self._test_profiles.items()
            if p.flaky_rate > 0.1
        ]

        if flaky_tests:
            flaky_tests.sort(key=lambda x: x[1].flaky_rate, reverse=True)
            test_ids = [tid for tid, _ in flaky_tests[:5]]

            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.MAINTENANCE,
                title="Fix Flaky Tests",
                description=f"{len(flaky_tests)} tests show flaky behavior",
                impact=RecommendationImpact.HIGH,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=test_ids,
                action_items=[
                    "Identify root cause of flakiness",
                    "Add explicit waits for async operations",
                    "Consider quarantining until fixed",
                ],
                expected_benefits=[
                    "More reliable test results",
                    "Reduced false negatives",
                    "Increased developer trust",
                ],
            ))

        # Find tests with many failures
        failing_tests = [
            (tid, p) for tid, p in self._test_profiles.items()
            if p.failure_count > 5 and p.pass_rate < 0.7
        ]

        if failing_tests:
            test_ids = [tid for tid, _ in failing_tests[:5]]

            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.MAINTENANCE,
                title="Repair or Remove Failing Tests",
                description=f"{len(failing_tests)} tests have persistent failures",
                impact=RecommendationImpact.MEDIUM,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=test_ids,
                action_items=[
                    "Investigate root cause of failures",
                    "Update tests to match current behavior",
                    "Consider removing obsolete tests",
                ],
                expected_benefits=[
                    "Cleaner test suite",
                    "More meaningful results",
                ],
            ))

        return recommendations

    def _generate_risk_recommendations(self) -> List[TestRecommendation]:
        """Generate risk mitigation recommendations."""
        recommendations = []

        # Find tests with no recent runs (stale)
        stale_threshold = timedelta(days=7)
        # Note: In real implementation, we'd track last run time
        # For now, we'll use last_failure as a proxy

        # Find tests with circular dependencies (simplified)
        tests_with_deps = [
            tid for tid, p in self._test_profiles.items()
            if p.dependencies
        ]

        if len(tests_with_deps) > len(self._test_profiles) * 0.5:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.RISK_MITIGATION,
                title="Reduce Test Dependencies",
                description="Many tests have dependencies, increasing failure cascade risk",
                impact=RecommendationImpact.MEDIUM,
                effort=RecommendationEffort.HIGH,
                affected_tests=tests_with_deps[:5],
                action_items=[
                    "Review and reduce unnecessary dependencies",
                    "Use mocks to isolate tests",
                    "Consider independent test data setup",
                ],
                expected_benefits=[
                    "More isolated tests",
                    "Easier debugging",
                    "Reduced cascade failures",
                ],
            ))

        # Find single points of failure
        dependency_counts: Dict[str, int] = {}
        for profile in self._test_profiles.values():
            for dep in profile.dependencies:
                dependency_counts[dep] = dependency_counts.get(dep, 0) + 1

        critical_deps = [
            (dep, count) for dep, count in dependency_counts.items()
            if count >= 3
        ]

        if critical_deps:
            recommendations.append(self._create_recommendation(
                recommendation_type=RecommendationType.RISK_MITIGATION,
                title="Address Single Points of Failure",
                description=f"{len(critical_deps)} tests are dependencies for multiple others",
                impact=RecommendationImpact.HIGH,
                effort=RecommendationEffort.MEDIUM,
                affected_tests=[dep for dep, _ in critical_deps],
                action_items=[
                    "Ensure critical tests are highly stable",
                    "Add redundant coverage for critical paths",
                    "Implement fast failure detection",
                ],
                expected_benefits=[
                    "Reduced risk of mass failures",
                    "More resilient test suite",
                ],
            ))

        return recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get recommender statistics."""
        type_counts = {}
        for rec_type in RecommendationType:
            type_counts[rec_type.value] = sum(
                1 for r in self._recommendations
                if r.recommendation_type == rec_type
            )

        return {
            "registered_tests": len(self._test_profiles),
            "registered_suites": len(self._suite_profiles),
            "total_recommendations": len(self._recommendations),
            "recommendations_by_type": type_counts,
            "quick_wins": len(self.get_quick_wins()),
        }

    def format_recommendation(self, rec: TestRecommendation) -> str:
        """Format a recommendation for display."""
        impact_emoji = {
            RecommendationImpact.CRITICAL: "🔴",
            RecommendationImpact.HIGH: "🟠",
            RecommendationImpact.MEDIUM: "🟡",
            RecommendationImpact.LOW: "🟢",
        }

        effort_emoji = {
            RecommendationEffort.TRIVIAL: "✨",
            RecommendationEffort.LOW: "🔧",
            RecommendationEffort.MEDIUM: "⚙️",
            RecommendationEffort.HIGH: "🏗️",
            RecommendationEffort.COMPLEX: "🔬",
        }

        lines = [
            "=" * 60,
            f"  {impact_emoji[rec.impact]} RECOMMENDATION",
            "=" * 60,
            "",
            f"  {rec.title}",
            "",
            f"  {rec.description}",
            "",
            f"  Type: {rec.recommendation_type.value}",
            f"  Impact: {rec.impact.value} {impact_emoji[rec.impact]}",
            f"  Effort: {rec.effort.value} {effort_emoji[rec.effort]}",
            f"  Priority: {rec.priority_score:.0%}",
            "",
        ]

        if rec.action_items:
            lines.append("-" * 60)
            lines.append("  ACTION ITEMS")
            lines.append("-" * 60)
            for item in rec.action_items:
                lines.append(f"  □ {item}")
            lines.append("")

        if rec.expected_benefits:
            lines.append("-" * 60)
            lines.append("  EXPECTED BENEFITS")
            lines.append("-" * 60)
            for benefit in rec.expected_benefits:
                lines.append(f"  ✓ {benefit}")
            lines.append("")

        if rec.affected_tests:
            lines.append("-" * 60)
            lines.append(f"  AFFECTED TESTS ({len(rec.affected_tests)})")
            lines.append("-" * 60)
            for test_id in rec.affected_tests[:5]:
                lines.append(f"  • {test_id}")
            if len(rec.affected_tests) > 5:
                lines.append(f"  ... and {len(rec.affected_tests) - 5} more")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_test_recommender(
    max_recommendations: int = 20,
) -> TestRecommender:
    """Create a test recommender instance."""
    return TestRecommender(max_recommendations=max_recommendations)
