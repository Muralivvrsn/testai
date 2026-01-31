"""
TestAI Agent - Test Parallelizer

Intelligent test parallelization with load balancing
and dependency-aware scheduling.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class BalanceStrategy(Enum):
    """Strategies for balancing test distribution."""
    ROUND_ROBIN = "round_robin"
    DURATION_BALANCED = "duration_balanced"
    COUNT_BALANCED = "count_balanced"
    SUITE_GROUPED = "suite_grouped"
    DEPENDENCY_AWARE = "dependency_aware"


@dataclass
class ParallelTest:
    """A test to be parallelized."""
    test_id: str
    test_name: str
    suite: str
    duration_sec: float
    dependencies: List[str]
    resource_requirements: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestBucket:
    """A bucket of tests for parallel execution."""
    bucket_id: str
    bucket_index: int
    tests: List[ParallelTest]
    total_duration_sec: float
    worker_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParallelizationPlan:
    """A plan for parallel test execution."""
    plan_id: str
    strategy: BalanceStrategy
    buckets: List[TestBucket]
    worker_count: int
    total_tests: int
    total_duration_sec: float
    estimated_wall_time_sec: float
    parallelism_efficiency: float
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestParallelizer:
    """
    Parallelizes tests across multiple workers.

    Features:
    - Load balancing strategies
    - Dependency handling
    - Resource awareness
    - Efficiency optimization
    """

    def __init__(
        self,
        default_workers: int = 4,
        default_strategy: BalanceStrategy = BalanceStrategy.DURATION_BALANCED,
    ):
        """Initialize the parallelizer."""
        self._default_workers = default_workers
        self._default_strategy = default_strategy
        self._tests: Dict[str, ParallelTest] = {}
        self._plans: List[ParallelizationPlan] = []
        self._test_counter = 0
        self._plan_counter = 0

    def add_test(
        self,
        test_name: str,
        suite: str = "default",
        duration_sec: float = 1.0,
        dependencies: Optional[List[str]] = None,
        resource_requirements: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> ParallelTest:
        """Add a test for parallelization."""
        self._test_counter += 1
        test_id = f"PT-{self._test_counter:05d}"

        test = ParallelTest(
            test_id=test_id,
            test_name=test_name,
            suite=suite,
            duration_sec=duration_sec,
            dependencies=dependencies or [],
            resource_requirements=resource_requirements or {},
            tags=tags or [],
        )

        self._tests[test_id] = test
        return test

    def add_tests_batch(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[ParallelTest]:
        """Add multiple tests at once."""
        results = []
        for test_data in tests:
            test = self.add_test(
                test_name=test_data.get("name", "Unknown"),
                suite=test_data.get("suite", "default"),
                duration_sec=test_data.get("duration", 1.0),
                dependencies=test_data.get("dependencies"),
                resource_requirements=test_data.get("resources"),
                tags=test_data.get("tags"),
            )
            results.append(test)
        return results

    def create_plan(
        self,
        worker_count: Optional[int] = None,
        strategy: Optional[BalanceStrategy] = None,
        test_ids: Optional[List[str]] = None,
    ) -> ParallelizationPlan:
        """Create a parallelization plan."""
        self._plan_counter += 1
        plan_id = f"PLAN-{self._plan_counter:05d}"

        workers = worker_count or self._default_workers
        strat = strategy or self._default_strategy

        # Get tests to parallelize
        if test_ids:
            tests = [self._tests[tid] for tid in test_ids if tid in self._tests]
        else:
            tests = list(self._tests.values())

        # Create buckets based on strategy
        if strat == BalanceStrategy.ROUND_ROBIN:
            buckets = self._round_robin(tests, workers)
        elif strat == BalanceStrategy.DURATION_BALANCED:
            buckets = self._duration_balanced(tests, workers)
        elif strat == BalanceStrategy.COUNT_BALANCED:
            buckets = self._count_balanced(tests, workers)
        elif strat == BalanceStrategy.SUITE_GROUPED:
            buckets = self._suite_grouped(tests, workers)
        elif strat == BalanceStrategy.DEPENDENCY_AWARE:
            buckets = self._dependency_aware(tests, workers)
        else:
            buckets = self._round_robin(tests, workers)

        # Calculate metrics
        total_duration = sum(t.duration_sec for t in tests)
        max_bucket_duration = max(b.total_duration_sec for b in buckets) if buckets else 0
        efficiency = (total_duration / (max_bucket_duration * workers) * 100) if max_bucket_duration > 0 else 100

        plan = ParallelizationPlan(
            plan_id=plan_id,
            strategy=strat,
            buckets=buckets,
            worker_count=workers,
            total_tests=len(tests),
            total_duration_sec=total_duration,
            estimated_wall_time_sec=max_bucket_duration,
            parallelism_efficiency=round(efficiency, 1),
            created_at=datetime.now(),
        )

        self._plans.append(plan)
        return plan

    def _round_robin(
        self,
        tests: List[ParallelTest],
        workers: int,
    ) -> List[TestBucket]:
        """Distribute tests round-robin."""
        buckets = [
            TestBucket(
                bucket_id=f"BKT-{i+1:03d}",
                bucket_index=i,
                tests=[],
                total_duration_sec=0,
            )
            for i in range(workers)
        ]

        for i, test in enumerate(tests):
            bucket = buckets[i % workers]
            bucket.tests.append(test)
            bucket.total_duration_sec += test.duration_sec

        return buckets

    def _duration_balanced(
        self,
        tests: List[ParallelTest],
        workers: int,
    ) -> List[TestBucket]:
        """Balance by duration (greedy)."""
        buckets = [
            TestBucket(
                bucket_id=f"BKT-{i+1:03d}",
                bucket_index=i,
                tests=[],
                total_duration_sec=0,
            )
            for i in range(workers)
        ]

        # Sort tests by duration (descending)
        sorted_tests = sorted(tests, key=lambda t: t.duration_sec, reverse=True)

        # Greedy assignment to least loaded bucket
        for test in sorted_tests:
            min_bucket = min(buckets, key=lambda b: b.total_duration_sec)
            min_bucket.tests.append(test)
            min_bucket.total_duration_sec += test.duration_sec

        return buckets

    def _count_balanced(
        self,
        tests: List[ParallelTest],
        workers: int,
    ) -> List[TestBucket]:
        """Balance by test count."""
        buckets = [
            TestBucket(
                bucket_id=f"BKT-{i+1:03d}",
                bucket_index=i,
                tests=[],
                total_duration_sec=0,
            )
            for i in range(workers)
        ]

        tests_per_bucket = len(tests) // workers
        remainder = len(tests) % workers

        test_index = 0
        for i, bucket in enumerate(buckets):
            count = tests_per_bucket + (1 if i < remainder else 0)
            for _ in range(count):
                if test_index < len(tests):
                    test = tests[test_index]
                    bucket.tests.append(test)
                    bucket.total_duration_sec += test.duration_sec
                    test_index += 1

        return buckets

    def _suite_grouped(
        self,
        tests: List[ParallelTest],
        workers: int,
    ) -> List[TestBucket]:
        """Group tests by suite, then balance."""
        # Group by suite
        suites: Dict[str, List[ParallelTest]] = {}
        for test in tests:
            if test.suite not in suites:
                suites[test.suite] = []
            suites[test.suite].append(test)

        # Create buckets
        buckets = [
            TestBucket(
                bucket_id=f"BKT-{i+1:03d}",
                bucket_index=i,
                tests=[],
                total_duration_sec=0,
            )
            for i in range(workers)
        ]

        # Assign entire suites to buckets
        suite_list = list(suites.items())
        suite_list.sort(key=lambda x: sum(t.duration_sec for t in x[1]), reverse=True)

        for suite_name, suite_tests in suite_list:
            min_bucket = min(buckets, key=lambda b: b.total_duration_sec)
            for test in suite_tests:
                min_bucket.tests.append(test)
                min_bucket.total_duration_sec += test.duration_sec

        return buckets

    def _dependency_aware(
        self,
        tests: List[ParallelTest],
        workers: int,
    ) -> List[TestBucket]:
        """Respect dependencies when parallelizing."""
        # Build dependency graph
        dep_map: Dict[str, Set[str]] = {}
        for test in tests:
            dep_map[test.test_id] = set(test.dependencies)

        # Topological sort (simplified)
        ordered: List[ParallelTest] = []
        remaining = set(t.test_id for t in tests)
        test_lookup = {t.test_id: t for t in tests}

        while remaining:
            # Find tests with no unmet dependencies
            ready = [
                tid for tid in remaining
                if not (dep_map.get(tid, set()) & remaining)
            ]

            if not ready:
                # Circular dependency - just take remaining
                ready = list(remaining)

            for tid in ready:
                ordered.append(test_lookup[tid])
                remaining.remove(tid)

        # Now distribute using duration balancing
        return self._duration_balanced(ordered, workers)

    def estimate_speedup(
        self,
        plan: ParallelizationPlan,
    ) -> Dict[str, float]:
        """Estimate speedup from parallelization."""
        sequential_time = plan.total_duration_sec
        parallel_time = plan.estimated_wall_time_sec

        speedup = sequential_time / parallel_time if parallel_time > 0 else 1.0
        ideal_speedup = plan.worker_count
        efficiency = (speedup / ideal_speedup) * 100 if ideal_speedup > 0 else 100

        return {
            "sequential_time_sec": round(sequential_time, 2),
            "parallel_time_sec": round(parallel_time, 2),
            "speedup": round(speedup, 2),
            "ideal_speedup": ideal_speedup,
            "efficiency_pct": round(efficiency, 1),
        }

    def get_test(self, test_id: str) -> Optional[ParallelTest]:
        """Get a test by ID."""
        return self._tests.get(test_id)

    def list_tests(self) -> List[ParallelTest]:
        """List all tests."""
        return list(self._tests.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get parallelizer statistics."""
        total_duration = sum(t.duration_sec for t in self._tests.values())
        suites = set(t.suite for t in self._tests.values())
        with_deps = sum(1 for t in self._tests.values() if t.dependencies)

        return {
            "total_tests": len(self._tests),
            "total_plans": len(self._plans),
            "total_duration_sec": round(total_duration, 2),
            "suites": len(suites),
            "tests_with_dependencies": with_deps,
            "default_workers": self._default_workers,
        }

    def format_plan(self, plan: ParallelizationPlan) -> str:
        """Format a parallelization plan for display."""
        speedup = self.estimate_speedup(plan)

        lines = [
            "=" * 55,
            f"  PARALLELIZATION PLAN",
            "=" * 55,
            "",
            f"  ID: {plan.plan_id}",
            f"  Strategy: {plan.strategy.value}",
            f"  Workers: {plan.worker_count}",
            f"  Tests: {plan.total_tests}",
            "",
            "-" * 55,
            "  METRICS",
            "-" * 55,
            "",
            f"  Total Duration: {plan.total_duration_sec:.1f}s",
            f"  Estimated Wall Time: {plan.estimated_wall_time_sec:.1f}s",
            f"  Speedup: {speedup['speedup']:.1f}x",
            f"  Efficiency: {plan.parallelism_efficiency}%",
            "",
            "-" * 55,
            "  BUCKETS",
            "-" * 55,
            "",
        ]

        for bucket in plan.buckets:
            lines.append(
                f"  Bucket {bucket.bucket_index + 1}: "
                f"{len(bucket.tests)} tests, {bucket.total_duration_sec:.1f}s"
            )

        lines.append("")
        lines.append("=" * 55)
        return "\n".join(lines)


def create_test_parallelizer(
    default_workers: int = 4,
    default_strategy: BalanceStrategy = BalanceStrategy.DURATION_BALANCED,
) -> TestParallelizer:
    """Create a test parallelizer instance."""
    return TestParallelizer(
        default_workers=default_workers,
        default_strategy=default_strategy,
    )
