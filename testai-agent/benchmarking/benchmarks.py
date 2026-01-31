"""
TestAI Agent - Benchmark Runner

Run standardized benchmarks to measure and compare
test performance across configurations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time
import statistics
import uuid


class BenchmarkCategory(Enum):
    """Categories of benchmarks."""
    EXECUTION_SPEED = "execution_speed"
    SELECTOR_PERFORMANCE = "selector_performance"
    WAIT_EFFICIENCY = "wait_efficiency"
    PARALLEL_SCALING = "parallel_scaling"
    MEMORY_USAGE = "memory_usage"
    STABILITY = "stability"


@dataclass
class Benchmark:
    """A single benchmark definition."""
    benchmark_id: str
    name: str
    description: str
    category: BenchmarkCategory
    iterations: int
    warmup_iterations: int
    runner: Callable[[], float]  # Returns duration in ms
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkMeasurement:
    """A single measurement from a benchmark run."""
    iteration: int
    duration_ms: float
    timestamp: datetime
    is_warmup: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    """Result of running a benchmark."""
    result_id: str
    benchmark_id: str
    benchmark_name: str
    category: BenchmarkCategory
    measurements: List[BenchmarkMeasurement]
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    std_dev_ms: float
    p50_ms: float
    p90_ms: float
    p99_ms: float
    total_iterations: int
    passed: bool
    run_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkSuite:
    """A suite of benchmarks."""
    suite_id: str
    name: str
    description: str
    benchmarks: List[Benchmark]
    created_at: datetime


@dataclass
class SuiteResult:
    """Result of running a benchmark suite."""
    suite_id: str
    suite_name: str
    results: List[BenchmarkResult]
    total_benchmarks: int
    passed_benchmarks: int
    failed_benchmarks: int
    total_duration_ms: float
    run_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class BenchmarkRunner:
    """
    Benchmark runner for performance testing.

    Features:
    - Standardized benchmarks
    - Statistical analysis
    - Comparison across runs
    - Suite management
    - Historical tracking
    """

    def __init__(self):
        """Initialize the runner."""
        self._suites: Dict[str, BenchmarkSuite] = {}
        self._benchmarks: Dict[str, Benchmark] = {}
        self._history: List[BenchmarkResult] = {}
        self._suite_history: List[SuiteResult] = []

        self._result_counter = 0
        self._suite_counter = 0

        # Initialize default benchmarks
        self._initialize_default_benchmarks()

    def _initialize_default_benchmarks(self):
        """Initialize default benchmarks."""
        # Selector benchmarks
        self.register_benchmark(
            name="ID Selector",
            description="Measure ID selector resolution speed",
            category=BenchmarkCategory.SELECTOR_PERFORMANCE,
            iterations=100,
            runner=lambda: self._simulate_selector_benchmark("id"),
        )

        self.register_benchmark(
            name="CSS Selector",
            description="Measure CSS selector resolution speed",
            category=BenchmarkCategory.SELECTOR_PERFORMANCE,
            iterations=100,
            runner=lambda: self._simulate_selector_benchmark("css"),
        )

        self.register_benchmark(
            name="XPath Selector",
            description="Measure XPath selector resolution speed",
            category=BenchmarkCategory.SELECTOR_PERFORMANCE,
            iterations=100,
            runner=lambda: self._simulate_selector_benchmark("xpath"),
        )

        # Execution benchmarks
        self.register_benchmark(
            name="Click Action",
            description="Measure click action execution time",
            category=BenchmarkCategory.EXECUTION_SPEED,
            iterations=50,
            runner=lambda: self._simulate_action_benchmark("click"),
        )

        self.register_benchmark(
            name="Fill Action",
            description="Measure fill action execution time",
            category=BenchmarkCategory.EXECUTION_SPEED,
            iterations=50,
            runner=lambda: self._simulate_action_benchmark("fill"),
        )

        # Stability benchmarks
        self.register_benchmark(
            name="Consistency Check",
            description="Measure execution time consistency",
            category=BenchmarkCategory.STABILITY,
            iterations=200,
            runner=lambda: self._simulate_stability_benchmark(),
        )

    def _simulate_selector_benchmark(self, selector_type: str) -> float:
        """Simulate a selector benchmark."""
        import random

        base_times = {
            "id": 5,
            "css": 10,
            "xpath": 25,
            "data_testid": 6,
        }

        base = base_times.get(selector_type, 15)
        variance = random.gauss(0, base * 0.2)

        time.sleep(base / 1000)  # Simulate actual work
        return max(1, base + variance)

    def _simulate_action_benchmark(self, action: str) -> float:
        """Simulate an action benchmark."""
        import random

        base_times = {
            "click": 50,
            "fill": 75,
            "navigate": 500,
            "hover": 40,
        }

        base = base_times.get(action, 100)
        variance = random.gauss(0, base * 0.15)

        time.sleep(base / 1000)
        return max(10, base + variance)

    def _simulate_stability_benchmark(self) -> float:
        """Simulate a stability benchmark."""
        import random

        # Should have low variance
        base = 100
        variance = random.gauss(0, 5)

        time.sleep(base / 1000)
        return max(50, base + variance)

    def register_benchmark(
        self,
        name: str,
        description: str,
        category: BenchmarkCategory,
        iterations: int,
        runner: Callable[[], float],
        warmup_iterations: int = 5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Benchmark:
        """Register a benchmark."""
        benchmark_id = f"BM-{uuid.uuid4().hex[:8]}"

        benchmark = Benchmark(
            benchmark_id=benchmark_id,
            name=name,
            description=description,
            category=category,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            runner=runner,
            metadata=metadata or {},
        )

        self._benchmarks[benchmark_id] = benchmark

        return benchmark

    def run_benchmark(
        self,
        benchmark_id: str,
        threshold_ms: Optional[float] = None,
    ) -> BenchmarkResult:
        """Run a single benchmark."""
        self._result_counter += 1
        result_id = f"BMRESULT-{self._result_counter:05d}"

        benchmark = self._benchmarks.get(benchmark_id)
        if not benchmark:
            raise ValueError(f"Benchmark {benchmark_id} not found")

        measurements = []

        # Warmup iterations
        for i in range(benchmark.warmup_iterations):
            duration = benchmark.runner()
            measurements.append(BenchmarkMeasurement(
                iteration=i,
                duration_ms=duration,
                timestamp=datetime.now(),
                is_warmup=True,
            ))

        # Actual iterations
        for i in range(benchmark.iterations):
            duration = benchmark.runner()
            measurements.append(BenchmarkMeasurement(
                iteration=i + benchmark.warmup_iterations,
                duration_ms=duration,
                timestamp=datetime.now(),
                is_warmup=False,
            ))

        # Calculate statistics (excluding warmup)
        durations = [m.duration_ms for m in measurements if not m.is_warmup]
        sorted_durations = sorted(durations)

        mean = statistics.mean(durations) if durations else 0
        median = statistics.median(durations) if durations else 0
        std_dev = statistics.stdev(durations) if len(durations) > 1 else 0

        p50_idx = int(len(sorted_durations) * 0.5)
        p90_idx = int(len(sorted_durations) * 0.9)
        p99_idx = int(len(sorted_durations) * 0.99)

        # Determine pass/fail
        passed = True
        if threshold_ms and mean > threshold_ms:
            passed = False

        result = BenchmarkResult(
            result_id=result_id,
            benchmark_id=benchmark_id,
            benchmark_name=benchmark.name,
            category=benchmark.category,
            measurements=measurements,
            min_ms=min(durations) if durations else 0,
            max_ms=max(durations) if durations else 0,
            mean_ms=mean,
            median_ms=median,
            std_dev_ms=std_dev,
            p50_ms=sorted_durations[p50_idx] if sorted_durations else 0,
            p90_ms=sorted_durations[min(p90_idx, len(sorted_durations) - 1)] if sorted_durations else 0,
            p99_ms=sorted_durations[min(p99_idx, len(sorted_durations) - 1)] if sorted_durations else 0,
            total_iterations=len(durations),
            passed=passed,
            run_at=datetime.now(),
            metadata={"threshold_ms": threshold_ms},
        )

        if benchmark_id not in self._history:
            self._history[benchmark_id] = []
        self._history[benchmark_id].append(result)

        return result

    def create_suite(
        self,
        name: str,
        description: str = "",
        benchmark_ids: Optional[List[str]] = None,
        category: Optional[BenchmarkCategory] = None,
    ) -> BenchmarkSuite:
        """Create a benchmark suite."""
        self._suite_counter += 1
        suite_id = f"SUITE-{self._suite_counter:05d}"

        # Get benchmarks
        if benchmark_ids:
            benchmarks = [self._benchmarks[bid] for bid in benchmark_ids if bid in self._benchmarks]
        elif category:
            benchmarks = [b for b in self._benchmarks.values() if b.category == category]
        else:
            benchmarks = list(self._benchmarks.values())

        suite = BenchmarkSuite(
            suite_id=suite_id,
            name=name,
            description=description,
            benchmarks=benchmarks,
            created_at=datetime.now(),
        )

        self._suites[suite_id] = suite

        return suite

    def run_suite(
        self,
        suite_id: str,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> SuiteResult:
        """Run all benchmarks in a suite."""
        suite = self._suites.get(suite_id)
        if not suite:
            raise ValueError(f"Suite {suite_id} not found")

        thresholds = thresholds or {}
        start_time = datetime.now()

        results = []
        for benchmark in suite.benchmarks:
            threshold = thresholds.get(benchmark.benchmark_id)
            result = self.run_benchmark(benchmark.benchmark_id, threshold)
            results.append(result)

        end_time = datetime.now()
        total_duration = (end_time - start_time).total_seconds() * 1000

        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed

        suite_result = SuiteResult(
            suite_id=suite_id,
            suite_name=suite.name,
            results=results,
            total_benchmarks=len(results),
            passed_benchmarks=passed,
            failed_benchmarks=failed,
            total_duration_ms=total_duration,
            run_at=datetime.now(),
        )

        self._suite_history.append(suite_result)

        return suite_result

    def compare_results(
        self,
        result_a: BenchmarkResult,
        result_b: BenchmarkResult,
    ) -> Dict[str, Any]:
        """Compare two benchmark results."""
        def pct_change(old: float, new: float) -> float:
            if old == 0:
                return 0.0
            return ((new - old) / old) * 100

        return {
            "mean_change_pct": pct_change(result_a.mean_ms, result_b.mean_ms),
            "median_change_pct": pct_change(result_a.median_ms, result_b.median_ms),
            "p99_change_pct": pct_change(result_a.p99_ms, result_b.p99_ms),
            "std_dev_change_pct": pct_change(result_a.std_dev_ms, result_b.std_dev_ms),
            "is_faster": result_b.mean_ms < result_a.mean_ms,
            "is_slower": result_b.mean_ms > result_a.mean_ms * 1.1,
            "is_more_stable": result_b.std_dev_ms < result_a.std_dev_ms,
        }

    def get_benchmark_history(
        self,
        benchmark_id: str,
        limit: int = 100,
    ) -> List[BenchmarkResult]:
        """Get history for a specific benchmark."""
        history = self._history.get(benchmark_id, [])
        return history[-limit:]

    def get_trend(
        self,
        benchmark_id: str,
        window: int = 10,
    ) -> Dict[str, Any]:
        """Get performance trend for a benchmark."""
        history = self._history.get(benchmark_id, [])

        if len(history) < 2:
            return {"trend": "insufficient_data"}

        recent = history[-min(window, len(history)):]
        means = [r.mean_ms for r in recent]

        if len(means) >= 2:
            first_half = statistics.mean(means[:len(means)//2])
            second_half = statistics.mean(means[len(means)//2:])

            if second_half > first_half * 1.1:
                trend = "degrading"
            elif second_half < first_half * 0.9:
                trend = "improving"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"

        return {
            "trend": trend,
            "data_points": len(means),
            "recent_mean_ms": statistics.mean(means) if means else 0,
            "recent_std_dev_ms": statistics.stdev(means) if len(means) > 1 else 0,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get runner statistics."""
        total_results = sum(len(h) for h in self._history.values())

        return {
            "registered_benchmarks": len(self._benchmarks),
            "registered_suites": len(self._suites),
            "total_results": total_results,
            "suite_runs": len(self._suite_history),
            "categories": list(set(b.category.value for b in self._benchmarks.values())),
        }

    def format_result(self, result: BenchmarkResult) -> str:
        """Format a benchmark result."""
        status = "✅ PASSED" if result.passed else "❌ FAILED"

        lines = [
            "=" * 60,
            f"  {status} BENCHMARK RESULT",
            "=" * 60,
            "",
            f"  Name: {result.benchmark_name}",
            f"  Category: {result.category.value}",
            "",
            "-" * 60,
            "  STATISTICS",
            "-" * 60,
            "",
            f"  Mean: {result.mean_ms:.2f}ms",
            f"  Median: {result.median_ms:.2f}ms",
            f"  Std Dev: {result.std_dev_ms:.2f}ms",
            "",
            f"  Min: {result.min_ms:.2f}ms",
            f"  Max: {result.max_ms:.2f}ms",
            "",
            f"  P50: {result.p50_ms:.2f}ms",
            f"  P90: {result.p90_ms:.2f}ms",
            f"  P99: {result.p99_ms:.2f}ms",
            "",
            f"  Iterations: {result.total_iterations}",
            "",
            "=" * 60,
        ]

        return "\n".join(lines)

    def format_suite_result(self, result: SuiteResult) -> str:
        """Format a suite result."""
        lines = [
            "=" * 70,
            "  BENCHMARK SUITE RESULT",
            "=" * 70,
            "",
            f"  Suite: {result.suite_name}",
            f"  Total Benchmarks: {result.total_benchmarks}",
            f"  Passed: {result.passed_benchmarks}",
            f"  Failed: {result.failed_benchmarks}",
            f"  Duration: {result.total_duration_ms:.0f}ms",
            "",
            "-" * 70,
            "  RESULTS",
            "-" * 70,
            "",
        ]

        for bm_result in result.results:
            status = "✅" if bm_result.passed else "❌"
            lines.append(
                f"  {status} {bm_result.benchmark_name}: "
                f"{bm_result.mean_ms:.2f}ms (±{bm_result.std_dev_ms:.2f}ms)"
            )

        lines.extend(["", "=" * 70])
        return "\n".join(lines)


def create_benchmark_runner() -> BenchmarkRunner:
    """Create a benchmark runner instance."""
    return BenchmarkRunner()
