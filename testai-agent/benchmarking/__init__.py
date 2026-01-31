"""
TestAI Agent - Performance Benchmarking

Comprehensive performance benchmarking and optimization
with profiling, bottleneck detection, and recommendations.
"""

from .profiler import (
    TestProfiler,
    ProfileType,
    ProfileResult,
    PerformanceMetrics,
    create_test_profiler,
)

from .optimizer import (
    TestOptimizer,
    OptimizationType,
    OptimizationResult,
    OptimizationRecommendation,
    create_test_optimizer,
)

from .benchmarks import (
    BenchmarkRunner,
    BenchmarkSuite,
    BenchmarkResult,
    BenchmarkCategory,
    BenchmarkMeasurement,
    Benchmark,
    create_benchmark_runner,
)

__all__ = [
    # Profiler
    "TestProfiler",
    "ProfileType",
    "ProfileResult",
    "PerformanceMetrics",
    "create_test_profiler",
    # Optimizer
    "TestOptimizer",
    "OptimizationType",
    "OptimizationResult",
    "OptimizationRecommendation",
    "create_test_optimizer",
    # Benchmarks
    "BenchmarkRunner",
    "BenchmarkSuite",
    "BenchmarkResult",
    "BenchmarkCategory",
    "BenchmarkMeasurement",
    "Benchmark",
    "create_benchmark_runner",
]
