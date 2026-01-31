"""
TestAI Agent - Cross-Browser Test Matrix Module

Generates test matrices for cross-browser and cross-device
testing with intelligent configuration selection.
"""

from .generator import (
    MatrixGenerator,
    TestMatrix,
    MatrixCell,
    BrowserConfig,
    DeviceConfig,
    create_matrix_generator,
)

from .optimizer import (
    MatrixOptimizer,
    OptimizedMatrix,
    CoverageStrategy,
    create_matrix_optimizer,
)

from .reporter import (
    MatrixReporter,
    MatrixReport,
    CompatibilityIssue,
    create_matrix_reporter,
)

__all__ = [
    # Generator
    "MatrixGenerator",
    "TestMatrix",
    "MatrixCell",
    "BrowserConfig",
    "DeviceConfig",
    "create_matrix_generator",
    # Optimizer
    "MatrixOptimizer",
    "OptimizedMatrix",
    "CoverageStrategy",
    "create_matrix_optimizer",
    # Reporter
    "MatrixReporter",
    "MatrixReport",
    "CompatibilityIssue",
    "create_matrix_reporter",
]
