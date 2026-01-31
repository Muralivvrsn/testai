"""
TestAI Agent - Adaptive Learning Module

Provides machine learning capabilities for improving test quality
based on historical results and patterns.
"""

from .learner import (
    AdaptiveLearner,
    LearningConfig,
    LearningInsight,
    create_adaptive_learner,
)

from .predictor import (
    FailurePredictor,
    PredictionResult,
    RiskFactor,
    create_failure_predictor,
)

from .optimizer import (
    TestOptimizer,
    OptimizationResult,
    OptimizationStrategy,
    create_test_optimizer,
)

__all__ = [
    # Learner
    "AdaptiveLearner",
    "LearningConfig",
    "LearningInsight",
    "create_adaptive_learner",
    # Predictor
    "FailurePredictor",
    "PredictionResult",
    "RiskFactor",
    "create_failure_predictor",
    # Optimizer
    "TestOptimizer",
    "OptimizationResult",
    "OptimizationStrategy",
    "create_test_optimizer",
]
