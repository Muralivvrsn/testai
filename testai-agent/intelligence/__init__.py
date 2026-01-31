"""
TestAI Agent - AI-Powered Test Intelligence

Predictive analytics, failure prediction, and intelligent
insights for proactive test management.
"""

from .predictor import (
    FailurePredictor,
    PredictionType,
    FailurePrediction,
    RiskFactor,
    create_failure_predictor,
)

from .insights import (
    InsightEngine,
    InsightType,
    TestInsight,
    InsightPriority,
    create_insight_engine,
)

from .recommender import (
    TestRecommender,
    RecommendationType,
    TestRecommendation,
    create_test_recommender,
)

__all__ = [
    # Predictor
    "FailurePredictor",
    "PredictionType",
    "FailurePrediction",
    "RiskFactor",
    "create_failure_predictor",
    # Insights
    "InsightEngine",
    "InsightType",
    "TestInsight",
    "InsightPriority",
    "create_insight_engine",
    # Recommender
    "TestRecommender",
    "RecommendationType",
    "TestRecommendation",
    "create_test_recommender",
]
