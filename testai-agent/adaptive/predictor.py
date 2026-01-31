"""
TestAI Agent - Failure Predictor

Predicts test failures using machine learning
based on historical patterns and risk factors.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional
import math


class RiskLevel(Enum):
    """Risk levels for predictions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class RiskFactor(Enum):
    """Factors that contribute to failure risk."""
    RECENT_FAILURE = "recent_failure"
    HIGH_FLAKINESS = "high_flakiness"
    TIMING_VARIANCE = "timing_variance"
    ENVIRONMENT_SENSITIVITY = "environment_sensitivity"
    COMPLEX_SELECTORS = "complex_selectors"
    EXTERNAL_DEPENDENCY = "external_dependency"
    CODE_CHANGE = "code_change"
    INFRASTRUCTURE_CHANGE = "infrastructure_change"


@dataclass
class RiskContribution:
    """Contribution of a risk factor."""
    factor: RiskFactor
    weight: float
    score: float
    description: str


@dataclass
class PredictionResult:
    """Result of failure prediction."""
    test_id: str
    test_name: str
    failure_probability: float
    risk_level: RiskLevel
    risk_factors: List[RiskContribution]
    recommendations: List[str]
    confidence: float
    predicted_at: datetime = field(default_factory=datetime.now)

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]


@dataclass
class TestProfile:
    """Profile of a test for prediction."""
    test_id: str
    test_name: str
    pass_rate: float
    avg_duration_ms: float
    duration_variance: float
    flakiness_score: float
    last_failure: Optional[datetime]
    failure_count: int
    total_runs: int
    selectors: List[str] = field(default_factory=list)
    external_deps: List[str] = field(default_factory=list)
    recent_code_changes: int = 0
    tags: List[str] = field(default_factory=list)


class FailurePredictor:
    """
    Predicts test failures using ML techniques.

    Features:
    - Risk-based scoring
    - Multiple risk factors
    - Confidence calibration
    - Historical pattern matching
    """

    # Risk factor weights
    FACTOR_WEIGHTS = {
        RiskFactor.RECENT_FAILURE: 0.25,
        RiskFactor.HIGH_FLAKINESS: 0.20,
        RiskFactor.TIMING_VARIANCE: 0.10,
        RiskFactor.ENVIRONMENT_SENSITIVITY: 0.15,
        RiskFactor.COMPLEX_SELECTORS: 0.10,
        RiskFactor.EXTERNAL_DEPENDENCY: 0.10,
        RiskFactor.CODE_CHANGE: 0.05,
        RiskFactor.INFRASTRUCTURE_CHANGE: 0.05,
    }

    # Risk level thresholds
    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 0.8,
        RiskLevel.HIGH: 0.6,
        RiskLevel.MEDIUM: 0.4,
        RiskLevel.LOW: 0.2,
        RiskLevel.MINIMAL: 0.0,
    }

    def __init__(self):
        """Initialize the failure predictor."""
        self._profiles: Dict[str, TestProfile] = {}
        self._predictions: List[PredictionResult] = {}
        self._historical_accuracy: List[Tuple[float, bool]] = []

    def register_profile(self, profile: TestProfile):
        """Register a test profile."""
        self._profiles[profile.test_id] = profile

    def predict(self, test_id: str) -> Optional[PredictionResult]:
        """Predict failure probability for a test."""
        profile = self._profiles.get(test_id)
        if not profile:
            return None

        # Calculate risk factors
        risk_factors = self._calculate_risk_factors(profile)

        # Calculate overall failure probability
        failure_prob = self._calculate_failure_probability(risk_factors)

        # Determine risk level
        risk_level = self._determine_risk_level(failure_prob)

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_factors)

        # Calculate confidence
        confidence = self._calculate_confidence(profile)

        result = PredictionResult(
            test_id=test_id,
            test_name=profile.test_name,
            failure_probability=failure_prob,
            risk_level=risk_level,
            risk_factors=risk_factors,
            recommendations=recommendations,
            confidence=confidence,
        )

        self._predictions[test_id] = result
        return result

    def predict_batch(self, test_ids: List[str]) -> List[PredictionResult]:
        """Predict for multiple tests."""
        results = []
        for test_id in test_ids:
            result = self.predict(test_id)
            if result:
                results.append(result)
        return results

    def predict_all(self) -> List[PredictionResult]:
        """Predict for all registered tests."""
        return self.predict_batch(list(self._profiles.keys()))

    def _calculate_risk_factors(self, profile: TestProfile) -> List[RiskContribution]:
        """Calculate risk factors for a profile."""
        factors = []

        # Recent failure
        if profile.last_failure:
            days_since = (datetime.now() - profile.last_failure).days
            if days_since < 7:
                score = 1.0 - (days_since / 7)
                factors.append(RiskContribution(
                    factor=RiskFactor.RECENT_FAILURE,
                    weight=self.FACTOR_WEIGHTS[RiskFactor.RECENT_FAILURE],
                    score=score,
                    description=f"Failed {days_since} days ago",
                ))

        # Flakiness
        if profile.flakiness_score > 0.1:
            factors.append(RiskContribution(
                factor=RiskFactor.HIGH_FLAKINESS,
                weight=self.FACTOR_WEIGHTS[RiskFactor.HIGH_FLAKINESS],
                score=min(profile.flakiness_score * 2, 1.0),
                description=f"Flakiness score: {profile.flakiness_score:.1%}",
            ))

        # Timing variance
        if profile.duration_variance > 0.3:
            factors.append(RiskContribution(
                factor=RiskFactor.TIMING_VARIANCE,
                weight=self.FACTOR_WEIGHTS[RiskFactor.TIMING_VARIANCE],
                score=min(profile.duration_variance, 1.0),
                description=f"Duration varies by {profile.duration_variance:.1%}",
            ))

        # Complex selectors
        complex_count = sum(
            1 for s in profile.selectors
            if self._is_complex_selector(s)
        )
        if complex_count > 0:
            score = min(complex_count / 5, 1.0)
            factors.append(RiskContribution(
                factor=RiskFactor.COMPLEX_SELECTORS,
                weight=self.FACTOR_WEIGHTS[RiskFactor.COMPLEX_SELECTORS],
                score=score,
                description=f"{complex_count} complex selectors",
            ))

        # External dependencies
        if profile.external_deps:
            score = min(len(profile.external_deps) / 3, 1.0)
            factors.append(RiskContribution(
                factor=RiskFactor.EXTERNAL_DEPENDENCY,
                weight=self.FACTOR_WEIGHTS[RiskFactor.EXTERNAL_DEPENDENCY],
                score=score,
                description=f"{len(profile.external_deps)} external dependencies",
            ))

        # Code changes
        if profile.recent_code_changes > 0:
            score = min(profile.recent_code_changes / 10, 1.0)
            factors.append(RiskContribution(
                factor=RiskFactor.CODE_CHANGE,
                weight=self.FACTOR_WEIGHTS[RiskFactor.CODE_CHANGE],
                score=score,
                description=f"{profile.recent_code_changes} recent code changes",
            ))

        # Base failure rate
        if profile.pass_rate < 1.0 and profile.total_runs >= 5:
            base_failure = 1.0 - profile.pass_rate
            # This contributes to overall probability but isn't a separate factor
            factors.append(RiskContribution(
                factor=RiskFactor.RECENT_FAILURE,
                weight=0.15,  # Additional weight for historical failures
                score=base_failure,
                description=f"Historical pass rate: {profile.pass_rate:.1%}",
            ))

        return factors

    def _is_complex_selector(self, selector: str) -> bool:
        """Check if a selector is complex."""
        # Complex selectors are fragile
        indicators = [
            ":nth-child",
            ":nth-of-type",
            " > ",
            "[class*=",
            "[id*=",
            "//",  # XPath
            "contains(",
        ]
        return any(ind in selector for ind in indicators)

    def _calculate_failure_probability(
        self,
        risk_factors: List[RiskContribution],
    ) -> float:
        """Calculate overall failure probability."""
        if not risk_factors:
            return 0.05  # Base probability

        # Weighted sum
        weighted_sum = sum(f.weight * f.score for f in risk_factors)
        total_weight = sum(f.weight for f in risk_factors)

        if total_weight > 0:
            probability = weighted_sum / total_weight
        else:
            probability = 0.05

        # Apply sigmoid for smoothing
        probability = 1 / (1 + math.exp(-5 * (probability - 0.5)))

        return min(max(probability, 0.01), 0.99)

    def _determine_risk_level(self, probability: float) -> RiskLevel:
        """Determine risk level from probability."""
        for level, threshold in self.RISK_THRESHOLDS.items():
            if probability >= threshold:
                return level
        return RiskLevel.MINIMAL

    def _generate_recommendations(
        self,
        risk_factors: List[RiskContribution],
    ) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []

        factor_recs = {
            RiskFactor.RECENT_FAILURE: [
                "Investigate root cause of recent failure",
                "Add additional assertions to catch regression",
            ],
            RiskFactor.HIGH_FLAKINESS: [
                "Add explicit waits for dynamic elements",
                "Consider test isolation improvements",
            ],
            RiskFactor.TIMING_VARIANCE: [
                "Investigate performance bottlenecks",
                "Consider mocking slow dependencies",
            ],
            RiskFactor.COMPLEX_SELECTORS: [
                "Simplify selectors using data-testid attributes",
                "Reduce reliance on DOM structure",
            ],
            RiskFactor.EXTERNAL_DEPENDENCY: [
                "Add retry logic for external calls",
                "Consider mocking external services",
            ],
            RiskFactor.CODE_CHANGE: [
                "Review test coverage for changed code",
                "Run extended validation suite",
            ],
        }

        for factor in sorted(risk_factors, key=lambda f: f.score, reverse=True):
            if factor.factor in factor_recs:
                recommendations.extend(factor_recs[factor.factor][:1])

        return recommendations[:5]

    def _calculate_confidence(self, profile: TestProfile) -> float:
        """Calculate confidence in the prediction."""
        # More data = higher confidence
        if profile.total_runs < 5:
            return 0.3
        elif profile.total_runs < 20:
            return 0.5 + (profile.total_runs - 5) * 0.02
        elif profile.total_runs < 50:
            return 0.7 + (profile.total_runs - 20) * 0.005
        else:
            return min(0.85 + (profile.total_runs - 50) * 0.001, 0.95)

    def record_outcome(
        self,
        test_id: str,
        actual_failed: bool,
    ):
        """Record actual outcome for calibration."""
        prediction = self._predictions.get(test_id)
        if prediction:
            self._historical_accuracy.append((
                prediction.failure_probability,
                actual_failed,
            ))

    def get_accuracy_metrics(self) -> Dict[str, float]:
        """Get prediction accuracy metrics."""
        if not self._historical_accuracy:
            return {"accuracy": 0, "precision": 0, "recall": 0}

        # Calculate metrics
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        for prob, actual in self._historical_accuracy:
            predicted = prob >= 0.5
            if predicted and actual:
                true_positives += 1
            elif predicted and not actual:
                false_positives += 1
            elif not predicted and not actual:
                true_negatives += 1
            else:
                false_negatives += 1

        total = len(self._historical_accuracy)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0 else 0
        )

        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0 else 0
        )

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "total_predictions": total,
        }

    def get_high_risk_tests(
        self,
        threshold: float = 0.5,
    ) -> List[PredictionResult]:
        """Get tests with high failure probability."""
        results = []
        for test_id in self._profiles:
            prediction = self.predict(test_id)
            if prediction and prediction.failure_probability >= threshold:
                results.append(prediction)

        return sorted(
            results,
            key=lambda p: p.failure_probability,
            reverse=True,
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get predictor statistics."""
        predictions = list(self._predictions.values())

        if not predictions:
            return {
                "total_tests": len(self._profiles),
                "predictions_made": 0,
            }

        by_risk = {level: 0 for level in RiskLevel}
        for pred in predictions:
            by_risk[pred.risk_level] += 1

        avg_prob = sum(p.failure_probability for p in predictions) / len(predictions)
        avg_confidence = sum(p.confidence for p in predictions) / len(predictions)

        return {
            "total_tests": len(self._profiles),
            "predictions_made": len(predictions),
            "by_risk_level": {k.value: v for k, v in by_risk.items()},
            "avg_failure_probability": avg_prob,
            "avg_confidence": avg_confidence,
            "accuracy_metrics": self.get_accuracy_metrics(),
        }

    def format_predictions(self) -> str:
        """Format predictions as readable text."""
        lines = [
            "=" * 60,
            "  FAILURE PREDICTIONS",
            "=" * 60,
            "",
        ]

        stats = self.get_statistics()
        lines.extend([
            f"  Total Tests: {stats['total_tests']}",
            f"  Predictions: {stats['predictions_made']}",
            f"  Avg Failure Probability: {stats.get('avg_failure_probability', 0):.1%}",
            "",
        ])

        # Show high risk tests
        high_risk = self.get_high_risk_tests(0.5)

        if high_risk:
            lines.extend(["-" * 60, "  HIGH RISK TESTS", "-" * 60])

            for pred in high_risk[:10]:
                risk_icon = {
                    RiskLevel.CRITICAL: "🔴",
                    RiskLevel.HIGH: "🟠",
                    RiskLevel.MEDIUM: "🟡",
                }.get(pred.risk_level, "⚪")

                lines.extend([
                    "",
                    f"  {risk_icon} {pred.test_name}",
                    f"     Failure Probability: {pred.failure_probability:.1%}",
                    f"     Risk Level: {pred.risk_level.value}",
                    f"     Confidence: {pred.confidence:.1%}",
                ])

                if pred.risk_factors:
                    top_factor = max(pred.risk_factors, key=lambda f: f.score)
                    lines.append(f"     Top Risk: {top_factor.description}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


# Import for type hints
from typing import Tuple


def create_failure_predictor() -> FailurePredictor:
    """Create a failure predictor instance."""
    return FailurePredictor()
