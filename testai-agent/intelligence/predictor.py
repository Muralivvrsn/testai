"""
TestAI Agent - Failure Predictor

AI-powered failure prediction that analyzes patterns,
code changes, and historical data to predict test failures
before they occur.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid
import math


class PredictionType(Enum):
    """Types of failure predictions."""
    FLAKY_TEST = "flaky_test"
    REGRESSION = "regression"
    ENVIRONMENT_ISSUE = "environment_issue"
    TIMING_ISSUE = "timing_issue"
    DEPENDENCY_FAILURE = "dependency_failure"
    CODE_CHANGE_IMPACT = "code_change_impact"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SELECTOR_BREAKAGE = "selector_breakage"


class RiskLevel(Enum):
    """Risk levels for predictions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class RiskFactor:
    """A factor contributing to failure risk."""
    factor_id: str
    name: str
    description: str
    weight: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    mitigation: str = ""


@dataclass
class FailurePrediction:
    """A failure prediction for a test."""
    prediction_id: str
    test_id: str
    prediction_type: PredictionType
    risk_level: RiskLevel
    probability: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    risk_factors: List[RiskFactor]
    predicted_at: datetime
    valid_until: datetime
    description: str
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestHistory:
    """Historical data for a test."""
    test_id: str
    total_runs: int
    pass_count: int
    fail_count: int
    flaky_count: int
    avg_duration_ms: float
    duration_variance: float
    last_failure: Optional[datetime]
    recent_results: List[bool]  # Last N results, True=pass
    failure_patterns: Dict[str, int] = field(default_factory=dict)


@dataclass
class CodeChange:
    """A code change that may affect tests."""
    change_id: str
    files_changed: List[str]
    lines_added: int
    lines_removed: int
    change_type: str  # feature, bugfix, refactor
    timestamp: datetime
    affected_tests: List[str] = field(default_factory=list)


class FailurePredictor:
    """
    AI-powered failure prediction engine.

    Features:
    - Historical pattern analysis
    - Code change impact prediction
    - Flakiness detection
    - Risk scoring
    - Proactive recommendations
    """

    # Risk weights for different factors
    RISK_WEIGHTS = {
        "flakiness": 0.25,
        "recent_failures": 0.20,
        "code_changes": 0.20,
        "duration_variance": 0.10,
        "environment": 0.10,
        "dependencies": 0.10,
        "age": 0.05,
    }

    # Flakiness thresholds
    FLAKY_THRESHOLD = 0.1  # 10% inconsistent results = flaky

    def __init__(
        self,
        history_window: int = 100,
        prediction_horizon_hours: int = 24,
    ):
        """Initialize the predictor."""
        self._history_window = history_window
        self._prediction_horizon = prediction_horizon_hours

        self._test_history: Dict[str, TestHistory] = {}
        self._code_changes: List[CodeChange] = []
        self._predictions: Dict[str, List[FailurePrediction]] = {}
        self._environment_issues: Dict[str, int] = {}

        self._prediction_counter = 0

    def record_result(
        self,
        test_id: str,
        passed: bool,
        duration_ms: float,
        failure_type: Optional[str] = None,
    ) -> None:
        """Record a test result for learning."""
        if test_id not in self._test_history:
            self._test_history[test_id] = TestHistory(
                test_id=test_id,
                total_runs=0,
                pass_count=0,
                fail_count=0,
                flaky_count=0,
                avg_duration_ms=0.0,
                duration_variance=0.0,
                last_failure=None,
                recent_results=[],
                failure_patterns={},
            )

        history = self._test_history[test_id]
        history.total_runs += 1

        if passed:
            history.pass_count += 1
        else:
            history.fail_count += 1
            history.last_failure = datetime.now()
            if failure_type:
                history.failure_patterns[failure_type] = (
                    history.failure_patterns.get(failure_type, 0) + 1
                )

        # Update recent results
        history.recent_results.append(passed)
        if len(history.recent_results) > self._history_window:
            history.recent_results.pop(0)

        # Update average duration
        n = history.total_runs
        old_avg = history.avg_duration_ms
        history.avg_duration_ms = old_avg + (duration_ms - old_avg) / n

        # Update variance (Welford's algorithm)
        if n > 1:
            history.duration_variance = (
                (n - 2) / (n - 1) * history.duration_variance
                + (duration_ms - old_avg) ** 2 / n
            )

        # Detect flakiness
        if len(history.recent_results) >= 10:
            recent = history.recent_results[-10:]
            transitions = sum(
                1 for i in range(1, len(recent))
                if recent[i] != recent[i - 1]
            )
            if transitions >= 3:  # Alternating results = flaky
                history.flaky_count += 1

    def record_code_change(
        self,
        files_changed: List[str],
        lines_added: int,
        lines_removed: int,
        change_type: str = "feature",
        affected_tests: Optional[List[str]] = None,
    ) -> CodeChange:
        """Record a code change for impact analysis."""
        change = CodeChange(
            change_id=f"CHG-{uuid.uuid4().hex[:8]}",
            files_changed=files_changed,
            lines_added=lines_added,
            lines_removed=lines_removed,
            change_type=change_type,
            timestamp=datetime.now(),
            affected_tests=affected_tests or [],
        )

        self._code_changes.append(change)

        # Keep only recent changes
        cutoff = datetime.now() - timedelta(days=30)
        self._code_changes = [c for c in self._code_changes if c.timestamp > cutoff]

        return change

    def record_environment_issue(
        self,
        issue_type: str,
    ) -> None:
        """Record an environment issue."""
        self._environment_issues[issue_type] = (
            self._environment_issues.get(issue_type, 0) + 1
        )

    def predict_failure(
        self,
        test_id: str,
    ) -> FailurePrediction:
        """Predict potential failure for a test."""
        self._prediction_counter += 1
        prediction_id = f"PRED-{self._prediction_counter:05d}"

        history = self._test_history.get(test_id)
        risk_factors = []
        total_risk = 0.0

        # Analyze flakiness
        flakiness_risk = self._analyze_flakiness(test_id, history)
        if flakiness_risk:
            risk_factors.append(flakiness_risk)
            total_risk += flakiness_risk.weight * flakiness_risk.confidence

        # Analyze recent failures
        recent_failure_risk = self._analyze_recent_failures(test_id, history)
        if recent_failure_risk:
            risk_factors.append(recent_failure_risk)
            total_risk += recent_failure_risk.weight * recent_failure_risk.confidence

        # Analyze code change impact
        code_change_risk = self._analyze_code_changes(test_id)
        if code_change_risk:
            risk_factors.append(code_change_risk)
            total_risk += code_change_risk.weight * code_change_risk.confidence

        # Analyze duration variance
        duration_risk = self._analyze_duration_variance(test_id, history)
        if duration_risk:
            risk_factors.append(duration_risk)
            total_risk += duration_risk.weight * duration_risk.confidence

        # Determine prediction type
        prediction_type = self._determine_prediction_type(risk_factors)

        # Calculate probability and risk level
        probability = min(1.0, total_risk)
        confidence = self._calculate_confidence(history, risk_factors)
        risk_level = self._calculate_risk_level(probability, confidence)

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_factors, prediction_type)

        prediction = FailurePrediction(
            prediction_id=prediction_id,
            test_id=test_id,
            prediction_type=prediction_type,
            risk_level=risk_level,
            probability=probability,
            confidence=confidence,
            risk_factors=risk_factors,
            predicted_at=datetime.now(),
            valid_until=datetime.now() + timedelta(hours=self._prediction_horizon),
            description=self._generate_description(prediction_type, probability, risk_factors),
            recommendations=recommendations,
        )

        # Store prediction
        if test_id not in self._predictions:
            self._predictions[test_id] = []
        self._predictions[test_id].append(prediction)

        return prediction

    def predict_batch(
        self,
        test_ids: List[str],
    ) -> List[FailurePrediction]:
        """Predict failures for multiple tests."""
        return [self.predict_failure(test_id) for test_id in test_ids]

    def get_high_risk_tests(
        self,
        threshold: float = 0.5,
    ) -> List[FailurePrediction]:
        """Get tests with high failure probability."""
        all_predictions = []

        for test_id in self._test_history:
            prediction = self.predict_failure(test_id)
            if prediction.probability >= threshold:
                all_predictions.append(prediction)

        return sorted(all_predictions, key=lambda p: p.probability, reverse=True)

    def get_test_health(
        self,
        test_id: str,
    ) -> Dict[str, Any]:
        """Get health metrics for a test."""
        history = self._test_history.get(test_id)

        if not history:
            return {
                "test_id": test_id,
                "health_score": 1.0,
                "status": "unknown",
                "data_points": 0,
            }

        # Calculate health score
        pass_rate = history.pass_count / max(1, history.total_runs)
        flaky_rate = history.flaky_count / max(1, history.total_runs)

        health_score = pass_rate * (1 - flaky_rate * 0.5)

        # Determine status
        if health_score >= 0.95:
            status = "healthy"
        elif health_score >= 0.80:
            status = "stable"
        elif health_score >= 0.60:
            status = "unstable"
        else:
            status = "critical"

        return {
            "test_id": test_id,
            "health_score": round(health_score, 3),
            "status": status,
            "pass_rate": round(pass_rate, 3),
            "flaky_rate": round(flaky_rate, 3),
            "total_runs": history.total_runs,
            "recent_trend": self._calculate_trend(history.recent_results),
            "avg_duration_ms": round(history.avg_duration_ms, 2),
        }

    def _analyze_flakiness(
        self,
        test_id: str,
        history: Optional[TestHistory],
    ) -> Optional[RiskFactor]:
        """Analyze flakiness risk."""
        if not history or history.total_runs < 5:
            return None

        flaky_rate = history.flaky_count / history.total_runs

        if flaky_rate < self.FLAKY_THRESHOLD:
            return None

        return RiskFactor(
            factor_id=f"RF-{uuid.uuid4().hex[:6]}",
            name="Flakiness",
            description=f"Test shows {flaky_rate:.1%} flaky behavior",
            weight=self.RISK_WEIGHTS["flakiness"],
            confidence=min(1.0, flaky_rate * 3),
            evidence=[
                f"Flaky runs: {history.flaky_count}",
                f"Total runs: {history.total_runs}",
            ],
            mitigation="Add retry logic or stabilize test conditions",
        )

    def _analyze_recent_failures(
        self,
        test_id: str,
        history: Optional[TestHistory],
    ) -> Optional[RiskFactor]:
        """Analyze recent failure patterns."""
        if not history or len(history.recent_results) < 3:
            return None

        recent = history.recent_results[-10:]
        fail_count = sum(1 for r in recent if not r)

        if fail_count == 0:
            return None

        fail_rate = fail_count / len(recent)

        return RiskFactor(
            factor_id=f"RF-{uuid.uuid4().hex[:6]}",
            name="Recent Failures",
            description=f"{fail_count} failures in last {len(recent)} runs",
            weight=self.RISK_WEIGHTS["recent_failures"],
            confidence=fail_rate,
            evidence=[
                f"Recent fail rate: {fail_rate:.1%}",
                f"Pattern: {''.join('✓' if r else '✗' for r in recent)}",
            ],
            mitigation="Investigate recent failure causes",
        )

    def _analyze_code_changes(
        self,
        test_id: str,
    ) -> Optional[RiskFactor]:
        """Analyze code change impact."""
        recent_changes = [
            c for c in self._code_changes
            if datetime.now() - c.timestamp < timedelta(days=7)
        ]

        if not recent_changes:
            return None

        # Check for changes affecting this test
        affecting_changes = [
            c for c in recent_changes
            if test_id in c.affected_tests
        ]

        if not affecting_changes:
            return None

        total_impact = sum(
            c.lines_added + c.lines_removed
            for c in affecting_changes
        )

        return RiskFactor(
            factor_id=f"RF-{uuid.uuid4().hex[:6]}",
            name="Code Changes",
            description=f"{len(affecting_changes)} recent changes affect this test",
            weight=self.RISK_WEIGHTS["code_changes"],
            confidence=min(1.0, total_impact / 100),
            evidence=[
                f"Changes: {len(affecting_changes)}",
                f"Lines modified: {total_impact}",
            ],
            mitigation="Review test after code changes",
        )

    def _analyze_duration_variance(
        self,
        test_id: str,
        history: Optional[TestHistory],
    ) -> Optional[RiskFactor]:
        """Analyze execution time variance."""
        if not history or history.total_runs < 5:
            return None

        if history.avg_duration_ms == 0:
            return None

        cv = math.sqrt(history.duration_variance) / history.avg_duration_ms  # Coefficient of variation

        if cv < 0.3:  # Less than 30% variance is acceptable
            return None

        return RiskFactor(
            factor_id=f"RF-{uuid.uuid4().hex[:6]}",
            name="Timing Variance",
            description=f"High execution time variance (CV={cv:.2f})",
            weight=self.RISK_WEIGHTS["duration_variance"],
            confidence=min(1.0, cv),
            evidence=[
                f"Avg duration: {history.avg_duration_ms:.0f}ms",
                f"Std dev: {math.sqrt(history.duration_variance):.0f}ms",
            ],
            mitigation="Add explicit waits or reduce environment sensitivity",
        )

    def _determine_prediction_type(
        self,
        risk_factors: List[RiskFactor],
    ) -> PredictionType:
        """Determine the primary prediction type."""
        if not risk_factors:
            return PredictionType.REGRESSION

        # Find highest weight factor
        top_factor = max(risk_factors, key=lambda f: f.weight * f.confidence)

        type_mapping = {
            "Flakiness": PredictionType.FLAKY_TEST,
            "Recent Failures": PredictionType.REGRESSION,
            "Code Changes": PredictionType.CODE_CHANGE_IMPACT,
            "Timing Variance": PredictionType.TIMING_ISSUE,
        }

        return type_mapping.get(top_factor.name, PredictionType.REGRESSION)

    def _calculate_confidence(
        self,
        history: Optional[TestHistory],
        risk_factors: List[RiskFactor],
    ) -> float:
        """Calculate prediction confidence."""
        if not history:
            return 0.3  # Low confidence without history

        # Base confidence on data points
        data_confidence = min(1.0, history.total_runs / 50)

        # Average factor confidences
        if risk_factors:
            factor_confidence = sum(f.confidence for f in risk_factors) / len(risk_factors)
        else:
            factor_confidence = 0.5

        return (data_confidence + factor_confidence) / 2

    def _calculate_risk_level(
        self,
        probability: float,
        confidence: float,
    ) -> RiskLevel:
        """Calculate risk level from probability and confidence."""
        risk_score = probability * confidence

        if risk_score >= 0.7:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.1:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _calculate_trend(
        self,
        recent_results: List[bool],
    ) -> str:
        """Calculate trend from recent results."""
        if len(recent_results) < 5:
            return "insufficient_data"

        first_half = recent_results[:len(recent_results) // 2]
        second_half = recent_results[len(recent_results) // 2:]

        first_pass_rate = sum(first_half) / len(first_half)
        second_pass_rate = sum(second_half) / len(second_half)

        diff = second_pass_rate - first_pass_rate

        if diff > 0.1:
            return "improving"
        elif diff < -0.1:
            return "degrading"
        else:
            return "stable"

    def _generate_recommendations(
        self,
        risk_factors: List[RiskFactor],
        prediction_type: PredictionType,
    ) -> List[str]:
        """Generate recommendations based on risk factors."""
        recommendations = []

        for factor in risk_factors:
            if factor.mitigation:
                recommendations.append(factor.mitigation)

        # Add type-specific recommendations
        type_recommendations = {
            PredictionType.FLAKY_TEST: [
                "Consider adding retry mechanisms",
                "Review async operations and waits",
            ],
            PredictionType.REGRESSION: [
                "Check recent code changes",
                "Verify test assertions are still valid",
            ],
            PredictionType.CODE_CHANGE_IMPACT: [
                "Review code changes affecting this test",
                "Update test to match new behavior if needed",
            ],
            PredictionType.TIMING_ISSUE: [
                "Add explicit waits for dynamic content",
                "Consider mocking slow operations",
            ],
        }

        for rec in type_recommendations.get(prediction_type, []):
            if rec not in recommendations:
                recommendations.append(rec)

        return recommendations[:5]  # Limit to 5

    def _generate_description(
        self,
        prediction_type: PredictionType,
        probability: float,
        risk_factors: List[RiskFactor],
    ) -> str:
        """Generate human-readable description."""
        factor_names = [f.name for f in risk_factors]

        if not factor_names:
            return f"Low risk of {prediction_type.value} ({probability:.0%} probability)"

        return (
            f"Predicted {prediction_type.value} with {probability:.0%} probability. "
            f"Contributing factors: {', '.join(factor_names)}"
        )

    def get_prediction_history(
        self,
        test_id: str,
        limit: int = 10,
    ) -> List[FailurePrediction]:
        """Get prediction history for a test."""
        predictions = self._predictions.get(test_id, [])
        return predictions[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get predictor statistics."""
        all_predictions = [
            p for preds in self._predictions.values()
            for p in preds
        ]

        return {
            "tracked_tests": len(self._test_history),
            "total_predictions": len(all_predictions),
            "code_changes_tracked": len(self._code_changes),
            "environment_issues": sum(self._environment_issues.values()),
            "avg_probability": (
                sum(p.probability for p in all_predictions) / len(all_predictions)
                if all_predictions else 0
            ),
        }

    def format_prediction(self, prediction: FailurePrediction) -> str:
        """Format a prediction for display."""
        risk_emoji = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢",
            RiskLevel.MINIMAL: "⚪",
        }

        lines = [
            "=" * 60,
            f"  {risk_emoji[prediction.risk_level]} FAILURE PREDICTION",
            "=" * 60,
            "",
            f"  Test: {prediction.test_id}",
            f"  Type: {prediction.prediction_type.value}",
            f"  Risk Level: {prediction.risk_level.value}",
            f"  Probability: {prediction.probability:.1%}",
            f"  Confidence: {prediction.confidence:.1%}",
            "",
            "-" * 60,
            "  RISK FACTORS",
            "-" * 60,
            "",
        ]

        for factor in prediction.risk_factors:
            lines.append(f"  • {factor.name} (weight: {factor.weight:.0%})")
            lines.append(f"    {factor.description}")

        if prediction.recommendations:
            lines.extend([
                "",
                "-" * 60,
                "  RECOMMENDATIONS",
                "-" * 60,
                "",
            ])
            for rec in prediction.recommendations:
                lines.append(f"  → {rec}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_failure_predictor(
    history_window: int = 100,
    prediction_horizon_hours: int = 24,
) -> FailurePredictor:
    """Create a failure predictor instance."""
    return FailurePredictor(
        history_window=history_window,
        prediction_horizon_hours=prediction_horizon_hours,
    )
