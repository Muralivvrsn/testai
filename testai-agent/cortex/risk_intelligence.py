"""
TestAI Agent - Risk Intelligence

Intelligent test prioritization based on historical data, business risk,
and learned patterns. This goes beyond simple priority scoring by
incorporating real execution history and learning from failures.

Key capabilities:
1. Historical Risk Analysis - Tests that failed before are higher risk
2. Business Impact Scoring - Features with higher business value get priority
3. Change-Based Risk - Recently changed areas get more testing
4. Dependency Risk - Tests for components with many dependencies
5. Time-Decay Learning - Recent failures matter more than old ones

This is what makes the agent smarter than a human - it REMEMBERS
every failure and uses that knowledge to prioritize future testing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import math


class RiskLevel(Enum):
    """Risk levels for tests and features."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ImpactArea(Enum):
    """Business impact areas."""
    REVENUE = "revenue"  # Direct revenue impact (checkout, payment)
    SECURITY = "security"  # Security vulnerabilities
    DATA_INTEGRITY = "data_integrity"  # Data loss or corruption
    USER_EXPERIENCE = "user_experience"  # UX degradation
    COMPLIANCE = "compliance"  # Regulatory compliance
    REPUTATION = "reputation"  # Brand reputation


@dataclass
class HistoricalRisk:
    """Risk data from historical test executions."""
    test_id: str
    total_runs: int = 0
    failures: int = 0
    flaky_count: int = 0
    last_failure: Optional[datetime] = None
    failure_streak: int = 0  # Consecutive failures
    avg_fix_time_hours: float = 0.0

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        if self.total_runs == 0:
            return 0.0
        return self.failures / self.total_runs

    @property
    def is_flaky(self) -> bool:
        """Check if test is flaky (inconsistent)."""
        return self.flaky_count >= 2

    @property
    def recently_failed(self) -> bool:
        """Check if test failed recently (within 7 days)."""
        if not self.last_failure:
            return False
        return (datetime.now() - self.last_failure).days <= 7


@dataclass
class FeatureRisk:
    """Risk assessment for a feature/page."""
    feature_name: str
    page_type: str

    # Business impact
    revenue_impact: float = 0.0  # 0-1
    user_impact: float = 0.0  # 0-1
    security_criticality: float = 0.0  # 0-1
    compliance_relevance: float = 0.0  # 0-1

    # Technical risk
    complexity_score: float = 0.0  # 0-1
    dependency_count: int = 0
    recent_changes: int = 0

    # Historical data
    total_bugs_found: int = 0
    critical_bugs_found: int = 0
    avg_bug_severity: float = 0.0

    def calculate_overall_risk(self) -> float:
        """Calculate overall risk score (0-1)."""
        # Weighted combination
        business_risk = (
            self.revenue_impact * 0.3 +
            self.user_impact * 0.2 +
            self.security_criticality * 0.3 +
            self.compliance_relevance * 0.2
        )

        technical_risk = (
            self.complexity_score * 0.4 +
            min(self.dependency_count / 10, 1.0) * 0.3 +
            min(self.recent_changes / 5, 1.0) * 0.3
        )

        historical_risk = 0.0
        if self.total_bugs_found > 0:
            historical_risk = min(self.total_bugs_found / 20, 1.0) * 0.5
            historical_risk += min(self.critical_bugs_found / 5, 1.0) * 0.5

        # Combined score
        return (
            business_risk * 0.4 +
            technical_risk * 0.3 +
            historical_risk * 0.3
        )


@dataclass
class RiskScore:
    """Complete risk score for a test case."""
    test_id: str
    test_title: str

    # Individual risk factors
    historical_risk: float = 0.0  # Based on past failures
    business_risk: float = 0.0  # Business impact
    technical_risk: float = 0.0  # Code complexity
    recency_risk: float = 0.0  # Recent changes/failures
    dependency_risk: float = 0.0  # Component dependencies

    # Final scores
    composite_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM

    # Explanation
    risk_factors: List[str] = field(default_factory=list)

    # Recommended action
    recommended_priority: int = 50  # 1-100


class RiskIntelligence:
    """
    Intelligent risk-based test prioritization.

    This system combines multiple risk factors to prioritize tests
    in a way that maximizes bug detection while minimizing testing time.
    """

    # Default business impact by page type
    PAGE_TYPE_IMPACT = {
        "checkout": {"revenue": 0.95, "user": 0.9, "security": 0.9, "compliance": 0.8},
        "payment": {"revenue": 0.95, "user": 0.9, "security": 0.95, "compliance": 0.9},
        "login": {"revenue": 0.3, "user": 0.8, "security": 0.95, "compliance": 0.7},
        "signup": {"revenue": 0.5, "user": 0.85, "security": 0.8, "compliance": 0.75},
        "profile": {"revenue": 0.2, "user": 0.7, "security": 0.7, "compliance": 0.6},
        "search": {"revenue": 0.6, "user": 0.85, "security": 0.3, "compliance": 0.2},
        "dashboard": {"revenue": 0.4, "user": 0.75, "security": 0.5, "compliance": 0.3},
    }

    # Category risk multipliers
    CATEGORY_MULTIPLIERS = {
        "security": 1.5,
        "data_integrity": 1.4,
        "payment": 1.4,
        "authentication": 1.3,
        "authorization": 1.3,
        "functional": 1.0,
        "ui": 0.8,
        "accessibility": 0.9,
        "performance": 0.9,
        "edge_case": 1.1,
    }

    # Time decay factor (how much recent failures matter more)
    TIME_DECAY_DAYS = 30  # Failures older than this matter less

    def __init__(self):
        """Initialize risk intelligence."""
        # Historical data storage
        self._test_history: Dict[str, HistoricalRisk] = {}
        self._feature_risks: Dict[str, FeatureRisk] = {}

        # Learning data
        self._bug_hotspots: Dict[str, int] = defaultdict(int)
        self._failure_correlations: Dict[Tuple[str, str], int] = defaultdict(int)

        # Statistics
        self._stats = {
            "tests_scored": 0,
            "high_risk_identified": 0,
            "prioritizations_made": 0,
        }

    def record_test_result(
        self,
        test_id: str,
        passed: bool,
        execution_time_ms: float = 0,
        was_flaky: bool = False,
    ) -> None:
        """
        Record a test execution result for learning.

        This is how the system learns which tests are risky.
        """
        if test_id not in self._test_history:
            self._test_history[test_id] = HistoricalRisk(test_id=test_id)

        history = self._test_history[test_id]
        history.total_runs += 1

        if not passed:
            history.failures += 1
            history.last_failure = datetime.now()
            history.failure_streak += 1
        else:
            history.failure_streak = 0

        if was_flaky:
            history.flaky_count += 1

    def record_bug(
        self,
        feature: str,
        page_type: str,
        severity: str,
        category: str,
    ) -> None:
        """Record a bug found for risk learning."""
        # Create feature risk if needed
        key = f"{page_type}:{feature}"
        if key not in self._feature_risks:
            self._feature_risks[key] = FeatureRisk(
                feature_name=feature,
                page_type=page_type,
            )

        risk = self._feature_risks[key]
        risk.total_bugs_found += 1

        if severity in ["critical", "high"]:
            risk.critical_bugs_found += 1

        # Track hotspots
        self._bug_hotspots[page_type] += 1
        self._bug_hotspots[category] += 1

    def score_test(
        self,
        test_id: str,
        test_title: str,
        category: str,
        page_type: str,
        steps: List[str] = None,
    ) -> RiskScore:
        """
        Score a test case for risk-based prioritization.

        This combines multiple factors to determine how important
        this test is relative to others.
        """
        self._stats["tests_scored"] += 1

        score = RiskScore(
            test_id=test_id,
            test_title=test_title,
        )

        # 1. Historical risk
        score.historical_risk = self._calculate_historical_risk(test_id)

        # 2. Business risk
        score.business_risk = self._calculate_business_risk(page_type, category)

        # 3. Technical risk
        score.technical_risk = self._calculate_technical_risk(
            page_type, category, steps or []
        )

        # 4. Recency risk
        score.recency_risk = self._calculate_recency_risk(test_id, page_type)

        # 5. Dependency risk
        score.dependency_risk = self._calculate_dependency_risk(page_type, category)

        # Calculate composite score (weighted)
        score.composite_score = (
            score.historical_risk * 0.30 +
            score.business_risk * 0.25 +
            score.technical_risk * 0.15 +
            score.recency_risk * 0.20 +
            score.dependency_risk * 0.10
        )

        # Apply category multiplier
        multiplier = self.CATEGORY_MULTIPLIERS.get(category.lower(), 1.0)
        score.composite_score = min(1.0, score.composite_score * multiplier)

        # Determine risk level
        score.risk_level = self._determine_risk_level(score.composite_score)

        # Generate risk factors explanation
        score.risk_factors = self._generate_risk_factors(score, page_type, category)

        # Calculate recommended priority (1-100, higher = more important)
        score.recommended_priority = int(score.composite_score * 100)

        if score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            self._stats["high_risk_identified"] += 1

        return score

    def _calculate_historical_risk(self, test_id: str) -> float:
        """Calculate risk based on test execution history."""
        if test_id not in self._test_history:
            return 0.3  # Default medium-low risk for new tests

        history = self._test_history[test_id]

        # Base on failure rate
        risk = history.failure_rate

        # Boost for recent failures
        if history.recently_failed:
            risk = min(1.0, risk + 0.2)

        # Boost for failure streaks
        if history.failure_streak >= 3:
            risk = min(1.0, risk + 0.3)

        # Boost for flaky tests
        if history.is_flaky:
            risk = min(1.0, risk + 0.15)

        return risk

    def _calculate_business_risk(self, page_type: str, category: str) -> float:
        """Calculate risk based on business impact."""
        impact = self.PAGE_TYPE_IMPACT.get(
            page_type.lower(),
            {"revenue": 0.3, "user": 0.5, "security": 0.3, "compliance": 0.2}
        )

        # Base business risk from page type
        base_risk = (
            impact["revenue"] * 0.3 +
            impact["user"] * 0.2 +
            impact["security"] * 0.3 +
            impact["compliance"] * 0.2
        )

        # Boost for security category
        if category.lower() == "security":
            base_risk = min(1.0, base_risk + 0.2)

        # Check for hotspots
        if page_type in self._bug_hotspots:
            hotspot_boost = min(0.2, self._bug_hotspots[page_type] / 50)
            base_risk = min(1.0, base_risk + hotspot_boost)

        return base_risk

    def _calculate_technical_risk(
        self,
        page_type: str,
        category: str,
        steps: List[str],
    ) -> float:
        """Calculate risk based on technical complexity."""
        risk = 0.3  # Base risk

        # Complexity from step count
        if steps:
            step_complexity = min(0.3, len(steps) / 20)
            risk += step_complexity

        # Complexity from page type
        complex_pages = {"checkout", "payment", "signup", "profile"}
        if page_type.lower() in complex_pages:
            risk += 0.2

        # Complexity from category
        complex_categories = {"security", "data_integrity", "integration"}
        if category.lower() in complex_categories:
            risk += 0.15

        return min(1.0, risk)

    def _calculate_recency_risk(self, test_id: str, page_type: str) -> float:
        """Calculate risk based on recent activity."""
        risk = 0.2  # Base

        # Recent test failures
        if test_id in self._test_history:
            history = self._test_history[test_id]
            if history.last_failure:
                days_since = (datetime.now() - history.last_failure).days
                if days_since <= 7:
                    risk += 0.4
                elif days_since <= 14:
                    risk += 0.2
                elif days_since <= 30:
                    risk += 0.1

        # Recent bugs in this area
        key = f"{page_type}:*"
        for k, feature_risk in self._feature_risks.items():
            if k.startswith(page_type):
                if feature_risk.recent_changes > 0:
                    risk += min(0.3, feature_risk.recent_changes * 0.1)
                    break

        return min(1.0, risk)

    def _calculate_dependency_risk(self, page_type: str, category: str) -> float:
        """Calculate risk based on dependencies."""
        # Pages that many things depend on
        high_dependency_pages = {"login", "authentication", "api", "database"}
        risk = 0.2

        if page_type.lower() in high_dependency_pages:
            risk += 0.3

        # Categories that affect many things
        high_dependency_categories = {"authentication", "authorization", "data_integrity"}
        if category.lower() in high_dependency_categories:
            risk += 0.2

        return min(1.0, risk)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from composite score."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _generate_risk_factors(
        self,
        score: RiskScore,
        page_type: str,
        category: str,
    ) -> List[str]:
        """Generate human-readable risk factors."""
        factors = []

        if score.historical_risk >= 0.5:
            factors.append("High historical failure rate")

        if score.business_risk >= 0.7:
            factors.append(f"High business impact ({page_type})")

        if score.technical_risk >= 0.5:
            factors.append("Complex technical implementation")

        if score.recency_risk >= 0.5:
            factors.append("Recent failures or changes")

        if score.dependency_risk >= 0.5:
            factors.append("Many dependent components")

        if category.lower() == "security":
            factors.append("Security-critical test")

        if not factors:
            factors.append("Standard risk profile")

        return factors

    def prioritize_tests(
        self,
        tests: List[Dict[str, Any]],
        max_count: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Prioritize a list of tests by risk.

        This is the main function for intelligent test ordering.
        Returns tests sorted by risk (highest risk first).
        """
        self._stats["prioritizations_made"] += 1

        scored_tests = []
        for test in tests:
            score = self.score_test(
                test_id=test.get("id", "unknown"),
                test_title=test.get("title", "Unknown Test"),
                category=test.get("category", "functional"),
                page_type=test.get("page_type", "general"),
                steps=test.get("steps", []),
            )

            # Attach score to test
            test_with_score = {
                **test,
                "_risk_score": score.composite_score,
                "_risk_level": score.risk_level.value,
                "_risk_factors": score.risk_factors,
                "_recommended_priority": score.recommended_priority,
            }
            scored_tests.append((score.composite_score, test_with_score))

        # Sort by score (highest first)
        scored_tests.sort(key=lambda x: x[0], reverse=True)

        # Extract just the tests
        prioritized = [t[1] for t in scored_tests]

        if max_count:
            prioritized = prioritized[:max_count]

        return prioritized

    def get_risk_summary(self) -> Dict[str, Any]:
        """Get a summary of risk intelligence data."""
        # Count risk levels
        risk_counts = defaultdict(int)
        for test_id, history in self._test_history.items():
            if history.failure_rate >= 0.5:
                risk_counts["high_failure_rate"] += 1
            if history.is_flaky:
                risk_counts["flaky"] += 1
            if history.recently_failed:
                risk_counts["recently_failed"] += 1

        return {
            "tests_tracked": len(self._test_history),
            "features_tracked": len(self._feature_risks),
            "bug_hotspots": dict(self._bug_hotspots),
            "risk_breakdown": dict(risk_counts),
            "stats": self._stats,
        }

    def get_recommendations(self, page_type: str) -> List[str]:
        """Get testing recommendations for a page type."""
        recommendations = []

        # Check for hotspots
        if self._bug_hotspots.get(page_type, 0) >= 5:
            recommendations.append(
                f"⚠️ {page_type} is a bug hotspot - increase test coverage"
            )

        # Check feature risks
        high_risk_features = [
            fr for k, fr in self._feature_risks.items()
            if k.startswith(page_type) and fr.calculate_overall_risk() >= 0.6
        ]
        if high_risk_features:
            recommendations.append(
                f"🔴 {len(high_risk_features)} high-risk features need attention"
            )

        # Check for flaky tests
        flaky_tests = [
            h for h in self._test_history.values()
            if h.is_flaky
        ]
        if flaky_tests:
            recommendations.append(
                f"⏱️ {len(flaky_tests)} flaky tests should be stabilized"
            )

        # Default recommendations based on page type
        if page_type in ["checkout", "payment"]:
            recommendations.append("💰 Prioritize payment flow and error handling")
        elif page_type == "login":
            recommendations.append("🔐 Focus on security and authentication tests")
        elif page_type == "signup":
            recommendations.append("📝 Test validation and user experience flows")

        return recommendations


def create_risk_intelligence() -> RiskIntelligence:
    """Create a risk intelligence instance."""
    return RiskIntelligence()
