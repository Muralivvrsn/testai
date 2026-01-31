"""
TestAI Agent - Flakiness Analyzer

Deep analysis of flaky test root causes
with correlation and impact assessment.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class FlakeRootCause(Enum):
    """Root causes of test flakiness."""
    ASYNC_WAIT = "async_wait"           # Missing or insufficient waits
    RACE_CONDITION = "race_condition"   # Race conditions
    SHARED_STATE = "shared_state"       # Shared state between tests
    TEST_ORDER = "test_order"           # Order-dependent
    NETWORK_LATENCY = "network_latency" # Network timing
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Memory/CPU limits
    EXTERNAL_DEPENDENCY = "external_dependency"  # External service issues
    DATE_TIME = "date_time"             # Time-dependent logic
    RANDOM_DATA = "random_data"         # Non-deterministic data
    UI_ANIMATION = "ui_animation"       # Animation timing
    BROWSER_STATE = "browser_state"     # Browser state leakage
    DATABASE_STATE = "database_state"   # Database state issues
    UNKNOWN = "unknown"


class ImpactLevel(Enum):
    """Impact level of flaky tests."""
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


@dataclass
class FlakeCorrelation:
    """Correlation between flaky tests."""
    test_a_id: str
    test_b_id: str
    correlation_score: float
    shared_factors: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlakeAnalysis:
    """Analysis result for a flaky test."""
    analysis_id: str
    test_id: str
    test_name: str
    root_causes: List[FlakeRootCause]
    impact_level: ImpactLevel
    affected_suites: List[str]
    correlations: List[FlakeCorrelation]
    recommendations: List[str]
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class FlakinessAnalyzer:
    """
    Flakiness root cause analyzer.

    Features:
    - Root cause identification
    - Impact assessment
    - Correlation detection
    - Recommendations
    """

    def __init__(self):
        """Initialize the analyzer."""
        self._analyses: Dict[str, FlakeAnalysis] = {}
        self._correlations: List[FlakeCorrelation] = []
        self._analysis_counter = 0

        # Root cause patterns
        self._cause_patterns = self._init_cause_patterns()

    def _init_cause_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize root cause detection patterns."""
        return {
            FlakeRootCause.ASYNC_WAIT: {
                "keywords": ["timeout", "wait", "async", "promise", "then"],
                "error_patterns": ["timed out", "waiting for", "element not found"],
                "recommendations": [
                    "Add explicit waits for async operations",
                    "Use waitFor utilities instead of fixed delays",
                    "Implement retry logic for flaky assertions",
                ],
            },
            FlakeRootCause.RACE_CONDITION: {
                "keywords": ["race", "concurrent", "parallel", "thread"],
                "error_patterns": ["stale element", "element is detached", "not attached"],
                "recommendations": [
                    "Use synchronization primitives",
                    "Implement proper locking mechanisms",
                    "Avoid shared mutable state",
                ],
            },
            FlakeRootCause.SHARED_STATE: {
                "keywords": ["state", "global", "singleton", "cache"],
                "error_patterns": ["expected .* but got", "state mismatch"],
                "recommendations": [
                    "Isolate test state using setup/teardown",
                    "Reset shared resources between tests",
                    "Use fresh instances for each test",
                ],
            },
            FlakeRootCause.TEST_ORDER: {
                "keywords": ["order", "depends", "after", "before"],
                "error_patterns": ["dependency", "prerequisite"],
                "recommendations": [
                    "Make tests independent and idempotent",
                    "Avoid test interdependencies",
                    "Use explicit test ordering only when necessary",
                ],
            },
            FlakeRootCause.NETWORK_LATENCY: {
                "keywords": ["network", "http", "api", "request", "response"],
                "error_patterns": ["connection refused", "ECONNRESET", "socket hang up"],
                "recommendations": [
                    "Mock external API calls",
                    "Implement retry with exponential backoff",
                    "Use network-level timeouts",
                ],
            },
            FlakeRootCause.RESOURCE_EXHAUSTION: {
                "keywords": ["memory", "cpu", "resource", "heap", "gc"],
                "error_patterns": ["out of memory", "heap", "resource limit"],
                "recommendations": [
                    "Clean up resources after tests",
                    "Increase resource limits for CI",
                    "Profile memory usage during tests",
                ],
            },
            FlakeRootCause.UI_ANIMATION: {
                "keywords": ["animation", "transition", "click", "scroll"],
                "error_patterns": ["element not clickable", "intercept"],
                "recommendations": [
                    "Disable animations in test environment",
                    "Wait for animations to complete",
                    "Use force click options when needed",
                ],
            },
            FlakeRootCause.DATE_TIME: {
                "keywords": ["date", "time", "timestamp", "now", "today"],
                "error_patterns": ["date", "time", "expired"],
                "recommendations": [
                    "Mock date/time in tests",
                    "Use fixed timestamps for assertions",
                    "Avoid time-sensitive comparisons",
                ],
            },
        }

    def analyze(
        self,
        test_id: str,
        test_name: str,
        error_messages: List[str],
        test_code: Optional[str] = None,
        execution_history: Optional[List[Dict[str, Any]]] = None,
    ) -> FlakeAnalysis:
        """Analyze a flaky test for root causes."""
        self._analysis_counter += 1
        analysis_id = f"ANALYSIS-{self._analysis_counter:05d}"

        # Detect root causes
        root_causes = self._detect_root_causes(error_messages, test_code)

        # Assess impact
        impact = self._assess_impact(execution_history or [])

        # Generate recommendations
        recommendations = self._generate_recommendations(root_causes)

        # Calculate confidence
        confidence = self._calculate_confidence(root_causes, error_messages)

        analysis = FlakeAnalysis(
            analysis_id=analysis_id,
            test_id=test_id,
            test_name=test_name,
            root_causes=root_causes,
            impact_level=impact,
            affected_suites=[],
            correlations=[],
            recommendations=recommendations,
            confidence=round(confidence, 2),
            timestamp=datetime.now(),
        )

        self._analyses[test_id] = analysis
        return analysis

    def _detect_root_causes(
        self,
        error_messages: List[str],
        test_code: Optional[str],
    ) -> List[FlakeRootCause]:
        """Detect potential root causes from errors and code."""
        causes = []
        combined_text = " ".join(error_messages).lower()

        if test_code:
            combined_text += " " + test_code.lower()

        for cause, patterns in self._cause_patterns.items():
            # Check keywords
            keyword_match = any(
                kw in combined_text for kw in patterns["keywords"]
            )

            # Check error patterns
            error_match = any(
                ep in combined_text for ep in patterns["error_patterns"]
            )

            if keyword_match or error_match:
                causes.append(cause)

        if not causes:
            causes.append(FlakeRootCause.UNKNOWN)

        return causes

    def _assess_impact(
        self,
        execution_history: List[Dict[str, Any]],
    ) -> ImpactLevel:
        """Assess the impact level of flakiness."""
        if not execution_history:
            return ImpactLevel.MODERATE

        # Count recent failures
        recent = execution_history[-20:] if len(execution_history) > 20 else execution_history
        fail_count = sum(1 for e in recent if not e.get("passed", True))

        fail_rate = fail_count / len(recent) if recent else 0

        if fail_rate >= 0.5:
            return ImpactLevel.SEVERE
        elif fail_rate >= 0.3:
            return ImpactLevel.HIGH
        elif fail_rate >= 0.15:
            return ImpactLevel.MODERATE
        elif fail_rate >= 0.05:
            return ImpactLevel.LOW
        else:
            return ImpactLevel.NEGLIGIBLE

    def _generate_recommendations(
        self,
        root_causes: List[FlakeRootCause],
    ) -> List[str]:
        """Generate recommendations based on root causes."""
        recommendations = []

        for cause in root_causes:
            if cause in self._cause_patterns:
                recs = self._cause_patterns[cause]["recommendations"]
                recommendations.extend(recs)

        # Deduplicate
        return list(dict.fromkeys(recommendations))

    def _calculate_confidence(
        self,
        root_causes: List[FlakeRootCause],
        error_messages: List[str],
    ) -> float:
        """Calculate analysis confidence."""
        if FlakeRootCause.UNKNOWN in root_causes and len(root_causes) == 1:
            return 0.3

        # Higher confidence with more error messages
        message_factor = min(1.0, len(error_messages) / 5)

        # Higher confidence with identified causes
        cause_factor = min(1.0, len(root_causes) / 3)

        return 0.4 + (message_factor * 0.3) + (cause_factor * 0.3)

    def find_correlations(
        self,
        test_ids: List[str],
    ) -> List[FlakeCorrelation]:
        """Find correlations between flaky tests."""
        correlations = []

        analyses = [self._analyses.get(tid) for tid in test_ids if tid in self._analyses]

        for i, a1 in enumerate(analyses):
            for a2 in analyses[i + 1:]:
                if not a1 or not a2:
                    continue

                # Calculate shared root causes
                shared_causes = set(a1.root_causes) & set(a2.root_causes)

                if shared_causes:
                    # Score based on shared causes
                    score = len(shared_causes) / max(len(a1.root_causes), len(a2.root_causes))

                    correlation = FlakeCorrelation(
                        test_a_id=a1.test_id,
                        test_b_id=a2.test_id,
                        correlation_score=round(score, 2),
                        shared_factors=[c.value for c in shared_causes],
                    )
                    correlations.append(correlation)

        self._correlations.extend(correlations)
        return correlations

    def get_analysis(self, test_id: str) -> Optional[FlakeAnalysis]:
        """Get analysis for a specific test."""
        return self._analyses.get(test_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        cause_counts: Dict[str, int] = {}
        for analysis in self._analyses.values():
            for cause in analysis.root_causes:
                cause_counts[cause.value] = cause_counts.get(cause.value, 0) + 1

        impact_counts: Dict[str, int] = {}
        for analysis in self._analyses.values():
            impact_counts[analysis.impact_level.value] = impact_counts.get(analysis.impact_level.value, 0) + 1

        return {
            "total_analyses": len(self._analyses),
            "total_correlations": len(self._correlations),
            "root_causes_distribution": cause_counts,
            "impact_distribution": impact_counts,
        }

    def format_analysis(self, analysis: FlakeAnalysis) -> str:
        """Format analysis for display."""
        impact_icons = {
            ImpactLevel.NEGLIGIBLE: "⚪",
            ImpactLevel.LOW: "🟡",
            ImpactLevel.MODERATE: "🟠",
            ImpactLevel.HIGH: "🔴",
            ImpactLevel.SEVERE: "⛔",
        }

        icon = impact_icons.get(analysis.impact_level, "")

        lines = [
            "=" * 55,
            f"  FLAKINESS ANALYSIS: {icon} {analysis.impact_level.value.upper()}",
            "=" * 55,
            "",
            f"  Test: {analysis.test_name}",
            f"  Confidence: {analysis.confidence:.0%}",
            "",
            "-" * 55,
            "  ROOT CAUSES",
            "-" * 55,
            "",
        ]

        for cause in analysis.root_causes:
            lines.append(f"  • {cause.value}")

        if analysis.recommendations:
            lines.extend([
                "",
                "-" * 55,
                "  RECOMMENDATIONS",
                "-" * 55,
                "",
            ])

            for i, rec in enumerate(analysis.recommendations[:5], 1):
                lines.append(f"  {i}. {rec}")

        lines.extend(["", "=" * 55])
        return "\n".join(lines)


def create_flakiness_analyzer() -> FlakinessAnalyzer:
    """Create a flakiness analyzer instance."""
    return FlakinessAnalyzer()
