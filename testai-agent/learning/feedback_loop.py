"""
TestAI Agent - Feedback Loop

Collects and processes feedback from test executions to enable learning.
This creates a continuous improvement cycle that makes the agent smarter over time.

The feedback loop:
1. Collects test execution results
2. Identifies patterns in failures and successes
3. Generates learning insights
4. Updates the knowledge base with new rules

Unlike traditional testing tools, this agent REMEMBERS and IMPROVES.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import json


class FeedbackType(Enum):
    """Types of feedback the system can receive."""
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    TEST_FLAKY = "test_flaky"
    FALSE_POSITIVE = "false_positive"  # Test passed but shouldn't have
    FALSE_NEGATIVE = "false_negative"  # Test failed but shouldn't have
    USER_CORRECTION = "user_correction"
    RULE_HELPFUL = "rule_helpful"
    RULE_UNHELPFUL = "rule_unhelpful"
    MISSING_TEST = "missing_test"  # User identified a test we should have generated
    UNNECESSARY_TEST = "unnecessary_test"  # Test was not needed


@dataclass
class TestFeedback:
    """Feedback for a single test execution."""
    test_id: str
    feedback_type: FeedbackType
    timestamp: datetime = field(default_factory=datetime.now)

    # Test details
    test_title: str = ""
    test_category: str = ""
    page_type: str = ""

    # Execution details
    execution_time_ms: float = 0
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None

    # Context
    url: Optional[str] = None
    browser: Optional[str] = None
    viewport: Optional[str] = None

    # User feedback
    user_comment: Optional[str] = None
    suggested_fix: Optional[str] = None

    # Citations
    source_citations: List[str] = field(default_factory=list)

    # Tags for pattern detection
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "test_id": self.test_id,
            "feedback_type": self.feedback_type.value,
            "timestamp": self.timestamp.isoformat(),
            "test_title": self.test_title,
            "test_category": self.test_category,
            "page_type": self.page_type,
            "execution_time_ms": self.execution_time_ms,
            "error_message": self.error_message,
            "stack_trace": self.stack_trace,
            "url": self.url,
            "browser": self.browser,
            "viewport": self.viewport,
            "user_comment": self.user_comment,
            "suggested_fix": self.suggested_fix,
            "source_citations": self.source_citations,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TestFeedback":
        """Create from dictionary."""
        return cls(
            test_id=data["test_id"],
            feedback_type=FeedbackType(data["feedback_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            test_title=data.get("test_title", ""),
            test_category=data.get("test_category", ""),
            page_type=data.get("page_type", ""),
            execution_time_ms=data.get("execution_time_ms", 0),
            error_message=data.get("error_message"),
            stack_trace=data.get("stack_trace"),
            url=data.get("url"),
            browser=data.get("browser"),
            viewport=data.get("viewport"),
            user_comment=data.get("user_comment"),
            suggested_fix=data.get("suggested_fix"),
            source_citations=data.get("source_citations", []),
            tags=set(data.get("tags", [])),
        )


@dataclass
class LearningInsight:
    """An insight derived from analyzing feedback."""
    insight_id: str
    insight_type: str  # pattern, correlation, gap, improvement
    confidence: float  # 0-1

    # What we learned
    description: str
    evidence: List[str]  # Test IDs that support this insight

    # Actionable recommendations
    recommendations: List[str]

    # Impact assessment
    affected_categories: List[str]
    affected_page_types: List[str]

    # Status
    applied: bool = False
    applied_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "insight_id": self.insight_id,
            "insight_type": self.insight_type,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "affected_categories": self.affected_categories,
            "affected_page_types": self.affected_page_types,
            "applied": self.applied,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
        }


class FeedbackLoop:
    """
    The core learning engine that processes feedback and generates insights.

    This is what makes the agent truly intelligent - it doesn't just run tests,
    it LEARNS from every execution and gets better over time.
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        min_samples_for_insight: int = 3,
    ):
        """
        Initialize the feedback loop.

        Args:
            storage_dir: Directory to store feedback data
            min_samples_for_insight: Minimum feedback samples before generating insights
        """
        self.storage_dir = Path(storage_dir) if storage_dir else Path.home() / ".testai_learning"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.min_samples = min_samples_for_insight

        # In-memory feedback storage
        self._feedback: List[TestFeedback] = []
        self._insights: List[LearningInsight] = []

        # Statistics
        self._stats = {
            "total_feedback": 0,
            "passes": 0,
            "failures": 0,
            "flaky": 0,
            "user_corrections": 0,
            "insights_generated": 0,
            "insights_applied": 0,
        }

        # Load existing data
        self._load_feedback()

    def add_feedback(self, feedback: TestFeedback) -> None:
        """
        Add feedback from a test execution.

        This is the primary input to the learning system. Every test result
        should be fed back here for continuous improvement.
        """
        self._feedback.append(feedback)
        self._stats["total_feedback"] += 1

        # Update type-specific stats
        if feedback.feedback_type == FeedbackType.TEST_PASSED:
            self._stats["passes"] += 1
        elif feedback.feedback_type == FeedbackType.TEST_FAILED:
            self._stats["failures"] += 1
        elif feedback.feedback_type == FeedbackType.TEST_FLAKY:
            self._stats["flaky"] += 1
        elif feedback.feedback_type == FeedbackType.USER_CORRECTION:
            self._stats["user_corrections"] += 1

        # Auto-tag based on content
        self._auto_tag(feedback)

        # Persist
        self._save_feedback()

        # Check if we can generate new insights
        if len(self._feedback) >= self.min_samples:
            self._check_for_insights()

    def _auto_tag(self, feedback: TestFeedback) -> None:
        """Automatically tag feedback based on content analysis."""
        # Tag based on error messages
        if feedback.error_message:
            error_lower = feedback.error_message.lower()

            if "timeout" in error_lower:
                feedback.tags.add("timeout")
            if "not found" in error_lower or "no such element" in error_lower:
                feedback.tags.add("element_not_found")
            if "network" in error_lower or "connection" in error_lower:
                feedback.tags.add("network_error")
            if "assertion" in error_lower:
                feedback.tags.add("assertion_failure")
            if "permission" in error_lower or "denied" in error_lower:
                feedback.tags.add("permission_error")
            if "authentication" in error_lower or "login" in error_lower:
                feedback.tags.add("auth_related")

        # Tag based on category
        if feedback.test_category:
            feedback.tags.add(f"category:{feedback.test_category}")

        # Tag based on page type
        if feedback.page_type:
            feedback.tags.add(f"page:{feedback.page_type}")

        # Tag based on execution time
        if feedback.execution_time_ms > 10000:
            feedback.tags.add("slow_test")
        elif feedback.execution_time_ms < 100:
            feedback.tags.add("fast_test")

    def _check_for_insights(self) -> None:
        """Analyze feedback to generate new insights."""
        insights = []

        # Pattern 1: High failure rate in specific category
        insights.extend(self._detect_category_patterns())

        # Pattern 2: Flaky tests
        insights.extend(self._detect_flaky_patterns())

        # Pattern 3: Slow test clusters
        insights.extend(self._detect_performance_patterns())

        # Pattern 4: Common error patterns
        insights.extend(self._detect_error_patterns())

        # Add new insights
        for insight in insights:
            if not self._insight_exists(insight):
                self._insights.append(insight)
                self._stats["insights_generated"] += 1

        self._save_insights()

    def _detect_category_patterns(self) -> List[LearningInsight]:
        """Detect patterns in test failures by category."""
        insights = []

        # Group by category
        category_results: Dict[str, Dict[str, int]] = {}
        for fb in self._feedback:
            cat = fb.test_category or "unknown"
            if cat not in category_results:
                category_results[cat] = {"passed": 0, "failed": 0}

            if fb.feedback_type == FeedbackType.TEST_PASSED:
                category_results[cat]["passed"] += 1
            elif fb.feedback_type == FeedbackType.TEST_FAILED:
                category_results[cat]["failed"] += 1

        # Check for high failure rates
        for category, results in category_results.items():
            total = results["passed"] + results["failed"]
            if total >= self.min_samples:
                failure_rate = results["failed"] / total

                if failure_rate > 0.5:  # More than 50% failure
                    # Get evidence
                    evidence = [
                        fb.test_id for fb in self._feedback
                        if fb.test_category == category
                        and fb.feedback_type == FeedbackType.TEST_FAILED
                    ][:5]

                    insight = LearningInsight(
                        insight_id=f"high_failure_{category}_{datetime.now().strftime('%Y%m%d')}",
                        insight_type="pattern",
                        confidence=min(0.9, 0.5 + (total / 20) * 0.4),
                        description=f"High failure rate ({failure_rate:.0%}) in '{category}' category tests",
                        evidence=evidence,
                        recommendations=[
                            f"Review test design for {category} tests",
                            f"Check if application under test has issues in {category} area",
                            "Consider adding retry logic for potentially flaky tests",
                        ],
                        affected_categories=[category],
                        affected_page_types=[],
                    )
                    insights.append(insight)

        return insights

    def _detect_flaky_patterns(self) -> List[LearningInsight]:
        """Detect flaky test patterns."""
        insights = []

        # Find tests that have both passed and failed
        test_results: Dict[str, Dict[str, int]] = {}
        for fb in self._feedback:
            if fb.test_id not in test_results:
                test_results[fb.test_id] = {"passed": 0, "failed": 0}

            if fb.feedback_type == FeedbackType.TEST_PASSED:
                test_results[fb.test_id]["passed"] += 1
            elif fb.feedback_type == FeedbackType.TEST_FAILED:
                test_results[fb.test_id]["failed"] += 1

        # Find flaky tests (both passed and failed)
        flaky_tests = [
            test_id for test_id, results in test_results.items()
            if results["passed"] > 0 and results["failed"] > 0
        ]

        if len(flaky_tests) >= 2:
            insight = LearningInsight(
                insight_id=f"flaky_tests_{datetime.now().strftime('%Y%m%d')}",
                insight_type="pattern",
                confidence=0.85,
                description=f"Detected {len(flaky_tests)} potentially flaky tests",
                evidence=flaky_tests[:5],
                recommendations=[
                    "Add explicit waits for dynamic content",
                    "Use more specific selectors",
                    "Consider test isolation improvements",
                    "Review asynchronous operation handling",
                ],
                affected_categories=list(set(
                    fb.test_category for fb in self._feedback
                    if fb.test_id in flaky_tests and fb.test_category
                )),
                affected_page_types=list(set(
                    fb.page_type for fb in self._feedback
                    if fb.test_id in flaky_tests and fb.page_type
                )),
            )
            insights.append(insight)

        return insights

    def _detect_performance_patterns(self) -> List[LearningInsight]:
        """Detect performance-related patterns."""
        insights = []

        # Find slow tests
        slow_tests = [
            fb for fb in self._feedback
            if fb.execution_time_ms > 10000  # More than 10 seconds
        ]

        if len(slow_tests) >= self.min_samples:
            # Group by page type
            slow_by_page: Dict[str, List[TestFeedback]] = {}
            for fb in slow_tests:
                page = fb.page_type or "unknown"
                if page not in slow_by_page:
                    slow_by_page[page] = []
                slow_by_page[page].append(fb)

            # Check for concentration
            for page_type, tests in slow_by_page.items():
                if len(tests) >= 2:
                    avg_time = sum(t.execution_time_ms for t in tests) / len(tests)

                    insight = LearningInsight(
                        insight_id=f"slow_tests_{page_type}_{datetime.now().strftime('%Y%m%d')}",
                        insight_type="performance",
                        confidence=0.8,
                        description=f"Slow test cluster on '{page_type}' page (avg {avg_time/1000:.1f}s)",
                        evidence=[t.test_id for t in tests[:5]],
                        recommendations=[
                            f"Optimize page load for {page_type}",
                            "Consider parallel test execution",
                            "Review selector efficiency",
                            "Check for unnecessary waits",
                        ],
                        affected_categories=[],
                        affected_page_types=[page_type],
                    )
                    insights.append(insight)

        return insights

    def _detect_error_patterns(self) -> List[LearningInsight]:
        """Detect common error patterns across failures."""
        insights = []

        # Group by error tags
        tag_counts: Dict[str, List[str]] = {}
        for fb in self._feedback:
            if fb.feedback_type == FeedbackType.TEST_FAILED:
                for tag in fb.tags:
                    if tag not in tag_counts:
                        tag_counts[tag] = []
                    tag_counts[tag].append(fb.test_id)

        # Generate insights for common error types
        error_tags = ["timeout", "element_not_found", "network_error", "assertion_failure"]

        for tag in error_tags:
            if tag in tag_counts and len(tag_counts[tag]) >= self.min_samples:
                recommendations = {
                    "timeout": [
                        "Increase timeout values for affected tests",
                        "Optimize page performance",
                        "Add loading state checks",
                    ],
                    "element_not_found": [
                        "Update selectors to be more robust",
                        "Add explicit waits for element visibility",
                        "Check for dynamic content rendering",
                    ],
                    "network_error": [
                        "Implement retry logic for network requests",
                        "Check API endpoint stability",
                        "Add network failure handling in tests",
                    ],
                    "assertion_failure": [
                        "Review expected values in assertions",
                        "Check for data-dependent test failures",
                        "Consider using fuzzy matching where appropriate",
                    ],
                }

                insight = LearningInsight(
                    insight_id=f"error_pattern_{tag}_{datetime.now().strftime('%Y%m%d')}",
                    insight_type="error_pattern",
                    confidence=0.75,
                    description=f"Common '{tag.replace('_', ' ')}' errors across {len(tag_counts[tag])} tests",
                    evidence=tag_counts[tag][:5],
                    recommendations=recommendations.get(tag, ["Review test implementation"]),
                    affected_categories=[],
                    affected_page_types=[],
                )
                insights.append(insight)

        return insights

    def _insight_exists(self, new_insight: LearningInsight) -> bool:
        """Check if a similar insight already exists."""
        for existing in self._insights:
            if (existing.insight_type == new_insight.insight_type and
                existing.description == new_insight.description):
                return True
        return False

    def get_insights(
        self,
        insight_type: Optional[str] = None,
        min_confidence: float = 0.0,
        applied_only: bool = False,
    ) -> List[LearningInsight]:
        """Get learning insights with optional filtering."""
        results = self._insights

        if insight_type:
            results = [i for i in results if i.insight_type == insight_type]

        if min_confidence > 0:
            results = [i for i in results if i.confidence >= min_confidence]

        if applied_only:
            results = [i for i in results if i.applied]

        return sorted(results, key=lambda x: x.confidence, reverse=True)

    def get_recommendations_for_page(self, page_type: str) -> List[str]:
        """Get recommendations specific to a page type based on learning."""
        recommendations = []

        for insight in self._insights:
            if page_type in insight.affected_page_types:
                recommendations.extend(insight.recommendations)

        return list(set(recommendations))  # Deduplicate

    def get_recommendations_for_category(self, category: str) -> List[str]:
        """Get recommendations specific to a test category based on learning."""
        recommendations = []

        for insight in self._insights:
            if category in insight.affected_categories:
                recommendations.extend(insight.recommendations)

        return list(set(recommendations))

    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        return {
            **self._stats,
            "total_insights": len(self._insights),
            "unapplied_insights": len([i for i in self._insights if not i.applied]),
            "feedback_by_type": self._count_feedback_by_type(),
        }

    def _count_feedback_by_type(self) -> Dict[str, int]:
        """Count feedback by type."""
        counts: Dict[str, int] = {}
        for fb in self._feedback:
            type_name = fb.feedback_type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts

    def mark_insight_applied(self, insight_id: str) -> bool:
        """Mark an insight as applied to the knowledge base."""
        for insight in self._insights:
            if insight.insight_id == insight_id:
                insight.applied = True
                insight.applied_at = datetime.now()
                self._stats["insights_applied"] += 1
                self._save_insights()
                return True
        return False

    def generate_learning_report(self) -> str:
        """Generate a human-readable learning report."""
        lines = [
            "# TestAI Learning Report",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Statistics",
            "",
            f"- Total feedback collected: {self._stats['total_feedback']}",
            f"- Tests passed: {self._stats['passes']}",
            f"- Tests failed: {self._stats['failures']}",
            f"- Flaky tests detected: {self._stats['flaky']}",
            f"- User corrections: {self._stats['user_corrections']}",
            f"- Insights generated: {self._stats['insights_generated']}",
            f"- Insights applied: {self._stats['insights_applied']}",
            "",
        ]

        # Add insights
        if self._insights:
            lines.extend([
                "## Learning Insights",
                "",
            ])

            for insight in sorted(self._insights, key=lambda x: x.confidence, reverse=True):
                status = "✅ Applied" if insight.applied else "⏳ Pending"
                lines.extend([
                    f"### {insight.description}",
                    "",
                    f"- **Type**: {insight.insight_type}",
                    f"- **Confidence**: {insight.confidence:.0%}",
                    f"- **Status**: {status}",
                    "",
                    "**Recommendations:**",
                    "",
                ])
                for rec in insight.recommendations:
                    lines.append(f"- {rec}")
                lines.append("")

        return "\n".join(lines)

    def _save_feedback(self) -> None:
        """Save feedback to disk."""
        feedback_file = self.storage_dir / "feedback.json"
        data = [fb.to_dict() for fb in self._feedback]
        with open(feedback_file, "w") as f:
            json.dump(data, f, indent=2)

    def _load_feedback(self) -> None:
        """Load feedback from disk."""
        feedback_file = self.storage_dir / "feedback.json"
        if feedback_file.exists():
            with open(feedback_file, "r") as f:
                data = json.load(f)
            self._feedback = [TestFeedback.from_dict(d) for d in data]

            # Rebuild stats
            for fb in self._feedback:
                self._stats["total_feedback"] += 1
                if fb.feedback_type == FeedbackType.TEST_PASSED:
                    self._stats["passes"] += 1
                elif fb.feedback_type == FeedbackType.TEST_FAILED:
                    self._stats["failures"] += 1

    def _save_insights(self) -> None:
        """Save insights to disk."""
        insights_file = self.storage_dir / "insights.json"
        data = [i.to_dict() for i in self._insights]
        with open(insights_file, "w") as f:
            json.dump(data, f, indent=2)


def create_feedback_loop(
    storage_dir: Optional[str] = None,
    min_samples: int = 3,
) -> FeedbackLoop:
    """Create a feedback loop instance."""
    return FeedbackLoop(
        storage_dir=storage_dir,
        min_samples_for_insight=min_samples,
    )
