"""
TestAI Agent - Test Optimizer

AI-powered test case optimization with redundancy detection,
assertion improvement, and step consolidation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re
from collections import defaultdict


class SuggestionType(Enum):
    """Types of optimization suggestions."""
    MERGE = "merge"  # Merge redundant tests
    SPLIT = "split"  # Split large test into smaller
    REMOVE = "remove"  # Remove unnecessary test
    IMPROVE_ASSERTION = "improve_assertion"  # Better assertions
    ADD_STEP = "add_step"  # Add missing step
    REMOVE_STEP = "remove_step"  # Remove redundant step
    REORDER = "reorder"  # Reorder steps
    PARAMETERIZE = "parameterize"  # Convert to parameterized test
    IMPROVE_DATA = "improve_data"  # Better test data


@dataclass
class OptimizationSuggestion:
    """A single optimization suggestion."""
    suggestion_id: str
    suggestion_type: SuggestionType
    description: str
    affected_tests: List[str]
    impact: str  # Description of expected impact
    priority: int  # 1 = highest
    confidence: float  # 0-1
    before_example: Optional[str] = None
    after_example: Optional[str] = None
    auto_applicable: bool = False


@dataclass
class OptimizationResult:
    """Result of test optimization analysis."""
    analyzed_at: datetime
    total_tests: int
    suggestions: List[OptimizationSuggestion]
    potential_reduction: int  # Tests that could be removed
    redundancy_rate: float  # Percentage of redundant content
    coverage_improvement: float  # Estimated improvement
    estimated_time_savings_pct: float


class TestOptimizer:
    """
    Optimizes test suites using AI-powered analysis.

    Analyzes:
    - Test redundancy and overlap
    - Assertion quality
    - Step efficiency
    - Data coverage
    - Execution order
    """

    # Common step patterns for normalization
    STEP_PATTERNS = {
        "navigate": r"(navigate|go|open|visit|load)\s+(to\s+)?",
        "click": r"(click|tap|press)\s+(on\s+)?",
        "input": r"(enter|type|input|fill)\s+(in\s+)?",
        "verify": r"(verify|check|assert|ensure|confirm|validate|expect)\s+",
        "wait": r"(wait|pause|sleep)\s+(for\s+)?",
        "select": r"(select|choose|pick)\s+",
        "scroll": r"(scroll)\s+(to\s+)?",
    }

    # Weak assertion patterns
    WEAK_ASSERTIONS = [
        r"should\s+be\s+visible",
        r"should\s+exist",
        r"should\s+not\s+be\s+empty",
        r"should\s+load",
    ]

    # Strong assertion patterns
    STRONG_ASSERTIONS = [
        r"should\s+equal",
        r"should\s+contain\s+text",
        r"should\s+have\s+(class|attribute)",
        r"should\s+match",
        r"should\s+be\s+(enabled|disabled)",
    ]

    def __init__(
        self,
        similarity_threshold: float = 0.7,
        min_steps_for_split: int = 10,
    ):
        """Initialize the optimizer."""
        self.similarity_threshold = similarity_threshold
        self.min_steps_for_split = min_steps_for_split
        self._suggestion_counter = 0

    def optimize(
        self,
        tests: List[Dict[str, Any]],
    ) -> OptimizationResult:
        """Analyze and suggest optimizations for a test suite."""
        suggestions = []

        # Find redundant tests
        redundant = self._find_redundant_tests(tests)
        suggestions.extend(redundant)

        # Find split candidates
        split_candidates = self._find_split_candidates(tests)
        suggestions.extend(split_candidates)

        # Find assertion improvements
        assertion_improvements = self._find_assertion_improvements(tests)
        suggestions.extend(assertion_improvements)

        # Find parameterization opportunities
        param_opportunities = self._find_parameterization_opportunities(tests)
        suggestions.extend(param_opportunities)

        # Find step optimizations
        step_optimizations = self._find_step_optimizations(tests)
        suggestions.extend(step_optimizations)

        # Sort by priority
        suggestions.sort(key=lambda s: s.priority)

        # Calculate metrics
        potential_reduction = sum(
            len(s.affected_tests) - 1 for s in suggestions
            if s.suggestion_type == SuggestionType.MERGE
        )

        redundancy_rate = self._calculate_redundancy_rate(tests)

        return OptimizationResult(
            analyzed_at=datetime.now(),
            total_tests=len(tests),
            suggestions=suggestions,
            potential_reduction=potential_reduction,
            redundancy_rate=redundancy_rate,
            coverage_improvement=len([s for s in suggestions if s.suggestion_type == SuggestionType.ADD_STEP]) * 0.05,
            estimated_time_savings_pct=potential_reduction / len(tests) * 100 if tests else 0,
        )

    def _find_redundant_tests(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[OptimizationSuggestion]:
        """Find tests that overlap significantly."""
        suggestions = []
        n = len(tests)

        # Compare all pairs
        for i in range(n):
            for j in range(i + 1, n):
                similarity = self._calculate_test_similarity(tests[i], tests[j])

                if similarity >= self.similarity_threshold:
                    self._suggestion_counter += 1
                    suggestions.append(OptimizationSuggestion(
                        suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                        suggestion_type=SuggestionType.MERGE,
                        description=f"Tests '{tests[i].get('title', tests[i].get('id', 'unknown'))}' "
                                    f"and '{tests[j].get('title', tests[j].get('id', 'unknown'))}' "
                                    f"are {similarity:.0%} similar",
                        affected_tests=[
                            tests[i].get("id", "unknown"),
                            tests[j].get("id", "unknown"),
                        ],
                        impact="Reduce maintenance overhead by consolidating similar tests",
                        priority=2 if similarity > 0.9 else 3,
                        confidence=similarity,
                        auto_applicable=similarity > 0.95,
                    ))

        return suggestions

    def _find_split_candidates(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[OptimizationSuggestion]:
        """Find tests that should be split."""
        suggestions = []

        for test in tests:
            steps = test.get("steps", [])

            if len(steps) >= self.min_steps_for_split:
                self._suggestion_counter += 1
                suggestions.append(OptimizationSuggestion(
                    suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                    suggestion_type=SuggestionType.SPLIT,
                    description=f"Test '{test.get('title', test.get('id', 'unknown'))}' "
                                f"has {len(steps)} steps - consider splitting",
                    affected_tests=[test.get("id", "unknown")],
                    impact="Improved test isolation and easier debugging",
                    priority=3,
                    confidence=0.7,
                ))

        return suggestions

    def _find_assertion_improvements(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[OptimizationSuggestion]:
        """Find weak assertions that could be improved."""
        suggestions = []

        for test in tests:
            expected = test.get("expected_result", "")
            steps = test.get("steps", [])

            # Check expected result
            weak_count = 0
            for pattern in self.WEAK_ASSERTIONS:
                if re.search(pattern, expected, re.IGNORECASE):
                    weak_count += 1

            # Check steps for assertions
            for step in steps:
                for pattern in self.WEAK_ASSERTIONS:
                    if re.search(pattern, step, re.IGNORECASE):
                        weak_count += 1

            if weak_count > 0:
                self._suggestion_counter += 1
                suggestions.append(OptimizationSuggestion(
                    suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                    suggestion_type=SuggestionType.IMPROVE_ASSERTION,
                    description=f"Test '{test.get('title', test.get('id', 'unknown'))}' "
                                f"has {weak_count} weak assertions",
                    affected_tests=[test.get("id", "unknown")],
                    impact="More precise failure detection",
                    priority=4,
                    confidence=0.8,
                    before_example="should be visible",
                    after_example="should contain text 'Success'",
                ))

        return suggestions

    def _find_parameterization_opportunities(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[OptimizationSuggestion]:
        """Find tests that could be parameterized."""
        suggestions = []

        # Group tests by normalized title
        title_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for test in tests:
            title = test.get("title", "")
            normalized = self._normalize_title(title)
            title_groups[normalized].append(test)

        for normalized, group in title_groups.items():
            if len(group) >= 3:
                self._suggestion_counter += 1
                suggestions.append(OptimizationSuggestion(
                    suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                    suggestion_type=SuggestionType.PARAMETERIZE,
                    description=f"{len(group)} tests with similar structure could be parameterized",
                    affected_tests=[t.get("id", "unknown") for t in group],
                    impact="Reduce code duplication, easier maintenance",
                    priority=2,
                    confidence=0.75,
                ))

        return suggestions

    def _find_step_optimizations(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[OptimizationSuggestion]:
        """Find step-level optimizations."""
        suggestions = []

        for test in tests:
            steps = test.get("steps", [])

            # Check for duplicate steps
            seen_steps = set()
            duplicates = []
            for i, step in enumerate(steps):
                normalized = self._normalize_step(step)
                if normalized in seen_steps:
                    duplicates.append(i)
                seen_steps.add(normalized)

            if duplicates:
                self._suggestion_counter += 1
                suggestions.append(OptimizationSuggestion(
                    suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                    suggestion_type=SuggestionType.REMOVE_STEP,
                    description=f"Test '{test.get('title', test.get('id', 'unknown'))}' "
                                f"has {len(duplicates)} duplicate steps",
                    affected_tests=[test.get("id", "unknown")],
                    impact="Faster execution, cleaner test logic",
                    priority=4,
                    confidence=0.9,
                    auto_applicable=True,
                ))

            # Check for missing wait steps before interactions
            for i, step in enumerate(steps[:-1]):
                current_action = self._get_step_action(step)
                next_action = self._get_step_action(steps[i + 1])

                if (current_action == "navigate" and next_action in {"click", "input"}):
                    # Missing wait after navigation
                    has_wait = any(
                        self._get_step_action(s) == "wait"
                        for s in steps[i:i + 2]
                    )
                    if not has_wait:
                        self._suggestion_counter += 1
                        suggestions.append(OptimizationSuggestion(
                            suggestion_id=f"OPT-{self._suggestion_counter:04d}",
                            suggestion_type=SuggestionType.ADD_STEP,
                            description=f"Consider adding wait after navigation in step {i + 1}",
                            affected_tests=[test.get("id", "unknown")],
                            impact="Reduced flakiness from timing issues",
                            priority=3,
                            confidence=0.7,
                        ))
                        break  # One suggestion per test

        return suggestions

    def _calculate_test_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate similarity between two tests."""
        # Compare steps
        steps1 = [self._normalize_step(s) for s in test1.get("steps", [])]
        steps2 = [self._normalize_step(s) for s in test2.get("steps", [])]

        if not steps1 or not steps2:
            return 0.0

        # Jaccard similarity on steps
        set1 = set(steps1)
        set2 = set(steps2)

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        step_similarity = intersection / union if union > 0 else 0

        # Compare titles
        title1 = self._normalize_title(test1.get("title", ""))
        title2 = self._normalize_title(test2.get("title", ""))

        title_words1 = set(title1.split())
        title_words2 = set(title2.split())

        title_intersection = len(title_words1 & title_words2)
        title_union = len(title_words1 | title_words2)

        title_similarity = title_intersection / title_union if title_union > 0 else 0

        # Weighted average
        return 0.7 * step_similarity + 0.3 * title_similarity

    def _calculate_redundancy_rate(
        self,
        tests: List[Dict[str, Any]],
    ) -> float:
        """Calculate overall redundancy rate."""
        if not tests:
            return 0.0

        all_steps = []
        for test in tests:
            all_steps.extend(self._normalize_step(s) for s in test.get("steps", []))

        if not all_steps:
            return 0.0

        unique_steps = set(all_steps)
        return 1 - (len(unique_steps) / len(all_steps))

    def _normalize_step(self, step: str) -> str:
        """Normalize a step for comparison."""
        step = step.lower()

        for action, pattern in self.STEP_PATTERNS.items():
            step = re.sub(pattern, f"{action} ", step)

        # Remove extra whitespace
        step = re.sub(r"\s+", " ", step).strip()

        return step

    def _normalize_title(self, title: str) -> str:
        """Normalize a title for grouping."""
        title = title.lower()

        # Remove common prefixes
        title = re.sub(r"^(test|verify|check|ensure)\s+", "", title)

        # Remove numbers and special chars
        title = re.sub(r"[0-9_\-]", " ", title)

        # Remove extra whitespace
        title = re.sub(r"\s+", " ", title).strip()

        return title

    def _get_step_action(self, step: str) -> str:
        """Extract action type from a step."""
        step_lower = step.lower()

        for action, pattern in self.STEP_PATTERNS.items():
            if re.search(pattern, step_lower):
                return action

        return "other"

    def format_result(self, result: OptimizationResult) -> str:
        """Format optimization result as readable text."""
        lines = [
            "=" * 60,
            "  TEST OPTIMIZATION ANALYSIS",
            "=" * 60,
            "",
            f"  Analyzed At: {result.analyzed_at.strftime('%Y-%m-%d %H:%M')}",
            f"  Total Tests: {result.total_tests}",
            "",
            f"  Redundancy Rate: {result.redundancy_rate:.1%}",
            f"  Potential Reduction: {result.potential_reduction} tests",
            f"  Est. Time Savings: {result.estimated_time_savings_pct:.1f}%",
            "",
        ]

        if result.suggestions:
            lines.extend([
                "-" * 60,
                "  OPTIMIZATION SUGGESTIONS",
                "-" * 60,
            ])

            type_icons = {
                SuggestionType.MERGE: "🔗",
                SuggestionType.SPLIT: "✂️",
                SuggestionType.IMPROVE_ASSERTION: "✓",
                SuggestionType.PARAMETERIZE: "📋",
                SuggestionType.ADD_STEP: "➕",
                SuggestionType.REMOVE_STEP: "➖",
            }

            for suggestion in result.suggestions[:10]:
                icon = type_icons.get(suggestion.suggestion_type, "•")
                lines.append(f"\n  {icon} [{suggestion.suggestion_id}] {suggestion.suggestion_type.value}")
                lines.append(f"     {suggestion.description}")
                lines.append(f"     Impact: {suggestion.impact}")
                lines.append(f"     Priority: {suggestion.priority} | Confidence: {suggestion.confidence:.0%}")

                if suggestion.before_example and suggestion.after_example:
                    lines.append(f"     Before: {suggestion.before_example}")
                    lines.append(f"     After: {suggestion.after_example}")

            if len(result.suggestions) > 10:
                lines.append(f"\n  ... and {len(result.suggestions) - 10} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_optimizer(
    similarity_threshold: float = 0.7,
    min_steps_for_split: int = 10,
) -> TestOptimizer:
    """Create a test optimizer instance."""
    return TestOptimizer(similarity_threshold, min_steps_for_split)
