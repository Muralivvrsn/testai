"""
TestAI Agent - Test Merger

Merges duplicate or similar test cases into comprehensive
unified test cases, preserving the best of each.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class MergeStrategy(Enum):
    """Strategies for merging tests."""
    KEEP_FIRST = "keep_first"  # Keep the first test, discard others
    KEEP_HIGHEST_PRIORITY = "keep_highest_priority"  # Keep highest priority
    MERGE_ALL = "merge_all"  # Merge all content
    UNION_STEPS = "union_steps"  # Union of all steps
    INTERSECTION_STEPS = "intersection_steps"  # Common steps only


@dataclass
class MergeResult:
    """Result of a merge operation."""
    success: bool
    merged_test: Optional[Dict[str, Any]]
    source_test_ids: List[str]
    strategy_used: MergeStrategy
    steps_merged: int
    message: str


class TestMerger:
    """
    Merges duplicate or similar tests into unified test cases.

    Supports multiple merge strategies to preserve the most
    valuable aspects of each test.
    """

    # Priority order for resolving conflicts
    PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def __init__(self, default_strategy: MergeStrategy = MergeStrategy.MERGE_ALL):
        """Initialize the merger."""
        self.default_strategy = default_strategy

    def merge(
        self,
        tests: List[Dict[str, Any]],
        strategy: Optional[MergeStrategy] = None,
    ) -> MergeResult:
        """Merge multiple tests into one."""
        if not tests:
            return MergeResult(
                success=False,
                merged_test=None,
                source_test_ids=[],
                strategy_used=strategy or self.default_strategy,
                steps_merged=0,
                message="No tests to merge",
            )

        if len(tests) == 1:
            return MergeResult(
                success=True,
                merged_test=tests[0].copy(),
                source_test_ids=[tests[0].get("id", "unknown")],
                strategy_used=strategy or self.default_strategy,
                steps_merged=len(tests[0].get("steps", [])),
                message="Single test, no merge needed",
            )

        strategy = strategy or self.default_strategy

        if strategy == MergeStrategy.KEEP_FIRST:
            merged = self._keep_first(tests)
        elif strategy == MergeStrategy.KEEP_HIGHEST_PRIORITY:
            merged = self._keep_highest_priority(tests)
        elif strategy == MergeStrategy.MERGE_ALL:
            merged = self._merge_all(tests)
        elif strategy == MergeStrategy.UNION_STEPS:
            merged = self._union_steps(tests)
        elif strategy == MergeStrategy.INTERSECTION_STEPS:
            merged = self._intersection_steps(tests)
        else:
            merged = self._merge_all(tests)

        return MergeResult(
            success=True,
            merged_test=merged,
            source_test_ids=[t.get("id", "unknown") for t in tests],
            strategy_used=strategy,
            steps_merged=len(merged.get("steps", [])),
            message=f"Merged {len(tests)} tests into one",
        )

    def _keep_first(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Keep the first test, add metadata about merged tests."""
        merged = tests[0].copy()
        merged["merged_from"] = [t.get("id", "unknown") for t in tests[1:]]
        return merged

    def _keep_highest_priority(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Keep the test with highest priority."""
        sorted_tests = sorted(
            tests,
            key=lambda t: self.PRIORITY_ORDER.get(t.get("priority", "medium"), 2)
        )
        merged = sorted_tests[0].copy()
        merged["merged_from"] = [t.get("id", "unknown") for t in tests if t != sorted_tests[0]]
        return merged

    def _merge_all(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge all content from all tests."""
        # Start with highest priority test
        sorted_tests = sorted(
            tests,
            key=lambda t: self.PRIORITY_ORDER.get(t.get("priority", "medium"), 2)
        )
        base = sorted_tests[0]

        merged = {
            "id": f"MERGED-{base.get('id', 'unknown')}",
            "title": self._merge_titles(tests),
            "description": self._merge_descriptions(tests),
            "category": self._merge_category(tests),
            "priority": self._merge_priority(tests),
            "steps": self._merge_steps_union(tests),
            "expected_result": self._merge_expected_results(tests),
            "merged_from": [t.get("id", "unknown") for t in tests],
            "merged_at": datetime.now().isoformat(),
        }

        # Preserve additional fields from base
        for key in base:
            if key not in merged:
                merged[key] = base[key]

        return merged

    def _union_steps(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Union all steps, removing duplicates."""
        merged = self._merge_all(tests)
        merged["steps"] = self._merge_steps_union(tests)
        return merged

    def _intersection_steps(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Keep only common steps."""
        merged = self._merge_all(tests)
        merged["steps"] = self._merge_steps_intersection(tests)
        return merged

    def _merge_titles(self, tests: List[Dict[str, Any]]) -> str:
        """Merge test titles, preferring the most descriptive."""
        titles = [t.get("title", "") for t in tests]

        # Choose the longest title as it's likely most descriptive
        best_title = max(titles, key=len) if titles else "Merged Test"

        # Check if titles are very different
        unique_words = set()
        for title in titles:
            unique_words.update(title.lower().split())

        # If titles are very different, create a combined title
        if len(unique_words) > len(best_title.split()) * 1.5:
            return f"{best_title} (Merged)"

        return best_title

    def _merge_descriptions(self, tests: List[Dict[str, Any]]) -> str:
        """Merge test descriptions."""
        descriptions = [t.get("description", "") for t in tests if t.get("description")]

        if not descriptions:
            return ""

        if len(descriptions) == 1:
            return descriptions[0]

        # Combine unique descriptions
        unique_descriptions = list(dict.fromkeys(descriptions))  # Preserve order
        return " | ".join(unique_descriptions[:3])  # Limit to 3

    def _merge_category(self, tests: List[Dict[str, Any]]) -> str:
        """Merge categories, preferring security."""
        categories = [t.get("category", "functional") for t in tests]

        # Priority: security > functional > ui > other
        if "security" in categories:
            return "security"
        elif "functional" in categories:
            return "functional"
        else:
            return categories[0]

    def _merge_priority(self, tests: List[Dict[str, Any]]) -> str:
        """Merge priorities, keeping highest."""
        priorities = [t.get("priority", "medium") for t in tests]

        for priority in ["critical", "high", "medium", "low"]:
            if priority in priorities:
                return priority

        return "medium"

    def _merge_steps_union(self, tests: List[Dict[str, Any]]) -> List[str]:
        """Merge steps, removing near-duplicates."""
        all_steps = []
        seen_normalized = set()

        for test in tests:
            for step in test.get("steps", []):
                normalized = self._normalize_step(step)
                if normalized not in seen_normalized:
                    seen_normalized.add(normalized)
                    all_steps.append(step)

        return all_steps

    def _merge_steps_intersection(self, tests: List[Dict[str, Any]]) -> List[str]:
        """Keep only steps that appear in all tests."""
        if not tests:
            return []

        # Get steps from first test
        steps_sets = []
        for test in tests:
            normalized_steps = {self._normalize_step(s) for s in test.get("steps", [])}
            steps_sets.append(normalized_steps)

        # Find intersection
        if not steps_sets:
            return []

        common = steps_sets[0]
        for s in steps_sets[1:]:
            common &= s

        # Return original steps that match normalized common steps
        result = []
        for test in tests:
            for step in test.get("steps", []):
                if self._normalize_step(step) in common:
                    if step not in result:
                        result.append(step)
                        common.discard(self._normalize_step(step))

        return result

    def _merge_expected_results(self, tests: List[Dict[str, Any]]) -> str:
        """Merge expected results."""
        results = [t.get("expected_result", "") for t in tests if t.get("expected_result")]

        if not results:
            return ""

        if len(results) == 1:
            return results[0]

        # Combine unique results
        unique_results = list(dict.fromkeys(results))
        return " AND ".join(unique_results[:3])

    def _normalize_step(self, step: str) -> str:
        """Normalize a step for comparison."""
        # Lowercase
        step = step.lower()
        # Remove special characters
        step = re.sub(r"[^a-z0-9\s]", " ", step)
        # Remove extra whitespace
        step = re.sub(r"\s+", " ", step).strip()
        # Remove common words
        words = step.split()
        filtered = [w for w in words if w not in {"the", "a", "an", "to", "and", "or"}]
        return " ".join(filtered)

    def suggest_merge_strategy(
        self,
        tests: List[Dict[str, Any]],
    ) -> MergeStrategy:
        """Suggest the best merge strategy based on test characteristics."""
        if not tests:
            return self.default_strategy

        # Count unique steps across all tests
        all_steps = set()
        common_steps = None
        for test in tests:
            normalized_steps = {self._normalize_step(s) for s in test.get("steps", [])}
            all_steps |= normalized_steps
            if common_steps is None:
                common_steps = normalized_steps
            else:
                common_steps &= normalized_steps

        common_steps = common_steps or set()

        # If most steps are common, keep highest priority
        if len(common_steps) >= len(all_steps) * 0.8:
            return MergeStrategy.KEEP_HIGHEST_PRIORITY

        # If steps are very different, union them
        if len(common_steps) < len(all_steps) * 0.3:
            return MergeStrategy.UNION_STEPS

        # Otherwise, merge all
        return MergeStrategy.MERGE_ALL

    def format_merge_result(self, result: MergeResult) -> str:
        """Format merge result as readable text."""
        lines = [
            "-" * 50,
            f"  MERGE RESULT",
            "-" * 50,
            "",
            f"  Status: {'Success' if result.success else 'Failed'}",
            f"  Strategy: {result.strategy_used.value}",
            f"  Sources: {', '.join(result.source_test_ids)}",
            f"  Steps Merged: {result.steps_merged}",
            "",
        ]

        if result.merged_test:
            lines.extend([
                "  MERGED TEST:",
                f"    ID: {result.merged_test.get('id', 'N/A')}",
                f"    Title: {result.merged_test.get('title', 'N/A')}",
                f"    Category: {result.merged_test.get('category', 'N/A')}",
                f"    Priority: {result.merged_test.get('priority', 'N/A')}",
                f"    Steps: {len(result.merged_test.get('steps', []))}",
            ])

        lines.extend(["", f"  {result.message}", "-" * 50])
        return "\n".join(lines)


def create_merger(
    default_strategy: MergeStrategy = MergeStrategy.MERGE_ALL,
) -> TestMerger:
    """Create a test merger instance."""
    return TestMerger(default_strategy)
