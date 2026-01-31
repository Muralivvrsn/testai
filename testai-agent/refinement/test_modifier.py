"""
TestAI Agent - Test Modifier

Provides structured modification operations for test cases.
Works with the NL Refiner to apply changes to test sets.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import copy


class ModificationAction(Enum):
    """Types of modification actions."""
    UPDATE_PRIORITY = "update_priority"
    UPDATE_CATEGORY = "update_category"
    ADD_STEP = "add_step"
    REMOVE_STEP = "remove_step"
    UPDATE_TITLE = "update_title"
    UPDATE_DESCRIPTION = "update_description"
    MERGE_TESTS = "merge_tests"
    SPLIT_TEST = "split_test"
    DUPLICATE = "duplicate"
    REORDER = "reorder"


@dataclass
class ModificationResult:
    """Result of a modification operation."""
    success: bool
    action: ModificationAction
    test_id: str
    changes: Dict[str, Any]
    message: str


class TestModifier:
    """
    Provides structured modification operations for test cases.

    This is the "surgical" tool for precise test modifications,
    complementing the NL refiner's high-level commands.
    """

    def __init__(self):
        """Initialize the test modifier."""
        self._modification_history: List[ModificationResult] = []

    def update_priority(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        new_priority: str,
    ) -> ModificationResult:
        """Update the priority of a specific test."""
        for test in tests:
            if test.get("id") == test_id:
                old_priority = test.get("priority", "medium")
                test["priority"] = new_priority

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.UPDATE_PRIORITY,
                    test_id=test_id,
                    changes={"old_priority": old_priority, "new_priority": new_priority},
                    message=f"Updated priority from {old_priority} to {new_priority}",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.UPDATE_PRIORITY,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def update_category(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        new_category: str,
    ) -> ModificationResult:
        """Update the category of a specific test."""
        for test in tests:
            if test.get("id") == test_id:
                old_category = test.get("category", "functional")
                test["category"] = new_category

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.UPDATE_CATEGORY,
                    test_id=test_id,
                    changes={"old_category": old_category, "new_category": new_category},
                    message=f"Updated category from {old_category} to {new_category}",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.UPDATE_CATEGORY,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def add_step(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        step: str,
        position: Optional[int] = None,
    ) -> ModificationResult:
        """Add a step to a specific test."""
        for test in tests:
            if test.get("id") == test_id:
                steps = test.get("steps", [])

                if position is None or position >= len(steps):
                    steps.append(step)
                    pos = len(steps) - 1
                else:
                    steps.insert(position, step)
                    pos = position

                test["steps"] = steps

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.ADD_STEP,
                    test_id=test_id,
                    changes={"step": step, "position": pos},
                    message=f"Added step at position {pos}",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.ADD_STEP,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def remove_step(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        step_index: int,
    ) -> ModificationResult:
        """Remove a step from a specific test."""
        for test in tests:
            if test.get("id") == test_id:
                steps = test.get("steps", [])

                if 0 <= step_index < len(steps):
                    removed_step = steps.pop(step_index)
                    test["steps"] = steps

                    result = ModificationResult(
                        success=True,
                        action=ModificationAction.REMOVE_STEP,
                        test_id=test_id,
                        changes={"removed_step": removed_step, "index": step_index},
                        message=f"Removed step at index {step_index}",
                    )
                    self._modification_history.append(result)
                    return result
                else:
                    return ModificationResult(
                        success=False,
                        action=ModificationAction.REMOVE_STEP,
                        test_id=test_id,
                        changes={},
                        message=f"Step index {step_index} out of range",
                    )

        return ModificationResult(
            success=False,
            action=ModificationAction.REMOVE_STEP,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def update_title(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        new_title: str,
    ) -> ModificationResult:
        """Update the title of a specific test."""
        for test in tests:
            if test.get("id") == test_id:
                old_title = test.get("title", "")
                test["title"] = new_title

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.UPDATE_TITLE,
                    test_id=test_id,
                    changes={"old_title": old_title, "new_title": new_title},
                    message=f"Updated title",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.UPDATE_TITLE,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def duplicate_test(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        new_id: Optional[str] = None,
    ) -> ModificationResult:
        """Duplicate a test case."""
        for i, test in enumerate(tests):
            if test.get("id") == test_id:
                # Create deep copy
                new_test = copy.deepcopy(test)

                # Generate new ID
                if new_id:
                    new_test["id"] = new_id
                else:
                    new_test["id"] = f"{test_id}-copy"

                # Append to list
                tests.append(new_test)

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.DUPLICATE,
                    test_id=test_id,
                    changes={"new_test_id": new_test["id"]},
                    message=f"Duplicated test as {new_test['id']}",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.DUPLICATE,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def reorder_tests(
        self,
        tests: List[Dict[str, Any]],
        order_key: str = "priority",
        reverse: bool = True,
    ) -> ModificationResult:
        """Reorder tests by a specific key."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        if order_key == "priority":
            tests.sort(
                key=lambda t: priority_order.get(t.get("priority", "medium"), 2),
                reverse=not reverse,  # Reverse order for priority (critical first)
            )
        elif order_key == "category":
            tests.sort(key=lambda t: t.get("category", ""), reverse=reverse)
        elif order_key == "title":
            tests.sort(key=lambda t: t.get("title", ""), reverse=reverse)
        elif order_key == "id":
            tests.sort(key=lambda t: t.get("id", ""), reverse=reverse)

        result = ModificationResult(
            success=True,
            action=ModificationAction.REORDER,
            test_id="all",
            changes={"order_key": order_key, "reverse": reverse},
            message=f"Reordered tests by {order_key}",
        )
        self._modification_history.append(result)
        return result

    def merge_tests(
        self,
        tests: List[Dict[str, Any]],
        test_ids: List[str],
        merged_title: str,
    ) -> ModificationResult:
        """Merge multiple tests into one."""
        tests_to_merge = []
        indices_to_remove = []

        for i, test in enumerate(tests):
            if test.get("id") in test_ids:
                tests_to_merge.append(test)
                indices_to_remove.append(i)

        if len(tests_to_merge) < 2:
            return ModificationResult(
                success=False,
                action=ModificationAction.MERGE_TESTS,
                test_id="",
                changes={},
                message="Need at least 2 tests to merge",
            )

        # Create merged test
        merged_test = {
            "id": f"MERGED-{tests_to_merge[0]['id']}",
            "title": merged_title,
            "description": " | ".join(t.get("description", "") for t in tests_to_merge),
            "category": tests_to_merge[0].get("category", "functional"),
            "priority": self._highest_priority([t.get("priority", "medium") for t in tests_to_merge]),
            "steps": [],
            "expected_result": " AND ".join(t.get("expected_result", "") for t in tests_to_merge),
        }

        # Merge steps
        for test in tests_to_merge:
            merged_test["steps"].extend(test.get("steps", []))

        # Remove old tests (in reverse order to maintain indices)
        for i in sorted(indices_to_remove, reverse=True):
            tests.pop(i)

        # Add merged test
        tests.append(merged_test)

        result = ModificationResult(
            success=True,
            action=ModificationAction.MERGE_TESTS,
            test_id=merged_test["id"],
            changes={"merged_ids": test_ids, "new_id": merged_test["id"]},
            message=f"Merged {len(test_ids)} tests into {merged_test['id']}",
        )
        self._modification_history.append(result)
        return result

    def split_test(
        self,
        tests: List[Dict[str, Any]],
        test_id: str,
        split_at_step: int,
    ) -> ModificationResult:
        """Split a test into two at a specific step."""
        for i, test in enumerate(tests):
            if test.get("id") == test_id:
                steps = test.get("steps", [])

                if split_at_step <= 0 or split_at_step >= len(steps):
                    return ModificationResult(
                        success=False,
                        action=ModificationAction.SPLIT_TEST,
                        test_id=test_id,
                        changes={},
                        message=f"Invalid split position {split_at_step}",
                    )

                # Create first part (modify original)
                test["steps"] = steps[:split_at_step]
                test["title"] = test.get("title", "") + " (Part 1)"

                # Create second part
                new_test = copy.deepcopy(test)
                new_test["id"] = f"{test_id}-part2"
                new_test["title"] = new_test["title"].replace(" (Part 1)", " (Part 2)")
                new_test["steps"] = steps[split_at_step:]

                tests.append(new_test)

                result = ModificationResult(
                    success=True,
                    action=ModificationAction.SPLIT_TEST,
                    test_id=test_id,
                    changes={"new_test_id": new_test["id"], "split_at": split_at_step},
                    message=f"Split test at step {split_at_step}",
                )
                self._modification_history.append(result)
                return result

        return ModificationResult(
            success=False,
            action=ModificationAction.SPLIT_TEST,
            test_id=test_id,
            changes={},
            message=f"Test {test_id} not found",
        )

    def _highest_priority(self, priorities: List[str]) -> str:
        """Get the highest priority from a list."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_priority = "low"
        min_value = 3

        for p in priorities:
            value = priority_order.get(p.lower(), 2)
            if value < min_value:
                min_value = value
                min_priority = p

        return min_priority

    def get_history(self) -> List[ModificationResult]:
        """Get modification history."""
        return self._modification_history

    def undo_last(
        self,
        tests: List[Dict[str, Any]],
    ) -> Optional[ModificationResult]:
        """Undo the last modification (limited support)."""
        if not self._modification_history:
            return None

        last = self._modification_history.pop()

        # Undo is complex and limited - just return what was done
        return ModificationResult(
            success=False,
            action=last.action,
            test_id=last.test_id,
            changes={"undone": last.changes},
            message="Undo not fully implemented - showing last change",
        )


def create_modifier() -> TestModifier:
    """Create a test modifier instance."""
    return TestModifier()
