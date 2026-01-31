"""
TestAI Agent - Test Updater

Generates and applies automated updates to tests
based on detected maintenance needs.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import re


class UpdateType(Enum):
    """Types of test updates."""
    SELECTOR_REPLACEMENT = "selector_replacement"
    WAIT_ADDITION = "wait_addition"
    TIMEOUT_ADJUSTMENT = "timeout_adjustment"
    ASSERTION_UPDATE = "assertion_update"
    CODE_CLEANUP = "code_cleanup"
    DEPRECATION_FIX = "deprecation_fix"
    DATA_UPDATE = "data_update"
    REFACTOR = "refactor"


class UpdateStatus(Enum):
    """Status of an update."""
    SUGGESTED = "suggested"
    APPROVED = "approved"
    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass
class UpdateSuggestion:
    """A suggested update to a test."""
    suggestion_id: str
    test_id: str
    update_type: UpdateType
    title: str
    description: str
    original_code: str
    suggested_code: str
    confidence: float
    auto_applicable: bool
    status: UpdateStatus = UpdateStatus.SUGGESTED
    applied_at: Optional[datetime] = None
    line_number: Optional[int] = None


@dataclass
class UpdateResult:
    """Result of applying an update."""
    suggestion_id: str
    success: bool
    message: str
    original_code: str
    new_code: str


@dataclass
class UpdateBatch:
    """A batch of related updates."""
    batch_id: str
    test_id: str
    suggestions: List[UpdateSuggestion]
    total_changes: int
    estimated_impact: str


class TestUpdater:
    """
    Generates and applies test updates.

    Features:
    - Selector replacement suggestions
    - Wait strategy updates
    - Code cleanup automation
    - Deprecation fixes
    - Batch update support
    """

    # Update patterns
    UPDATE_PATTERNS = {
        "add_wait_for_selector": {
            "pattern": r"(await\s+page\.click\(['\"]([^'\"]+)['\"]\))",
            "replacement": "await page.waitForSelector('{selector}', {{visible: true}});\n  {original}",
            "description": "Add explicit wait before click",
        },
        "add_wait_for_navigation": {
            "pattern": r"(await\s+(?:page|element)\.click\([^)]+\))(?!\s*;?\s*await\s+page\.waitFor)",
            "replacement": "{original};\n  await page.waitForNavigation()",
            "description": "Add wait for navigation after click",
        },
        "replace_sleep_with_wait": {
            "pattern": r"await\s+page\.waitForTimeout\((\d+)\)",
            "replacement": "await page.waitForSelector('.target-element', {{timeout: {timeout}}})",
            "description": "Replace timeout with explicit wait",
        },
        "increase_timeout": {
            "pattern": r"timeout:\s*(\d+)",
            "replacement": "timeout: {new_timeout}",
            "description": "Increase timeout value",
        },
        "remove_console_log": {
            "pattern": r"console\.log\([^)]+\);?\n?",
            "replacement": "",
            "description": "Remove console.log statement",
        },
        "remove_debugger": {
            "pattern": r"debugger;?\n?",
            "replacement": "",
            "description": "Remove debugger statement",
        },
        "fix_only": {
            "pattern": r"(test|it|describe)\.only\(",
            "replacement": "{keyword}(",
            "description": "Remove .only from test",
        },
        "fix_skip": {
            "pattern": r"(test|it|describe)\.skip\(",
            "replacement": "{keyword}(",
            "description": "Remove .skip from test (if no longer needed)",
        },
    }

    def __init__(self):
        """Initialize the test updater."""
        self._suggestion_counter = 0
        self._batch_counter = 0
        self._suggestions: Dict[str, UpdateSuggestion] = {}

    def analyze_for_updates(
        self,
        test_id: str,
        code: str,
        issues: Optional[List[Dict[str, Any]]] = None,
    ) -> List[UpdateSuggestion]:
        """Analyze test code and generate update suggestions."""
        suggestions = []

        # Check for common patterns
        suggestions.extend(self._check_wait_patterns(test_id, code))
        suggestions.extend(self._check_cleanup_patterns(test_id, code))
        suggestions.extend(self._check_deprecation_patterns(test_id, code))

        # Handle specific issues if provided
        if issues:
            for issue in issues:
                issue_suggestions = self._generate_for_issue(test_id, code, issue)
                suggestions.extend(issue_suggestions)

        # Store suggestions
        for suggestion in suggestions:
            self._suggestions[suggestion.suggestion_id] = suggestion

        return suggestions

    def _check_wait_patterns(
        self,
        test_id: str,
        code: str,
    ) -> List[UpdateSuggestion]:
        """Check for wait pattern improvements."""
        suggestions = []

        # Check for clicks without waits
        click_pattern = r"await\s+page\.click\(['\"]([^'\"]+)['\"]\)"
        for match in re.finditer(click_pattern, code):
            selector = match.group(1)
            original = match.group(0)

            # Check if there's already a wait before this
            context_start = max(0, match.start() - 100)
            context = code[context_start:match.start()]

            if "waitForSelector" not in context and "waitFor" not in context:
                self._suggestion_counter += 1
                suggestion = UpdateSuggestion(
                    suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                    test_id=test_id,
                    update_type=UpdateType.WAIT_ADDITION,
                    title="Add explicit wait before click",
                    description=f"Add waitForSelector before clicking '{selector[:30]}'",
                    original_code=original,
                    suggested_code=f"await page.waitForSelector('{selector}', {{visible: true}});\n  {original}",
                    confidence=0.8,
                    auto_applicable=True,
                    line_number=code[:match.start()].count('\n') + 1,
                )
                suggestions.append(suggestion)

        # Check for waitForTimeout (anti-pattern)
        timeout_pattern = r"await\s+page\.waitForTimeout\((\d+)\)"
        for match in re.finditer(timeout_pattern, code):
            timeout = match.group(1)
            original = match.group(0)

            self._suggestion_counter += 1
            suggestion = UpdateSuggestion(
                suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                test_id=test_id,
                update_type=UpdateType.WAIT_ADDITION,
                title="Replace hard wait with explicit wait",
                description=f"Replace waitForTimeout({timeout}) with condition-based wait",
                original_code=original,
                suggested_code=f"await page.waitForSelector('.target', {{timeout: {timeout}}})",
                confidence=0.6,
                auto_applicable=False,  # Needs manual selector
                line_number=code[:match.start()].count('\n') + 1,
            )
            suggestions.append(suggestion)

        return suggestions

    def _check_cleanup_patterns(
        self,
        test_id: str,
        code: str,
    ) -> List[UpdateSuggestion]:
        """Check for code cleanup opportunities."""
        suggestions = []

        # Check for console.log
        console_pattern = r"console\.log\([^)]+\);?"
        for match in re.finditer(console_pattern, code):
            original = match.group(0)

            self._suggestion_counter += 1
            suggestion = UpdateSuggestion(
                suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                test_id=test_id,
                update_type=UpdateType.CODE_CLEANUP,
                title="Remove debug logging",
                description="Remove console.log statement from test",
                original_code=original,
                suggested_code="",
                confidence=0.95,
                auto_applicable=True,
                line_number=code[:match.start()].count('\n') + 1,
            )
            suggestions.append(suggestion)

        # Check for debugger
        debugger_pattern = r"debugger;?"
        for match in re.finditer(debugger_pattern, code):
            original = match.group(0)

            self._suggestion_counter += 1
            suggestion = UpdateSuggestion(
                suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                test_id=test_id,
                update_type=UpdateType.CODE_CLEANUP,
                title="Remove debugger statement",
                description="Remove debugger statement from test",
                original_code=original,
                suggested_code="",
                confidence=1.0,
                auto_applicable=True,
                line_number=code[:match.start()].count('\n') + 1,
            )
            suggestions.append(suggestion)

        # Check for .only
        only_pattern = r"(test|it|describe)\.only\("
        for match in re.finditer(only_pattern, code):
            keyword = match.group(1)
            original = match.group(0)

            self._suggestion_counter += 1
            suggestion = UpdateSuggestion(
                suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                test_id=test_id,
                update_type=UpdateType.CODE_CLEANUP,
                title="Remove .only",
                description="Remove .only to run all tests",
                original_code=original,
                suggested_code=f"{keyword}(",
                confidence=1.0,
                auto_applicable=True,
                line_number=code[:match.start()].count('\n') + 1,
            )
            suggestions.append(suggestion)

        return suggestions

    def _check_deprecation_patterns(
        self,
        test_id: str,
        code: str,
    ) -> List[UpdateSuggestion]:
        """Check for deprecated patterns."""
        suggestions = []

        deprecated = [
            (r"page\.waitFor\((\d+)\)", "waitFor({}) is deprecated", "page.waitForTimeout({})"),
            (r"page\.\$eval\(", "Consider using locator.evaluate()", None),
            (r"elementHandle\.click\(\)", "Consider using locator.click()", None),
        ]

        for pattern, message, replacement in deprecated:
            for match in re.finditer(pattern, code):
                original = match.group(0)
                suggested = original
                if replacement and match.groups():
                    suggested = replacement.format(*match.groups())

                self._suggestion_counter += 1
                suggestion = UpdateSuggestion(
                    suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                    test_id=test_id,
                    update_type=UpdateType.DEPRECATION_FIX,
                    title="Update deprecated pattern",
                    description=message.format(*match.groups()) if match.groups() else message,
                    original_code=original,
                    suggested_code=suggested,
                    confidence=0.7,
                    auto_applicable=replacement is not None,
                    line_number=code[:match.start()].count('\n') + 1,
                )
                suggestions.append(suggestion)

        return suggestions

    def _generate_for_issue(
        self,
        test_id: str,
        code: str,
        issue: Dict[str, Any],
    ) -> List[UpdateSuggestion]:
        """Generate suggestions for a specific issue."""
        suggestions = []
        issue_type = issue.get("type", "")

        if issue_type == "selector_update":
            old_selector = issue.get("selector", "")
            new_selector = issue.get("suggested_selector", f'[data-testid="{old_selector}"]')

            if old_selector and old_selector in code:
                self._suggestion_counter += 1
                suggestion = UpdateSuggestion(
                    suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                    test_id=test_id,
                    update_type=UpdateType.SELECTOR_REPLACEMENT,
                    title="Update fragile selector",
                    description=f"Replace '{old_selector[:30]}' with stable selector",
                    original_code=old_selector,
                    suggested_code=new_selector,
                    confidence=0.7,
                    auto_applicable=False,
                )
                suggestions.append(suggestion)

        elif issue_type == "timeout":
            # Find timeout values and suggest increase
            timeout_pattern = r"timeout:\s*(\d+)"
            for match in re.finditer(timeout_pattern, code):
                old_timeout = int(match.group(1))
                new_timeout = old_timeout * 2

                self._suggestion_counter += 1
                suggestion = UpdateSuggestion(
                    suggestion_id=f"UPD-{self._suggestion_counter:05d}",
                    test_id=test_id,
                    update_type=UpdateType.TIMEOUT_ADJUSTMENT,
                    title="Increase timeout",
                    description=f"Increase timeout from {old_timeout}ms to {new_timeout}ms",
                    original_code=f"timeout: {old_timeout}",
                    suggested_code=f"timeout: {new_timeout}",
                    confidence=0.6,
                    auto_applicable=True,
                    line_number=code[:match.start()].count('\n') + 1,
                )
                suggestions.append(suggestion)

        return suggestions

    def apply_suggestion(
        self,
        suggestion_id: str,
        code: str,
    ) -> UpdateResult:
        """Apply a single suggestion to code."""
        suggestion = self._suggestions.get(suggestion_id)

        if not suggestion:
            return UpdateResult(
                suggestion_id=suggestion_id,
                success=False,
                message="Suggestion not found",
                original_code=code,
                new_code=code,
            )

        if suggestion.original_code not in code:
            suggestion.status = UpdateStatus.FAILED
            return UpdateResult(
                suggestion_id=suggestion_id,
                success=False,
                message="Original code not found in test",
                original_code=code,
                new_code=code,
            )

        try:
            new_code = code.replace(
                suggestion.original_code,
                suggestion.suggested_code,
                1  # Replace first occurrence only
            )

            suggestion.status = UpdateStatus.APPLIED
            suggestion.applied_at = datetime.now()

            return UpdateResult(
                suggestion_id=suggestion_id,
                success=True,
                message="Update applied successfully",
                original_code=code,
                new_code=new_code,
            )

        except Exception as e:
            suggestion.status = UpdateStatus.FAILED
            return UpdateResult(
                suggestion_id=suggestion_id,
                success=False,
                message=str(e),
                original_code=code,
                new_code=code,
            )

    def apply_batch(
        self,
        test_id: str,
        code: str,
        auto_only: bool = True,
    ) -> UpdateResult:
        """Apply all applicable suggestions to a test."""
        suggestions = [
            s for s in self._suggestions.values()
            if s.test_id == test_id and s.status == UpdateStatus.SUGGESTED
        ]

        if auto_only:
            suggestions = [s for s in suggestions if s.auto_applicable]

        # Sort by line number (reverse to apply from bottom up)
        suggestions.sort(key=lambda s: s.line_number or 0, reverse=True)

        new_code = code
        applied_count = 0

        for suggestion in suggestions:
            if suggestion.original_code in new_code:
                new_code = new_code.replace(
                    suggestion.original_code,
                    suggestion.suggested_code,
                    1
                )
                suggestion.status = UpdateStatus.APPLIED
                suggestion.applied_at = datetime.now()
                applied_count += 1

        return UpdateResult(
            suggestion_id=f"BATCH-{test_id}",
            success=applied_count > 0,
            message=f"Applied {applied_count} updates",
            original_code=code,
            new_code=new_code,
        )

    def create_batch(
        self,
        test_id: str,
        suggestion_ids: List[str],
    ) -> UpdateBatch:
        """Create a batch of updates."""
        self._batch_counter += 1

        suggestions = [
            self._suggestions[sid]
            for sid in suggestion_ids
            if sid in self._suggestions
        ]

        return UpdateBatch(
            batch_id=f"BATCH-{self._batch_counter:05d}",
            test_id=test_id,
            suggestions=suggestions,
            total_changes=len(suggestions),
            estimated_impact=self._estimate_impact(suggestions),
        )

    def _estimate_impact(self, suggestions: List[UpdateSuggestion]) -> str:
        """Estimate impact of applying suggestions."""
        if not suggestions:
            return "No changes"

        by_type = {}
        for s in suggestions:
            by_type[s.update_type] = by_type.get(s.update_type, 0) + 1

        impacts = []
        if UpdateType.SELECTOR_REPLACEMENT in by_type:
            impacts.append(f"{by_type[UpdateType.SELECTOR_REPLACEMENT]} selector(s)")
        if UpdateType.WAIT_ADDITION in by_type:
            impacts.append(f"{by_type[UpdateType.WAIT_ADDITION]} wait(s)")
        if UpdateType.CODE_CLEANUP in by_type:
            impacts.append(f"{by_type[UpdateType.CODE_CLEANUP]} cleanup(s)")

        return ", ".join(impacts) if impacts else "Minor changes"

    def get_pending_suggestions(
        self,
        test_id: Optional[str] = None,
    ) -> List[UpdateSuggestion]:
        """Get pending suggestions."""
        suggestions = list(self._suggestions.values())

        if test_id:
            suggestions = [s for s in suggestions if s.test_id == test_id]

        return [s for s in suggestions if s.status == UpdateStatus.SUGGESTED]

    def format_suggestions(
        self,
        suggestions: List[UpdateSuggestion],
    ) -> str:
        """Format suggestions as readable text."""
        lines = [
            "=" * 60,
            "  UPDATE SUGGESTIONS",
            "=" * 60,
            "",
            f"  Total Suggestions: {len(suggestions)}",
            f"  Auto-applicable: {sum(1 for s in suggestions if s.auto_applicable)}",
            "",
        ]

        by_type: Dict[UpdateType, List[UpdateSuggestion]] = {}
        for s in suggestions:
            if s.update_type not in by_type:
                by_type[s.update_type] = []
            by_type[s.update_type].append(s)

        for update_type, type_suggestions in by_type.items():
            lines.extend([
                "-" * 60,
                f"  {update_type.value.upper()} ({len(type_suggestions)})",
                "-" * 60,
            ])

            for s in type_suggestions[:5]:
                auto = "✓" if s.auto_applicable else "○"
                lines.extend([
                    f"",
                    f"  [{auto}] {s.title}",
                    f"      {s.description}",
                    f"      Confidence: {s.confidence:.0%}",
                ])

                if s.line_number:
                    lines.append(f"      Line: {s.line_number}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_updater() -> TestUpdater:
    """Create a test updater instance."""
    return TestUpdater()
