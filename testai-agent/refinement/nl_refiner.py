"""
TestAI Agent - Natural Language Refiner

Understands natural language commands to refine and modify test cases.
This allows users to interact with test plans like they would with a human QA.

Examples:
- "Add more security tests"
- "Make the password tests stricter"
- "Focus on edge cases"
- "Remove the UI tests"
- "Prioritize authentication"
- "Add tests for SQL injection"
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple, Set
import re


class RefinementType(Enum):
    """Types of refinement actions."""
    ADD = "add"  # Add new tests
    REMOVE = "remove"  # Remove tests
    MODIFY = "modify"  # Modify existing tests
    PRIORITIZE = "prioritize"  # Change priorities
    FOCUS = "focus"  # Focus on specific area
    EXPAND = "expand"  # Expand coverage
    SIMPLIFY = "simplify"  # Reduce complexity
    STRENGTHEN = "strengthen"  # Make tests more rigorous


@dataclass
class RefinementCommand:
    """A parsed refinement command from natural language."""
    command_type: RefinementType
    target: str  # What to affect (category, specific test, etc.)

    # Specific details
    category_filter: Optional[str] = None
    keyword_filter: Optional[str] = None
    priority_filter: Optional[str] = None

    # Parameters
    quantity: Optional[int] = None  # How many (e.g., "add 5 more")
    intensity: str = "normal"  # normal, strict, relaxed

    # Original input
    original_input: str = ""
    confidence: float = 0.0


@dataclass
class RefinementResult:
    """Result of applying a refinement."""
    success: bool
    command: RefinementCommand

    # What changed
    tests_added: int = 0
    tests_removed: int = 0
    tests_modified: int = 0

    # New test set
    refined_tests: List[Dict[str, Any]] = field(default_factory=list)

    # Explanation
    explanation: str = ""
    suggestions: List[str] = field(default_factory=list)


class NaturalLanguageRefiner:
    """
    Parses natural language commands and refines test cases accordingly.

    This is what makes the agent truly conversational - it understands
    what you want and applies changes intelligently.
    """

    # Command patterns for parsing
    ADD_PATTERNS = [
        r"add\s+(?:more\s+)?(\d+)?\s*(.+?)\s*(?:tests?)?$",
        r"include\s+(.+?)\s*(?:tests?)?$",
        r"create\s+(.+?)\s*(?:tests?)?$",
        r"generate\s+(?:more\s+)?(\d+)?\s*(.+?)\s*(?:tests?)?$",
        r"need\s+(?:more\s+)?(.+?)\s*(?:tests?)?$",
    ]

    REMOVE_PATTERNS = [
        r"remove\s+(?:all\s+)?(.+?)\s*(?:tests?)?$",
        r"delete\s+(?:all\s+)?(.+?)\s*(?:tests?)?$",
        r"drop\s+(?:all\s+)?(.+?)\s*(?:tests?)?$",
        r"exclude\s+(.+?)\s*(?:tests?)?$",
        r"skip\s+(.+?)\s*(?:tests?)?$",
        r"don'?t\s+(?:need|want)\s+(.+?)\s*(?:tests?)?$",
    ]

    PRIORITIZE_PATTERNS = [
        r"prioritize\s+(.+?)$",
        r"focus\s+(?:on\s+)?(.+?)$",
        r"emphasize\s+(.+?)$",
        r"make\s+(.+?)\s+(?:more\s+)?important",
        r"(.+?)\s+(?:is|are)\s+(?:more\s+)?important",
    ]

    MODIFY_PATTERNS = [
        r"make\s+(.+?)\s+(?:tests?\s+)?(?:more\s+)?(\w+)$",
        r"(.+?)\s+(?:tests?\s+)?should\s+be\s+(?:more\s+)?(\w+)$",
        r"strengthen\s+(.+?)\s*(?:tests?)?$",
        r"improve\s+(.+?)\s*(?:tests?)?$",
    ]

    EXPAND_PATTERNS = [
        r"expand\s+(.+?)\s*(?:coverage)?$",
        r"more\s+(.+?)\s*(?:coverage)?$",
        r"increase\s+(.+?)\s*(?:coverage)?$",
        r"add\s+(?:more\s+)?coverage\s+(?:for\s+)?(.+?)$",
    ]

    # Category keywords
    CATEGORY_KEYWORDS = {
        "security": ["security", "secure", "injection", "xss", "sql", "auth", "csrf", "vulnerability"],
        "functional": ["functional", "function", "feature", "flow", "workflow", "process"],
        "validation": ["validation", "validate", "input", "form", "field", "format"],
        "edge_case": ["edge", "edge case", "boundary", "limit", "extreme", "corner"],
        "ui": ["ui", "ux", "interface", "visual", "display", "layout", "style"],
        "accessibility": ["accessibility", "a11y", "screen reader", "aria", "keyboard"],
        "performance": ["performance", "speed", "load", "response", "timeout"],
        "error_handling": ["error", "exception", "failure", "invalid", "wrong"],
    }

    # Priority keywords
    PRIORITY_KEYWORDS = {
        "critical": ["critical", "crucial", "essential", "must", "mandatory", "blocking"],
        "high": ["high", "important", "significant", "major"],
        "medium": ["medium", "moderate", "normal", "standard"],
        "low": ["low", "minor", "optional", "nice to have"],
    }

    # Intensity keywords
    INTENSITY_KEYWORDS = {
        "strict": ["strict", "rigorous", "thorough", "comprehensive", "exhaustive"],
        "relaxed": ["relaxed", "simple", "basic", "minimal", "quick"],
    }

    def __init__(self):
        """Initialize the natural language refiner."""
        self._history: List[RefinementCommand] = []

    def parse_command(self, user_input: str) -> RefinementCommand:
        """
        Parse a natural language command into a structured refinement command.

        This is the core NLU (Natural Language Understanding) for test refinement.
        """
        input_lower = user_input.lower().strip()

        # Try each command type
        command = None

        # Try ADD patterns
        for pattern in self.ADD_PATTERNS:
            match = re.search(pattern, input_lower)
            if match:
                groups = match.groups()
                quantity = None
                target = groups[-1] if groups else ""

                # Check if first group is a number
                if len(groups) > 1 and groups[0] and groups[0].isdigit():
                    quantity = int(groups[0])

                command = RefinementCommand(
                    command_type=RefinementType.ADD,
                    target=target,
                    quantity=quantity,
                    original_input=user_input,
                )
                break

        # Try REMOVE patterns
        if not command:
            for pattern in self.REMOVE_PATTERNS:
                match = re.search(pattern, input_lower)
                if match:
                    command = RefinementCommand(
                        command_type=RefinementType.REMOVE,
                        target=match.group(1),
                        original_input=user_input,
                    )
                    break

        # Try PRIORITIZE patterns
        if not command:
            for pattern in self.PRIORITIZE_PATTERNS:
                match = re.search(pattern, input_lower)
                if match:
                    command = RefinementCommand(
                        command_type=RefinementType.PRIORITIZE,
                        target=match.group(1),
                        original_input=user_input,
                    )
                    break

        # Try MODIFY patterns
        if not command:
            for pattern in self.MODIFY_PATTERNS:
                match = re.search(pattern, input_lower)
                if match:
                    groups = match.groups()
                    target = groups[0] if groups else ""
                    intensity = groups[1] if len(groups) > 1 else "normal"

                    command = RefinementCommand(
                        command_type=RefinementType.MODIFY,
                        target=target,
                        intensity=intensity,
                        original_input=user_input,
                    )
                    break

        # Try EXPAND patterns
        if not command:
            for pattern in self.EXPAND_PATTERNS:
                match = re.search(pattern, input_lower)
                if match:
                    command = RefinementCommand(
                        command_type=RefinementType.EXPAND,
                        target=match.group(1),
                        original_input=user_input,
                    )
                    break

        # Default to FOCUS if nothing matched but has category keywords
        if not command:
            detected_category = self._detect_category(input_lower)
            if detected_category:
                command = RefinementCommand(
                    command_type=RefinementType.FOCUS,
                    target=detected_category,
                    original_input=user_input,
                )

        # Fallback to generic MODIFY
        if not command:
            command = RefinementCommand(
                command_type=RefinementType.MODIFY,
                target=input_lower,
                original_input=user_input,
            )

        # Enrich with detected categories and priorities
        self._enrich_command(command, input_lower)

        # Calculate confidence
        command.confidence = self._calculate_confidence(command, input_lower)

        # Store in history
        self._history.append(command)

        return command

    def _detect_category(self, text: str) -> Optional[str]:
        """Detect which test category the text refers to."""
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    return category
        return None

    def _detect_priority(self, text: str) -> Optional[str]:
        """Detect which priority level the text refers to."""
        for priority, keywords in self.PRIORITY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    return priority
        return None

    def _detect_intensity(self, text: str) -> str:
        """Detect the intensity/rigor level from text."""
        for intensity, keywords in self.INTENSITY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    return intensity
        return "normal"

    def _enrich_command(self, command: RefinementCommand, text: str) -> None:
        """Enrich command with detected categories and other metadata."""
        command.category_filter = self._detect_category(text)
        command.priority_filter = self._detect_priority(text)
        command.intensity = self._detect_intensity(text)

        # Extract keywords from target
        keywords = self._extract_keywords(command.target)
        if keywords:
            command.keyword_filter = keywords[0]

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from text."""
        # Remove common words
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "shall", "can",
            "tests", "test", "testing", "more", "less", "some", "all",
        }

        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        return [w for w in words if w not in stop_words]

    def _calculate_confidence(self, command: RefinementCommand, text: str) -> float:
        """Calculate confidence in the parsed command."""
        confidence = 0.5  # Base confidence

        # Boost for detected category
        if command.category_filter:
            confidence += 0.2

        # Boost for clear command type match
        if command.command_type in [RefinementType.ADD, RefinementType.REMOVE]:
            confidence += 0.15

        # Boost for quantity specification
        if command.quantity:
            confidence += 0.1

        # Boost for priority detection
        if command.priority_filter:
            confidence += 0.1

        return min(1.0, confidence)

    def apply_refinement(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
        generator_func: Optional[callable] = None,
    ) -> RefinementResult:
        """
        Apply a refinement command to a list of tests.

        This is where the magic happens - taking the parsed command
        and actually modifying the test set.
        """
        result = RefinementResult(
            success=True,
            command=command,
            refined_tests=tests.copy(),
        )

        if command.command_type == RefinementType.ADD:
            result = self._apply_add(command, tests, generator_func)

        elif command.command_type == RefinementType.REMOVE:
            result = self._apply_remove(command, tests)

        elif command.command_type == RefinementType.PRIORITIZE:
            result = self._apply_prioritize(command, tests)

        elif command.command_type == RefinementType.MODIFY:
            result = self._apply_modify(command, tests)

        elif command.command_type == RefinementType.FOCUS:
            result = self._apply_focus(command, tests)

        elif command.command_type == RefinementType.EXPAND:
            result = self._apply_expand(command, tests, generator_func)

        # Generate explanation
        result.explanation = self._generate_explanation(result)

        # Generate suggestions
        result.suggestions = self._generate_suggestions(result, tests)

        return result

    def _apply_add(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
        generator_func: Optional[callable],
    ) -> RefinementResult:
        """Apply ADD refinement - add new tests."""
        result = RefinementResult(
            success=True,
            command=command,
            refined_tests=tests.copy(),
        )

        category = command.category_filter or "functional"
        quantity = command.quantity or 3

        # Create new test templates based on category
        new_tests = self._generate_tests_for_category(
            category, quantity, command.keyword_filter
        )

        # Add to test list
        existing_ids = {t.get("id", "") for t in tests}
        start_id = len(tests) + 1

        for i, test in enumerate(new_tests):
            test["id"] = f"TC-{start_id + i:03d}"
            while test["id"] in existing_ids:
                start_id += 1
                test["id"] = f"TC-{start_id + i:03d}"
            result.refined_tests.append(test)

        result.tests_added = len(new_tests)

        return result

    def _apply_remove(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
    ) -> RefinementResult:
        """Apply REMOVE refinement - remove tests matching criteria."""
        result = RefinementResult(
            success=True,
            command=command,
        )

        # Determine what to remove
        category = command.category_filter
        keyword = command.keyword_filter or command.target

        remaining = []
        removed_count = 0

        for test in tests:
            should_remove = False

            # Check category
            if category and test.get("category", "").lower() == category.lower():
                should_remove = True

            # Check keywords in title/description
            if keyword:
                title = test.get("title", "").lower()
                desc = test.get("description", "").lower()
                if keyword.lower() in title or keyword.lower() in desc:
                    should_remove = True

            if should_remove:
                removed_count += 1
            else:
                remaining.append(test)

        result.refined_tests = remaining
        result.tests_removed = removed_count

        return result

    def _apply_prioritize(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
    ) -> RefinementResult:
        """Apply PRIORITIZE refinement - boost priority of matching tests."""
        result = RefinementResult(
            success=True,
            command=command,
        )

        category = command.category_filter
        keyword = command.keyword_filter or command.target

        modified_count = 0
        refined = []

        for test in tests:
            test_copy = test.copy()

            # Check if should prioritize
            should_boost = False

            if category and test.get("category", "").lower() == category.lower():
                should_boost = True

            if keyword:
                title = test.get("title", "").lower()
                if keyword.lower() in title:
                    should_boost = True

            if should_boost:
                # Boost priority
                current = test_copy.get("priority", "medium")
                priority_order = ["low", "medium", "high", "critical"]
                try:
                    idx = priority_order.index(current.lower())
                    if idx < len(priority_order) - 1:
                        test_copy["priority"] = priority_order[idx + 1]
                        modified_count += 1
                except ValueError:
                    pass

            refined.append(test_copy)

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        refined.sort(key=lambda t: priority_order.get(t.get("priority", "medium"), 2))

        result.refined_tests = refined
        result.tests_modified = modified_count

        return result

    def _apply_modify(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
    ) -> RefinementResult:
        """Apply MODIFY refinement - enhance tests based on intensity."""
        result = RefinementResult(
            success=True,
            command=command,
        )

        category = command.category_filter
        intensity = command.intensity

        modified_count = 0
        refined = []

        for test in tests:
            test_copy = test.copy()

            # Check if should modify
            should_modify = True

            if category:
                should_modify = test.get("category", "").lower() == category.lower()

            if should_modify and intensity == "strict":
                # Add additional validation steps
                steps = test_copy.get("steps", [])
                if steps and "Verify" not in steps[-1]:
                    steps.append("Verify no data corruption occurred")
                test_copy["steps"] = steps
                test_copy["_enhanced"] = True
                modified_count += 1

            refined.append(test_copy)

        result.refined_tests = refined
        result.tests_modified = modified_count

        return result

    def _apply_focus(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
    ) -> RefinementResult:
        """Apply FOCUS refinement - filter to matching category and boost."""
        # Combine prioritize and keep relevant tests
        result = self._apply_prioritize(command, tests)

        # Move focused tests to top
        category = command.category_filter
        focused = []
        others = []

        for test in result.refined_tests:
            if category and test.get("category", "").lower() == category.lower():
                focused.append(test)
            else:
                others.append(test)

        result.refined_tests = focused + others

        return result

    def _apply_expand(
        self,
        command: RefinementCommand,
        tests: List[Dict[str, Any]],
        generator_func: Optional[callable],
    ) -> RefinementResult:
        """Apply EXPAND refinement - add more tests for coverage."""
        # Essentially ADD with auto-detection of what's needed
        category = command.category_filter or self._detect_undercovered(tests)

        expand_command = RefinementCommand(
            command_type=RefinementType.ADD,
            target=category,
            category_filter=category,
            quantity=command.quantity or 5,
            original_input=command.original_input,
        )

        return self._apply_add(expand_command, tests, generator_func)

    def _detect_undercovered(self, tests: List[Dict[str, Any]]) -> str:
        """Detect which category is undercovered."""
        category_counts: Dict[str, int] = {}

        for test in tests:
            cat = test.get("category", "functional").lower()
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Find least covered category
        min_category = "security"
        min_count = float('inf')

        for category in self.CATEGORY_KEYWORDS.keys():
            count = category_counts.get(category, 0)
            if count < min_count:
                min_count = count
                min_category = category

        return min_category

    def _generate_tests_for_category(
        self,
        category: str,
        count: int,
        keyword: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Generate template tests for a category."""
        templates = {
            "security": [
                {
                    "title": "Test SQL injection prevention",
                    "description": "Verify SQL injection attacks are blocked",
                    "category": "security",
                    "priority": "critical",
                    "steps": [
                        "Enter SQL injection payload in input fields",
                        "Submit the form",
                        "Verify attack is blocked",
                    ],
                    "expected_result": "Attack prevented, appropriate error shown",
                },
                {
                    "title": "Test XSS prevention",
                    "description": "Verify XSS attacks are prevented",
                    "category": "security",
                    "priority": "critical",
                    "steps": [
                        "Enter XSS payload in input fields",
                        "Submit and reload page",
                        "Verify script is not executed",
                    ],
                    "expected_result": "Script is escaped or blocked",
                },
                {
                    "title": "Test CSRF protection",
                    "description": "Verify CSRF tokens are validated",
                    "category": "security",
                    "priority": "high",
                    "steps": [
                        "Attempt form submission without CSRF token",
                        "Attempt submission with invalid token",
                        "Verify both are rejected",
                    ],
                    "expected_result": "Invalid CSRF requests rejected",
                },
            ],
            "edge_case": [
                {
                    "title": "Test empty input handling",
                    "description": "Verify empty inputs are handled correctly",
                    "category": "edge_case",
                    "priority": "high",
                    "steps": [
                        "Leave all required fields empty",
                        "Submit the form",
                        "Verify appropriate error messages",
                    ],
                    "expected_result": "Clear validation errors shown",
                },
                {
                    "title": "Test maximum length inputs",
                    "description": "Verify very long inputs are handled",
                    "category": "edge_case",
                    "priority": "medium",
                    "steps": [
                        "Enter maximum length text in fields",
                        "Submit the form",
                        "Verify data is handled correctly",
                    ],
                    "expected_result": "Long inputs truncated or rejected gracefully",
                },
            ],
            "validation": [
                {
                    "title": "Test email format validation",
                    "description": "Verify email format is validated",
                    "category": "validation",
                    "priority": "high",
                    "steps": [
                        "Enter invalid email formats",
                        "Verify each is rejected",
                        "Enter valid email and verify acceptance",
                    ],
                    "expected_result": "Invalid emails rejected with clear message",
                },
                {
                    "title": "Test required field validation",
                    "description": "Verify required fields are enforced",
                    "category": "validation",
                    "priority": "high",
                    "steps": [
                        "Leave required fields empty",
                        "Submit the form",
                        "Verify validation messages appear",
                    ],
                    "expected_result": "Required field errors shown",
                },
            ],
            "functional": [
                {
                    "title": "Test successful flow completion",
                    "description": "Verify the happy path works correctly",
                    "category": "functional",
                    "priority": "critical",
                    "steps": [
                        "Fill all fields with valid data",
                        "Submit the form",
                        "Verify successful completion",
                    ],
                    "expected_result": "Flow completes successfully",
                },
                {
                    "title": "Test form persistence",
                    "description": "Verify form data persists on error",
                    "category": "functional",
                    "priority": "medium",
                    "steps": [
                        "Fill form with valid data",
                        "Cause a validation error",
                        "Verify entered data is preserved",
                    ],
                    "expected_result": "User data preserved after error",
                },
            ],
        }

        category_tests = templates.get(category, templates["functional"])
        return category_tests[:count]

    def _generate_explanation(self, result: RefinementResult) -> str:
        """Generate a human-readable explanation of what was done."""
        parts = []

        if result.tests_added > 0:
            parts.append(f"Added {result.tests_added} new tests")

        if result.tests_removed > 0:
            parts.append(f"Removed {result.tests_removed} tests")

        if result.tests_modified > 0:
            parts.append(f"Modified {result.tests_modified} tests")

        if not parts:
            parts.append("No changes made")

        return ". ".join(parts) + "."

    def _generate_suggestions(
        self,
        result: RefinementResult,
        original_tests: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate suggestions for further refinements."""
        suggestions = []

        # Check for missing categories
        categories_present = {t.get("category", "").lower() for t in result.refined_tests}
        important_categories = {"security", "functional", "validation"}

        for cat in important_categories:
            if cat not in categories_present:
                suggestions.append(f"Consider adding {cat} tests")

        # Check for low coverage
        if len(result.refined_tests) < 5:
            suggestions.append("Consider adding more tests for comprehensive coverage")

        # Check for priority balance
        priority_counts = {}
        for t in result.refined_tests:
            p = t.get("priority", "medium")
            priority_counts[p] = priority_counts.get(p, 0) + 1

        if priority_counts.get("critical", 0) == 0:
            suggestions.append("No critical priority tests - review if appropriate")

        return suggestions

    def get_help(self) -> str:
        """Get help text for using the refiner."""
        return """
Natural Language Test Refinement Commands:

ADD TESTS:
  - "Add more security tests"
  - "Add 5 edge case tests"
  - "Generate SQL injection tests"

REMOVE TESTS:
  - "Remove UI tests"
  - "Delete low priority tests"
  - "Skip accessibility tests"

PRIORITIZE:
  - "Prioritize security"
  - "Focus on authentication"
  - "Make validation more important"

MODIFY:
  - "Make tests stricter"
  - "Strengthen security tests"
  - "Simplify edge cases"

EXPAND:
  - "Expand security coverage"
  - "More functional tests"
  - "Increase validation coverage"

Examples:
  > "Add 3 more SQL injection tests"
  > "Remove all low priority tests"
  > "Focus on security and make it stricter"
"""


def create_refiner() -> NaturalLanguageRefiner:
    """Create a natural language refiner instance."""
    return NaturalLanguageRefiner()
