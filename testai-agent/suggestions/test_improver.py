"""
TestAI Agent - Test Improver

Analyzes individual tests and suggests improvements to make them
more robust, maintainable, and effective.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import re


class ImprovementType(Enum):
    """Types of test improvements."""
    ADD_ASSERTION = "add_assertion"
    ADD_STEP = "add_step"
    IMPROVE_SELECTOR = "improve_selector"
    ADD_WAIT = "add_wait"
    ADD_ERROR_HANDLING = "add_error_handling"
    CLARIFY_EXPECTED = "clarify_expected"
    ADD_DATA_VARIATIONS = "add_data_variations"
    IMPROVE_PRIORITY = "improve_priority"
    ADD_TAGS = "add_tags"
    SPLIT_TEST = "split_test"
    COMBINE_TESTS = "combine_tests"


@dataclass
class TestImprovement:
    """A suggested improvement for a test."""
    improvement_type: ImprovementType
    test_id: str
    title: str
    description: str
    current_value: Optional[Any] = None
    suggested_value: Optional[Any] = None
    rationale: str = ""
    confidence: float = 0.8
    auto_applicable: bool = False


@dataclass
class ImprovedTest:
    """Result of applying improvements to a test."""
    original_test: Dict[str, Any]
    improved_test: Dict[str, Any]
    improvements_applied: List[TestImprovement]
    improvement_score: float


class TestImprover:
    """
    Analyzes individual tests and suggests specific improvements.

    This focuses on making each test better, rather than finding
    missing tests (which is the SuggestionEngine's job).
    """

    # Weak selectors that should be improved
    WEAK_SELECTORS = [
        r'^div$',
        r'^span$',
        r'^\.[a-z]+$',  # Single class selectors
        r'^\#[a-z]+$',  # Short ID selectors
        r'^xpath=//',   # XPath (fragile)
        r'^nth-child',  # Position-based
    ]

    # Strong selector patterns
    STRONG_SELECTOR_PATTERNS = [
        r'data-testid',
        r'data-test',
        r'\[aria-',
        r'\[role=',
    ]

    # Assertions that should be present
    RECOMMENDED_ASSERTIONS = {
        "login": [
            "verify user is logged in",
            "check session exists",
            "validate redirect to dashboard",
        ],
        "signup": [
            "verify account created",
            "check confirmation email",
            "validate welcome message",
        ],
        "checkout": [
            "verify order confirmation",
            "check payment processed",
            "validate receipt displayed",
        ],
        "search": [
            "verify results displayed",
            "check result count",
            "validate no error message",
        ],
        "profile": [
            "verify changes saved",
            "check success message",
            "validate updated data displayed",
        ],
    }

    # Steps that often need waits
    WAIT_REQUIRED_ACTIONS = [
        "click",
        "submit",
        "navigate",
        "load",
        "fetch",
        "save",
        "delete",
    ]

    def __init__(self):
        """Initialize the test improver."""
        self._improvements: List[TestImprovement] = []

    def analyze_test(
        self,
        test: Dict[str, Any],
        page_type: str = "generic",
    ) -> List[TestImprovement]:
        """Analyze a single test and return improvement suggestions."""
        improvements = []

        test_id = test.get("id", "unknown")

        # Check steps
        improvements.extend(self._analyze_steps(test, page_type))

        # Check expected result
        improvements.extend(self._analyze_expected_result(test, page_type))

        # Check priority
        improvements.extend(self._analyze_priority(test, page_type))

        # Check for missing assertions
        improvements.extend(self._analyze_assertions(test, page_type))

        # Check for data variations
        improvements.extend(self._analyze_data_variations(test))

        # Check test complexity
        improvements.extend(self._analyze_complexity(test))

        self._improvements.extend(improvements)
        return improvements

    def _analyze_steps(
        self,
        test: Dict[str, Any],
        page_type: str,
    ) -> List[TestImprovement]:
        """Analyze test steps for improvements."""
        improvements = []
        test_id = test.get("id", "unknown")
        steps = test.get("steps", [])

        if not steps:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.ADD_STEP,
                test_id=test_id,
                title="No Steps Defined",
                description="Test has no steps - add clear step-by-step instructions",
                rationale="Tests without steps are hard to execute and maintain",
                confidence=0.95,
            ))
            return improvements

        # Check each step
        for i, step in enumerate(steps):
            step_lower = step.lower()

            # Check for weak selectors in steps
            for weak_pattern in self.WEAK_SELECTORS:
                if re.search(weak_pattern, step_lower):
                    improvements.append(TestImprovement(
                        improvement_type=ImprovementType.IMPROVE_SELECTOR,
                        test_id=test_id,
                        title=f"Weak Selector in Step {i+1}",
                        description=f"Step '{step[:40]}...' may have a fragile selector",
                        current_value=step,
                        suggested_value=f"Use data-testid or aria-label: {step}",
                        rationale="Stable selectors like data-testid prevent test flakiness",
                        confidence=0.7,
                    ))

            # Check if waits might be needed
            for action in self.WAIT_REQUIRED_ACTIONS:
                if action in step_lower:
                    # Check if next step has a wait
                    has_wait = False
                    if i + 1 < len(steps):
                        next_step = steps[i + 1].lower()
                        if "wait" in next_step or "verify" in next_step:
                            has_wait = True

                    if not has_wait and i == len(steps) - 1:
                        # Last step with action - might need assertion
                        improvements.append(TestImprovement(
                            improvement_type=ImprovementType.ADD_WAIT,
                            test_id=test_id,
                            title=f"Consider Adding Wait After Step {i+1}",
                            description=f"After '{action}' action, consider adding a wait or assertion",
                            current_value=step,
                            rationale="Waits after async actions prevent race conditions",
                            confidence=0.6,
                        ))
                    break

        return improvements

    def _analyze_expected_result(
        self,
        test: Dict[str, Any],
        page_type: str,
    ) -> List[TestImprovement]:
        """Analyze expected result for clarity."""
        improvements = []
        test_id = test.get("id", "unknown")
        expected = test.get("expected_result", "")

        if not expected:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.CLARIFY_EXPECTED,
                test_id=test_id,
                title="No Expected Result",
                description="Test has no expected result defined",
                rationale="Clear expected results make pass/fail determination unambiguous",
                confidence=0.9,
            ))
            return improvements

        # Check for vague expected results
        vague_phrases = [
            "should work",
            "works correctly",
            "functions properly",
            "behaves as expected",
            "no errors",
        ]

        for phrase in vague_phrases:
            if phrase in expected.lower():
                improvements.append(TestImprovement(
                    improvement_type=ImprovementType.CLARIFY_EXPECTED,
                    test_id=test_id,
                    title="Vague Expected Result",
                    description=f"Expected result contains vague phrase: '{phrase}'",
                    current_value=expected,
                    suggested_value="Be specific: what exactly should appear/happen?",
                    rationale="Specific expected results are easier to verify",
                    confidence=0.75,
                ))
                break

        return improvements

    def _analyze_priority(
        self,
        test: Dict[str, Any],
        page_type: str,
    ) -> List[TestImprovement]:
        """Analyze if priority matches test importance."""
        improvements = []
        test_id = test.get("id", "unknown")
        title = test.get("title", "").lower()
        category = test.get("category", "").lower()
        priority = test.get("priority", "medium").lower()

        # Security tests should be high/critical
        if category == "security" and priority not in ["high", "critical"]:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.IMPROVE_PRIORITY,
                test_id=test_id,
                title="Security Test Priority Too Low",
                description=f"Security test has '{priority}' priority",
                current_value=priority,
                suggested_value="high or critical",
                rationale="Security tests should have high priority to catch vulnerabilities early",
                confidence=0.85,
                auto_applicable=True,
            ))

        # Login/auth tests on login page should be high priority
        if page_type == "login" and any(kw in title for kw in ["valid login", "authentication"]):
            if priority == "low":
                improvements.append(TestImprovement(
                    improvement_type=ImprovementType.IMPROVE_PRIORITY,
                    test_id=test_id,
                    title="Core Login Test Priority Low",
                    description="Core login functionality test has low priority",
                    current_value=priority,
                    suggested_value="high",
                    rationale="Core functionality tests should have higher priority",
                    confidence=0.8,
                    auto_applicable=True,
                ))

        # Payment tests should be critical
        if page_type == "checkout" and "payment" in title and priority != "critical":
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.IMPROVE_PRIORITY,
                test_id=test_id,
                title="Payment Test Should Be Critical",
                description="Payment-related test should be critical priority",
                current_value=priority,
                suggested_value="critical",
                rationale="Payment tests directly impact revenue and must always pass",
                confidence=0.9,
                auto_applicable=True,
            ))

        return improvements

    def _analyze_assertions(
        self,
        test: Dict[str, Any],
        page_type: str,
    ) -> List[TestImprovement]:
        """Check for missing assertions."""
        improvements = []
        test_id = test.get("id", "unknown")
        steps = test.get("steps", [])
        expected = test.get("expected_result", "").lower()

        # Check if test has assertion-like steps
        has_assertion = False
        assertion_keywords = ["verify", "assert", "check", "validate", "ensure", "confirm"]

        for step in steps:
            if any(kw in step.lower() for kw in assertion_keywords):
                has_assertion = True
                break

        if not has_assertion and expected:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.ADD_ASSERTION,
                test_id=test_id,
                title="No Assertion Steps",
                description="Test has expected result but no assertion steps",
                suggested_value=f"Add step: Verify {expected[:50]}",
                rationale="Explicit assertion steps make test outcomes clear",
                confidence=0.8,
            ))

        # Check for recommended assertions based on page type
        if page_type in self.RECOMMENDED_ASSERTIONS:
            for recommended in self.RECOMMENDED_ASSERTIONS[page_type]:
                # Check if any step or expected result covers this
                covered = False
                for step in steps:
                    if any(word in step.lower() for word in recommended.split()):
                        covered = True
                        break

                if not covered and any(word in expected for word in recommended.split()[:2]):
                    covered = True

                # Only suggest if relevant to test title
                title_lower = test.get("title", "").lower()
                if not covered and self._is_relevant_assertion(recommended, title_lower, page_type):
                    improvements.append(TestImprovement(
                        improvement_type=ImprovementType.ADD_ASSERTION,
                        test_id=test_id,
                        title=f"Consider Adding: {recommended}",
                        description=f"Common assertion for {page_type} tests is missing",
                        suggested_value=f"Add step: {recommended}",
                        rationale="This assertion helps validate the complete scenario",
                        confidence=0.5,
                    ))
                    break  # Only suggest one per test

        return improvements

    def _is_relevant_assertion(
        self,
        assertion: str,
        test_title: str,
        page_type: str,
    ) -> bool:
        """Check if an assertion is relevant to the test."""
        # Map assertions to test title keywords
        relevance = {
            "verify user is logged in": ["login", "valid"],
            "check session exists": ["session", "login"],
            "validate redirect to dashboard": ["login", "redirect"],
            "verify account created": ["register", "signup", "create"],
            "check confirmation email": ["email", "register"],
            "verify order confirmation": ["checkout", "order", "complete"],
            "check payment processed": ["payment", "checkout"],
            "verify results displayed": ["search", "results"],
        }

        relevant_keywords = relevance.get(assertion, [])
        return any(kw in test_title for kw in relevant_keywords)

    def _analyze_data_variations(
        self,
        test: Dict[str, Any],
    ) -> List[TestImprovement]:
        """Check if test could benefit from data variations."""
        improvements = []
        test_id = test.get("id", "unknown")
        title = test.get("title", "").lower()
        steps = test.get("steps", [])

        # Check for hardcoded-looking values in steps
        hardcoded_patterns = [
            (r'"[^"]{5,}"', "hardcoded string"),
            (r"'[^']{5,}'", "hardcoded string"),
            (r'\b\d{4,}\b', "hardcoded number"),
            (r'test@', "hardcoded test email"),
            (r'password123', "hardcoded password"),
        ]

        for step in steps:
            for pattern, pattern_name in hardcoded_patterns:
                if re.search(pattern, step, re.IGNORECASE):
                    improvements.append(TestImprovement(
                        improvement_type=ImprovementType.ADD_DATA_VARIATIONS,
                        test_id=test_id,
                        title=f"Hardcoded {pattern_name}",
                        description=f"Step contains {pattern_name}: consider parameterizing",
                        current_value=step,
                        rationale="Parameterized tests are more maintainable and can test multiple scenarios",
                        confidence=0.6,
                    ))
                    break

        return improvements

    def _analyze_complexity(
        self,
        test: Dict[str, Any],
    ) -> List[TestImprovement]:
        """Analyze test complexity for potential splitting."""
        improvements = []
        test_id = test.get("id", "unknown")
        steps = test.get("steps", [])

        # Tests with many steps might need splitting
        if len(steps) > 10:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.SPLIT_TEST,
                test_id=test_id,
                title="Consider Splitting Long Test",
                description=f"Test has {len(steps)} steps - consider breaking into smaller tests",
                current_value=len(steps),
                suggested_value="5-7 steps per test",
                rationale="Smaller tests are easier to debug and maintain",
                confidence=0.7,
            ))

        # Very short tests might be combinable
        if len(steps) < 2:
            improvements.append(TestImprovement(
                improvement_type=ImprovementType.COMBINE_TESTS,
                test_id=test_id,
                title="Very Short Test",
                description="Test has very few steps - could be combined with related tests",
                current_value=len(steps),
                rationale="Very short tests add overhead; consider combining related scenarios",
                confidence=0.5,
            ))

        return improvements

    def apply_improvement(
        self,
        test: Dict[str, Any],
        improvement: TestImprovement,
    ) -> Dict[str, Any]:
        """Apply a single improvement to a test."""
        improved = test.copy()

        if improvement.improvement_type == ImprovementType.IMPROVE_PRIORITY:
            if improvement.suggested_value:
                improved["priority"] = improvement.suggested_value

        elif improvement.improvement_type == ImprovementType.ADD_STEP:
            if improvement.suggested_value:
                steps = improved.get("steps", [])
                steps.append(improvement.suggested_value)
                improved["steps"] = steps

        elif improvement.improvement_type == ImprovementType.ADD_ASSERTION:
            if improvement.suggested_value:
                steps = improved.get("steps", [])
                steps.append(improvement.suggested_value)
                improved["steps"] = steps

        elif improvement.improvement_type == ImprovementType.CLARIFY_EXPECTED:
            if improvement.suggested_value:
                improved["expected_result"] = improvement.suggested_value

        return improved

    def apply_auto_improvements(
        self,
        test: Dict[str, Any],
        page_type: str = "generic",
    ) -> ImprovedTest:
        """Analyze and apply all auto-applicable improvements."""
        improvements = self.analyze_test(test, page_type)
        auto_applicable = [imp for imp in improvements if imp.auto_applicable]

        improved_test = test.copy()
        applied = []

        for improvement in auto_applicable:
            improved_test = self.apply_improvement(improved_test, improvement)
            applied.append(improvement)

        # Calculate improvement score
        score = len(applied) / max(len(improvements), 1) if improvements else 1.0

        return ImprovedTest(
            original_test=test,
            improved_test=improved_test,
            improvements_applied=applied,
            improvement_score=score,
        )

    def get_all_improvements(self) -> List[TestImprovement]:
        """Get all generated improvements."""
        return self._improvements

    def clear(self):
        """Clear all improvements."""
        self._improvements = []


def create_test_improver() -> TestImprover:
    """Create a test improver instance."""
    return TestImprover()
