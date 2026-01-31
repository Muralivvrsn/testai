"""
TestAI Agent - Test Generator

The core test generation engine.
Combines brain knowledge + LLM intelligence to generate comprehensive tests.

Why This Beats Humans:
1. Never forgets edge cases (brain remembers all)
2. Consistent quality every time
3. Exhaustive coverage (doesn't get tired)
4. Pattern recognition across all historical knowledge
5. Speed: 100 tests in seconds
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json


class TestCategory(Enum):
    """Categories of tests we generate."""
    HAPPY_PATH = "happy_path"
    EDGE_CASE = "edge_case"
    NEGATIVE = "negative"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    INTEGRATION = "integration"
    BOUNDARY = "boundary"
    ERROR_HANDLING = "error_handling"
    USABILITY = "usability"


class Priority(Enum):
    """Test priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TestCase:
    """A single test case."""
    id: str
    title: str
    description: str
    category: TestCategory
    priority: Priority
    steps: List[str]
    expected_result: str
    preconditions: List[str] = field(default_factory=list)
    test_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "priority": self.priority.value,
            "steps": self.steps,
            "expected_result": self.expected_result,
            "preconditions": self.preconditions,
            "test_data": self.test_data,
            "tags": self.tags,
        }

    def __str__(self) -> str:
        return f"[{self.priority.value.upper()}] {self.title}"


@dataclass
class TestSuite:
    """A collection of test cases."""
    name: str
    feature: str
    page_type: str
    tests: List[TestCase] = field(default_factory=list)
    coverage_summary: Dict[str, int] = field(default_factory=dict)

    def add_test(self, test: TestCase):
        self.tests.append(test)
        cat = test.category.value
        self.coverage_summary[cat] = self.coverage_summary.get(cat, 0) + 1

    def get_by_category(self, category: TestCategory) -> List[TestCase]:
        return [t for t in self.tests if t.category == category]

    def get_by_priority(self, priority: Priority) -> List[TestCase]:
        return [t for t in self.tests if t.priority == priority]

    def summarize(self) -> str:
        """Human-friendly summary."""
        total = len(self.tests)
        critical = len(self.get_by_priority(Priority.CRITICAL))
        high = len(self.get_by_priority(Priority.HIGH))

        return (
            f"{self.name}: {total} tests "
            f"({critical} critical, {high} high priority)\n"
            f"Coverage: {', '.join(f'{k}: {v}' for k, v in self.coverage_summary.items())}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "feature": self.feature,
            "page_type": self.page_type,
            "tests": [t.to_dict() for t in self.tests],
            "coverage_summary": self.coverage_summary,
        }


@dataclass
class GenerationResult:
    """Result of test generation."""
    suite: TestSuite
    knowledge_used: int
    confidence: float
    generation_time_ms: float
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def summarize(self) -> str:
        return (
            f"Generated {len(self.suite.tests)} tests in {self.generation_time_ms:.0f}ms. "
            f"Confidence: {self.confidence:.0%}. "
            f"Used {self.knowledge_used} knowledge chunks."
        )


# Import expert prompts
from .prompts import (
    EXPERT_QA_SYSTEM_PROMPT,
    get_feature_prompt,
    get_template_tests,
    HUMAN_QUALITY_TEMPLATES,
)

# Use the expert system prompt
GENERATOR_SYSTEM_PROMPT = EXPERT_QA_SYSTEM_PROMPT


class TestGenerator:
    """
    The main test generation engine.

    Usage:
        from brain import QABrain
        from gateway import create_router, TaskType

        brain = QABrain()
        router = create_router(api_key="sk-xxx")

        generator = TestGenerator(brain=brain, router=router)

        result = await generator.generate(
            feature="User Login",
            page_type="login",
            elements=[{"type": "input", "name": "email"}, ...]
        )

        print(result.suite.summarize())
    """

    def __init__(
        self,
        brain: Optional[Any] = None,  # QABrain
        router: Optional[Any] = None,  # ModelRouter
        max_tests_per_category: int = 10,
    ):
        """
        Initialize the generator.

        Args:
            brain: QABrain instance for knowledge retrieval
            router: ModelRouter for LLM calls
            max_tests_per_category: Limit tests per category
        """
        self.brain = brain
        self.router = router
        self.max_per_category = max_tests_per_category

    async def generate(
        self,
        feature: str,
        page_type: str,
        elements: Optional[List[Dict[str, Any]]] = None,
        focus_categories: Optional[List[TestCategory]] = None,
        context: Optional[str] = None,
    ) -> GenerationResult:
        """
        Generate a comprehensive test suite.

        Args:
            feature: Feature name (e.g., "User Login")
            page_type: Page type (e.g., "login")
            elements: Detected page elements
            focus_categories: Categories to prioritize (all if None)
            context: Additional context from user

        Returns:
            GenerationResult with test suite
        """
        import time
        start_time = time.time()

        # Query brain for relevant knowledge
        knowledge_chunks = []
        if self.brain and self.brain.is_ready:
            search_result = self.brain.search(
                query=f"Testing rules for {page_type} {feature}",
                limit=10,
            )
            knowledge_chunks = search_result.chunks

        # Build the prompt
        prompt = self._build_prompt(
            feature=feature,
            page_type=page_type,
            elements=elements,
            knowledge=knowledge_chunks,
            focus_categories=focus_categories,
            context=context,
        )

        # Call LLM (or use fallback)
        tests = []
        confidence = 0.5

        if self.router:
            from gateway.router import TaskType
            response = await self.router.route(
                task=TaskType.GENERATE_TESTS,
                prompt=prompt,
                system=GENERATOR_SYSTEM_PROMPT,
            )

            if response.finish_reason != "error":
                tests = self._parse_response(response.content)
                confidence = 0.8 if len(tests) > 5 else 0.6
        else:
            # Fallback: generate template tests
            tests = self._generate_template_tests(feature, page_type, elements)
            confidence = 0.5

        # Build the suite
        suite = TestSuite(
            name=f"{feature} Test Suite",
            feature=feature,
            page_type=page_type,
        )

        for test in tests:
            suite.add_test(test)

        generation_time = (time.time() - start_time) * 1000

        # Generate warnings and suggestions
        warnings = []
        suggestions = []

        if len(tests) < 5:
            warnings.append("Generated fewer tests than expected. Consider adding more context.")

        if not any(t.category == TestCategory.SECURITY for t in tests):
            suggestions.append("Consider adding security-focused tests.")

        if not any(t.category == TestCategory.ACCESSIBILITY for t in tests):
            suggestions.append("Accessibility tests would improve coverage.")

        return GenerationResult(
            suite=suite,
            knowledge_used=len(knowledge_chunks),
            confidence=confidence,
            generation_time_ms=generation_time,
            warnings=warnings,
            suggestions=suggestions,
        )

    def _build_prompt(
        self,
        feature: str,
        page_type: str,
        elements: Optional[List[Dict]],
        knowledge: List[Any],
        focus_categories: Optional[List[TestCategory]],
        context: Optional[str],
    ) -> str:
        """Build the generation prompt using expert QA prompt engineering."""
        # Use our expert prompt builder
        return get_feature_prompt(
            feature=feature,
            page_type=page_type,
            elements=elements,
            knowledge=knowledge,
            context=context,
        )

    def _summarize_elements(self, elements: List[Dict]) -> str:
        """Create a summary of page elements."""
        by_type = {}
        for el in elements:
            el_type = el.get("elementType") or el.get("type") or el.get("tag", "unknown")
            by_type[el_type] = by_type.get(el_type, 0) + 1

        return "\n".join(f"  - {t}: {c}" for t, c in by_type.items())

    def _parse_response(self, content: str) -> List[TestCase]:
        """Parse LLM response into test cases."""
        tests = []

        try:
            # Try to extract JSON from response
            start = content.find("[")
            end = content.rfind("]") + 1

            if start >= 0 and end > start:
                json_str = content[start:end]
                data = json.loads(json_str)

                for i, item in enumerate(data):
                    test = self._dict_to_test(item, i)
                    if test:
                        tests.append(test)

        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract tests from text
            tests = self._parse_text_tests(content)

        return tests

    def _dict_to_test(self, data: Dict, index: int) -> Optional[TestCase]:
        """Convert a dictionary to a TestCase."""
        try:
            # Map category string to enum
            cat_str = data.get("category", "happy_path").lower()
            category = TestCategory.HAPPY_PATH
            for cat in TestCategory:
                if cat.value == cat_str:
                    category = cat
                    break

            # Map priority string to enum
            pri_str = data.get("priority", "medium").lower()
            priority = Priority.MEDIUM
            for pri in Priority:
                if pri.value == pri_str:
                    priority = pri
                    break

            return TestCase(
                id=data.get("id", f"TC-{index + 1:03d}"),
                title=data.get("title", f"Test Case {index + 1}"),
                description=data.get("description", ""),
                category=category,
                priority=priority,
                steps=data.get("steps", []),
                expected_result=data.get("expected_result", ""),
                preconditions=data.get("preconditions", []),
                test_data=data.get("test_data", {}),
                tags=data.get("tags", []),
            )
        except Exception:
            return None

    def _parse_text_tests(self, content: str) -> List[TestCase]:
        """Fallback parser for non-JSON responses."""
        # Simple extraction based on patterns
        tests = []
        lines = content.split("\n")

        current_test = None
        for line in lines:
            line = line.strip()

            if line.startswith("Test:") or line.startswith("TC-"):
                if current_test:
                    tests.append(current_test)
                current_test = {
                    "id": f"TC-{len(tests) + 1:03d}",
                    "title": line.replace("Test:", "").strip(),
                    "steps": [],
                    "category": "happy_path",
                    "priority": "medium",
                }

            elif current_test and (line.startswith("-") or line.startswith("*")):
                step = line.lstrip("-* ")
                if "expect" in step.lower():
                    current_test["expected_result"] = step
                else:
                    current_test.setdefault("steps", []).append(step)

        if current_test:
            tests.append(current_test)

        return [self._dict_to_test(t, i) for i, t in enumerate(tests) if t]

    def _generate_template_tests(
        self,
        feature: str,
        page_type: str,
        elements: Optional[List[Dict]],
    ) -> List[TestCase]:
        """Generate human-quality template tests when no LLM is available."""
        # Get pre-written human-quality templates
        template_dicts = get_template_tests(page_type, feature)

        if template_dicts:
            # Convert dicts to TestCase objects
            tests = []
            for i, data in enumerate(template_dicts):
                test = self._dict_to_test(data, i)
                if test:
                    tests.append(test)
            return tests

        # Fallback to basic templates if no human-quality templates exist
        basic_templates = [
            {
                "id": "TC-001",
                "title": f"{feature}: Successful basic operation",
                "description": "Verify the core functionality works with valid input",
                "category": "happy_path",
                "priority": "critical",
                "preconditions": ["User is on the page", "All required data is available"],
                "steps": [
                    "1. Fill in all required fields with valid data",
                    "2. Click the submit/action button",
                    "3. Wait for response"
                ],
                "expected_result": "Operation completes successfully with confirmation",
                "test_data": {}
            },
            {
                "id": "TC-002",
                "title": f"{feature}: Empty required fields",
                "description": "Ensure validation catches missing required data",
                "category": "negative",
                "priority": "high",
                "preconditions": ["User is on the page"],
                "steps": [
                    "1. Leave all fields empty",
                    "2. Click the submit/action button"
                ],
                "expected_result": "Validation error messages appear for each required field",
                "test_data": {}
            },
            {
                "id": "TC-003",
                "title": f"{feature}: Script injection attempt",
                "description": "Verify input is sanitized against XSS",
                "category": "security",
                "priority": "critical",
                "preconditions": ["User is on the page"],
                "steps": [
                    "1. Enter '<script>alert(1)</script>' in a text field",
                    "2. Submit the form",
                    "3. View the data where it's displayed"
                ],
                "expected_result": "Script is escaped or removed. No alert box appears.",
                "test_data": {"malicious_input": "<script>alert(1)</script>"}
            },
        ]

        return [self._dict_to_test(t, i) for i, t in enumerate(basic_templates) if t]


# Convenience function
def create_generator(
    brain: Optional[Any] = None,
    router: Optional[Any] = None,
) -> TestGenerator:
    """Create a test generator instance."""
    return TestGenerator(brain=brain, router=router)
