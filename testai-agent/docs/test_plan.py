"""
TestAI Agent - Test Plan Generator

Generates comprehensive test plans with automatic
test case organization and prioritization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class TestPriority(Enum):
    """Test priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TestStatus(Enum):
    """Test case status."""
    DRAFT = "draft"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass
class TestCase:
    """A test case in the plan."""
    case_id: str
    name: str
    description: str
    priority: TestPriority
    status: TestStatus
    preconditions: List[str]
    steps: List[str]
    expected_results: List[str]
    tags: List[str] = field(default_factory=list)
    estimated_minutes: int = 5
    assigned_to: Optional[str] = None


@dataclass
class TestSuite:
    """A test suite grouping related tests."""
    suite_id: str
    name: str
    description: str
    test_cases: List[TestCase]
    tags: List[str] = field(default_factory=list)


@dataclass
class TestPlan:
    """A complete test plan."""
    plan_id: str
    title: str
    version: str
    overview: str
    scope: List[str]
    objectives: List[str]
    test_suites: List[TestSuite]
    schedule: Dict[str, str]
    resources: List[str]
    risks: List[str]
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "TestAI Agent"


class TestPlanGenerator:
    """
    Generates comprehensive test plans.

    Features:
    - Automatic test case organization
    - Priority-based ordering
    - Suite grouping
    - Schedule estimation
    """

    def __init__(self):
        """Initialize the test plan generator."""
        self._plan_counter = 0
        self._suite_counter = 0
        self._case_counter = 0

    def create_plan(
        self,
        title: str,
        overview: str,
        scope: List[str],
        objectives: Optional[List[str]] = None,
        version: str = "1.0",
    ) -> TestPlan:
        """Create a new test plan."""
        self._plan_counter += 1

        return TestPlan(
            plan_id=f"TP-{self._plan_counter:04d}",
            title=title,
            version=version,
            overview=overview,
            scope=scope,
            objectives=objectives or ["Verify functionality", "Ensure quality"],
            test_suites=[],
            schedule={},
            resources=[],
            risks=[],
        )

    def add_suite(
        self,
        plan: TestPlan,
        name: str,
        description: str,
        tags: Optional[List[str]] = None,
    ) -> TestSuite:
        """Add a test suite to the plan."""
        self._suite_counter += 1

        suite = TestSuite(
            suite_id=f"TS-{self._suite_counter:04d}",
            name=name,
            description=description,
            test_cases=[],
            tags=tags or [],
        )

        plan.test_suites.append(suite)
        return suite

    def add_test_case(
        self,
        suite: TestSuite,
        name: str,
        description: str,
        priority: TestPriority = TestPriority.MEDIUM,
        preconditions: Optional[List[str]] = None,
        steps: Optional[List[str]] = None,
        expected_results: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        estimated_minutes: int = 5,
    ) -> TestCase:
        """Add a test case to a suite."""
        self._case_counter += 1

        case = TestCase(
            case_id=f"TC-{self._case_counter:04d}",
            name=name,
            description=description,
            priority=priority,
            status=TestStatus.DRAFT,
            preconditions=preconditions or [],
            steps=steps or [],
            expected_results=expected_results or [],
            tags=tags or [],
            estimated_minutes=estimated_minutes,
        )

        suite.test_cases.append(case)
        return case

    def generate_from_features(
        self,
        title: str,
        features: List[Dict[str, Any]],
    ) -> TestPlan:
        """Generate a test plan from feature descriptions."""
        plan = self.create_plan(
            title=title,
            overview=f"Test plan for {title}",
            scope=[f.get("name", "Feature") for f in features],
        )

        for feature in features:
            suite = self.add_suite(
                plan=plan,
                name=f"{feature.get('name', 'Feature')} Tests",
                description=feature.get('description', ''),
            )

            # Add happy path test
            self.add_test_case(
                suite=suite,
                name=f"{feature.get('name', 'Feature')} - Happy Path",
                description=f"Verify {feature.get('name', 'feature')} works correctly",
                priority=TestPriority.HIGH,
                steps=[
                    f"Navigate to {feature.get('name', 'feature')}",
                    "Perform the main action",
                    "Verify the expected result",
                ],
                expected_results=["Operation completes successfully"],
            )

            # Add error handling test
            self.add_test_case(
                suite=suite,
                name=f"{feature.get('name', 'Feature')} - Error Handling",
                description=f"Verify {feature.get('name', 'feature')} handles errors",
                priority=TestPriority.MEDIUM,
                steps=[
                    "Provide invalid input",
                    "Verify error message is displayed",
                ],
                expected_results=["Appropriate error message shown"],
            )

            # Add edge case tests if specified
            for edge_case in feature.get('edge_cases', []):
                self.add_test_case(
                    suite=suite,
                    name=f"{feature.get('name', 'Feature')} - {edge_case}",
                    description=f"Edge case: {edge_case}",
                    priority=TestPriority.LOW,
                )

        return plan

    def prioritize_tests(self, plan: TestPlan) -> List[TestCase]:
        """Get all tests sorted by priority."""
        all_cases = []
        for suite in plan.test_suites:
            all_cases.extend(suite.test_cases)

        priority_order = {
            TestPriority.CRITICAL: 0,
            TestPriority.HIGH: 1,
            TestPriority.MEDIUM: 2,
            TestPriority.LOW: 3,
        }

        return sorted(all_cases, key=lambda c: priority_order.get(c.priority, 99))

    def estimate_duration(self, plan: TestPlan) -> Dict[str, int]:
        """Estimate total duration for the test plan."""
        total_minutes = 0
        by_priority = {p: 0 for p in TestPriority}

        for suite in plan.test_suites:
            for case in suite.test_cases:
                total_minutes += case.estimated_minutes
                by_priority[case.priority] += case.estimated_minutes

        return {
            "total_minutes": total_minutes,
            "total_hours": total_minutes / 60,
            "by_priority": {
                p.value: minutes for p, minutes in by_priority.items()
            },
        }

    def get_statistics(self, plan: TestPlan) -> Dict[str, Any]:
        """Get statistics for a test plan."""
        all_cases = []
        for suite in plan.test_suites:
            all_cases.extend(suite.test_cases)

        by_priority = {}
        by_status = {}
        by_tag = {}

        for case in all_cases:
            # Count by priority
            p = case.priority.value
            by_priority[p] = by_priority.get(p, 0) + 1

            # Count by status
            s = case.status.value
            by_status[s] = by_status.get(s, 0) + 1

            # Count by tag
            for tag in case.tags:
                by_tag[tag] = by_tag.get(tag, 0) + 1

        return {
            "total_suites": len(plan.test_suites),
            "total_cases": len(all_cases),
            "by_priority": by_priority,
            "by_status": by_status,
            "by_tag": by_tag,
        }

    def format_plan(
        self,
        plan: TestPlan,
        format: str = "markdown",
    ) -> str:
        """Format test plan as text."""
        if format == "markdown":
            return self._format_markdown(plan)
        return str(plan)

    def _format_markdown(self, plan: TestPlan) -> str:
        """Format plan as Markdown."""
        lines = [
            f"# {plan.title}",
            "",
            f"**Version:** {plan.version}",
            f"**Created:** {plan.created_at.strftime('%Y-%m-%d')}",
            f"**Author:** {plan.created_by}",
            "",
            "## Overview",
            "",
            plan.overview,
            "",
            "## Scope",
            "",
        ]

        for item in plan.scope:
            lines.append(f"- {item}")

        lines.extend([
            "",
            "## Objectives",
            "",
        ])

        for obj in plan.objectives:
            lines.append(f"- {obj}")

        # Test Suites
        for suite in plan.test_suites:
            lines.extend([
                "",
                f"## Test Suite: {suite.name}",
                "",
                suite.description,
                "",
            ])

            for case in suite.test_cases:
                lines.extend([
                    f"### {case.case_id}: {case.name}",
                    "",
                    f"**Priority:** {case.priority.value}",
                    f"**Status:** {case.status.value}",
                    f"**Estimated:** {case.estimated_minutes} minutes",
                    "",
                    case.description,
                    "",
                ])

                if case.preconditions:
                    lines.append("**Preconditions:**")
                    for pre in case.preconditions:
                        lines.append(f"- {pre}")
                    lines.append("")

                if case.steps:
                    lines.append("**Steps:**")
                    for i, step in enumerate(case.steps, 1):
                        lines.append(f"{i}. {step}")
                    lines.append("")

                if case.expected_results:
                    lines.append("**Expected Results:**")
                    for result in case.expected_results:
                        lines.append(f"- {result}")
                    lines.append("")

        # Statistics
        stats = self.get_statistics(plan)
        duration = self.estimate_duration(plan)

        lines.extend([
            "",
            "## Summary",
            "",
            f"- **Total Suites:** {stats['total_suites']}",
            f"- **Total Test Cases:** {stats['total_cases']}",
            f"- **Estimated Duration:** {duration['total_hours']:.1f} hours",
            "",
        ])

        return "\n".join(lines)


def create_test_plan_generator() -> TestPlanGenerator:
    """Create a test plan generator instance."""
    return TestPlanGenerator()
