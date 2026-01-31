"""
TestAI Agent - Debug Assistant

Provides intelligent debugging suggestions and strategies
for resolving test failures.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class DebugStrategy(Enum):
    """Debugging strategies."""
    ISOLATE = "isolate"  # Isolate the failing test
    REPRODUCE = "reproduce"  # Steps to reproduce
    BINARY_SEARCH = "binary_search"  # Find regression point
    ADD_LOGGING = "add_logging"  # Add debug logging
    INSPECT_STATE = "inspect_state"  # Examine application state
    CHECK_DEPS = "check_deps"  # Verify dependencies
    REVIEW_CHANGES = "review_changes"  # Review recent changes
    COMPARE_ENVS = "compare_envs"  # Compare environments
    TIME_BASED = "time_based"  # Time-based analysis
    DATA_DRIVEN = "data_driven"  # Data-related debugging


class DebugPriority(Enum):
    """Priority levels for debug suggestions."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DebugStep:
    """A single debugging step."""
    step_id: str
    action: str
    description: str
    expected_outcome: str
    commands: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class DebugSuggestion:
    """A debugging suggestion."""
    suggestion_id: str
    strategy: DebugStrategy
    priority: DebugPriority
    title: str
    description: str
    steps: List[DebugStep]
    estimated_time_minutes: int
    success_probability: float
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class DebugPlan:
    """Complete debugging plan."""
    test_id: str
    error_summary: str
    suggestions: List[DebugSuggestion]
    recommended_order: List[str]  # suggestion IDs in recommended order
    total_estimated_time: int
    quick_wins: List[DebugSuggestion]


class DebugAssistant:
    """
    Provides intelligent debugging assistance.

    Features:
    - Strategy-based debugging
    - Step-by-step guides
    - Context-aware suggestions
    - Time estimates
    - Success probability
    """

    # Strategy templates
    STRATEGY_TEMPLATES = {
        DebugStrategy.ISOLATE: {
            "title": "Isolate the Failing Test",
            "description": "Run the test in isolation to rule out inter-test dependencies",
            "steps": [
                ("Run test alone", "Execute the test in isolation", "Determine if failure is reproducible"),
                ("Clear state", "Reset application state before test", "Ensure clean environment"),
                ("Check dependencies", "Verify no external test dependencies", "Identify coupling issues"),
            ],
            "time": 15,
            "probability": 0.7,
        },
        DebugStrategy.REPRODUCE: {
            "title": "Reproduce the Failure",
            "description": "Systematically reproduce the failure for investigation",
            "steps": [
                ("Document conditions", "Record environment and test conditions", "Create reproduction baseline"),
                ("Run multiple times", "Execute test 5-10 times", "Confirm failure consistency"),
                ("Vary conditions", "Try different browsers/environments", "Identify environment factors"),
            ],
            "time": 20,
            "probability": 0.8,
        },
        DebugStrategy.BINARY_SEARCH: {
            "title": "Binary Search for Regression",
            "description": "Use git bisect to find the commit that introduced the failure",
            "steps": [
                ("Find good commit", "Identify last known working version", "Establish baseline"),
                ("Run bisect", "Execute git bisect with test", "Narrow down culprit"),
                ("Analyze change", "Review the identified commit", "Understand root cause"),
            ],
            "time": 45,
            "probability": 0.85,
        },
        DebugStrategy.ADD_LOGGING: {
            "title": "Add Debug Logging",
            "description": "Instrument code with additional logging to trace execution",
            "steps": [
                ("Identify key points", "Find critical execution points", "Target logging locations"),
                ("Add trace logs", "Insert detailed logging statements", "Capture execution flow"),
                ("Run and analyze", "Execute test and review logs", "Identify failure point"),
            ],
            "time": 25,
            "probability": 0.75,
        },
        DebugStrategy.INSPECT_STATE: {
            "title": "Inspect Application State",
            "description": "Examine the application state at failure point",
            "steps": [
                ("Capture state", "Take screenshot or DOM snapshot", "Record visual state"),
                ("Check network", "Review network requests/responses", "Identify API issues"),
                ("Examine console", "Check browser console for errors", "Find JavaScript errors"),
            ],
            "time": 20,
            "probability": 0.7,
        },
        DebugStrategy.CHECK_DEPS: {
            "title": "Verify Dependencies",
            "description": "Check external services and dependencies",
            "steps": [
                ("List dependencies", "Identify all external services", "Map service dependencies"),
                ("Health check", "Verify each service is healthy", "Find unhealthy services"),
                ("Test connectivity", "Verify network access to services", "Identify network issues"),
            ],
            "time": 15,
            "probability": 0.65,
        },
        DebugStrategy.REVIEW_CHANGES: {
            "title": "Review Recent Changes",
            "description": "Analyze recent code changes that may have caused the failure",
            "steps": [
                ("Get recent commits", "List commits since last success", "Identify candidates"),
                ("Review diffs", "Examine changed files and lines", "Find suspicious changes"),
                ("Correlate timing", "Match failure with change timing", "Confirm causation"),
            ],
            "time": 30,
            "probability": 0.8,
        },
        DebugStrategy.COMPARE_ENVS: {
            "title": "Compare Environments",
            "description": "Compare failing vs working environment configurations",
            "steps": [
                ("Document configs", "Record both environment settings", "Create comparison baseline"),
                ("Diff configurations", "Compare settings side by side", "Find differences"),
                ("Test differences", "Apply changes one by one", "Isolate root cause"),
            ],
            "time": 35,
            "probability": 0.75,
        },
        DebugStrategy.TIME_BASED: {
            "title": "Time-Based Analysis",
            "description": "Investigate timing-related issues and race conditions",
            "steps": [
                ("Add delays", "Insert strategic waits", "Test for race conditions"),
                ("Measure timing", "Profile execution times", "Find timing bottlenecks"),
                ("Test variations", "Run at different speeds", "Identify timing sensitivity"),
            ],
            "time": 30,
            "probability": 0.6,
        },
        DebugStrategy.DATA_DRIVEN: {
            "title": "Data-Driven Analysis",
            "description": "Investigate data-related issues",
            "steps": [
                ("Capture test data", "Record input data used", "Document test data"),
                ("Validate data", "Check data against schema", "Find data issues"),
                ("Test variations", "Try different data sets", "Isolate problematic data"),
            ],
            "time": 25,
            "probability": 0.7,
        },
    }

    # Error-to-strategy mapping
    ERROR_STRATEGIES = {
        "timeout": [DebugStrategy.TIME_BASED, DebugStrategy.ADD_LOGGING, DebugStrategy.INSPECT_STATE],
        "timed out": [DebugStrategy.TIME_BASED, DebugStrategy.ADD_LOGGING, DebugStrategy.INSPECT_STATE],
        "timed": [DebugStrategy.TIME_BASED, DebugStrategy.ADD_LOGGING, DebugStrategy.INSPECT_STATE],
        "element": [DebugStrategy.INSPECT_STATE, DebugStrategy.ADD_LOGGING, DebugStrategy.COMPARE_ENVS],
        "assertion": [DebugStrategy.REVIEW_CHANGES, DebugStrategy.DATA_DRIVEN, DebugStrategy.ISOLATE],
        "network": [DebugStrategy.CHECK_DEPS, DebugStrategy.COMPARE_ENVS, DebugStrategy.ADD_LOGGING],
        "authentication": [DebugStrategy.CHECK_DEPS, DebugStrategy.COMPARE_ENVS, DebugStrategy.REVIEW_CHANGES],
        "state": [DebugStrategy.ISOLATE, DebugStrategy.INSPECT_STATE, DebugStrategy.REPRODUCE],
        "race": [DebugStrategy.TIME_BASED, DebugStrategy.ISOLATE, DebugStrategy.ADD_LOGGING],
        "data": [DebugStrategy.DATA_DRIVEN, DebugStrategy.REVIEW_CHANGES, DebugStrategy.REPRODUCE],
        "default": [DebugStrategy.REPRODUCE, DebugStrategy.ISOLATE, DebugStrategy.REVIEW_CHANGES],
    }

    def __init__(self):
        """Initialize the debug assistant."""
        self._suggestion_counter = 0
        self._step_counter = 0

    def create_debug_plan(
        self,
        test_id: str,
        error_message: str,
        failure_category: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> DebugPlan:
        """Create a comprehensive debugging plan."""
        # Determine relevant strategies
        strategies = self._select_strategies(error_message, failure_category)

        # Generate suggestions
        suggestions = []
        for strategy in strategies:
            suggestion = self._create_suggestion(strategy, error_message, context)
            suggestions.append(suggestion)

        # Sort by priority and probability
        suggestions.sort(key=lambda s: (-s.success_probability, s.estimated_time_minutes))

        # Identify quick wins
        quick_wins = [s for s in suggestions if s.estimated_time_minutes <= 20]

        # Create recommended order
        recommended_order = [s.suggestion_id for s in suggestions]

        # Calculate total time
        total_time = sum(s.estimated_time_minutes for s in suggestions)

        return DebugPlan(
            test_id=test_id,
            error_summary=error_message[:200],
            suggestions=suggestions,
            recommended_order=recommended_order,
            total_estimated_time=total_time,
            quick_wins=quick_wins,
        )

    def _select_strategies(
        self,
        error_message: str,
        failure_category: Optional[str],
    ) -> List[DebugStrategy]:
        """Select relevant debugging strategies."""
        error_lower = error_message.lower()

        # Map error keywords to strategy categories
        for keyword, strategies in self.ERROR_STRATEGIES.items():
            if keyword in error_lower:
                return strategies

        # Use category if provided
        if failure_category:
            category_lower = failure_category.lower()
            for keyword, strategies in self.ERROR_STRATEGIES.items():
                if keyword in category_lower:
                    return strategies

        return self.ERROR_STRATEGIES["default"]

    def _create_suggestion(
        self,
        strategy: DebugStrategy,
        error_message: str,
        context: Optional[Dict[str, Any]],
    ) -> DebugSuggestion:
        """Create a debugging suggestion."""
        self._suggestion_counter += 1
        template = self.STRATEGY_TEMPLATES[strategy]

        # Create steps
        steps = []
        for step_def in template["steps"]:
            self._step_counter += 1
            action, description, expected = step_def
            step = DebugStep(
                step_id=f"STEP-{self._step_counter:05d}",
                action=action,
                description=description,
                expected_outcome=expected,
                commands=self._get_commands_for_step(strategy, action),
                notes=self._get_notes_for_step(strategy, action, context),
            )
            steps.append(step)

        # Determine priority based on strategy and error
        priority = self._determine_priority(strategy, error_message)

        return DebugSuggestion(
            suggestion_id=f"DBG-{self._suggestion_counter:05d}",
            strategy=strategy,
            priority=priority,
            title=template["title"],
            description=template["description"],
            steps=steps,
            estimated_time_minutes=template["time"],
            success_probability=template["probability"],
            prerequisites=self._get_prerequisites(strategy),
        )

    def _get_commands_for_step(
        self,
        strategy: DebugStrategy,
        action: str,
    ) -> List[str]:
        """Get CLI commands for a debug step."""
        commands = {
            (DebugStrategy.ISOLATE, "Run test alone"): [
                "npm test -- --testNamePattern='<test_name>'",
                "pytest -k '<test_name>' -v",
            ],
            (DebugStrategy.BINARY_SEARCH, "Run bisect"): [
                "git bisect start",
                "git bisect bad HEAD",
                "git bisect good <last_good_commit>",
            ],
            (DebugStrategy.ADD_LOGGING, "Add trace logs"): [
                "console.log('DEBUG:', variable)",
                "print(f'DEBUG: {variable}')",
            ],
            (DebugStrategy.CHECK_DEPS, "Health check"): [
                "curl -I https://service-url/health",
                "ping service-hostname",
            ],
            (DebugStrategy.REVIEW_CHANGES, "Get recent commits"): [
                "git log --oneline -20",
                "git diff HEAD~10..HEAD",
            ],
        }

        return commands.get((strategy, action), [])

    def _get_notes_for_step(
        self,
        strategy: DebugStrategy,
        action: str,
        context: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Get helpful notes for a debug step."""
        notes = []

        if strategy == DebugStrategy.ISOLATE:
            notes.append("Ensure no tests run before this one that might affect state")

        if strategy == DebugStrategy.TIME_BASED:
            notes.append("Consider that timing issues may be environment-specific")

        if strategy == DebugStrategy.COMPARE_ENVS:
            notes.append("Document Node.js version, npm version, and OS details")

        if context:
            if context.get("flaky"):
                notes.append("This test has been flaky - consider running multiple times")
            if context.get("recent_change"):
                notes.append(f"Recent change detected: {context['recent_change']}")

        return notes

    def _determine_priority(
        self,
        strategy: DebugStrategy,
        error_message: str,
    ) -> DebugPriority:
        """Determine priority of the debug suggestion."""
        high_priority_strategies = {
            DebugStrategy.REVIEW_CHANGES,
            DebugStrategy.CHECK_DEPS,
        }

        immediate_keywords = ["critical", "security", "production", "blocking"]
        high_keywords = ["authentication", "payment", "data loss"]

        error_lower = error_message.lower()

        for keyword in immediate_keywords:
            if keyword in error_lower:
                return DebugPriority.IMMEDIATE

        for keyword in high_keywords:
            if keyword in error_lower:
                return DebugPriority.HIGH

        if strategy in high_priority_strategies:
            return DebugPriority.HIGH

        return DebugPriority.MEDIUM

    def _get_prerequisites(self, strategy: DebugStrategy) -> List[str]:
        """Get prerequisites for a debugging strategy."""
        prereqs = {
            DebugStrategy.BINARY_SEARCH: [
                "Access to git repository",
                "Ability to checkout different versions",
                "Automated test execution",
            ],
            DebugStrategy.COMPARE_ENVS: [
                "Access to both environments",
                "Permission to read configurations",
            ],
            DebugStrategy.CHECK_DEPS: [
                "List of external dependencies",
                "Network access to services",
            ],
            DebugStrategy.ADD_LOGGING: [
                "Ability to modify code",
                "Log viewing access",
            ],
        }

        return prereqs.get(strategy, [])

    def suggest_quick_fix(
        self,
        error_message: str,
        failure_category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get a quick fix suggestion."""
        quick_fixes = {
            "timeout": {
                "fix": "Increase timeout value",
                "code": "jest.setTimeout(30000); // or await page.waitFor(30000)",
                "confidence": 0.6,
            },
            "element": {
                "fix": "Add explicit wait for element",
                "code": "await page.waitForSelector('.element', {visible: true, timeout: 10000})",
                "confidence": 0.7,
            },
            "assertion": {
                "fix": "Verify expected value matches current state",
                "code": "console.log('Actual value:', actualValue); // Debug before assertion",
                "confidence": 0.5,
            },
            "network": {
                "fix": "Add retry logic for network requests",
                "code": "await retry(async () => await fetch(url), {retries: 3})",
                "confidence": 0.6,
            },
            "stale": {
                "fix": "Re-fetch element reference",
                "code": "const element = await page.$('.selector'); // Re-query element",
                "confidence": 0.75,
            },
        }

        error_lower = error_message.lower()

        for keyword, fix in quick_fixes.items():
            if keyword in error_lower:
                return fix

        return {
            "fix": "Review error message and stack trace for clues",
            "code": "// Manual investigation required",
            "confidence": 0.3,
        }

    def get_common_fixes(
        self,
        failure_category: str,
    ) -> List[Dict[str, str]]:
        """Get common fixes for a failure category."""
        fixes = {
            "timeout": [
                {"fix": "Increase timeout", "impact": "May hide performance issues"},
                {"fix": "Add explicit waits", "impact": "More reliable but slower"},
                {"fix": "Optimize test data", "impact": "Faster execution"},
            ],
            "element_not_found": [
                {"fix": "Update selector", "impact": "May need regular maintenance"},
                {"fix": "Add wait condition", "impact": "More reliable"},
                {"fix": "Use data-testid", "impact": "More stable selectors"},
            ],
            "assertion": [
                {"fix": "Update expected value", "impact": "May hide real issues"},
                {"fix": "Add tolerance", "impact": "Handles minor variations"},
                {"fix": "Fix source data", "impact": "Root cause resolution"},
            ],
            "network": [
                {"fix": "Add retry logic", "impact": "Handles transient failures"},
                {"fix": "Mock external calls", "impact": "More isolated tests"},
                {"fix": "Check service health", "impact": "Identifies infrastructure issues"},
            ],
            "race_condition": [
                {"fix": "Add synchronization", "impact": "More reliable"},
                {"fix": "Reduce parallelism", "impact": "Slower but stable"},
                {"fix": "Use atomic operations", "impact": "Proper concurrency handling"},
            ],
        }

        return fixes.get(failure_category.lower(), [
            {"fix": "Review logs", "impact": "Identify root cause"},
            {"fix": "Isolate test", "impact": "Rule out dependencies"},
        ])

    def format_plan(self, plan: DebugPlan) -> str:
        """Format debug plan as readable text."""
        lines = [
            "=" * 60,
            "  DEBUG PLAN",
            "=" * 60,
            "",
            f"  Test: {plan.test_id}",
            f"  Error: {plan.error_summary}",
            f"  Total Estimated Time: {plan.total_estimated_time} minutes",
            "",
        ]

        if plan.quick_wins:
            lines.extend([
                "-" * 60,
                "  QUICK WINS (< 20 min)",
                "-" * 60,
            ])
            for suggestion in plan.quick_wins:
                lines.append(f"  - {suggestion.title} ({suggestion.estimated_time_minutes}m)")
            lines.append("")

        lines.extend([
            "-" * 60,
            "  SUGGESTED APPROACHES",
            "-" * 60,
        ])

        for i, suggestion in enumerate(plan.suggestions, 1):
            lines.extend([
                "",
                f"  {i}. {suggestion.title}",
                f"     Strategy: {suggestion.strategy.value}",
                f"     Priority: {suggestion.priority.value}",
                f"     Time: {suggestion.estimated_time_minutes}m | Success: {suggestion.success_probability:.0%}",
                f"     {suggestion.description}",
                "",
                "     Steps:",
            ])

            for j, step in enumerate(suggestion.steps, 1):
                lines.append(f"       {j}. {step.action}")
                lines.append(f"          {step.description}")
                if step.commands:
                    lines.append(f"          Commands: {step.commands[0]}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_debug_assistant() -> DebugAssistant:
    """Create a debug assistant instance."""
    return DebugAssistant()
