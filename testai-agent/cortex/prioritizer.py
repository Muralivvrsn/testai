"""
TestAI Agent - Smart Test Prioritization

Prioritizes test cases based on risk, not just arbitrary labels.

Key factors:
1. Security impact (highest weight)
2. User impact (how many users affected)
3. Business impact (revenue, reputation)
4. Failure probability (based on complexity)
5. Historical data (if available)

Design: European QA philosophy - thorough but pragmatic.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import re


class RiskFactor(Enum):
    """Factors that affect test priority."""
    SECURITY = "security"           # Security vulnerabilities
    DATA_LOSS = "data_loss"         # Potential data loss
    REVENUE = "revenue"             # Revenue impact
    USER_FRICTION = "user_friction" # User experience
    COMPLIANCE = "compliance"       # Legal/regulatory
    REPUTATION = "reputation"       # Brand damage
    COMPLEXITY = "complexity"       # Implementation complexity


class Priority(Enum):
    """Test priority levels."""
    CRITICAL = "critical"   # Must pass before release
    HIGH = "high"          # Should pass before release
    MEDIUM = "medium"      # Can release with known issue
    LOW = "low"            # Nice to have


@dataclass
class RiskAssessment:
    """Risk assessment for a test case."""
    security_score: float = 0.0      # 0-1
    data_loss_score: float = 0.0     # 0-1
    revenue_score: float = 0.0       # 0-1
    user_impact_score: float = 0.0   # 0-1
    compliance_score: float = 0.0    # 0-1
    complexity_score: float = 0.0    # 0-1

    @property
    def total_score(self) -> float:
        """Calculate weighted total risk score."""
        weights = {
            "security": 0.30,
            "data_loss": 0.25,
            "revenue": 0.15,
            "user_impact": 0.15,
            "compliance": 0.10,
            "complexity": 0.05,
        }
        return (
            self.security_score * weights["security"] +
            self.data_loss_score * weights["data_loss"] +
            self.revenue_score * weights["revenue"] +
            self.user_impact_score * weights["user_impact"] +
            self.compliance_score * weights["compliance"] +
            self.complexity_score * weights["complexity"]
        )

    @property
    def priority(self) -> Priority:
        """Determine priority from risk score."""
        score = self.total_score
        if score >= 0.7:
            return Priority.CRITICAL
        elif score >= 0.5:
            return Priority.HIGH
        elif score >= 0.3:
            return Priority.MEDIUM
        else:
            return Priority.LOW

    @property
    def reasoning(self) -> str:
        """Explain the priority reasoning."""
        factors = []

        if self.security_score >= 0.7:
            factors.append("high security risk")
        if self.data_loss_score >= 0.7:
            factors.append("potential data loss")
        if self.revenue_score >= 0.7:
            factors.append("revenue impact")
        if self.compliance_score >= 0.7:
            factors.append("compliance requirement")

        if not factors:
            if self.total_score >= 0.5:
                factors.append("moderate combined risk")
            else:
                factors.append("low overall risk")

        return f"Priority: {self.priority.value.upper()} due to {', '.join(factors)}"


@dataclass
class PrioritizedTest:
    """A test case with priority information."""
    original_test: Dict[str, Any]
    risk_assessment: RiskAssessment
    computed_priority: Priority
    execution_order: int = 0


class TestPrioritizer:
    """
    Prioritizes tests based on risk analysis.

    Uses multiple signals:
    - Test category (security tests are higher priority)
    - Keywords in title/description
    - Page type context (checkout > profile)
    - Test data complexity

    Usage:
        prioritizer = TestPrioritizer()

        # Prioritize a list of tests
        prioritized = prioritizer.prioritize(tests, page_type="checkout")

        # Get execution order
        for test in prioritizer.get_execution_order(prioritized):
            print(f"{test.execution_order}. {test.original_test['title']}")
    """

    # Keywords that indicate high security risk
    SECURITY_KEYWORDS = [
        "injection", "xss", "csrf", "sql", "authentication", "authorization",
        "password", "token", "session", "cookie", "bypass", "privilege",
        "escalation", "access control", "encryption", "certificate", "tls",
        "ssl", "api key", "secret", "credential", "vulnerability", "attack",
    ]

    # Keywords that indicate data loss risk
    DATA_LOSS_KEYWORDS = [
        "delete", "remove", "clear", "reset", "destroy", "drop", "truncate",
        "overwrite", "modify", "update", "save", "submit", "commit", "transfer",
        "payment", "transaction", "order", "purchase",
    ]

    # Keywords that indicate revenue impact
    REVENUE_KEYWORDS = [
        "checkout", "payment", "cart", "purchase", "order", "subscription",
        "billing", "invoice", "pricing", "discount", "coupon", "refund",
        "transaction", "credit", "debit",
    ]

    # Keywords that indicate user friction
    USER_FRICTION_KEYWORDS = [
        "login", "signup", "register", "onboarding", "navigation", "search",
        "filter", "form", "validation", "error", "message", "notification",
        "loading", "timeout", "performance",
    ]

    # Keywords that indicate compliance requirements
    COMPLIANCE_KEYWORDS = [
        "gdpr", "ccpa", "hipaa", "pci", "privacy", "consent", "opt-in",
        "opt-out", "unsubscribe", "accessibility", "wcag", "ada", "audit",
    ]

    # Page type risk multipliers
    PAGE_TYPE_RISK = {
        "checkout": 1.3,     # High risk - money involved
        "payment": 1.3,
        "login": 1.2,        # Medium-high - security
        "signup": 1.1,       # Medium - user acquisition
        "profile": 1.0,      # Normal
        "settings": 1.0,
        "search": 0.9,       # Lower - read-only
        "dashboard": 0.9,
        "form": 1.0,
    }

    def __init__(self):
        """Initialize the prioritizer."""
        pass

    def prioritize(
        self,
        tests: List[Dict[str, Any]],
        page_type: Optional[str] = None,
        context: Optional[str] = None,
    ) -> List[PrioritizedTest]:
        """
        Prioritize a list of tests.

        Args:
            tests: List of test case dictionaries
            page_type: Type of page being tested
            context: Additional context

        Returns:
            List of PrioritizedTest with risk assessments
        """
        prioritized = []

        for test in tests:
            risk = self._assess_risk(test, page_type)
            prioritized_test = PrioritizedTest(
                original_test=test,
                risk_assessment=risk,
                computed_priority=risk.priority,
            )
            prioritized.append(prioritized_test)

        # Sort by total risk score (descending)
        prioritized.sort(key=lambda t: t.risk_assessment.total_score, reverse=True)

        # Assign execution order
        for i, test in enumerate(prioritized, 1):
            test.execution_order = i

        return prioritized

    def _assess_risk(
        self,
        test: Dict[str, Any],
        page_type: Optional[str] = None,
    ) -> RiskAssessment:
        """
        Assess risk for a single test.

        Args:
            test: Test case dictionary
            page_type: Type of page

        Returns:
            RiskAssessment with scores
        """
        # Get searchable text
        title = test.get("title", "").lower()
        description = test.get("description", "").lower()
        category = test.get("category", "").lower()
        steps = " ".join(test.get("steps", [])).lower()
        all_text = f"{title} {description} {category} {steps}"

        # Calculate individual scores
        security_score = self._score_keywords(all_text, self.SECURITY_KEYWORDS)
        data_loss_score = self._score_keywords(all_text, self.DATA_LOSS_KEYWORDS)
        revenue_score = self._score_keywords(all_text, self.REVENUE_KEYWORDS)
        user_impact_score = self._score_keywords(all_text, self.USER_FRICTION_KEYWORDS)
        compliance_score = self._score_keywords(all_text, self.COMPLIANCE_KEYWORDS)

        # Category-based adjustments (strong boost for security category)
        if category == "security":
            # Security category gets high scores across multiple risk factors
            # This ensures total_score reaches HIGH/CRITICAL thresholds
            security_score = max(security_score, 1.0)  # Maximum security
            data_loss_score = max(data_loss_score, 0.8)  # Security often involves data
            compliance_score = max(compliance_score, 0.7)  # Security is compliance
        elif category == "negative":
            data_loss_score = max(data_loss_score, 0.6)
            user_impact_score = max(user_impact_score, 0.5)
        elif category == "edge_case":
            user_impact_score = max(user_impact_score, 0.5)
        elif category == "happy_path":
            # Happy path still important but lower priority
            user_impact_score = max(user_impact_score, 0.3)

        # Complexity based on steps count
        steps_count = len(test.get("steps", []))
        complexity_score = min(1.0, steps_count / 10)

        # Apply page type multiplier
        multiplier = self.PAGE_TYPE_RISK.get(page_type or "", 1.0)
        security_score *= multiplier
        data_loss_score *= multiplier
        revenue_score *= multiplier

        # Cap at 1.0
        return RiskAssessment(
            security_score=min(1.0, security_score),
            data_loss_score=min(1.0, data_loss_score),
            revenue_score=min(1.0, revenue_score),
            user_impact_score=min(1.0, user_impact_score),
            compliance_score=min(1.0, compliance_score),
            complexity_score=min(1.0, complexity_score),
        )

    def _score_keywords(self, text: str, keywords: List[str]) -> float:
        """
        Score text based on keyword matches.

        Args:
            text: Text to search
            keywords: Keywords to look for

        Returns:
            Score between 0 and 1
        """
        matches = sum(1 for kw in keywords if kw in text)
        # Diminishing returns for multiple matches
        return min(1.0, matches * 0.3)

    def get_execution_order(
        self,
        prioritized: List[PrioritizedTest],
        group_by_priority: bool = True,
    ) -> List[PrioritizedTest]:
        """
        Get tests in execution order.

        Args:
            prioritized: List of prioritized tests
            group_by_priority: If True, group by priority level first

        Returns:
            Tests in recommended execution order
        """
        if not group_by_priority:
            return prioritized

        # Group by priority
        by_priority = {
            Priority.CRITICAL: [],
            Priority.HIGH: [],
            Priority.MEDIUM: [],
            Priority.LOW: [],
        }

        for test in prioritized:
            by_priority[test.computed_priority].append(test)

        # Flatten in priority order
        result = []
        order = 1
        for priority in [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]:
            for test in by_priority[priority]:
                test.execution_order = order
                result.append(test)
                order += 1

        return result

    def get_summary(self, prioritized: List[PrioritizedTest]) -> Dict[str, Any]:
        """
        Get a summary of prioritized tests.

        Args:
            prioritized: List of prioritized tests

        Returns:
            Summary dictionary
        """
        by_priority = {}
        for test in prioritized:
            priority = test.computed_priority.value
            by_priority[priority] = by_priority.get(priority, 0) + 1

        # Find highest risk tests
        high_risk = [t for t in prioritized if t.risk_assessment.total_score >= 0.7]

        return {
            "total_tests": len(prioritized),
            "by_priority": by_priority,
            "high_risk_count": len(high_risk),
            "execution_order": [
                {
                    "order": t.execution_order,
                    "title": t.original_test.get("title"),
                    "priority": t.computed_priority.value,
                    "risk_score": round(t.risk_assessment.total_score, 2),
                }
                for t in prioritized[:10]  # Top 10
            ],
        }

    def format_prioritization(
        self,
        prioritized: List[PrioritizedTest],
        show_reasoning: bool = True,
    ) -> str:
        """
        Format prioritized tests for display.

        Args:
            prioritized: List of prioritized tests
            show_reasoning: Include reasoning

        Returns:
            Formatted string
        """
        lines = []
        lines.append("Test Execution Order (Risk-Based)")
        lines.append("=" * 40)
        lines.append("")

        current_priority = None
        for test in prioritized:
            # Priority header
            if test.computed_priority != current_priority:
                current_priority = test.computed_priority
                icon = {
                    Priority.CRITICAL: "🔴",
                    Priority.HIGH: "🟠",
                    Priority.MEDIUM: "🟡",
                    Priority.LOW: "🟢",
                }[current_priority]
                lines.append(f"\n{icon} {current_priority.value.upper()}")
                lines.append("-" * 30)

            # Test entry
            title = test.original_test.get("title", "Untitled")
            score = test.risk_assessment.total_score
            lines.append(f"{test.execution_order:2d}. {title}")
            lines.append(f"    Risk: {score:.0%}")

            if show_reasoning:
                lines.append(f"    {test.risk_assessment.reasoning}")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def prioritize_tests(
    tests: List[Dict],
    page_type: Optional[str] = None,
) -> List[Dict]:
    """
    Quick function to prioritize tests.

    Args:
        tests: List of test dictionaries
        page_type: Page type context

    Returns:
        Tests with updated priorities
    """
    prioritizer = TestPrioritizer()
    prioritized = prioritizer.prioritize(tests, page_type)

    # Update original tests with computed priority
    result = []
    for pt in prioritized:
        test = pt.original_test.copy()
        test["priority"] = pt.computed_priority.value
        test["risk_score"] = round(pt.risk_assessment.total_score, 2)
        test["execution_order"] = pt.execution_order
        result.append(test)

    return result


def get_critical_tests(tests: List[Dict]) -> List[Dict]:
    """Get only critical priority tests."""
    prioritizer = TestPrioritizer()
    prioritized = prioritizer.prioritize(tests)
    return [
        pt.original_test
        for pt in prioritized
        if pt.computed_priority == Priority.CRITICAL
    ]


if __name__ == "__main__":
    # Demo
    sample_tests = [
        {
            "id": "TC-001",
            "title": "Valid login with correct credentials",
            "category": "happy_path",
            "steps": ["Enter valid email", "Enter valid password", "Click login"],
        },
        {
            "id": "TC-002",
            "title": "SQL injection in email field",
            "category": "security",
            "steps": ["Enter ' OR '1'='1 in email", "Submit form"],
        },
        {
            "id": "TC-003",
            "title": "XSS prevention in password field",
            "category": "security",
            "steps": ["Enter <script>alert(1)</script>", "Submit"],
        },
        {
            "id": "TC-004",
            "title": "Empty form submission",
            "category": "negative",
            "steps": ["Leave all fields empty", "Click submit"],
        },
        {
            "id": "TC-005",
            "title": "Session timeout handling",
            "category": "edge_case",
            "steps": ["Login", "Wait for session timeout", "Try to navigate"],
        },
        {
            "id": "TC-006",
            "title": "CSRF token validation",
            "category": "security",
            "steps": ["Intercept request", "Remove CSRF token", "Submit"],
        },
    ]

    prioritizer = TestPrioritizer()
    prioritized = prioritizer.prioritize(sample_tests, page_type="login")
    prioritized = prioritizer.get_execution_order(prioritized)

    print(prioritizer.format_prioritization(prioritized))
    print("\n" + "=" * 40)
    print("\nSummary:")
    import json
    print(json.dumps(prioritizer.get_summary(prioritized), indent=2))
