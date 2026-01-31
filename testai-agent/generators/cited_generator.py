"""
TestAI Agent - Citation-First Test Generator

Generates test cases with explicit source citations.
Every test case traces back to a specific Brain section.

Design: Zero hallucination through mandatory citations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import json
import re


class TestCategory(Enum):
    """Test categories."""
    SECURITY = "security"
    FUNCTIONAL = "functional"
    UI = "ui"
    EDGE_CASE = "edge_case"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"


class TestPriority(Enum):
    """Test priorities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Citation:
    """A citation to a Brain section."""
    section_id: str           # e.g., "7.1"
    section_title: str        # e.g., "Email Validation"
    full_path: str            # e.g., "Section 7: Login Page > 7.1 Email Validation"
    relevance_score: float    # 0-1 how relevant to this test
    excerpt: Optional[str] = None  # Key excerpt from section

    def format_short(self) -> str:
        """Short citation format."""
        return f"[{self.section_id}]"

    def format_full(self) -> str:
        """Full citation format."""
        return f"Source: {self.full_path} ({int(self.relevance_score * 100)}% match)"


@dataclass
class CitedTestCase:
    """A test case with explicit citations."""
    id: str
    title: str
    description: str
    category: TestCategory
    priority: TestPriority
    steps: List[str]
    expected_result: str
    citations: List[Citation]
    test_data: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "priority": self.priority.value,
            "steps": self.steps,
            "expected_result": self.expected_result,
            "citations": [
                {
                    "section_id": c.section_id,
                    "section_title": c.section_title,
                    "full_path": c.full_path,
                    "relevance_score": c.relevance_score,
                }
                for c in self.citations
            ],
            "test_data": self.test_data,
            "tags": self.tags,
        }

    def format_markdown(self, show_citations: bool = True) -> str:
        """Format as Markdown."""
        lines = []

        # Header with priority badge
        priority_badges = {
            TestPriority.CRITICAL: "🔴",
            TestPriority.HIGH: "🟠",
            TestPriority.MEDIUM: "🟡",
            TestPriority.LOW: "🟢",
        }
        badge = priority_badges.get(self.priority, "")

        lines.append(f"### {badge} {self.id}: {self.title}")
        lines.append("")
        lines.append(f"**Category:** {self.category.value.title()}")
        lines.append(f"**Priority:** {self.priority.value.upper()}")
        lines.append("")
        lines.append(f"**Description:** {self.description}")
        lines.append("")

        # Steps
        lines.append("**Steps:**")
        for i, step in enumerate(self.steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        lines.append(f"**Expected Result:** {self.expected_result}")

        # Test data
        if self.test_data:
            lines.append("")
            lines.append("**Test Data:**")
            lines.append("```json")
            lines.append(json.dumps(self.test_data, indent=2))
            lines.append("```")

        # Citations
        if show_citations and self.citations:
            lines.append("")
            lines.append("**Sources:**")
            for citation in self.citations:
                lines.append(f"- {citation.format_full()}")

        return "\n".join(lines)


@dataclass
class CitedTestPlan:
    """A complete test plan with citations."""
    feature: str
    page_type: Optional[str]
    tests: List[CitedTestCase]
    all_citations: List[Citation]
    generation_context: Dict[str, Any]

    def get_by_category(self, category: TestCategory) -> List[CitedTestCase]:
        """Get tests by category."""
        return [t for t in self.tests if t.category == category]

    def get_by_priority(self, priority: TestPriority) -> List[CitedTestCase]:
        """Get tests by priority."""
        return [t for t in self.tests if t.priority == priority]

    def summary(self) -> Dict[str, Any]:
        """Get plan summary."""
        by_category = {}
        by_priority = {}

        for test in self.tests:
            cat = test.category.value
            pri = test.priority.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_priority[pri] = by_priority.get(pri, 0) + 1

        return {
            "total_tests": len(self.tests),
            "by_category": by_category,
            "by_priority": by_priority,
            "unique_sources": len(set(c.section_id for c in self.all_citations)),
        }

    def format_markdown(self) -> str:
        """Format complete plan as Markdown."""
        lines = []

        # Header
        lines.append(f"# Test Plan: {self.feature}")
        lines.append("")

        # Summary
        summary = self.summary()
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Test Cases:** {summary['total_tests']}")
        lines.append(f"- **Sources Cited:** {summary['unique_sources']}")
        lines.append("")

        # By category
        lines.append("### By Category")
        for cat, count in summary["by_category"].items():
            lines.append(f"- {cat.title()}: {count}")
        lines.append("")

        # By priority
        lines.append("### By Priority")
        priority_order = ["critical", "high", "medium", "low"]
        for pri in priority_order:
            if pri in summary["by_priority"]:
                lines.append(f"- {pri.upper()}: {summary['by_priority'][pri]}")
        lines.append("")

        # All sources
        lines.append("## Sources Cited")
        lines.append("")
        seen = set()
        for citation in self.all_citations:
            if citation.section_id not in seen:
                lines.append(f"- **[{citation.section_id}]** {citation.section_title}")
                seen.add(citation.section_id)
        lines.append("")

        # Test cases by category
        lines.append("## Test Cases")
        lines.append("")

        for category in TestCategory:
            tests = self.get_by_category(category)
            if tests:
                lines.append(f"### {category.value.replace('_', ' ').title()} Tests")
                lines.append("")
                for test in tests:
                    lines.append(test.format_markdown())
                    lines.append("")
                    lines.append("---")
                    lines.append("")

        return "\n".join(lines)


class CitedTestGenerator:
    """
    Generates test cases with mandatory citations.

    Every test case must trace to a Brain section.
    No test is generated without a source.

    Usage:
        generator = CitedTestGenerator()

        # Add knowledge chunks from Brain
        generator.add_knowledge("7.1", "Email Validation", [
            "Test valid email formats",
            "Test invalid email handling",
            "Test SQL injection in email field",
        ])

        # Generate tests
        plan = generator.generate(
            feature="Login Page",
            page_type="login",
            focus=["security", "functional"],
        )

        # Get markdown output
        print(plan.format_markdown())
    """

    def __init__(self):
        """Initialize generator."""
        self.knowledge_base: Dict[str, Dict[str, Any]] = {}
        self._test_counter = 0

    def add_knowledge(
        self,
        section_id: str,
        section_title: str,
        rules: List[str],
        parent_section: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        """
        Add knowledge from a Brain section.

        Args:
            section_id: Section identifier (e.g., "7.1")
            section_title: Section title
            rules: List of testing rules/patterns
            parent_section: Parent section name
            tags: Tags for categorization
        """
        full_path = f"Section {section_id}: {section_title}"
        if parent_section:
            full_path = f"{parent_section} > {full_path}"

        self.knowledge_base[section_id] = {
            "id": section_id,
            "title": section_title,
            "full_path": full_path,
            "rules": rules,
            "tags": tags or [],
        }

    def _next_test_id(self, prefix: str = "TC") -> str:
        """Generate next test ID."""
        self._test_counter += 1
        return f"{prefix}-{self._test_counter:03d}"

    def _create_citation(
        self,
        section_id: str,
        relevance: float = 1.0,
        excerpt: Optional[str] = None,
    ) -> Citation:
        """Create a citation from a knowledge section."""
        kb = self.knowledge_base.get(section_id, {})
        return Citation(
            section_id=section_id,
            section_title=kb.get("title", "Unknown"),
            full_path=kb.get("full_path", f"Section {section_id}"),
            relevance_score=relevance,
            excerpt=excerpt,
        )

    def _infer_category(self, rule: str, tags: List[str]) -> TestCategory:
        """Infer test category from rule text and tags."""
        rule_lower = rule.lower()

        # Security keywords
        if any(kw in rule_lower for kw in [
            "injection", "xss", "csrf", "sql", "security", "auth",
            "password", "token", "session", "bypass", "vulnerability",
        ]):
            return TestCategory.SECURITY

        # Accessibility keywords
        if any(kw in rule_lower for kw in [
            "screen reader", "aria", "wcag", "accessibility", "keyboard",
            "focus", "contrast", "alt text",
        ]):
            return TestCategory.ACCESSIBILITY

        # Performance keywords
        if any(kw in rule_lower for kw in [
            "performance", "speed", "load time", "timeout", "latency",
        ]):
            return TestCategory.PERFORMANCE

        # UI keywords
        if any(kw in rule_lower for kw in [
            "display", "layout", "responsive", "visual", "styling",
            "hover", "animation", "mobile",
        ]):
            return TestCategory.UI

        # Edge case keywords
        if any(kw in rule_lower for kw in [
            "edge case", "boundary", "empty", "null", "special character",
            "unicode", "maximum", "minimum", "overflow",
        ]):
            return TestCategory.EDGE_CASE

        # Default to functional
        return TestCategory.FUNCTIONAL

    def _infer_priority(
        self,
        category: TestCategory,
        rule: str,
        page_type: Optional[str],
    ) -> TestPriority:
        """Infer test priority from category, rule, and context."""
        rule_lower = rule.lower()

        # Security tests on auth pages are critical
        if category == TestCategory.SECURITY:
            if page_type in ["login", "signup", "checkout", "payment"]:
                return TestPriority.CRITICAL
            return TestPriority.HIGH

        # Data loss keywords are critical
        if any(kw in rule_lower for kw in [
            "delete", "data loss", "corrupt", "destroy", "payment",
        ]):
            return TestPriority.CRITICAL

        # Authentication/authorization are high priority
        if any(kw in rule_lower for kw in [
            "login", "logout", "auth", "permission", "access",
        ]):
            return TestPriority.HIGH

        # Form validation is medium
        if category == TestCategory.FUNCTIONAL:
            return TestPriority.MEDIUM

        # Edge cases and UI are lower priority
        if category in [TestCategory.EDGE_CASE, TestCategory.UI]:
            return TestPriority.LOW

        return TestPriority.MEDIUM

    def generate_from_rule(
        self,
        section_id: str,
        rule: str,
        page_type: Optional[str] = None,
        feature: Optional[str] = None,
    ) -> CitedTestCase:
        """
        Generate a single test case from a rule.

        Args:
            section_id: Source section ID
            rule: The testing rule
            page_type: Type of page being tested
            feature: Feature being tested

        Returns:
            CitedTestCase with citation
        """
        kb = self.knowledge_base.get(section_id, {})
        tags = kb.get("tags", [])

        category = self._infer_category(rule, tags)
        priority = self._infer_priority(category, rule, page_type)

        # Generate test case details from rule
        test_id = self._next_test_id()
        title = self._rule_to_title(rule)
        description = f"Verify that {rule.lower()}"
        steps = self._rule_to_steps(rule, page_type)
        expected = self._rule_to_expected(rule)

        citation = self._create_citation(section_id, relevance=1.0, excerpt=rule)

        return CitedTestCase(
            id=test_id,
            title=title,
            description=description,
            category=category,
            priority=priority,
            steps=steps,
            expected_result=expected,
            citations=[citation],
            tags=tags,
        )

    def _rule_to_title(self, rule: str) -> str:
        """Convert rule to test title."""
        # Clean up the rule for a title
        title = rule.strip()

        # Capitalize first letter
        if title:
            title = title[0].upper() + title[1:]

        # Truncate if too long
        if len(title) > 80:
            title = title[:77] + "..."

        return title

    def _rule_to_steps(self, rule: str, page_type: Optional[str]) -> List[str]:
        """Convert rule to test steps."""
        rule_lower = rule.lower()
        steps = []

        # Navigation step based on page type
        if page_type:
            steps.append(f"Navigate to the {page_type} page")

        # Infer steps from rule keywords
        if "input" in rule_lower or "enter" in rule_lower or "field" in rule_lower:
            steps.append("Locate the relevant input field")
            steps.append("Enter the test data")

        if "click" in rule_lower or "button" in rule_lower or "submit" in rule_lower:
            steps.append("Click the submit/action button")

        if "validation" in rule_lower or "error" in rule_lower:
            steps.append("Observe the system response")
            steps.append("Check for validation messages")

        if "injection" in rule_lower or "xss" in rule_lower:
            steps.append("Enter malicious payload in the input field")
            steps.append("Submit the form")
            steps.append("Verify the payload is not executed")

        # Default steps if none inferred
        if len(steps) <= 1:
            steps.extend([
                "Perform the action described in the test",
                "Observe the system behavior",
                "Verify the expected outcome",
            ])

        return steps

    def _rule_to_expected(self, rule: str) -> str:
        """Convert rule to expected result."""
        rule_lower = rule.lower()

        # Security expectations
        if "injection" in rule_lower:
            return "System should sanitize input and prevent injection attacks"
        if "xss" in rule_lower:
            return "System should escape special characters and prevent XSS"
        if "unauthorized" in rule_lower or "access" in rule_lower:
            return "System should deny unauthorized access and show appropriate error"

        # Validation expectations
        if "invalid" in rule_lower:
            return "System should display appropriate validation error message"
        if "valid" in rule_lower and "invalid" not in rule_lower:
            return "System should accept the input and proceed successfully"

        # Default
        return "System should behave as specified in the requirement"

    def generate(
        self,
        feature: str,
        page_type: Optional[str] = None,
        focus: Optional[List[str]] = None,
        max_tests: int = 50,
    ) -> CitedTestPlan:
        """
        Generate a complete test plan.

        Args:
            feature: Feature being tested
            page_type: Type of page
            focus: Categories to focus on
            max_tests: Maximum tests to generate

        Returns:
            CitedTestPlan with all tests and citations
        """
        tests = []
        all_citations = []
        self._test_counter = 0

        focus_categories = None
        if focus:
            focus_categories = {TestCategory(f) for f in focus if f in [c.value for c in TestCategory]}

        for section_id, kb in self.knowledge_base.items():
            for rule in kb.get("rules", []):
                if len(tests) >= max_tests:
                    break

                test = self.generate_from_rule(
                    section_id=section_id,
                    rule=rule,
                    page_type=page_type,
                    feature=feature,
                )

                # Filter by focus if specified
                if focus_categories and test.category not in focus_categories:
                    continue

                tests.append(test)
                all_citations.extend(test.citations)

        # Sort by priority
        priority_order = {
            TestPriority.CRITICAL: 0,
            TestPriority.HIGH: 1,
            TestPriority.MEDIUM: 2,
            TestPriority.LOW: 3,
        }
        tests.sort(key=lambda t: priority_order[t.priority])

        return CitedTestPlan(
            feature=feature,
            page_type=page_type,
            tests=tests,
            all_citations=all_citations,
            generation_context={
                "focus": focus,
                "max_tests": max_tests,
                "sections_used": list(self.knowledge_base.keys()),
            },
        )


# ─────────────────────────────────────────────────────────────────
# Pre-built Knowledge for Common Page Types
# ─────────────────────────────────────────────────────────────────

def get_login_knowledge() -> Dict[str, Dict[str, Any]]:
    """Get pre-built knowledge for login page testing."""
    return {
        "7.1": {
            "title": "Email Validation",
            "rules": [
                "Test valid email format acceptance (user@domain.com)",
                "Test invalid email format rejection (missing @, no domain)",
                "Test email with special characters",
                "Test maximum email length handling",
                "Test SQL injection in email field",
                "Test XSS in email field",
            ],
            "tags": ["validation", "security", "input"],
        },
        "7.2": {
            "title": "Password Validation",
            "rules": [
                "Test minimum password length requirement",
                "Test maximum password length handling",
                "Test password complexity requirements",
                "Test password visibility toggle",
                "Test password field masking",
                "Test copy-paste behavior in password field",
            ],
            "tags": ["validation", "security", "password"],
        },
        "7.3": {
            "title": "Authentication Security",
            "rules": [
                "Test CSRF token validation",
                "Test brute force protection after failed attempts",
                "Test account lockout mechanism",
                "Test session token generation",
                "Test secure cookie attributes",
                "Test login over HTTPS only",
            ],
            "tags": ["security", "authentication"],
        },
        "7.4": {
            "title": "Login Flow",
            "rules": [
                "Test successful login with valid credentials",
                "Test failed login with invalid password",
                "Test failed login with non-existent user",
                "Test remember me functionality",
                "Test redirect after successful login",
                "Test login button disabled during submission",
            ],
            "tags": ["functional", "flow"],
        },
        "7.5": {
            "title": "Error Handling",
            "rules": [
                "Test generic error message for security",
                "Test error message does not reveal if user exists",
                "Test network error handling",
                "Test timeout handling",
                "Test error message accessibility",
            ],
            "tags": ["error", "security", "accessibility"],
        },
    }


def create_login_generator() -> CitedTestGenerator:
    """Create a generator pre-loaded with login page knowledge."""
    generator = CitedTestGenerator()

    for section_id, data in get_login_knowledge().items():
        generator.add_knowledge(
            section_id=section_id,
            section_title=data["title"],
            rules=data["rules"],
            parent_section="Section 7: Login Page Testing",
            tags=data["tags"],
        )

    return generator


# ─────────────────────────────────────────────────────────────────
# Signup Page Knowledge
# ─────────────────────────────────────────────────────────────────

def get_signup_knowledge() -> Dict[str, Dict[str, Any]]:
    """Get pre-built knowledge for signup/registration page testing."""
    return {
        "8.1": {
            "title": "Registration Form Fields",
            "rules": [
                "Test all required fields are marked and validated",
                "Test optional fields can be left empty",
                "Test first name accepts valid characters only",
                "Test last name handles special characters (O'Brien, García)",
                "Test username uniqueness validation",
                "Test username character restrictions",
                "Test phone number format validation",
                "Test international phone number formats",
            ],
            "tags": ["validation", "form", "input"],
        },
        "8.2": {
            "title": "Email Verification",
            "rules": [
                "Test email format validation on signup",
                "Test duplicate email rejection",
                "Test email confirmation field matches",
                "Test verification email is sent",
                "Test verification link expiration",
                "Test resend verification email functionality",
            ],
            "tags": ["validation", "email", "verification"],
        },
        "8.3": {
            "title": "Password Creation",
            "rules": [
                "Test password strength indicator accuracy",
                "Test password and confirm password match",
                "Test password complexity requirements display",
                "Test weak password rejection with helpful message",
                "Test common password detection (password123, qwerty)",
                "Test password cannot contain username",
            ],
            "tags": ["validation", "security", "password"],
        },
        "8.4": {
            "title": "Terms and Consent",
            "rules": [
                "Test terms of service checkbox is required",
                "Test privacy policy link is accessible",
                "Test marketing consent is optional",
                "Test age verification for age-restricted services",
                "Test consent checkboxes are not pre-checked (GDPR)",
            ],
            "tags": ["legal", "consent", "compliance"],
        },
        "8.5": {
            "title": "Registration Security",
            "rules": [
                "Test CAPTCHA or bot protection mechanism",
                "Test rate limiting on registration attempts",
                "Test SQL injection in all form fields",
                "Test XSS prevention in name fields",
                "Test registration over HTTPS only",
                "Test no sensitive data in URL parameters",
            ],
            "tags": ["security", "protection"],
        },
        "8.6": {
            "title": "Registration Flow",
            "rules": [
                "Test successful registration creates account",
                "Test welcome email is sent after registration",
                "Test redirect to appropriate page after signup",
                "Test form data preservation on validation errors",
                "Test back button behavior during registration",
                "Test progress indicator for multi-step registration",
            ],
            "tags": ["functional", "flow", "ux"],
        },
    }


def create_signup_generator() -> CitedTestGenerator:
    """Create a generator pre-loaded with signup page knowledge."""
    generator = CitedTestGenerator()

    for section_id, data in get_signup_knowledge().items():
        generator.add_knowledge(
            section_id=section_id,
            section_title=data["title"],
            rules=data["rules"],
            parent_section="Section 8: Signup Page Testing",
            tags=data["tags"],
        )

    return generator


# ─────────────────────────────────────────────────────────────────
# Checkout Page Knowledge
# ─────────────────────────────────────────────────────────────────

def get_checkout_knowledge() -> Dict[str, Dict[str, Any]]:
    """Get pre-built knowledge for checkout/payment page testing."""
    return {
        "9.1": {
            "title": "Cart Review",
            "rules": [
                "Test cart items display correctly with images",
                "Test quantity can be modified in checkout",
                "Test item removal from cart during checkout",
                "Test cart total recalculates on changes",
                "Test out-of-stock item handling",
                "Test price change notification during checkout",
            ],
            "tags": ["cart", "display", "functional"],
        },
        "9.2": {
            "title": "Shipping Information",
            "rules": [
                "Test address autocomplete functionality",
                "Test address validation for deliverable addresses",
                "Test international address format support",
                "Test saved address selection",
                "Test new address addition during checkout",
                "Test shipping method selection and pricing",
                "Test estimated delivery date display",
            ],
            "tags": ["shipping", "address", "validation"],
        },
        "9.3": {
            "title": "Payment Processing",
            "rules": [
                "Test credit card number validation (Luhn algorithm)",
                "Test credit card type detection (Visa, Mastercard, Amex)",
                "Test expiry date validation (not expired)",
                "Test CVV length validation by card type",
                "Test payment failure error messages",
                "Test 3D Secure authentication flow",
                "Test multiple payment method support",
                "Test saved payment method selection",
            ],
            "tags": ["payment", "security", "validation"],
        },
        "9.4": {
            "title": "Payment Security",
            "rules": [
                "Test PCI DSS compliance indicators",
                "Test card data is not logged or stored insecurely",
                "Test payment form is on HTTPS",
                "Test card number masking in UI",
                "Test CVV is never stored or displayed",
                "Test fraud detection triggers appropriately",
                "Test session timeout during payment",
            ],
            "tags": ["security", "compliance", "pci"],
        },
        "9.5": {
            "title": "Discounts and Promotions",
            "rules": [
                "Test valid coupon code application",
                "Test invalid coupon code rejection with message",
                "Test expired coupon handling",
                "Test coupon removal functionality",
                "Test multiple coupon stacking rules",
                "Test percentage vs fixed discount calculation",
                "Test minimum order requirement for coupons",
            ],
            "tags": ["promotions", "pricing", "functional"],
        },
        "9.6": {
            "title": "Order Completion",
            "rules": [
                "Test order confirmation page displays",
                "Test order confirmation email is sent",
                "Test order number is generated and unique",
                "Test inventory is updated after purchase",
                "Test double-submit prevention (idempotency)",
                "Test back button after order completion",
                "Test print receipt functionality",
            ],
            "tags": ["completion", "confirmation", "flow"],
        },
        "9.7": {
            "title": "Checkout Error Handling",
            "rules": [
                "Test payment gateway timeout handling",
                "Test network error during payment",
                "Test insufficient funds handling",
                "Test card declined error message",
                "Test partial order failure handling",
                "Test recovery options after failed payment",
            ],
            "tags": ["error", "recovery", "resilience"],
        },
    }


def create_checkout_generator() -> CitedTestGenerator:
    """Create a generator pre-loaded with checkout page knowledge."""
    generator = CitedTestGenerator()

    for section_id, data in get_checkout_knowledge().items():
        generator.add_knowledge(
            section_id=section_id,
            section_title=data["title"],
            rules=data["rules"],
            parent_section="Section 9: Checkout Page Testing",
            tags=data["tags"],
        )

    return generator


# ─────────────────────────────────────────────────────────────────
# Search Page Knowledge
# ─────────────────────────────────────────────────────────────────

def get_search_knowledge() -> Dict[str, Dict[str, Any]]:
    """Get pre-built knowledge for search functionality testing."""
    return {
        "10.1": {
            "title": "Search Input",
            "rules": [
                "Test search with valid keywords returns results",
                "Test empty search handling",
                "Test search with special characters",
                "Test search with very long queries",
                "Test search input maximum length",
                "Test search placeholder text is helpful",
                "Test search icon/button is clickable",
            ],
            "tags": ["input", "validation", "functional"],
        },
        "10.2": {
            "title": "Search Results",
            "rules": [
                "Test results relevance to search query",
                "Test result count display accuracy",
                "Test no results found message",
                "Test search result pagination",
                "Test infinite scroll if implemented",
                "Test result item click navigation",
                "Test result snippet highlights search terms",
            ],
            "tags": ["results", "display", "ux"],
        },
        "10.3": {
            "title": "Search Filters",
            "rules": [
                "Test category filter functionality",
                "Test price range filter accuracy",
                "Test date range filter",
                "Test multiple filter combination",
                "Test filter count indicators",
                "Test clear all filters functionality",
                "Test filter persistence on pagination",
            ],
            "tags": ["filters", "faceted", "functional"],
        },
        "10.4": {
            "title": "Search Sorting",
            "rules": [
                "Test relevance sorting (default)",
                "Test price low to high sorting",
                "Test price high to low sorting",
                "Test date/newest first sorting",
                "Test popularity sorting",
                "Test sort persistence across pages",
            ],
            "tags": ["sorting", "ordering", "functional"],
        },
        "10.5": {
            "title": "Search Suggestions",
            "rules": [
                "Test autocomplete suggestions appear",
                "Test suggestion relevance",
                "Test keyboard navigation of suggestions",
                "Test suggestion selection on click",
                "Test recent searches display",
                "Test popular searches display",
                "Test suggestion debounce (not too frequent)",
            ],
            "tags": ["autocomplete", "suggestions", "ux"],
        },
        "10.6": {
            "title": "Search Security",
            "rules": [
                "Test SQL injection in search query",
                "Test XSS in search query",
                "Test search query sanitization",
                "Test rate limiting on search requests",
                "Test no sensitive data exposure in results",
                "Test search logs don't contain PII",
            ],
            "tags": ["security", "injection", "protection"],
        },
        "10.7": {
            "title": "Search Performance",
            "rules": [
                "Test search response time under 2 seconds",
                "Test search with high result count",
                "Test search during high traffic",
                "Test search caching effectiveness",
                "Test search index freshness",
            ],
            "tags": ["performance", "speed", "scalability"],
        },
    }


def create_search_generator() -> CitedTestGenerator:
    """Create a generator pre-loaded with search page knowledge."""
    generator = CitedTestGenerator()

    for section_id, data in get_search_knowledge().items():
        generator.add_knowledge(
            section_id=section_id,
            section_title=data["title"],
            rules=data["rules"],
            parent_section="Section 10: Search Functionality Testing",
            tags=data["tags"],
        )

    return generator


# ─────────────────────────────────────────────────────────────────
# Profile/Settings Page Knowledge
# ─────────────────────────────────────────────────────────────────

def get_profile_knowledge() -> Dict[str, Dict[str, Any]]:
    """Get pre-built knowledge for profile/account settings page testing."""
    return {
        "11.1": {
            "title": "Profile Information",
            "rules": [
                "Test profile displays current user information",
                "Test profile picture upload functionality",
                "Test profile picture size/format validation",
                "Test name update saves correctly",
                "Test bio/description character limit",
                "Test profile URL/username change",
            ],
            "tags": ["profile", "display", "update"],
        },
        "11.2": {
            "title": "Email Settings",
            "rules": [
                "Test email change requires verification",
                "Test email change sends confirmation to old email",
                "Test email change sends confirmation to new email",
                "Test email preferences save correctly",
                "Test unsubscribe links work",
            ],
            "tags": ["email", "settings", "verification"],
        },
        "11.3": {
            "title": "Password Change",
            "rules": [
                "Test current password is required for change",
                "Test new password meets complexity requirements",
                "Test password change logs out other sessions",
                "Test password change confirmation email",
                "Test forgot password link availability",
            ],
            "tags": ["password", "security", "authentication"],
        },
        "11.4": {
            "title": "Privacy Settings",
            "rules": [
                "Test profile visibility settings",
                "Test data export functionality (GDPR)",
                "Test account deletion request",
                "Test activity history visibility",
                "Test connected apps/services management",
                "Test two-factor authentication toggle",
            ],
            "tags": ["privacy", "gdpr", "security"],
        },
        "11.5": {
            "title": "Notification Preferences",
            "rules": [
                "Test email notification toggles",
                "Test push notification toggles",
                "Test SMS notification toggles",
                "Test notification frequency settings",
                "Test quiet hours/do not disturb",
            ],
            "tags": ["notifications", "preferences", "settings"],
        },
    }


def create_profile_generator() -> CitedTestGenerator:
    """Create a generator pre-loaded with profile page knowledge."""
    generator = CitedTestGenerator()

    for section_id, data in get_profile_knowledge().items():
        generator.add_knowledge(
            section_id=section_id,
            section_title=data["title"],
            rules=data["rules"],
            parent_section="Section 11: Profile Page Testing",
            tags=data["tags"],
        )

    return generator


# ─────────────────────────────────────────────────────────────────
# Factory Function
# ─────────────────────────────────────────────────────────────────

def create_generator_for_page_type(page_type: str) -> CitedTestGenerator:
    """
    Factory function to create appropriate generator for page type.

    Args:
        page_type: Type of page (login, signup, checkout, search, profile)

    Returns:
        CitedTestGenerator with appropriate knowledge loaded
    """
    generators = {
        "login": create_login_generator,
        "signin": create_login_generator,
        "signup": create_signup_generator,
        "register": create_signup_generator,
        "registration": create_signup_generator,
        "checkout": create_checkout_generator,
        "payment": create_checkout_generator,
        "cart": create_checkout_generator,
        "search": create_search_generator,
        "find": create_search_generator,
        "profile": create_profile_generator,
        "settings": create_profile_generator,
        "account": create_profile_generator,
    }

    creator = generators.get(page_type.lower())
    if creator:
        return creator()

    # Return generic generator for unknown page types
    generator = CitedTestGenerator()
    generator.add_knowledge(
        "1.1", "Input Validation",
        [
            "Test required field validation",
            "Test maximum length handling",
            "Test special character handling",
            "Test SQL injection prevention",
            "Test XSS prevention",
        ],
        tags=["validation", "security"],
    )
    generator.add_knowledge(
        "2.1", "Form Submission",
        [
            "Test successful form submission",
            "Test submission with missing fields",
            "Test duplicate submission prevention",
            "Test form reset functionality",
        ],
        tags=["functional", "form"],
    )
    generator.add_knowledge(
        "3.1", "Error Handling",
        [
            "Test error message display",
            "Test error recovery options",
            "Test network error handling",
            "Test timeout handling",
        ],
        tags=["error", "ux"],
    )
    return generator


if __name__ == "__main__":
    # Demo
    generator = create_login_generator()

    plan = generator.generate(
        feature="Login Page",
        page_type="login",
        focus=["security", "functional"],
        max_tests=10,
    )

    print(plan.format_markdown())

    print("\n" + "=" * 50)
    print("\nSummary:")
    import json
    print(json.dumps(plan.summary(), indent=2))
