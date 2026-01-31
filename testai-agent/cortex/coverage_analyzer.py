"""
TestAI Agent - Coverage Gap Analyzer

Identifies gaps in test coverage by comparing existing tests against
required testing rules and categories.

This is what makes the agent truly comprehensive - it doesn't just
generate tests, it identifies what's MISSING.

Key capabilities:
1. Rule Coverage - Which Brain rules have tests?
2. Category Coverage - Which categories are tested?
3. Edge Case Coverage - Which edge cases are covered?
4. Security Coverage - Which security tests exist?
5. Gap Prioritization - Which gaps are most critical?
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict


class GapSeverity(Enum):
    """Severity of a coverage gap."""
    CRITICAL = "critical"  # Must have test, security/compliance risk
    HIGH = "high"  # Should have test, significant risk
    MEDIUM = "medium"  # Nice to have test
    LOW = "low"  # Optional test


class CoverageCategory(Enum):
    """Test coverage categories."""
    SECURITY = "security"
    FUNCTIONAL = "functional"
    VALIDATION = "validation"
    EDGE_CASE = "edge_case"
    ERROR_HANDLING = "error_handling"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    INTEGRATION = "integration"
    UI_UX = "ui_ux"
    COMPLIANCE = "compliance"


@dataclass
class CoverageGap:
    """A gap in test coverage."""
    gap_id: str
    description: str
    severity: GapSeverity

    # What's missing
    missing_category: CoverageCategory
    missing_rule: Optional[str] = None
    missing_scenario: Optional[str] = None

    # Context
    page_type: str = ""
    affected_feature: str = ""

    # Source citation (what rule says we need this)
    source_section: str = ""
    source_rule: str = ""

    # Suggested test
    suggested_test_title: str = ""
    suggested_test_steps: List[str] = field(default_factory=list)

    # Impact
    business_impact: str = ""
    security_impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "gap_id": self.gap_id,
            "description": self.description,
            "severity": self.severity.value,
            "missing_category": self.missing_category.value,
            "missing_rule": self.missing_rule,
            "page_type": self.page_type,
            "source_section": self.source_section,
            "suggested_test_title": self.suggested_test_title,
            "suggested_test_steps": self.suggested_test_steps,
            "business_impact": self.business_impact,
            "security_impact": self.security_impact,
        }


@dataclass
class CoverageReport:
    """Complete coverage analysis report."""
    timestamp: datetime = field(default_factory=datetime.now)

    # Coverage metrics
    total_rules: int = 0
    covered_rules: int = 0
    coverage_percentage: float = 0.0

    # By category
    category_coverage: Dict[str, float] = field(default_factory=dict)

    # Gaps
    gaps: List[CoverageGap] = field(default_factory=list)
    critical_gaps: int = 0
    high_gaps: int = 0

    # Summary
    overall_health: str = ""  # "healthy", "needs_attention", "critical"

    def get_gaps_by_severity(self, severity: GapSeverity) -> List[CoverageGap]:
        """Get gaps of a specific severity."""
        return [g for g in self.gaps if g.severity == severity]

    def get_gaps_by_category(self, category: CoverageCategory) -> List[CoverageGap]:
        """Get gaps in a specific category."""
        return [g for g in self.gaps if g.missing_category == category]


class CoverageAnalyzer:
    """
    Analyzes test coverage against required rules and identifies gaps.

    This is the "completeness checker" - it ensures we're not missing
    important test cases that a human QA might think of.
    """

    # Required rules by page type (minimum testing requirements)
    REQUIRED_RULES = {
        "login": {
            "security": [
                ("sql_injection", "Test SQL injection in email/password fields", GapSeverity.CRITICAL),
                ("xss_prevention", "Test XSS prevention in inputs", GapSeverity.CRITICAL),
                ("brute_force", "Test brute force protection", GapSeverity.HIGH),
                ("session_security", "Test session handling security", GapSeverity.HIGH),
                ("password_exposure", "Test password is not logged/exposed", GapSeverity.HIGH),
                ("https_enforcement", "Test HTTPS enforcement", GapSeverity.MEDIUM),
            ],
            "functional": [
                ("valid_login", "Test successful login with valid credentials", GapSeverity.CRITICAL),
                ("invalid_login", "Test login rejection with invalid credentials", GapSeverity.CRITICAL),
                ("remember_me", "Test remember me functionality", GapSeverity.MEDIUM),
                ("password_reset", "Test password reset flow", GapSeverity.HIGH),
                ("logout", "Test logout functionality", GapSeverity.HIGH),
            ],
            "validation": [
                ("email_format", "Test email format validation", GapSeverity.HIGH),
                ("password_requirements", "Test password requirements enforcement", GapSeverity.HIGH),
                ("required_fields", "Test required field validation", GapSeverity.HIGH),
                ("error_messages", "Test error message display", GapSeverity.MEDIUM),
            ],
            "edge_case": [
                ("empty_fields", "Test empty field submission", GapSeverity.HIGH),
                ("whitespace_handling", "Test whitespace in inputs", GapSeverity.MEDIUM),
                ("special_characters", "Test special characters in inputs", GapSeverity.MEDIUM),
                ("long_input", "Test very long input values", GapSeverity.MEDIUM),
            ],
            "accessibility": [
                ("keyboard_navigation", "Test keyboard-only navigation", GapSeverity.MEDIUM),
                ("screen_reader", "Test screen reader compatibility", GapSeverity.MEDIUM),
                ("focus_indicators", "Test focus indicators", GapSeverity.LOW),
            ],
        },
        "signup": {
            "security": [
                ("sql_injection", "Test SQL injection in all fields", GapSeverity.CRITICAL),
                ("xss_prevention", "Test XSS prevention", GapSeverity.CRITICAL),
                ("duplicate_check", "Test duplicate account prevention", GapSeverity.HIGH),
                ("email_verification", "Test email verification requirement", GapSeverity.HIGH),
            ],
            "functional": [
                ("valid_signup", "Test successful registration", GapSeverity.CRITICAL),
                ("password_match", "Test password confirmation match", GapSeverity.HIGH),
                ("terms_acceptance", "Test terms acceptance requirement", GapSeverity.HIGH),
                ("confirmation_email", "Test confirmation email sent", GapSeverity.HIGH),
            ],
            "validation": [
                ("email_format", "Test email format validation", GapSeverity.HIGH),
                ("password_strength", "Test password strength requirements", GapSeverity.HIGH),
                ("username_rules", "Test username rules", GapSeverity.MEDIUM),
                ("phone_format", "Test phone number format", GapSeverity.MEDIUM),
            ],
            "edge_case": [
                ("duplicate_email", "Test duplicate email handling", GapSeverity.HIGH),
                ("case_sensitivity", "Test case sensitivity handling", GapSeverity.MEDIUM),
            ],
        },
        "checkout": {
            "security": [
                ("pci_compliance", "Test PCI compliance for card data", GapSeverity.CRITICAL),
                ("card_data_protection", "Test card data encryption", GapSeverity.CRITICAL),
                ("cvv_handling", "Test CVV not stored", GapSeverity.CRITICAL),
                ("address_validation", "Test address validation security", GapSeverity.HIGH),
            ],
            "functional": [
                ("complete_purchase", "Test complete purchase flow", GapSeverity.CRITICAL),
                ("cart_update", "Test cart update during checkout", GapSeverity.HIGH),
                ("price_calculation", "Test price calculation accuracy", GapSeverity.CRITICAL),
                ("tax_calculation", "Test tax calculation", GapSeverity.HIGH),
                ("shipping_calculation", "Test shipping cost calculation", GapSeverity.HIGH),
            ],
            "validation": [
                ("card_number_validation", "Test card number validation", GapSeverity.CRITICAL),
                ("expiry_validation", "Test expiry date validation", GapSeverity.HIGH),
                ("cvv_validation", "Test CVV validation", GapSeverity.HIGH),
                ("address_validation", "Test address field validation", GapSeverity.HIGH),
            ],
            "edge_case": [
                ("payment_failure", "Test payment failure handling", GapSeverity.CRITICAL),
                ("timeout_handling", "Test timeout handling", GapSeverity.HIGH),
                ("partial_order", "Test partial order completion", GapSeverity.MEDIUM),
            ],
            "error_handling": [
                ("card_declined", "Test card declined handling", GapSeverity.CRITICAL),
                ("network_error", "Test network error handling", GapSeverity.HIGH),
                ("inventory_error", "Test out-of-stock handling", GapSeverity.HIGH),
            ],
        },
        "search": {
            "security": [
                ("sql_injection", "Test SQL injection in search query", GapSeverity.CRITICAL),
                ("xss_prevention", "Test XSS in search results display", GapSeverity.HIGH),
            ],
            "functional": [
                ("basic_search", "Test basic search functionality", GapSeverity.CRITICAL),
                ("result_display", "Test search results display", GapSeverity.HIGH),
                ("pagination", "Test search pagination", GapSeverity.HIGH),
                ("filtering", "Test search filters", GapSeverity.HIGH),
                ("sorting", "Test search sorting", GapSeverity.MEDIUM),
            ],
            "edge_case": [
                ("empty_query", "Test empty search query", GapSeverity.HIGH),
                ("no_results", "Test no results handling", GapSeverity.HIGH),
                ("special_characters", "Test special characters in query", GapSeverity.MEDIUM),
                ("long_query", "Test very long search query", GapSeverity.MEDIUM),
            ],
            "performance": [
                ("response_time", "Test search response time", GapSeverity.MEDIUM),
                ("large_results", "Test handling large result sets", GapSeverity.MEDIUM),
            ],
        },
        "profile": {
            "security": [
                ("data_access", "Test unauthorized data access prevention", GapSeverity.CRITICAL),
                ("password_change", "Test secure password change", GapSeverity.HIGH),
                ("session_validation", "Test session validation for changes", GapSeverity.HIGH),
            ],
            "functional": [
                ("view_profile", "Test profile viewing", GapSeverity.HIGH),
                ("edit_profile", "Test profile editing", GapSeverity.HIGH),
                ("upload_avatar", "Test avatar upload", GapSeverity.MEDIUM),
                ("email_change", "Test email change with verification", GapSeverity.HIGH),
            ],
            "validation": [
                ("field_validation", "Test field validation", GapSeverity.HIGH),
                ("image_validation", "Test image upload validation", GapSeverity.MEDIUM),
            ],
        },
    }

    def __init__(self):
        """Initialize the coverage analyzer."""
        self._existing_tests: Dict[str, Set[str]] = defaultdict(set)  # page_type -> rule_ids
        self._test_categories: Dict[str, Set[str]] = defaultdict(set)  # page_type -> categories

        # Statistics
        self._stats = {
            "analyses_performed": 0,
            "gaps_identified": 0,
            "critical_gaps": 0,
        }

    def register_test(
        self,
        test_id: str,
        title: str,
        category: str,
        page_type: str,
        covered_rules: List[str] = None,
    ) -> None:
        """
        Register an existing test for coverage tracking.

        This builds the picture of what's already covered.
        """
        # Track categories covered
        self._test_categories[page_type].add(category.lower())

        # Track specific rules covered
        if covered_rules:
            for rule in covered_rules:
                self._existing_tests[page_type].add(rule.lower())

        # Auto-detect rules from title
        self._detect_covered_rules(title, page_type)

    def _detect_covered_rules(self, title: str, page_type: str) -> None:
        """Automatically detect which rules a test covers based on its title."""
        title_lower = title.lower()

        # Security rules
        if "sql" in title_lower and "injection" in title_lower:
            self._existing_tests[page_type].add("sql_injection")
        if "xss" in title_lower:
            self._existing_tests[page_type].add("xss_prevention")
        if "brute" in title_lower or "lockout" in title_lower:
            self._existing_tests[page_type].add("brute_force")

        # Functional rules
        if "valid" in title_lower and ("login" in title_lower or "credential" in title_lower):
            self._existing_tests[page_type].add("valid_login")
        if "invalid" in title_lower and ("login" in title_lower or "credential" in title_lower):
            self._existing_tests[page_type].add("invalid_login")
        if "password" in title_lower and "reset" in title_lower:
            self._existing_tests[page_type].add("password_reset")
        if "logout" in title_lower:
            self._existing_tests[page_type].add("logout")

        # Validation rules
        if "email" in title_lower and ("format" in title_lower or "valid" in title_lower):
            self._existing_tests[page_type].add("email_format")
        if "password" in title_lower and ("requirement" in title_lower or "strength" in title_lower):
            self._existing_tests[page_type].add("password_requirements")
        if "required" in title_lower and "field" in title_lower:
            self._existing_tests[page_type].add("required_fields")

        # Edge case rules
        if "empty" in title_lower:
            self._existing_tests[page_type].add("empty_fields")
        if "special" in title_lower and "character" in title_lower:
            self._existing_tests[page_type].add("special_characters")
        if "whitespace" in title_lower:
            self._existing_tests[page_type].add("whitespace_handling")

    def analyze_coverage(
        self,
        page_type: str,
        existing_tests: List[Dict[str, Any]] = None,
    ) -> CoverageReport:
        """
        Analyze test coverage for a page type and identify gaps.

        This is the main analysis function that tells you what's missing.
        """
        self._stats["analyses_performed"] += 1

        # Register existing tests if provided
        if existing_tests:
            for test in existing_tests:
                self.register_test(
                    test_id=test.get("id", ""),
                    title=test.get("title", ""),
                    category=test.get("category", "functional"),
                    page_type=page_type,
                )

        report = CoverageReport()

        # Get required rules for this page type
        required = self.REQUIRED_RULES.get(page_type.lower(), {})
        if not required:
            # Use generic rules if page type not found
            required = self._get_generic_rules()

        # Count rules and find gaps
        covered_rules = self._existing_tests.get(page_type.lower(), set())
        gaps = []

        total_rules = 0
        covered_count = 0

        for category, rules in required.items():
            for rule_id, description, severity in rules:
                total_rules += 1

                if rule_id.lower() in covered_rules:
                    covered_count += 1
                else:
                    # Found a gap
                    gap = self._create_gap(
                        rule_id=rule_id,
                        description=description,
                        severity=severity,
                        category=category,
                        page_type=page_type,
                    )
                    gaps.append(gap)
                    self._stats["gaps_identified"] += 1

                    if severity == GapSeverity.CRITICAL:
                        self._stats["critical_gaps"] += 1

        # Calculate metrics
        report.total_rules = total_rules
        report.covered_rules = covered_count
        report.coverage_percentage = (covered_count / total_rules * 100) if total_rules > 0 else 0

        # Calculate category coverage
        report.category_coverage = self._calculate_category_coverage(required, covered_rules)

        # Set gaps
        report.gaps = sorted(gaps, key=lambda g: (
            0 if g.severity == GapSeverity.CRITICAL else
            1 if g.severity == GapSeverity.HIGH else
            2 if g.severity == GapSeverity.MEDIUM else 3
        ))

        report.critical_gaps = len([g for g in gaps if g.severity == GapSeverity.CRITICAL])
        report.high_gaps = len([g for g in gaps if g.severity == GapSeverity.HIGH])

        # Determine overall health
        if report.critical_gaps > 0:
            report.overall_health = "critical"
        elif report.high_gaps > 0 or report.coverage_percentage < 60:
            report.overall_health = "needs_attention"
        else:
            report.overall_health = "healthy"

        return report

    def _create_gap(
        self,
        rule_id: str,
        description: str,
        severity: GapSeverity,
        category: str,
        page_type: str,
    ) -> CoverageGap:
        """Create a coverage gap with suggested test."""
        # Map category string to enum
        category_enum = {
            "security": CoverageCategory.SECURITY,
            "functional": CoverageCategory.FUNCTIONAL,
            "validation": CoverageCategory.VALIDATION,
            "edge_case": CoverageCategory.EDGE_CASE,
            "error_handling": CoverageCategory.ERROR_HANDLING,
            "accessibility": CoverageCategory.ACCESSIBILITY,
            "performance": CoverageCategory.PERFORMANCE,
        }.get(category.lower(), CoverageCategory.FUNCTIONAL)

        # Generate suggested test steps
        steps = self._generate_test_steps(rule_id, page_type, category)

        # Determine impacts
        business_impact = self._assess_business_impact(rule_id, category, page_type)
        security_impact = self._assess_security_impact(rule_id, category)

        return CoverageGap(
            gap_id=f"gap_{page_type}_{rule_id}",
            description=description,
            severity=severity,
            missing_category=category_enum,
            missing_rule=rule_id,
            missing_scenario=description,
            page_type=page_type,
            source_section=f"Section {self._get_section_number(page_type)}.{category}",
            source_rule=f"Rule: {rule_id}",
            suggested_test_title=f"Test {description}",
            suggested_test_steps=steps,
            business_impact=business_impact,
            security_impact=security_impact,
        )

    def _generate_test_steps(
        self,
        rule_id: str,
        page_type: str,
        category: str,
    ) -> List[str]:
        """Generate suggested test steps for a gap."""
        # Step templates by rule type
        step_templates = {
            "sql_injection": [
                f"Navigate to {page_type} page",
                "Enter SQL injection payload in input field (e.g., ' OR '1'='1)",
                "Submit the form",
                "Verify the attack is prevented",
                "Check for appropriate error handling",
            ],
            "xss_prevention": [
                f"Navigate to {page_type} page",
                "Enter XSS payload in input field (e.g., <script>alert('XSS')</script>)",
                "Submit the form",
                "Verify the script is not executed",
                "Check output is properly escaped",
            ],
            "valid_login": [
                "Navigate to login page",
                "Enter valid email address",
                "Enter correct password",
                "Click login button",
                "Verify successful login (redirect to dashboard)",
            ],
            "invalid_login": [
                "Navigate to login page",
                "Enter valid email address",
                "Enter incorrect password",
                "Click login button",
                "Verify login is rejected with appropriate error message",
            ],
            "email_format": [
                f"Navigate to {page_type} page",
                "Enter invalid email format (e.g., 'notanemail')",
                "Attempt to submit",
                "Verify validation error is shown",
                "Enter valid email and verify it's accepted",
            ],
            "empty_fields": [
                f"Navigate to {page_type} page",
                "Leave required fields empty",
                "Attempt to submit the form",
                "Verify appropriate validation messages",
                "Check form is not submitted",
            ],
            "payment_failure": [
                "Navigate to checkout page",
                "Enter product information",
                "Enter card details that will trigger decline",
                "Submit payment",
                "Verify appropriate error handling",
                "Verify user can retry with different card",
            ],
        }

        if rule_id in step_templates:
            return step_templates[rule_id]

        # Generic steps based on category
        generic = {
            "security": [
                f"Navigate to {page_type} page",
                "Identify security-sensitive operations",
                f"Test {rule_id} scenario",
                "Verify security controls are in place",
                "Check for appropriate error handling",
            ],
            "functional": [
                f"Navigate to {page_type} page",
                f"Perform {rule_id} action",
                "Verify expected behavior",
                "Check success/error feedback",
            ],
            "validation": [
                f"Navigate to {page_type} page",
                f"Test {rule_id} with invalid data",
                "Verify validation message is shown",
                "Test with valid data",
                "Verify data is accepted",
            ],
            "edge_case": [
                f"Navigate to {page_type} page",
                f"Set up {rule_id} edge case scenario",
                "Trigger the edge case",
                "Verify graceful handling",
            ],
        }

        return generic.get(category, [
            f"Navigate to {page_type} page",
            f"Test {rule_id}",
            "Verify expected behavior",
        ])

    def _assess_business_impact(
        self,
        rule_id: str,
        category: str,
        page_type: str,
    ) -> str:
        """Assess business impact of missing this test."""
        high_impact_rules = {
            "valid_login": "Users cannot access the application",
            "complete_purchase": "Revenue loss - users cannot complete purchases",
            "payment_failure": "Poor user experience leads to cart abandonment",
            "pci_compliance": "Regulatory fines and legal liability",
            "data_access": "Privacy violations and potential lawsuits",
        }

        if rule_id in high_impact_rules:
            return high_impact_rules[rule_id]

        if category == "security" and page_type in ["checkout", "payment"]:
            return "High - Security breach could result in financial loss"

        if category == "functional" and page_type in ["checkout", "login"]:
            return "High - Core functionality affecting user conversion"

        return "Medium - Quality issue affecting user experience"

    def _assess_security_impact(self, rule_id: str, category: str) -> str:
        """Assess security impact of missing this test."""
        security_impacts = {
            "sql_injection": "Critical - Could lead to data breach",
            "xss_prevention": "High - Could lead to session hijacking",
            "brute_force": "High - Account compromise risk",
            "pci_compliance": "Critical - Card data exposure",
            "data_access": "Critical - Unauthorized access to user data",
            "password_exposure": "High - Credential leakage",
        }

        if rule_id in security_impacts:
            return security_impacts[rule_id]

        if category == "security":
            return "Security vulnerability if not tested"

        return "Low security impact"

    def _calculate_category_coverage(
        self,
        required: Dict[str, List],
        covered: Set[str],
    ) -> Dict[str, float]:
        """Calculate coverage percentage by category."""
        coverage = {}

        for category, rules in required.items():
            total = len(rules)
            covered_count = sum(
                1 for rule_id, _, _ in rules
                if rule_id.lower() in covered
            )
            coverage[category] = (covered_count / total * 100) if total > 0 else 0

        return coverage

    def _get_section_number(self, page_type: str) -> str:
        """Get section number for page type."""
        sections = {
            "login": "7",
            "signup": "8",
            "checkout": "9",
            "search": "10",
            "profile": "11",
        }
        return sections.get(page_type.lower(), "1")

    def _get_generic_rules(self) -> Dict[str, List]:
        """Get generic testing rules for unknown page types."""
        return {
            "security": [
                ("input_sanitization", "Test input sanitization", GapSeverity.HIGH),
                ("xss_prevention", "Test XSS prevention", GapSeverity.HIGH),
            ],
            "functional": [
                ("basic_functionality", "Test basic functionality", GapSeverity.HIGH),
                ("error_handling", "Test error handling", GapSeverity.MEDIUM),
            ],
            "validation": [
                ("input_validation", "Test input validation", GapSeverity.MEDIUM),
            ],
        }

    def generate_gap_report(self, report: CoverageReport) -> str:
        """Generate a human-readable gap report."""
        lines = [
            "# Test Coverage Gap Analysis",
            "",
            f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            f"- **Coverage**: {report.coverage_percentage:.1f}% ({report.covered_rules}/{report.total_rules} rules)",
            f"- **Overall Health**: {report.overall_health.upper()}",
            f"- **Critical Gaps**: {report.critical_gaps}",
            f"- **High Priority Gaps**: {report.high_gaps}",
            "",
            "## Category Coverage",
            "",
        ]

        for category, coverage in sorted(report.category_coverage.items()):
            bar = "█" * int(coverage / 10) + "░" * (10 - int(coverage / 10))
            status = "✅" if coverage >= 80 else "⚠️" if coverage >= 50 else "❌"
            lines.append(f"- {category.title()}: {bar} {coverage:.0f}% {status}")

        if report.gaps:
            lines.extend([
                "",
                "## Coverage Gaps",
                "",
            ])

            # Group by severity
            for severity in [GapSeverity.CRITICAL, GapSeverity.HIGH, GapSeverity.MEDIUM, GapSeverity.LOW]:
                gaps = report.get_gaps_by_severity(severity)
                if gaps:
                    icon = "🔴" if severity == GapSeverity.CRITICAL else "🟠" if severity == GapSeverity.HIGH else "🟡" if severity == GapSeverity.MEDIUM else "🟢"
                    lines.extend([
                        f"### {icon} {severity.value.title()} Priority ({len(gaps)})",
                        "",
                    ])

                    for gap in gaps:
                        lines.extend([
                            f"**{gap.suggested_test_title}**",
                            f"- Category: {gap.missing_category.value}",
                            f"- Source: {gap.source_section}",
                            f"- Business Impact: {gap.business_impact}",
                            "",
                        ])

        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return self._stats


def create_coverage_analyzer() -> CoverageAnalyzer:
    """Create a coverage analyzer instance."""
    return CoverageAnalyzer()
