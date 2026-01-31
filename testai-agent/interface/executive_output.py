"""
TestAI Agent - Executive-Ready Output Formatter

Formats test plans and reports for different audiences:
- Executives: High-level summary, risk assessment, ship decision
- Product Managers: Feature coverage, user impact, priorities
- Engineering: Technical details, edge cases, implementation notes
- QA Team: Full test cases, step-by-step, all details

Design: European minimal - clean, scannable, professional.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import json


class Audience(Enum):
    """Target audience for the output."""
    EXECUTIVE = "executive"
    PRODUCT = "product"
    ENGINEERING = "engineering"
    QA = "qa"
    ALL = "all"  # Full details for everyone


class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"  # Ship blocker
    HIGH = "high"          # Should fix before release
    MEDIUM = "medium"      # Can release with known issue
    LOW = "low"            # Nice to fix


class ShipDecision(Enum):
    """Overall ship recommendation."""
    GO = "go"              # Safe to ship
    CAUTION = "caution"    # Ship with monitoring
    NO_GO = "no_go"        # Do not ship


@dataclass
class TestSummary:
    """Summary of test coverage."""
    total_tests: int
    critical_tests: int
    high_priority: int
    medium_priority: int
    low_priority: int
    security_tests: int
    accessibility_tests: int
    edge_case_tests: int
    functional_tests: int

    @property
    def security_coverage_percent(self) -> float:
        """What percentage are security tests."""
        return (self.security_tests / self.total_tests * 100) if self.total_tests > 0 else 0

    @property
    def critical_ratio(self) -> float:
        """Ratio of critical tests to total."""
        return (self.critical_tests / self.total_tests) if self.total_tests > 0 else 0


@dataclass
class RiskAssessment:
    """Risk assessment for the feature."""
    overall_level: RiskLevel
    ship_decision: ShipDecision
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add_blocker(self, issue: str):
        """Add a ship blocker."""
        self.blockers.append(issue)
        self.overall_level = RiskLevel.CRITICAL
        self.ship_decision = ShipDecision.NO_GO

    def add_warning(self, issue: str):
        """Add a warning."""
        self.warnings.append(issue)
        if self.overall_level not in [RiskLevel.CRITICAL]:
            self.overall_level = RiskLevel.HIGH
            self.ship_decision = ShipDecision.CAUTION


@dataclass
class Citation:
    """Source citation for traceability."""
    section: str
    confidence: float
    excerpt: Optional[str] = None


class ExecutiveOutputFormatter:
    """
    Formats output for executive consumption.

    Key principles:
    1. Lead with the decision (GO/NO-GO)
    2. Show risk clearly
    3. Summarize, don't overwhelm
    4. Make action items clear
    5. Professional, scannable format

    Usage:
        formatter = ExecutiveOutputFormatter()

        # Format test plan
        output = formatter.format_test_plan(
            tests=tests,
            feature="Login Page",
            audience=Audience.EXECUTIVE,
        )

        print(output)
    """

    # ─────────────────────────────────────────────────────────────
    # Color/Style Constants (ANSI)
    # ─────────────────────────────────────────────────────────────

    # European muted palette
    COLORS = {
        "slate": "\033[38;5;67m",      # Muted blue - headers
        "sage": "\033[38;5;108m",       # Muted green - success
        "coral": "\033[38;5;174m",      # Muted red - warnings
        "warm": "\033[38;5;180m",       # Muted amber - caution
        "muted": "\033[38;5;245m",      # Gray - secondary
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
    }

    ICONS = {
        "go": "✅",
        "caution": "⚠️",
        "no_go": "🛑",
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "security": "🔒",
        "accessibility": "♿",
        "check": "✓",
        "cross": "✗",
        "thinking": "💭",
        "source": "📚",
        "risk": "⚡",
        "action": "→",
    }

    def __init__(self, use_color: bool = True, use_icons: bool = True):
        """
        Initialize the formatter.

        Args:
            use_color: Use ANSI colors
            use_icons: Use emoji icons
        """
        self.use_color = use_color
        self.use_icons = use_icons

    def _color(self, name: str, text: str) -> str:
        """Apply color to text."""
        if not self.use_color:
            return text
        color = self.COLORS.get(name, "")
        reset = self.COLORS["reset"]
        return f"{color}{text}{reset}"

    def _icon(self, name: str) -> str:
        """Get icon if enabled."""
        if not self.use_icons:
            return ""
        return self.ICONS.get(name, "")

    # ─────────────────────────────────────────────────────────────
    # Main Formatting Methods
    # ─────────────────────────────────────────────────────────────

    def format_test_plan(
        self,
        tests: List[Dict[str, Any]],
        feature: str,
        audience: Audience = Audience.ALL,
        risk_assessment: Optional[RiskAssessment] = None,
        citations: Optional[List[Citation]] = None,
    ) -> str:
        """
        Format a complete test plan.

        Args:
            tests: List of test case dictionaries
            feature: Feature name
            audience: Target audience
            risk_assessment: Risk assessment (generated if not provided)
            citations: Source citations

        Returns:
            Formatted test plan string
        """
        # Generate summary
        summary = self._create_summary(tests)

        # Generate risk assessment if not provided
        if not risk_assessment:
            risk_assessment = self._assess_risk(tests, summary)

        # Build output based on audience
        if audience == Audience.EXECUTIVE:
            return self._format_executive(feature, summary, risk_assessment, citations)
        elif audience == Audience.PRODUCT:
            return self._format_product(feature, tests, summary, risk_assessment)
        elif audience == Audience.ENGINEERING:
            return self._format_engineering(feature, tests, summary, citations)
        elif audience == Audience.QA:
            return self._format_qa(feature, tests, summary, risk_assessment, citations)
        else:
            return self._format_full(feature, tests, summary, risk_assessment, citations)

    def _create_summary(self, tests: List[Dict[str, Any]]) -> TestSummary:
        """Create a summary from test list."""
        total = len(tests)
        critical = sum(1 for t in tests if t.get("priority") == "critical")
        high = sum(1 for t in tests if t.get("priority") == "high")
        medium = sum(1 for t in tests if t.get("priority") == "medium")
        low = sum(1 for t in tests if t.get("priority") == "low")

        security = sum(1 for t in tests if t.get("category") == "security")
        accessibility = sum(1 for t in tests if t.get("category") == "accessibility")
        edge_cases = sum(1 for t in tests if t.get("category") == "edge_case")
        functional = sum(1 for t in tests if t.get("category") in ["happy_path", "functional", "negative"])

        return TestSummary(
            total_tests=total,
            critical_tests=critical,
            high_priority=high,
            medium_priority=medium,
            low_priority=low,
            security_tests=security,
            accessibility_tests=accessibility,
            edge_case_tests=edge_cases,
            functional_tests=functional,
        )

    def _assess_risk(self, tests: List[Dict[str, Any]], summary: TestSummary) -> RiskAssessment:
        """Generate risk assessment from tests."""
        blockers = []
        warnings = []
        notes = []

        # Check for critical issues
        if summary.critical_tests > 0:
            blockers.append(f"{summary.critical_tests} critical test(s) must pass before release")

        # Check security coverage
        if summary.security_tests == 0 and summary.total_tests > 0:
            warnings.append("No security tests included - recommend adding security coverage")
        elif summary.security_coverage_percent < 10 and summary.total_tests > 5:
            warnings.append(f"Security coverage is low ({summary.security_coverage_percent:.0f}%)")

        # Check accessibility
        if summary.accessibility_tests == 0:
            notes.append("Consider adding accessibility tests for WCAG compliance")

        # Determine overall risk and ship decision
        if blockers:
            level = RiskLevel.CRITICAL
            decision = ShipDecision.NO_GO
        elif warnings:
            level = RiskLevel.HIGH
            decision = ShipDecision.CAUTION
        elif summary.critical_ratio > 0.3:
            level = RiskLevel.MEDIUM
            decision = ShipDecision.CAUTION
        else:
            level = RiskLevel.LOW
            decision = ShipDecision.GO

        return RiskAssessment(
            overall_level=level,
            ship_decision=decision,
            blockers=blockers,
            warnings=warnings,
            notes=notes,
        )

    # ─────────────────────────────────────────────────────────────
    # Audience-Specific Formatting
    # ─────────────────────────────────────────────────────────────

    def _format_executive(
        self,
        feature: str,
        summary: TestSummary,
        risk: RiskAssessment,
        citations: Optional[List[Citation]],
    ) -> str:
        """Format for executive audience - high level only."""
        lines = []

        # Header
        lines.append(self._color("slate", "═" * 60))
        lines.append(self._color("bold", f"  TEST PLAN: {feature.upper()}"))
        lines.append(self._color("slate", "═" * 60))
        lines.append("")

        # Ship Decision - THE MOST IMPORTANT THING
        decision_icon = self._icon(risk.ship_decision.value)
        decision_color = {
            ShipDecision.GO: "sage",
            ShipDecision.CAUTION: "warm",
            ShipDecision.NO_GO: "coral",
        }[risk.ship_decision]

        lines.append(self._color("bold", "SHIP DECISION"))
        lines.append(self._color(decision_color, f"  {decision_icon} {risk.ship_decision.value.upper().replace('_', ' ')}"))
        lines.append("")

        # Risk Level
        risk_icon = self._icon(risk.overall_level.value)
        lines.append(f"Risk Level: {risk_icon} {risk.overall_level.value.upper()}")
        lines.append("")

        # Quick Stats
        lines.append("Coverage Summary:")
        lines.append(f"  • {summary.total_tests} total tests planned")
        lines.append(f"  • {summary.critical_tests} critical, {summary.high_priority} high priority")
        lines.append(f"  • {summary.security_tests} security tests ({summary.security_coverage_percent:.0f}% coverage)")
        lines.append("")

        # Blockers (if any)
        if risk.blockers:
            lines.append(self._color("coral", "BLOCKERS:"))
            for blocker in risk.blockers:
                lines.append(f"  {self._icon('cross')} {blocker}")
            lines.append("")

        # Warnings (if any)
        if risk.warnings:
            lines.append(self._color("warm", "WARNINGS:"))
            for warning in risk.warnings:
                lines.append(f"  {self._icon('caution')} {warning}")
            lines.append("")

        # Action Items
        lines.append("Recommended Actions:")
        if risk.ship_decision == ShipDecision.NO_GO:
            lines.append(f"  {self._icon('action')} Resolve blockers before release")
            lines.append(f"  {self._icon('action')} Execute critical test cases")
        elif risk.ship_decision == ShipDecision.CAUTION:
            lines.append(f"  {self._icon('action')} Address warnings if possible")
            lines.append(f"  {self._icon('action')} Monitor closely post-release")
        else:
            lines.append(f"  {self._icon('action')} Execute test plan")
            lines.append(f"  {self._icon('action')} Proceed with release")

        lines.append("")
        lines.append(self._color("slate", "═" * 60))

        return "\n".join(lines)

    def _format_product(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        summary: TestSummary,
        risk: RiskAssessment,
    ) -> str:
        """Format for product managers - feature/user focused."""
        lines = []

        lines.append(self._color("slate", f"─── Test Plan: {feature} ───"))
        lines.append("")

        # User Impact Summary
        lines.append(self._color("bold", "User Impact"))
        happy_path = sum(1 for t in tests if t.get("category") == "happy_path")
        negative = sum(1 for t in tests if t.get("category") == "negative")
        edge = sum(1 for t in tests if t.get("category") == "edge_case")

        lines.append(f"  Happy path scenarios: {happy_path}")
        lines.append(f"  Error handling scenarios: {negative}")
        lines.append(f"  Edge cases covered: {edge}")
        lines.append("")

        # Feature Coverage
        lines.append(self._color("bold", "Feature Coverage"))
        categories = {}
        for test in tests:
            cat = test.get("category", "other")
            categories[cat] = categories.get(cat, 0) + 1

        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 10)
            lines.append(f"  {cat.replace('_', ' ').title():20} {bar} {count}")
        lines.append("")

        # Priority Breakdown
        lines.append(self._color("bold", "Priority Breakdown"))
        lines.append(f"  {self._icon('critical')} Critical: {summary.critical_tests}")
        lines.append(f"  {self._icon('high')} High: {summary.high_priority}")
        lines.append(f"  {self._icon('medium')} Medium: {summary.medium_priority}")
        lines.append(f"  {self._icon('low')} Low: {summary.low_priority}")
        lines.append("")

        # Key Test Cases (critical and high only)
        lines.append(self._color("bold", "Key Test Cases"))
        key_tests = [t for t in tests if t.get("priority") in ["critical", "high"]]
        for test in key_tests[:7]:
            priority_icon = self._icon(test.get("priority", "medium"))
            lines.append(f"  {priority_icon} {test.get('title', 'Untitled')}")
        if len(key_tests) > 7:
            lines.append(f"  ... and {len(key_tests) - 7} more")

        return "\n".join(lines)

    def _format_engineering(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        summary: TestSummary,
        citations: Optional[List[Citation]],
    ) -> str:
        """Format for engineering - technical details."""
        lines = []

        lines.append(f"# Test Plan: {feature}")
        lines.append("")

        # Technical Summary
        lines.append("## Technical Summary")
        lines.append(f"- Total test cases: {summary.total_tests}")
        lines.append(f"- Security tests: {summary.security_tests}")
        lines.append(f"- Edge cases: {summary.edge_case_tests}")
        lines.append("")

        # Security Tests (important for engineers)
        security_tests = [t for t in tests if t.get("category") == "security"]
        if security_tests:
            lines.append("## Security Test Cases")
            for test in security_tests:
                lines.append(f"### {test.get('id', 'TC-XXX')}: {test.get('title', 'Untitled')}")
                lines.append(f"**Priority:** {test.get('priority', 'medium').upper()}")
                if test.get("steps"):
                    lines.append("**Steps:**")
                    for i, step in enumerate(test.get("steps", []), 1):
                        lines.append(f"{i}. {step}")
                if test.get("expected_result"):
                    lines.append(f"**Expected:** {test.get('expected_result')}")
                lines.append("")

        # Edge Cases (engineers love these)
        edge_tests = [t for t in tests if t.get("category") == "edge_case"]
        if edge_tests:
            lines.append("## Edge Cases")
            for test in edge_tests:
                lines.append(f"- **{test.get('id', 'TC-XXX')}**: {test.get('title', 'Untitled')}")
                if test.get("notes"):
                    lines.append(f"  - Note: {test.get('notes')}")
            lines.append("")

        # Sources (for verification)
        if citations:
            lines.append("## Sources")
            for citation in citations:
                conf_pct = f"{citation.confidence * 100:.0f}%"
                lines.append(f"- {citation.section} ({conf_pct} confidence)")
            lines.append("")

        return "\n".join(lines)

    def _format_qa(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        summary: TestSummary,
        risk: RiskAssessment,
        citations: Optional[List[Citation]],
    ) -> str:
        """Format for QA team - full details."""
        lines = []

        lines.append("=" * 70)
        lines.append(f"TEST PLAN: {feature}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("=" * 70)
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append(f"Total Tests: {summary.total_tests}")
        lines.append(f"  - Critical: {summary.critical_tests}")
        lines.append(f"  - High: {summary.high_priority}")
        lines.append(f"  - Medium: {summary.medium_priority}")
        lines.append(f"  - Low: {summary.low_priority}")
        lines.append("")
        lines.append(f"Categories:")
        lines.append(f"  - Security: {summary.security_tests}")
        lines.append(f"  - Accessibility: {summary.accessibility_tests}")
        lines.append(f"  - Edge Cases: {summary.edge_case_tests}")
        lines.append(f"  - Functional: {summary.functional_tests}")
        lines.append("")

        # Risk Assessment
        lines.append("## Risk Assessment")
        lines.append(f"Risk Level: {risk.overall_level.value.upper()}")
        lines.append(f"Ship Decision: {risk.ship_decision.value.upper().replace('_', ' ')}")
        if risk.blockers:
            lines.append("Blockers:")
            for b in risk.blockers:
                lines.append(f"  - {b}")
        if risk.warnings:
            lines.append("Warnings:")
            for w in risk.warnings:
                lines.append(f"  - {w}")
        lines.append("")

        # All Test Cases (grouped by priority)
        lines.append("## Test Cases")
        lines.append("")

        # Group by priority
        for priority in ["critical", "high", "medium", "low"]:
            priority_tests = [t for t in tests if t.get("priority") == priority]
            if priority_tests:
                lines.append(f"### {priority.upper()} Priority ({len(priority_tests)} tests)")
                lines.append("")
                for test in priority_tests:
                    lines.append(f"#### {test.get('id', 'TC-XXX')}: {test.get('title', 'Untitled')}")
                    lines.append(f"- **Category:** {test.get('category', 'general')}")
                    lines.append(f"- **Priority:** {test.get('priority', 'medium')}")

                    if test.get("preconditions"):
                        lines.append(f"- **Preconditions:** {test.get('preconditions')}")

                    if test.get("steps"):
                        lines.append("- **Steps:**")
                        for i, step in enumerate(test.get("steps", []), 1):
                            lines.append(f"  {i}. {step}")

                    if test.get("expected_result"):
                        lines.append(f"- **Expected Result:** {test.get('expected_result')}")

                    if test.get("notes"):
                        lines.append(f"- **Notes:** {test.get('notes')}")

                    lines.append("")

        # Sources
        if citations:
            lines.append("## Sources (Zero Hallucination)")
            for citation in citations:
                lines.append(f"- {self._icon('source')} {citation.section}")
                lines.append(f"  Confidence: {citation.confidence * 100:.0f}%")
                if citation.excerpt:
                    lines.append(f"  Excerpt: \"{citation.excerpt[:100]}...\"")
            lines.append("")

        lines.append("=" * 70)
        lines.append("END OF TEST PLAN")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _format_full(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        summary: TestSummary,
        risk: RiskAssessment,
        citations: Optional[List[Citation]],
    ) -> str:
        """Format full output with all sections."""
        # Combine all formats
        parts = [
            self._format_executive(feature, summary, risk, citations),
            "\n\n",
            self._format_qa(feature, tests, summary, risk, citations),
        ]
        return "".join(parts)


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def format_for_executive(tests: List[Dict], feature: str) -> str:
    """Quick format for executives."""
    formatter = ExecutiveOutputFormatter()
    return formatter.format_test_plan(tests, feature, Audience.EXECUTIVE)


def format_for_qa(tests: List[Dict], feature: str) -> str:
    """Quick format for QA team."""
    formatter = ExecutiveOutputFormatter()
    return formatter.format_test_plan(tests, feature, Audience.QA)


def format_for_engineering(tests: List[Dict], feature: str) -> str:
    """Quick format for engineering."""
    formatter = ExecutiveOutputFormatter()
    return formatter.format_test_plan(tests, feature, Audience.ENGINEERING)


if __name__ == "__main__":
    # Demo
    sample_tests = [
        {"id": "TC-001", "title": "Valid login", "priority": "critical", "category": "happy_path"},
        {"id": "TC-002", "title": "SQL injection in email", "priority": "critical", "category": "security"},
        {"id": "TC-003", "title": "XSS in password field", "priority": "critical", "category": "security"},
        {"id": "TC-004", "title": "Empty email error", "priority": "high", "category": "negative"},
        {"id": "TC-005", "title": "Rate limiting", "priority": "high", "category": "security"},
        {"id": "TC-006", "title": "Remember me checkbox", "priority": "medium", "category": "functional"},
        {"id": "TC-007", "title": "Keyboard navigation", "priority": "medium", "category": "accessibility"},
        {"id": "TC-008", "title": "Unicode email", "priority": "low", "category": "edge_case"},
    ]

    formatter = ExecutiveOutputFormatter()

    print("\n" + "=" * 70)
    print("EXECUTIVE VIEW")
    print("=" * 70)
    print(formatter.format_test_plan(sample_tests, "Login Page", Audience.EXECUTIVE))

    print("\n" + "=" * 70)
    print("PRODUCT VIEW")
    print("=" * 70)
    print(formatter.format_test_plan(sample_tests, "Login Page", Audience.PRODUCT))
