"""
TestAI Agent - Executive Report Generator

Creates stakeholder-ready reports designed for:
- C-Suite executives (quick risk summary)
- Product managers (feature coverage)
- Engineering leads (technical details)
- QA managers (test metrics)

Design Philosophy (European):
- Information hierarchy (most important first)
- Clean typography
- Visual indicators over text
- Scannable in 30 seconds
- Actionable recommendations
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum
import json


class AudienceType(Enum):
    """Target audience for the report."""
    EXECUTIVE = "executive"      # C-suite, quick summary
    PRODUCT = "product"          # PMs, feature coverage
    ENGINEERING = "engineering"  # Tech leads, technical details
    QA = "qa"                    # QA managers, full details


class RiskLevel(Enum):
    """Overall risk assessment."""
    CRITICAL = "critical"  # Ship blocker
    HIGH = "high"          # Should fix before release
    MODERATE = "moderate"  # Can ship with known issues
    LOW = "low"            # Good to ship


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment."""
    level: RiskLevel
    score: int  # 0-100
    blockers: List[str]  # Issues that block release
    warnings: List[str]  # Issues to be aware of
    recommendation: str
    confidence: float  # 0-1

    @property
    def color(self) -> str:
        """Get color for risk level."""
        return {
            RiskLevel.CRITICAL: "#dc2626",
            RiskLevel.HIGH: "#ea580c",
            RiskLevel.MODERATE: "#ca8a04",
            RiskLevel.LOW: "#16a34a",
        }[self.level]

    @property
    def icon(self) -> str:
        """Get icon for risk level."""
        return {
            RiskLevel.CRITICAL: "🚨",
            RiskLevel.HIGH: "⚠️",
            RiskLevel.MODERATE: "📋",
            RiskLevel.LOW: "✅",
        }[self.level]


@dataclass
class CoverageMetrics:
    """Test coverage metrics."""
    total_tests: int
    by_priority: Dict[str, int]
    by_category: Dict[str, int]
    estimated_coverage: float  # 0-1
    gaps: List[str]  # Areas not covered


@dataclass
class ExecutiveReport:
    """Executive-ready test report."""
    # Metadata
    title: str
    feature: str
    page_type: Optional[str]
    generated_at: datetime

    # Assessment
    risk: RiskAssessment
    coverage: CoverageMetrics

    # Content
    tests: List[Dict[str, Any]]
    citations: List[Dict[str, Any]]  # Sources used (zero hallucination)

    # Recommendations
    ship_decision: str  # "Ship", "Ship with caution", "Do not ship"
    action_items: List[str]
    follow_ups: List[str]


class ExecutiveReportGenerator:
    """
    Generates executive-friendly reports.

    Usage:
        generator = ExecutiveReportGenerator()

        report = generator.generate(
            tests=my_tests,
            feature="User Authentication",
            citations=brain_citations,
        )

        # Get for different audiences
        exec_summary = generator.format_for_audience(report, AudienceType.EXECUTIVE)
        full_report = generator.format_for_audience(report, AudienceType.QA)
    """

    def __init__(self):
        """Initialize the generator."""
        self.audience_configs = {
            AudienceType.EXECUTIVE: {
                "show_tests": False,
                "show_details": False,
                "show_citations": False,
                "max_items": 3,
            },
            AudienceType.PRODUCT: {
                "show_tests": True,
                "show_details": False,
                "show_citations": False,
                "max_items": 10,
            },
            AudienceType.ENGINEERING: {
                "show_tests": True,
                "show_details": True,
                "show_citations": True,
                "max_items": 50,
            },
            AudienceType.QA: {
                "show_tests": True,
                "show_details": True,
                "show_citations": True,
                "max_items": None,  # All
            },
        }

    def generate(
        self,
        tests: List[Dict[str, Any]],
        feature: str,
        page_type: Optional[str] = None,
        citations: Optional[List[Dict[str, Any]]] = None,
    ) -> ExecutiveReport:
        """
        Generate executive report from tests.

        Args:
            tests: Test cases
            feature: Feature name
            page_type: Page type
            citations: Brain citations used

        Returns:
            ExecutiveReport
        """
        citations = citations or []

        # Calculate metrics
        coverage = self._calculate_coverage(tests)
        risk = self._assess_risk(tests, coverage)

        # Generate recommendations
        ship_decision = self._determine_ship_decision(risk)
        action_items = self._generate_action_items(tests, risk)
        follow_ups = self._generate_follow_ups(tests, coverage)

        return ExecutiveReport(
            title=f"Test Assessment: {feature}",
            feature=feature,
            page_type=page_type,
            generated_at=datetime.now(),
            risk=risk,
            coverage=coverage,
            tests=tests,
            citations=citations,
            ship_decision=ship_decision,
            action_items=action_items,
            follow_ups=follow_ups,
        )

    def _calculate_coverage(self, tests: List[Dict]) -> CoverageMetrics:
        """Calculate test coverage metrics."""
        by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_category = {}

        for test in tests:
            # Priority
            pri = test.get("priority", "medium").lower()
            if pri in by_priority:
                by_priority[pri] += 1

            # Category
            cat = test.get("category", "general").lower()
            by_category[cat] = by_category.get(cat, 0) + 1

        # Estimate coverage (heuristic)
        expected_categories = {"happy_path", "negative", "edge_case", "security", "boundary"}
        covered = set(by_category.keys())
        coverage_ratio = len(covered & expected_categories) / len(expected_categories)

        # Find gaps
        gaps = list(expected_categories - covered)

        return CoverageMetrics(
            total_tests=len(tests),
            by_priority=by_priority,
            by_category=by_category,
            estimated_coverage=coverage_ratio,
            gaps=gaps,
        )

    def _assess_risk(self, tests: List[Dict], coverage: CoverageMetrics) -> RiskAssessment:
        """Assess overall risk level."""
        blockers = []
        warnings = []

        # Check for critical tests
        critical_count = coverage.by_priority.get("critical", 0)
        high_count = coverage.by_priority.get("high", 0)

        if critical_count > 0:
            blockers.append(f"{critical_count} critical test(s) must pass before release")

        if high_count > 3:
            warnings.append(f"{high_count} high-priority tests need attention")

        # Check for security tests
        security_count = coverage.by_category.get("security", 0)
        if security_count == 0:
            blockers.append("No security tests defined - security review required")

        # Check coverage
        if coverage.estimated_coverage < 0.6:
            warnings.append(f"Test coverage is low ({coverage.estimated_coverage:.0%})")

        # Check for gaps
        if coverage.gaps:
            warnings.append(f"Missing test categories: {', '.join(coverage.gaps)}")

        # Determine risk level
        if len(blockers) > 0:
            level = RiskLevel.CRITICAL if "security" in str(blockers).lower() else RiskLevel.HIGH
        elif len(warnings) > 2:
            level = RiskLevel.HIGH
        elif len(warnings) > 0:
            level = RiskLevel.MODERATE
        else:
            level = RiskLevel.LOW

        # Calculate score (inverse of risk)
        score = 100 - (len(blockers) * 30 + len(warnings) * 10)
        score = max(0, min(100, score))

        # Generate recommendation
        if level == RiskLevel.CRITICAL:
            recommendation = "Do not ship until blockers are resolved."
        elif level == RiskLevel.HIGH:
            recommendation = "Address high-priority issues before release."
        elif level == RiskLevel.MODERATE:
            recommendation = "Can proceed with release, but monitor closely."
        else:
            recommendation = "Good to ship. All critical areas covered."

        return RiskAssessment(
            level=level,
            score=score,
            blockers=blockers,
            warnings=warnings,
            recommendation=recommendation,
            confidence=coverage.estimated_coverage,
        )

    def _determine_ship_decision(self, risk: RiskAssessment) -> str:
        """Determine ship/no-ship decision."""
        if risk.level == RiskLevel.CRITICAL:
            return "🚫 Do Not Ship"
        elif risk.level == RiskLevel.HIGH:
            return "⚠️ Ship with Caution"
        elif risk.level == RiskLevel.MODERATE:
            return "📋 Ship (Monitor)"
        else:
            return "✅ Ship"

    def _generate_action_items(self, tests: List[Dict], risk: RiskAssessment) -> List[str]:
        """Generate action items."""
        items = []

        # From blockers
        for blocker in risk.blockers:
            items.append(f"[BLOCKER] {blocker}")

        # From warnings
        for warning in risk.warnings[:2]:
            items.append(f"[WARNING] {warning}")

        # Default items
        if not items:
            items.append("Execute all test cases")
            items.append("Review test results before release")

        return items

    def _generate_follow_ups(self, tests: List[Dict], coverage: CoverageMetrics) -> List[str]:
        """Generate follow-up items."""
        follow_ups = []

        # Coverage gaps
        if coverage.gaps:
            follow_ups.append(f"Add tests for: {', '.join(coverage.gaps)}")

        # Low priority items
        if coverage.by_priority.get("low", 0) < 2:
            follow_ups.append("Consider adding more exploratory tests")

        # Automation
        follow_ups.append("Automate critical path tests")

        return follow_ups

    def format_for_audience(
        self,
        report: ExecutiveReport,
        audience: AudienceType,
    ) -> str:
        """
        Format report for specific audience.

        Args:
            report: ExecutiveReport
            audience: Target audience

        Returns:
            Formatted report string (Markdown)
        """
        config = self.audience_configs[audience]
        lines = []

        # Header
        lines.append(f"# {report.title}")
        lines.append("")
        lines.append(f"*{report.generated_at.strftime('%B %d, %Y')} | {audience.value.title()} View*")
        lines.append("")

        # Risk Summary (always show)
        lines.append("---")
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(f"**{report.risk.icon} {report.risk.level.value.upper()}** | Score: {report.risk.score}/100")
        lines.append("")
        lines.append(f"**Ship Decision: {report.ship_decision}**")
        lines.append("")
        lines.append(f"> {report.risk.recommendation}")
        lines.append("")

        # Action Items (always show for exec)
        if report.action_items:
            lines.append("### Action Items")
            lines.append("")
            for item in report.action_items[:config["max_items"] or len(report.action_items)]:
                lines.append(f"- {item}")
            lines.append("")

        # Coverage (show for product+)
        if audience != AudienceType.EXECUTIVE:
            lines.append("---")
            lines.append("## Test Coverage")
            lines.append("")
            lines.append(f"**Total Tests:** {report.coverage.total_tests}")
            lines.append(f"**Estimated Coverage:** {report.coverage.estimated_coverage:.0%}")
            lines.append("")

            if report.coverage.gaps:
                lines.append("**Gaps:**")
                for gap in report.coverage.gaps:
                    lines.append(f"- {gap}")
                lines.append("")

            lines.append("**By Priority:**")
            lines.append("")
            for pri, count in report.coverage.by_priority.items():
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[pri]
                lines.append(f"- {icon} {pri.title()}: {count}")
            lines.append("")

        # Test Cases (for engineering/QA)
        if config["show_tests"]:
            lines.append("---")
            lines.append("## Test Cases")
            lines.append("")

            max_tests = config["max_items"]
            tests_to_show = report.tests[:max_tests] if max_tests else report.tests

            for test in tests_to_show:
                lines.extend(self._format_test(test, config["show_details"]))
                lines.append("")

        # Citations (for engineering/QA)
        if config["show_citations"] and report.citations:
            lines.append("---")
            lines.append("## Sources (Zero Hallucination)")
            lines.append("")
            for citation in report.citations[:5]:
                source = citation.get("source", "Unknown")
                conf = citation.get("confidence", 0)
                lines.append(f"- 📚 {source} ({conf:.0%} match)")
            lines.append("")

        # Follow-ups
        if report.follow_ups:
            lines.append("---")
            lines.append("## Follow-up Items")
            lines.append("")
            for item in report.follow_ups:
                lines.append(f"- [ ] {item}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Generated by TestAI Agent | {audience.value.title()} Report*")

        return "\n".join(lines)

    def _format_test(self, test: Dict[str, Any], show_details: bool) -> List[str]:
        """Format a single test case."""
        lines = []

        test_id = test.get("id", "TC-XXX")
        title = test.get("title", "Untitled")
        priority = test.get("priority", "medium").lower()
        category = test.get("category", "general")

        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(priority, "⚪")

        lines.append(f"### {icon} {test_id}: {title}")
        lines.append(f"*{category.replace('_', ' ').title()}*")
        lines.append("")

        if show_details:
            description = test.get("description", "")
            steps = test.get("steps", [])
            expected = test.get("expected_result", "")

            if description:
                lines.append(f"> {description}")
                lines.append("")

            if steps:
                lines.append("**Steps:**")
                for i, step in enumerate(steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            if expected:
                lines.append(f"**Expected:** {expected}")

        return lines

    def to_json(self, report: ExecutiveReport) -> str:
        """Export report as JSON."""
        return json.dumps({
            "title": report.title,
            "feature": report.feature,
            "page_type": report.page_type,
            "generated_at": report.generated_at.isoformat(),
            "risk": {
                "level": report.risk.level.value,
                "score": report.risk.score,
                "blockers": report.risk.blockers,
                "warnings": report.risk.warnings,
                "recommendation": report.risk.recommendation,
            },
            "coverage": {
                "total_tests": report.coverage.total_tests,
                "by_priority": report.coverage.by_priority,
                "by_category": report.coverage.by_category,
                "estimated_coverage": report.coverage.estimated_coverage,
                "gaps": report.coverage.gaps,
            },
            "ship_decision": report.ship_decision,
            "action_items": report.action_items,
            "follow_ups": report.follow_ups,
            "tests": report.tests,
            "citations": report.citations,
        }, indent=2)


def generate_executive_report(
    tests: List[Dict[str, Any]],
    feature: str,
    audience: AudienceType = AudienceType.EXECUTIVE,
    citations: Optional[List[Dict]] = None,
) -> str:
    """
    Quick helper to generate executive report.

    Args:
        tests: Test cases
        feature: Feature name
        audience: Target audience
        citations: Brain citations

    Returns:
        Formatted report string
    """
    generator = ExecutiveReportGenerator()
    report = generator.generate(tests, feature, citations=citations)
    return generator.format_for_audience(report, audience)


if __name__ == "__main__":
    # Demo
    sample_tests = [
        {
            "id": "TC-001",
            "title": "Login with valid credentials",
            "priority": "critical",
            "category": "happy_path",
            "description": "Verify user can login with valid email and password",
            "steps": [
                "Navigate to login page",
                "Enter email: maya.test@company.com",
                "Enter password: Test123!",
                "Click Login button",
            ],
            "expected_result": "User is logged in and redirected to dashboard",
        },
        {
            "id": "TC-002",
            "title": "SQL injection in email field",
            "priority": "critical",
            "category": "security",
            "description": "Verify SQL injection is prevented",
            "steps": [
                "Navigate to login page",
                "Enter email: ' OR '1'='1",
                "Enter any password",
                "Click Login button",
            ],
            "expected_result": "Login fails with generic error, no SQL error exposed",
        },
        {
            "id": "TC-003",
            "title": "Empty email validation",
            "priority": "high",
            "category": "negative",
            "steps": ["Leave email empty", "Click Login"],
            "expected_result": "Email required error shown",
        },
    ]

    citations = [
        {"source": "Brain: Section 7.1 - Email Validation", "confidence": 0.92},
        {"source": "Brain: Section 12.3 - SQL Injection Prevention", "confidence": 0.88},
    ]

    generator = ExecutiveReportGenerator()
    report = generator.generate(sample_tests, "User Login", page_type="login", citations=citations)

    print("=" * 60)
    print("EXECUTIVE VIEW")
    print("=" * 60)
    print(generator.format_for_audience(report, AudienceType.EXECUTIVE))

    print("\n" + "=" * 60)
    print("QA VIEW")
    print("=" * 60)
    print(generator.format_for_audience(report, AudienceType.QA))
