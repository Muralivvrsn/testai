"""
TestAI Agent - Executive Summary Generator

Creates stakeholder-ready reports:
- C-level summary (risk, go/no-go)
- Product summary (features, coverage)
- Engineering summary (technical details)
- QA summary (full test breakdown)

Design: European business reporting - clear, actionable, professional.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime


class StakeholderType(Enum):
    """Types of stakeholders."""
    EXECUTIVE = "executive"      # C-level, board
    PRODUCT = "product"          # Product managers
    ENGINEERING = "engineering"  # Developers, tech leads
    QA = "qa"                    # QA team


class ShipDecision(Enum):
    """Ship/no-ship decision."""
    GO = "go"              # Safe to ship
    CAUTION = "caution"    # Ship with monitoring
    NO_GO = "no_go"        # Do not ship


class RiskLevel(Enum):
    """Risk assessment level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RiskItem:
    """A single risk item."""
    title: str
    description: str
    level: RiskLevel
    mitigation: Optional[str] = None
    source: Optional[str] = None  # Citation


@dataclass
class CoverageMetrics:
    """Test coverage metrics."""
    total_tests: int
    by_category: Dict[str, int]
    by_priority: Dict[str, int]
    sources_cited: int
    coverage_percentage: float  # Estimated coverage


@dataclass
class ExecutiveSummary:
    """Complete executive summary."""
    feature: str
    generated_at: datetime
    ship_decision: ShipDecision
    ship_rationale: str
    risk_level: RiskLevel
    risks: List[RiskItem]
    coverage: CoverageMetrics
    key_findings: List[str]
    recommendations: List[str]
    blockers: List[str]
    warnings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "feature": self.feature,
            "generated_at": self.generated_at.isoformat(),
            "ship_decision": self.ship_decision.value,
            "ship_rationale": self.ship_rationale,
            "risk_level": self.risk_level.value,
            "risks": [
                {
                    "title": r.title,
                    "description": r.description,
                    "level": r.level.value,
                    "mitigation": r.mitigation,
                }
                for r in self.risks
            ],
            "coverage": {
                "total_tests": self.coverage.total_tests,
                "by_category": self.coverage.by_category,
                "by_priority": self.coverage.by_priority,
                "sources_cited": self.coverage.sources_cited,
                "coverage_percentage": self.coverage.coverage_percentage,
            },
            "key_findings": self.key_findings,
            "recommendations": self.recommendations,
            "blockers": self.blockers,
            "warnings": self.warnings,
        }


class ExecutiveSummaryGenerator:
    """
    Generates executive summaries from test results.

    Tailors output to different stakeholder types:
    - Executive: Ship decision, risk overview, blockers
    - Product: Feature coverage, user impact
    - Engineering: Technical details, implementation notes
    - QA: Full test breakdown, citations

    Usage:
        generator = ExecutiveSummaryGenerator()

        # Create summary from test data
        summary = generator.create_summary(
            feature="Login Page",
            tests=test_list,
            risks=risk_list,
        )

        # Format for different audiences
        exec_report = generator.format_for_stakeholder(summary, StakeholderType.EXECUTIVE)
        eng_report = generator.format_for_stakeholder(summary, StakeholderType.ENGINEERING)
    """

    def __init__(self):
        """Initialize generator."""
        pass

    def create_summary(
        self,
        feature: str,
        tests: List[Dict[str, Any]],
        risks: Optional[List[RiskItem]] = None,
        citations: Optional[List[str]] = None,
    ) -> ExecutiveSummary:
        """
        Create an executive summary.

        Args:
            feature: Feature being tested
            tests: List of test dictionaries
            risks: List of identified risks
            citations: List of cited sources

        Returns:
            ExecutiveSummary
        """
        # Calculate metrics
        coverage = self._calculate_coverage(tests, citations)

        # Assess risks
        risks = risks or self._assess_risks(tests)

        # Determine ship decision
        ship_decision, rationale = self._determine_ship_decision(tests, risks)

        # Calculate overall risk level
        risk_level = self._calculate_risk_level(risks)

        # Generate findings
        key_findings = self._generate_findings(tests, risks, coverage)

        # Generate recommendations
        recommendations = self._generate_recommendations(tests, risks, coverage)

        # Identify blockers and warnings
        blockers = self._identify_blockers(risks)
        warnings = self._identify_warnings(tests, risks, coverage)

        return ExecutiveSummary(
            feature=feature,
            generated_at=datetime.now(),
            ship_decision=ship_decision,
            ship_rationale=rationale,
            risk_level=risk_level,
            risks=risks,
            coverage=coverage,
            key_findings=key_findings,
            recommendations=recommendations,
            blockers=blockers,
            warnings=warnings,
        )

    def _calculate_coverage(
        self,
        tests: List[Dict[str, Any]],
        citations: Optional[List[str]],
    ) -> CoverageMetrics:
        """Calculate test coverage metrics."""
        by_category = {}
        by_priority = {}

        for test in tests:
            cat = test.get("category", "unknown")
            pri = test.get("priority", "medium")

            by_category[cat] = by_category.get(cat, 0) + 1
            by_priority[pri] = by_priority.get(pri, 0) + 1

        # Estimate coverage percentage based on test count and categories
        base_coverage = min(100, len(tests) * 5)  # 5% per test, max 100%

        # Bonus for having security tests
        if by_category.get("security", 0) > 0:
            base_coverage = min(100, base_coverage + 10)

        # Bonus for having edge case tests
        if by_category.get("edge_case", 0) > 0:
            base_coverage = min(100, base_coverage + 5)

        return CoverageMetrics(
            total_tests=len(tests),
            by_category=by_category,
            by_priority=by_priority,
            sources_cited=len(citations) if citations else 0,
            coverage_percentage=base_coverage,
        )

    def _assess_risks(self, tests: List[Dict[str, Any]]) -> List[RiskItem]:
        """Assess risks from test data."""
        risks = []

        # Check for missing security tests
        security_tests = sum(1 for t in tests if t.get("category") == "security")
        if security_tests == 0:
            risks.append(RiskItem(
                title="No Security Tests",
                description="No security-specific test cases were generated.",
                level=RiskLevel.CRITICAL,
                mitigation="Add security test cases for authentication, injection, and access control.",
            ))
        elif security_tests < 3:
            risks.append(RiskItem(
                title="Limited Security Coverage",
                description=f"Only {security_tests} security tests. Consider expanding.",
                level=RiskLevel.HIGH,
                mitigation="Review security checklist and add missing test cases.",
            ))

        # Check for missing critical tests
        critical_tests = sum(1 for t in tests if t.get("priority") == "critical")
        if critical_tests == 0:
            risks.append(RiskItem(
                title="No Critical Tests",
                description="No tests marked as critical priority.",
                level=RiskLevel.HIGH,
                mitigation="Review and prioritize tests based on business impact.",
            ))

        # Check overall test count
        if len(tests) < 5:
            risks.append(RiskItem(
                title="Low Test Coverage",
                description=f"Only {len(tests)} tests generated. May miss important scenarios.",
                level=RiskLevel.MEDIUM,
                mitigation="Expand test suite to cover more scenarios.",
            ))

        return risks

    def _determine_ship_decision(
        self,
        tests: List[Dict[str, Any]],
        risks: List[RiskItem],
    ) -> tuple[ShipDecision, str]:
        """Determine if it's safe to ship."""
        critical_risks = [r for r in risks if r.level == RiskLevel.CRITICAL]
        high_risks = [r for r in risks if r.level == RiskLevel.HIGH]

        if critical_risks:
            return (
                ShipDecision.NO_GO,
                f"Blocked by {len(critical_risks)} critical risk(s): {critical_risks[0].title}"
            )

        if high_risks:
            return (
                ShipDecision.CAUTION,
                f"Proceed with caution due to {len(high_risks)} high-priority risk(s)"
            )

        security_tests = sum(1 for t in tests if t.get("category") == "security")
        if security_tests >= 3 and len(tests) >= 10:
            return (
                ShipDecision.GO,
                "Adequate test coverage with security tests in place"
            )

        return (
            ShipDecision.CAUTION,
            "Limited test coverage - recommend additional testing"
        )

    def _calculate_risk_level(self, risks: List[RiskItem]) -> RiskLevel:
        """Calculate overall risk level."""
        if any(r.level == RiskLevel.CRITICAL for r in risks):
            return RiskLevel.CRITICAL
        if any(r.level == RiskLevel.HIGH for r in risks):
            return RiskLevel.HIGH
        if any(r.level == RiskLevel.MEDIUM for r in risks):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _generate_findings(
        self,
        tests: List[Dict[str, Any]],
        risks: List[RiskItem],
        coverage: CoverageMetrics,
    ) -> List[str]:
        """Generate key findings."""
        findings = []

        findings.append(f"Generated {coverage.total_tests} test cases across {len(coverage.by_category)} categories")

        if coverage.sources_cited > 0:
            findings.append(f"All tests backed by {coverage.sources_cited} knowledge base citations")

        security_count = coverage.by_category.get("security", 0)
        if security_count > 0:
            findings.append(f"Includes {security_count} security-focused test cases")

        critical_count = coverage.by_priority.get("critical", 0)
        if critical_count > 0:
            findings.append(f"{critical_count} critical-priority tests identified")

        if risks:
            findings.append(f"Identified {len(risks)} risk areas requiring attention")

        return findings

    def _generate_recommendations(
        self,
        tests: List[Dict[str, Any]],
        risks: List[RiskItem],
        coverage: CoverageMetrics,
    ) -> List[str]:
        """Generate recommendations."""
        recommendations = []

        # Security recommendations
        if coverage.by_category.get("security", 0) < 5:
            recommendations.append("Expand security test coverage to at least 5 test cases")

        # Coverage recommendations
        if coverage.coverage_percentage < 70:
            recommendations.append("Increase test coverage to at least 70%")

        # Risk-based recommendations
        for risk in risks:
            if risk.mitigation:
                recommendations.append(risk.mitigation)

        # General recommendations
        if len(tests) > 0:
            recommendations.append("Run all tests before deployment")
            recommendations.append("Set up automated regression testing")

        return recommendations[:5]  # Top 5 recommendations

    def _identify_blockers(self, risks: List[RiskItem]) -> List[str]:
        """Identify release blockers."""
        blockers = []

        for risk in risks:
            if risk.level == RiskLevel.CRITICAL:
                blockers.append(f"BLOCKER: {risk.title} - {risk.description}")

        return blockers

    def _identify_warnings(
        self,
        tests: List[Dict[str, Any]],
        risks: List[RiskItem],
        coverage: CoverageMetrics,
    ) -> List[str]:
        """Identify warnings."""
        warnings = []

        for risk in risks:
            if risk.level == RiskLevel.HIGH:
                warnings.append(f"WARNING: {risk.title}")

        if coverage.coverage_percentage < 50:
            warnings.append("WARNING: Test coverage below 50%")

        return warnings

    def format_for_stakeholder(
        self,
        summary: ExecutiveSummary,
        stakeholder: StakeholderType,
    ) -> str:
        """
        Format summary for a specific stakeholder type.

        Args:
            summary: ExecutiveSummary to format
            stakeholder: Target stakeholder type

        Returns:
            Formatted string
        """
        if stakeholder == StakeholderType.EXECUTIVE:
            return self._format_executive(summary)
        elif stakeholder == StakeholderType.PRODUCT:
            return self._format_product(summary)
        elif stakeholder == StakeholderType.ENGINEERING:
            return self._format_engineering(summary)
        elif stakeholder == StakeholderType.QA:
            return self._format_qa(summary)
        else:
            return self._format_executive(summary)

    def _format_executive(self, summary: ExecutiveSummary) -> str:
        """Format for executives."""
        lines = []

        # Header
        lines.append(f"# Executive Summary: {summary.feature}")
        lines.append(f"*Generated: {summary.generated_at.strftime('%Y-%m-%d %H:%M')}*")
        lines.append("")

        # Ship Decision Box
        decision_emoji = {
            ShipDecision.GO: "✅",
            ShipDecision.CAUTION: "⚠️",
            ShipDecision.NO_GO: "🛑",
        }[summary.ship_decision]

        lines.append("## Ship Decision")
        lines.append("")
        lines.append(f"### {decision_emoji} {summary.ship_decision.value.upper()}")
        lines.append("")
        lines.append(f"*{summary.ship_rationale}*")
        lines.append("")

        # Risk Overview
        risk_emoji = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢",
        }[summary.risk_level]

        lines.append("## Risk Level")
        lines.append("")
        lines.append(f"{risk_emoji} **{summary.risk_level.value.upper()}**")
        lines.append("")

        # Blockers (if any)
        if summary.blockers:
            lines.append("## ⛔ Blockers")
            lines.append("")
            for blocker in summary.blockers:
                lines.append(f"- {blocker}")
            lines.append("")

        # Key Metrics
        lines.append("## Key Metrics")
        lines.append("")
        lines.append(f"- **Tests:** {summary.coverage.total_tests}")
        lines.append(f"- **Coverage:** {summary.coverage.coverage_percentage:.0f}%")
        lines.append(f"- **Risk Items:** {len(summary.risks)}")
        lines.append("")

        # Top Recommendations
        lines.append("## Recommendations")
        lines.append("")
        for rec in summary.recommendations[:3]:
            lines.append(f"- {rec}")
        lines.append("")

        return "\n".join(lines)

    def _format_product(self, summary: ExecutiveSummary) -> str:
        """Format for product managers."""
        lines = []

        lines.append(f"# Product Test Report: {summary.feature}")
        lines.append("")

        # Coverage by category
        lines.append("## Test Coverage")
        lines.append("")
        for cat, count in summary.coverage.by_category.items():
            lines.append(f"- **{cat.replace('_', ' ').title()}:** {count} tests")
        lines.append("")
        lines.append(f"**Overall Coverage:** {summary.coverage.coverage_percentage:.0f}%")
        lines.append("")

        # Key Findings
        lines.append("## Key Findings")
        lines.append("")
        for finding in summary.key_findings:
            lines.append(f"- {finding}")
        lines.append("")

        # User Impact Risks
        user_impact_risks = [r for r in summary.risks if "user" in r.description.lower() or "access" in r.description.lower()]
        if user_impact_risks:
            lines.append("## User Impact Concerns")
            lines.append("")
            for risk in user_impact_risks:
                lines.append(f"- **{risk.title}:** {risk.description}")
            lines.append("")

        # Recommendations
        lines.append("## Action Items")
        lines.append("")
        for rec in summary.recommendations:
            lines.append(f"- [ ] {rec}")
        lines.append("")

        return "\n".join(lines)

    def _format_engineering(self, summary: ExecutiveSummary) -> str:
        """Format for engineering team."""
        lines = []

        lines.append(f"# Engineering Test Report: {summary.feature}")
        lines.append("")

        # Technical Summary
        lines.append("## Technical Summary")
        lines.append("")
        lines.append(f"```")
        lines.append(f"Total Tests: {summary.coverage.total_tests}")
        lines.append(f"Sources:     {summary.coverage.sources_cited}")
        lines.append(f"Coverage:    {summary.coverage.coverage_percentage:.0f}%")
        lines.append(f"```")
        lines.append("")

        # Tests by Priority
        lines.append("## Priority Breakdown")
        lines.append("")
        for pri, count in summary.coverage.by_priority.items():
            lines.append(f"- `{pri.upper()}`: {count}")
        lines.append("")

        # Technical Risks
        lines.append("## Technical Risks")
        lines.append("")
        for risk in summary.risks:
            level_badge = {
                RiskLevel.CRITICAL: "🔴 CRITICAL",
                RiskLevel.HIGH: "🟠 HIGH",
                RiskLevel.MEDIUM: "🟡 MEDIUM",
                RiskLevel.LOW: "🟢 LOW",
            }[risk.level]
            lines.append(f"### {level_badge}: {risk.title}")
            lines.append("")
            lines.append(risk.description)
            if risk.mitigation:
                lines.append("")
                lines.append(f"**Fix:** {risk.mitigation}")
            if risk.source:
                lines.append(f"*Source: {risk.source}*")
            lines.append("")

        # Implementation Notes
        lines.append("## Implementation Notes")
        lines.append("")
        lines.append("- All tests should be automated in CI/CD pipeline")
        lines.append("- Security tests should run on every PR")
        lines.append("- Consider load testing for high-traffic features")
        lines.append("")

        return "\n".join(lines)

    def _format_qa(self, summary: ExecutiveSummary) -> str:
        """Format for QA team."""
        lines = []

        lines.append(f"# QA Test Report: {summary.feature}")
        lines.append(f"*Generated: {summary.generated_at.isoformat()}*")
        lines.append("")

        # Full metrics
        lines.append("## Test Metrics")
        lines.append("")
        lines.append("### By Category")
        for cat, count in summary.coverage.by_category.items():
            lines.append(f"- {cat}: {count}")
        lines.append("")

        lines.append("### By Priority")
        for pri, count in summary.coverage.by_priority.items():
            lines.append(f"- {pri}: {count}")
        lines.append("")

        lines.append(f"### Sources Cited: {summary.coverage.sources_cited}")
        lines.append("")

        # All risks with full detail
        lines.append("## Risk Assessment")
        lines.append("")
        for i, risk in enumerate(summary.risks, 1):
            lines.append(f"### {i}. {risk.title}")
            lines.append(f"**Level:** {risk.level.value.upper()}")
            lines.append(f"**Description:** {risk.description}")
            if risk.mitigation:
                lines.append(f"**Mitigation:** {risk.mitigation}")
            if risk.source:
                lines.append(f"**Source:** {risk.source}")
            lines.append("")

        # All findings
        lines.append("## Findings")
        lines.append("")
        for finding in summary.key_findings:
            lines.append(f"- {finding}")
        lines.append("")

        # All recommendations
        lines.append("## Recommendations")
        lines.append("")
        for rec in summary.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

        # Warnings
        if summary.warnings:
            lines.append("## Warnings")
            lines.append("")
            for warning in summary.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_executive_summary(
    feature: str,
    tests: List[Dict[str, Any]],
    stakeholder: StakeholderType = StakeholderType.EXECUTIVE,
) -> str:
    """Quick create and format an executive summary."""
    generator = ExecutiveSummaryGenerator()
    summary = generator.create_summary(feature, tests)
    return generator.format_for_stakeholder(summary, stakeholder)


if __name__ == "__main__":
    # Demo
    sample_tests = [
        {"id": "TC-001", "title": "Valid login", "category": "functional", "priority": "high"},
        {"id": "TC-002", "title": "Invalid password", "category": "functional", "priority": "medium"},
        {"id": "TC-003", "title": "SQL injection", "category": "security", "priority": "critical"},
        {"id": "TC-004", "title": "XSS in email", "category": "security", "priority": "critical"},
        {"id": "TC-005", "title": "CSRF protection", "category": "security", "priority": "high"},
        {"id": "TC-006", "title": "Empty form", "category": "edge_case", "priority": "medium"},
    ]

    generator = ExecutiveSummaryGenerator()
    summary = generator.create_summary("Login Page", sample_tests, citations=["7.1", "7.2", "7.3"])

    print("=" * 60)
    print("EXECUTIVE VIEW")
    print("=" * 60)
    print(generator.format_for_stakeholder(summary, StakeholderType.EXECUTIVE))

    print("\n" + "=" * 60)
    print("ENGINEERING VIEW")
    print("=" * 60)
    print(generator.format_for_stakeholder(summary, StakeholderType.ENGINEERING))
