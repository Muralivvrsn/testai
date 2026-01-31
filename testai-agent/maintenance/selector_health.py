"""
TestAI Agent - Selector Health Monitor

Monitors the health and stability of selectors used in tests,
providing risk assessment and recommendations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re


class SelectorRisk(Enum):
    """Risk levels for selectors."""
    CRITICAL = "critical"  # Very likely to break
    HIGH = "high"  # Likely to break
    MEDIUM = "medium"  # May break
    LOW = "low"  # Unlikely to break
    STABLE = "stable"  # Very unlikely to break


class SelectorType(Enum):
    """Types of selectors."""
    ID = "id"
    CLASS = "class"
    DATA_ATTRIBUTE = "data_attribute"
    ARIA = "aria"
    TAG = "tag"
    XPATH = "xpath"
    TEXT = "text"
    COMBINATION = "combination"


@dataclass
class SelectorHealth:
    """Health information for a selector."""
    selector: str
    selector_type: SelectorType
    risk: SelectorRisk
    risk_score: float  # 0.0 to 1.0 (lower is better)
    issues: List[str]
    recommendations: List[str]
    used_in_tests: List[str]
    failure_count: int = 0
    last_used: Optional[datetime] = None
    stability_score: float = 1.0


@dataclass
class SelectorReport:
    """Selector health report."""
    total_selectors: int
    by_risk: Dict[SelectorRisk, int]
    critical_selectors: List[SelectorHealth]
    recommendations: List[Dict[str, str]]
    overall_health_score: float


class SelectorHealthMonitor:
    """
    Monitors selector health and stability.

    Features:
    - Selector risk assessment
    - Pattern detection
    - Stability tracking
    - Recommendation generation
    """

    # Risk factors and their weights
    RISK_FACTORS = {
        # High risk patterns
        "dynamic_id": (r"#[\w-]*\d{3,}", 0.8, "ID contains numeric sequence"),
        "dynamic_class": (r"\.[\w-]*\d{3,}", 0.7, "Class contains numeric sequence"),
        "css_in_js": (r"\.(css|sc|emotion)-[\w]{5,}", 0.9, "CSS-in-JS generated class"),
        "framework_generated": (r"\[(?:ng-|_ng|data-v-|__vue)", 0.8, "Framework-generated attribute"),
        "deep_nesting": (r"(\s*>\s*){4,}", 0.7, "Deep nesting (4+ levels)"),
        "positional": (r":nth-(?:child|of-type)\(\d+\)", 0.6, "Positional selector"),
        "long_xpath": (r"\/\/[\w\[\]@='\"./]+\/\/[\w\[\]@='\"./]+\/\/", 0.8, "Complex XPath"),
        "index_based": (r"\[\d+\]", 0.5, "Index-based selection"),

        # Medium risk patterns
        "generic_class": (r"^\.(?:btn|button|link|item|row|col|container)$", 0.4, "Generic class name"),
        "style_class": (r"\.(?:active|selected|disabled|hidden|visible)", 0.3, "State-based class"),
        "layout_class": (r"\.(?:flex|grid|float|clear|margin|padding)", 0.3, "Layout class"),

        # Low risk patterns (good practices)
        "data_testid": (r"\[data-testid[=]", -0.3, "Uses data-testid (good)"),
        "data_cy": (r"\[data-cy[=]", -0.3, "Uses data-cy (good)"),
        "aria_label": (r"\[aria-label[=]", -0.2, "Uses aria-label (good)"),
        "role": (r"\[role[=]", -0.2, "Uses role attribute (good)"),
    }

    # Selector type patterns
    TYPE_PATTERNS = {
        SelectorType.ID: r"^#[\w-]+$",
        SelectorType.CLASS: r"^\.[\w-]+$",
        SelectorType.DATA_ATTRIBUTE: r"^\[data-[\w-]+=",
        SelectorType.ARIA: r"^\[aria-[\w-]+=",
        SelectorType.TAG: r"^[a-z]+$",
        SelectorType.XPATH: r"^\/\/",
        SelectorType.TEXT: r"text[=()]",
    }

    def __init__(self):
        """Initialize the selector health monitor."""
        self._selectors: Dict[str, SelectorHealth] = {}
        self._test_selectors: Dict[str, List[str]] = {}  # test_id -> selectors
        self._execution_results: Dict[str, List[bool]] = {}  # selector -> results

    def register_selector(
        self,
        selector: str,
        test_id: str,
    ):
        """Register a selector used in a test."""
        if selector not in self._selectors:
            self._selectors[selector] = self._analyze_selector(selector)

        self._selectors[selector].used_in_tests.append(test_id)
        self._selectors[selector].last_used = datetime.now()

        if test_id not in self._test_selectors:
            self._test_selectors[test_id] = []
        if selector not in self._test_selectors[test_id]:
            self._test_selectors[test_id].append(selector)

    def record_selector_result(
        self,
        selector: str,
        found: bool,
    ):
        """Record whether a selector was found."""
        if selector not in self._execution_results:
            self._execution_results[selector] = []

        self._execution_results[selector].append(found)

        if selector in self._selectors:
            if not found:
                self._selectors[selector].failure_count += 1

            # Update stability score
            results = self._execution_results[selector][-10:]
            self._selectors[selector].stability_score = sum(results) / len(results)

    def _analyze_selector(self, selector: str) -> SelectorHealth:
        """Analyze a selector for risk factors."""
        issues = []
        recommendations = []
        risk_score = 0.3  # Base risk

        # Determine selector type
        selector_type = SelectorType.COMBINATION
        for stype, pattern in self.TYPE_PATTERNS.items():
            if re.search(pattern, selector, re.IGNORECASE):
                selector_type = stype
                break

        # Check risk factors
        for name, (pattern, weight, description) in self.RISK_FACTORS.items():
            if re.search(pattern, selector, re.IGNORECASE):
                risk_score += weight
                if weight > 0:
                    issues.append(description)
                else:
                    # Positive factor
                    recommendations.append(f"Good: {description}")

        # Determine risk level
        risk_score = max(0.0, min(1.0, risk_score))
        risk = self._score_to_risk(risk_score)

        # Generate recommendations
        if risk in {SelectorRisk.CRITICAL, SelectorRisk.HIGH}:
            recommendations.extend(self._generate_recommendations(selector, issues))

        return SelectorHealth(
            selector=selector,
            selector_type=selector_type,
            risk=risk,
            risk_score=risk_score,
            issues=issues,
            recommendations=recommendations,
            used_in_tests=[],
        )

    def _score_to_risk(self, score: float) -> SelectorRisk:
        """Convert risk score to risk level."""
        if score >= 0.8:
            return SelectorRisk.CRITICAL
        elif score >= 0.6:
            return SelectorRisk.HIGH
        elif score >= 0.4:
            return SelectorRisk.MEDIUM
        elif score >= 0.2:
            return SelectorRisk.LOW
        return SelectorRisk.STABLE

    def _generate_recommendations(
        self,
        selector: str,
        issues: List[str],
    ) -> List[str]:
        """Generate recommendations for a risky selector."""
        recommendations = []

        # Common recommendations
        if any("numeric" in i.lower() for i in issues):
            recommendations.append("Add a data-testid attribute to the element")

        if any("generated" in i.lower() or "css-in-js" in i.lower() for i in issues):
            recommendations.append("Use data-testid instead of generated class names")

        if any("nesting" in i.lower() for i in issues):
            recommendations.append("Simplify selector or add data-testid to target element")

        if any("positional" in i.lower() for i in issues):
            recommendations.append("Add unique identifier instead of using position")

        if any("xpath" in i.lower() for i in issues):
            recommendations.append("Convert XPath to CSS selector where possible")

        if not recommendations:
            recommendations.append("Review selector and consider adding data-testid")

        return recommendations

    def get_selector_health(self, selector: str) -> Optional[SelectorHealth]:
        """Get health information for a selector."""
        return self._selectors.get(selector)

    def get_test_selectors(self, test_id: str) -> List[SelectorHealth]:
        """Get all selectors used by a test."""
        selector_list = self._test_selectors.get(test_id, [])
        return [
            self._selectors[s]
            for s in selector_list
            if s in self._selectors
        ]

    def get_risky_selectors(
        self,
        min_risk: SelectorRisk = SelectorRisk.MEDIUM,
    ) -> List[SelectorHealth]:
        """Get selectors at or above a risk level."""
        risk_order = [
            SelectorRisk.STABLE,
            SelectorRisk.LOW,
            SelectorRisk.MEDIUM,
            SelectorRisk.HIGH,
            SelectorRisk.CRITICAL,
        ]

        min_index = risk_order.index(min_risk)

        return [
            health for health in self._selectors.values()
            if risk_order.index(health.risk) >= min_index
        ]

    def generate_report(self) -> SelectorReport:
        """Generate a selector health report."""
        by_risk: Dict[SelectorRisk, int] = {r: 0 for r in SelectorRisk}

        for health in self._selectors.values():
            by_risk[health.risk] += 1

        critical = self.get_risky_selectors(SelectorRisk.HIGH)
        critical.sort(key=lambda h: -h.risk_score)

        # Generate global recommendations
        recommendations = []
        if by_risk[SelectorRisk.CRITICAL] > 0:
            recommendations.append({
                "priority": "high",
                "recommendation": f"Fix {by_risk[SelectorRisk.CRITICAL]} critical selectors immediately",
            })

        if by_risk[SelectorRisk.HIGH] > 0:
            recommendations.append({
                "priority": "medium",
                "recommendation": f"Review {by_risk[SelectorRisk.HIGH]} high-risk selectors",
            })

        # Calculate overall health
        if not self._selectors:
            overall_health = 1.0
        else:
            total_risk = sum(h.risk_score for h in self._selectors.values())
            overall_health = 1.0 - (total_risk / len(self._selectors))

        return SelectorReport(
            total_selectors=len(self._selectors),
            by_risk=by_risk,
            critical_selectors=critical[:10],
            recommendations=recommendations,
            overall_health_score=max(0.0, overall_health),
        )

    def suggest_alternative(self, selector: str) -> Optional[str]:
        """Suggest an alternative selector."""
        # Extract element information from selector
        if selector.startswith("#"):
            # ID selector - suggest data-testid
            element = selector[1:].split("[")[0].split(".")[0]
            return f'[data-testid="{element}"]'

        elif selector.startswith("."):
            # Class selector - suggest data-testid
            element = selector[1:].split("[")[0].split(".")[0]
            return f'[data-testid="{element}"]'

        elif selector.startswith("//"):
            # XPath - try to convert to CSS
            # Simple conversions
            if "[@id=" in selector:
                match = re.search(r"@id='([^']+)'", selector)
                if match:
                    return f'#{match.group(1)}'

            if "[@class=" in selector:
                match = re.search(r"@class='([^']+)'", selector)
                if match:
                    return f'.{match.group(1).split()[0]}'

        return f'[data-testid="<add-unique-id>"]'

    def format_report(self, report: SelectorReport) -> str:
        """Format selector report as readable text."""
        lines = [
            "=" * 60,
            "  SELECTOR HEALTH REPORT",
            "=" * 60,
            "",
            f"  Total Selectors: {report.total_selectors}",
            f"  Overall Health: {report.overall_health_score:.0%}",
            "",
            "-" * 60,
            "  RISK DISTRIBUTION",
            "-" * 60,
        ]

        for risk in SelectorRisk:
            count = report.by_risk.get(risk, 0)
            bar = "█" * min(count, 20)
            lines.append(f"  {risk.value:10} | {bar} ({count})")

        if report.critical_selectors:
            lines.extend([
                "",
                "-" * 60,
                "  CRITICAL SELECTORS",
                "-" * 60,
            ])
            for health in report.critical_selectors[:5]:
                lines.extend([
                    f"",
                    f"  Risk: {health.risk.value.upper()} ({health.risk_score:.0%})",
                    f"  Selector: {health.selector[:50]}",
                    f"  Issues: {', '.join(health.issues[:2])}",
                    f"  Used in: {len(health.used_in_tests)} test(s)",
                ])

        if report.recommendations:
            lines.extend([
                "",
                "-" * 60,
                "  RECOMMENDATIONS",
                "-" * 60,
            ])
            for rec in report.recommendations:
                lines.append(f"  [{rec['priority'].upper()}] {rec['recommendation']}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_selector_monitor() -> SelectorHealthMonitor:
    """Create a selector health monitor instance."""
    return SelectorHealthMonitor()
