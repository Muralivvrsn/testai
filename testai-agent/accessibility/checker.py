"""
TestAI Agent - Accessibility Checker

WCAG 2.1 compliance checking with automated
violation detection and remediation suggestions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid


class WCAGLevel(Enum):
    """WCAG conformance levels."""
    A = "A"
    AA = "AA"
    AAA = "AAA"


class WCAGPrinciple(Enum):
    """WCAG principles (POUR)."""
    PERCEIVABLE = "perceivable"
    OPERABLE = "operable"
    UNDERSTANDABLE = "understandable"
    ROBUST = "robust"


class ImpactLevel(Enum):
    """Impact level of violations."""
    CRITICAL = "critical"
    SERIOUS = "serious"
    MODERATE = "moderate"
    MINOR = "minor"


@dataclass
class ElementInfo:
    """Information about a DOM element."""
    selector: str
    tag_name: str
    attributes: Dict[str, str]
    text_content: str
    role: Optional[str] = None
    aria_label: Optional[str] = None


@dataclass
class AccessibilityViolation:
    """An accessibility violation."""
    violation_id: str
    rule_id: str
    rule_name: str
    description: str
    impact: ImpactLevel
    wcag_criteria: List[str]
    wcag_level: WCAGLevel
    principle: WCAGPrinciple
    element: Optional[ElementInfo]
    remediation: str
    help_url: Optional[str] = None


@dataclass
class AccessibilityResult:
    """Result of accessibility check."""
    result_id: str
    page_url: str
    violations: List[AccessibilityViolation]
    passes: int
    warnings: int
    total_elements_checked: int
    wcag_level_checked: WCAGLevel
    score: float  # 0-100
    checked_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class AccessibilityChecker:
    """
    WCAG accessibility checker.

    Features:
    - WCAG 2.1 A/AA/AAA compliance
    - Automated violation detection
    - Impact assessment
    - Remediation suggestions
    - Score calculation
    """

    # Common WCAG criteria
    WCAG_CRITERIA = {
        "1.1.1": ("Non-text Content", WCAGLevel.A, WCAGPrinciple.PERCEIVABLE),
        "1.3.1": ("Info and Relationships", WCAGLevel.A, WCAGPrinciple.PERCEIVABLE),
        "1.4.1": ("Use of Color", WCAGLevel.A, WCAGPrinciple.PERCEIVABLE),
        "1.4.3": ("Contrast (Minimum)", WCAGLevel.AA, WCAGPrinciple.PERCEIVABLE),
        "1.4.4": ("Resize Text", WCAGLevel.AA, WCAGPrinciple.PERCEIVABLE),
        "2.1.1": ("Keyboard", WCAGLevel.A, WCAGPrinciple.OPERABLE),
        "2.1.2": ("No Keyboard Trap", WCAGLevel.A, WCAGPrinciple.OPERABLE),
        "2.4.1": ("Bypass Blocks", WCAGLevel.A, WCAGPrinciple.OPERABLE),
        "2.4.2": ("Page Titled", WCAGLevel.A, WCAGPrinciple.OPERABLE),
        "2.4.4": ("Link Purpose", WCAGLevel.A, WCAGPrinciple.OPERABLE),
        "2.4.6": ("Headings and Labels", WCAGLevel.AA, WCAGPrinciple.OPERABLE),
        "2.4.7": ("Focus Visible", WCAGLevel.AA, WCAGPrinciple.OPERABLE),
        "3.1.1": ("Language of Page", WCAGLevel.A, WCAGPrinciple.UNDERSTANDABLE),
        "3.2.1": ("On Focus", WCAGLevel.A, WCAGPrinciple.UNDERSTANDABLE),
        "3.2.2": ("On Input", WCAGLevel.A, WCAGPrinciple.UNDERSTANDABLE),
        "3.3.1": ("Error Identification", WCAGLevel.A, WCAGPrinciple.UNDERSTANDABLE),
        "3.3.2": ("Labels or Instructions", WCAGLevel.A, WCAGPrinciple.UNDERSTANDABLE),
        "4.1.1": ("Parsing", WCAGLevel.A, WCAGPrinciple.ROBUST),
        "4.1.2": ("Name, Role, Value", WCAGLevel.A, WCAGPrinciple.ROBUST),
    }

    # Impact weights for scoring
    IMPACT_WEIGHTS = {
        ImpactLevel.CRITICAL: 1.0,
        ImpactLevel.SERIOUS: 0.7,
        ImpactLevel.MODERATE: 0.4,
        ImpactLevel.MINOR: 0.2,
    }

    def __init__(
        self,
        target_level: WCAGLevel = WCAGLevel.AA,
        include_warnings: bool = True,
    ):
        """Initialize the checker."""
        self._target_level = target_level
        self._include_warnings = include_warnings

        self._results: List[AccessibilityResult] = []
        self._violation_counter = 0
        self._result_counter = 0

    def check_page(
        self,
        page_url: str,
        elements: List[Dict[str, Any]],
        page_metadata: Optional[Dict[str, Any]] = None,
    ) -> AccessibilityResult:
        """Check a page for accessibility issues."""
        self._result_counter += 1
        result_id = f"A11Y-{self._result_counter:05d}"

        violations = []
        passes = 0
        warnings = 0

        # Convert elements to ElementInfo objects
        element_infos = [self._to_element_info(e) for e in elements]

        # Run accessibility checks
        violations.extend(self._check_images(element_infos))
        violations.extend(self._check_form_labels(element_infos))
        violations.extend(self._check_links(element_infos))
        violations.extend(self._check_headings(element_infos))
        violations.extend(self._check_buttons(element_infos))
        violations.extend(self._check_aria(element_infos))
        violations.extend(self._check_contrast(element_infos, page_metadata or {}))
        violations.extend(self._check_language(page_metadata or {}))
        violations.extend(self._check_page_title(page_metadata or {}))

        # Filter by target level
        violations = [
            v for v in violations
            if self._is_within_level(v.wcag_level)
        ]

        # Count passes (elements without violations)
        elements_with_violations = set(
            v.element.selector for v in violations if v.element
        )
        passes = len(element_infos) - len(elements_with_violations)

        # Count warnings vs errors
        warnings = sum(1 for v in violations if v.impact == ImpactLevel.MINOR)
        errors = len(violations) - warnings

        # Calculate score
        score = self._calculate_score(violations, len(element_infos))

        result = AccessibilityResult(
            result_id=result_id,
            page_url=page_url,
            violations=violations,
            passes=passes,
            warnings=warnings,
            total_elements_checked=len(element_infos),
            wcag_level_checked=self._target_level,
            score=score,
            checked_at=datetime.now(),
            metadata=page_metadata or {},
        )

        self._results.append(result)
        return result

    def _to_element_info(self, element: Dict[str, Any]) -> ElementInfo:
        """Convert element dict to ElementInfo."""
        return ElementInfo(
            selector=element.get("selector", "unknown"),
            tag_name=element.get("tag_name", "div").lower(),
            attributes=element.get("attributes", {}),
            text_content=element.get("text_content", ""),
            role=element.get("role"),
            aria_label=element.get("aria_label"),
        )

    def _create_violation(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        impact: ImpactLevel,
        wcag_criteria: List[str],
        wcag_level: WCAGLevel,
        principle: WCAGPrinciple,
        element: Optional[ElementInfo],
        remediation: str,
    ) -> AccessibilityViolation:
        """Create an accessibility violation."""
        self._violation_counter += 1

        return AccessibilityViolation(
            violation_id=f"VIOL-{self._violation_counter:05d}",
            rule_id=rule_id,
            rule_name=rule_name,
            description=description,
            impact=impact,
            wcag_criteria=wcag_criteria,
            wcag_level=wcag_level,
            principle=principle,
            element=element,
            remediation=remediation,
        )

    def _is_within_level(self, level: WCAGLevel) -> bool:
        """Check if level is within target."""
        levels = {WCAGLevel.A: 1, WCAGLevel.AA: 2, WCAGLevel.AAA: 3}
        return levels[level] <= levels[self._target_level]

    def _check_images(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check images for alt text."""
        violations = []

        for elem in elements:
            if elem.tag_name == "img":
                alt = elem.attributes.get("alt")

                if alt is None:
                    violations.append(self._create_violation(
                        rule_id="image-alt",
                        rule_name="Images must have alt text",
                        description="Image is missing alt attribute",
                        impact=ImpactLevel.CRITICAL,
                        wcag_criteria=["1.1.1"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.PERCEIVABLE,
                        element=elem,
                        remediation="Add alt attribute describing the image content",
                    ))
                elif alt == "" and not elem.attributes.get("role") == "presentation":
                    violations.append(self._create_violation(
                        rule_id="image-alt-empty",
                        rule_name="Non-decorative images need alt text",
                        description="Image has empty alt text but is not decorative",
                        impact=ImpactLevel.SERIOUS,
                        wcag_criteria=["1.1.1"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.PERCEIVABLE,
                        element=elem,
                        remediation="Add descriptive alt text or mark as decorative",
                    ))

        return violations

    def _check_form_labels(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check form inputs for labels."""
        violations = []
        input_types = {"text", "email", "password", "tel", "search", "url", "number"}

        for elem in elements:
            if elem.tag_name == "input":
                input_type = elem.attributes.get("type", "text")

                if input_type in input_types:
                    has_label = (
                        elem.aria_label or
                        elem.attributes.get("aria-labelledby") or
                        elem.attributes.get("title") or
                        elem.attributes.get("placeholder")
                    )

                    if not has_label:
                        violations.append(self._create_violation(
                            rule_id="input-label",
                            rule_name="Form inputs must have labels",
                            description=f"Input field ({input_type}) is missing an accessible label",
                            impact=ImpactLevel.CRITICAL,
                            wcag_criteria=["3.3.2", "1.3.1"],
                            wcag_level=WCAGLevel.A,
                            principle=WCAGPrinciple.UNDERSTANDABLE,
                            element=elem,
                            remediation="Add a <label> element or aria-label attribute",
                        ))

        return violations

    def _check_links(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check links for accessible names."""
        violations = []

        for elem in elements:
            if elem.tag_name == "a":
                link_text = elem.text_content.strip()
                aria_label = elem.aria_label

                if not link_text and not aria_label:
                    violations.append(self._create_violation(
                        rule_id="link-name",
                        rule_name="Links must have discernible text",
                        description="Link has no accessible text content",
                        impact=ImpactLevel.CRITICAL,
                        wcag_criteria=["2.4.4", "4.1.2"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.OPERABLE,
                        element=elem,
                        remediation="Add text content or aria-label to the link",
                    ))
                elif link_text.lower() in ["click here", "here", "more", "read more"]:
                    violations.append(self._create_violation(
                        rule_id="link-purpose",
                        rule_name="Link text should describe purpose",
                        description=f"Link text '{link_text}' is not descriptive",
                        impact=ImpactLevel.MODERATE,
                        wcag_criteria=["2.4.4"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.OPERABLE,
                        element=elem,
                        remediation="Use descriptive link text that explains the destination",
                    ))

        return violations

    def _check_headings(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check heading structure."""
        violations = []
        heading_tags = ["h1", "h2", "h3", "h4", "h5", "h6"]
        found_headings = []

        for elem in elements:
            if elem.tag_name in heading_tags:
                level = int(elem.tag_name[1])
                found_headings.append((elem, level))

                if not elem.text_content.strip():
                    violations.append(self._create_violation(
                        rule_id="heading-empty",
                        rule_name="Headings should not be empty",
                        description=f"Empty {elem.tag_name} heading",
                        impact=ImpactLevel.MODERATE,
                        wcag_criteria=["2.4.6", "1.3.1"],
                        wcag_level=WCAGLevel.AA,
                        principle=WCAGPrinciple.OPERABLE,
                        element=elem,
                        remediation="Add meaningful content to the heading",
                    ))

        # Check heading order
        if found_headings:
            prev_level = 0
            for elem, level in found_headings:
                if level > prev_level + 1 and prev_level > 0:
                    violations.append(self._create_violation(
                        rule_id="heading-order",
                        rule_name="Heading levels should not be skipped",
                        description=f"Heading skips from h{prev_level} to h{level}",
                        impact=ImpactLevel.MODERATE,
                        wcag_criteria=["1.3.1"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.PERCEIVABLE,
                        element=elem,
                        remediation=f"Use h{prev_level + 1} instead of h{level}",
                    ))
                prev_level = level

        return violations

    def _check_buttons(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check buttons for accessible names."""
        violations = []

        for elem in elements:
            if elem.tag_name == "button" or elem.role == "button":
                button_text = elem.text_content.strip()
                aria_label = elem.aria_label

                if not button_text and not aria_label:
                    violations.append(self._create_violation(
                        rule_id="button-name",
                        rule_name="Buttons must have discernible text",
                        description="Button has no accessible text content",
                        impact=ImpactLevel.CRITICAL,
                        wcag_criteria=["4.1.2"],
                        wcag_level=WCAGLevel.A,
                        principle=WCAGPrinciple.ROBUST,
                        element=elem,
                        remediation="Add text content or aria-label to the button",
                    ))

        return violations

    def _check_aria(
        self,
        elements: List[ElementInfo],
    ) -> List[AccessibilityViolation]:
        """Check ARIA usage."""
        violations = []

        valid_roles = {
            "button", "link", "checkbox", "radio", "textbox", "listbox",
            "menu", "menuitem", "tab", "tabpanel", "dialog", "alert",
            "navigation", "main", "banner", "complementary", "contentinfo",
            "search", "form", "region", "heading", "img", "list", "listitem",
            "presentation", "none", "application",
        }

        for elem in elements:
            role = elem.role

            if role and role not in valid_roles:
                violations.append(self._create_violation(
                    rule_id="aria-role-valid",
                    rule_name="ARIA roles must be valid",
                    description=f"Invalid ARIA role: {role}",
                    impact=ImpactLevel.SERIOUS,
                    wcag_criteria=["4.1.2"],
                    wcag_level=WCAGLevel.A,
                    principle=WCAGPrinciple.ROBUST,
                    element=elem,
                    remediation="Use a valid ARIA role or remove the role attribute",
                ))

        return violations

    def _check_contrast(
        self,
        elements: List[ElementInfo],
        metadata: Dict[str, Any],
    ) -> List[AccessibilityViolation]:
        """Check color contrast (simulated)."""
        violations = []

        # In a real implementation, we'd check computed styles
        # Here we simulate by checking for common issues
        low_contrast_elements = metadata.get("low_contrast_elements", [])

        for selector in low_contrast_elements:
            violations.append(self._create_violation(
                rule_id="color-contrast",
                rule_name="Color contrast must be sufficient",
                description="Text has insufficient color contrast",
                impact=ImpactLevel.SERIOUS,
                wcag_criteria=["1.4.3"],
                wcag_level=WCAGLevel.AA,
                principle=WCAGPrinciple.PERCEIVABLE,
                element=ElementInfo(
                    selector=selector,
                    tag_name="span",
                    attributes={},
                    text_content="",
                ),
                remediation="Increase contrast ratio to at least 4.5:1 for normal text",
            ))

        return violations

    def _check_language(
        self,
        metadata: Dict[str, Any],
    ) -> List[AccessibilityViolation]:
        """Check page language is set."""
        violations = []

        lang = metadata.get("lang")

        if not lang:
            violations.append(self._create_violation(
                rule_id="html-lang",
                rule_name="Page must have lang attribute",
                description="The <html> element does not have a lang attribute",
                impact=ImpactLevel.SERIOUS,
                wcag_criteria=["3.1.1"],
                wcag_level=WCAGLevel.A,
                principle=WCAGPrinciple.UNDERSTANDABLE,
                element=None,
                remediation="Add a lang attribute to the <html> element (e.g., lang='en')",
            ))

        return violations

    def _check_page_title(
        self,
        metadata: Dict[str, Any],
    ) -> List[AccessibilityViolation]:
        """Check page has a title."""
        violations = []

        title = metadata.get("title")

        if not title:
            violations.append(self._create_violation(
                rule_id="page-title",
                rule_name="Page must have a title",
                description="Page is missing a <title> element",
                impact=ImpactLevel.SERIOUS,
                wcag_criteria=["2.4.2"],
                wcag_level=WCAGLevel.A,
                principle=WCAGPrinciple.OPERABLE,
                element=None,
                remediation="Add a descriptive <title> element to the page",
            ))
        elif len(title) < 5:
            violations.append(self._create_violation(
                rule_id="page-title-descriptive",
                rule_name="Page title should be descriptive",
                description=f"Page title '{title}' is not descriptive enough",
                impact=ImpactLevel.MODERATE,
                wcag_criteria=["2.4.2"],
                wcag_level=WCAGLevel.A,
                principle=WCAGPrinciple.OPERABLE,
                element=None,
                remediation="Use a more descriptive page title",
            ))

        return violations

    def _calculate_score(
        self,
        violations: List[AccessibilityViolation],
        total_elements: int,
    ) -> float:
        """Calculate accessibility score (0-100)."""
        if total_elements == 0:
            return 100.0

        # Weight violations by impact
        weighted_violations = sum(
            self.IMPACT_WEIGHTS[v.impact]
            for v in violations
        )

        # Score based on violation density
        violation_ratio = weighted_violations / max(1, total_elements)
        score = max(0, 100 - (violation_ratio * 100))

        return round(score, 1)

    def get_results(
        self,
        limit: int = 10,
    ) -> List[AccessibilityResult]:
        """Get recent results."""
        return self._results[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get checker statistics."""
        if not self._results:
            return {
                "total_checks": 0,
                "avg_score": 0,
                "total_violations": 0,
            }

        return {
            "total_checks": len(self._results),
            "avg_score": sum(r.score for r in self._results) / len(self._results),
            "total_violations": sum(len(r.violations) for r in self._results),
            "target_level": self._target_level.value,
        }

    def format_result(self, result: AccessibilityResult) -> str:
        """Format a result for display."""
        status = "✅ PASS" if result.score >= 90 else "⚠️ NEEDS WORK" if result.score >= 70 else "❌ FAIL"

        lines = [
            "=" * 60,
            f"  {status} ACCESSIBILITY CHECK",
            "=" * 60,
            "",
            f"  URL: {result.page_url}",
            f"  Score: {result.score}/100",
            f"  Level: WCAG {result.wcag_level_checked.value}",
            "",
            f"  Violations: {len(result.violations)}",
            f"  Passes: {result.passes}",
            f"  Elements Checked: {result.total_elements_checked}",
            "",
        ]

        if result.violations:
            lines.append("-" * 60)
            lines.append("  VIOLATIONS")
            lines.append("-" * 60)

            for v in result.violations[:10]:
                impact_icon = {
                    ImpactLevel.CRITICAL: "🔴",
                    ImpactLevel.SERIOUS: "🟠",
                    ImpactLevel.MODERATE: "🟡",
                    ImpactLevel.MINOR: "🟢",
                }[v.impact]

                lines.append(f"  {impact_icon} [{v.wcag_criteria[0]}] {v.rule_name}")
                if v.element:
                    lines.append(f"     Element: {v.element.selector}")

            if len(result.violations) > 10:
                lines.append(f"  ... and {len(result.violations) - 10} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_accessibility_checker(
    target_level: WCAGLevel = WCAGLevel.AA,
    include_warnings: bool = True,
) -> AccessibilityChecker:
    """Create an accessibility checker instance."""
    return AccessibilityChecker(
        target_level=target_level,
        include_warnings=include_warnings,
    )
