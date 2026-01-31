"""
TestAI Agent - Accessibility Rules

Extensible rule engine for custom accessibility
checks beyond standard WCAG criteria.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import uuid


class RuleCategory(Enum):
    """Categories of accessibility rules."""
    CONTENT = "content"
    NAVIGATION = "navigation"
    FORMS = "forms"
    MEDIA = "media"
    KEYBOARD = "keyboard"
    SEMANTICS = "semantics"
    ARIA = "aria"
    MOBILE = "mobile"


class RuleSeverity(Enum):
    """Severity levels for rules."""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    SUGGESTION = "suggestion"


@dataclass
class AccessibilityRule:
    """An accessibility rule definition."""
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: RuleSeverity
    wcag_criteria: List[str]
    enabled: bool = True
    check_function: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleMatch:
    """A rule match (violation) result."""
    match_id: str
    rule_id: str
    element_selector: str
    message: str
    suggestion: str
    severity: RuleSeverity
    context: Dict[str, Any] = field(default_factory=dict)


class AccessibilityRuleEngine:
    """
    Extensible accessibility rule engine.

    Features:
    - Built-in rules
    - Custom rule creation
    - Rule configuration
    - Selective execution
    """

    def __init__(self):
        """Initialize the rule engine."""
        self._rules: Dict[str, AccessibilityRule] = {}
        self._matches: List[RuleMatch] = []
        self._rule_counter = 0
        self._match_counter = 0

        # Initialize built-in rules
        self._init_builtin_rules()

    def _init_builtin_rules(self):
        """Initialize built-in accessibility rules."""
        builtin_rules = [
            # Content rules
            AccessibilityRule(
                rule_id="img-alt",
                name="Image Alternative Text",
                description="Images must have alternative text",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["1.1.1"],
            ),
            AccessibilityRule(
                rule_id="img-alt-meaningful",
                name="Meaningful Alt Text",
                description="Alt text should be meaningful and descriptive",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["1.1.1"],
            ),

            # Navigation rules
            AccessibilityRule(
                rule_id="skip-link",
                name="Skip Navigation Link",
                description="Pages should have a skip to main content link",
                category=RuleCategory.NAVIGATION,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["2.4.1"],
            ),
            AccessibilityRule(
                rule_id="landmark-main",
                name="Main Landmark",
                description="Page should have a main landmark",
                category=RuleCategory.NAVIGATION,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["1.3.1", "2.4.1"],
            ),

            # Forms rules
            AccessibilityRule(
                rule_id="form-label",
                name="Form Input Labels",
                description="Form inputs must have associated labels",
                category=RuleCategory.FORMS,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["1.3.1", "3.3.2"],
            ),
            AccessibilityRule(
                rule_id="form-error",
                name="Form Error Messages",
                description="Form errors should be clearly identified",
                category=RuleCategory.FORMS,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["3.3.1"],
            ),
            AccessibilityRule(
                rule_id="required-indicator",
                name="Required Field Indicator",
                description="Required fields should be clearly indicated",
                category=RuleCategory.FORMS,
                severity=RuleSeverity.MINOR,
                wcag_criteria=["3.3.2"],
            ),

            # Media rules
            AccessibilityRule(
                rule_id="video-captions",
                name="Video Captions",
                description="Videos must have captions",
                category=RuleCategory.MEDIA,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["1.2.2"],
            ),
            AccessibilityRule(
                rule_id="audio-transcript",
                name="Audio Transcript",
                description="Audio content should have a transcript",
                category=RuleCategory.MEDIA,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["1.2.1"],
            ),

            # Keyboard rules
            AccessibilityRule(
                rule_id="focus-visible",
                name="Focus Visibility",
                description="Focus indicator must be visible",
                category=RuleCategory.KEYBOARD,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["2.4.7"],
            ),
            AccessibilityRule(
                rule_id="focus-order",
                name="Focus Order",
                description="Focus order should be logical",
                category=RuleCategory.KEYBOARD,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["2.4.3"],
            ),
            AccessibilityRule(
                rule_id="keyboard-trap",
                name="No Keyboard Trap",
                description="Users must be able to navigate away using keyboard",
                category=RuleCategory.KEYBOARD,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["2.1.2"],
            ),

            # Semantics rules
            AccessibilityRule(
                rule_id="heading-structure",
                name="Heading Structure",
                description="Headings should have logical structure",
                category=RuleCategory.SEMANTICS,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["1.3.1", "2.4.6"],
            ),
            AccessibilityRule(
                rule_id="list-markup",
                name="List Markup",
                description="Lists should use appropriate markup",
                category=RuleCategory.SEMANTICS,
                severity=RuleSeverity.MINOR,
                wcag_criteria=["1.3.1"],
            ),

            # ARIA rules
            AccessibilityRule(
                rule_id="aria-valid",
                name="Valid ARIA",
                description="ARIA attributes must be valid",
                category=RuleCategory.ARIA,
                severity=RuleSeverity.CRITICAL,
                wcag_criteria=["4.1.2"],
            ),
            AccessibilityRule(
                rule_id="aria-required",
                name="Required ARIA Properties",
                description="ARIA roles must have required properties",
                category=RuleCategory.ARIA,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["4.1.2"],
            ),

            # Mobile rules
            AccessibilityRule(
                rule_id="touch-target",
                name="Touch Target Size",
                description="Touch targets should be at least 44x44 pixels",
                category=RuleCategory.MOBILE,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["2.5.5"],
            ),
            AccessibilityRule(
                rule_id="zoom-support",
                name="Zoom Support",
                description="Content should be zoomable to 200%",
                category=RuleCategory.MOBILE,
                severity=RuleSeverity.MAJOR,
                wcag_criteria=["1.4.4"],
            ),
        ]

        for rule in builtin_rules:
            self._rules[rule.rule_id] = rule

    def add_rule(
        self,
        name: str,
        description: str,
        category: RuleCategory,
        severity: RuleSeverity,
        wcag_criteria: List[str],
        rule_id: Optional[str] = None,
    ) -> AccessibilityRule:
        """Add a custom rule."""
        if rule_id is None:
            self._rule_counter += 1
            rule_id = f"custom-{self._rule_counter:03d}"

        rule = AccessibilityRule(
            rule_id=rule_id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            wcag_criteria=wcag_criteria,
        )

        self._rules[rule_id] = rule
        return rule

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[AccessibilityRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules_by_category(
        self,
        category: RuleCategory,
    ) -> List[AccessibilityRule]:
        """Get rules by category."""
        return [
            r for r in self._rules.values()
            if r.category == category and r.enabled
        ]

    def get_enabled_rules(self) -> List[AccessibilityRule]:
        """Get all enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def check_rule(
        self,
        rule_id: str,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check a specific rule against elements."""
        rule = self._rules.get(rule_id)
        if not rule or not rule.enabled:
            return []

        matches = []

        # Dispatch to appropriate check function
        if rule.rule_id == "img-alt":
            matches = self._check_img_alt(rule, elements)
        elif rule.rule_id == "form-label":
            matches = self._check_form_labels(rule, elements)
        elif rule.rule_id == "heading-structure":
            matches = self._check_heading_structure(rule, elements)
        elif rule.rule_id == "focus-visible":
            matches = self._check_focus_visible(rule, elements)
        elif rule.rule_id == "aria-valid":
            matches = self._check_aria_valid(rule, elements)
        # Add more rule checks as needed

        self._matches.extend(matches)
        return matches

    def check_all(
        self,
        elements: List[Dict[str, Any]],
        categories: Optional[List[RuleCategory]] = None,
    ) -> List[RuleMatch]:
        """Check all enabled rules."""
        all_matches = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue
            if categories and rule.category not in categories:
                continue

            matches = self.check_rule(rule.rule_id, elements)
            all_matches.extend(matches)

        return all_matches

    def _create_match(
        self,
        rule: AccessibilityRule,
        element_selector: str,
        message: str,
        suggestion: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> RuleMatch:
        """Create a rule match."""
        self._match_counter += 1

        return RuleMatch(
            match_id=f"MATCH-{self._match_counter:05d}",
            rule_id=rule.rule_id,
            element_selector=element_selector,
            message=message,
            suggestion=suggestion,
            severity=rule.severity,
            context=context or {},
        )

    def _check_img_alt(
        self,
        rule: AccessibilityRule,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check images for alt text."""
        matches = []

        for elem in elements:
            if elem.get("tag_name", "").lower() == "img":
                alt = elem.get("attributes", {}).get("alt")

                if alt is None:
                    matches.append(self._create_match(
                        rule=rule,
                        element_selector=elem.get("selector", "img"),
                        message="Image is missing alt attribute",
                        suggestion="Add descriptive alt text",
                    ))

        return matches

    def _check_form_labels(
        self,
        rule: AccessibilityRule,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check form inputs for labels."""
        matches = []

        for elem in elements:
            if elem.get("tag_name", "").lower() == "input":
                has_label = (
                    elem.get("aria_label") or
                    elem.get("attributes", {}).get("aria-labelledby") or
                    elem.get("attributes", {}).get("id")  # Assuming paired label
                )

                if not has_label:
                    matches.append(self._create_match(
                        rule=rule,
                        element_selector=elem.get("selector", "input"),
                        message="Input field is missing a label",
                        suggestion="Add a <label> element or aria-label",
                    ))

        return matches

    def _check_heading_structure(
        self,
        rule: AccessibilityRule,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check heading structure."""
        matches = []
        headings = []

        for elem in elements:
            tag = elem.get("tag_name", "").lower()
            if tag in ["h1", "h2", "h3", "h4", "h5", "h6"]:
                headings.append((elem, int(tag[1])))

        prev_level = 0
        for elem, level in headings:
            if level > prev_level + 1 and prev_level > 0:
                matches.append(self._create_match(
                    rule=rule,
                    element_selector=elem.get("selector", f"h{level}"),
                    message=f"Heading level skips from h{prev_level} to h{level}",
                    suggestion=f"Use h{prev_level + 1} instead",
                ))
            prev_level = level

        return matches

    def _check_focus_visible(
        self,
        rule: AccessibilityRule,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check focus visibility (simulated)."""
        matches = []

        for elem in elements:
            # In real implementation, check CSS focus styles
            if elem.get("has_outline_none"):
                matches.append(self._create_match(
                    rule=rule,
                    element_selector=elem.get("selector", "element"),
                    message="Element removes focus outline",
                    suggestion="Ensure focus indicator is visible",
                ))

        return matches

    def _check_aria_valid(
        self,
        rule: AccessibilityRule,
        elements: List[Dict[str, Any]],
    ) -> List[RuleMatch]:
        """Check ARIA validity."""
        matches = []

        valid_roles = {
            "button", "link", "checkbox", "radio", "textbox",
            "menu", "menuitem", "tab", "tabpanel", "dialog",
        }

        for elem in elements:
            role = elem.get("role")
            if role and role not in valid_roles:
                matches.append(self._create_match(
                    rule=rule,
                    element_selector=elem.get("selector", "element"),
                    message=f"Invalid ARIA role: {role}",
                    suggestion="Use a valid ARIA role",
                ))

        return matches

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        enabled = sum(1 for r in self._rules.values() if r.enabled)

        category_counts = {}
        for category in RuleCategory:
            category_counts[category.value] = sum(
                1 for r in self._rules.values()
                if r.category == category
            )

        return {
            "total_rules": len(self._rules),
            "enabled_rules": enabled,
            "disabled_rules": len(self._rules) - enabled,
            "total_matches": len(self._matches),
            "rules_by_category": category_counts,
        }

    def format_rule(self, rule: AccessibilityRule) -> str:
        """Format a rule for display."""
        status = "✅ Enabled" if rule.enabled else "❌ Disabled"

        severity_icon = {
            RuleSeverity.CRITICAL: "🔴",
            RuleSeverity.MAJOR: "🟠",
            RuleSeverity.MINOR: "🟡",
            RuleSeverity.SUGGESTION: "💡",
        }[rule.severity]

        lines = [
            "=" * 50,
            "  ACCESSIBILITY RULE",
            "=" * 50,
            "",
            f"  {status}",
            "",
            f"  ID: {rule.rule_id}",
            f"  Name: {rule.name}",
            f"  Category: {rule.category.value}",
            f"  Severity: {severity_icon} {rule.severity.value}",
            "",
            f"  Description: {rule.description}",
            f"  WCAG: {', '.join(rule.wcag_criteria)}",
            "",
            "=" * 50,
        ]

        return "\n".join(lines)


def create_rule_engine() -> AccessibilityRuleEngine:
    """Create a rule engine instance."""
    return AccessibilityRuleEngine()
