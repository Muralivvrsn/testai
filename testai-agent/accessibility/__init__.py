"""
TestAI Agent - Accessibility Testing

WCAG compliance checking, accessibility auditing,
and inclusive design validation.
"""

from .checker import (
    AccessibilityChecker,
    WCAGLevel,
    WCAGPrinciple,
    AccessibilityViolation,
    AccessibilityResult,
    create_accessibility_checker,
)

from .rules import (
    AccessibilityRuleEngine,
    AccessibilityRule,
    RuleCategory,
    RuleSeverity,
    RuleMatch,
    create_rule_engine,
)

from .reporter import (
    AccessibilityReporter,
    AccessibilityReport,
    A11yReportFormat,
    create_accessibility_reporter,
)

__all__ = [
    # Checker
    "AccessibilityChecker",
    "WCAGLevel",
    "WCAGPrinciple",
    "AccessibilityViolation",
    "AccessibilityResult",
    "create_accessibility_checker",
    # Rules
    "AccessibilityRuleEngine",
    "AccessibilityRule",
    "RuleCategory",
    "RuleSeverity",
    "RuleMatch",
    "create_rule_engine",
    # Reporter
    "AccessibilityReporter",
    "AccessibilityReport",
    "A11yReportFormat",
    "create_accessibility_reporter",
]
