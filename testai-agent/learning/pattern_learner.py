"""
TestAI Agent - Pattern Learner

Learns patterns from test executions to improve future test generation.
This module identifies what makes tests succeed or fail, and uses that
knowledge to generate better tests.

Key capabilities:
1. Failure Pattern Recognition - Why tests fail
2. Success Pattern Recognition - What makes tests reliable
3. Rule Learning - Generate new testing rules from experience
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import re


@dataclass
class FailurePattern:
    """A pattern that commonly leads to test failures."""
    pattern_id: str
    name: str
    description: str

    # Pattern matching
    error_patterns: List[str]  # Regex patterns to match
    selector_patterns: List[str]  # Selector patterns involved
    action_patterns: List[str]  # Actions that trigger this

    # Statistics
    occurrence_count: int = 0
    last_seen: Optional[datetime] = None

    # Prevention strategies
    prevention_strategies: List[str] = field(default_factory=list)
    alternative_approaches: List[str] = field(default_factory=list)

    # Confidence
    confidence: float = 0.5

    def matches(self, error_message: str, selector: str = "", action: str = "") -> bool:
        """Check if this pattern matches the given failure."""
        # Check error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, error_message, re.IGNORECASE):
                return True

        # Check selector patterns
        if selector:
            for pattern in self.selector_patterns:
                if re.search(pattern, selector, re.IGNORECASE):
                    return True

        # Check action patterns
        if action:
            for pattern in self.action_patterns:
                if re.search(pattern, action, re.IGNORECASE):
                    return True

        return False

    def record_occurrence(self) -> None:
        """Record that this pattern was observed."""
        self.occurrence_count += 1
        self.last_seen = datetime.now()
        # Increase confidence with more occurrences
        self.confidence = min(0.95, self.confidence + 0.05)


@dataclass
class SuccessPattern:
    """A pattern that leads to reliable, successful tests."""
    pattern_id: str
    name: str
    description: str

    # Pattern characteristics
    selector_patterns: List[str]  # What selectors work well
    wait_strategies: List[str]  # What wait strategies work
    assertion_patterns: List[str]  # What assertions are reliable

    # Context
    page_types: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)

    # Statistics
    success_count: int = 0
    confidence: float = 0.5

    def record_success(self) -> None:
        """Record a successful application of this pattern."""
        self.success_count += 1
        self.confidence = min(0.95, self.confidence + 0.03)


@dataclass
class LearnedRule:
    """A testing rule learned from execution patterns."""
    rule_id: str
    rule_text: str
    category: str

    # Origin
    learned_from: str  # What insight/pattern generated this
    evidence_count: int = 0

    # Applicability
    page_types: List[str] = field(default_factory=list)
    test_categories: List[str] = field(default_factory=list)

    # Confidence and validation
    confidence: float = 0.5
    validated: bool = False
    validation_result: Optional[str] = None

    # Status
    active: bool = True
    created_at: datetime = field(default_factory=datetime.now)


class PatternLearner:
    """
    Learns patterns from test execution data to improve test generation.

    This is the core intelligence that makes the agent better over time.
    It observes what works and what doesn't, and uses that to generate
    smarter tests in the future.
    """

    # Pre-defined failure patterns (baseline knowledge)
    KNOWN_FAILURE_PATTERNS = [
        FailurePattern(
            pattern_id="fp_timeout_dynamic",
            name="Dynamic Content Timeout",
            description="Timeout waiting for dynamically loaded content",
            error_patterns=[
                r"timeout.*waiting",
                r"timed?\s*out",
                r"exceeded.*timeout",
            ],
            selector_patterns=[
                r"loading",
                r"spinner",
                r"skeleton",
            ],
            action_patterns=[
                r"wait.*visible",
                r"wait.*present",
            ],
            prevention_strategies=[
                "Use explicit waits with appropriate timeout values",
                "Check for loading indicators before interacting",
                "Implement retry logic for dynamic content",
            ],
            alternative_approaches=[
                "Wait for network idle instead of fixed timeout",
                "Use JavaScript to check DOM readiness",
            ],
        ),
        FailurePattern(
            pattern_id="fp_stale_element",
            name="Stale Element Reference",
            description="Element reference became stale after DOM update",
            error_patterns=[
                r"stale.*element",
                r"element.*detached",
                r"not attached.*dom",
            ],
            selector_patterns=[],
            action_patterns=[
                r"click",
                r"type",
                r"fill",
            ],
            prevention_strategies=[
                "Re-locate element immediately before interaction",
                "Use stable selectors (data-testid, aria-label)",
                "Add wait for DOM stability after navigation",
            ],
            alternative_approaches=[
                "Use JavaScript click instead of Playwright click",
                "Implement element wrapper with auto-refresh",
            ],
        ),
        FailurePattern(
            pattern_id="fp_element_obscured",
            name="Element Obscured",
            description="Element blocked by overlay, modal, or other element",
            error_patterns=[
                r"element.*obscured",
                r"not.*clickable",
                r"intercepted",
                r"overlay",
            ],
            selector_patterns=[
                r"button",
                r"link",
                r"submit",
            ],
            action_patterns=[
                r"click",
            ],
            prevention_strategies=[
                "Check for and dismiss overlays/modals first",
                "Wait for any animations to complete",
                "Scroll element into view before clicking",
            ],
            alternative_approaches=[
                "Use force:true option for click",
                "Use JavaScript click to bypass visibility check",
            ],
        ),
        FailurePattern(
            pattern_id="fp_network_flaky",
            name="Network Instability",
            description="Intermittent network failures causing test flakiness",
            error_patterns=[
                r"network.*error",
                r"fetch.*failed",
                r"connection.*refused",
                r"ECONNRESET",
            ],
            selector_patterns=[],
            action_patterns=[
                r"navigate",
                r"goto",
                r"request",
            ],
            prevention_strategies=[
                "Implement retry logic for network operations",
                "Add longer timeout for initial page load",
                "Check network connectivity before test suite",
            ],
            alternative_approaches=[
                "Mock network requests for faster, reliable tests",
                "Use network throttling simulation for consistent behavior",
            ],
        ),
        FailurePattern(
            pattern_id="fp_assertion_timing",
            name="Assertion Timing Issue",
            description="Assertion fails due to async state not being ready",
            error_patterns=[
                r"assert.*failed",
                r"expected.*but.*got",
                r"not.*equal",
            ],
            selector_patterns=[],
            action_patterns=[
                r"assert",
                r"expect",
                r"verify",
            ],
            prevention_strategies=[
                "Wait for state change before asserting",
                "Use polling assertions (toHaveText, toBeVisible)",
                "Add explicit wait for API response completion",
            ],
            alternative_approaches=[
                "Use retry assertions with timeout",
                "Check for loading state before assertion",
            ],
        ),
    ]

    # Pre-defined success patterns
    KNOWN_SUCCESS_PATTERNS = [
        SuccessPattern(
            pattern_id="sp_data_testid",
            name="Data-TestID Selectors",
            description="Using data-testid attributes for reliable element selection",
            selector_patterns=[r"data-testid", r"\[data-test"],
            wait_strategies=[],
            assertion_patterns=[],
            page_types=["all"],
            categories=["all"],
        ),
        SuccessPattern(
            pattern_id="sp_aria_labels",
            name="ARIA Label Selectors",
            description="Using ARIA labels for accessible and stable selection",
            selector_patterns=[r"aria-label", r"role="],
            wait_strategies=[],
            assertion_patterns=[],
            page_types=["all"],
            categories=["accessibility"],
        ),
        SuccessPattern(
            pattern_id="sp_network_idle",
            name="Network Idle Wait",
            description="Waiting for network idle ensures all resources loaded",
            selector_patterns=[],
            wait_strategies=[r"networkidle", r"load.*complete"],
            assertion_patterns=[],
            page_types=["all"],
            categories=["functional"],
        ),
    ]

    def __init__(self):
        """Initialize the pattern learner."""
        self.failure_patterns = {
            p.pattern_id: p for p in self.KNOWN_FAILURE_PATTERNS
        }
        self.success_patterns = {
            p.pattern_id: p for p in self.KNOWN_SUCCESS_PATTERNS
        }
        self.learned_rules: List[LearnedRule] = []

        # Learning statistics
        self._stats = {
            "failures_analyzed": 0,
            "successes_analyzed": 0,
            "patterns_matched": 0,
            "rules_generated": 0,
        }

    def analyze_failure(
        self,
        error_message: str,
        selector: str = "",
        action: str = "",
        page_type: str = "",
        category: str = "",
    ) -> List[FailurePattern]:
        """
        Analyze a test failure and return matching patterns.

        This is how the agent learns what causes failures and how to avoid them.
        """
        self._stats["failures_analyzed"] += 1
        matched = []

        for pattern in self.failure_patterns.values():
            if pattern.matches(error_message, selector, action):
                pattern.record_occurrence()
                matched.append(pattern)
                self._stats["patterns_matched"] += 1

        # If no pattern matched, this might be a new failure type
        if not matched:
            self._learn_new_failure_pattern(
                error_message, selector, action, page_type, category
            )

        return matched

    def _learn_new_failure_pattern(
        self,
        error_message: str,
        selector: str,
        action: str,
        page_type: str,
        category: str,
    ) -> Optional[FailurePattern]:
        """Learn a new failure pattern from an unrecognized error."""
        # Extract key terms from error message
        key_terms = self._extract_key_terms(error_message)

        if not key_terms:
            return None

        # Generate pattern ID
        pattern_id = f"fp_learned_{len(self.failure_patterns)}"

        # Create new pattern
        new_pattern = FailurePattern(
            pattern_id=pattern_id,
            name=f"Learned: {key_terms[0].title()} Error",
            description=f"Auto-learned pattern from: {error_message[:100]}",
            error_patterns=[re.escape(term) for term in key_terms],
            selector_patterns=[re.escape(selector)] if selector else [],
            action_patterns=[re.escape(action)] if action else [],
            prevention_strategies=[
                "Review test implementation for this specific case",
                "Check application behavior manually",
            ],
            confidence=0.3,  # Low confidence for learned patterns
        )

        new_pattern.record_occurrence()
        self.failure_patterns[pattern_id] = new_pattern

        return new_pattern

    def _extract_key_terms(self, text: str) -> List[str]:
        """Extract key terms from error text for pattern matching."""
        # Remove common words
        stop_words = {
            "the", "a", "an", "is", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "shall", "can",
            "to", "of", "in", "for", "on", "with", "at", "by", "from",
            "as", "into", "through", "during", "before", "after", "above",
            "below", "between", "under", "again", "further", "then", "once",
            "here", "there", "when", "where", "why", "how", "all", "each",
            "few", "more", "most", "other", "some", "such", "no", "nor",
            "not", "only", "own", "same", "so", "than", "too", "very",
        }

        # Extract words
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())

        # Filter and get unique
        key_terms = []
        seen = set()
        for word in words:
            if word not in stop_words and word not in seen:
                key_terms.append(word)
                seen.add(word)
                if len(key_terms) >= 3:
                    break

        return key_terms

    def analyze_success(
        self,
        test_code: str,
        page_type: str = "",
        category: str = "",
    ) -> List[SuccessPattern]:
        """
        Analyze a successful test to identify what made it work.

        This helps the agent understand what patterns lead to reliable tests.
        """
        self._stats["successes_analyzed"] += 1
        matched = []

        for pattern in self.success_patterns.values():
            # Check selector patterns
            for sp in pattern.selector_patterns:
                if re.search(sp, test_code, re.IGNORECASE):
                    pattern.record_success()
                    matched.append(pattern)
                    break

            # Check wait strategies
            for ws in pattern.wait_strategies:
                if re.search(ws, test_code, re.IGNORECASE):
                    pattern.record_success()
                    if pattern not in matched:
                        matched.append(pattern)
                    break

        return matched

    def generate_rules_from_patterns(self) -> List[LearnedRule]:
        """
        Generate new testing rules based on observed patterns.

        This is where the agent creates new knowledge from experience.
        """
        new_rules = []

        # Generate rules from high-confidence failure patterns
        for pattern in self.failure_patterns.values():
            if pattern.confidence >= 0.7 and pattern.occurrence_count >= 3:
                for strategy in pattern.prevention_strategies:
                    rule = LearnedRule(
                        rule_id=f"lr_{pattern.pattern_id}_{len(self.learned_rules)}",
                        rule_text=f"When testing: {strategy}",
                        category="prevention",
                        learned_from=pattern.pattern_id,
                        evidence_count=pattern.occurrence_count,
                        confidence=pattern.confidence,
                    )
                    self.learned_rules.append(rule)
                    new_rules.append(rule)
                    self._stats["rules_generated"] += 1

        # Generate rules from high-confidence success patterns
        for pattern in self.success_patterns.values():
            if pattern.confidence >= 0.7 and pattern.success_count >= 5:
                rule = LearnedRule(
                    rule_id=f"lr_{pattern.pattern_id}_{len(self.learned_rules)}",
                    rule_text=f"Best practice: {pattern.description}",
                    category="best_practice",
                    learned_from=pattern.pattern_id,
                    evidence_count=pattern.success_count,
                    confidence=pattern.confidence,
                )
                self.learned_rules.append(rule)
                new_rules.append(rule)
                self._stats["rules_generated"] += 1

        return new_rules

    def get_prevention_strategies(self, error_message: str) -> List[str]:
        """Get prevention strategies for a given error."""
        strategies = []

        for pattern in self.failure_patterns.values():
            if pattern.matches(error_message):
                strategies.extend(pattern.prevention_strategies)

        return list(set(strategies))

    def get_best_practices(self, page_type: str = "", category: str = "") -> List[str]:
        """Get best practices based on learned patterns."""
        practices = []

        for pattern in self.success_patterns.values():
            if page_type and "all" not in pattern.page_types:
                if page_type not in pattern.page_types:
                    continue

            if category and "all" not in pattern.categories:
                if category not in pattern.categories:
                    continue

            practices.append(pattern.description)

        return practices

    def get_learned_rules(
        self,
        category: Optional[str] = None,
        min_confidence: float = 0.5,
    ) -> List[LearnedRule]:
        """Get learned rules with optional filtering."""
        rules = self.learned_rules

        if category:
            rules = [r for r in rules if r.category == category]

        rules = [r for r in rules if r.confidence >= min_confidence]

        return sorted(rules, key=lambda x: x.confidence, reverse=True)

    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        return {
            **self._stats,
            "known_failure_patterns": len(self.KNOWN_FAILURE_PATTERNS),
            "learned_failure_patterns": len(self.failure_patterns) - len(self.KNOWN_FAILURE_PATTERNS),
            "success_patterns": len(self.success_patterns),
            "learned_rules": len(self.learned_rules),
        }

    def export_knowledge(self) -> Dict[str, Any]:
        """Export all learned knowledge for persistence or sharing."""
        return {
            "failure_patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "name": p.name,
                    "description": p.description,
                    "occurrence_count": p.occurrence_count,
                    "confidence": p.confidence,
                    "prevention_strategies": p.prevention_strategies,
                }
                for p in self.failure_patterns.values()
            ],
            "success_patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "name": p.name,
                    "description": p.description,
                    "success_count": p.success_count,
                    "confidence": p.confidence,
                }
                for p in self.success_patterns.values()
            ],
            "learned_rules": [
                {
                    "rule_id": r.rule_id,
                    "rule_text": r.rule_text,
                    "category": r.category,
                    "confidence": r.confidence,
                }
                for r in self.learned_rules
            ],
            "stats": self._stats,
        }


def create_pattern_learner() -> PatternLearner:
    """Create a pattern learner instance."""
    return PatternLearner()
