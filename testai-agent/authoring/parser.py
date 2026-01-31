"""
TestAI Agent - Natural Language Test Parser

Parses natural language test descriptions into
structured test definitions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import re


class ActionIntent(Enum):
    """Detected action intents."""
    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    SCROLL = "scroll"
    WAIT = "wait"
    HOVER = "hover"
    DRAG = "drag"
    UPLOAD = "upload"
    SCREENSHOT = "screenshot"
    ASSERT = "assert"
    UNKNOWN = "unknown"


class AssertionType(Enum):
    """Types of assertions."""
    VISIBLE = "visible"
    HIDDEN = "hidden"
    TEXT_CONTAINS = "text_contains"
    TEXT_EQUALS = "text_equals"
    VALUE_EQUALS = "value_equals"
    URL_CONTAINS = "url_contains"
    URL_EQUALS = "url_equals"
    TITLE_CONTAINS = "title_contains"
    ENABLED = "enabled"
    DISABLED = "disabled"
    CHECKED = "checked"
    EXISTS = "exists"


@dataclass
class ParsedAssertion:
    """A parsed assertion."""
    assertion_type: AssertionType
    target: Optional[str]
    expected_value: Optional[str]
    original_text: str


@dataclass
class ParsedStep:
    """A parsed test step."""
    step_number: int
    action: ActionIntent
    target: Optional[str]
    value: Optional[str]
    original_text: str
    assertions: List[ParsedAssertion] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedTest:
    """A parsed test definition."""
    name: str
    description: str
    steps: List[ParsedStep]
    preconditions: List[str]
    tags: List[str]
    priority: str
    original_text: str
    parse_confidence: float
    warnings: List[str] = field(default_factory=list)


class NLTestParser:
    """
    Parses natural language into test definitions.

    Features:
    - Intent detection
    - Target extraction
    - Assertion parsing
    - Multi-language support
    """

    # Action keywords mapping
    ACTION_PATTERNS = {
        ActionIntent.NAVIGATE: [
            r"go to",
            r"navigate to",
            r"open",
            r"visit",
            r"browse to",
            r"load",
        ],
        ActionIntent.CLICK: [
            r"click",
            r"tap",
            r"press",
            r"hit",
            r"select",
        ],
        ActionIntent.TYPE: [
            r"type",
            r"enter",
            r"input",
            r"fill",
            r"write",
        ],
        ActionIntent.SELECT: [
            r"select",
            r"choose",
            r"pick",
            r"dropdown",
        ],
        ActionIntent.SCROLL: [
            r"scroll",
            r"swipe",
        ],
        ActionIntent.WAIT: [
            r"wait",
            r"pause",
            r"delay",
        ],
        ActionIntent.HOVER: [
            r"hover",
            r"mouse over",
            r"move to",
        ],
        ActionIntent.DRAG: [
            r"drag",
            r"move",
        ],
        ActionIntent.UPLOAD: [
            r"upload",
            r"attach",
        ],
        ActionIntent.SCREENSHOT: [
            r"screenshot",
            r"capture",
            r"snap",
        ],
        ActionIntent.ASSERT: [
            r"verify",
            r"check",
            r"assert",
            r"ensure",
            r"confirm",
            r"should",
            r"must",
            r"expect",
        ],
    }

    # Assertion patterns
    ASSERTION_PATTERNS = {
        AssertionType.VISIBLE: [
            r"is visible",
            r"should be visible",
            r"can see",
            r"is displayed",
            r"appears",
        ],
        AssertionType.HIDDEN: [
            r"is hidden",
            r"is not visible",
            r"should not be visible",
            r"disappears",
        ],
        AssertionType.TEXT_CONTAINS: [
            r"contains? (?:text |the text )?['\"](.+?)['\"]",
            r"has text",
            r"shows",
            r"displays",
        ],
        AssertionType.TEXT_EQUALS: [
            r"equals? ['\"](.+?)['\"]",
            r"is exactly",
            r"matches exactly",
        ],
        AssertionType.URL_CONTAINS: [
            r"url contains",
            r"in the url",
        ],
        AssertionType.URL_EQUALS: [
            r"url is",
            r"url equals",
            r"on page",
        ],
        AssertionType.ENABLED: [
            r"is enabled",
            r"should be enabled",
            r"is active",
        ],
        AssertionType.DISABLED: [
            r"is disabled",
            r"should be disabled",
            r"is inactive",
        ],
        AssertionType.CHECKED: [
            r"is checked",
            r"should be checked",
            r"is selected",
        ],
    }

    # Target extraction patterns
    TARGET_PATTERNS = [
        r"(?:the |a |an )?['\"](.+?)['\"]",  # Quoted text
        r"(?:the |a |an )?(\w+) (?:button|link|field|input|checkbox|dropdown)",
        r"(?:on |in )(?:the )?(\w+)",
        r"#(\w+)",  # ID selector
        r"\.(\w+)",  # Class selector
    ]

    def __init__(self):
        """Initialize the parser."""
        self._compiled_actions = self._compile_patterns(self.ACTION_PATTERNS)
        self._compiled_assertions = self._compile_patterns(self.ASSERTION_PATTERNS)
        self._compiled_targets = [re.compile(p, re.IGNORECASE) for p in self.TARGET_PATTERNS]

    def _compile_patterns(self, patterns: Dict) -> Dict:
        """Compile regex patterns."""
        compiled = {}
        for key, pattern_list in patterns.items():
            compiled[key] = [re.compile(p, re.IGNORECASE) for p in pattern_list]
        return compiled

    def parse(self, text: str) -> ParsedTest:
        """Parse natural language text into a test definition."""
        lines = [line.strip() for line in text.strip().split("\n") if line.strip()]

        if not lines:
            return ParsedTest(
                name="Untitled Test",
                description="",
                steps=[],
                preconditions=[],
                tags=[],
                priority="medium",
                original_text=text,
                parse_confidence=0.0,
                warnings=["Empty input"],
            )

        # Extract metadata from first lines
        name, description, start_index = self._extract_header(lines)

        # Parse steps
        steps = []
        preconditions = []
        warnings = []
        step_number = 0

        for i, line in enumerate(lines[start_index:], start_index):
            # Check for preconditions
            if self._is_precondition(line):
                preconditions.append(self._clean_precondition(line))
                continue

            # Parse as step
            step_number += 1
            parsed_step = self._parse_step(line, step_number)
            steps.append(parsed_step)

            if parsed_step.confidence < 0.5:
                warnings.append(f"Low confidence for step {step_number}: '{line[:50]}...'")

        # Extract tags and priority
        tags = self._extract_tags(text)
        priority = self._extract_priority(text)

        # Calculate overall confidence
        if steps:
            avg_confidence = sum(s.confidence for s in steps) / len(steps)
        else:
            avg_confidence = 0.0

        return ParsedTest(
            name=name,
            description=description,
            steps=steps,
            preconditions=preconditions,
            tags=tags,
            priority=priority,
            original_text=text,
            parse_confidence=avg_confidence,
            warnings=warnings,
        )

    def _extract_header(self, lines: List[str]) -> Tuple[str, str, int]:
        """Extract test name and description from header lines."""
        name = "Untitled Test"
        description = ""
        start_index = 0

        # Check for title patterns
        title_patterns = [
            r"^(?:test[:\s]+)?(.+)$",
            r"^#\s*(.+)$",
        ]

        if lines:
            # First line is usually the title
            first_line = lines[0]

            # Skip if it's a step
            if not self._looks_like_step(first_line):
                for pattern in title_patterns:
                    match = re.match(pattern, first_line, re.IGNORECASE)
                    if match:
                        name = match.group(1).strip()
                        start_index = 1
                        break

            # Second line might be description
            if start_index == 1 and len(lines) > 1:
                second_line = lines[1]
                if not self._looks_like_step(second_line):
                    description = second_line
                    start_index = 2

        return name, description, start_index

    def _looks_like_step(self, line: str) -> bool:
        """Check if a line looks like a test step."""
        # Check for numbered step
        if re.match(r"^\d+[\.\)]\s+", line):
            return True

        # Check for action keywords
        line_lower = line.lower()
        for action, patterns in self._compiled_actions.items():
            for pattern in patterns:
                if pattern.search(line_lower):
                    return True

        return False

    def _is_precondition(self, line: str) -> bool:
        """Check if a line is a precondition."""
        precondition_markers = [
            r"^given\s+",
            r"^precondition:\s+",
            r"^prerequisite:\s+",
            r"^assuming\s+",
            r"^when\s+.*\s+is\s+",
        ]

        for marker in precondition_markers:
            if re.match(marker, line.lower()):
                return True

        return False

    def _clean_precondition(self, line: str) -> str:
        """Clean up precondition text."""
        # Remove markers
        cleaned = re.sub(
            r"^(?:given|precondition:|prerequisite:|assuming)\s+",
            "",
            line,
            flags=re.IGNORECASE,
        )
        return cleaned.strip()

    def _parse_step(self, line: str, step_number: int) -> ParsedStep:
        """Parse a single step line."""
        # Clean step number if present
        clean_line = re.sub(r"^\d+[\.\)]\s*", "", line)

        # Detect action intent
        action, action_confidence = self._detect_action(clean_line)

        # Extract target
        target = self._extract_target(clean_line)

        # Extract value
        value = self._extract_value(clean_line, action)

        # Extract assertions
        assertions = self._parse_assertions(clean_line)

        # Calculate confidence
        confidence = action_confidence
        if target:
            confidence += 0.2
        if action != ActionIntent.UNKNOWN:
            confidence += 0.2

        return ParsedStep(
            step_number=step_number,
            action=action,
            target=target,
            value=value,
            original_text=line,
            assertions=assertions,
            confidence=min(confidence, 1.0),
        )

    def _detect_action(self, text: str) -> Tuple[ActionIntent, float]:
        """Detect action intent from text."""
        text_lower = text.lower()

        for action, patterns in self._compiled_actions.items():
            for pattern in patterns:
                if pattern.search(text_lower):
                    return action, 0.8

        return ActionIntent.UNKNOWN, 0.2

    def _extract_target(self, text: str) -> Optional[str]:
        """Extract target element from text."""
        for pattern in self._compiled_targets:
            match = pattern.search(text)
            if match:
                return match.group(1)

        # Try to find quoted text
        quoted = re.search(r"['\"](.+?)['\"]", text)
        if quoted:
            return quoted.group(1)

        return None

    def _extract_value(self, text: str, action: ActionIntent) -> Optional[str]:
        """Extract value for the action."""
        if action in [ActionIntent.TYPE, ActionIntent.SELECT]:
            # Look for value after "with" or in quotes
            patterns = [
                r"with\s+['\"](.+?)['\"]",
                r"(?:type|enter|input)\s+['\"](.+?)['\"]",
                r"value\s+['\"](.+?)['\"]",
            ]
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)

        elif action == ActionIntent.NAVIGATE:
            # Look for URL
            url_pattern = r"(https?://[^\s]+)"
            match = re.search(url_pattern, text)
            if match:
                return match.group(1)

            # Look for quoted path
            path_pattern = r"['\"]([/\w\-\.]+)['\"]"
            match = re.search(path_pattern, text)
            if match:
                return match.group(1)

        elif action == ActionIntent.WAIT:
            # Look for duration
            time_pattern = r"(\d+)\s*(?:seconds?|s|ms|milliseconds?)"
            match = re.search(time_pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _parse_assertions(self, text: str) -> List[ParsedAssertion]:
        """Parse assertions from text."""
        assertions = []
        text_lower = text.lower()

        for assertion_type, patterns in self._compiled_assertions.items():
            for pattern in patterns:
                match = pattern.search(text_lower)
                if match:
                    # Extract expected value if present
                    expected = None
                    if match.groups():
                        expected = match.group(1)

                    # Extract target
                    target = self._extract_target(text)

                    assertions.append(ParsedAssertion(
                        assertion_type=assertion_type,
                        target=target,
                        expected_value=expected,
                        original_text=text,
                    ))

        return assertions

    def _extract_tags(self, text: str) -> List[str]:
        """Extract tags from text."""
        tags = []

        # Look for explicit tags
        tag_pattern = r"@(\w+)"
        tags.extend(re.findall(tag_pattern, text))

        # Look for [tag] format
        bracket_pattern = r"\[(\w+)\]"
        tags.extend(re.findall(bracket_pattern, text))

        # Infer tags from content
        if "login" in text.lower():
            tags.append("authentication")
        if "checkout" in text.lower() or "payment" in text.lower():
            tags.append("e-commerce")
        if "api" in text.lower():
            tags.append("api")

        return list(set(tags))

    def _extract_priority(self, text: str) -> str:
        """Extract priority from text."""
        text_lower = text.lower()

        if any(p in text_lower for p in ["critical", "p0", "urgent"]):
            return "critical"
        elif any(p in text_lower for p in ["high", "important", "p1"]):
            return "high"
        elif any(p in text_lower for p in ["low", "minor", "p3"]):
            return "low"

        return "medium"

    def parse_batch(self, texts: List[str]) -> List[ParsedTest]:
        """Parse multiple test descriptions."""
        return [self.parse(text) for text in texts]

    def get_statistics(self, parsed: ParsedTest) -> Dict[str, Any]:
        """Get parsing statistics."""
        action_counts = {}
        for step in parsed.steps:
            action = step.action.value
            action_counts[action] = action_counts.get(action, 0) + 1

        return {
            "total_steps": len(parsed.steps),
            "total_assertions": sum(len(s.assertions) for s in parsed.steps),
            "preconditions": len(parsed.preconditions),
            "avg_confidence": parsed.parse_confidence,
            "warnings": len(parsed.warnings),
            "actions_by_type": action_counts,
        }

    def format_parsed(self, parsed: ParsedTest) -> str:
        """Format parsed test as readable text."""
        lines = [
            "=" * 60,
            f"  PARSED TEST: {parsed.name}",
            "=" * 60,
            "",
        ]

        if parsed.description:
            lines.extend([f"  Description: {parsed.description}", ""])

        if parsed.preconditions:
            lines.append("  Preconditions:")
            for pre in parsed.preconditions:
                lines.append(f"    - {pre}")
            lines.append("")

        lines.extend([
            f"  Priority: {parsed.priority}",
            f"  Tags: {', '.join(parsed.tags) if parsed.tags else 'none'}",
            f"  Confidence: {parsed.parse_confidence:.1%}",
            "",
        ])

        if parsed.steps:
            lines.extend(["-" * 60, "  STEPS", "-" * 60])

            for step in parsed.steps:
                confidence_icon = "🟢" if step.confidence > 0.7 else "🟡" if step.confidence > 0.4 else "🔴"
                lines.extend([
                    "",
                    f"  {step.step_number}. {step.action.value.upper()}",
                    f"     {confidence_icon} Confidence: {step.confidence:.1%}",
                ])

                if step.target:
                    lines.append(f"     Target: {step.target}")
                if step.value:
                    lines.append(f"     Value: {step.value}")
                if step.assertions:
                    lines.append(f"     Assertions: {len(step.assertions)}")

        if parsed.warnings:
            lines.extend(["", "-" * 60, "  WARNINGS", "-" * 60])
            for warning in parsed.warnings:
                lines.append(f"  ⚠️ {warning}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_nl_parser() -> NLTestParser:
    """Create a natural language parser instance."""
    return NLTestParser()
