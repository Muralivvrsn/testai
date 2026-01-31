"""
TestAI Agent - Human Response Formatting

Formats responses to feel natural and readable.
European design: clean, minimal, purposeful.

Key Principles:
- Progressive disclosure (summary → details on request)
- Visual hierarchy (important things first)
- Breathing room (whitespace is your friend)
- Scannable (headers, bullets, not walls of text)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class OutputStyle(Enum):
    """How to format output."""
    COMPACT = "compact"      # Minimal, just the essentials
    STANDARD = "standard"    # Balanced detail
    DETAILED = "detailed"    # Full information
    JSON = "json"            # Machine-readable


@dataclass
class HumanResponse:
    """
    A response formatted for human consumption.

    Supports progressive disclosure:
    - summary: Quick overview (always shown)
    - details: More information (shown on request)
    - raw_data: Full data (for export/tools)
    """
    summary: str
    details: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    follow_up: Optional[str] = None
    confidence_note: Optional[str] = None

    def __str__(self) -> str:
        """Default string is just the summary."""
        parts = [self.summary]

        if self.confidence_note:
            parts.append(f"\n{self.confidence_note}")

        if self.follow_up:
            parts.append(f"\n{self.follow_up}")

        return "\n".join(parts)

    def full(self) -> str:
        """Get full response with details."""
        parts = [self.summary]

        if self.details:
            parts.append(f"\n{self.details}")

        if self.confidence_note:
            parts.append(f"\n{self.confidence_note}")

        if self.follow_up:
            parts.append(f"\n{self.follow_up}")

        return "\n".join(parts)


def format_thinking(thought: str) -> str:
    """
    Format a thinking step for display.

    Shows the agent's reasoning in a subtle way.
    """
    # Add subtle indicator
    lines = thought.split("\n")
    formatted = []
    for line in lines:
        formatted.append(f"  💭 {line}")

    return "\n".join(formatted)


def format_test_cases(
    tests: List[Dict[str, Any]],
    style: OutputStyle = OutputStyle.STANDARD,
    max_show: int = 5,
) -> HumanResponse:
    """
    Format test cases for human reading.

    Args:
        tests: List of test case dictionaries
        style: Output style
        max_show: Max tests to show in summary

    Returns:
        HumanResponse with formatted tests
    """
    if not tests:
        return HumanResponse(
            summary="No test cases generated.",
            follow_up="Would you like me to try with different parameters?",
        )

    # Count by priority
    by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}

    for test in tests:
        pri = test.get("priority", "medium").lower()
        cat = test.get("category", "general").lower()
        by_priority[pri] = by_priority.get(pri, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1

    # Build summary
    total = len(tests)
    critical = by_priority.get("critical", 0)
    high = by_priority.get("high", 0)

    summary_parts = [f"Generated {total} test cases."]

    if critical > 0:
        summary_parts.append(f"  ⚠️  {critical} critical priority")
    if high > 0:
        summary_parts.append(f"  ⬆️  {high} high priority")

    # Show top tests
    summary_parts.append("\nTop tests:")
    for i, test in enumerate(tests[:max_show]):
        title = test.get("title", f"Test {i+1}")
        priority = test.get("priority", "medium")
        icon = _priority_icon(priority)
        summary_parts.append(f"  {icon} {title}")

    if total > max_show:
        summary_parts.append(f"  ... and {total - max_show} more")

    summary = "\n".join(summary_parts)

    # Build details (shown on request)
    detail_parts = ["\n" + "─" * 40, "Full Test Suite", "─" * 40 + "\n"]

    for i, test in enumerate(tests):
        detail_parts.append(_format_single_test(test, i + 1, style))

    details = "\n".join(detail_parts)

    # Category breakdown
    cat_summary = ", ".join(f"{cat}: {count}" for cat, count in by_category.items())

    return HumanResponse(
        summary=summary,
        details=details,
        raw_data={"tests": tests, "by_priority": by_priority, "by_category": by_category},
        follow_up=f"Categories: {cat_summary}\n\nWant details on any specific test?",
    )


def _priority_icon(priority: str) -> str:
    """Get icon for priority level."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }.get(priority.lower(), "⚪")


def _format_single_test(
    test: Dict[str, Any],
    number: int,
    style: OutputStyle,
) -> str:
    """Format a single test case."""
    title = test.get("title", f"Test Case {number}")
    priority = test.get("priority", "medium")
    category = test.get("category", "general")
    description = test.get("description", "")
    steps = test.get("steps", [])
    expected = test.get("expected_result", "")

    icon = _priority_icon(priority)

    if style == OutputStyle.COMPACT:
        return f"{icon} TC-{number:03d}: {title}"

    parts = [
        f"\n{icon} TC-{number:03d}: {title}",
        f"   Priority: {priority.upper()} | Category: {category}",
    ]

    if description and style != OutputStyle.COMPACT:
        parts.append(f"   {description}")

    if steps and style == OutputStyle.DETAILED:
        parts.append("   Steps:")
        for j, step in enumerate(steps[:5]):  # Limit steps shown
            parts.append(f"     {j+1}. {step}")
        if len(steps) > 5:
            parts.append(f"     ... {len(steps) - 5} more steps")

    if expected and style == OutputStyle.DETAILED:
        parts.append(f"   Expected: {expected}")

    return "\n".join(parts)


def format_page_analysis(
    page_type: str,
    confidence: float,
    elements: List[Dict[str, Any]],
    style: OutputStyle = OutputStyle.STANDARD,
) -> HumanResponse:
    """
    Format page analysis results.

    Args:
        page_type: Detected page type
        confidence: Confidence score (0-1)
        elements: Found elements
        style: Output style

    Returns:
        HumanResponse with analysis
    """
    # Confidence phrase
    if confidence >= 0.9:
        conf_text = "I'm confident"
    elif confidence >= 0.7:
        conf_text = "I'm fairly sure"
    elif confidence >= 0.5:
        conf_text = "I think"
    else:
        conf_text = "This might be"

    summary = f"{conf_text} this is a {page_type} page."

    # Element breakdown
    by_type = {}
    for el in elements:
        t = el.get("elementType", el.get("type", el.get("tag", "other")))
        by_type[t] = by_type.get(t, 0) + 1

    if by_type:
        summary += f"\n\nFound {len(elements)} testable elements:"
        for el_type, count in sorted(by_type.items(), key=lambda x: -x[1])[:5]:
            summary += f"\n  • {el_type}: {count}"

    # Confidence note
    conf_note = None
    if confidence < 0.7:
        conf_note = "⚠️  I'm not 100% sure about this classification. Can you confirm?"

    # Follow up
    follow_up = "Should I generate test cases for this page?"

    return HumanResponse(
        summary=summary,
        confidence_note=conf_note,
        follow_up=follow_up,
        raw_data={"page_type": page_type, "confidence": confidence, "elements": by_type},
    )


def format_security_findings(
    findings: List[Dict[str, Any]],
    style: OutputStyle = OutputStyle.STANDARD,
) -> HumanResponse:
    """
    Format security analysis findings.

    Args:
        findings: Security findings
        style: Output style

    Returns:
        HumanResponse with findings
    """
    if not findings:
        return HumanResponse(
            summary="No security issues detected.",
            confidence_note="Note: This is based on static analysis. Always perform manual security testing for critical features.",
            follow_up="Want me to generate security-focused test cases anyway?",
        )

    # Categorize by severity
    high = [f for f in findings if f.get("severity", "").lower() in ["high", "critical"]]
    medium = [f for f in findings if f.get("severity", "").lower() == "medium"]
    low = [f for f in findings if f.get("severity", "").lower() == "low"]

    parts = []

    if high:
        parts.append(f"⚠️  Found {len(high)} high-severity issues:")
        for f in high[:3]:
            parts.append(f"   • {f.get('title', 'Security issue')}")

    if medium:
        parts.append(f"\n🟡 Found {len(medium)} medium-severity items to review")

    if low:
        parts.append(f"\n🟢 Found {len(low)} low-priority suggestions")

    summary = "\n".join(parts)

    # Details
    detail_parts = ["Full Security Report", "─" * 30]
    for i, finding in enumerate(findings):
        detail_parts.append(f"\n{i+1}. {finding.get('title', 'Finding')}")
        detail_parts.append(f"   Severity: {finding.get('severity', 'Unknown')}")
        if finding.get("description"):
            detail_parts.append(f"   {finding['description']}")
        if finding.get("recommendation"):
            detail_parts.append(f"   Fix: {finding['recommendation']}")

    details = "\n".join(detail_parts)

    return HumanResponse(
        summary=summary,
        details=details,
        raw_data={"findings": findings, "high": len(high), "medium": len(medium), "low": len(low)},
        follow_up="Want me to prioritize fixes or generate security tests?",
    )


def format_progress(
    current_step: str,
    completed: int,
    total: int,
    eta_seconds: Optional[int] = None,
) -> str:
    """
    Format a progress indicator.

    Args:
        current_step: What's happening now
        completed: Steps completed
        total: Total steps
        eta_seconds: Estimated time remaining

    Returns:
        Formatted progress string
    """
    progress = completed / total if total > 0 else 0
    bar_width = 20
    filled = int(progress * bar_width)

    bar = "█" * filled + "░" * (bar_width - filled)
    pct = int(progress * 100)

    result = f"{bar} {pct}% | {current_step}"

    if eta_seconds:
        if eta_seconds < 60:
            result += f" (~{eta_seconds}s remaining)"
        else:
            mins = eta_seconds // 60
            result += f" (~{mins}m remaining)"

    return result


def format_error(
    error: str,
    suggestion: Optional[str] = None,
    recoverable: bool = True,
) -> HumanResponse:
    """
    Format an error message.

    Args:
        error: The error description
        suggestion: How to fix it
        recoverable: Can we continue?

    Returns:
        HumanResponse with error
    """
    if recoverable:
        summary = f"Small hiccup: {error}"
        follow_up = suggestion or "Should I try a different approach?"
    else:
        summary = f"Ran into an issue: {error}"
        follow_up = suggestion or "Need your help to continue."

    return HumanResponse(
        summary=summary,
        follow_up=follow_up,
        raw_data={"error": error, "recoverable": recoverable},
    )


# Quick format helpers
def bullet_list(items: List[str], prefix: str = "•") -> str:
    """Format a bullet list."""
    return "\n".join(f"  {prefix} {item}" for item in items)


def numbered_list(items: List[str]) -> str:
    """Format a numbered list."""
    return "\n".join(f"  {i+1}. {item}" for i, item in enumerate(items))


def section(title: str, content: str) -> str:
    """Format a section with title."""
    return f"{title}\n{'─' * len(title)}\n{content}"
