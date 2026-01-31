"""
TestAI Agent - Visible Thinking Display

Shows the agent's reasoning process in real-time:
- What it's analyzing
- What it's searching for
- What it found
- How confident it is

This is key to the "human-like" experience - humans show their thinking,
not just results. European design: minimal, clean, purposeful.
"""

import sys
import time
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from enum import Enum
from contextlib import contextmanager


class ThinkingPhase(Enum):
    """Phases of the thinking process."""
    UNDERSTANDING = "understanding"      # Understanding the request
    SEARCHING = "searching"             # Searching knowledge base
    ANALYZING = "analyzing"             # Analyzing findings
    REASONING = "reasoning"             # Reasoning about approach
    GENERATING = "generating"           # Generating output
    VALIDATING = "validating"           # Validating results
    CITING = "citing"                   # Finding citations
    COMPLETE = "complete"               # Done


@dataclass
class ThinkingStep:
    """A single step in the thinking process."""
    phase: ThinkingPhase
    message: str
    detail: Optional[str] = None
    confidence: Optional[float] = None
    duration_ms: int = 0
    source: Optional[str] = None  # Citation source


@dataclass
class ThinkingSession:
    """A complete thinking session."""
    steps: List[ThinkingStep] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    total_sources: int = 0
    avg_confidence: float = 0.0

    def add_step(self, step: ThinkingStep):
        """Add a thinking step."""
        self.steps.append(step)
        if step.confidence:
            confidences = [s.confidence for s in self.steps if s.confidence]
            self.avg_confidence = sum(confidences) / len(confidences)

    def duration_seconds(self) -> float:
        """Total duration in seconds."""
        return time.time() - self.start_time


class ThinkingDisplay:
    """
    Real-time display of agent thinking process.

    Key principles:
    1. Show progress, not just results
    2. Be informative, not overwhelming
    3. European minimal aesthetic
    4. Make confidence visible
    5. Cite sources as they're found

    Usage:
        display = ThinkingDisplay()

        with display.thinking_context("Analyzing login page"):
            display.update("Searching QA Brain...")
            display.found_source("Section 15 - Login Page Specific", 0.92)
            display.update("Found 5 relevant test patterns")
            display.progress(0.5)
            display.update("Generating test cases...")

        display.complete("Generated 12 test cases")
    """

    # Phase icons
    PHASE_ICONS = {
        ThinkingPhase.UNDERSTANDING: "🤔",
        ThinkingPhase.SEARCHING: "🔍",
        ThinkingPhase.ANALYZING: "📊",
        ThinkingPhase.REASONING: "💭",
        ThinkingPhase.GENERATING: "✍️",
        ThinkingPhase.VALIDATING: "✓",
        ThinkingPhase.CITING: "📚",
        ThinkingPhase.COMPLETE: "✅",
    }

    # Phase messages (randomized for human feel)
    PHASE_MESSAGES = {
        ThinkingPhase.UNDERSTANDING: [
            "Let me understand what you need...",
            "Processing your request...",
            "Analyzing the requirements...",
            "Understanding the context...",
        ],
        ThinkingPhase.SEARCHING: [
            "Consulting the QA knowledge base...",
            "Searching for relevant testing patterns...",
            "Looking up best practices...",
            "Querying the Brain...",
        ],
        ThinkingPhase.ANALYZING: [
            "Analyzing what I found...",
            "Examining the patterns...",
            "Evaluating the results...",
            "Processing the information...",
        ],
        ThinkingPhase.REASONING: [
            "Thinking about the best approach...",
            "Reasoning through the scenarios...",
            "Considering edge cases...",
            "Planning the test coverage...",
        ],
        ThinkingPhase.GENERATING: [
            "Generating test cases...",
            "Creating the test plan...",
            "Writing test scenarios...",
            "Building comprehensive coverage...",
        ],
        ThinkingPhase.VALIDATING: [
            "Validating the results...",
            "Checking for completeness...",
            "Verifying coverage...",
            "Final quality check...",
        ],
        ThinkingPhase.CITING: [
            "Documenting sources...",
            "Adding citations...",
            "Recording the knowledge sources...",
        ],
    }

    # ANSI colors (European muted palette)
    COLORS = {
        "thinking": "\033[38;5;67m",    # Muted blue
        "source": "\033[38;5;108m",      # Sage green
        "progress": "\033[38;5;180m",    # Warm amber
        "confidence": "\033[38;5;174m",  # Muted coral
        "dim": "\033[2m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    def __init__(
        self,
        use_color: bool = True,
        use_icons: bool = True,
        verbose: bool = True,
        stream: bool = True,
    ):
        """
        Initialize the display.

        Args:
            use_color: Use ANSI colors
            use_icons: Use emoji icons
            verbose: Show detailed thinking
            stream: Stream output in real-time
        """
        self.use_color = use_color
        self.use_icons = use_icons
        self.verbose = verbose
        self.stream = stream
        self.session: Optional[ThinkingSession] = None
        self._spinner_active = False
        self._spinner_thread: Optional[threading.Thread] = None

    def _color(self, name: str, text: str) -> str:
        """Apply color to text."""
        if not self.use_color:
            return text
        color = self.COLORS.get(name, "")
        return f"{color}{text}{self.COLORS['reset']}"

    def _icon(self, phase: ThinkingPhase) -> str:
        """Get icon for phase."""
        if not self.use_icons:
            return ""
        return self.PHASE_ICONS.get(phase, "•")

    def _write(self, text: str, end: str = "\n"):
        """Write to output."""
        if self.stream:
            sys.stdout.write(text + end)
            sys.stdout.flush()

    def _clear_line(self):
        """Clear the current line."""
        if self.stream:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()

    # ─────────────────────────────────────────────────────────────
    # Main Display Methods
    # ─────────────────────────────────────────────────────────────

    def start_thinking(self, context: str = ""):
        """Start a new thinking session."""
        self.session = ThinkingSession()
        if context:
            self._write(self._color("thinking", f"{self._icon(ThinkingPhase.UNDERSTANDING)} {context}"))

    def think(self, phase: ThinkingPhase, message: Optional[str] = None):
        """
        Show a thinking step.

        Args:
            phase: Current phase
            message: Optional custom message
        """
        if not self.verbose:
            return

        import random
        if not message:
            messages = self.PHASE_MESSAGES.get(phase, ["Processing..."])
            message = random.choice(messages)

        icon = self._icon(phase)
        output = self._color("thinking", f"  {icon} {message}")
        self._write(output)

        if self.session:
            self.session.add_step(ThinkingStep(phase=phase, message=message))

    def update(self, message: str):
        """Update with a simple message."""
        if not self.verbose:
            return
        self._write(self._color("dim", f"    → {message}"))

    def found_source(self, source: str, confidence: float):
        """Show a found source/citation."""
        if not self.verbose:
            return

        conf_pct = f"{confidence * 100:.0f}%"
        icon = self._icon(ThinkingPhase.CITING)
        output = self._color("source", f"    {icon} Source: {source} ({conf_pct} match)")
        self._write(output)

        if self.session:
            self.session.total_sources += 1
            self.session.add_step(ThinkingStep(
                phase=ThinkingPhase.CITING,
                message=f"Found: {source}",
                confidence=confidence,
                source=source,
            ))

    def show_confidence(self, level: str, score: float, reason: str = ""):
        """Show confidence assessment."""
        if not self.verbose:
            return

        # Confidence bar
        bar_width = 20
        filled = int(score * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        score_pct = f"{score * 100:.0f}%"
        output = f"  Confidence: [{bar}] {score_pct} ({level})"
        if reason:
            output += f"\n    {reason}"

        self._write(self._color("confidence", output))

    def progress(self, pct: float, message: str = ""):
        """Show progress indicator."""
        if not self.verbose:
            return

        bar_width = 30
        filled = int(pct * bar_width)
        bar = "━" * filled + "╺" + "─" * (bar_width - filled - 1)

        pct_str = f"{pct * 100:.0f}%"
        output = f"  [{bar}] {pct_str}"
        if message:
            output += f" {message}"

        self._clear_line()
        self._write(self._color("progress", output), end="")
        if pct >= 1.0:
            self._write("")  # New line when complete

    def complete(self, message: str = "Done"):
        """Mark thinking as complete."""
        icon = self._icon(ThinkingPhase.COMPLETE)

        if self.session:
            duration = self.session.duration_seconds()
            sources = self.session.total_sources
            output = f"{icon} {message}"
            if duration > 0.1:
                output += f" ({duration:.1f}s, {sources} sources)"
        else:
            output = f"{icon} {message}"

        self._write(self._color("source", output))
        self._write("")  # Blank line after

    def error(self, message: str):
        """Show an error."""
        self._write(self._color("confidence", f"  ✗ Error: {message}"))

    def warning(self, message: str):
        """Show a warning."""
        self._write(self._color("progress", f"  ⚠ {message}"))

    # ─────────────────────────────────────────────────────────────
    # Context Managers
    # ─────────────────────────────────────────────────────────────

    @contextmanager
    def thinking_context(self, description: str):
        """
        Context manager for a thinking block.

        Usage:
            with display.thinking_context("Analyzing request"):
                display.update("Processing...")
                display.found_source("Section 1", 0.9)
        """
        self.start_thinking(description)
        try:
            yield self
        except Exception as e:
            self.error(str(e))
            raise
        finally:
            pass  # Don't auto-complete, let caller do it

    @contextmanager
    def spinner(self, message: str = "Processing"):
        """
        Show a spinner while processing.

        Usage:
            with display.spinner("Generating"):
                # Long operation
                pass
        """
        if not self.verbose or not self.stream:
            yield
            return

        self._spinner_active = True
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

        def spin():
            i = 0
            while self._spinner_active:
                frame = frames[i % len(frames)]
                sys.stdout.write(f"\r  {frame} {message}...")
                sys.stdout.flush()
                time.sleep(0.1)
                i += 1
            sys.stdout.write("\r" + " " * 50 + "\r")
            sys.stdout.flush()

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

        try:
            yield
        finally:
            self._spinner_active = False
            if self._spinner_thread:
                self._spinner_thread.join(timeout=0.5)

    # ─────────────────────────────────────────────────────────────
    # Pre-built Sequences
    # ─────────────────────────────────────────────────────────────

    def show_analysis_sequence(
        self,
        feature: str,
        sources_found: int,
        confidence: float,
        on_step: Optional[Callable[[str], None]] = None,
    ):
        """
        Show a complete analysis sequence.

        Args:
            feature: Feature being analyzed
            sources_found: Number of sources found
            confidence: Overall confidence
            on_step: Optional callback for each step
        """
        steps = [
            (ThinkingPhase.UNDERSTANDING, f"Understanding '{feature}'..."),
            (ThinkingPhase.SEARCHING, None),
            (ThinkingPhase.ANALYZING, f"Found {sources_found} relevant knowledge chunks"),
            (ThinkingPhase.REASONING, None),
        ]

        for phase, message in steps:
            self.think(phase, message)
            if on_step:
                on_step(phase.value)
            time.sleep(0.3)  # Small delay for human feel

        # Show confidence
        level = "HIGH" if confidence > 0.7 else "MODERATE" if confidence > 0.4 else "LOW"
        self.show_confidence(level, confidence)

    def show_generation_sequence(
        self,
        test_count: int,
        categories: List[str],
    ):
        """Show test generation sequence."""
        self.think(ThinkingPhase.GENERATING, f"Generating {test_count} test cases...")
        time.sleep(0.2)

        for i, cat in enumerate(categories):
            pct = (i + 1) / len(categories)
            self.progress(pct, f"Processing {cat}...")
            time.sleep(0.1)

        self.progress(1.0, "Complete")
        self.complete(f"Generated {test_count} tests across {len(categories)} categories")


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_display(verbose: bool = True) -> ThinkingDisplay:
    """Create a thinking display instance."""
    return ThinkingDisplay(verbose=verbose)


def show_thinking(message: str, phase: ThinkingPhase = ThinkingPhase.REASONING):
    """Quick function to show a thinking message."""
    display = ThinkingDisplay()
    display.think(phase, message)


if __name__ == "__main__":
    # Demo
    print("=" * 60)
    print("Thinking Display Demo")
    print("=" * 60)
    print()

    display = ThinkingDisplay()

    # Full sequence demo
    with display.thinking_context("Analyzing login page feature"):
        display.think(ThinkingPhase.UNDERSTANDING)
        time.sleep(0.5)

        display.think(ThinkingPhase.SEARCHING)
        time.sleep(0.5)

        display.update("Querying ChromaDB...")
        time.sleep(0.3)

        display.found_source("Section 15.1 - Login Happy Path Tests", 0.92)
        display.found_source("Section 15.3 - Login Security Tests", 0.88)
        display.found_source("Section 2.1 - SQL Injection Prevention", 0.85)
        time.sleep(0.3)

        display.think(ThinkingPhase.ANALYZING, "Found 3 relevant sections")
        time.sleep(0.3)

        display.show_confidence("HIGH", 0.88, "Multiple high-confidence sources found")
        time.sleep(0.3)

        display.think(ThinkingPhase.GENERATING)

        # Progress bar
        for i in range(11):
            display.progress(i / 10, f"Generating test {i}/10")
            time.sleep(0.1)

        display.complete("Generated 10 test cases from 3 knowledge sources")

    print()
    print("Demo complete!")
