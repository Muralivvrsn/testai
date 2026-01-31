"""
TestAI Agent - Real-Time Thinking Stream

Shows the agent's thought process as it happens.
Makes the AI feel human by revealing its reasoning step by step.

Design: European transparency - show the work, build trust.
"""

import sys
import time
import threading
from typing import Optional, List, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ThoughtType(Enum):
    """Types of thoughts the agent can express."""
    UNDERSTANDING = "understanding"   # Processing user input
    SEARCHING = "searching"           # Querying the Brain
    FOUND = "found"                   # Found relevant knowledge
    ANALYZING = "analyzing"           # Analyzing information
    REASONING = "reasoning"           # Drawing conclusions
    DECIDING = "deciding"             # Making decisions
    GENERATING = "generating"         # Creating output
    CITING = "citing"                 # Adding citations
    VALIDATING = "validating"         # Checking quality
    COMPLETE = "complete"             # Done


@dataclass
class Thought:
    """A single thought in the stream."""
    thought_type: ThoughtType
    message: str
    detail: Optional[str] = None
    source: Optional[str] = None  # Brain section citation
    confidence: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def format(self, use_color: bool = True) -> str:
        """Format thought for display."""
        icons = {
            ThoughtType.UNDERSTANDING: "🤔",
            ThoughtType.SEARCHING: "🔍",
            ThoughtType.FOUND: "📚",
            ThoughtType.ANALYZING: "🧠",
            ThoughtType.REASONING: "💭",
            ThoughtType.DECIDING: "⚖️",
            ThoughtType.GENERATING: "✍️",
            ThoughtType.CITING: "📖",
            ThoughtType.VALIDATING: "✓",
            ThoughtType.COMPLETE: "✅",
        }

        icon = icons.get(self.thought_type, "•")

        if use_color:
            colors = {
                ThoughtType.UNDERSTANDING: "\033[38;5;67m",   # Slate blue
                ThoughtType.SEARCHING: "\033[38;5;179m",      # Gold
                ThoughtType.FOUND: "\033[38;5;108m",          # Sage
                ThoughtType.ANALYZING: "\033[38;5;67m",       # Slate
                ThoughtType.REASONING: "\033[38;5;245m",      # Gray
                ThoughtType.DECIDING: "\033[38;5;179m",       # Gold
                ThoughtType.GENERATING: "\033[38;5;108m",     # Sage
                ThoughtType.CITING: "\033[38;5;67m",          # Slate
                ThoughtType.VALIDATING: "\033[38;5;108m",     # Sage
                ThoughtType.COMPLETE: "\033[38;5;108m",       # Sage
            }
            reset = "\033[0m"
            dim = "\033[2m"
            color = colors.get(self.thought_type, "")
        else:
            color = reset = dim = ""

        parts = [f"{color}{icon} {self.message}{reset}"]

        if self.detail:
            parts.append(f"{dim}   {self.detail}{reset}")

        if self.source:
            parts.append(f"{dim}   📖 Source: {self.source}{reset}")

        if self.confidence is not None:
            conf_pct = int(self.confidence * 100)
            parts.append(f"{dim}   Confidence: {conf_pct}%{reset}")

        return "\n".join(parts)


class ThinkingStream:
    """
    Real-time thinking display.

    Shows thoughts as they happen with typing effect.
    Creates a human-like feel of watching someone think.

    Usage:
        stream = ThinkingStream()

        with stream.thinking("Processing your request..."):
            # Do work
            stream.think(ThoughtType.SEARCHING, "Querying QA knowledge base...")
            results = brain.query(...)

            stream.think(ThoughtType.FOUND, f"Found {len(results)} relevant rules",
                        source="Section 7.1 - Email Validation")

            stream.think(ThoughtType.GENERATING, "Creating test cases...")

        # Stream automatically closes with summary
    """

    def __init__(
        self,
        output_stream=None,
        use_color: bool = True,
        typing_speed: float = 0.02,
        show_timestamps: bool = False,
    ):
        """
        Initialize thinking stream.

        Args:
            output_stream: Where to write (default: sys.stdout)
            use_color: Whether to use ANSI colors
            typing_speed: Delay between characters (0 for instant)
            show_timestamps: Show timestamps for each thought
        """
        self.output = output_stream or sys.stdout
        self.use_color = use_color
        self.typing_speed = typing_speed
        self.show_timestamps = show_timestamps

        self.thoughts: List[Thought] = []
        self._active = False
        self._spinner_thread: Optional[threading.Thread] = None
        self._stop_spinner = threading.Event()

    def _write(self, text: str, newline: bool = True):
        """Write to output stream."""
        self.output.write(text)
        if newline:
            self.output.write("\n")
        self.output.flush()

    def _type_effect(self, text: str):
        """Write with typing effect."""
        if self.typing_speed <= 0:
            self._write(text)
            return

        for char in text:
            self.output.write(char)
            self.output.flush()
            if char not in " \n":
                time.sleep(self.typing_speed)
        self._write("")

    def _start_spinner(self, message: str):
        """Start a spinner for long operations."""
        self._stop_spinner.clear()

        def spin():
            frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            i = 0
            while not self._stop_spinner.is_set():
                frame = frames[i % len(frames)]
                self.output.write(f"\r{frame} {message}...")
                self.output.flush()
                time.sleep(0.1)
                i += 1
            # Clear spinner line
            self.output.write("\r" + " " * (len(message) + 10) + "\r")
            self.output.flush()

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

    def _stop_spinner_thread(self):
        """Stop the spinner."""
        if self._spinner_thread:
            self._stop_spinner.set()
            self._spinner_thread.join(timeout=0.5)
            self._spinner_thread = None

    def think(
        self,
        thought_type: ThoughtType,
        message: str,
        detail: Optional[str] = None,
        source: Optional[str] = None,
        confidence: Optional[float] = None,
        typing: bool = False,
    ):
        """
        Express a thought.

        Args:
            thought_type: Type of thought
            message: Main thought message
            detail: Additional detail
            source: Brain section citation
            confidence: Confidence level (0-1)
            typing: Use typing effect
        """
        thought = Thought(
            thought_type=thought_type,
            message=message,
            detail=detail,
            source=source,
            confidence=confidence,
        )
        self.thoughts.append(thought)

        formatted = thought.format(use_color=self.use_color)

        if self.show_timestamps:
            ts = thought.timestamp.strftime("%H:%M:%S")
            formatted = f"[{ts}] {formatted}"

        if typing:
            self._type_effect(formatted)
        else:
            self._write(formatted)

    def understanding(self, message: str, **kwargs):
        """Express understanding thought."""
        self.think(ThoughtType.UNDERSTANDING, message, **kwargs)

    def searching(self, message: str, **kwargs):
        """Express searching thought."""
        self.think(ThoughtType.SEARCHING, message, **kwargs)

    def found(self, message: str, source: Optional[str] = None, **kwargs):
        """Express found thought with source."""
        self.think(ThoughtType.FOUND, message, source=source, **kwargs)

    def analyzing(self, message: str, **kwargs):
        """Express analyzing thought."""
        self.think(ThoughtType.ANALYZING, message, **kwargs)

    def reasoning(self, message: str, **kwargs):
        """Express reasoning thought."""
        self.think(ThoughtType.REASONING, message, **kwargs)

    def deciding(self, message: str, confidence: Optional[float] = None, **kwargs):
        """Express deciding thought with confidence."""
        self.think(ThoughtType.DECIDING, message, confidence=confidence, **kwargs)

    def generating(self, message: str, **kwargs):
        """Express generating thought."""
        self.think(ThoughtType.GENERATING, message, **kwargs)

    def citing(self, source: str, message: str = "Citing source", **kwargs):
        """Express citing thought."""
        self.think(ThoughtType.CITING, message, source=source, **kwargs)

    def validating(self, message: str, **kwargs):
        """Express validating thought."""
        self.think(ThoughtType.VALIDATING, message, **kwargs)

    def complete(self, message: str, **kwargs):
        """Express completion thought."""
        self.think(ThoughtType.COMPLETE, message, **kwargs)

    def with_spinner(self, message: str):
        """Context manager for spinner during long operations."""
        return SpinnerContext(self, message)

    def thinking(self, initial_message: str):
        """Context manager for a thinking session."""
        return ThinkingContext(self, initial_message)

    def get_summary(self) -> dict:
        """Get summary of thinking session."""
        sources = set()
        for t in self.thoughts:
            if t.source:
                sources.add(t.source)

        return {
            "total_thoughts": len(self.thoughts),
            "sources_cited": list(sources),
            "thought_types": [t.thought_type.value for t in self.thoughts],
        }


class SpinnerContext:
    """Context manager for spinner."""

    def __init__(self, stream: ThinkingStream, message: str):
        self.stream = stream
        self.message = message

    def __enter__(self):
        self.stream._start_spinner(self.message)
        return self

    def __exit__(self, *args):
        self.stream._stop_spinner_thread()


class ThinkingContext:
    """Context manager for thinking session."""

    def __init__(self, stream: ThinkingStream, initial_message: str):
        self.stream = stream
        self.initial_message = initial_message
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        self.stream._active = True
        self.stream.thoughts = []

        # Header
        if self.stream.use_color:
            self.stream._write(f"\n\033[2m{'─' * 40}\033[0m")
            self.stream._write(f"\033[1m💭 {self.initial_message}\033[0m")
            self.stream._write(f"\033[2m{'─' * 40}\033[0m")
        else:
            self.stream._write(f"\n{'─' * 40}")
            self.stream._write(f"Thinking: {self.initial_message}")
            self.stream._write(f"{'─' * 40}")

        return self.stream

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stream._active = False
        elapsed = time.time() - self.start_time

        # Footer
        summary = self.stream.get_summary()
        sources = summary["sources_cited"]

        if self.stream.use_color:
            self.stream._write(f"\033[2m{'─' * 40}\033[0m")
            self.stream._write(f"\033[2m⏱ Completed in {elapsed:.1f}s | {len(sources)} sources cited\033[0m")
        else:
            self.stream._write(f"{'─' * 40}")
            self.stream._write(f"Completed in {elapsed:.1f}s | {len(sources)} sources cited")


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_stream(verbose: bool = True, color: bool = True) -> ThinkingStream:
    """Create a thinking stream with common settings."""
    return ThinkingStream(
        use_color=color and sys.stdout.isatty(),
        typing_speed=0.01 if verbose else 0,
        show_timestamps=False,
    )


if __name__ == "__main__":
    # Demo
    stream = create_stream(verbose=True)

    with stream.thinking("Processing your request for login page tests"):
        stream.understanding("Analyzing request: 'test login page'")
        time.sleep(0.3)

        stream.searching("Querying QA Brain for login-related rules...")
        time.sleep(0.5)

        stream.found("Found 12 relevant rules",
                    source="Section 7 - Login Page Testing",
                    detail="Covers authentication, validation, security")
        time.sleep(0.3)

        stream.found("Found 8 security rules",
                    source="Section 3 - Security Testing")
        time.sleep(0.3)

        stream.analyzing("Cross-referencing security requirements with login flow...")
        time.sleep(0.4)

        stream.reasoning("Login page requires both positive and negative test cases",
                        detail="High-risk area due to authentication handling")
        time.sleep(0.3)

        stream.deciding("Will generate 15 test cases",
                       confidence=0.85,
                       detail="6 security, 5 functional, 4 edge cases")
        time.sleep(0.3)

        with stream.with_spinner("Generating test cases"):
            time.sleep(1.5)

        stream.generating("Created 15 comprehensive test cases")
        time.sleep(0.2)

        stream.validating("All test cases have citations")
        time.sleep(0.2)

        stream.complete("Test plan ready for review")

    print("\n✨ Done!")
