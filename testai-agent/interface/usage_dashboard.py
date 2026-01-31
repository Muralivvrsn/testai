"""
TestAI Agent - Usage Tracking Dashboard

Displays real-time API usage and system status:
- API calls remaining
- Token consumption
- Cost tracking
- Session statistics
- Brain status

Design: European dashboard - clean, informative, professional.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import json


class ProviderName(Enum):
    """LLM Provider names."""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


@dataclass
class ProviderUsage:
    """Usage statistics for a single provider."""
    name: ProviderName
    calls_made: int = 0
    calls_limit: int = 10
    tokens_used: int = 0
    tokens_limit: int = 50000
    cost_usd: float = 0.0
    last_call: Optional[datetime] = None
    errors: int = 0

    @property
    def calls_remaining(self) -> int:
        return max(0, self.calls_limit - self.calls_made)

    @property
    def calls_percent(self) -> float:
        return (self.calls_made / self.calls_limit * 100) if self.calls_limit > 0 else 0

    @property
    def tokens_percent(self) -> float:
        return (self.tokens_used / self.tokens_limit * 100) if self.tokens_limit > 0 else 0

    @property
    def is_available(self) -> bool:
        return self.calls_remaining > 0


@dataclass
class BrainStatus:
    """Status of the QA Brain."""
    is_ready: bool = False
    knowledge_chunks: int = 0
    categories: List[str] = field(default_factory=list)
    last_query: Optional[datetime] = None
    avg_confidence: float = 0.0
    queries_made: int = 0


@dataclass
class SessionStats:
    """Statistics for the current session."""
    started_at: datetime = field(default_factory=datetime.now)
    tests_generated: int = 0
    features_analyzed: int = 0
    questions_asked: int = 0
    questions_answered: int = 0
    citations_provided: int = 0
    errors_encountered: int = 0

    @property
    def duration_minutes(self) -> float:
        return (datetime.now() - self.started_at).total_seconds() / 60


class UsageDashboard:
    """
    Real-time usage tracking dashboard.

    Provides visibility into:
    - API usage per provider
    - Cost tracking
    - Brain status
    - Session statistics

    Usage:
        dashboard = UsageDashboard()

        # Update usage
        dashboard.record_api_call(ProviderName.DEEPSEEK, tokens=1500, cost=0.002)

        # Check availability
        if dashboard.can_call(ProviderName.DEEPSEEK):
            # Make call
            pass

        # Display dashboard
        print(dashboard.render())
    """

    # ANSI colors
    COLORS = {
        "header": "\033[38;5;67m",    # Slate blue
        "ok": "\033[38;5;108m",       # Sage green
        "warning": "\033[38;5;180m",  # Warm amber
        "danger": "\033[38;5;174m",   # Coral
        "dim": "\033[38;5;245m",      # Gray
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    # Default limits by provider
    DEFAULT_LIMITS = {
        ProviderName.DEEPSEEK: {"calls": 10, "tokens": 50000},
        ProviderName.OPENAI: {"calls": 20, "tokens": 100000},
        ProviderName.ANTHROPIC: {"calls": 20, "tokens": 100000},
        ProviderName.GEMINI: {"calls": 30, "tokens": 150000},
    }

    # Approximate costs per 1K tokens (input + output average)
    COSTS_PER_1K = {
        ProviderName.DEEPSEEK: 0.0005,
        ProviderName.OPENAI: 0.005,
        ProviderName.ANTHROPIC: 0.008,
        ProviderName.GEMINI: 0.0001,
    }

    def __init__(
        self,
        primary_provider: ProviderName = ProviderName.DEEPSEEK,
        use_color: bool = True,
    ):
        """
        Initialize the dashboard.

        Args:
            primary_provider: Primary LLM provider
            use_color: Use ANSI colors
        """
        self.primary_provider = primary_provider
        self.use_color = use_color

        # Initialize usage tracking
        self.providers: Dict[ProviderName, ProviderUsage] = {}
        for provider, limits in self.DEFAULT_LIMITS.items():
            self.providers[provider] = ProviderUsage(
                name=provider,
                calls_limit=limits["calls"],
                tokens_limit=limits["tokens"],
            )

        # Brain status
        self.brain = BrainStatus()

        # Session stats
        self.session = SessionStats()

    def _color(self, name: str, text: str) -> str:
        """Apply color to text."""
        if not self.use_color:
            return text
        color = self.COLORS.get(name, "")
        return f"{color}{text}{self.COLORS['reset']}"

    # ─────────────────────────────────────────────────────────────
    # Usage Recording
    # ─────────────────────────────────────────────────────────────

    def record_api_call(
        self,
        provider: ProviderName,
        tokens: int = 0,
        cost: Optional[float] = None,
        error: bool = False,
    ):
        """
        Record an API call.

        Args:
            provider: Provider used
            tokens: Tokens consumed
            cost: Cost in USD (calculated if not provided)
            error: Whether the call resulted in an error
        """
        usage = self.providers.get(provider)
        if not usage:
            return

        usage.calls_made += 1
        usage.tokens_used += tokens
        usage.last_call = datetime.now()

        if error:
            usage.errors += 1
            self.session.errors_encountered += 1
        else:
            # Calculate cost if not provided
            if cost is None:
                cost_per_1k = self.COSTS_PER_1K.get(provider, 0.001)
                cost = (tokens / 1000) * cost_per_1k
            usage.cost_usd += cost

    def record_brain_query(self, chunks_found: int, confidence: float):
        """Record a Brain query."""
        self.brain.queries_made += 1
        self.brain.last_query = datetime.now()

        # Update rolling average confidence
        if self.brain.avg_confidence == 0:
            self.brain.avg_confidence = confidence
        else:
            self.brain.avg_confidence = (self.brain.avg_confidence + confidence) / 2

    def record_test_generation(self, count: int):
        """Record test generation."""
        self.session.tests_generated += count

    def record_feature_analyzed(self):
        """Record feature analysis."""
        self.session.features_analyzed += 1

    def record_citation(self):
        """Record a citation provided."""
        self.session.citations_provided += 1

    def set_brain_status(
        self,
        is_ready: bool,
        chunks: int = 0,
        categories: Optional[List[str]] = None,
    ):
        """Set Brain status."""
        self.brain.is_ready = is_ready
        self.brain.knowledge_chunks = chunks
        if categories:
            self.brain.categories = categories

    # ─────────────────────────────────────────────────────────────
    # Query Methods
    # ─────────────────────────────────────────────────────────────

    def can_call(self, provider: Optional[ProviderName] = None) -> bool:
        """Check if we can make an API call."""
        if provider is None:
            provider = self.primary_provider
        usage = self.providers.get(provider)
        return usage.is_available if usage else False

    def get_remaining_calls(self, provider: Optional[ProviderName] = None) -> int:
        """Get remaining calls for a provider."""
        if provider is None:
            provider = self.primary_provider
        usage = self.providers.get(provider)
        return usage.calls_remaining if usage else 0

    def get_total_cost(self) -> float:
        """Get total cost across all providers."""
        return sum(p.cost_usd for p in self.providers.values())

    def get_status_dict(self) -> Dict[str, Any]:
        """Get status as dictionary."""
        return {
            "session": {
                "duration_minutes": round(self.session.duration_minutes, 1),
                "tests_generated": self.session.tests_generated,
                "features_analyzed": self.session.features_analyzed,
                "citations_provided": self.session.citations_provided,
                "errors": self.session.errors_encountered,
            },
            "providers": {
                p.name.value: {
                    "calls_made": p.calls_made,
                    "calls_remaining": p.calls_remaining,
                    "tokens_used": p.tokens_used,
                    "cost_usd": round(p.cost_usd, 4),
                }
                for p in self.providers.values()
            },
            "brain": {
                "ready": self.brain.is_ready,
                "chunks": self.brain.knowledge_chunks,
                "queries": self.brain.queries_made,
                "avg_confidence": round(self.brain.avg_confidence, 2),
            },
            "total_cost_usd": round(self.get_total_cost(), 4),
        }

    # ─────────────────────────────────────────────────────────────
    # Rendering
    # ─────────────────────────────────────────────────────────────

    def render(self, compact: bool = False) -> str:
        """
        Render the dashboard.

        Args:
            compact: Use compact format

        Returns:
            Formatted dashboard string
        """
        if compact:
            return self._render_compact()
        return self._render_full()

    def _render_compact(self) -> str:
        """Render compact single-line dashboard."""
        primary = self.providers.get(self.primary_provider)
        if not primary:
            return "Dashboard unavailable"

        # Build compact line
        parts = []

        # API status
        remaining = primary.calls_remaining
        color = "ok" if remaining > 3 else "warning" if remaining > 0 else "danger"
        parts.append(self._color(color, f"API: {remaining}/{primary.calls_limit}"))

        # Brain status
        brain_status = "Ready" if self.brain.is_ready else "Not loaded"
        brain_color = "ok" if self.brain.is_ready else "dim"
        parts.append(self._color(brain_color, f"Brain: {brain_status}"))

        # Tests generated
        if self.session.tests_generated > 0:
            parts.append(f"Tests: {self.session.tests_generated}")

        # Cost
        cost = self.get_total_cost()
        if cost > 0:
            parts.append(f"Cost: ${cost:.3f}")

        return " │ ".join(parts)

    def _render_full(self) -> str:
        """Render full dashboard."""
        lines = []

        # Header
        lines.append(self._color("header", "┌" + "─" * 58 + "┐"))
        lines.append(self._color("header", "│") + self._color("bold", "  TestAI Agent - Dashboard") + " " * 31 + self._color("header", "│"))
        lines.append(self._color("header", "├" + "─" * 58 + "┤"))

        # Session info
        duration = f"{self.session.duration_minutes:.1f} min"
        lines.append(self._color("header", "│") + f"  Session Duration: {duration}" + " " * (37 - len(duration)) + self._color("header", "│"))
        lines.append(self._color("header", "│") + " " * 58 + self._color("header", "│"))

        # API Usage section
        lines.append(self._color("header", "│") + self._color("bold", "  API Usage") + " " * 47 + self._color("header", "│"))

        for provider in [ProviderName.DEEPSEEK, ProviderName.OPENAI]:
            usage = self.providers.get(provider)
            if not usage:
                continue

            # Provider line
            name = provider.value.capitalize()
            calls_str = f"{usage.calls_made}/{usage.calls_limit}"
            bar = self._usage_bar(usage.calls_percent, 15)

            # Color based on usage
            if usage.calls_percent > 80:
                color = "danger"
            elif usage.calls_percent > 50:
                color = "warning"
            else:
                color = "ok"

            is_primary = " (primary)" if provider == self.primary_provider else ""
            line = f"  {name}{is_primary}: {bar} {calls_str}"
            padding = 58 - len(line) + len(self._color(color, ""))
            lines.append(self._color("header", "│") + self._color(color, f"  {name}{is_primary}: ") + bar + f" {calls_str}" + " " * (58 - len(f"  {name}{is_primary}: ") - len(bar) - len(f" {calls_str}")) + self._color("header", "│"))

        lines.append(self._color("header", "│") + " " * 58 + self._color("header", "│"))

        # Brain status
        lines.append(self._color("header", "│") + self._color("bold", "  Brain Status") + " " * 44 + self._color("header", "│"))
        brain_status = "✅ Ready" if self.brain.is_ready else "⚠️ Not loaded"
        brain_color = "ok" if self.brain.is_ready else "warning"
        lines.append(self._color("header", "│") + f"  Status: {self._color(brain_color, brain_status)}" + " " * (48 - len(brain_status)) + self._color("header", "│"))
        lines.append(self._color("header", "│") + f"  Knowledge chunks: {self.brain.knowledge_chunks}" + " " * (38 - len(str(self.brain.knowledge_chunks))) + self._color("header", "│"))
        lines.append(self._color("header", "│") + f"  Queries made: {self.brain.queries_made}" + " " * (42 - len(str(self.brain.queries_made))) + self._color("header", "│"))
        lines.append(self._color("header", "│") + " " * 58 + self._color("header", "│"))

        # Session stats
        lines.append(self._color("header", "│") + self._color("bold", "  Session Statistics") + " " * 38 + self._color("header", "│"))
        lines.append(self._color("header", "│") + f"  Tests generated: {self.session.tests_generated}" + " " * (39 - len(str(self.session.tests_generated))) + self._color("header", "│"))
        lines.append(self._color("header", "│") + f"  Features analyzed: {self.session.features_analyzed}" + " " * (37 - len(str(self.session.features_analyzed))) + self._color("header", "│"))
        lines.append(self._color("header", "│") + f"  Citations provided: {self.session.citations_provided}" + " " * (36 - len(str(self.session.citations_provided))) + self._color("header", "│"))
        lines.append(self._color("header", "│") + " " * 58 + self._color("header", "│"))

        # Cost
        total_cost = self.get_total_cost()
        cost_str = f"${total_cost:.4f}"
        lines.append(self._color("header", "│") + f"  Total Cost: {cost_str}" + " " * (44 - len(cost_str)) + self._color("header", "│"))

        # Footer
        lines.append(self._color("header", "└" + "─" * 58 + "┘"))

        return "\n".join(lines)

    def _usage_bar(self, percent: float, width: int = 10) -> str:
        """Create a usage bar."""
        filled = int(percent / 100 * width)
        empty = width - filled

        if percent > 80:
            fill_char = self._color("danger", "█")
        elif percent > 50:
            fill_char = self._color("warning", "█")
        else:
            fill_char = self._color("ok", "█")

        return fill_char * filled + self._color("dim", "░") * empty

    def render_status_line(self) -> str:
        """Render a minimal status line for CLI prompts."""
        primary = self.providers.get(self.primary_provider)
        if not primary:
            return ""

        remaining = primary.calls_remaining
        brain = "🧠" if self.brain.is_ready else "⚠️"
        tests = self.session.tests_generated

        return f"[{brain} {remaining} calls │ {tests} tests]"


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_dashboard() -> UsageDashboard:
    """Create a new dashboard instance."""
    return UsageDashboard()


if __name__ == "__main__":
    # Demo
    dashboard = UsageDashboard()

    # Simulate some usage
    dashboard.set_brain_status(is_ready=True, chunks=150, categories=["security", "validation", "ui"])
    dashboard.record_api_call(ProviderName.DEEPSEEK, tokens=2500)
    dashboard.record_api_call(ProviderName.DEEPSEEK, tokens=1800)
    dashboard.record_api_call(ProviderName.DEEPSEEK, tokens=3200)
    dashboard.record_brain_query(5, 0.85)
    dashboard.record_brain_query(3, 0.78)
    dashboard.record_test_generation(12)
    dashboard.record_feature_analyzed()
    dashboard.record_citation()
    dashboard.record_citation()
    dashboard.record_citation()

    print(dashboard.render())
    print()
    print("Compact view:")
    print(dashboard.render_compact())
    print()
    print("Status line:")
    print(dashboard.render_status_line())
