"""
TestAI Agent - Conversational Memory

Maintains context across interactions like a real human QA consultant would:
- Remembers what features were discussed
- Tracks clarifications and decisions made
- Builds progressive understanding of the project
- Maintains working memory for current session

Design: European-style - precise, thoughtful, building on context.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
from datetime import datetime, timedelta
from enum import Enum
import json


class MemoryType(Enum):
    """Types of memories the agent maintains."""
    FEATURE = "feature"           # Features discussed
    CLARIFICATION = "clarification"  # Q&A exchanges
    DECISION = "decision"         # Decisions made
    INSIGHT = "insight"           # Insights discovered
    TEST = "test"                 # Tests generated
    RISK = "risk"                 # Risks identified
    PREFERENCE = "preference"     # User preferences


@dataclass
class Memory:
    """A single memory unit."""
    type: MemoryType
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    importance: float = 0.5  # 0-1 scale
    source_section: Optional[str] = None  # Brain section citation

    def age_minutes(self) -> float:
        """How old is this memory in minutes."""
        return (datetime.now() - self.timestamp).total_seconds() / 60

    def is_recent(self, minutes: int = 30) -> bool:
        """Is this memory recent (within N minutes)."""
        return self.age_minutes() < minutes

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "type": self.type.value,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "importance": self.importance,
            "source_section": self.source_section,
        }


@dataclass
class ConversationTurn:
    """A single turn in the conversation."""
    role: str  # "user" or "assistant"
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    intent: Optional[str] = None  # Detected intent
    entities: Dict[str, Any] = field(default_factory=dict)  # Extracted entities


@dataclass
class WorkingContext:
    """Current working context - what we're focused on right now."""
    current_feature: Optional[str] = None
    current_page_type: Optional[str] = None
    pending_questions: List[str] = field(default_factory=list)
    confirmed_requirements: List[str] = field(default_factory=list)
    identified_risks: List[str] = field(default_factory=list)
    test_focus: List[str] = field(default_factory=list)  # security, ui, functional

    def has_context(self) -> bool:
        """Do we have enough context to proceed?"""
        return bool(self.current_feature or self.current_page_type)

    def needs_clarification(self) -> bool:
        """Do we need to ask questions?"""
        return len(self.pending_questions) > 0

    def summary(self) -> str:
        """Get a human-readable summary of current context."""
        parts = []
        if self.current_feature:
            parts.append(f"Feature: {self.current_feature}")
        if self.current_page_type:
            parts.append(f"Page Type: {self.current_page_type}")
        if self.confirmed_requirements:
            parts.append(f"Requirements: {len(self.confirmed_requirements)} confirmed")
        if self.identified_risks:
            parts.append(f"Risks: {len(self.identified_risks)} identified")
        return " | ".join(parts) if parts else "No context established"


class ConversationalMemory:
    """
    Human-like conversational memory system.

    Maintains:
    - Short-term: Recent conversation turns (last 10)
    - Working: Current task context
    - Long-term: Important decisions, preferences, insights

    Usage:
        memory = ConversationalMemory()

        # User says something
        memory.add_user_turn("I want to test the login page")

        # Agent processes and responds
        memory.set_working_context(feature="login", page_type="login")
        memory.add_assistant_turn("I'll help you test the login page...")

        # Remember important things
        memory.remember(MemoryType.DECISION, "Focus on security tests first")

        # Recall later
        relevant = memory.recall("security")
    """

    # How many conversation turns to keep in short-term
    SHORT_TERM_LIMIT = 10

    # How old before memory fades from relevance (hours)
    MEMORY_DECAY_HOURS = 4

    def __init__(self):
        """Initialize empty memory."""
        self.conversation_history: List[ConversationTurn] = []
        self.memories: List[Memory] = []
        self.working: WorkingContext = WorkingContext()
        self.session_start: datetime = datetime.now()

        # Track what we've discussed
        self._discussed_features: Set[str] = set()
        self._asked_questions: Set[str] = set()
        self._user_preferences: Dict[str, Any] = {}

    # ─────────────────────────────────────────────────────────────
    # Conversation Management
    # ─────────────────────────────────────────────────────────────

    def add_user_turn(
        self,
        message: str,
        intent: Optional[str] = None,
        entities: Optional[Dict[str, Any]] = None,
    ):
        """
        Add a user message to the conversation.

        Args:
            message: What the user said
            intent: Detected intent (e.g., "generate_tests", "ask_question")
            entities: Extracted entities (e.g., {"feature": "login"})
        """
        turn = ConversationTurn(
            role="user",
            message=message,
            intent=intent,
            entities=entities or {},
        )
        self.conversation_history.append(turn)
        self._trim_history()

        # Extract and remember entities
        if entities:
            if "feature" in entities:
                self._discussed_features.add(entities["feature"])
            if "page_type" in entities:
                self.working.current_page_type = entities["page_type"]

    def add_assistant_turn(self, message: str, intent: Optional[str] = None):
        """Add an assistant message to the conversation."""
        turn = ConversationTurn(
            role="assistant",
            message=message,
            intent=intent,
        )
        self.conversation_history.append(turn)
        self._trim_history()

    def _trim_history(self):
        """Keep only recent conversation turns."""
        if len(self.conversation_history) > self.SHORT_TERM_LIMIT:
            # Keep most recent
            self.conversation_history = self.conversation_history[-self.SHORT_TERM_LIMIT:]

    def get_recent_context(self, turns: int = 5) -> str:
        """
        Get recent conversation as context string.

        Args:
            turns: Number of recent turns to include

        Returns:
            Formatted conversation history
        """
        recent = self.conversation_history[-turns:]
        lines = []
        for turn in recent:
            role = "User" if turn.role == "user" else "Assistant"
            lines.append(f"{role}: {turn.message}")
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────
    # Working Context
    # ─────────────────────────────────────────────────────────────

    def set_working_context(
        self,
        feature: Optional[str] = None,
        page_type: Optional[str] = None,
        test_focus: Optional[List[str]] = None,
    ):
        """
        Set the current working context.

        Args:
            feature: Feature being tested
            page_type: Type of page (login, signup, checkout, etc.)
            test_focus: Focus areas (security, ui, functional, accessibility)
        """
        if feature:
            self.working.current_feature = feature
            self._discussed_features.add(feature)
        if page_type:
            self.working.current_page_type = page_type
        if test_focus:
            self.working.test_focus = test_focus

    def add_pending_question(self, question: str):
        """Add a question that needs user clarification."""
        if question not in self._asked_questions:
            self.working.pending_questions.append(question)

    def resolve_question(self, question: str, answer: str):
        """Record that a question was answered."""
        self._asked_questions.add(question)
        if question in self.working.pending_questions:
            self.working.pending_questions.remove(question)

        # Store as clarification memory
        self.remember(
            MemoryType.CLARIFICATION,
            f"Q: {question}\nA: {answer}",
            importance=0.7,
        )

        # Add to confirmed requirements
        self.working.confirmed_requirements.append(f"{question} → {answer}")

    def add_risk(self, risk: str, severity: str = "medium"):
        """Add an identified risk."""
        self.working.identified_risks.append(risk)
        self.remember(
            MemoryType.RISK,
            risk,
            context={"severity": severity},
            importance=0.8 if severity == "high" else 0.5,
        )

    def clear_working_context(self):
        """Clear working context for a new task."""
        self.working = WorkingContext()

    # ─────────────────────────────────────────────────────────────
    # Long-term Memory
    # ─────────────────────────────────────────────────────────────

    def remember(
        self,
        memory_type: MemoryType,
        content: str,
        context: Optional[Dict[str, Any]] = None,
        importance: float = 0.5,
        source_section: Optional[str] = None,
    ):
        """
        Store something in long-term memory.

        Args:
            memory_type: Type of memory
            content: What to remember
            context: Additional context
            importance: How important (0-1)
            source_section: Brain section citation
        """
        memory = Memory(
            type=memory_type,
            content=content,
            context=context or {},
            importance=importance,
            source_section=source_section,
        )
        self.memories.append(memory)

    def recall(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        limit: int = 5,
        recent_only: bool = False,
    ) -> List[Memory]:
        """
        Recall memories matching a query.

        Args:
            query: Search query
            memory_type: Filter by type
            limit: Maximum memories to return
            recent_only: Only memories from last 30 minutes

        Returns:
            List of matching memories
        """
        results = []
        query_lower = query.lower()

        for memory in self.memories:
            # Filter by type
            if memory_type and memory.type != memory_type:
                continue

            # Filter by recency
            if recent_only and not memory.is_recent():
                continue

            # Simple keyword matching
            if query_lower in memory.content.lower():
                results.append(memory)

        # Sort by importance and recency
        results.sort(
            key=lambda m: (m.importance, -m.age_minutes()),
            reverse=True,
        )

        return results[:limit]

    def get_decisions(self) -> List[Memory]:
        """Get all recorded decisions."""
        return [m for m in self.memories if m.type == MemoryType.DECISION]

    def get_preferences(self) -> Dict[str, Any]:
        """Get user preferences."""
        return self._user_preferences.copy()

    def set_preference(self, key: str, value: Any):
        """Set a user preference."""
        self._user_preferences[key] = value
        self.remember(
            MemoryType.PREFERENCE,
            f"{key}: {value}",
            importance=0.6,
        )

    # ─────────────────────────────────────────────────────────────
    # Context Building
    # ─────────────────────────────────────────────────────────────

    def build_context_for_llm(self) -> str:
        """
        Build a context string for LLM prompts.

        Returns:
            Formatted context including conversation history,
            working context, and relevant memories.
        """
        parts = []

        # Working context
        if self.working.has_context():
            parts.append("## Current Context")
            parts.append(self.working.summary())
            parts.append("")

        # Confirmed requirements
        if self.working.confirmed_requirements:
            parts.append("## Confirmed Requirements")
            for req in self.working.confirmed_requirements[-5:]:
                parts.append(f"- {req}")
            parts.append("")

        # Identified risks
        if self.working.identified_risks:
            parts.append("## Identified Risks")
            for risk in self.working.identified_risks[-3:]:
                parts.append(f"- ⚠️ {risk}")
            parts.append("")

        # Recent decisions
        decisions = self.get_decisions()
        if decisions:
            parts.append("## Previous Decisions")
            for decision in decisions[-3:]:
                parts.append(f"- {decision.content}")
            parts.append("")

        # Recent conversation
        if self.conversation_history:
            parts.append("## Recent Conversation")
            parts.append(self.get_recent_context(3))

        return "\n".join(parts)

    def should_ask_clarification(self) -> bool:
        """Should we ask the user for clarification?"""
        # Ask if we have pending questions
        if self.working.pending_questions:
            return True

        # Ask if we don't have enough context
        if not self.working.current_feature and not self.working.current_page_type:
            return True

        return False

    def get_next_question(self) -> Optional[str]:
        """Get the next clarifying question to ask."""
        if self.working.pending_questions:
            return self.working.pending_questions[0]

        # Generate default questions based on missing context
        if not self.working.current_feature:
            return "What feature would you like me to test?"

        if not self.working.current_page_type:
            return "What type of page is this? (e.g., login, signup, checkout, form)"

        if not self.working.test_focus:
            return "Should I focus on any particular area? (security, accessibility, edge cases)"

        return None

    # ─────────────────────────────────────────────────────────────
    # Session Management
    # ─────────────────────────────────────────────────────────────

    def session_duration_minutes(self) -> float:
        """How long has this session been running."""
        return (datetime.now() - self.session_start).total_seconds() / 60

    def get_session_summary(self) -> Dict[str, Any]:
        """Get a summary of the current session."""
        return {
            "duration_minutes": round(self.session_duration_minutes(), 1),
            "conversation_turns": len(self.conversation_history),
            "features_discussed": list(self._discussed_features),
            "questions_asked": len(self._asked_questions),
            "decisions_made": len(self.get_decisions()),
            "risks_identified": len(self.working.identified_risks),
            "current_context": self.working.summary(),
        }

    def export_session(self) -> Dict[str, Any]:
        """Export the entire session for storage/analysis."""
        return {
            "session_start": self.session_start.isoformat(),
            "conversation": [
                {
                    "role": turn.role,
                    "message": turn.message,
                    "timestamp": turn.timestamp.isoformat(),
                    "intent": turn.intent,
                }
                for turn in self.conversation_history
            ],
            "memories": [m.to_dict() for m in self.memories],
            "working_context": {
                "feature": self.working.current_feature,
                "page_type": self.working.current_page_type,
                "requirements": self.working.confirmed_requirements,
                "risks": self.working.identified_risks,
            },
            "preferences": self._user_preferences,
            "summary": self.get_session_summary(),
        }


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_memory() -> ConversationalMemory:
    """Create a new conversational memory instance."""
    return ConversationalMemory()


def extract_entities(message: str) -> Dict[str, Any]:
    """
    Extract entities from a user message.

    Args:
        message: User's message

    Returns:
        Dictionary of extracted entities
    """
    entities = {}
    message_lower = message.lower()

    # Detect page types
    page_types = {
        "login": ["login", "sign in", "signin", "log in"],
        "signup": ["signup", "sign up", "register", "registration", "create account"],
        "checkout": ["checkout", "payment", "purchase", "buy", "cart"],
        "search": ["search", "find", "lookup", "look up"],
        "profile": ["profile", "account", "settings", "preferences"],
        "dashboard": ["dashboard", "home", "overview", "main"],
        "form": ["form", "submit", "contact", "feedback"],
    }

    for page_type, keywords in page_types.items():
        if any(kw in message_lower for kw in keywords):
            entities["page_type"] = page_type
            entities["feature"] = page_type
            break

    # Detect test focus
    focus_keywords = {
        "security": ["security", "secure", "vulnerability", "injection", "xss", "csrf"],
        "accessibility": ["accessibility", "a11y", "wcag", "screen reader", "keyboard"],
        "performance": ["performance", "speed", "load time", "fast", "slow"],
        "ui": ["ui", "ux", "user interface", "design", "visual", "layout"],
        "functional": ["functional", "feature", "functionality", "behavior"],
        "edge_cases": ["edge case", "edge cases", "boundary", "corner case", "unusual"],
    }

    detected_focus = []
    for focus, keywords in focus_keywords.items():
        if any(kw in message_lower for kw in keywords):
            detected_focus.append(focus)

    if detected_focus:
        entities["test_focus"] = detected_focus

    return entities


if __name__ == "__main__":
    # Demo usage
    memory = create_memory()

    # Simulate conversation
    memory.add_user_turn(
        "I want to test the login page",
        entities=extract_entities("I want to test the login page"),
    )

    memory.set_working_context(
        feature="login",
        page_type="login",
        test_focus=["security", "functional"],
    )

    memory.add_assistant_turn(
        "I'll help you test the login page. Let me ask a few questions first.",
    )

    memory.add_pending_question("Does the login support social authentication (Google, Facebook)?")
    memory.add_pending_question("Is there MFA (multi-factor authentication)?")

    memory.resolve_question(
        "Does the login support social authentication?",
        "Yes, Google and Facebook SSO",
    )

    memory.remember(
        MemoryType.DECISION,
        "Focus on SSO security testing given social auth integration",
        importance=0.8,
    )

    memory.add_risk("SSO implementation may have OAuth redirect vulnerabilities", "high")

    # Print session summary
    print("Session Summary:")
    print(json.dumps(memory.get_session_summary(), indent=2))

    print("\nContext for LLM:")
    print(memory.build_context_for_llm())
