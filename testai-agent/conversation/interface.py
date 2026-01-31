"""
TestAI Agent - Conversation Interface

Handles human-like conversations with the user.
Remembers context, asks smart follow-ups, shows thinking.

Design Philosophy:
- Talk like a colleague, not a machine
- Show your work (but don't overwhelm)
- Ask before assuming
- Remember what was said
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from datetime import datetime
import re


class MessageType(Enum):
    """Type of message in conversation."""
    USER = "user"
    AGENT = "agent"
    THINKING = "thinking"
    QUESTION = "question"
    RESULT = "result"
    ERROR = "error"


class ConversationState(Enum):
    """Current state of the conversation."""
    IDLE = "idle"                          # Waiting for input
    UNDERSTANDING = "understanding"        # Processing user request
    CLARIFYING = "clarifying"              # Asking questions
    ANALYZING = "analyzing"                # Analyzing page/feature
    GENERATING = "generating"              # Generating tests
    PRESENTING = "presenting"              # Showing results
    WAITING_ANSWER = "waiting_answer"      # Waiting for user response


@dataclass
class Message:
    """A message in the conversation."""
    type: MessageType
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        prefix = {
            MessageType.USER: "You",
            MessageType.AGENT: "QA Agent",
            MessageType.THINKING: "  💭",
            MessageType.QUESTION: "  ❓",
            MessageType.RESULT: "  ✓",
            MessageType.ERROR: "  ⚠️",
        }.get(self.type, "")

        return f"{prefix}: {self.content}"


@dataclass
class PendingQuestion:
    """A question waiting for user response."""
    question: str
    options: List[str]
    default: Optional[str]
    context: str
    callback: Optional[Callable] = None


class Conversation:
    """
    Manages human-like conversation flow.

    The conversation has memory - it remembers:
    - What feature we're testing
    - What page type was detected
    - What questions were asked
    - What the user prefers

    Usage:
        conv = Conversation()

        # User says something
        conv.receive("I want to test the login page")

        # Agent thinks (visible to user)
        conv.think("Hmm, a login page. Let me check what elements we have...")

        # Agent asks for clarification
        conv.ask("Does this login support social sign-in?", ["Yes", "No"])

        # Agent responds
        conv.respond("Alright, I'll generate comprehensive login tests...")
    """

    def __init__(self, max_history: int = 50):
        """
        Initialize conversation.

        Args:
            max_history: Max messages to remember
        """
        self.messages: List[Message] = []
        self.max_history = max_history
        self.state = ConversationState.IDLE

        # Context tracking
        self.current_feature: Optional[str] = None
        self.current_page_type: Optional[str] = None
        self.user_preferences: Dict[str, Any] = {}
        self.pending_questions: List[PendingQuestion] = []

        # Callbacks
        self._on_message: Optional[Callable[[Message], None]] = None

    def on_message(self, callback: Callable[[Message], None]):
        """Set callback for new messages."""
        self._on_message = callback

    def _emit(self, message: Message):
        """Emit a message and store it."""
        self.messages.append(message)

        # Trim history
        if len(self.messages) > self.max_history:
            self.messages = self.messages[-self.max_history:]

        # Call callback
        if self._on_message:
            self._on_message(message)

    def receive(self, content: str) -> Message:
        """
        Receive a message from the user.

        Args:
            content: What the user said

        Returns:
            The stored message
        """
        message = Message(
            type=MessageType.USER,
            content=content,
        )
        self._emit(message)
        self.state = ConversationState.UNDERSTANDING

        # Extract context from message
        self._extract_context(content)

        return message

    def think(self, content: str, visible: bool = True) -> Optional[Message]:
        """
        Show the agent's thinking process.

        Args:
            content: What the agent is thinking
            visible: Whether to show to user

        Returns:
            The message if visible
        """
        if not visible:
            return None

        message = Message(
            type=MessageType.THINKING,
            content=content,
        )
        self._emit(message)
        return message

    def respond(self, content: str, metadata: Optional[Dict] = None) -> Message:
        """
        Agent responds to the user.

        Args:
            content: The response
            metadata: Additional data

        Returns:
            The response message
        """
        message = Message(
            type=MessageType.AGENT,
            content=content,
            metadata=metadata or {},
        )
        self._emit(message)
        self.state = ConversationState.IDLE
        return message

    def ask(
        self,
        question: str,
        options: Optional[List[str]] = None,
        default: Optional[str] = None,
        context: str = "",
    ) -> Message:
        """
        Ask the user a clarification question.

        Args:
            question: The question to ask
            options: Multiple choice options
            default: Default answer if user skips
            context: Why we're asking

        Returns:
            The question message
        """
        # Format the question
        formatted = question
        if options:
            opts_str = " / ".join(options)
            formatted += f"\n  Options: {opts_str}"
        if default:
            formatted += f"\n  (Default: {default})"

        message = Message(
            type=MessageType.QUESTION,
            content=formatted,
            metadata={
                "options": options,
                "default": default,
                "context": context,
            },
        )
        self._emit(message)

        # Track pending question
        self.pending_questions.append(PendingQuestion(
            question=question,
            options=options or [],
            default=default,
            context=context,
        ))

        self.state = ConversationState.WAITING_ANSWER
        return message

    def result(self, content: str, success: bool = True) -> Message:
        """
        Show a result to the user.

        Args:
            content: The result
            success: Whether it was successful

        Returns:
            The result message
        """
        message = Message(
            type=MessageType.RESULT if success else MessageType.ERROR,
            content=content,
        )
        self._emit(message)
        return message

    def error(self, content: str, recoverable: bool = True) -> Message:
        """
        Show an error to the user.

        Args:
            content: Error description
            recoverable: Can we continue?

        Returns:
            The error message
        """
        if recoverable:
            content = f"Small hiccup: {content}. Let me try another way."
        else:
            content = f"I ran into an issue: {content}"

        message = Message(
            type=MessageType.ERROR,
            content=content,
        )
        self._emit(message)
        return message

    def _extract_context(self, content: str):
        """Extract context from user message."""
        content_lower = content.lower()

        # Detect feature
        feature_patterns = [
            r"test(?:ing)?\s+(?:the\s+)?(\w+(?:\s+\w+)?)",
            r"(\w+(?:\s+\w+)?)\s+(?:page|feature|form)",
        ]

        for pattern in feature_patterns:
            match = re.search(pattern, content_lower)
            if match:
                self.current_feature = match.group(1).title()
                break

        # Detect page type
        page_types = ["login", "signup", "checkout", "search", "settings", "dashboard", "profile"]
        for pt in page_types:
            if pt in content_lower:
                self.current_page_type = pt
                break

    def get_context_summary(self) -> str:
        """Get a summary of current context."""
        parts = []
        if self.current_feature:
            parts.append(f"Feature: {self.current_feature}")
        if self.current_page_type:
            parts.append(f"Page type: {self.current_page_type}")
        if self.pending_questions:
            parts.append(f"Pending questions: {len(self.pending_questions)}")

        return " | ".join(parts) if parts else "No context yet"

    def get_history(self, limit: int = 10) -> List[Message]:
        """Get recent conversation history."""
        return self.messages[-limit:]

    def clear(self):
        """Clear conversation and reset state."""
        self.messages = []
        self.state = ConversationState.IDLE
        self.current_feature = None
        self.current_page_type = None
        self.pending_questions = []


# =============================================================================
# Natural Language Patterns
# =============================================================================

# Greetings for different contexts
GREETINGS = {
    "first_time": [
        "Hey! I'm your QA assistant. What would you like to test today?",
        "Hi there! Ready to find some bugs. What are we testing?",
        "Hello! Let's make sure this feature works perfectly. What's the target?",
        "Hey! Point me at something and I'll find the issues.",
        "Hi! What feature should we put through its paces?",
    ],
    "returning": [
        "Welcome back! What are we testing this time?",
        "Hey again! Ready for another round of testing.",
        "Back for more bug hunting? What's the feature?",
        "Good to see you! What needs testing today?",
    ],
    "after_completion": [
        "That's done! What else would you like to test?",
        "Finished that one. What's next?",
        "All set with that feature. Another one?",
        "Done! Ready for the next challenge.",
    ],
}

# Acknowledgments for different task types
ACKNOWLEDGMENTS = {
    "testing": [
        "Got it! Testing {feature}. Let me take a look...",
        "Alright, {feature} it is. Give me a moment to analyze this...",
        "Testing {feature}. Let me see what we're working with...",
        "On it. Checking out {feature}...",
        "{feature} - let me dig into this...",
        "Sounds good. Analyzing {feature} now...",
    ],
    "security_focus": [
        "Security testing for {feature}. I'll look for vulnerabilities...",
        "Running security checks on {feature}. This is important stuff...",
        "Checking {feature} for security issues. Let me be thorough...",
    ],
    "quick_test": [
        "Quick smoke test of {feature}. One moment...",
        "Running a quick check on {feature}...",
        "Fast sanity check for {feature}...",
    ],
    "deep_dive": [
        "Deep dive into {feature}. I'll be thorough...",
        "Comprehensive analysis of {feature} coming up...",
        "Full coverage test for {feature}. This will take a bit...",
    ],
}

# Clarification request patterns
CLARIFICATION_PATTERNS = {
    "general": [
        "Quick question about {topic} - ",
        "Just want to make sure about {topic}: ",
        "Before I dive in, about {topic} - ",
        "Help me understand {topic} better: ",
        "One thing I'm not sure about - {topic}. ",
    ],
    "important": [
        "I need to know about {topic} before I proceed: ",
        "This is important - about {topic}: ",
        "Can you clarify {topic}? It affects how I test this: ",
    ],
    "optional": [
        "By the way, about {topic} - but feel free to skip if you're not sure: ",
        "If you know about {topic}, it would help, but no worries if not: ",
        "Optional question about {topic}: ",
    ],
}

# Thinking aloud patterns
THINKING_PATTERNS = {
    "analyzing": [
        "Let me see what we have here...",
        "Analyzing the page structure...",
        "Looking at the elements...",
        "Checking what's on this page...",
        "Taking a closer look...",
    ],
    "detecting": [
        "I'm seeing a {type} pattern here...",
        "This looks like {type}...",
        "The structure suggests {type}...",
        "Based on the elements, this appears to be {type}...",
    ],
    "planning": [
        "Thinking through the test scenarios...",
        "Planning the test coverage...",
        "Figuring out what to test...",
        "Mapping out the edge cases...",
    ],
    "generating": [
        "Generating test cases now...",
        "Writing up the tests...",
        "Creating the test scenarios...",
        "Putting together the test suite...",
    ],
    "found_issue": [
        "Hmm, this is interesting...",
        "Wait, let me flag this...",
        "Found something worth noting...",
        "This could be an issue...",
    ],
}

# Follow-up suggestions
FOLLOW_UP_SUGGESTIONS = {
    "after_tests": [
        "Want me to explain any of these tests in detail?",
        "Should I focus on a specific category?",
        "Need more edge cases for any particular area?",
        "Want me to export these to a file?",
    ],
    "after_security": [
        "Should I generate remediation suggestions?",
        "Want me to prioritize these by severity?",
        "Need more details on any of these findings?",
    ],
    "after_error": [
        "Should I try a different approach?",
        "Want to give me more context?",
        "Can you help me understand what went wrong?",
    ],
    "uncertain": [
        "I'm not 100% sure about this - want me to explain my reasoning?",
        "My confidence isn't super high here - should I dig deeper?",
        "I might be missing something - any additional context?",
    ],
}

# Empathy and understanding phrases
EMPATHY_PHRASES = [
    "I understand.",
    "Got it.",
    "Makes sense.",
    "That's helpful to know.",
    "Okay, I see.",
    "Thanks for clarifying.",
    "That helps a lot.",
    "Perfect, now I understand.",
]


# =============================================================================
# Convenience functions for common conversation patterns
# =============================================================================

def greet(context: str = "first_time") -> str:
    """Generate a friendly greeting."""
    import random
    greetings = GREETINGS.get(context, GREETINGS["first_time"])
    return random.choice(greetings)


def acknowledge_task(feature: str, task_type: str = "testing") -> str:
    """Acknowledge a testing task."""
    import random
    acks = ACKNOWLEDGMENTS.get(task_type, ACKNOWLEDGMENTS["testing"])
    return random.choice(acks).format(feature=feature)


def ask_for_clarification(topic: str, importance: str = "general") -> str:
    """Ask for clarification naturally."""
    import random
    patterns = CLARIFICATION_PATTERNS.get(importance, CLARIFICATION_PATTERNS["general"])
    return random.choice(patterns).format(topic=topic)


def think_aloud(phase: str, context: Optional[str] = None) -> str:
    """Generate thinking-aloud text."""
    import random
    patterns = THINKING_PATTERNS.get(phase, THINKING_PATTERNS["analyzing"])
    text = random.choice(patterns)
    if context and "{type}" in text:
        text = text.format(type=context)
    return text


def suggest_follow_up(context: str = "after_tests") -> str:
    """Suggest a follow-up action."""
    import random
    suggestions = FOLLOW_UP_SUGGESTIONS.get(context, FOLLOW_UP_SUGGESTIONS["after_tests"])
    return random.choice(suggestions)


def empathize() -> str:
    """Express understanding."""
    import random
    return random.choice(EMPATHY_PHRASES)
