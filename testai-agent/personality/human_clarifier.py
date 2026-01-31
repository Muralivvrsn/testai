"""
TestAI Agent - Human-Like Clarification System

Asks questions like a real Senior QA Consultant would:
- Thoughtful, not robotic
- Context-aware (doesn't ask what it already knows)
- Prioritizes what matters (security > cosmetic)
- European style: direct but warm

The goal is to gather just enough information to generate
excellent test cases, without overwhelming the user.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum
import random


class QuestionPriority(Enum):
    """How important is it to ask this question."""
    CRITICAL = "critical"    # Must know before generating tests
    HIGH = "high"           # Significantly improves test quality
    MEDIUM = "medium"       # Nice to know
    LOW = "low"             # Optional enhancement


class QuestionCategory(Enum):
    """Categories of clarifying questions."""
    SCOPE = "scope"              # What to test
    SECURITY = "security"        # Security requirements
    USERS = "users"              # User types and roles
    INTEGRATION = "integration"  # Third-party integrations
    TECHNICAL = "technical"      # Technical constraints
    PRIORITY = "priority"        # What matters most
    EXISTING = "existing"        # Existing issues/history


@dataclass
class ClarifyingQuestion:
    """A question to ask the user."""
    question: str
    category: QuestionCategory
    priority: QuestionPriority
    context: str = ""  # Why we're asking
    options: List[str] = field(default_factory=list)  # If multiple choice
    follow_up: Optional[str] = None  # If yes, ask this next
    skip_if: Optional[str] = None  # Skip if this info is known


@dataclass
class QuestionContext:
    """What we know that affects what questions to ask."""
    page_type: Optional[str] = None
    feature_name: Optional[str] = None
    known_integrations: Set[str] = field(default_factory=set)
    known_user_roles: Set[str] = field(default_factory=set)
    security_mentioned: bool = False
    accessibility_mentioned: bool = False
    has_forms: bool = False
    has_authentication: bool = False
    has_payment: bool = False


class HumanClarifier:
    """
    Generates contextual clarifying questions like a human consultant.

    Key principles:
    1. Don't ask what you already know
    2. Ask the most important questions first
    3. Keep questions conversational
    4. Provide context for why you're asking
    5. Offer options when applicable

    Usage:
        clarifier = HumanClarifier()

        # Set what we know
        context = QuestionContext(page_type="login")

        # Get relevant questions
        questions = clarifier.get_questions(context)

        # Format for display
        for q in questions[:3]:
            print(clarifier.format_question(q))
    """

    # ─────────────────────────────────────────────────────────────
    # Question Templates by Page Type
    # ─────────────────────────────────────────────────────────────

    LOGIN_QUESTIONS = [
        ClarifyingQuestion(
            question="Does this login support social authentication (Google, Facebook, etc.)?",
            category=QuestionCategory.INTEGRATION,
            priority=QuestionPriority.HIGH,
            context="Social auth has specific OAuth security considerations.",
        ),
        ClarifyingQuestion(
            question="Is multi-factor authentication (MFA) enabled?",
            category=QuestionCategory.SECURITY,
            priority=QuestionPriority.CRITICAL,
            context="MFA flows need dedicated test cases.",
        ),
        ClarifyingQuestion(
            question="What happens after failed login attempts?",
            category=QuestionCategory.SECURITY,
            priority=QuestionPriority.HIGH,
            context="Rate limiting and lockout behavior varies.",
            options=["Account lockout", "CAPTCHA", "Time delay", "Just error message"],
        ),
        ClarifyingQuestion(
            question="Is there a 'Remember Me' or 'Stay signed in' option?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Persistent sessions have security implications.",
        ),
        ClarifyingQuestion(
            question="How is password reset handled?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            options=["Email link", "SMS code", "Security questions", "Not sure"],
        ),
    ]

    SIGNUP_QUESTIONS = [
        ClarifyingQuestion(
            question="What information is required for signup?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.CRITICAL,
            context="This determines which validation tests are needed.",
            options=["Email only", "Email + password", "Full profile", "Phone number"],
        ),
        ClarifyingQuestion(
            question="Is email verification required?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Verification flows need separate test coverage.",
        ),
        ClarifyingQuestion(
            question="Are there different user roles/types during signup?",
            category=QuestionCategory.USERS,
            priority=QuestionPriority.HIGH,
            context="Different roles may have different validation rules.",
        ),
        ClarifyingQuestion(
            question="Is there terms & conditions acceptance?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Consent tracking has legal implications.",
        ),
        ClarifyingQuestion(
            question="What password requirements exist?",
            category=QuestionCategory.SECURITY,
            priority=QuestionPriority.HIGH,
            context="Need to test both acceptance and rejection of passwords.",
            options=["Standard (8+ chars)", "Complex (special chars required)", "Custom rules"],
        ),
    ]

    CHECKOUT_QUESTIONS = [
        ClarifyingQuestion(
            question="What payment methods are supported?",
            category=QuestionCategory.INTEGRATION,
            priority=QuestionPriority.CRITICAL,
            context="Each payment method needs specific testing.",
            options=["Credit/Debit cards", "PayPal", "Apple Pay/Google Pay", "Multiple"],
        ),
        ClarifyingQuestion(
            question="Is guest checkout available?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Guest vs. authenticated flows differ significantly.",
        ),
        ClarifyingQuestion(
            question="Are there discount codes or promotions?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Promo code validation is a common source of bugs.",
        ),
        ClarifyingQuestion(
            question="Is shipping address collection required?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Address validation has international complexity.",
        ),
        ClarifyingQuestion(
            question="What happens if payment fails?",
            category=QuestionCategory.TECHNICAL,
            priority=QuestionPriority.HIGH,
            context="Error handling in payment is critical.",
        ),
    ]

    SEARCH_QUESTIONS = [
        ClarifyingQuestion(
            question="Is there autocomplete or search suggestions?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Autocomplete has specific UX and performance concerns.",
        ),
        ClarifyingQuestion(
            question="Are there search filters available?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Filter combinations can cause edge cases.",
        ),
        ClarifyingQuestion(
            question="How large is the searchable dataset?",
            category=QuestionCategory.TECHNICAL,
            priority=QuestionPriority.MEDIUM,
            context="Affects performance testing approach.",
            options=["Small (<1K items)", "Medium (1K-100K)", "Large (100K+)"],
        ),
        ClarifyingQuestion(
            question="Does search support fuzzy matching or typos?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Fuzzy search needs specific test cases.",
        ),
    ]

    FORM_QUESTIONS = [
        ClarifyingQuestion(
            question="How many fields does the form have?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Larger forms need more comprehensive testing.",
            options=["Simple (1-5)", "Medium (5-15)", "Complex (15+)"],
        ),
        ClarifyingQuestion(
            question="Is there a multi-step wizard flow?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Multi-step forms have state management concerns.",
        ),
        ClarifyingQuestion(
            question="Is there file upload functionality?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="File uploads have specific security tests.",
        ),
        ClarifyingQuestion(
            question="Is there auto-save or draft functionality?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.MEDIUM,
            context="Auto-save needs edge case testing.",
        ),
    ]

    # Universal questions that apply to most pages
    UNIVERSAL_QUESTIONS = [
        ClarifyingQuestion(
            question="Who are the primary users of this feature?",
            category=QuestionCategory.USERS,
            priority=QuestionPriority.HIGH,
            context="User personas affect test priority.",
            options=["End consumers", "Business users", "Admins", "Multiple types"],
        ),
        ClarifyingQuestion(
            question="Are there any known issues or problem areas?",
            category=QuestionCategory.EXISTING,
            priority=QuestionPriority.HIGH,
            context="Helps me focus on historically problematic areas.",
        ),
        ClarifyingQuestion(
            question="Is accessibility compliance required (WCAG)?",
            category=QuestionCategory.SCOPE,
            priority=QuestionPriority.HIGH,
            context="Accessibility testing adds specific checks.",
            skip_if="accessibility_mentioned",
        ),
        ClarifyingQuestion(
            question="What browsers/devices need support?",
            category=QuestionCategory.TECHNICAL,
            priority=QuestionPriority.MEDIUM,
            context="Affects compatibility testing scope.",
            options=["Modern browsers only", "IE11 support needed", "Mobile-first", "All platforms"],
        ),
        ClarifyingQuestion(
            question="Is this a new feature or updating existing functionality?",
            category=QuestionCategory.EXISTING,
            priority=QuestionPriority.MEDIUM,
            context="Updates need regression testing consideration.",
        ),
    ]

    # Security-focused questions
    SECURITY_QUESTIONS = [
        ClarifyingQuestion(
            question="Is there sensitive data being handled (PII, financial)?",
            category=QuestionCategory.SECURITY,
            priority=QuestionPriority.CRITICAL,
            context="Sensitive data requires specific security tests.",
        ),
        ClarifyingQuestion(
            question="Are there API endpoints exposed by this feature?",
            category=QuestionCategory.TECHNICAL,
            priority=QuestionPriority.HIGH,
            context="APIs need separate security testing.",
        ),
        ClarifyingQuestion(
            question="Is input validation happening client-side, server-side, or both?",
            category=QuestionCategory.SECURITY,
            priority=QuestionPriority.HIGH,
            context="Server-side validation is mandatory for security.",
        ),
    ]

    # Conversational phrases for natural flow
    QUESTION_INTROS = [
        "Before I proceed, I have a question:",
        "One thing I'd like to clarify:",
        "To make sure I cover the right areas:",
        "Quick question before I generate tests:",
        "I want to make sure I understand:",
        "To provide comprehensive coverage:",
    ]

    CONTEXT_PHRASES = [
        "I'm asking because",
        "The reason I ask is that",
        "This matters because",
        "This helps me",
        "Knowing this will",
    ]

    def __init__(self):
        """Initialize the clarifier."""
        self._asked_questions: Set[str] = set()

    def get_questions(
        self,
        context: QuestionContext,
        max_questions: int = 3,
        priority_threshold: QuestionPriority = QuestionPriority.MEDIUM,
    ) -> List[ClarifyingQuestion]:
        """
        Get relevant questions based on context.

        Args:
            context: What we already know
            max_questions: Maximum questions to return
            priority_threshold: Minimum priority to include

        Returns:
            List of relevant questions, sorted by priority
        """
        candidates = []

        # Get page-specific questions
        page_questions = self._get_page_questions(context.page_type)
        candidates.extend(page_questions)

        # Add universal questions
        candidates.extend(self.UNIVERSAL_QUESTIONS)

        # Add security questions if relevant
        if context.has_authentication or context.has_payment or context.page_type in ["login", "signup", "checkout"]:
            candidates.extend(self.SECURITY_QUESTIONS)

        # Filter out already asked questions
        candidates = [q for q in candidates if q.question not in self._asked_questions]

        # Filter by skip conditions
        candidates = self._filter_by_context(candidates, context)

        # Filter by priority
        priority_order = [
            QuestionPriority.CRITICAL,
            QuestionPriority.HIGH,
            QuestionPriority.MEDIUM,
            QuestionPriority.LOW,
        ]
        threshold_index = priority_order.index(priority_threshold)
        allowed_priorities = priority_order[:threshold_index + 1]
        candidates = [q for q in candidates if q.priority in allowed_priorities]

        # Sort by priority
        candidates.sort(key=lambda q: priority_order.index(q.priority))

        return candidates[:max_questions]

    def _get_page_questions(self, page_type: Optional[str]) -> List[ClarifyingQuestion]:
        """Get questions specific to a page type."""
        mapping = {
            "login": self.LOGIN_QUESTIONS,
            "signup": self.SIGNUP_QUESTIONS,
            "checkout": self.CHECKOUT_QUESTIONS,
            "search": self.SEARCH_QUESTIONS,
            "form": self.FORM_QUESTIONS,
        }
        return mapping.get(page_type or "", [])

    def _filter_by_context(
        self,
        questions: List[ClarifyingQuestion],
        context: QuestionContext,
    ) -> List[ClarifyingQuestion]:
        """Filter questions based on what we already know."""
        filtered = []
        for q in questions:
            # Check skip_if condition
            if q.skip_if:
                if q.skip_if == "accessibility_mentioned" and context.accessibility_mentioned:
                    continue
                if q.skip_if == "security_mentioned" and context.security_mentioned:
                    continue

            filtered.append(q)
        return filtered

    def format_question(
        self,
        question: ClarifyingQuestion,
        show_context: bool = True,
        show_options: bool = True,
    ) -> str:
        """
        Format a question for human-readable display.

        Args:
            question: The question to format
            show_context: Include why we're asking
            show_options: Include multiple choice options

        Returns:
            Formatted question string
        """
        parts = []

        # Add intro phrase
        intro = random.choice(self.QUESTION_INTROS)
        parts.append(f"{intro}\n")

        # Add the question
        parts.append(f"  {question.question}")

        # Add context if requested
        if show_context and question.context:
            context_phrase = random.choice(self.CONTEXT_PHRASES)
            parts.append(f"\n  ({context_phrase} {question.context.lower()})")

        # Add options if available
        if show_options and question.options:
            parts.append("\n  Options:")
            for i, option in enumerate(question.options, 1):
                parts.append(f"\n    {i}. {option}")

        return "".join(parts)

    def format_questions_batch(
        self,
        questions: List[ClarifyingQuestion],
        intro_message: Optional[str] = None,
    ) -> str:
        """
        Format multiple questions as a batch.

        Args:
            questions: Questions to format
            intro_message: Custom intro message

        Returns:
            Formatted batch of questions
        """
        if not questions:
            return ""

        parts = []

        # Intro
        if intro_message:
            parts.append(intro_message)
        else:
            parts.append("Before I generate your test cases, I have a few questions to ensure comprehensive coverage:\n")

        # Questions
        for i, q in enumerate(questions, 1):
            parts.append(f"\n{i}. {q.question}")
            if q.options:
                options_str = " / ".join(q.options)
                parts.append(f"\n   ({options_str})")

        parts.append("\n\nTake your time - these help me generate better tests.")

        return "".join(parts)

    def mark_asked(self, question: str):
        """Mark a question as already asked."""
        self._asked_questions.add(question)

    def reset(self):
        """Reset asked questions for new session."""
        self._asked_questions.clear()

    def should_ask_questions(self, context: QuestionContext) -> Tuple[bool, str]:
        """
        Determine if we should ask questions or proceed.

        Args:
            context: Current context

        Returns:
            Tuple of (should_ask, reason)
        """
        # Always ask for critical unknowns
        questions = self.get_questions(context, priority_threshold=QuestionPriority.CRITICAL)
        critical = [q for q in questions if q.priority == QuestionPriority.CRITICAL]

        if critical:
            return True, "There are critical details I need to confirm."

        # Ask if context is very sparse
        if not context.page_type and not context.feature_name:
            return True, "I need more context about what to test."

        # Don't ask if we have good context
        if context.page_type and (context.security_mentioned or context.accessibility_mentioned):
            return False, "I have enough context to proceed."

        # Default: ask a few questions for quality
        return True, "A few quick questions will help me generate better tests."


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_clarifier() -> HumanClarifier:
    """Create a new HumanClarifier instance."""
    return HumanClarifier()


def get_clarifying_questions(
    page_type: Optional[str] = None,
    feature: Optional[str] = None,
    max_questions: int = 3,
) -> List[str]:
    """
    Quick function to get clarifying questions.

    Args:
        page_type: Type of page (login, signup, etc.)
        feature: Feature name
        max_questions: Maximum questions

    Returns:
        List of question strings
    """
    clarifier = HumanClarifier()
    context = QuestionContext(
        page_type=page_type,
        feature_name=feature,
    )

    questions = clarifier.get_questions(context, max_questions=max_questions)
    return [q.question for q in questions]


if __name__ == "__main__":
    # Demo
    clarifier = HumanClarifier()

    print("=" * 60)
    print("Human-Like Clarification Demo")
    print("=" * 60)

    # Login page scenario
    print("\n## Login Page Scenario\n")
    context = QuestionContext(page_type="login")
    questions = clarifier.get_questions(context, max_questions=3)

    print(clarifier.format_questions_batch(questions))

    # Checkout page scenario
    print("\n\n## Checkout Page Scenario\n")
    context = QuestionContext(
        page_type="checkout",
        has_payment=True,
    )
    questions = clarifier.get_questions(context, max_questions=3)

    print(clarifier.format_questions_batch(questions))

    # Unknown page scenario
    print("\n\n## Vague Request Scenario\n")
    context = QuestionContext()
    should_ask, reason = clarifier.should_ask_questions(context)
    print(f"Should ask questions: {should_ask}")
    print(f"Reason: {reason}")
