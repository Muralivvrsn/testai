"""
TestAI Agent - Clarification System

Asks smart questions like humans do.
Good QA engineers don't assume - they clarify.

Design Philosophy:
- Ask before assuming
- Group related questions
- Offer sensible defaults
- Don't overwhelm with questions
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class QuestionPriority(Enum):
    """How important is this question?"""
    CRITICAL = "critical"      # Can't proceed without answer
    IMPORTANT = "important"    # Significantly affects outcome
    OPTIONAL = "optional"      # Nice to know, has default


@dataclass
class ClarificationQuestion:
    """A question to ask the user."""
    question: str
    priority: QuestionPriority
    default: Optional[str] = None
    options: List[str] = field(default_factory=list)
    context: Optional[str] = None
    category: str = "general"

    def __str__(self) -> str:
        q = self.question
        if self.options:
            opts = " / ".join(self.options)
            q += f" ({opts})"
        if self.default:
            q += f" [default: {self.default}]"
        return q


@dataclass
class ClarificationBundle:
    """A group of related questions."""
    title: str
    questions: List[ClarificationQuestion]
    required_before_proceed: bool = False

    def get_critical(self) -> List[ClarificationQuestion]:
        """Get only critical questions."""
        return [q for q in self.questions if q.priority == QuestionPriority.CRITICAL]

    def summarize(self) -> str:
        """Quick summary of what we need to know."""
        critical = len([q for q in self.questions if q.priority == QuestionPriority.CRITICAL])
        important = len([q for q in self.questions if q.priority == QuestionPriority.IMPORTANT])

        parts = []
        if critical > 0:
            parts.append(f"{critical} critical")
        if important > 0:
            parts.append(f"{important} important")

        return f"{self.title}: {', '.join(parts)} questions"


class Clarifier:
    """
    Generates smart clarification questions based on context.

    Usage:
        clarifier = Clarifier()

        # Get questions for a login page
        bundle = clarifier.for_page_type("login", found_elements=["email", "password", "submit"])

        # Get questions for ambiguous input
        bundle = clarifier.for_ambiguous_feature("user authentication")
    """

    def __init__(self, max_questions: int = 5):
        """
        Initialize clarifier.

        Args:
            max_questions: Maximum questions to ask at once
        """
        self.max_questions = max_questions

    def for_page_type(
        self,
        page_type: str,
        found_elements: Optional[List[str]] = None,
        url: Optional[str] = None,
    ) -> ClarificationBundle:
        """Generate questions for a detected page type."""
        questions = []

        # Page-specific questions
        page_type_lower = page_type.lower()
        if page_type_lower == "login":
            questions.extend(self._login_questions(found_elements))
        elif page_type_lower == "signup":
            questions.extend(self._signup_questions(found_elements))
        elif page_type_lower == "checkout":
            questions.extend(self._checkout_questions(found_elements))
        elif page_type_lower == "search":
            questions.extend(self._search_questions(found_elements))
        elif page_type_lower == "form":
            questions.extend(self._form_questions(found_elements))
        elif page_type_lower == "settings":
            questions.extend(self._settings_questions(found_elements))
        elif page_type_lower == "profile":
            questions.extend(self._profile_questions(found_elements))
        elif page_type_lower == "dashboard":
            questions.extend(self._dashboard_questions(found_elements))
        elif page_type_lower in ["list", "table"]:
            questions.extend(self._list_questions(found_elements))
        else:
            questions.extend(self._generic_questions(page_type, found_elements))

        # Limit questions
        questions = questions[:self.max_questions]

        has_critical = any(q.priority == QuestionPriority.CRITICAL for q in questions)

        return ClarificationBundle(
            title=f"Questions about {page_type} page",
            questions=questions,
            required_before_proceed=has_critical,
        )

    def for_ambiguous_feature(
        self,
        feature_description: str,
        detected_types: Optional[List[str]] = None,
    ) -> ClarificationBundle:
        """Generate questions when feature intent is unclear."""
        questions = [
            ClarificationQuestion(
                question=f"What should '{feature_description}' accomplish?",
                priority=QuestionPriority.CRITICAL,
                category="intent",
            ),
            ClarificationQuestion(
                question="Who are the primary users of this feature?",
                priority=QuestionPriority.IMPORTANT,
                options=["End users", "Admin users", "Both"],
                default="End users",
                category="audience",
            ),
            ClarificationQuestion(
                question="Are there any specific business rules I should know?",
                priority=QuestionPriority.OPTIONAL,
                category="rules",
            ),
        ]

        if detected_types:
            questions.append(ClarificationQuestion(
                question=f"I detected these element types: {', '.join(detected_types)}. Is this complete?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No, there's more"],
                category="completeness",
            ))

        return ClarificationBundle(
            title=f"Clarifying: {feature_description}",
            questions=questions[:self.max_questions],
            required_before_proceed=True,
        )

    def for_test_focus(
        self,
        feature: str,
        suggested_categories: List[str],
    ) -> ClarificationBundle:
        """Ask about testing priorities."""
        questions = [
            ClarificationQuestion(
                question="Which testing areas should I prioritize?",
                priority=QuestionPriority.IMPORTANT,
                options=suggested_categories[:4],
                category="priority",
            ),
            ClarificationQuestion(
                question="Any specific edge cases you're worried about?",
                priority=QuestionPriority.OPTIONAL,
                category="edge_cases",
            ),
            ClarificationQuestion(
                question="Should I include accessibility testing?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes", "No", "Basic only"],
                default="Basic only",
                category="accessibility",
            ),
        ]

        return ClarificationBundle(
            title=f"Testing focus for {feature}",
            questions=questions,
            required_before_proceed=False,
        )

    def for_missing_info(
        self,
        what_is_missing: str,
        context: Optional[str] = None,
    ) -> ClarificationQuestion:
        """Generate a single question for missing information."""
        return ClarificationQuestion(
            question=f"I need to know: {what_is_missing}",
            priority=QuestionPriority.CRITICAL,
            context=context,
            category="missing_info",
        )

    # =========================================================================
    # Page-specific question generators
    # =========================================================================

    def _login_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to login pages."""
        questions = []

        # Check what we found
        has_social = elements and any("google" in e.lower() or "facebook" in e.lower() or "oauth" in e.lower() for e in elements)
        has_2fa = elements and any("2fa" in e.lower() or "otp" in e.lower() or "code" in e.lower() for e in elements)
        has_remember = elements and any("remember" in e.lower() for e in elements)

        if not has_social:
            questions.append(ClarificationQuestion(
                question="Does this login support social sign-in (Google, Facebook, etc.)?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No"],
                category="auth_method",
            ))

        if not has_2fa:
            questions.append(ClarificationQuestion(
                question="Is two-factor authentication (2FA) enabled?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No", "Optional"],
                category="security",
            ))

        questions.append(ClarificationQuestion(
            question="What's the lockout policy after failed attempts?",
            priority=QuestionPriority.OPTIONAL,
            options=["3 attempts", "5 attempts", "No lockout", "Unknown"],
            default="Unknown",
            category="security",
        ))

        return questions

    def _signup_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to signup pages."""
        questions = [
            ClarificationQuestion(
                question="What fields are required for registration?",
                priority=QuestionPriority.IMPORTANT,
                category="requirements",
            ),
            ClarificationQuestion(
                question="Are there password complexity requirements?",
                priority=QuestionPriority.IMPORTANT,
                options=["Strong (8+ chars, symbols)", "Medium (6+ chars)", "Weak (any)", "Unknown"],
                category="validation",
            ),
            ClarificationQuestion(
                question="Is email verification required?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes", "No"],
                default="Yes",
                category="flow",
            ),
        ]
        return questions

    def _checkout_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to checkout pages."""
        questions = [
            ClarificationQuestion(
                question="What payment methods should I test?",
                priority=QuestionPriority.CRITICAL,
                options=["Credit card", "PayPal", "Apple Pay", "All"],
                category="payment",
            ),
            ClarificationQuestion(
                question="Should I test guest checkout (no account)?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No", "If available"],
                default="If available",
                category="flow",
            ),
            ClarificationQuestion(
                question="Are there promo codes to test?",
                priority=QuestionPriority.OPTIONAL,
                category="discounts",
            ),
        ]
        return questions

    def _search_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to search pages."""
        questions = [
            ClarificationQuestion(
                question="What type of content is being searched?",
                priority=QuestionPriority.IMPORTANT,
                options=["Products", "Articles", "Users", "Mixed"],
                category="content",
            ),
            ClarificationQuestion(
                question="Are there filters or faceted search?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes", "No"],
                category="features",
            ),
        ]
        return questions

    def _form_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions for generic forms."""
        questions = [
            ClarificationQuestion(
                question="What is the purpose of this form?",
                priority=QuestionPriority.CRITICAL,
                category="intent",
            ),
            ClarificationQuestion(
                question="Which fields are required vs optional?",
                priority=QuestionPriority.IMPORTANT,
                category="validation",
            ),
        ]
        return questions

    def _settings_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to settings pages."""
        questions = [
            ClarificationQuestion(
                question="What settings can users change here?",
                priority=QuestionPriority.IMPORTANT,
                options=["Profile info", "Password/Security", "Notifications", "All of the above"],
                default="All of the above",
                category="scope",
            ),
            ClarificationQuestion(
                question="Can users delete their account from this page?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No", "Not sure"],
                category="danger_zone",
            ),
            ClarificationQuestion(
                question="Are there any settings that require re-authentication?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes, password change", "Yes, email change", "No"],
                category="security",
            ),
        ]
        return questions

    def _profile_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to profile pages."""
        questions = [
            ClarificationQuestion(
                question="Can users upload a profile picture?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes", "No"],
                category="features",
            ),
            ClarificationQuestion(
                question="Is any profile information public to other users?",
                priority=QuestionPriority.IMPORTANT,
                options=["Yes, some fields", "No, all private", "User can choose"],
                category="privacy",
            ),
            ClarificationQuestion(
                question="Are there character limits on fields like bio or name?",
                priority=QuestionPriority.OPTIONAL,
                category="validation",
            ),
        ]
        return questions

    def _dashboard_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to dashboard pages."""
        questions = [
            ClarificationQuestion(
                question="What widgets or sections appear on this dashboard?",
                priority=QuestionPriority.IMPORTANT,
                category="layout",
            ),
            ClarificationQuestion(
                question="Does the dashboard data refresh automatically?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes, real-time", "Yes, every few minutes", "No, manual only"],
                category="behavior",
            ),
            ClarificationQuestion(
                question="Can users customize which widgets they see?",
                priority=QuestionPriority.OPTIONAL,
                options=["Yes", "No"],
                category="personalization",
            ),
        ]
        return questions

    def _list_questions(self, elements: Optional[List[str]]) -> List[ClarificationQuestion]:
        """Questions specific to list/table pages."""
        questions = [
            ClarificationQuestion(
                question="What items does this list display?",
                priority=QuestionPriority.IMPORTANT,
                options=["Products", "Users", "Orders", "Custom data"],
                category="content",
            ),
            ClarificationQuestion(
                question="Does it support sorting and filtering?",
                priority=QuestionPriority.IMPORTANT,
                options=["Both", "Sorting only", "Filtering only", "Neither"],
                category="features",
            ),
            ClarificationQuestion(
                question="How many items per page (pagination)?",
                priority=QuestionPriority.OPTIONAL,
                options=["10", "25", "50", "Infinite scroll", "Unknown"],
                default="Unknown",
                category="pagination",
            ),
        ]
        return questions

    def _generic_questions(
        self,
        page_type: str,
        elements: Optional[List[str]],
    ) -> List[ClarificationQuestion]:
        """Generic questions for unknown page types."""
        questions = [
            ClarificationQuestion(
                question=f"Help me understand - what does this {page_type} page do?",
                priority=QuestionPriority.IMPORTANT,
                category="intent",
            ),
            ClarificationQuestion(
                question="What's the main thing users do on this page?",
                priority=QuestionPriority.IMPORTANT,
                category="actions",
            ),
            ClarificationQuestion(
                question="Anything you're particularly worried about with this feature?",
                priority=QuestionPriority.OPTIONAL,
                category="focus",
            ),
        ]
        return questions
