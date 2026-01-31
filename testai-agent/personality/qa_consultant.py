"""
TestAI Agent - QA Consultant Personality

Behaves like a Senior European QA Consultant:
- Asks clarifying questions before acting
- Shares reasoning and concerns
- Provides professional recommendations
- Maintains a helpful but thorough demeanor

Design: European professionalism - precise, thoughtful, thorough.
"""

import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum


class ConsultantMood(Enum):
    """Consultant's mood/tone."""
    PROFESSIONAL = "professional"
    CURIOUS = "curious"
    CONCERNED = "concerned"
    CONFIDENT = "confident"
    THOUGHTFUL = "thoughtful"


class QuestionPriority(Enum):
    """Priority of clarifying questions."""
    CRITICAL = "critical"    # Must know before proceeding
    IMPORTANT = "important"  # Should know for better results
    OPTIONAL = "optional"    # Nice to have


@dataclass
class ClarifyingQuestion:
    """A question the consultant wants to ask."""
    question: str
    priority: QuestionPriority
    context: str  # Why this question matters
    options: Optional[List[str]] = None  # Suggested answers
    default: Optional[str] = None  # Default if not answered
    tags: List[str] = field(default_factory=list)

    def format(self, include_context: bool = True) -> str:
        """Format for display."""
        parts = [f"  {self.question}"]

        if include_context:
            parts.append(f"    (This helps me {self.context})")

        if self.options:
            parts.append(f"    Options: {', '.join(self.options)}")

        if self.default:
            parts.append(f"    Default: {self.default}")

        return "\n".join(parts)


@dataclass
class ConsultantThought:
    """A thought the consultant shares."""
    thought: str
    mood: ConsultantMood
    source: Optional[str] = None  # Brain section if applicable


@dataclass
class Recommendation:
    """A professional recommendation."""
    title: str
    description: str
    priority: str  # critical, high, medium, low
    rationale: str
    action_items: List[str]


class QAConsultantPersonality:
    """
    Senior QA Consultant personality.

    Knows when to ask questions, what concerns to raise,
    and how to communicate professionally.

    Usage:
        consultant = QAConsultantPersonality()

        # Get opening greeting
        greeting = consultant.greet()

        # Analyze input and get questions
        questions = consultant.get_clarifying_questions(
            user_input="test login",
            detected_page_type="login",
        )

        # Get thoughts during analysis
        thoughts = consultant.share_thoughts(
            phase="analyzing",
            context={"feature": "login", "risks": ["security", "auth"]},
        )

        # Get recommendations
        recs = consultant.make_recommendations(
            test_results={"security": 8, "functional": 5},
            risks_found=["xss", "csrf"],
        )
    """

    # Greetings - professional but warm
    GREETINGS = [
        "Hello! I'm your QA consultant. Let me help you create thorough test coverage.",
        "Good to see you. What would you like me to help test today?",
        "Ready to help with your testing needs. What's on your mind?",
        "Hello. I'll help you think through the testing requirements systematically.",
    ]

    # Thinking phrases by mood
    THINKING_PHRASES = {
        ConsultantMood.PROFESSIONAL: [
            "Let me analyze the requirements...",
            "I'll review the relevant testing guidelines...",
            "Consulting the knowledge base for best practices...",
        ],
        ConsultantMood.CURIOUS: [
            "Interesting - let me dig deeper into this...",
            "I'm curious about the edge cases here...",
            "Let me explore the security implications...",
        ],
        ConsultantMood.CONCERNED: [
            "I notice some potential risks here...",
            "This raises some security concerns...",
            "We should be careful about this area...",
        ],
        ConsultantMood.CONFIDENT: [
            "I know exactly what we need here...",
            "This is a well-documented pattern...",
            "I've seen this many times - here's what works...",
        ],
        ConsultantMood.THOUGHTFUL: [
            "Let me think about the best approach...",
            "There are several angles to consider...",
            "This requires careful consideration...",
        ],
    }

    # Questions by page type
    PAGE_TYPE_QUESTIONS = {
        "login": [
            ClarifyingQuestion(
                question="Does your login support social authentication (Google, Facebook)?",
                priority=QuestionPriority.IMPORTANT,
                context="include OAuth-specific test cases",
                options=["Yes", "No", "Planning to add"],
                default="No",
                tags=["oauth", "social"],
            ),
            ClarifyingQuestion(
                question="Is there a 'Remember Me' or persistent session feature?",
                priority=QuestionPriority.IMPORTANT,
                context="test session persistence and security",
                options=["Yes", "No"],
                default="Yes",
                tags=["session", "security"],
            ),
            ClarifyingQuestion(
                question="What happens after 3-5 failed login attempts?",
                priority=QuestionPriority.CRITICAL,
                context="verify brute-force protection",
                options=["Account lockout", "CAPTCHA", "Delay", "Nothing"],
                tags=["security", "brute-force"],
            ),
            ClarifyingQuestion(
                question="Is multi-factor authentication (MFA/2FA) enabled?",
                priority=QuestionPriority.IMPORTANT,
                context="include MFA flow testing",
                options=["Yes - SMS", "Yes - App", "Yes - Email", "No"],
                tags=["mfa", "security"],
            ),
        ],
        "signup": [
            ClarifyingQuestion(
                question="What fields are required for registration?",
                priority=QuestionPriority.CRITICAL,
                context="test all validation rules",
                tags=["validation", "fields"],
            ),
            ClarifyingQuestion(
                question="Is email verification required?",
                priority=QuestionPriority.IMPORTANT,
                context="test the verification flow",
                options=["Yes - Required", "Yes - Optional", "No"],
                tags=["email", "verification"],
            ),
            ClarifyingQuestion(
                question="Are there password strength requirements?",
                priority=QuestionPriority.IMPORTANT,
                context="test password validation rules",
                options=["Strict", "Moderate", "Basic", "None"],
                tags=["password", "validation"],
            ),
        ],
        "checkout": [
            ClarifyingQuestion(
                question="What payment methods are supported?",
                priority=QuestionPriority.CRITICAL,
                context="test each payment integration",
                options=["Credit Card", "PayPal", "Apple Pay", "Multiple"],
                tags=["payment", "integration"],
            ),
            ClarifyingQuestion(
                question="Is guest checkout available?",
                priority=QuestionPriority.IMPORTANT,
                context="test both authenticated and guest flows",
                options=["Yes", "No"],
                tags=["guest", "flow"],
            ),
            ClarifyingQuestion(
                question="What happens if payment fails mid-transaction?",
                priority=QuestionPriority.CRITICAL,
                context="test error recovery and data integrity",
                tags=["error", "recovery", "payment"],
            ),
        ],
        "form": [
            ClarifyingQuestion(
                question="What type of data does this form collect?",
                priority=QuestionPriority.IMPORTANT,
                context="determine sensitivity and validation needs",
                options=["Personal info", "Contact only", "Feedback", "Application"],
                tags=["data", "sensitivity"],
            ),
            ClarifyingQuestion(
                question="Is there file upload functionality?",
                priority=QuestionPriority.IMPORTANT,
                context="test upload security and validation",
                options=["Yes", "No"],
                tags=["upload", "security"],
            ),
        ],
        "search": [
            ClarifyingQuestion(
                question="Should search results be paginated?",
                priority=QuestionPriority.OPTIONAL,
                context="test pagination behavior",
                options=["Yes", "No - Infinite scroll", "No - All results"],
                tags=["pagination", "ui"],
            ),
            ClarifyingQuestion(
                question="Are there filters or advanced search options?",
                priority=QuestionPriority.IMPORTANT,
                context="test filter combinations and edge cases",
                options=["Yes - Multiple filters", "Yes - Basic", "No"],
                tags=["filters", "functionality"],
            ),
        ],
    }

    # Generic questions for any page type
    GENERIC_QUESTIONS = [
        ClarifyingQuestion(
            question="What browsers and devices must be supported?",
            priority=QuestionPriority.IMPORTANT,
            context="define cross-browser test matrix",
            options=["Chrome only", "All modern", "Including IE11", "Mobile-first"],
            default="All modern",
            tags=["compatibility", "browsers"],
        ),
        ClarifyingQuestion(
            question="Are there accessibility requirements (WCAG)?",
            priority=QuestionPriority.IMPORTANT,
            context="include accessibility testing",
            options=["WCAG 2.1 AA", "WCAG 2.0", "Basic", "None specified"],
            default="Basic",
            tags=["accessibility", "wcag"],
        ),
        ClarifyingQuestion(
            question="What's the expected user load for this feature?",
            priority=QuestionPriority.OPTIONAL,
            context="consider performance testing",
            options=["Low (<100 users)", "Medium", "High (>10k)", "Unknown"],
            tags=["performance", "load"],
        ),
    ]

    def __init__(self, verbose: bool = True):
        """Initialize consultant personality."""
        self.verbose = verbose
        self.mood = ConsultantMood.PROFESSIONAL

    def greet(self) -> str:
        """Get a greeting."""
        return random.choice(self.GREETINGS)

    def set_mood(self, mood: ConsultantMood):
        """Set consultant's current mood."""
        self.mood = mood

    def get_thinking_phrase(self, mood: Optional[ConsultantMood] = None) -> str:
        """Get a thinking phrase for current mood."""
        mood = mood or self.mood
        phrases = self.THINKING_PHRASES.get(mood, self.THINKING_PHRASES[ConsultantMood.PROFESSIONAL])
        return random.choice(phrases)

    def get_clarifying_questions(
        self,
        user_input: str,
        detected_page_type: Optional[str] = None,
        max_questions: int = 5,
        priority_filter: Optional[QuestionPriority] = None,
    ) -> List[ClarifyingQuestion]:
        """
        Get clarifying questions based on context.

        Args:
            user_input: What the user asked for
            detected_page_type: Detected page type
            max_questions: Maximum questions to ask
            priority_filter: Only return questions of this priority or higher

        Returns:
            List of ClarifyingQuestion
        """
        questions = []

        # Add page-type specific questions
        if detected_page_type and detected_page_type in self.PAGE_TYPE_QUESTIONS:
            questions.extend(self.PAGE_TYPE_QUESTIONS[detected_page_type])

        # Add relevant generic questions
        questions.extend(self.GENERIC_QUESTIONS)

        # Filter by priority if specified
        if priority_filter:
            priority_order = [QuestionPriority.CRITICAL, QuestionPriority.IMPORTANT, QuestionPriority.OPTIONAL]
            cutoff_index = priority_order.index(priority_filter)
            allowed = priority_order[:cutoff_index + 1]
            questions = [q for q in questions if q.priority in allowed]

        # Sort by priority
        priority_order = {
            QuestionPriority.CRITICAL: 0,
            QuestionPriority.IMPORTANT: 1,
            QuestionPriority.OPTIONAL: 2,
        }
        questions.sort(key=lambda q: priority_order[q.priority])

        return questions[:max_questions]

    def format_questions_dialog(
        self,
        questions: List[ClarifyingQuestion],
        intro: Optional[str] = None,
    ) -> str:
        """
        Format questions as a dialog.

        Args:
            questions: Questions to format
            intro: Optional intro message

        Returns:
            Formatted dialog string
        """
        lines = []

        if intro:
            lines.append(intro)
        else:
            lines.append("Before I generate the test cases, I'd like to clarify a few things:")

        lines.append("")

        for i, q in enumerate(questions, 1):
            priority_icon = {
                QuestionPriority.CRITICAL: "🔴",
                QuestionPriority.IMPORTANT: "🟡",
                QuestionPriority.OPTIONAL: "🟢",
            }[q.priority]

            lines.append(f"{i}. {priority_icon} {q.question}")

            if q.options:
                lines.append(f"   Options: {' | '.join(q.options)}")

            if q.context:
                lines.append(f"   (This helps me {q.context})")

            lines.append("")

        lines.append("You can answer these, or just say 'proceed' to use defaults.")

        return "\n".join(lines)

    def share_thoughts(
        self,
        phase: str,
        context: Dict[str, Any],
    ) -> List[ConsultantThought]:
        """
        Share thoughts during analysis.

        Args:
            phase: Current phase (analyzing, searching, generating, etc.)
            context: Context information

        Returns:
            List of thoughts to share
        """
        thoughts = []

        if phase == "analyzing":
            feature = context.get("feature", "this feature")
            thoughts.append(ConsultantThought(
                thought=f"Analyzing requirements for {feature}...",
                mood=ConsultantMood.THOUGHTFUL,
            ))

            if "risks" in context:
                risks = context["risks"]
                if "security" in risks:
                    thoughts.append(ConsultantThought(
                        thought="I notice this involves authentication - security testing will be critical.",
                        mood=ConsultantMood.CONCERNED,
                    ))

        elif phase == "searching":
            thoughts.append(ConsultantThought(
                thought="Let me check my knowledge base for relevant testing patterns...",
                mood=ConsultantMood.PROFESSIONAL,
            ))

        elif phase == "found":
            sources = context.get("sources", [])
            if sources:
                thoughts.append(ConsultantThought(
                    thought=f"Found {len(sources)} relevant sections in the QA knowledge base.",
                    mood=ConsultantMood.CONFIDENT,
                    source=sources[0] if sources else None,
                ))

        elif phase == "generating":
            test_count = context.get("test_count", 0)
            thoughts.append(ConsultantThought(
                thought=f"Generating {test_count} comprehensive test cases...",
                mood=ConsultantMood.PROFESSIONAL,
            ))

        elif phase == "validating":
            thoughts.append(ConsultantThought(
                thought="Validating all test cases have proper citations...",
                mood=ConsultantMood.THOUGHTFUL,
            ))

        return thoughts

    def make_recommendations(
        self,
        test_results: Dict[str, int],
        risks_found: List[str],
        coverage_gaps: Optional[List[str]] = None,
    ) -> List[Recommendation]:
        """
        Make professional recommendations.

        Args:
            test_results: Count of tests by category
            risks_found: List of identified risks
            coverage_gaps: Areas needing more testing

        Returns:
            List of recommendations
        """
        recommendations = []

        # Security recommendation if risks found
        if risks_found:
            security_tests = test_results.get("security", 0)
            recommendations.append(Recommendation(
                title="Security Testing Priority",
                description=f"I've identified {len(risks_found)} potential security concerns.",
                priority="critical" if len(risks_found) > 2 else "high",
                rationale=f"Found risks: {', '.join(risks_found)}",
                action_items=[
                    f"Run all {security_tests} security test cases",
                    "Consider penetration testing for critical vulnerabilities",
                    "Review security test failures with the development team",
                ],
            ))

        # Coverage recommendation
        total_tests = sum(test_results.values())
        if total_tests < 10:
            recommendations.append(Recommendation(
                title="Expand Test Coverage",
                description="The current test count seems low for comprehensive coverage.",
                priority="medium",
                rationale=f"Only {total_tests} tests generated. Consider additional scenarios.",
                action_items=[
                    "Review edge cases for each user flow",
                    "Add negative test cases",
                    "Consider cross-browser testing",
                ],
            ))

        # Gap-specific recommendations
        if coverage_gaps:
            recommendations.append(Recommendation(
                title="Address Coverage Gaps",
                description=f"Some areas need additional testing: {', '.join(coverage_gaps)}",
                priority="high",
                rationale="These gaps could lead to production issues.",
                action_items=[
                    f"Create test cases for: {gap}"
                    for gap in coverage_gaps[:3]
                ],
            ))

        return recommendations

    def format_recommendations(self, recommendations: List[Recommendation]) -> str:
        """Format recommendations for display."""
        lines = []
        lines.append("## Professional Recommendations")
        lines.append("")

        for i, rec in enumerate(recommendations, 1):
            priority_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(rec.priority, "•")

            lines.append(f"### {i}. {priority_icon} {rec.title}")
            lines.append("")
            lines.append(rec.description)
            lines.append("")
            lines.append(f"**Rationale:** {rec.rationale}")
            lines.append("")
            lines.append("**Action Items:**")
            for item in rec.action_items:
                lines.append(f"- {item}")
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def create_consultant(verbose: bool = True) -> QAConsultantPersonality:
    """Create a QA consultant."""
    return QAConsultantPersonality(verbose=verbose)


if __name__ == "__main__":
    # Demo
    consultant = create_consultant()

    print(consultant.greet())
    print()

    # Get questions for login page
    questions = consultant.get_clarifying_questions(
        user_input="test login page",
        detected_page_type="login",
        max_questions=4,
    )

    print(consultant.format_questions_dialog(questions))
    print()

    # Share thoughts
    print("During analysis:")
    for thought in consultant.share_thoughts("analyzing", {"feature": "login", "risks": ["security"]}):
        print(f"  💭 {thought.thought}")

    print()

    # Make recommendations
    recommendations = consultant.make_recommendations(
        test_results={"security": 8, "functional": 5, "edge_case": 3},
        risks_found=["xss", "csrf", "brute_force"],
    )

    print(consultant.format_recommendations(recommendations))
