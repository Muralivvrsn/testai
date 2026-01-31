"""
TestAI Agent - Response Tone & Style

Makes responses feel human and conversational.
Follows European design principles: minimal, warm, purposeful.

Key Principles:
1. Don't dump information - reveal progressively
2. Show confidence levels naturally
3. Be conversational, not robotic
4. Every word has purpose
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum
import random


class Confidence(Enum):
    """How confident the agent is about something."""
    CERTAIN = "certain"        # 95%+ sure
    CONFIDENT = "confident"    # 80-95% sure
    LIKELY = "likely"          # 60-80% sure
    UNCERTAIN = "uncertain"    # 40-60% sure
    GUESSING = "guessing"      # <40% sure

    @property
    def score(self) -> float:
        """Numeric score for confidence."""
        return {
            Confidence.CERTAIN: 0.97,
            Confidence.CONFIDENT: 0.87,
            Confidence.LIKELY: 0.70,
            Confidence.UNCERTAIN: 0.50,
            Confidence.GUESSING: 0.30,
        }[self]


# Human-like phrases for different confidence levels
CONFIDENCE_PHRASES = {
    Confidence.CERTAIN: [
        "This is definitely",
        "I can confirm this is",
        "Clearly, this is",
        "No doubt about it, this is",
        "100% sure this is",
        "This is unmistakably",
    ],
    Confidence.CONFIDENT: [
        "I'm pretty sure this is",
        "This looks like",
        "I'd say this is",
        "Based on what I see, this is",
        "I'm confident this is",
        "This has all the hallmarks of",
    ],
    Confidence.LIKELY: [
        "This appears to be",
        "This seems like",
        "Most likely, this is",
        "I'd lean towards this being",
        "This has the characteristics of",
        "If I had to bet, this is",
    ],
    Confidence.UNCERTAIN: [
        "I think this might be",
        "This could be",
        "If I had to guess, this is",
        "I'm not entirely sure, but this looks like",
        "My best guess is this is",
        "This resembles",
    ],
    Confidence.GUESSING: [
        "I'm not sure, but maybe",
        "This is a bit unclear, perhaps",
        "Hard to tell, but possibly",
        "I'd need more context, but maybe",
        "Honestly, I'm guessing here - could be",
        "This is tricky to identify, but perhaps",
    ],
}

# Transition phrases for natural flow
TRANSITIONS = {
    "starting": [
        "Let me take a look...",
        "Looking at this...",
        "Examining the page...",
        "Alright, analyzing this...",
        "Let me see what we have here...",
        "Checking this out...",
        "Taking a closer look...",
        "One moment while I analyze this...",
    ],
    "found_something": [
        "I found",
        "I noticed",
        "I spotted",
        "I detected",
        "I identified",
        "I see",
        "There's",
        "I picked up on",
    ],
    "continuing": [
        "Also,",
        "Additionally,",
        "I also see",
        "Beyond that,",
        "Furthermore,",
        "On top of that,",
        "And there's more -",
        "Worth noting,",
    ],
    "concluding": [
        "So overall,",
        "In summary,",
        "To wrap up,",
        "Bottom line:",
        "All things considered,",
        "Taking everything together,",
        "The gist is:",
        "Here's the takeaway:",
    ],
    "asking": [
        "Quick question:",
        "Just to clarify:",
        "I want to make sure:",
        "Before I continue,",
        "One thing I need to know:",
        "Help me understand:",
        "Can you tell me:",
        "I'm curious about:",
    ],
    "thinking": [
        "Let me think about this...",
        "Hmm, interesting...",
        "Processing this...",
        "Working through this...",
        "Bear with me...",
        "This needs some thought...",
        "Analyzing the patterns...",
        "Running through scenarios...",
    ],
    "success": [
        "Done!",
        "All set.",
        "Finished.",
        "Complete.",
        "Got it.",
        "That's done.",
        "Wrapped up.",
        "Good to go.",
    ],
    "problem": [
        "Hmm, ran into something...",
        "Small hiccup here...",
        "Found an issue...",
        "Something's not right...",
        "Let me flag this...",
        "This needs attention...",
        "Spotted a problem...",
        "Heads up -",
    ],
}

# Greetings for different times of day / contexts
GREETINGS = [
    "Hey! What are we testing today?",
    "Hi there! Ready to find some bugs.",
    "Hello! Let's make sure this feature works perfectly.",
    "Hey! What would you like me to test?",
    "Hi! I'm ready to dig into whatever you've got.",
    "Hello! Point me at something to test.",
    "Hey there! What's on the testing agenda?",
    "Hi! Let's catch some bugs before users do.",
]

# Celebration phrases for achievements
CELEBRATIONS = {
    "small": [
        "Nice.",
        "Got it.",
        "Good find.",
        "Noted.",
        "Check.",
        "Solid.",
    ],
    "medium": [
        "Nice find!",
        "Good catch!",
        "That's useful.",
        "This is helpful.",
        "Getting somewhere.",
        "Making progress.",
    ],
    "large": [
        "Excellent!",
        "This is great!",
        "Really good progress!",
        "We're onto something.",
        "This is valuable stuff.",
        "Strong work here.",
    ],
    "critical_find": [
        "This is a big one!",
        "Critical find here!",
        "Glad we caught this!",
        "This could've been bad.",
        "Major catch!",
        "This was hiding in plain sight!",
    ],
}

# Softening phrases for when being uncertain
SOFTENERS = [
    "I could be wrong, but",
    "Take this with a grain of salt,",
    "My confidence isn't super high here, but",
    "I'd want to verify this, but",
    "This is preliminary, but",
    "Initial thoughts:",
]

# Empathy phrases for when things go wrong
EMPATHY_PHRASES = [
    "I understand that's frustrating.",
    "That's annoying, I get it.",
    "Yeah, this is tricky.",
    "Totally understand the concern.",
    "Makes sense you'd want to catch this.",
    "Good instinct to test this.",
]

# Phrases for explaining why something matters
IMPORTANCE_PHRASES = {
    "critical": [
        "This is critical because",
        "This matters a lot because",
        "You definitely want to test this because",
        "This could break things badly -",
        "High stakes here -",
    ],
    "security": [
        "Security-wise, this is important because",
        "From a security perspective,",
        "This could be a vulnerability because",
        "Bad actors could exploit this -",
    ],
    "ux": [
        "Users will notice this because",
        "This affects user experience -",
        "From a UX standpoint,",
        "Users might get confused here because",
    ],
    "edge_case": [
        "Edge case alert:",
        "This catches the corner case where",
        "Not obvious, but this matters when",
        "Easy to miss, but",
    ],
}


@dataclass
class StyledResponse:
    """A response styled for human consumption."""
    main_content: str
    confidence: Confidence
    suggestions: List[str]
    questions: List[str]
    metadata: Dict[str, Any]

    def __str__(self) -> str:
        """Render the full response."""
        parts = [self.main_content]

        if self.suggestions:
            parts.append("\n\nSuggestions:")
            for s in self.suggestions:
                parts.append(f"  → {s}")

        if self.questions:
            parts.append("\n\nQuestions:")
            for q in self.questions:
                parts.append(f"  ? {q}")

        return "\n".join(parts)


class ResponseStyler:
    """
    Styles agent responses to feel human.

    Usage:
        styler = ResponseStyler()

        # Style a classification result
        response = styler.classify_page(
            page_type="login",
            confidence=Confidence.CONFIDENT,
            elements_found=12
        )

        # Style a test generation result
        response = styler.tests_generated(
            count=15,
            categories=["security", "edge_case", "happy_path"]
        )
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize styler.

        Args:
            verbose: If True, include more details
        """
        self.verbose = verbose

    def _pick(self, phrases: List[str]) -> str:
        """Pick a random phrase for variety."""
        return random.choice(phrases)

    def _confidence_prefix(self, confidence: Confidence) -> str:
        """Get a natural confidence prefix."""
        return self._pick(CONFIDENCE_PHRASES[confidence])

    def classify_page(
        self,
        page_type: str,
        confidence: Confidence,
        elements_found: int = 0,
        hints: Optional[List[str]] = None,
    ) -> StyledResponse:
        """Style a page classification result."""
        prefix = self._confidence_prefix(confidence)

        main = f"{prefix} a {page_type} page."

        if elements_found > 0:
            main += f" Found {elements_found} testable elements."

        suggestions = []
        questions = []

        if confidence.score < 0.7:
            questions.append(f"Can you confirm this is a {page_type} page?")

        if hints:
            suggestions = hints[:3]  # Limit to 3

        return StyledResponse(
            main_content=main,
            confidence=confidence,
            suggestions=suggestions,
            questions=questions,
            metadata={"page_type": page_type, "elements": elements_found},
        )

    def tests_generated(
        self,
        count: int,
        categories: List[str],
        critical_count: int = 0,
    ) -> StyledResponse:
        """Style a test generation result."""
        if count == 0:
            main = "I couldn't generate any tests. Let me know more about what you're testing."
            confidence = Confidence.UNCERTAIN
        elif count < 5:
            main = f"Generated {count} test cases. Might need more context for comprehensive coverage."
            confidence = Confidence.LIKELY
        else:
            main = f"Generated {count} test cases across {len(categories)} categories."
            confidence = Confidence.CONFIDENT

        if critical_count > 0:
            main += f" Found {critical_count} critical edge cases!"

        cat_list = ", ".join(categories) if categories else "general"

        suggestions = [f"Categories covered: {cat_list}"]
        questions = []

        if count < 10:
            questions.append("Want me to dig deeper into any specific area?")

        return StyledResponse(
            main_content=main,
            confidence=confidence,
            suggestions=suggestions,
            questions=questions,
            metadata={"count": count, "categories": categories, "critical": critical_count},
        )

    def security_analysis(
        self,
        vulnerabilities: int,
        severity_high: int = 0,
        severity_medium: int = 0,
        severity_low: int = 0,
    ) -> StyledResponse:
        """Style a security analysis result."""
        if vulnerabilities == 0:
            main = "No obvious security issues found. The page follows good practices."
            confidence = Confidence.CONFIDENT
        elif severity_high > 0:
            main = f"⚠️ Found {severity_high} high-severity security concerns that need attention."
            confidence = Confidence.CERTAIN
        else:
            main = f"Found {vulnerabilities} potential security items to review."
            confidence = Confidence.CONFIDENT

        suggestions = []
        if severity_high > 0:
            suggestions.append("Address high-severity issues first")
        if severity_medium > 0:
            suggestions.append(f"Review {severity_medium} medium-priority items")

        return StyledResponse(
            main_content=main,
            confidence=confidence,
            suggestions=suggestions,
            questions=[],
            metadata={
                "total": vulnerabilities,
                "high": severity_high,
                "medium": severity_medium,
                "low": severity_low,
            },
        )

    def edge_cases(
        self,
        cases: List[Dict[str, Any]],
        feature: str,
    ) -> StyledResponse:
        """Style edge case detection results."""
        count = len(cases)

        if count == 0:
            main = f"No unusual edge cases for {feature}. Standard testing should suffice."
            confidence = Confidence.LIKELY
        elif count > 10:
            main = f"Found {count} edge cases for {feature}. Some interesting scenarios here!"
            confidence = Confidence.CONFIDENT
        else:
            main = f"Identified {count} edge cases to test for {feature}."
            confidence = Confidence.CONFIDENT

        # Highlight the most interesting ones
        suggestions = []
        for case in cases[:3]:
            if isinstance(case, dict) and "description" in case:
                suggestions.append(case["description"][:80])
            elif isinstance(case, str):
                suggestions.append(case[:80])

        return StyledResponse(
            main_content=main,
            confidence=confidence,
            suggestions=suggestions,
            questions=["Want me to prioritize these by risk level?"] if count > 5 else [],
            metadata={"count": count, "feature": feature},
        )

    def progress_update(
        self,
        current_step: str,
        total_steps: int,
        completed_steps: int,
    ) -> str:
        """Quick progress message."""
        progress = completed_steps / total_steps if total_steps > 0 else 0
        bar = "█" * int(progress * 10) + "░" * (10 - int(progress * 10))

        return f"{bar} {current_step} ({completed_steps}/{total_steps})"

    def error_message(
        self,
        error: str,
        recoverable: bool = True,
    ) -> StyledResponse:
        """Style an error message."""
        if recoverable:
            main = f"Hit a small snag: {error}. Let me try a different approach."
            confidence = Confidence.UNCERTAIN
        else:
            main = f"Ran into an issue: {error}. Need your help to continue."
            confidence = Confidence.GUESSING

        return StyledResponse(
            main_content=main,
            confidence=confidence,
            suggestions=["Try refreshing the page", "Check if the element still exists"] if recoverable else [],
            questions=["Should I skip this and continue?"] if recoverable else [],
            metadata={"error": error, "recoverable": recoverable},
        )


def styled_response(
    content: str,
    confidence: Confidence = Confidence.CONFIDENT,
    suggestions: Optional[List[str]] = None,
    questions: Optional[List[str]] = None,
) -> StyledResponse:
    """Quick helper to create a styled response."""
    return StyledResponse(
        main_content=content,
        confidence=confidence,
        suggestions=suggestions or [],
        questions=questions or [],
        metadata={},
    )
