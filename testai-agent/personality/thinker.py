"""
TestAI Agent - Thinking Aloud System

Makes the agent's reasoning visible to users.
Good QA engineers explain their thinking - it builds trust.

Design Philosophy:
- Show work, but don't overwhelm
- Vary the phrasing to feel natural
- Connect thinking to actions
- Express uncertainty when appropriate
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum
import random
import time


class ThinkingPhase(Enum):
    """Phases of the thinking process."""
    RECEIVING = "receiving"          # Just got input
    ANALYZING = "analyzing"          # Looking at the page/feature
    DETECTING = "detecting"          # Identifying patterns
    PLANNING = "planning"            # Planning test approach
    GENERATING = "generating"        # Creating tests
    REVIEWING = "reviewing"          # Checking results
    UNCERTAIN = "uncertain"          # Not sure about something
    FOUND_ISSUE = "found_issue"      # Spotted a problem
    COMPLETED = "completed"          # Done with task


@dataclass
class Thought:
    """A single thought to display."""
    text: str
    phase: ThinkingPhase
    confidence: float = 1.0  # 0-1, affects how certain the phrasing sounds
    delay: float = 0.3       # Seconds to pause after showing


class Thinker:
    """
    Generates human-like thinking-aloud text.

    The thinker makes the agent feel more human by:
    1. Showing its reasoning process
    2. Using varied, natural phrasing
    3. Expressing appropriate uncertainty
    4. Building narrative flow

    Usage:
        thinker = Thinker()

        # Get a thought for a specific phase
        thought = thinker.think("analyzing")
        print(f"💭 {thought.text}")

        # Get a sequence of thoughts
        for thought in thinker.analyze_sequence("login"):
            print(f"💭 {thought.text}")
            time.sleep(thought.delay)
    """

    # Thought patterns for each phase
    PATTERNS = {
        ThinkingPhase.RECEIVING: [
            "Got it. Let me think about this...",
            "Okay, processing that...",
            "Understood. Give me a moment...",
            "Alright, let me work on this...",
            "Hmm, interesting request...",
        ],

        ThinkingPhase.ANALYZING: [
            "Looking at what we have here...",
            "Examining the structure...",
            "Checking the elements...",
            "Taking a closer look...",
            "Analyzing the page layout...",
            "Seeing what we're working with...",
            "Mapping out the feature...",
        ],

        ThinkingPhase.DETECTING: [
            "I'm seeing a pattern here...",
            "This looks like {context}...",
            "The structure suggests {context}...",
            "Based on what I see, this appears to be {context}...",
            "Detecting {context} characteristics...",
            "This has the hallmarks of {context}...",
        ],

        ThinkingPhase.PLANNING: [
            "Thinking through the scenarios...",
            "Planning what to test...",
            "Mapping out the edge cases...",
            "Figuring out the critical paths...",
            "Considering what could go wrong...",
            "Identifying the risk areas...",
            "Prioritizing the test cases...",
        ],

        ThinkingPhase.GENERATING: [
            "Writing up the tests...",
            "Generating test cases...",
            "Creating the test suite...",
            "Putting together the scenarios...",
            "Building the test plan...",
            "Crafting the test cases...",
        ],

        ThinkingPhase.REVIEWING: [
            "Let me double-check this...",
            "Reviewing what I've got...",
            "Making sure I haven't missed anything...",
            "Verifying the coverage...",
            "Checking my work...",
        ],

        ThinkingPhase.UNCERTAIN: [
            "I'm not 100% sure about this...",
            "This is a bit unclear...",
            "I might be missing something here...",
            "My confidence isn't super high on this one...",
            "I'd want to verify this...",
            "This needs a closer look...",
        ],

        ThinkingPhase.FOUND_ISSUE: [
            "Wait, this is interesting...",
            "Hmm, found something...",
            "This could be a problem...",
            "Let me flag this...",
            "This needs attention...",
            "Spotted something worth noting...",
        ],

        ThinkingPhase.COMPLETED: [
            "Done with that.",
            "Finished.",
            "All set.",
            "That's wrapped up.",
            "Complete.",
        ],
    }

    # Context-specific patterns for different page types
    PAGE_SPECIFIC_THOUGHTS = {
        "login": [
            "Checking authentication flow...",
            "Looking at the security setup...",
            "Examining credential handling...",
            "Checking for session management...",
        ],
        "signup": [
            "Looking at registration validation...",
            "Checking email verification flow...",
            "Examining password requirements...",
            "Looking at duplicate handling...",
        ],
        "checkout": [
            "Examining payment flow...",
            "Checking cart integrity...",
            "Looking at pricing logic...",
            "Verifying order processing...",
        ],
        "search": [
            "Looking at query handling...",
            "Checking result accuracy...",
            "Examining filter logic...",
            "Testing special characters...",
        ],
        "form": [
            "Checking field validation...",
            "Looking at submission handling...",
            "Examining error states...",
            "Testing input sanitization...",
        ],
    }

    # Confidence modifiers
    CONFIDENT_PREFIXES = [
        "I can see that",
        "Clearly,",
        "It's evident that",
        "I'm confident that",
    ]

    UNCERTAIN_PREFIXES = [
        "I think",
        "It seems like",
        "Possibly",
        "It appears that",
        "My guess is",
    ]

    def __init__(self, verbose: bool = True):
        """
        Initialize the thinker.

        Args:
            verbose: If True, show more detailed thoughts
        """
        self.verbose = verbose
        self.recent_thoughts: List[str] = []
        self.max_recent = 5  # Track recent to avoid repetition

    def think(
        self,
        phase: ThinkingPhase,
        context: Optional[str] = None,
        confidence: float = 1.0,
    ) -> Thought:
        """
        Generate a thought for a specific phase.

        Args:
            phase: The thinking phase
            context: Optional context (e.g., page type)
            confidence: How confident (affects phrasing)

        Returns:
            A Thought object
        """
        patterns = self.PATTERNS.get(phase, self.PATTERNS[ThinkingPhase.ANALYZING])

        # Filter out recently used patterns
        available = [p for p in patterns if p not in self.recent_thoughts]
        if not available:
            available = patterns
            self.recent_thoughts = []

        text = random.choice(available)

        # Handle context substitution
        if context and "{context}" in text:
            text = text.format(context=context)

        # Add confidence modifier for uncertain thoughts
        if confidence < 0.5 and phase != ThinkingPhase.UNCERTAIN:
            prefix = random.choice(self.UNCERTAIN_PREFIXES)
            text = f"{prefix} {text.lower()}"

        # Track recent
        self.recent_thoughts.append(text)
        if len(self.recent_thoughts) > self.max_recent:
            self.recent_thoughts.pop(0)

        # Determine delay based on phase
        delay = {
            ThinkingPhase.RECEIVING: 0.3,
            ThinkingPhase.ANALYZING: 0.5,
            ThinkingPhase.DETECTING: 0.3,
            ThinkingPhase.PLANNING: 0.5,
            ThinkingPhase.GENERATING: 0.6,
            ThinkingPhase.REVIEWING: 0.4,
            ThinkingPhase.UNCERTAIN: 0.3,
            ThinkingPhase.FOUND_ISSUE: 0.4,
            ThinkingPhase.COMPLETED: 0.2,
        }.get(phase, 0.3)

        return Thought(
            text=text,
            phase=phase,
            confidence=confidence,
            delay=delay,
        )

    def analyze_sequence(
        self,
        page_type: Optional[str] = None,
        include_planning: bool = True,
    ) -> List[Thought]:
        """
        Generate a sequence of thoughts for analyzing a page.

        Args:
            page_type: Type of page being analyzed
            include_planning: Whether to include planning thoughts

        Returns:
            List of Thought objects
        """
        thoughts = []

        # Start with analysis
        thoughts.append(self.think(ThinkingPhase.ANALYZING))

        # Add page-specific thought if available
        if page_type and page_type.lower() in self.PAGE_SPECIFIC_THOUGHTS:
            specific = random.choice(self.PAGE_SPECIFIC_THOUGHTS[page_type.lower()])
            thoughts.append(Thought(
                text=specific,
                phase=ThinkingPhase.ANALYZING,
                delay=0.4,
            ))

        # Detection
        if page_type:
            thoughts.append(self.think(ThinkingPhase.DETECTING, context=page_type))

        # Planning
        if include_planning:
            thoughts.append(self.think(ThinkingPhase.PLANNING))

        return thoughts

    def generate_sequence(self) -> List[Thought]:
        """Generate a sequence of thoughts for test generation."""
        return [
            self.think(ThinkingPhase.PLANNING),
            self.think(ThinkingPhase.GENERATING),
            self.think(ThinkingPhase.REVIEWING),
        ]

    def uncertainty_thought(self, about: str) -> Thought:
        """Express uncertainty about something."""
        text = f"I'm not entirely sure about {about}..."
        return Thought(
            text=text,
            phase=ThinkingPhase.UNCERTAIN,
            confidence=0.5,
            delay=0.3,
        )

    def discovery_thought(self, what: str) -> Thought:
        """Express finding something interesting."""
        prefixes = [
            "Wait,",
            "Interesting -",
            "Hmm,",
            "Oh,",
            "Found something:",
        ]
        text = f"{random.choice(prefixes)} {what}"
        return Thought(
            text=text,
            phase=ThinkingPhase.FOUND_ISSUE,
            confidence=0.9,
            delay=0.4,
        )


def think(phase: str, context: Optional[str] = None) -> str:
    """Quick helper to generate a thought."""
    thinker = Thinker()
    phase_enum = ThinkingPhase(phase) if phase in [p.value for p in ThinkingPhase] else ThinkingPhase.ANALYZING
    return thinker.think(phase_enum, context).text


def think_sequence(page_type: Optional[str] = None) -> List[str]:
    """Quick helper to generate a thinking sequence."""
    thinker = Thinker()
    return [t.text for t in thinker.analyze_sequence(page_type)]
