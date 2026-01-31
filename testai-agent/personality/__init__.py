"""
TestAI Agent - Personality Module

Makes the agent feel human, not robotic.
European design: clean, minimal, warm.

Components:
- ResponseStyler: Response tone and styling
- Clarifier: Basic clarification questions
- HumanClarifier: Advanced context-aware questions
- Celebrator: Achievement celebration
- Thinker: Thinking aloud patterns
"""

from .tone import ResponseStyler, Confidence, styled_response, TRANSITIONS, CELEBRATIONS
from .clarifier import Clarifier, ClarificationQuestion, ClarificationBundle
from .celebrator import Celebrator, Achievement, AchievementType
from .thinker import Thinker, Thought, ThinkingPhase, think, think_sequence
from .human_clarifier import (
    HumanClarifier,
    ClarifyingQuestion,
    QuestionContext,
    QuestionPriority,
    QuestionCategory,
    create_clarifier,
    get_clarifying_questions,
)
from .qa_consultant import (
    QAConsultantPersonality,
    ConsultantMood,
    Recommendation,
    ConsultantThought,
    create_consultant,
)

__all__ = [
    # Tone
    'ResponseStyler',
    'Confidence',
    'styled_response',
    'TRANSITIONS',
    'CELEBRATIONS',
    # Basic Clarifier
    'Clarifier',
    'ClarificationQuestion',
    'ClarificationBundle',
    # Human Clarifier
    'HumanClarifier',
    'ClarifyingQuestion',
    'QuestionContext',
    'QuestionPriority',
    'QuestionCategory',
    'create_clarifier',
    'get_clarifying_questions',
    # Celebrator
    'Celebrator',
    'Achievement',
    'AchievementType',
    # Thinker
    'Thinker',
    'Thought',
    'ThinkingPhase',
    'think',
    'think_sequence',
    # QA Consultant
    'QAConsultantPersonality',
    'ConsultantMood',
    'Recommendation',
    'ConsultantThought',
    'create_consultant',
]
