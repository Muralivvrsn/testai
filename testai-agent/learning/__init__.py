"""
TestAI Agent - Learning Module

Enables the agent to learn from test executions and improve over time.
This is what separates a good QA tool from a truly intelligent agent.
"""

from .feedback_loop import (
    FeedbackLoop,
    TestFeedback,
    FeedbackType,
    LearningInsight,
    create_feedback_loop,
)

from .pattern_learner import (
    PatternLearner,
    FailurePattern,
    SuccessPattern,
    LearnedRule,
    create_pattern_learner,
)

from .knowledge_updater import (
    KnowledgeUpdater,
    KnowledgeUpdate,
    UpdateType,
    create_knowledge_updater,
)

__all__ = [
    # Feedback Loop
    "FeedbackLoop",
    "TestFeedback",
    "FeedbackType",
    "LearningInsight",
    "create_feedback_loop",
    # Pattern Learner
    "PatternLearner",
    "FailurePattern",
    "SuccessPattern",
    "LearnedRule",
    "create_pattern_learner",
    # Knowledge Updater
    "KnowledgeUpdater",
    "KnowledgeUpdate",
    "UpdateType",
    "create_knowledge_updater",
]
