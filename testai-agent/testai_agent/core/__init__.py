"""
TestAI Agent - Core Module

The Cortex reasoning engine that:
- Queries the Brain for relevant knowledge
- Generates test plans with citations
- Performs risk assessment
- Asks clarifying questions like a real QA

Key Classes:
- Cortex: Main reasoning engine
- CitedTestCase: Test case with mandatory citation
- TestPlan: Complete test plan with risk assessment
- QAConsultantPersonality: Human-like personality traits
- SessionMemory: Conversation persistence
"""

from .cortex import (
    Cortex,
    create_cortex,
    CitedTestCase,
    TestPlan,
    RiskAssessment,
    TestCategory,
    RiskLevel
)

from .personality import (
    QAConsultantPersonality,
    ThinkingStream,
    ThinkingPhase,
    get_questions_for_feature,
)

from .memory import (
    SessionMemory,
    Session,
    ConversationTurn,
    GeneratedPlan,
)

from .report import (
    ReportGenerator,
    ExecutiveSummary,
)

__all__ = [
    'Cortex',
    'create_cortex',
    'CitedTestCase',
    'TestPlan',
    'RiskAssessment',
    'TestCategory',
    'RiskLevel',
    'QAConsultantPersonality',
    'ThinkingStream',
    'ThinkingPhase',
    'get_questions_for_feature',
    'SessionMemory',
    'Session',
    'ConversationTurn',
    'GeneratedPlan',
    'ReportGenerator',
    'ExecutiveSummary',
]
