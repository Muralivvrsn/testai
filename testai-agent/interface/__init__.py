"""
TestAI Agent - Interface Module

Human-centric CLI interface that behaves like a Senior European QA Consultant.

Components:
- QAConsultant: Senior QA consultant persona
- RichOutput: Beautiful terminal output
- ThinkingDisplay: Visible thinking with progress
- ExecutiveOutputFormatter: Audience-specific formatting
- UsageDashboard: Real-time usage tracking
"""

from .consultant import QAConsultant, ConsultantResponse, ConsultationSession
from .rich_output import RichOutput, console
from .thinking_display import (
    ThinkingDisplay,
    ThinkingPhase,
    ThinkingStep,
    ThinkingSession,
    create_display,
)
from .executive_output import (
    ExecutiveOutputFormatter,
    Audience,
    RiskLevel,
    ShipDecision,
    TestSummary,
    RiskAssessment,
    format_for_executive,
    format_for_qa,
    format_for_engineering,
)
from .usage_dashboard import (
    UsageDashboard,
    ProviderUsage,
    BrainStatus,
    SessionStats,
    create_dashboard,
)
from .thinking_stream import (
    ThinkingStream,
    ThoughtType,
    Thought,
    create_stream,
)

__all__ = [
    # Consultant
    'QAConsultant',
    'ConsultantResponse',
    'ConsultationSession',
    # Rich Output
    'RichOutput',
    'console',
    # Thinking Display
    'ThinkingDisplay',
    'ThinkingPhase',
    'ThinkingStep',
    'ThinkingSession',
    'create_display',
    # Executive Output
    'ExecutiveOutputFormatter',
    'Audience',
    'RiskLevel',
    'ShipDecision',
    'TestSummary',
    'RiskAssessment',
    'format_for_executive',
    'format_for_qa',
    'format_for_engineering',
    # Usage Dashboard
    'UsageDashboard',
    'ProviderUsage',
    'BrainStatus',
    'SessionStats',
    'create_dashboard',
    # Thinking Stream
    'ThinkingStream',
    'ThoughtType',
    'Thought',
    'create_stream',
]
