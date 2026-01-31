"""
TestAI Agent - Conversation Module

Human-like conversation handling.
Makes the agent feel like a real QA colleague.

Components:
- Conversation: Main conversation state manager
- ConversationalMemory: Long-term context tracking
- HumanResponse: Response formatting
"""

from .interface import (
    Conversation,
    Message,
    ConversationState,
    greet,
    acknowledge_task,
    ask_for_clarification,
    think_aloud,
    suggest_follow_up,
    empathize,
    GREETINGS,
    ACKNOWLEDGMENTS,
    THINKING_PATTERNS,
    FOLLOW_UP_SUGGESTIONS,
)
from .responses import HumanResponse, format_test_cases, format_thinking
from .memory import (
    ConversationalMemory,
    Memory,
    MemoryType,
    ConversationTurn,
    WorkingContext,
    create_memory,
    extract_entities,
)
from .persistence import (
    SessionStore,
    SavedSession,
    SessionMetadata,
    save_session,
    load_session,
    load_latest_session,
    get_session_summary,
)

__all__ = [
    # Conversation
    'Conversation',
    'Message',
    'ConversationState',
    # Memory
    'ConversationalMemory',
    'Memory',
    'MemoryType',
    'ConversationTurn',
    'WorkingContext',
    'create_memory',
    'extract_entities',
    # Responses
    'HumanResponse',
    'format_test_cases',
    'format_thinking',
    # Functions
    'greet',
    'acknowledge_task',
    'ask_for_clarification',
    'think_aloud',
    'suggest_follow_up',
    'empathize',
    # Constants
    'GREETINGS',
    'ACKNOWLEDGMENTS',
    'THINKING_PATTERNS',
    'FOLLOW_UP_SUGGESTIONS',
    # Persistence
    'SessionStore',
    'SavedSession',
    'SessionMetadata',
    'save_session',
    'load_session',
    'load_latest_session',
    'get_session_summary',
]
