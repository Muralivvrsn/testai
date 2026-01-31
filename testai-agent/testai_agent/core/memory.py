"""
TestAI Agent - Session Memory Module

Provides persistent memory for the QA Consultant:
- Conversation history within a session
- Generated test plans (for reference)
- User preferences and context
- Learning from interactions

Storage: JSON files in .session/ directory
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class ConversationTurn:
    """A single turn in the conversation."""
    timestamp: str
    role: str  # 'user' or 'assistant'
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ConversationTurn':
        return cls(**data)


@dataclass
class GeneratedPlan:
    """A generated test plan summary."""
    timestamp: str
    feature: str
    test_count: int
    risk_level: str
    summary: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'GeneratedPlan':
        return cls(**data)


@dataclass
class Session:
    """A complete session with the agent."""
    id: str
    started_at: str
    last_activity: str
    conversation: List[ConversationTurn] = field(default_factory=list)
    generated_plans: List[GeneratedPlan] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'started_at': self.started_at,
            'last_activity': self.last_activity,
            'conversation': [t.to_dict() for t in self.conversation],
            'generated_plans': [p.to_dict() for p in self.generated_plans],
            'context': self.context,
            'preferences': self.preferences,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Session':
        return cls(
            id=data['id'],
            started_at=data['started_at'],
            last_activity=data['last_activity'],
            conversation=[ConversationTurn.from_dict(t) for t in data.get('conversation', [])],
            generated_plans=[GeneratedPlan.from_dict(p) for p in data.get('generated_plans', [])],
            context=data.get('context', {}),
            preferences=data.get('preferences', {}),
        )


class SessionMemory:
    """
    Manages session state and persistence.
    
    Features:
    - Automatic session creation
    - Conversation history tracking
    - Test plan archive
    - User preference learning
    """
    
    def __init__(self, storage_dir: str = ".session"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.session: Optional[Session] = None
        self._load_or_create_session()
        
    def _get_session_file(self) -> Path:
        """Get the current session file path."""
        return self.storage_dir / "current_session.json"
    
    def _load_or_create_session(self):
        """Load existing session or create new one."""
        session_file = self._get_session_file()
        
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                self.session = Session.from_dict(data)
                self.session.last_activity = datetime.now().isoformat()
            except (json.JSONDecodeError, KeyError):
                self._create_new_session()
        else:
            self._create_new_session()
            
    def _create_new_session(self):
        """Create a new session."""
        now = datetime.now().isoformat()
        self.session = Session(
            id=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            started_at=now,
            last_activity=now,
        )
        self._save()
        
    def _save(self):
        """Save session to disk."""
        if self.session:
            session_file = self._get_session_file()
            with open(session_file, 'w') as f:
                json.dump(self.session.to_dict(), f, indent=2)
                
    def add_user_message(self, content: str, metadata: Dict = None):
        """Record a user message."""
        turn = ConversationTurn(
            timestamp=datetime.now().isoformat(),
            role='user',
            content=content,
            metadata=metadata or {}
        )
        self.session.conversation.append(turn)
        self.session.last_activity = turn.timestamp
        self._save()
        
    def add_assistant_message(self, content: str, metadata: Dict = None):
        """Record an assistant message."""
        turn = ConversationTurn(
            timestamp=datetime.now().isoformat(),
            role='assistant',
            content=content,
            metadata=metadata or {}
        )
        self.session.conversation.append(turn)
        self.session.last_activity = turn.timestamp
        self._save()
        
    def add_generated_plan(self, feature: str, test_count: int, risk_level: str, summary: str):
        """Record a generated test plan."""
        plan = GeneratedPlan(
            timestamp=datetime.now().isoformat(),
            feature=feature,
            test_count=test_count,
            risk_level=risk_level,
            summary=summary,
        )
        self.session.generated_plans.append(plan)
        self._save()
        
    def set_context(self, key: str, value: Any):
        """Set a context value for the session."""
        self.session.context[key] = value
        self._save()
        
    def get_context(self, key: str, default: Any = None) -> Any:
        """Get a context value."""
        return self.session.context.get(key, default)
        
    def set_preference(self, key: str, value: Any):
        """Set a user preference."""
        self.session.preferences[key] = value
        self._save()
        
    def get_preference(self, key: str, default: Any = None) -> Any:
        """Get a user preference."""
        return self.session.preferences.get(key, default)
        
    def get_conversation_summary(self, last_n: int = 5) -> str:
        """Get a summary of recent conversation."""
        recent = self.session.conversation[-last_n:] if self.session.conversation else []
        
        if not recent:
            return "No previous conversation."
            
        lines = ["Recent conversation:"]
        for turn in recent:
            role = "You" if turn.role == 'user' else "Alex"
            preview = turn.content[:100] + "..." if len(turn.content) > 100 else turn.content
            lines.append(f"  {role}: {preview}")
            
        return '\n'.join(lines)
        
    def get_previous_plans_summary(self) -> str:
        """Get a summary of previously generated plans."""
        if not self.session.generated_plans:
            return "No test plans generated yet in this session."
            
        lines = ["Previously generated test plans:"]
        for plan in self.session.generated_plans:
            lines.append(f"  • {plan.feature}: {plan.test_count} tests ({plan.risk_level} risk)")
            
        return '\n'.join(lines)
        
    def clear_session(self):
        """Clear the current session and start fresh."""
        self._create_new_session()
        
    def export_session(self, filepath: str):
        """Export session to a file."""
        with open(filepath, 'w') as f:
            json.dump(self.session.to_dict(), f, indent=2)
            
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics."""
        return {
            "session_id": self.session.id,
            "started": self.session.started_at,
            "conversation_turns": len(self.session.conversation),
            "plans_generated": len(self.session.generated_plans),
            "total_tests_generated": sum(p.test_count for p in self.session.generated_plans),
        }
