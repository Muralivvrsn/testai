"""
TestAI Agent - Session Persistence

Saves and loads conversational context across CLI runs.
Remember what the user was working on, their preferences, and decisions.

Design: European pragmatism - store what matters, discard noise.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

from .memory import ConversationalMemory, Memory, MemoryType, WorkingContext


# ─────────────────────────────────────────────────────────────────
# Session Data Structures
# ─────────────────────────────────────────────────────────────────

@dataclass
class SessionMetadata:
    """Metadata about a saved session."""
    session_id: str
    created_at: str
    updated_at: str
    feature_focus: Optional[str] = None
    page_type: Optional[str] = None
    test_count: int = 0
    interaction_count: int = 0

    @classmethod
    def from_memory(cls, memory: ConversationalMemory, session_id: str) -> "SessionMetadata":
        """Create metadata from memory state."""
        now = datetime.now().isoformat()
        # Count tests from memories
        test_memories = [m for m in memory.memories if m.type == MemoryType.TEST]
        return cls(
            session_id=session_id,
            created_at=now,
            updated_at=now,
            feature_focus=memory.working.current_feature,
            page_type=memory.working.current_page_type,
            test_count=len(test_memories),
            interaction_count=len(memory.conversation_history),
        )


@dataclass
class SavedSession:
    """A complete saved session."""
    metadata: SessionMetadata
    working_context: Dict[str, Any]
    memories: List[Dict[str, Any]]
    decisions: List[str]
    preferences: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "metadata": asdict(self.metadata),
            "working_context": self.working_context,
            "memories": self.memories,
            "decisions": self.decisions,
            "preferences": self.preferences,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SavedSession":
        """Create from dictionary."""
        return cls(
            metadata=SessionMetadata(**data["metadata"]),
            working_context=data["working_context"],
            memories=data["memories"],
            decisions=data["decisions"],
            preferences=data.get("preferences", {}),
        )


# ─────────────────────────────────────────────────────────────────
# Session Store
# ─────────────────────────────────────────────────────────────────

class SessionStore:
    """
    Persistent storage for conversation sessions.

    Stores sessions as JSON files in a directory.
    Supports multiple sessions, auto-cleanup, and session resume.

    Usage:
        store = SessionStore()

        # Save current session
        store.save_session(memory, "my-session")

        # List available sessions
        for session in store.list_sessions():
            print(f"{session.session_id}: {session.feature_focus}")

        # Load a session
        memory = store.load_session("my-session")

        # Auto-save on exit
        store.auto_save(memory)
    """

    DEFAULT_DIR = ".testai_sessions"
    MAX_SESSIONS = 10  # Keep last 10 sessions
    SESSION_EXPIRY_DAYS = 7  # Sessions older than 7 days are cleaned up

    def __init__(self, session_dir: Optional[str] = None):
        """
        Initialize the session store.

        Args:
            session_dir: Directory for session files (default: ~/.testai_sessions)
        """
        if session_dir:
            self.session_dir = Path(session_dir)
        else:
            # Use home directory for persistence across projects
            self.session_dir = Path.home() / self.DEFAULT_DIR

        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._current_session_id: Optional[str] = None

    def _session_path(self, session_id: str) -> Path:
        """Get path for a session file."""
        # Sanitize session_id
        safe_id = "".join(c for c in session_id if c.isalnum() or c in "-_")
        return self.session_dir / f"{safe_id}.json"

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"session_{timestamp}"

    def save_session(
        self,
        memory: ConversationalMemory,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Save a session to disk.

        Args:
            memory: ConversationalMemory to save
            session_id: Optional ID (auto-generated if not provided)

        Returns:
            Session ID
        """
        if not session_id:
            session_id = self._current_session_id or self._generate_session_id()

        # Build saved session
        session = SavedSession(
            metadata=SessionMetadata.from_memory(memory, session_id),
            working_context={
                "current_feature": memory.working.current_feature,
                "current_page_type": memory.working.current_page_type,
                "test_focus": memory.working.test_focus,
                "pending_questions": memory.working.pending_questions,
                "confirmed_requirements": memory.working.confirmed_requirements,
                "identified_risks": memory.working.identified_risks,
            },
            memories=[
                {
                    "type": m.type.value,
                    "content": m.content,
                    "importance": m.importance,
                    "source_section": m.source_section,
                    "timestamp": m.timestamp.isoformat() if hasattr(m.timestamp, 'isoformat') else str(m.timestamp),
                }
                for m in memory.memories
            ],
            decisions=[m.content for m in memory.get_decisions()],
            preferences=memory.get_preferences(),
        )

        # Write to file
        path = self._session_path(session_id)
        with open(path, "w") as f:
            json.dump(session.to_dict(), f, indent=2)

        self._current_session_id = session_id

        # Cleanup old sessions
        self._cleanup_old_sessions()

        return session_id

    def load_session(self, session_id: str) -> Optional[ConversationalMemory]:
        """
        Load a session from disk.

        Args:
            session_id: Session to load

        Returns:
            ConversationalMemory or None if not found
        """
        path = self._session_path(session_id)

        if not path.exists():
            return None

        try:
            with open(path) as f:
                data = json.load(f)

            saved = SavedSession.from_dict(data)

            # Reconstruct memory
            memory = ConversationalMemory()

            # Restore working context
            wc = saved.working_context
            memory.set_working_context(
                feature=wc.get("current_feature"),
                page_type=wc.get("current_page_type"),
                test_focus=wc.get("test_focus"),
            )
            memory.working.pending_questions = wc.get("pending_questions", [])
            memory.working.confirmed_requirements = wc.get("confirmed_requirements", [])
            memory.working.identified_risks = wc.get("identified_risks", [])

            # Restore memories
            for m_data in saved.memories:
                memory_type = MemoryType(m_data["type"])
                memory.remember(
                    memory_type=memory_type,
                    content=m_data["content"],
                    importance=m_data.get("importance", 0.5),
                    source_section=m_data.get("source_section"),
                )

            # Restore preferences
            for key, value in saved.preferences.items():
                memory.set_preference(key, value)

            self._current_session_id = session_id

            return memory

        except (json.JSONDecodeError, KeyError) as e:
            # Corrupted session file
            return None

    def list_sessions(self, limit: int = 10) -> List[SessionMetadata]:
        """
        List available sessions.

        Args:
            limit: Maximum sessions to return

        Returns:
            List of session metadata, most recent first
        """
        sessions = []

        for path in self.session_dir.glob("*.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                metadata = SessionMetadata(**data["metadata"])
                sessions.append(metadata)
            except (json.JSONDecodeError, KeyError):
                continue

        # Sort by updated_at descending
        sessions.sort(key=lambda s: s.updated_at, reverse=True)

        return sessions[:limit]

    def get_latest_session(self) -> Optional[str]:
        """Get the most recent session ID."""
        sessions = self.list_sessions(limit=1)
        return sessions[0].session_id if sessions else None

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session to delete

        Returns:
            True if deleted, False if not found
        """
        path = self._session_path(session_id)

        if path.exists():
            path.unlink()
            return True
        return False

    def _cleanup_old_sessions(self):
        """Remove old sessions beyond limit and expiry."""
        sessions = self.list_sessions(limit=100)

        # Remove sessions beyond max
        if len(sessions) > self.MAX_SESSIONS:
            for session in sessions[self.MAX_SESSIONS:]:
                self.delete_session(session.session_id)

        # Remove expired sessions
        cutoff = datetime.now() - timedelta(days=self.SESSION_EXPIRY_DAYS)
        for session in sessions:
            try:
                updated = datetime.fromisoformat(session.updated_at)
                if updated < cutoff:
                    self.delete_session(session.session_id)
            except ValueError:
                continue

    def auto_save(self, memory: ConversationalMemory) -> str:
        """
        Auto-save current session (for exit hooks).

        Args:
            memory: Memory to save

        Returns:
            Session ID
        """
        return self.save_session(memory, self._current_session_id)

    def get_resume_context(self) -> Optional[str]:
        """
        Get a human-readable summary of the last session for resuming.

        Returns:
            Summary string or None
        """
        latest_id = self.get_latest_session()
        if not latest_id:
            return None

        path = self._session_path(latest_id)
        if not path.exists():
            return None

        try:
            with open(path) as f:
                data = json.load(f)

            metadata = SessionMetadata(**data["metadata"])
            wc = data.get("working_context", {})

            parts = []

            if metadata.feature_focus:
                parts.append(f"Working on: {metadata.feature_focus}")
            if metadata.page_type:
                parts.append(f"Page type: {metadata.page_type}")
            if metadata.test_count:
                parts.append(f"Tests generated: {metadata.test_count}")

            if not parts:
                return None

            # Calculate time since last session
            try:
                updated = datetime.fromisoformat(metadata.updated_at)
                delta = datetime.now() - updated
                if delta.days > 0:
                    time_str = f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
                elif delta.seconds > 3600:
                    hours = delta.seconds // 3600
                    time_str = f"{hours} hour{'s' if hours > 1 else ''} ago"
                else:
                    minutes = delta.seconds // 60
                    time_str = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                parts.append(f"Last active: {time_str}")
            except ValueError:
                pass

            return " | ".join(parts)

        except (json.JSONDecodeError, KeyError):
            return None


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

def save_session(memory: ConversationalMemory, session_id: Optional[str] = None) -> str:
    """Quick save session."""
    store = SessionStore()
    return store.save_session(memory, session_id)


def load_session(session_id: str) -> Optional[ConversationalMemory]:
    """Quick load session."""
    store = SessionStore()
    return store.load_session(session_id)


def load_latest_session() -> Optional[ConversationalMemory]:
    """Load the most recent session."""
    store = SessionStore()
    latest_id = store.get_latest_session()
    if latest_id:
        return store.load_session(latest_id)
    return None


def get_session_summary() -> Optional[str]:
    """Get summary of last session for display."""
    store = SessionStore()
    return store.get_resume_context()


if __name__ == "__main__":
    # Demo
    from .memory import ConversationalMemory, MemoryType

    # Create a memory with some data
    memory = ConversationalMemory()
    memory.add_user_turn("test login page")
    memory.set_working_context(feature="login", page_type="login")
    memory.remember(MemoryType.DECISION, "Focus on security first")
    memory.remember(MemoryType.USER_PREFERENCE, "Prefers detailed explanations")
    memory.working.generated_tests = ["TC-001", "TC-002"]

    # Save it
    store = SessionStore()
    session_id = store.save_session(memory)
    print(f"Saved session: {session_id}")

    # List sessions
    print("\nAvailable sessions:")
    for session in store.list_sessions():
        print(f"  {session.session_id}: {session.feature_focus} ({session.test_count} tests)")

    # Load it back
    loaded = store.load_session(session_id)
    if loaded:
        print(f"\nLoaded: {loaded.working.current_feature}")
        print(f"Tests: {loaded.working.generated_tests}")
        print(f"Decisions: {loaded.get_decisions()}")

    # Get resume context
    print(f"\nResume context: {store.get_resume_context()}")
