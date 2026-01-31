"""
TestAI Agent - Comment System

Threaded comment system for test case discussions
with resolution tracking and mentions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid
import re


class CommentType(Enum):
    """Types of comments."""
    GENERAL = "general"  # General discussion
    SUGGESTION = "suggestion"  # Suggested change
    QUESTION = "question"  # Question about the test
    ISSUE = "issue"  # Problem identified
    PRAISE = "praise"  # Positive feedback
    BLOCKING = "blocking"  # Blocks approval


class ThreadStatus(Enum):
    """Status of a comment thread."""
    OPEN = "open"
    RESOLVED = "resolved"
    OUTDATED = "outdated"  # Test changed since comment


@dataclass
class Mention:
    """A user mention in a comment."""
    user_id: str
    username: str
    position: int  # Position in comment text


@dataclass
class Comment:
    """A single comment in a thread."""
    id: str
    author_id: str
    author_name: str
    content: str
    comment_type: CommentType
    timestamp: datetime
    edited_at: Optional[datetime] = None
    reactions: Dict[str, List[str]] = field(default_factory=dict)  # emoji -> user_ids
    mentions: List[Mention] = field(default_factory=list)


@dataclass
class CommentThread:
    """A thread of comments on a test case."""
    id: str
    test_id: str
    line_reference: Optional[str]  # e.g., "step:3" or "expected_result"
    status: ThreadStatus
    comments: List[Comment]
    created_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


@dataclass
class ThreadSummary:
    """Summary of comment threads."""
    total_threads: int
    open_threads: int
    resolved_threads: int
    blocking_comments: int
    total_comments: int
    participants: Set[str]


class CommentManager:
    """
    Manages comment threads on test cases.

    Supports:
    - Threaded discussions on specific test parts
    - @mentions with notifications
    - Reactions (emoji)
    - Thread resolution tracking
    - Blocking comments that prevent approval
    """

    MENTION_PATTERN = re.compile(r"@(\w+)")

    def __init__(self):
        """Initialize the comment manager."""
        self._threads: Dict[str, CommentThread] = {}
        self._threads_by_test: Dict[str, List[str]] = {}  # test_id -> thread_ids
        self._listeners: List[callable] = []

    def create_thread(
        self,
        test_id: str,
        author_id: str,
        author_name: str,
        content: str,
        comment_type: CommentType = CommentType.GENERAL,
        line_reference: Optional[str] = None,
    ) -> CommentThread:
        """Create a new comment thread on a test."""
        thread_id = f"THR-{uuid.uuid4().hex[:8].upper()}"
        comment_id = f"CMT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now()

        # Extract mentions
        mentions = self._extract_mentions(content)

        initial_comment = Comment(
            id=comment_id,
            author_id=author_id,
            author_name=author_name,
            content=content,
            comment_type=comment_type,
            timestamp=now,
            mentions=mentions,
        )

        thread = CommentThread(
            id=thread_id,
            test_id=test_id,
            line_reference=line_reference,
            status=ThreadStatus.OPEN,
            comments=[initial_comment],
            created_at=now,
        )

        self._threads[thread_id] = thread

        if test_id not in self._threads_by_test:
            self._threads_by_test[test_id] = []
        self._threads_by_test[test_id].append(thread_id)

        self._notify("thread_created", thread, mentions)

        return thread

    def reply(
        self,
        thread_id: str,
        author_id: str,
        author_name: str,
        content: str,
        comment_type: CommentType = CommentType.GENERAL,
    ) -> Optional[Comment]:
        """Add a reply to an existing thread."""
        thread = self._threads.get(thread_id)
        if not thread:
            return None

        comment_id = f"CMT-{uuid.uuid4().hex[:8].upper()}"
        mentions = self._extract_mentions(content)

        comment = Comment(
            id=comment_id,
            author_id=author_id,
            author_name=author_name,
            content=content,
            comment_type=comment_type,
            timestamp=datetime.now(),
            mentions=mentions,
        )

        thread.comments.append(comment)
        self._notify("comment_added", thread, comment, mentions)

        return comment

    def edit_comment(
        self,
        thread_id: str,
        comment_id: str,
        author_id: str,
        new_content: str,
    ) -> bool:
        """Edit an existing comment."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        for comment in thread.comments:
            if comment.id == comment_id:
                if comment.author_id != author_id:
                    return False  # Can only edit own comments

                comment.content = new_content
                comment.edited_at = datetime.now()
                comment.mentions = self._extract_mentions(new_content)

                self._notify("comment_edited", thread, comment)
                return True

        return False

    def delete_comment(
        self,
        thread_id: str,
        comment_id: str,
        user_id: str,
    ) -> bool:
        """Delete a comment (soft delete by replacing content)."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        for comment in thread.comments:
            if comment.id == comment_id:
                if comment.author_id != user_id:
                    return False  # Can only delete own comments

                comment.content = "[Comment deleted]"
                comment.edited_at = datetime.now()
                comment.mentions = []

                self._notify("comment_deleted", thread, comment)
                return True

        return False

    def add_reaction(
        self,
        thread_id: str,
        comment_id: str,
        user_id: str,
        emoji: str,
    ) -> bool:
        """Add a reaction to a comment."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        for comment in thread.comments:
            if comment.id == comment_id:
                if emoji not in comment.reactions:
                    comment.reactions[emoji] = []

                if user_id not in comment.reactions[emoji]:
                    comment.reactions[emoji].append(user_id)
                    self._notify("reaction_added", thread, comment, emoji, user_id)
                    return True

        return False

    def remove_reaction(
        self,
        thread_id: str,
        comment_id: str,
        user_id: str,
        emoji: str,
    ) -> bool:
        """Remove a reaction from a comment."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        for comment in thread.comments:
            if comment.id == comment_id:
                if emoji in comment.reactions and user_id in comment.reactions[emoji]:
                    comment.reactions[emoji].remove(user_id)
                    if not comment.reactions[emoji]:
                        del comment.reactions[emoji]
                    return True

        return False

    def resolve_thread(
        self,
        thread_id: str,
        user_id: str,
    ) -> bool:
        """Mark a thread as resolved."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        if thread.status == ThreadStatus.RESOLVED:
            return False

        thread.status = ThreadStatus.RESOLVED
        thread.resolved_at = datetime.now()
        thread.resolved_by = user_id

        self._notify("thread_resolved", thread)
        return True

    def unresolve_thread(
        self,
        thread_id: str,
    ) -> bool:
        """Reopen a resolved thread."""
        thread = self._threads.get(thread_id)
        if not thread:
            return False

        if thread.status != ThreadStatus.RESOLVED:
            return False

        thread.status = ThreadStatus.OPEN
        thread.resolved_at = None
        thread.resolved_by = None

        self._notify("thread_reopened", thread)
        return True

    def mark_outdated(
        self,
        test_id: str,
    ):
        """Mark all threads for a test as outdated (test was modified)."""
        thread_ids = self._threads_by_test.get(test_id, [])

        for thread_id in thread_ids:
            thread = self._threads.get(thread_id)
            if thread and thread.status == ThreadStatus.OPEN:
                thread.status = ThreadStatus.OUTDATED
                self._notify("thread_outdated", thread)

    def get_thread(self, thread_id: str) -> Optional[CommentThread]:
        """Get a thread by ID."""
        return self._threads.get(thread_id)

    def get_threads_for_test(self, test_id: str) -> List[CommentThread]:
        """Get all threads for a test."""
        thread_ids = self._threads_by_test.get(test_id, [])
        return [self._threads[tid] for tid in thread_ids if tid in self._threads]

    def get_open_threads(self, test_id: str) -> List[CommentThread]:
        """Get open threads for a test."""
        threads = self.get_threads_for_test(test_id)
        return [t for t in threads if t.status == ThreadStatus.OPEN]

    def get_blocking_threads(self, test_id: str) -> List[CommentThread]:
        """Get threads with blocking comments."""
        threads = self.get_threads_for_test(test_id)
        blocking = []

        for thread in threads:
            if thread.status != ThreadStatus.OPEN:
                continue

            for comment in thread.comments:
                if comment.comment_type == CommentType.BLOCKING:
                    blocking.append(thread)
                    break

        return blocking

    def get_summary(self, test_id: str) -> ThreadSummary:
        """Get summary of threads for a test."""
        threads = self.get_threads_for_test(test_id)

        participants: Set[str] = set()
        total_comments = 0
        blocking = 0

        for thread in threads:
            for comment in thread.comments:
                participants.add(comment.author_id)
                total_comments += 1
                if comment.comment_type == CommentType.BLOCKING:
                    blocking += 1

        return ThreadSummary(
            total_threads=len(threads),
            open_threads=len([t for t in threads if t.status == ThreadStatus.OPEN]),
            resolved_threads=len([t for t in threads if t.status == ThreadStatus.RESOLVED]),
            blocking_comments=blocking,
            total_comments=total_comments,
            participants=participants,
        )

    def search_comments(
        self,
        query: str,
        test_id: Optional[str] = None,
    ) -> List[Comment]:
        """Search comments by content."""
        query_lower = query.lower()
        results = []

        threads = (
            self.get_threads_for_test(test_id)
            if test_id
            else self._threads.values()
        )

        for thread in threads:
            for comment in thread.comments:
                if query_lower in comment.content.lower():
                    results.append(comment)

        return results

    def get_mentions_for_user(
        self,
        user_id: str,
        unread_only: bool = False,
    ) -> List[tuple]:
        """Get all mentions for a user. Returns (thread, comment) tuples."""
        results = []

        for thread in self._threads.values():
            for comment in thread.comments:
                for mention in comment.mentions:
                    if mention.user_id == user_id:
                        results.append((thread, comment))

        return results

    def add_listener(self, callback: callable):
        """Add a listener for comment events."""
        self._listeners.append(callback)

    def _notify(self, event: str, *args):
        """Notify listeners of an event."""
        for listener in self._listeners:
            try:
                listener(event, *args)
            except Exception:
                pass

    def _extract_mentions(self, content: str) -> List[Mention]:
        """Extract @mentions from comment content."""
        mentions = []
        for match in self.MENTION_PATTERN.finditer(content):
            username = match.group(1)
            mentions.append(Mention(
                user_id=username.lower(),  # Normalize
                username=username,
                position=match.start(),
            ))
        return mentions

    def format_thread(self, thread: CommentThread) -> str:
        """Format a thread as readable text."""
        status_icons = {
            ThreadStatus.OPEN: "○",
            ThreadStatus.RESOLVED: "✓",
            ThreadStatus.OUTDATED: "⚠",
        }

        lines = [
            "-" * 50,
            f"  {status_icons.get(thread.status, '?')} Thread: {thread.id}",
            f"  Test: {thread.test_id}",
        ]

        if thread.line_reference:
            lines.append(f"  Reference: {thread.line_reference}")

        lines.extend([
            f"  Status: {thread.status.value}",
            "-" * 50,
        ])

        for i, comment in enumerate(thread.comments):
            time_str = comment.timestamp.strftime("%m/%d %H:%M")
            type_icon = {
                CommentType.GENERAL: "💬",
                CommentType.SUGGESTION: "💡",
                CommentType.QUESTION: "❓",
                CommentType.ISSUE: "🚨",
                CommentType.PRAISE: "👍",
                CommentType.BLOCKING: "🚫",
            }.get(comment.comment_type, "•")

            indent = "  " if i == 0 else "    "
            lines.append(f"{indent}{type_icon} {comment.author_name} ({time_str}):")
            lines.append(f"{indent}  {comment.content}")

            if comment.reactions:
                reactions_str = " ".join(
                    f"{emoji}({len(users)})"
                    for emoji, users in comment.reactions.items()
                )
                lines.append(f"{indent}  Reactions: {reactions_str}")

            if comment.edited_at:
                lines.append(f"{indent}  (edited)")

        lines.append("-" * 50)
        return "\n".join(lines)


def create_comment_thread(
    test_id: str,
    author_id: str,
    author_name: str,
    content: str,
    manager: Optional[CommentManager] = None,
    comment_type: CommentType = CommentType.GENERAL,
    line_reference: Optional[str] = None,
) -> CommentThread:
    """Create a comment thread (convenience function)."""
    if manager is None:
        manager = CommentManager()

    return manager.create_thread(
        test_id=test_id,
        author_id=author_id,
        author_name=author_name,
        content=content,
        comment_type=comment_type,
        line_reference=line_reference,
    )
