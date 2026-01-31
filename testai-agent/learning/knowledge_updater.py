"""
TestAI Agent - Knowledge Updater

Updates the Brain's knowledge base with learned insights.
This closes the learning loop - insights from test executions
are fed back into the knowledge base to improve future generations.

The knowledge update cycle:
1. Feedback Loop generates insights
2. Pattern Learner identifies rules
3. Knowledge Updater adds rules to Brain
4. Future test generation uses updated knowledge

This is what makes the agent continuously improve.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pathlib import Path
import json


class UpdateType(Enum):
    """Types of knowledge updates."""
    NEW_RULE = "new_rule"
    RULE_REFINEMENT = "rule_refinement"
    DEPRECATION = "deprecation"
    PRIORITY_CHANGE = "priority_change"
    CATEGORY_EXPANSION = "category_expansion"
    EXAMPLE_ADDITION = "example_addition"


@dataclass
class KnowledgeUpdate:
    """A single update to the knowledge base."""
    update_id: str
    update_type: UpdateType
    timestamp: datetime = field(default_factory=datetime.now)

    # What's being updated
    section: str = ""  # e.g., "7.1" for login security
    category: str = ""

    # The update content
    content: str = ""
    reason: str = ""  # Why this update is being made

    # Source of the update
    source: str = ""  # e.g., "feedback_loop", "pattern_learner"
    evidence: List[str] = field(default_factory=list)

    # Validation
    confidence: float = 0.5
    validated: bool = False
    validator: Optional[str] = None  # Who/what validated this

    # Status
    applied: bool = False
    applied_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "update_id": self.update_id,
            "update_type": self.update_type.value,
            "timestamp": self.timestamp.isoformat(),
            "section": self.section,
            "category": self.category,
            "content": self.content,
            "reason": self.reason,
            "source": self.source,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "validated": self.validated,
            "validator": self.validator,
            "applied": self.applied,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KnowledgeUpdate":
        """Create from dictionary."""
        return cls(
            update_id=data["update_id"],
            update_type=UpdateType(data["update_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            section=data.get("section", ""),
            category=data.get("category", ""),
            content=data.get("content", ""),
            reason=data.get("reason", ""),
            source=data.get("source", ""),
            evidence=data.get("evidence", []),
            confidence=data.get("confidence", 0.5),
            validated=data.get("validated", False),
            validator=data.get("validator"),
            applied=data.get("applied", False),
            applied_at=datetime.fromisoformat(data["applied_at"]) if data.get("applied_at") else None,
        )


class KnowledgeUpdater:
    """
    Updates the Brain's knowledge base with learned insights.

    This is the mechanism that makes the agent continuously improve.
    It takes insights from the feedback loop and pattern learner,
    and integrates them into the knowledge base.
    """

    # Section mapping for different page types
    SECTION_MAP = {
        "login": "7",
        "signup": "8",
        "checkout": "9",
        "search": "10",
        "profile": "11",
        "general": "1",
    }

    # Category sections
    CATEGORY_SECTIONS = {
        "security": ".1",
        "validation": ".2",
        "functional": ".3",
        "edge_case": ".4",
        "accessibility": ".5",
        "performance": ".6",
    }

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        auto_apply_threshold: float = 0.85,
    ):
        """
        Initialize the knowledge updater.

        Args:
            storage_dir: Directory to store update history
            auto_apply_threshold: Confidence threshold for auto-applying updates
        """
        self.storage_dir = Path(storage_dir) if storage_dir else Path.home() / ".testai_learning"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.auto_apply_threshold = auto_apply_threshold

        # Update queue and history
        self._pending_updates: List[KnowledgeUpdate] = []
        self._applied_updates: List[KnowledgeUpdate] = []

        # Statistics
        self._stats = {
            "updates_created": 0,
            "updates_applied": 0,
            "updates_rejected": 0,
            "auto_applied": 0,
        }

        # Load existing data
        self._load_updates()

    def create_update_from_insight(
        self,
        insight_description: str,
        insight_type: str,
        confidence: float,
        evidence: List[str],
        affected_categories: List[str],
        affected_page_types: List[str],
        recommendations: List[str],
    ) -> KnowledgeUpdate:
        """
        Create a knowledge update from a learning insight.

        This is the primary way insights get converted into knowledge updates.
        """
        # Determine section
        section = self._determine_section(affected_page_types, affected_categories)

        # Determine update type
        update_type = self._determine_update_type(insight_type)

        # Format content
        content = self._format_content(
            insight_description,
            recommendations,
            evidence,
        )

        update = KnowledgeUpdate(
            update_id=f"ku_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self._pending_updates)}",
            update_type=update_type,
            section=section,
            category=affected_categories[0] if affected_categories else "general",
            content=content,
            reason=insight_description,
            source="feedback_loop",
            evidence=evidence,
            confidence=confidence,
        )

        self._pending_updates.append(update)
        self._stats["updates_created"] += 1

        # Check for auto-apply
        if confidence >= self.auto_apply_threshold:
            self._auto_apply_update(update)

        self._save_updates()

        return update

    def create_update_from_rule(
        self,
        rule_text: str,
        category: str,
        confidence: float,
        evidence_count: int,
        page_types: Optional[List[str]] = None,
    ) -> KnowledgeUpdate:
        """
        Create a knowledge update from a learned rule.

        This is how pattern learner rules get integrated into the knowledge base.
        """
        section = self._determine_section(
            page_types or [],
            [category],
        )

        update = KnowledgeUpdate(
            update_id=f"ku_rule_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self._pending_updates)}",
            update_type=UpdateType.NEW_RULE,
            section=section,
            category=category,
            content=f"- {rule_text}",
            reason=f"Learned from {evidence_count} test executions",
            source="pattern_learner",
            evidence=[f"{evidence_count} supporting observations"],
            confidence=confidence,
        )

        self._pending_updates.append(update)
        self._stats["updates_created"] += 1

        # Check for auto-apply
        if confidence >= self.auto_apply_threshold:
            self._auto_apply_update(update)

        self._save_updates()

        return update

    def _determine_section(
        self,
        page_types: List[str],
        categories: List[str],
    ) -> str:
        """Determine the knowledge base section for an update."""
        # Get base section from page type
        base_section = "1"  # Default to general
        if page_types:
            first_page = page_types[0].lower()
            base_section = self.SECTION_MAP.get(first_page, "1")

        # Get subsection from category
        subsection = ".0"  # Default
        if categories:
            first_cat = categories[0].lower()
            subsection = self.CATEGORY_SECTIONS.get(first_cat, ".0")

        return f"{base_section}{subsection}"

    def _determine_update_type(self, insight_type: str) -> UpdateType:
        """Determine the update type from an insight type."""
        type_map = {
            "pattern": UpdateType.NEW_RULE,
            "correlation": UpdateType.RULE_REFINEMENT,
            "gap": UpdateType.CATEGORY_EXPANSION,
            "improvement": UpdateType.RULE_REFINEMENT,
            "performance": UpdateType.PRIORITY_CHANGE,
            "error_pattern": UpdateType.NEW_RULE,
        }
        return type_map.get(insight_type, UpdateType.NEW_RULE)

    def _format_content(
        self,
        description: str,
        recommendations: List[str],
        evidence: List[str],
    ) -> str:
        """Format update content in markdown."""
        lines = [
            f"### Learned: {description}",
            "",
            "**Testing Rules:**",
        ]

        for rec in recommendations:
            lines.append(f"- {rec}")

        if evidence:
            lines.extend([
                "",
                "**Evidence:**",
            ])
            for ev in evidence[:3]:  # Limit to 3 evidence items
                lines.append(f"- Based on: {ev}")

        return "\n".join(lines)

    def _auto_apply_update(self, update: KnowledgeUpdate) -> bool:
        """Automatically apply a high-confidence update."""
        update.validated = True
        update.validator = "auto"
        update.applied = True
        update.applied_at = datetime.now()

        self._applied_updates.append(update)
        self._pending_updates.remove(update)

        self._stats["updates_applied"] += 1
        self._stats["auto_applied"] += 1

        return True

    def apply_update(self, update_id: str, validator: str = "user") -> bool:
        """Manually apply a pending update."""
        for update in self._pending_updates:
            if update.update_id == update_id:
                update.validated = True
                update.validator = validator
                update.applied = True
                update.applied_at = datetime.now()

                self._applied_updates.append(update)
                self._pending_updates.remove(update)

                self._stats["updates_applied"] += 1
                self._save_updates()

                return True

        return False

    def reject_update(self, update_id: str, reason: str = "") -> bool:
        """Reject a pending update."""
        for update in self._pending_updates:
            if update.update_id == update_id:
                self._pending_updates.remove(update)
                self._stats["updates_rejected"] += 1
                self._save_updates()
                return True

        return False

    def get_pending_updates(
        self,
        min_confidence: float = 0.0,
        section: Optional[str] = None,
    ) -> List[KnowledgeUpdate]:
        """Get pending updates with optional filtering."""
        updates = self._pending_updates

        if min_confidence > 0:
            updates = [u for u in updates if u.confidence >= min_confidence]

        if section:
            updates = [u for u in updates if u.section.startswith(section)]

        return sorted(updates, key=lambda x: x.confidence, reverse=True)

    def get_applied_updates(
        self,
        since: Optional[datetime] = None,
    ) -> List[KnowledgeUpdate]:
        """Get applied updates with optional date filter."""
        updates = self._applied_updates

        if since:
            updates = [u for u in updates if u.applied_at and u.applied_at >= since]

        return sorted(updates, key=lambda x: x.applied_at or datetime.min, reverse=True)

    def generate_brain_patch(self) -> str:
        """
        Generate a markdown patch for the QA_BRAIN.md file.

        This creates the actual content that would be added to the knowledge base.
        """
        lines = [
            "# Learned Knowledge Patch",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Updates: {len(self._applied_updates)}",
            "",
        ]

        # Group updates by section
        by_section: Dict[str, List[KnowledgeUpdate]] = {}
        for update in self._applied_updates:
            section = update.section or "general"
            if section not in by_section:
                by_section[section] = []
            by_section[section].append(update)

        # Format each section
        for section in sorted(by_section.keys()):
            updates = by_section[section]
            lines.extend([
                f"## Section {section} - Learned Rules",
                "",
            ])

            for update in updates:
                lines.extend([
                    update.content,
                    "",
                    f"> Source: {update.source} | Confidence: {update.confidence:.0%}",
                    "",
                ])

        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge updater statistics."""
        return {
            **self._stats,
            "pending_updates": len(self._pending_updates),
            "applied_updates": len(self._applied_updates),
        }

    def export_updates(self) -> Dict[str, Any]:
        """Export all updates for analysis or sharing."""
        return {
            "pending": [u.to_dict() for u in self._pending_updates],
            "applied": [u.to_dict() for u in self._applied_updates],
            "stats": self._stats,
        }

    def _save_updates(self) -> None:
        """Save updates to disk."""
        updates_file = self.storage_dir / "knowledge_updates.json"
        data = {
            "pending": [u.to_dict() for u in self._pending_updates],
            "applied": [u.to_dict() for u in self._applied_updates],
            "stats": self._stats,
        }
        with open(updates_file, "w") as f:
            json.dump(data, f, indent=2)

    def _load_updates(self) -> None:
        """Load updates from disk."""
        updates_file = self.storage_dir / "knowledge_updates.json"
        if updates_file.exists():
            with open(updates_file, "r") as f:
                data = json.load(f)

            self._pending_updates = [
                KnowledgeUpdate.from_dict(u) for u in data.get("pending", [])
            ]
            self._applied_updates = [
                KnowledgeUpdate.from_dict(u) for u in data.get("applied", [])
            ]
            self._stats = data.get("stats", self._stats)


def create_knowledge_updater(
    storage_dir: Optional[str] = None,
    auto_apply_threshold: float = 0.85,
) -> KnowledgeUpdater:
    """Create a knowledge updater instance."""
    return KnowledgeUpdater(
        storage_dir=storage_dir,
        auto_apply_threshold=auto_apply_threshold,
    )
