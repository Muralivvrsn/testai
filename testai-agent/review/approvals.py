"""
TestAI Agent - Approval Chain System

Multi-stage approval chains with role-based authorization
and configurable approval requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid


class ApprovalStatus(Enum):
    """Status of an approval."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SKIPPED = "skipped"  # Auto-approved or bypassed


@dataclass
class Approver:
    """An approver in the chain."""
    id: str
    name: str
    email: str
    role: str  # e.g., "qa_lead", "security", "product_owner"
    can_override: bool = False  # Can approve on behalf of others
    expertise: List[str] = field(default_factory=list)


@dataclass
class ApprovalRecord:
    """Record of an approval decision."""
    id: str
    approver: Approver
    status: ApprovalStatus
    comment: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalStage:
    """A stage in the approval chain."""
    id: str
    name: str
    description: str
    required_roles: Set[str]  # Roles required to approve
    min_approvals: int
    approvers: List[Approver]
    approvals: List[ApprovalRecord] = field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    is_optional: bool = False
    can_be_bypassed_by: Set[str] = field(default_factory=set)  # Roles that can bypass


@dataclass
class ApprovalChain:
    """A complete approval chain."""
    id: str
    name: str
    description: str
    stages: List[ApprovalStage]
    created_at: datetime
    completed_at: Optional[datetime] = None
    is_complete: bool = False
    is_approved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainResult:
    """Result of a chain operation."""
    success: bool
    chain_id: str
    message: str
    current_stage: Optional[str] = None
    pending_approvers: List[str] = field(default_factory=list)


class ApprovalChainManager:
    """
    Manages multi-stage approval chains.

    Supports:
    - Sequential approval stages
    - Role-based approval requirements
    - Override capabilities for leads
    - Optional stages with bypass
    - Audit trail of all decisions
    """

    # Default stage templates
    STAGE_TEMPLATES = {
        "technical_review": {
            "name": "Technical Review",
            "description": "Code quality and implementation review",
            "required_roles": {"developer", "tech_lead"},
            "min_approvals": 1,
        },
        "qa_review": {
            "name": "QA Review",
            "description": "Test coverage and quality assurance review",
            "required_roles": {"qa", "qa_lead"},
            "min_approvals": 1,
        },
        "security_review": {
            "name": "Security Review",
            "description": "Security assessment and vulnerability check",
            "required_roles": {"security", "security_lead"},
            "min_approvals": 1,
        },
        "product_review": {
            "name": "Product Review",
            "description": "Business requirements and feature validation",
            "required_roles": {"product_owner", "product_manager"},
            "min_approvals": 1,
        },
        "final_approval": {
            "name": "Final Approval",
            "description": "Final sign-off before merge",
            "required_roles": {"lead", "manager"},
            "min_approvals": 1,
        },
    }

    def __init__(self):
        """Initialize the approval chain manager."""
        self._chains: Dict[str, ApprovalChain] = {}
        self._listeners: List[callable] = []

    def create_chain(
        self,
        name: str,
        description: str,
        stage_configs: List[Dict[str, Any]],
    ) -> ApprovalChain:
        """Create a new approval chain."""
        chain_id = f"CHN-{uuid.uuid4().hex[:8].upper()}"

        stages = []
        for i, config in enumerate(stage_configs):
            stage = self._create_stage(config, i)
            stages.append(stage)

        chain = ApprovalChain(
            id=chain_id,
            name=name,
            description=description,
            stages=stages,
            created_at=datetime.now(),
        )

        self._chains[chain_id] = chain
        self._notify("chain_created", chain)

        return chain

    def create_chain_from_templates(
        self,
        name: str,
        description: str,
        template_names: List[str],
    ) -> ApprovalChain:
        """Create a chain from predefined templates."""
        stage_configs = []

        for template_name in template_names:
            template = self.STAGE_TEMPLATES.get(template_name)
            if template:
                stage_configs.append(template.copy())

        return self.create_chain(name, description, stage_configs)

    def add_approver_to_stage(
        self,
        chain_id: str,
        stage_id: str,
        approver: Approver,
    ) -> bool:
        """Add an approver to a stage."""
        chain = self._chains.get(chain_id)
        if not chain:
            return False

        for stage in chain.stages:
            if stage.id == stage_id:
                # Check if approver has required role
                if approver.role not in stage.required_roles:
                    return False

                # Check if already added
                if any(a.id == approver.id for a in stage.approvers):
                    return False

                stage.approvers.append(approver)
                return True

        return False

    def submit_approval(
        self,
        chain_id: str,
        stage_id: str,
        approver: Approver,
        status: ApprovalStatus,
        comment: str = "",
    ) -> ChainResult:
        """Submit an approval decision."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Chain {chain_id} not found",
            )

        # Find the stage
        stage = None
        stage_index = -1
        for i, s in enumerate(chain.stages):
            if s.id == stage_id:
                stage = s
                stage_index = i
                break

        if not stage:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Stage {stage_id} not found",
            )

        # Check if this stage is active (previous stages must be complete)
        for i, s in enumerate(chain.stages):
            if i < stage_index and s.status == ApprovalStatus.PENDING:
                return ChainResult(
                    success=False,
                    chain_id=chain_id,
                    message=f"Previous stage '{s.name}' must be completed first",
                    current_stage=s.id,
                )

        # Check if stage is already complete
        if stage.status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Stage '{stage.name}' is already {stage.status.value}",
            )

        # Check if approver is authorized
        is_authorized = (
            approver.role in stage.required_roles
            or approver.can_override
        )

        if not is_authorized:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Approver {approver.name} is not authorized for this stage",
            )

        # Check if already approved by this person
        if any(a.approver.id == approver.id for a in stage.approvals):
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Approver {approver.name} has already submitted a decision",
            )

        # Record the approval
        record = ApprovalRecord(
            id=f"APR-{uuid.uuid4().hex[:8].upper()}",
            approver=approver,
            status=status,
            comment=comment,
            timestamp=datetime.now(),
        )
        stage.approvals.append(record)

        # Update stage status
        self._update_stage_status(stage)

        # Update chain status if this stage is now complete
        if stage.status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}:
            self._update_chain_status(chain)

        self._notify("approval_submitted", chain, stage, record)

        return ChainResult(
            success=True,
            chain_id=chain_id,
            message=f"Approval recorded: {status.value}",
            current_stage=stage.id if stage.status == ApprovalStatus.PENDING else None,
            pending_approvers=self._get_pending_approvers(stage),
        )

    def bypass_stage(
        self,
        chain_id: str,
        stage_id: str,
        bypasser: Approver,
        reason: str,
    ) -> ChainResult:
        """Bypass an optional stage."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Chain {chain_id} not found",
            )

        stage = None
        for s in chain.stages:
            if s.id == stage_id:
                stage = s
                break

        if not stage:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Stage {stage_id} not found",
            )

        # Check if stage can be bypassed
        can_bypass = (
            stage.is_optional
            or bypasser.role in stage.can_be_bypassed_by
            or bypasser.can_override
        )

        if not can_bypass:
            return ChainResult(
                success=False,
                chain_id=chain_id,
                message=f"Stage '{stage.name}' cannot be bypassed",
            )

        # Record bypass as a skip
        record = ApprovalRecord(
            id=f"APR-{uuid.uuid4().hex[:8].upper()}",
            approver=bypasser,
            status=ApprovalStatus.SKIPPED,
            comment=f"Bypassed: {reason}",
            timestamp=datetime.now(),
            metadata={"bypass_reason": reason},
        )
        stage.approvals.append(record)
        stage.status = ApprovalStatus.SKIPPED

        self._update_chain_status(chain)
        self._notify("stage_bypassed", chain, stage, bypasser)

        return ChainResult(
            success=True,
            chain_id=chain_id,
            message=f"Stage '{stage.name}' bypassed",
        )

    def get_chain(self, chain_id: str) -> Optional[ApprovalChain]:
        """Get a chain by ID."""
        return self._chains.get(chain_id)

    def get_current_stage(self, chain_id: str) -> Optional[ApprovalStage]:
        """Get the current active stage in a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        for stage in chain.stages:
            if stage.status == ApprovalStatus.PENDING:
                return stage

        return None

    def get_chain_progress(self, chain_id: str) -> Dict[str, Any]:
        """Get progress summary of a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return {}

        total_stages = len(chain.stages)
        completed = sum(
            1 for s in chain.stages
            if s.status in {ApprovalStatus.APPROVED, ApprovalStatus.SKIPPED}
        )
        rejected = sum(
            1 for s in chain.stages
            if s.status == ApprovalStatus.REJECTED
        )

        return {
            "chain_id": chain_id,
            "name": chain.name,
            "total_stages": total_stages,
            "completed_stages": completed,
            "rejected_stages": rejected,
            "pending_stages": total_stages - completed - rejected,
            "progress_pct": completed / total_stages if total_stages > 0 else 0,
            "is_complete": chain.is_complete,
            "is_approved": chain.is_approved,
        }

    def add_listener(self, callback: callable):
        """Add a listener for chain events."""
        self._listeners.append(callback)

    def _create_stage(
        self,
        config: Dict[str, Any],
        index: int,
    ) -> ApprovalStage:
        """Create a stage from configuration."""
        return ApprovalStage(
            id=f"STG-{uuid.uuid4().hex[:8].upper()}",
            name=config.get("name", f"Stage {index + 1}"),
            description=config.get("description", ""),
            required_roles=set(config.get("required_roles", [])),
            min_approvals=config.get("min_approvals", 1),
            approvers=config.get("approvers", []),
            is_optional=config.get("is_optional", False),
            can_be_bypassed_by=set(config.get("can_be_bypassed_by", [])),
        )

    def _update_stage_status(self, stage: ApprovalStage):
        """Update stage status based on approvals."""
        # Check for any rejections
        if any(a.status == ApprovalStatus.REJECTED for a in stage.approvals):
            stage.status = ApprovalStatus.REJECTED
            return

        # Count approvals
        approval_count = sum(
            1 for a in stage.approvals
            if a.status == ApprovalStatus.APPROVED
        )

        if approval_count >= stage.min_approvals:
            stage.status = ApprovalStatus.APPROVED

    def _update_chain_status(self, chain: ApprovalChain):
        """Update chain status based on stage statuses."""
        # Check if any stage is rejected
        if any(s.status == ApprovalStatus.REJECTED for s in chain.stages):
            chain.is_complete = True
            chain.is_approved = False
            chain.completed_at = datetime.now()
            self._notify("chain_rejected", chain)
            return

        # Check if all stages are complete
        all_complete = all(
            s.status in {ApprovalStatus.APPROVED, ApprovalStatus.SKIPPED}
            for s in chain.stages
        )

        if all_complete:
            chain.is_complete = True
            chain.is_approved = True
            chain.completed_at = datetime.now()
            self._notify("chain_approved", chain)

    def _get_pending_approvers(self, stage: ApprovalStage) -> List[str]:
        """Get list of pending approvers for a stage."""
        approved_ids = {a.approver.id for a in stage.approvals}
        return [a.name for a in stage.approvers if a.id not in approved_ids]

    def _notify(self, event: str, *args):
        """Notify listeners of an event."""
        for listener in self._listeners:
            try:
                listener(event, *args)
            except Exception:
                pass

    def format_chain(self, chain: ApprovalChain) -> str:
        """Format a chain as readable text."""
        status_icon = "✅" if chain.is_approved else "❌" if chain.is_complete else "○"

        lines = [
            "=" * 60,
            f"  {status_icon} APPROVAL CHAIN: {chain.id}",
            "=" * 60,
            "",
            f"  Name: {chain.name}",
            f"  Description: {chain.description}",
            f"  Created: {chain.created_at.strftime('%Y-%m-%d %H:%M')}",
            "",
        ]

        if chain.completed_at:
            lines.append(f"  Completed: {chain.completed_at.strftime('%Y-%m-%d %H:%M')}")
            lines.append(f"  Result: {'APPROVED' if chain.is_approved else 'REJECTED'}")
            lines.append("")

        lines.extend([
            "-" * 60,
            "  STAGES",
            "-" * 60,
        ])

        for i, stage in enumerate(chain.stages):
            stage_icon = {
                ApprovalStatus.PENDING: "○",
                ApprovalStatus.APPROVED: "✅",
                ApprovalStatus.REJECTED: "❌",
                ApprovalStatus.SKIPPED: "⏭",
            }.get(stage.status, "?")

            lines.append(f"\n  {i + 1}. {stage_icon} {stage.name}")
            lines.append(f"     {stage.description}")
            lines.append(f"     Required: {', '.join(stage.required_roles)}")
            lines.append(f"     Min Approvals: {stage.min_approvals}")

            if stage.approvals:
                lines.append("     Decisions:")
                for record in stage.approvals:
                    decision_icon = {
                        ApprovalStatus.APPROVED: "✓",
                        ApprovalStatus.REJECTED: "✗",
                        ApprovalStatus.SKIPPED: "⏭",
                    }.get(record.status, "?")
                    time_str = record.timestamp.strftime("%m/%d %H:%M")
                    lines.append(
                        f"       {decision_icon} {record.approver.name} "
                        f"({record.status.value}) - {time_str}"
                    )
                    if record.comment:
                        lines.append(f"         \"{record.comment}\"")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_approval_chain(
    name: str,
    description: str,
    stage_configs: Optional[List[Dict[str, Any]]] = None,
    template_names: Optional[List[str]] = None,
    manager: Optional[ApprovalChainManager] = None,
) -> ApprovalChain:
    """Create an approval chain (convenience function)."""
    if manager is None:
        manager = ApprovalChainManager()

    if template_names:
        return manager.create_chain_from_templates(name, description, template_names)
    elif stage_configs:
        return manager.create_chain(name, description, stage_configs)
    else:
        # Default chain with basic stages
        return manager.create_chain_from_templates(
            name,
            description,
            ["technical_review", "qa_review", "final_approval"],
        )
