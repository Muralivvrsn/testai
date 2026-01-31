"""
TestAI Agent - Review Workflow

Core workflow engine for collaborative test case review
with status tracking and decision management.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid


class ReviewStatus(Enum):
    """Status of a review request."""
    DRAFT = "draft"  # Not yet submitted for review
    PENDING = "pending"  # Awaiting review
    IN_REVIEW = "in_review"  # Currently being reviewed
    CHANGES_REQUESTED = "changes_requested"  # Needs modifications
    APPROVED = "approved"  # All approvals received
    REJECTED = "rejected"  # Review rejected
    MERGED = "merged"  # Tests integrated


class ReviewDecision(Enum):
    """Possible decisions on a review."""
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"
    COMMENT = "comment"  # Comment only, no decision


@dataclass
class Reviewer:
    """A reviewer in the workflow."""
    id: str
    name: str
    email: str
    role: str = "reviewer"  # reviewer, lead, owner
    expertise: List[str] = field(default_factory=list)


@dataclass
class ReviewAction:
    """An action taken on a review."""
    id: str
    reviewer: Reviewer
    decision: ReviewDecision
    comment: str
    timestamp: datetime
    test_ids: List[str] = field(default_factory=list)  # Specific tests reviewed


@dataclass
class ReviewRequest:
    """A request for test case review."""
    id: str
    title: str
    description: str
    test_ids: List[str]
    author: Reviewer
    reviewers: List[Reviewer]
    status: ReviewStatus
    created_at: datetime
    updated_at: datetime
    actions: List[ReviewAction] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReviewResponse:
    """Response from a review operation."""
    success: bool
    request_id: str
    status: ReviewStatus
    message: str
    pending_reviewers: List[str] = field(default_factory=list)


class ReviewWorkflow:
    """
    Manages collaborative test case review workflow.

    Supports:
    - Creating and submitting review requests
    - Tracking reviewer decisions
    - Managing approval requirements
    - Status transitions and notifications
    """

    # Valid status transitions
    VALID_TRANSITIONS = {
        ReviewStatus.DRAFT: {ReviewStatus.PENDING},
        ReviewStatus.PENDING: {ReviewStatus.IN_REVIEW, ReviewStatus.REJECTED},
        ReviewStatus.IN_REVIEW: {
            ReviewStatus.CHANGES_REQUESTED,
            ReviewStatus.APPROVED,
            ReviewStatus.REJECTED,
        },
        ReviewStatus.CHANGES_REQUESTED: {ReviewStatus.PENDING, ReviewStatus.REJECTED},
        ReviewStatus.APPROVED: {ReviewStatus.MERGED},
        ReviewStatus.REJECTED: set(),  # Terminal state
        ReviewStatus.MERGED: set(),  # Terminal state
    }

    def __init__(
        self,
        require_all_approvals: bool = True,
        min_approvals: int = 1,
        auto_merge: bool = False,
    ):
        """Initialize the workflow."""
        self.require_all_approvals = require_all_approvals
        self.min_approvals = min_approvals
        self.auto_merge = auto_merge
        self._requests: Dict[str, ReviewRequest] = {}
        self._listeners: List[callable] = []

    def create_request(
        self,
        title: str,
        description: str,
        test_ids: List[str],
        author: Reviewer,
        reviewers: List[Reviewer],
        labels: Optional[List[str]] = None,
    ) -> ReviewRequest:
        """Create a new review request."""
        request_id = f"REV-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now()

        request = ReviewRequest(
            id=request_id,
            title=title,
            description=description,
            test_ids=test_ids,
            author=author,
            reviewers=reviewers,
            status=ReviewStatus.DRAFT,
            created_at=now,
            updated_at=now,
            labels=labels or [],
        )

        self._requests[request_id] = request
        self._notify("request_created", request)
        return request

    def submit_for_review(self, request_id: str) -> ReviewResponse:
        """Submit a draft request for review."""
        request = self._requests.get(request_id)
        if not request:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=ReviewStatus.DRAFT,
                message=f"Request {request_id} not found",
            )

        if request.status != ReviewStatus.DRAFT:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Cannot submit from status {request.status.value}",
            )

        if not request.reviewers:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message="At least one reviewer is required",
            )

        request.status = ReviewStatus.PENDING
        request.updated_at = datetime.now()

        self._notify("review_submitted", request)

        return ReviewResponse(
            success=True,
            request_id=request_id,
            status=request.status,
            message="Review submitted successfully",
            pending_reviewers=[r.name for r in request.reviewers],
        )

    def start_review(
        self,
        request_id: str,
        reviewer: Reviewer,
    ) -> ReviewResponse:
        """Mark a review as being actively reviewed."""
        request = self._requests.get(request_id)
        if not request:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=ReviewStatus.DRAFT,
                message=f"Request {request_id} not found",
            )

        if request.status not in {ReviewStatus.PENDING, ReviewStatus.IN_REVIEW}:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Cannot start review from status {request.status.value}",
            )

        # Check if reviewer is assigned
        if not any(r.id == reviewer.id for r in request.reviewers):
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Reviewer {reviewer.name} is not assigned to this request",
            )

        request.status = ReviewStatus.IN_REVIEW
        request.updated_at = datetime.now()

        self._notify("review_started", request, reviewer)

        return ReviewResponse(
            success=True,
            request_id=request_id,
            status=request.status,
            message=f"Review started by {reviewer.name}",
        )

    def submit_decision(
        self,
        request_id: str,
        reviewer: Reviewer,
        decision: ReviewDecision,
        comment: str,
        test_ids: Optional[List[str]] = None,
    ) -> ReviewResponse:
        """Submit a review decision."""
        request = self._requests.get(request_id)
        if not request:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=ReviewStatus.DRAFT,
                message=f"Request {request_id} not found",
            )

        if request.status != ReviewStatus.IN_REVIEW:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Cannot submit decision from status {request.status.value}",
            )

        # Check if reviewer is assigned
        if not any(r.id == reviewer.id for r in request.reviewers):
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Reviewer {reviewer.name} is not assigned to this request",
            )

        # Record the action
        action = ReviewAction(
            id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            reviewer=reviewer,
            decision=decision,
            comment=comment,
            timestamp=datetime.now(),
            test_ids=test_ids or request.test_ids,
        )
        request.actions.append(action)
        request.updated_at = datetime.now()

        # Update status based on decision
        new_status = self._calculate_new_status(request, decision)
        request.status = new_status

        # Auto-merge if enabled and approved
        if self.auto_merge and new_status == ReviewStatus.APPROVED:
            request.status = ReviewStatus.MERGED
            self._notify("review_merged", request)

        self._notify("decision_submitted", request, action)

        pending = self._get_pending_reviewers(request)

        return ReviewResponse(
            success=True,
            request_id=request_id,
            status=request.status,
            message=f"Decision recorded: {decision.value}",
            pending_reviewers=pending,
        )

    def resubmit(self, request_id: str) -> ReviewResponse:
        """Resubmit after making requested changes."""
        request = self._requests.get(request_id)
        if not request:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=ReviewStatus.DRAFT,
                message=f"Request {request_id} not found",
            )

        if request.status != ReviewStatus.CHANGES_REQUESTED:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Cannot resubmit from status {request.status.value}",
            )

        request.status = ReviewStatus.PENDING
        request.updated_at = datetime.now()

        self._notify("review_resubmitted", request)

        return ReviewResponse(
            success=True,
            request_id=request_id,
            status=request.status,
            message="Review resubmitted for approval",
            pending_reviewers=[r.name for r in request.reviewers],
        )

    def merge(self, request_id: str) -> ReviewResponse:
        """Merge an approved review."""
        request = self._requests.get(request_id)
        if not request:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=ReviewStatus.DRAFT,
                message=f"Request {request_id} not found",
            )

        if request.status != ReviewStatus.APPROVED:
            return ReviewResponse(
                success=False,
                request_id=request_id,
                status=request.status,
                message=f"Cannot merge from status {request.status.value}",
            )

        request.status = ReviewStatus.MERGED
        request.updated_at = datetime.now()

        self._notify("review_merged", request)

        return ReviewResponse(
            success=True,
            request_id=request_id,
            status=request.status,
            message="Tests merged successfully",
        )

    def get_request(self, request_id: str) -> Optional[ReviewRequest]:
        """Get a review request by ID."""
        return self._requests.get(request_id)

    def get_requests_by_status(
        self,
        status: ReviewStatus,
    ) -> List[ReviewRequest]:
        """Get all requests with a specific status."""
        return [r for r in self._requests.values() if r.status == status]

    def get_requests_for_reviewer(
        self,
        reviewer_id: str,
    ) -> List[ReviewRequest]:
        """Get all requests assigned to a reviewer."""
        return [
            r for r in self._requests.values()
            if any(rv.id == reviewer_id for rv in r.reviewers)
        ]

    def get_pending_for_reviewer(
        self,
        reviewer_id: str,
    ) -> List[ReviewRequest]:
        """Get pending requests for a specific reviewer."""
        requests = self.get_requests_for_reviewer(reviewer_id)
        return [
            r for r in requests
            if r.status in {ReviewStatus.PENDING, ReviewStatus.IN_REVIEW}
            and not self._has_reviewed(r, reviewer_id)
        ]

    def add_listener(self, callback: callable):
        """Add a listener for workflow events."""
        self._listeners.append(callback)

    def _notify(self, event: str, *args):
        """Notify listeners of an event."""
        for listener in self._listeners:
            try:
                listener(event, *args)
            except Exception:
                pass

    def _calculate_new_status(
        self,
        request: ReviewRequest,
        latest_decision: ReviewDecision,
    ) -> ReviewStatus:
        """Calculate the new status based on decisions."""
        if latest_decision == ReviewDecision.REJECT:
            return ReviewStatus.REJECTED

        if latest_decision == ReviewDecision.REQUEST_CHANGES:
            return ReviewStatus.CHANGES_REQUESTED

        if latest_decision == ReviewDecision.COMMENT:
            return ReviewStatus.IN_REVIEW

        # Check if we have enough approvals
        approvals = [
            a for a in request.actions
            if a.decision == ReviewDecision.APPROVE
        ]

        unique_approvers = {a.reviewer.id for a in approvals}

        if self.require_all_approvals:
            reviewer_ids = {r.id for r in request.reviewers}
            if unique_approvers >= reviewer_ids:
                return ReviewStatus.APPROVED
        elif len(unique_approvers) >= self.min_approvals:
            return ReviewStatus.APPROVED

        return ReviewStatus.IN_REVIEW

    def _get_pending_reviewers(
        self,
        request: ReviewRequest,
    ) -> List[str]:
        """Get reviewers who haven't submitted a decision."""
        approved = {
            a.reviewer.id for a in request.actions
            if a.decision == ReviewDecision.APPROVE
        }
        return [r.name for r in request.reviewers if r.id not in approved]

    def _has_reviewed(
        self,
        request: ReviewRequest,
        reviewer_id: str,
    ) -> bool:
        """Check if a reviewer has submitted a decision."""
        return any(
            a.reviewer.id == reviewer_id
            and a.decision in {ReviewDecision.APPROVE, ReviewDecision.REJECT, ReviewDecision.REQUEST_CHANGES}
            for a in request.actions
        )

    def format_request(self, request: ReviewRequest) -> str:
        """Format a request as readable text."""
        lines = [
            "=" * 60,
            f"  REVIEW REQUEST: {request.id}",
            "=" * 60,
            "",
            f"  Title: {request.title}",
            f"  Status: {request.status.value.upper()}",
            f"  Author: {request.author.name}",
            f"  Created: {request.created_at.strftime('%Y-%m-%d %H:%M')}",
            f"  Tests: {len(request.test_ids)}",
            "",
            f"  Description:",
            f"    {request.description}",
            "",
            "-" * 60,
            "  REVIEWERS",
            "-" * 60,
        ]

        for reviewer in request.reviewers:
            has_reviewed = self._has_reviewed(request, reviewer.id)
            status = "✓" if has_reviewed else "○"
            lines.append(f"  {status} {reviewer.name} ({reviewer.role})")

        if request.actions:
            lines.extend([
                "",
                "-" * 60,
                "  ACTIVITY",
                "-" * 60,
            ])

            for action in request.actions[-5:]:  # Last 5 actions
                time_str = action.timestamp.strftime("%m/%d %H:%M")
                decision_icon = {
                    ReviewDecision.APPROVE: "✅",
                    ReviewDecision.REQUEST_CHANGES: "📝",
                    ReviewDecision.REJECT: "❌",
                    ReviewDecision.COMMENT: "💬",
                }.get(action.decision, "•")

                lines.append(
                    f"  {time_str} {decision_icon} {action.reviewer.name}: "
                    f"{action.decision.value}"
                )
                if action.comment:
                    comment_preview = action.comment[:50]
                    if len(action.comment) > 50:
                        comment_preview += "..."
                    lines.append(f"           \"{comment_preview}\"")

        if request.labels:
            lines.extend([
                "",
                f"  Labels: {', '.join(request.labels)}",
            ])

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_review_workflow(
    require_all_approvals: bool = True,
    min_approvals: int = 1,
    auto_merge: bool = False,
) -> ReviewWorkflow:
    """Create a review workflow instance."""
    return ReviewWorkflow(require_all_approvals, min_approvals, auto_merge)
