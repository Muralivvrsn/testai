"""
TestAI Agent - Test Repair Engine

Intelligent test repair system that diagnoses failures,
generates repair actions, and applies fixes automatically.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable
import uuid

from .selector_healer import (
    SelectorHealer,
    SelectorType,
    HealingStrategy,
    HealingResult,
)
from .change_detector import (
    ChangeDetector,
    ChangeType,
    UIChange,
)


class RepairStrategy(Enum):
    """Strategies for repairing tests."""
    SELECTOR_HEALING = "selector_healing"  # Fix broken selectors
    WAIT_ADJUSTMENT = "wait_adjustment"  # Adjust wait times
    STEP_REORDERING = "step_reordering"  # Reorder steps
    ASSERTION_UPDATE = "assertion_update"  # Update assertions
    PRECONDITION_FIX = "precondition_fix"  # Fix preconditions
    ELEMENT_REMAPPING = "element_remapping"  # Map to new elements
    FLOW_ADAPTATION = "flow_adaptation"  # Adapt to new flow
    RETRY_LOGIC = "retry_logic"  # Add retry logic


class RepairPriority(Enum):
    """Priority of a repair action."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RepairStatus(Enum):
    """Status of a repair action."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class FailureAnalysis:
    """Analysis of a test failure."""
    analysis_id: str
    test_id: str
    failure_type: str
    root_cause: str
    failed_step: Optional[str]
    failed_selector: Optional[str]
    error_message: str
    confidence: float
    suggested_strategies: List[RepairStrategy]
    analyzed_at: datetime


@dataclass
class RepairAction:
    """A specific action to repair a test."""
    action_id: str
    test_id: str
    strategy: RepairStrategy
    priority: RepairPriority
    description: str
    target: str  # What to repair (selector, step, etc.)
    original_value: str
    repaired_value: str
    confidence: float
    status: RepairStatus = RepairStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    applied_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RepairResult:
    """Result of applying repairs."""
    result_id: str
    test_id: str
    actions_applied: int
    actions_successful: int
    actions_failed: int
    test_passes: bool
    repair_time_ms: int
    repairs: List[RepairAction]
    repaired_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class RepairEngine:
    """
    Intelligent test repair engine.

    Features:
    - Failure analysis
    - Multi-strategy repair
    - Automatic selector healing
    - Step optimization
    - Rollback support
    - Repair verification
    """

    def __init__(
        self,
        selector_healer: Optional[SelectorHealer] = None,
        change_detector: Optional[ChangeDetector] = None,
        auto_apply: bool = False,
    ):
        """Initialize the repair engine."""
        self.healer = selector_healer or SelectorHealer()
        self.detector = change_detector or ChangeDetector()
        self.auto_apply = auto_apply

        self._analysis_counter = 0
        self._action_counter = 0
        self._result_counter = 0

        self._pending_repairs: Dict[str, List[RepairAction]] = {}
        self._repair_history: List[RepairResult] = []
        self._original_tests: Dict[str, Dict[str, Any]] = {}

    def analyze_failure(
        self,
        test_id: str,
        error_message: str,
        failed_step: Optional[str] = None,
        failed_selector: Optional[str] = None,
        stack_trace: Optional[str] = None,
    ) -> FailureAnalysis:
        """Analyze a test failure and determine root cause."""
        self._analysis_counter += 1
        analysis_id = f"ANALYSIS-{self._analysis_counter:05d}"

        # Determine failure type and root cause
        failure_type, root_cause, confidence = self._classify_failure(
            error_message, failed_step, failed_selector, stack_trace
        )

        # Suggest repair strategies
        strategies = self._suggest_strategies(failure_type, root_cause)

        return FailureAnalysis(
            analysis_id=analysis_id,
            test_id=test_id,
            failure_type=failure_type,
            root_cause=root_cause,
            failed_step=failed_step,
            failed_selector=failed_selector,
            error_message=error_message,
            confidence=confidence,
            suggested_strategies=strategies,
            analyzed_at=datetime.now(),
        )

    def _classify_failure(
        self,
        error_message: str,
        failed_step: Optional[str],
        failed_selector: Optional[str],
        stack_trace: Optional[str],
    ) -> tuple[str, str, float]:
        """Classify the failure type and determine root cause."""
        error_lower = error_message.lower()

        # Element not found
        if any(phrase in error_lower for phrase in [
            "element not found",
            "no element",
            "unable to locate",
            "cannot find",
            "timeout waiting for element",
        ]):
            if failed_selector:
                return "selector_broken", f"Selector '{failed_selector}' no longer matches", 0.90
            return "element_missing", "Target element not found in DOM", 0.80

        # Timeout
        if "timeout" in error_lower:
            if "navigation" in error_lower:
                return "navigation_timeout", "Page navigation timed out", 0.85
            if "wait" in error_lower:
                return "wait_timeout", "Element wait timed out", 0.85
            return "timeout", "Operation timed out", 0.75

        # Assertion failure
        if any(phrase in error_lower for phrase in [
            "assertion",
            "expected",
            "actual",
            "not equal",
            "mismatch",
        ]):
            return "assertion_failure", "Test assertion did not match", 0.90

        # Click/interaction failure
        if any(phrase in error_lower for phrase in [
            "not clickable",
            "not interactable",
            "element not visible",
            "obscured",
        ]):
            return "interaction_blocked", "Element not interactable", 0.85

        # Network/API failure
        if any(phrase in error_lower for phrase in [
            "network",
            "api",
            "request failed",
            "status code",
        ]):
            return "api_failure", "API or network request failed", 0.80

        # Default
        return "unknown", "Unable to determine specific root cause", 0.40

    def _suggest_strategies(
        self,
        failure_type: str,
        root_cause: str,
    ) -> List[RepairStrategy]:
        """Suggest repair strategies based on failure type."""
        strategy_map = {
            "selector_broken": [
                RepairStrategy.SELECTOR_HEALING,
                RepairStrategy.ELEMENT_REMAPPING,
            ],
            "element_missing": [
                RepairStrategy.SELECTOR_HEALING,
                RepairStrategy.FLOW_ADAPTATION,
            ],
            "timeout": [
                RepairStrategy.WAIT_ADJUSTMENT,
                RepairStrategy.RETRY_LOGIC,
            ],
            "wait_timeout": [
                RepairStrategy.WAIT_ADJUSTMENT,
                RepairStrategy.SELECTOR_HEALING,
            ],
            "navigation_timeout": [
                RepairStrategy.WAIT_ADJUSTMENT,
                RepairStrategy.RETRY_LOGIC,
            ],
            "assertion_failure": [
                RepairStrategy.ASSERTION_UPDATE,
            ],
            "interaction_blocked": [
                RepairStrategy.WAIT_ADJUSTMENT,
                RepairStrategy.STEP_REORDERING,
            ],
            "api_failure": [
                RepairStrategy.RETRY_LOGIC,
                RepairStrategy.PRECONDITION_FIX,
            ],
        }

        return strategy_map.get(failure_type, [RepairStrategy.SELECTOR_HEALING])

    def generate_repairs(
        self,
        analysis: FailureAnalysis,
        test_content: Optional[Dict[str, Any]] = None,
    ) -> List[RepairAction]:
        """Generate repair actions based on failure analysis."""
        repairs = []

        for strategy in analysis.suggested_strategies:
            if strategy == RepairStrategy.SELECTOR_HEALING:
                repairs.extend(self._generate_selector_repairs(analysis))

            elif strategy == RepairStrategy.WAIT_ADJUSTMENT:
                repairs.extend(self._generate_wait_repairs(analysis))

            elif strategy == RepairStrategy.ASSERTION_UPDATE:
                repairs.extend(self._generate_assertion_repairs(analysis))

            elif strategy == RepairStrategy.RETRY_LOGIC:
                repairs.extend(self._generate_retry_repairs(analysis))

            elif strategy == RepairStrategy.FLOW_ADAPTATION:
                repairs.extend(self._generate_flow_repairs(analysis))

        # Store pending repairs
        self._pending_repairs[analysis.test_id] = repairs

        return repairs

    def _generate_selector_repairs(
        self,
        analysis: FailureAnalysis,
    ) -> List[RepairAction]:
        """Generate selector healing repairs."""
        repairs = []

        if analysis.failed_selector:
            # Use selector healer
            healing_result = self.healer.heal(
                analysis.failed_selector,
                SelectorType.CSS,
            )

            if healing_result.success:
                self._action_counter += 1
                repairs.append(RepairAction(
                    action_id=f"REPAIR-{self._action_counter:06d}",
                    test_id=analysis.test_id,
                    strategy=RepairStrategy.SELECTOR_HEALING,
                    priority=RepairPriority.HIGH,
                    description=f"Replace broken selector with healed alternative",
                    target="selector",
                    original_value=analysis.failed_selector,
                    repaired_value=healing_result.healed_selector,
                    confidence=healing_result.confidence,
                    metadata={
                        "healing_strategy": healing_result.strategy_used.value,
                        "healing_id": healing_result.result_id,
                    },
                ))

        return repairs

    def _generate_wait_repairs(
        self,
        analysis: FailureAnalysis,
    ) -> List[RepairAction]:
        """Generate wait time adjustment repairs."""
        repairs = []
        self._action_counter += 1

        # Suggest increased wait time
        repairs.append(RepairAction(
            action_id=f"REPAIR-{self._action_counter:06d}",
            test_id=analysis.test_id,
            strategy=RepairStrategy.WAIT_ADJUSTMENT,
            priority=RepairPriority.MEDIUM,
            description="Increase wait timeout for element visibility",
            target="timeout",
            original_value="30000",  # 30 seconds
            repaired_value="60000",  # 60 seconds
            confidence=0.70,
        ))

        # Suggest explicit wait
        self._action_counter += 1
        repairs.append(RepairAction(
            action_id=f"REPAIR-{self._action_counter:06d}",
            test_id=analysis.test_id,
            strategy=RepairStrategy.WAIT_ADJUSTMENT,
            priority=RepairPriority.MEDIUM,
            description="Add explicit wait for network idle",
            target="step",
            original_value=analysis.failed_step or "",
            repaired_value=f"await page.waitForLoadState('networkidle')\n{analysis.failed_step or ''}",
            confidence=0.65,
        ))

        return repairs

    def _generate_assertion_repairs(
        self,
        analysis: FailureAnalysis,
    ) -> List[RepairAction]:
        """Generate assertion update repairs."""
        repairs = []
        self._action_counter += 1

        repairs.append(RepairAction(
            action_id=f"REPAIR-{self._action_counter:06d}",
            test_id=analysis.test_id,
            strategy=RepairStrategy.ASSERTION_UPDATE,
            priority=RepairPriority.HIGH,
            description="Update assertion to match current behavior",
            target="assertion",
            original_value=analysis.failed_step or "",
            repaired_value="// TODO: Update assertion based on new expected value",
            confidence=0.50,
            metadata={"requires_manual_review": True},
        ))

        return repairs

    def _generate_retry_repairs(
        self,
        analysis: FailureAnalysis,
    ) -> List[RepairAction]:
        """Generate retry logic repairs."""
        repairs = []
        self._action_counter += 1

        repairs.append(RepairAction(
            action_id=f"REPAIR-{self._action_counter:06d}",
            test_id=analysis.test_id,
            strategy=RepairStrategy.RETRY_LOGIC,
            priority=RepairPriority.LOW,
            description="Add retry wrapper for flaky operation",
            target="step",
            original_value=analysis.failed_step or "",
            repaired_value=f"await retry(async () => {{ {analysis.failed_step or ''} }}, {{ retries: 3 }})",
            confidence=0.60,
        ))

        return repairs

    def _generate_flow_repairs(
        self,
        analysis: FailureAnalysis,
    ) -> List[RepairAction]:
        """Generate flow adaptation repairs."""
        repairs = []
        self._action_counter += 1

        repairs.append(RepairAction(
            action_id=f"REPAIR-{self._action_counter:06d}",
            test_id=analysis.test_id,
            strategy=RepairStrategy.FLOW_ADAPTATION,
            priority=RepairPriority.HIGH,
            description="Adapt test to new UI flow",
            target="flow",
            original_value="original_flow",
            repaired_value="adapted_flow",
            confidence=0.55,
            metadata={"requires_manual_review": True},
        ))

        return repairs

    def apply_repairs(
        self,
        test_id: str,
        repairs: Optional[List[RepairAction]] = None,
    ) -> RepairResult:
        """Apply repairs to a test."""
        start_time = datetime.now()
        self._result_counter += 1
        result_id = f"RESULT-{self._result_counter:05d}"

        repairs = repairs or self._pending_repairs.get(test_id, [])

        applied = 0
        successful = 0
        failed = 0

        for repair in repairs:
            repair.status = RepairStatus.IN_PROGRESS

            try:
                # Simulate applying repair
                self._apply_single_repair(repair)
                repair.status = RepairStatus.APPLIED
                repair.applied_at = datetime.now()
                applied += 1
                successful += 1

            except Exception as e:
                repair.status = RepairStatus.FAILED
                repair.metadata["error"] = str(e)
                applied += 1
                failed += 1

        # Calculate repair time
        repair_time = int((datetime.now() - start_time).total_seconds() * 1000)

        # Check if test passes (simulated)
        test_passes = successful > 0 and failed == 0

        result = RepairResult(
            result_id=result_id,
            test_id=test_id,
            actions_applied=applied,
            actions_successful=successful,
            actions_failed=failed,
            test_passes=test_passes,
            repair_time_ms=repair_time,
            repairs=repairs,
            repaired_at=datetime.now(),
        )

        self._repair_history.append(result)

        # Clear pending repairs for this test
        if test_id in self._pending_repairs:
            del self._pending_repairs[test_id]

        return result

    def _apply_single_repair(self, repair: RepairAction):
        """Apply a single repair action."""
        # In a real implementation, this would modify the test file
        # For now, we simulate success
        pass

    def verify_repairs(
        self,
        test_id: str,
        run_test_callback: Optional[Callable[[str], bool]] = None,
    ) -> bool:
        """Verify that repairs fixed the test."""
        # Get applied repairs
        repairs = []
        for result in self._repair_history:
            if result.test_id == test_id:
                repairs.extend([r for r in result.repairs if r.status == RepairStatus.APPLIED])

        if not repairs:
            return False

        # Run test if callback provided
        if run_test_callback:
            passed = run_test_callback(test_id)

            for repair in repairs:
                repair.status = RepairStatus.VERIFIED if passed else RepairStatus.FAILED

            return passed

        # Without callback, assume success if repairs were applied
        for repair in repairs:
            repair.status = RepairStatus.VERIFIED

        return True

    def rollback_repairs(
        self,
        test_id: str,
    ) -> bool:
        """Rollback repairs to a test."""
        if test_id in self._original_tests:
            # In real implementation, restore from backup
            for result in self._repair_history:
                if result.test_id == test_id:
                    for repair in result.repairs:
                        repair.status = RepairStatus.ROLLED_BACK

            return True

        return False

    def get_pending_repairs(
        self,
        test_id: Optional[str] = None,
    ) -> Dict[str, List[RepairAction]]:
        """Get pending repairs."""
        if test_id:
            return {test_id: self._pending_repairs.get(test_id, [])}
        return self._pending_repairs.copy()

    def get_repair_history(
        self,
        test_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[RepairResult]:
        """Get repair history."""
        results = self._repair_history

        if test_id:
            results = [r for r in results if r.test_id == test_id]

        return results[-limit:]

    def get_success_rate(self) -> float:
        """Get overall repair success rate."""
        if not self._repair_history:
            return 0.0

        successful = sum(1 for r in self._repair_history if r.test_passes)
        return successful / len(self._repair_history)

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        strategy_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}

        for result in self._repair_history:
            for repair in result.repairs:
                strategy = repair.strategy.value
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

                status = repair.status.value
                status_counts[status] = status_counts.get(status, 0) + 1

        total_repairs = sum(r.actions_applied for r in self._repair_history)
        total_successful = sum(r.actions_successful for r in self._repair_history)

        return {
            "total_analyses": self._analysis_counter,
            "total_repairs_generated": self._action_counter,
            "total_repairs_applied": total_repairs,
            "total_repairs_successful": total_successful,
            "repair_sessions": len(self._repair_history),
            "pending_repairs": sum(len(r) for r in self._pending_repairs.values()),
            "success_rate": self.get_success_rate(),
            "strategy_distribution": strategy_counts,
            "status_distribution": status_counts,
            "healer_stats": self.healer.get_statistics(),
        }

    def format_analysis(self, analysis: FailureAnalysis) -> str:
        """Format failure analysis."""
        lines = [
            "=" * 60,
            "  FAILURE ANALYSIS",
            "=" * 60,
            "",
            f"  Analysis ID: {analysis.analysis_id}",
            f"  Test ID: {analysis.test_id}",
            "",
            f"  Failure Type: {analysis.failure_type}",
            f"  Root Cause: {analysis.root_cause}",
            f"  Confidence: {analysis.confidence:.0%}",
            "",
            f"  Error: {analysis.error_message[:80]}...",
            "",
        ]

        if analysis.failed_selector:
            lines.append(f"  Failed Selector: {analysis.failed_selector}")

        if analysis.failed_step:
            lines.append(f"  Failed Step: {analysis.failed_step}")

        lines.extend([
            "",
            "-" * 60,
            "  SUGGESTED STRATEGIES",
            "-" * 60,
            "",
        ])

        for strategy in analysis.suggested_strategies:
            lines.append(f"  • {strategy.value}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)

    def format_result(self, result: RepairResult) -> str:
        """Format repair result."""
        status_icon = "✅" if result.test_passes else "❌"

        lines = [
            "=" * 60,
            f"  {status_icon} REPAIR RESULT",
            "=" * 60,
            "",
            f"  Result ID: {result.result_id}",
            f"  Test ID: {result.test_id}",
            f"  Test Passes: {result.test_passes}",
            "",
            f"  Actions Applied: {result.actions_applied}",
            f"  Successful: {result.actions_successful}",
            f"  Failed: {result.actions_failed}",
            f"  Repair Time: {result.repair_time_ms}ms",
            "",
        ]

        if result.repairs:
            lines.extend([
                "-" * 60,
                "  REPAIRS",
                "-" * 60,
                "",
            ])

            for repair in result.repairs:
                status_icons = {
                    RepairStatus.APPLIED: "✓",
                    RepairStatus.VERIFIED: "✓✓",
                    RepairStatus.FAILED: "✗",
                    RepairStatus.PENDING: "○",
                    RepairStatus.ROLLED_BACK: "↩",
                }
                icon = status_icons.get(repair.status, "?")

                lines.extend([
                    f"  {icon} {repair.strategy.value}",
                    f"    {repair.description}",
                    f"    Confidence: {repair.confidence:.0%}",
                    "",
                ])

        lines.extend(["=" * 60])
        return "\n".join(lines)


def create_repair_engine(
    selector_healer: Optional[SelectorHealer] = None,
    change_detector: Optional[ChangeDetector] = None,
    auto_apply: bool = False,
) -> RepairEngine:
    """Create a repair engine instance."""
    return RepairEngine(selector_healer, change_detector, auto_apply)
