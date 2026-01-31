"""
TestAI Agent - Flakiness Mitigator

Automated mitigation strategies for flaky tests
with code fixes and configuration adjustments.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class MitigationStrategy(Enum):
    """Strategies for mitigating flakiness."""
    RETRY = "retry"                   # Simple retry mechanism
    WAIT_LONGER = "wait_longer"       # Increase timeouts
    QUARANTINE = "quarantine"         # Isolate from main suite
    SKIP = "skip"                     # Skip temporarily
    FIX_CODE = "fix_code"             # Code modification
    MOCK_DEPENDENCY = "mock_dependency"  # Mock external deps
    RESET_STATE = "reset_state"       # Add state reset
    PARALLELIZE = "parallelize"       # Run in isolation
    STABILIZE = "stabilize"           # Wait for stability


class MitigationStatus(Enum):
    """Status of a mitigation."""
    PENDING = "pending"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    REVERTED = "reverted"


@dataclass
class MitigationAction:
    """A specific mitigation action."""
    action_id: str
    strategy: MitigationStrategy
    description: str
    code_change: Optional[str] = None
    config_change: Optional[Dict[str, Any]] = None
    priority: int = 5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MitigationResult:
    """Result of applying a mitigation."""
    result_id: str
    test_id: str
    test_name: str
    strategy: MitigationStrategy
    status: MitigationStatus
    actions_taken: List[MitigationAction]
    success_rate_before: float
    success_rate_after: Optional[float]
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class FlakinessMitigator:
    """
    Flakiness mitigation engine.

    Features:
    - Automated fixes
    - Strategy selection
    - Verification
    - Rollback support
    """

    def __init__(
        self,
        auto_apply: bool = False,
        max_retries: int = 3,
    ):
        """Initialize the mitigator."""
        self._auto_apply = auto_apply
        self._max_retries = max_retries
        self._mitigations: Dict[str, MitigationResult] = {}
        self._action_counter = 0
        self._result_counter = 0

        # Strategy templates
        self._strategies = self._init_strategies()

    def _init_strategies(self) -> Dict[MitigationStrategy, Dict[str, Any]]:
        """Initialize mitigation strategy templates."""
        return {
            MitigationStrategy.RETRY: {
                "description": "Add retry mechanism for flaky assertions",
                "code_template": """
# Add retry wrapper
from functools import wraps
import time

def retry(max_attempts=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    time.sleep(delay * (attempt + 1))
            raise last_exception
        return wrapper
    return decorator
""",
                "config_template": {"retry_count": 3, "retry_delay": 1},
                "priority": 1,
            },
            MitigationStrategy.WAIT_LONGER: {
                "description": "Increase timeout values for async operations",
                "code_template": """
# Increase timeout
TIMEOUT = 30000  # 30 seconds
await page.wait_for_selector(selector, timeout=TIMEOUT)
""",
                "config_template": {"default_timeout": 30000},
                "priority": 2,
            },
            MitigationStrategy.QUARANTINE: {
                "description": "Move test to quarantine suite",
                "code_template": """
@pytest.mark.quarantine
@pytest.mark.flaky
def test_flaky_feature():
    # Test code here
    pass
""",
                "config_template": {"quarantine": True, "suite": "quarantine"},
                "priority": 4,
            },
            MitigationStrategy.SKIP: {
                "description": "Skip test until root cause is fixed",
                "code_template": """
@pytest.mark.skip(reason="Flaky - under investigation")
def test_flaky_feature():
    pass
""",
                "config_template": {"skip": True, "reason": "Flaky test"},
                "priority": 5,
            },
            MitigationStrategy.FIX_CODE: {
                "description": "Apply code fix for identified root cause",
                "code_template": None,  # Generated based on analysis
                "config_template": {},
                "priority": 3,
            },
            MitigationStrategy.MOCK_DEPENDENCY: {
                "description": "Mock external dependencies",
                "code_template": """
# Mock external service
@pytest.fixture
def mock_external_api(mocker):
    return mocker.patch('app.external_api.call', return_value={'status': 'ok'})
""",
                "config_template": {"mock_external": True},
                "priority": 3,
            },
            MitigationStrategy.RESET_STATE: {
                "description": "Add state reset between tests",
                "code_template": """
@pytest.fixture(autouse=True)
def reset_state():
    # Setup - reset before test
    reset_database()
    clear_cache()
    yield
    # Teardown - cleanup after test
    reset_database()
    clear_cache()
""",
                "config_template": {"reset_state": True},
                "priority": 2,
            },
            MitigationStrategy.PARALLELIZE: {
                "description": "Run test in isolation to avoid interference",
                "code_template": """
@pytest.mark.isolated
@pytest.mark.xdist_group("isolated")
def test_isolated_feature():
    pass
""",
                "config_template": {"isolated": True, "parallel_safe": False},
                "priority": 3,
            },
            MitigationStrategy.STABILIZE: {
                "description": "Add stability waits for UI/network",
                "code_template": """
# Wait for network idle
await page.wait_for_load_state('networkidle')

# Wait for no animations
await page.wait_for_function('!document.querySelector(".animating")')

# Wait for element stability
await page.wait_for_selector(selector, state='stable')
""",
                "config_template": {"wait_for_stability": True},
                "priority": 2,
            },
        }

    def suggest(
        self,
        test_id: str,
        test_name: str,
        root_causes: List[str],
        success_rate: float,
    ) -> List[MitigationAction]:
        """Suggest mitigation strategies based on analysis."""
        suggestions = []

        # Map root causes to strategies
        cause_to_strategy = {
            "async_wait": [MitigationStrategy.WAIT_LONGER, MitigationStrategy.STABILIZE],
            "race_condition": [MitigationStrategy.RETRY, MitigationStrategy.RESET_STATE],
            "shared_state": [MitigationStrategy.RESET_STATE, MitigationStrategy.PARALLELIZE],
            "test_order": [MitigationStrategy.RESET_STATE, MitigationStrategy.PARALLELIZE],
            "network_latency": [MitigationStrategy.MOCK_DEPENDENCY, MitigationStrategy.RETRY],
            "resource_exhaustion": [MitigationStrategy.PARALLELIZE, MitigationStrategy.RESET_STATE],
            "external_dependency": [MitigationStrategy.MOCK_DEPENDENCY, MitigationStrategy.RETRY],
            "ui_animation": [MitigationStrategy.STABILIZE, MitigationStrategy.WAIT_LONGER],
            "date_time": [MitigationStrategy.FIX_CODE, MitigationStrategy.MOCK_DEPENDENCY],
            "unknown": [MitigationStrategy.RETRY, MitigationStrategy.QUARANTINE],
        }

        seen_strategies = set()

        for cause in root_causes:
            strategies = cause_to_strategy.get(cause, [MitigationStrategy.RETRY])
            for strategy in strategies:
                if strategy not in seen_strategies:
                    seen_strategies.add(strategy)
                    action = self._create_action(strategy)
                    suggestions.append(action)

        # Sort by priority
        suggestions.sort(key=lambda a: a.priority)

        # If success rate is very low, suggest quarantine
        if success_rate < 0.5 and MitigationStrategy.QUARANTINE not in seen_strategies:
            suggestions.append(self._create_action(MitigationStrategy.QUARANTINE))

        return suggestions

    def _create_action(self, strategy: MitigationStrategy) -> MitigationAction:
        """Create a mitigation action."""
        self._action_counter += 1
        action_id = f"ACTION-{self._action_counter:05d}"

        template = self._strategies.get(strategy, {})

        return MitigationAction(
            action_id=action_id,
            strategy=strategy,
            description=template.get("description", f"Apply {strategy.value} strategy"),
            code_change=template.get("code_template"),
            config_change=template.get("config_template"),
            priority=template.get("priority", 5),
        )

    def apply(
        self,
        test_id: str,
        test_name: str,
        actions: List[MitigationAction],
        success_rate_before: float,
    ) -> MitigationResult:
        """Apply mitigation actions."""
        self._result_counter += 1
        result_id = f"MITIGATE-{self._result_counter:05d}"

        # In a real implementation, this would modify code/config
        status = MitigationStatus.APPLIED if self._auto_apply else MitigationStatus.PENDING

        result = MitigationResult(
            result_id=result_id,
            test_id=test_id,
            test_name=test_name,
            strategy=actions[0].strategy if actions else MitigationStrategy.RETRY,
            status=status,
            actions_taken=actions,
            success_rate_before=success_rate_before,
            success_rate_after=None,
            timestamp=datetime.now(),
        )

        self._mitigations[test_id] = result
        return result

    def verify(
        self,
        test_id: str,
        new_success_rate: float,
    ) -> Optional[MitigationResult]:
        """Verify if mitigation was successful."""
        result = self._mitigations.get(test_id)
        if not result:
            return None

        result.success_rate_after = new_success_rate

        # Consider successful if success rate improved significantly
        improvement = new_success_rate - result.success_rate_before

        if new_success_rate >= 0.95:
            result.status = MitigationStatus.VERIFIED
        elif improvement >= 0.2:
            result.status = MitigationStatus.VERIFIED
        else:
            result.status = MitigationStatus.FAILED

        return result

    def revert(self, test_id: str) -> Optional[MitigationResult]:
        """Revert a mitigation."""
        result = self._mitigations.get(test_id)
        if result:
            result.status = MitigationStatus.REVERTED
            result.success_rate_after = None
        return result

    def get_mitigation(self, test_id: str) -> Optional[MitigationResult]:
        """Get mitigation result for a test."""
        return self._mitigations.get(test_id)

    def get_pending(self) -> List[MitigationResult]:
        """Get all pending mitigations."""
        return [
            r for r in self._mitigations.values()
            if r.status == MitigationStatus.PENDING
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get mitigator statistics."""
        status_counts = {s.value: 0 for s in MitigationStatus}
        strategy_counts: Dict[str, int] = {}

        for result in self._mitigations.values():
            status_counts[result.status.value] += 1
            strategy_counts[result.strategy.value] = strategy_counts.get(result.strategy.value, 0) + 1

        # Calculate success rate
        verified = [r for r in self._mitigations.values() if r.status == MitigationStatus.VERIFIED]
        failed = [r for r in self._mitigations.values() if r.status == MitigationStatus.FAILED]

        success_rate = len(verified) / (len(verified) + len(failed)) if (verified or failed) else 0

        return {
            "total_mitigations": len(self._mitigations),
            "status_distribution": status_counts,
            "strategy_distribution": strategy_counts,
            "mitigation_success_rate": round(success_rate, 2),
        }

    def format_result(self, result: MitigationResult) -> str:
        """Format mitigation result for display."""
        status_icons = {
            MitigationStatus.PENDING: "⏳",
            MitigationStatus.APPLIED: "📝",
            MitigationStatus.VERIFIED: "✅",
            MitigationStatus.FAILED: "❌",
            MitigationStatus.REVERTED: "↩️",
        }

        icon = status_icons.get(result.status, "")

        lines = [
            "=" * 55,
            f"  MITIGATION RESULT: {icon} {result.status.value.upper()}",
            "=" * 55,
            "",
            f"  Test: {result.test_name}",
            f"  Strategy: {result.strategy.value}",
            "",
            "-" * 55,
            "  SUCCESS RATES",
            "-" * 55,
            "",
            f"  Before: {result.success_rate_before:.1%}",
        ]

        if result.success_rate_after is not None:
            lines.append(f"  After: {result.success_rate_after:.1%}")
            improvement = result.success_rate_after - result.success_rate_before
            lines.append(f"  Improvement: {improvement:+.1%}")

        if result.actions_taken:
            lines.extend([
                "",
                "-" * 55,
                "  ACTIONS TAKEN",
                "-" * 55,
                "",
            ])

            for action in result.actions_taken[:3]:
                lines.append(f"  • {action.strategy.value}: {action.description[:40]}...")

        lines.extend(["", "=" * 55])
        return "\n".join(lines)


def create_flakiness_mitigator(
    auto_apply: bool = False,
    max_retries: int = 3,
) -> FlakinessMitigator:
    """Create a flakiness mitigator instance."""
    return FlakinessMitigator(
        auto_apply=auto_apply,
        max_retries=max_retries,
    )
