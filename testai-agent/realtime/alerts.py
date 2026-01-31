"""
TestAI Agent - Alert Manager

Manages real-time alerts based on metric thresholds
with configurable rules and notification channels.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Set
import uuid

from .metrics import MetricsCollector, MetricType, TimeWindow


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertCondition(Enum):
    """Types of alert conditions."""
    ABOVE_THRESHOLD = "above_threshold"
    BELOW_THRESHOLD = "below_threshold"
    CHANGE_RATE = "change_rate"
    CONSECUTIVE_FAILURES = "consecutive_failures"
    ANOMALY = "anomaly"
    PATTERN = "pattern"


class AlertState(Enum):
    """Alert states."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SILENCED = "silenced"


@dataclass
class AlertRule:
    """A rule for triggering alerts."""
    rule_id: str
    name: str
    description: str
    metric_type: MetricType
    condition: AlertCondition
    threshold: float
    severity: AlertSeverity
    window: TimeWindow = TimeWindow.MINUTE
    cooldown_seconds: int = 300
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def is_active(self) -> bool:
        return self.enabled


@dataclass
class Alert:
    """A triggered alert."""
    alert_id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    state: AlertState
    message: str
    metric_type: MetricType
    metric_value: float
    threshold: float
    triggered_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AlertManager:
    """
    Manages real-time alerts with configurable rules.

    Features:
    - Threshold-based alerting
    - Rate of change detection
    - Cooldown periods
    - Alert acknowledgment
    - Notification callbacks
    """

    def __init__(
        self,
        metrics_collector: Optional[MetricsCollector] = None,
    ):
        """Initialize the alert manager."""
        self.metrics = metrics_collector
        self._rules: Dict[str, AlertRule] = {}
        self._alerts: Dict[str, Alert] = {}
        self._active_alerts: Set[str] = set()
        self._last_triggered: Dict[str, datetime] = {}
        self._callbacks: List[Callable[[Alert], None]] = []
        self._rule_counter = 0
        self._alert_counter = 0

        # Default rules
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """Set up default alert rules."""
        defaults = [
            {
                "name": "High Failure Rate",
                "description": "Alert when failure rate exceeds threshold",
                "metric_type": MetricType.FAILURE_RATE,
                "condition": AlertCondition.ABOVE_THRESHOLD,
                "threshold": 0.2,  # 20% failure rate
                "severity": AlertSeverity.ERROR,
            },
            {
                "name": "Critical Failure Rate",
                "description": "Critical alert when failure rate is very high",
                "metric_type": MetricType.FAILURE_RATE,
                "condition": AlertCondition.ABOVE_THRESHOLD,
                "threshold": 0.5,  # 50% failure rate
                "severity": AlertSeverity.CRITICAL,
            },
            {
                "name": "Slow Execution",
                "description": "Alert when execution time is slow",
                "metric_type": MetricType.EXECUTION_TIME,
                "condition": AlertCondition.ABOVE_THRESHOLD,
                "threshold": 30000,  # 30 seconds
                "severity": AlertSeverity.WARNING,
            },
            {
                "name": "Low Throughput",
                "description": "Alert when throughput drops",
                "metric_type": MetricType.THROUGHPUT,
                "condition": AlertCondition.BELOW_THRESHOLD,
                "threshold": 0.1,  # Less than 0.1 tests/second
                "severity": AlertSeverity.WARNING,
            },
            {
                "name": "High Flakiness",
                "description": "Alert when flakiness is high",
                "metric_type": MetricType.FLAKINESS_RATE,
                "condition": AlertCondition.ABOVE_THRESHOLD,
                "threshold": 0.1,  # 10% flaky
                "severity": AlertSeverity.WARNING,
            },
            {
                "name": "Queue Backup",
                "description": "Alert when queue is backing up",
                "metric_type": MetricType.QUEUE_SIZE,
                "condition": AlertCondition.ABOVE_THRESHOLD,
                "threshold": 100,
                "severity": AlertSeverity.WARNING,
            },
        ]

        for default in defaults:
            self.create_rule(**default)

    def create_rule(
        self,
        name: str,
        description: str,
        metric_type: MetricType,
        condition: AlertCondition,
        threshold: float,
        severity: AlertSeverity = AlertSeverity.WARNING,
        window: TimeWindow = TimeWindow.MINUTE,
        cooldown_seconds: int = 300,
        tags: Optional[Dict[str, str]] = None,
    ) -> AlertRule:
        """Create an alert rule."""
        self._rule_counter += 1
        rule_id = f"RULE-{self._rule_counter:04d}"

        rule = AlertRule(
            rule_id=rule_id,
            name=name,
            description=description,
            metric_type=metric_type,
            condition=condition,
            threshold=threshold,
            severity=severity,
            window=window,
            cooldown_seconds=cooldown_seconds,
            tags=tags or {},
        )

        self._rules[rule_id] = rule
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """Delete an alert rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def check_rules(self) -> List[Alert]:
        """Check all rules and trigger alerts as needed."""
        if not self.metrics:
            return []

        triggered = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            # Check cooldown
            last_trigger = self._last_triggered.get(rule.rule_id)
            if last_trigger:
                cooldown_end = last_trigger + timedelta(seconds=rule.cooldown_seconds)
                if datetime.now() < cooldown_end:
                    continue

            # Get metric aggregation
            agg = self.metrics.aggregate(rule.metric_type, rule.window)
            if not agg:
                continue

            # Check condition
            should_trigger = False
            current_value = agg.avg_value

            if rule.condition == AlertCondition.ABOVE_THRESHOLD:
                should_trigger = current_value > rule.threshold
            elif rule.condition == AlertCondition.BELOW_THRESHOLD:
                should_trigger = current_value < rule.threshold
            elif rule.condition == AlertCondition.CHANGE_RATE:
                # Check rate of change
                trend = self.metrics.get_trend(rule.metric_type)
                should_trigger = abs(trend["change_percent"]) > rule.threshold

            if should_trigger:
                alert = self._trigger_alert(rule, current_value)
                triggered.append(alert)

        return triggered

    def _trigger_alert(self, rule: AlertRule, value: float) -> Alert:
        """Trigger an alert for a rule."""
        self._alert_counter += 1
        alert_id = f"ALERT-{self._alert_counter:05d}"

        message = self._build_message(rule, value)

        alert = Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            state=AlertState.ACTIVE,
            message=message,
            metric_type=rule.metric_type,
            metric_value=value,
            threshold=rule.threshold,
            triggered_at=datetime.now(),
        )

        self._alerts[alert_id] = alert
        self._active_alerts.add(alert_id)
        self._last_triggered[rule.rule_id] = datetime.now()

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception:
                pass

        return alert

    def _build_message(self, rule: AlertRule, value: float) -> str:
        """Build alert message."""
        if rule.condition == AlertCondition.ABOVE_THRESHOLD:
            return f"{rule.name}: {rule.metric_type.value} is {value:.2f} (threshold: >{rule.threshold})"
        elif rule.condition == AlertCondition.BELOW_THRESHOLD:
            return f"{rule.name}: {rule.metric_type.value} is {value:.2f} (threshold: <{rule.threshold})"
        else:
            return f"{rule.name}: {rule.metric_type.value} triggered at {value:.2f}"

    def acknowledge(
        self,
        alert_id: str,
        acknowledged_by: str,
        note: Optional[str] = None,
    ) -> bool:
        """Acknowledge an alert."""
        alert = self._alerts.get(alert_id)
        if not alert or alert.state != AlertState.ACTIVE:
            return False

        alert.state = AlertState.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now()
        alert.acknowledged_by = acknowledged_by

        if note:
            alert.notes.append(f"[{datetime.now().isoformat()}] {acknowledged_by}: {note}")

        return True

    def resolve(
        self,
        alert_id: str,
        note: Optional[str] = None,
    ) -> bool:
        """Resolve an alert."""
        alert = self._alerts.get(alert_id)
        if not alert or alert.state == AlertState.RESOLVED:
            return False

        alert.state = AlertState.RESOLVED
        alert.resolved_at = datetime.now()

        if note:
            alert.notes.append(f"[{datetime.now().isoformat()}] Resolved: {note}")

        self._active_alerts.discard(alert_id)
        return True

    def silence(
        self,
        alert_id: str,
        duration_minutes: int = 60,
    ) -> bool:
        """Silence an alert temporarily."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.state = AlertState.SILENCED
        alert.metadata["silenced_until"] = (
            datetime.now() + timedelta(minutes=duration_minutes)
        ).isoformat()

        return True

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self._alerts.get(alert_id)

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return [
            self._alerts[aid]
            for aid in self._active_alerts
            if self._alerts[aid].state == AlertState.ACTIVE
        ]

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        state: Optional[AlertState] = None,
        limit: int = 100,
    ) -> List[Alert]:
        """Get alerts with optional filtering."""
        alerts = list(self._alerts.values())

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        if state:
            alerts = [a for a in alerts if a.state == state]

        # Sort by triggered time, newest first
        alerts.sort(key=lambda a: a.triggered_at, reverse=True)

        return alerts[:limit]

    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules(self, enabled_only: bool = False) -> List[AlertRule]:
        """Get all rules."""
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def add_callback(self, callback: Callable[[Alert], None]):
        """Add a callback for new alerts."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[Alert], None]):
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        alerts = list(self._alerts.values())

        by_severity = {}
        by_state = {}

        for alert in alerts:
            sev = alert.severity.value
            state = alert.state.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1

        return {
            "total_rules": len(self._rules),
            "enabled_rules": len([r for r in self._rules.values() if r.enabled]),
            "total_alerts": len(alerts),
            "active_alerts": len(self._active_alerts),
            "by_severity": by_severity,
            "by_state": by_state,
        }

    def format_alerts(self) -> str:
        """Format alerts for display."""
        lines = [
            "=" * 60,
            "  ALERT DASHBOARD",
            "=" * 60,
            "",
        ]

        active = self.get_active_alerts()

        if not active:
            lines.append("  No active alerts")
        else:
            lines.extend([f"  Active Alerts: {len(active)}", ""])

            for alert in active[:10]:
                severity_icon = {
                    AlertSeverity.INFO: "ℹ️",
                    AlertSeverity.WARNING: "⚠️",
                    AlertSeverity.ERROR: "❌",
                    AlertSeverity.CRITICAL: "🚨",
                }.get(alert.severity, "?")

                time_str = alert.triggered_at.strftime("%H:%M:%S")
                lines.extend([
                    f"  {severity_icon} [{time_str}] {alert.message}",
                    f"     ID: {alert.alert_id} | Rule: {alert.rule_name}",
                    "",
                ])

        # Show rules summary
        lines.extend([
            "-" * 60,
            "  ALERT RULES",
            "-" * 60,
            "",
        ])

        for rule in list(self._rules.values())[:5]:
            status = "✓" if rule.enabled else "✗"
            lines.append(
                f"  {status} {rule.name} ({rule.severity.value}): "
                f"{rule.condition.value} {rule.threshold}"
            )

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_alert_manager(
    metrics_collector: Optional[MetricsCollector] = None,
) -> AlertManager:
    """Create an alert manager instance."""
    return AlertManager(metrics_collector)
