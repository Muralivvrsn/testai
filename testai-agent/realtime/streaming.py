"""
TestAI Agent - Streaming Dashboard

Real-time streaming dashboard with WebSocket support,
live updates, and interactive visualizations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Set
import json
import threading
import queue
import time

from .metrics import MetricsCollector, MetricType, TimeWindow, MetricPoint
from .alerts import AlertManager, Alert, AlertSeverity


class EventType(Enum):
    """Types of dashboard events."""
    METRIC_UPDATE = "metric_update"
    ALERT_TRIGGERED = "alert_triggered"
    ALERT_RESOLVED = "alert_resolved"
    TEST_STARTED = "test_started"
    TEST_COMPLETED = "test_completed"
    TEST_FAILED = "test_failed"
    STATUS_CHANGE = "status_change"
    HEARTBEAT = "heartbeat"


@dataclass
class DashboardEvent:
    """An event to be streamed to clients."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    data: Dict[str, Any]
    severity: str = "info"
    source: str = "system"


@dataclass
class StreamConfig:
    """Configuration for streaming."""
    heartbeat_interval_seconds: int = 5
    max_event_buffer: int = 1000
    metric_update_interval_seconds: float = 1.0
    include_heartbeats: bool = True
    compress_events: bool = False


@dataclass
class ClientConnection:
    """A connected client."""
    client_id: str
    connected_at: datetime
    last_activity: datetime
    subscriptions: Set[EventType]
    filters: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class StreamingDashboard:
    """
    Real-time streaming dashboard.

    Features:
    - Event streaming
    - Client management
    - Metric aggregation
    - Alert integration
    - WebSocket-ready output
    """

    def __init__(
        self,
        metrics: Optional[MetricsCollector] = None,
        alerts: Optional[AlertManager] = None,
        config: Optional[StreamConfig] = None,
    ):
        """Initialize the streaming dashboard."""
        self.metrics = metrics or MetricsCollector()
        self.alerts = alerts or AlertManager(self.metrics)
        self.config = config or StreamConfig()

        self._clients: Dict[str, ClientConnection] = {}
        self._event_queue: queue.Queue = queue.Queue(maxsize=self.config.max_event_buffer)
        self._event_counter = 0
        self._callbacks: Dict[str, List[Callable[[DashboardEvent], None]]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Status tracking
        self._status = "idle"
        self._total_tests = 0
        self._completed_tests = 0
        self._passed_tests = 0
        self._failed_tests = 0
        self._start_time: Optional[datetime] = None

        # Connect to metrics and alerts
        self.metrics.add_listener(self._on_metric)
        self.alerts.add_callback(self._on_alert)

    def start(self):
        """Start the streaming dashboard."""
        if self._running:
            return

        self._running = True
        self._start_time = datetime.now()
        self._status = "running"

        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        self._emit_event(EventType.STATUS_CHANGE, {
            "status": "running",
            "started_at": self._start_time.isoformat(),
        })

    def stop(self):
        """Stop the streaming dashboard."""
        if not self._running:
            return

        self._running = False
        self._status = "stopped"

        self._emit_event(EventType.STATUS_CHANGE, {
            "status": "stopped",
            "stopped_at": datetime.now().isoformat(),
        })

        if self._thread:
            self._thread.join(timeout=2)

    def _run_loop(self):
        """Main event loop."""
        last_heartbeat = datetime.now()
        last_metric_update = datetime.now()

        while self._running:
            now = datetime.now()

            # Heartbeat
            if self.config.include_heartbeats:
                since_heartbeat = (now - last_heartbeat).total_seconds()
                if since_heartbeat >= self.config.heartbeat_interval_seconds:
                    self._emit_heartbeat()
                    last_heartbeat = now

            # Metric updates
            since_metric = (now - last_metric_update).total_seconds()
            if since_metric >= self.config.metric_update_interval_seconds:
                self._emit_metric_update()
                last_metric_update = now

            # Check alerts
            self.alerts.check_rules()

            time.sleep(0.1)

    def _emit_event(
        self,
        event_type: EventType,
        data: Dict[str, Any],
        severity: str = "info",
    ) -> DashboardEvent:
        """Emit an event."""
        self._event_counter += 1
        event_id = f"EVT-{self._event_counter:08d}"

        event = DashboardEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.now(),
            data=data,
            severity=severity,
        )

        # Add to queue
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            # Remove oldest event
            try:
                self._event_queue.get_nowait()
                self._event_queue.put_nowait(event)
            except queue.Empty:
                pass

        # Notify callbacks
        for callback in self._callbacks.get(event_type.value, []):
            try:
                callback(event)
            except Exception:
                pass

        # Notify all subscribers
        for callback in self._callbacks.get("*", []):
            try:
                callback(event)
            except Exception:
                pass

        return event

    def _emit_heartbeat(self):
        """Emit a heartbeat event."""
        stats = self.get_summary()
        self._emit_event(EventType.HEARTBEAT, {
            "timestamp": datetime.now().isoformat(),
            "status": self._status,
            "stats": stats,
        })

    def _emit_metric_update(self):
        """Emit metric update event."""
        dashboard_metrics = self.metrics.get_dashboard_metrics()
        self._emit_event(EventType.METRIC_UPDATE, {
            "metrics": dashboard_metrics,
        })

    def _on_metric(self, point: MetricPoint):
        """Handle new metric point."""
        # Metrics are batched in _emit_metric_update
        pass

    def _on_alert(self, alert: Alert):
        """Handle new alert."""
        self._emit_event(
            EventType.ALERT_TRIGGERED,
            {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity.value,
                "message": alert.message,
                "metric_value": alert.metric_value,
                "threshold": alert.threshold,
            },
            severity=alert.severity.value,
        )

    def record_test_start(
        self,
        test_id: str,
        test_name: str,
        browser: Optional[str] = None,
        device: Optional[str] = None,
    ):
        """Record a test starting."""
        self._emit_event(EventType.TEST_STARTED, {
            "test_id": test_id,
            "test_name": test_name,
            "browser": browser,
            "device": device,
        })

        self.metrics.record_active_tests(1)

    def record_test_complete(
        self,
        test_id: str,
        test_name: str,
        passed: bool,
        duration_ms: int,
        browser: Optional[str] = None,
        device: Optional[str] = None,
        error: Optional[str] = None,
        flaky: bool = False,
        retried: bool = False,
    ):
        """Record a test completing."""
        self._completed_tests += 1

        if passed:
            self._passed_tests += 1
            event_type = EventType.TEST_COMPLETED
            severity = "success"
        else:
            self._failed_tests += 1
            event_type = EventType.TEST_FAILED
            severity = "error"

        self._emit_event(event_type, {
            "test_id": test_id,
            "test_name": test_name,
            "passed": passed,
            "duration_ms": duration_ms,
            "browser": browser,
            "device": device,
            "error": error,
            "flaky": flaky,
            "retried": retried,
        }, severity=severity)

        # Record to metrics
        self.metrics.record_test_result(
            test_id=test_id,
            passed=passed,
            duration_ms=duration_ms,
            retried=retried,
            flaky=flaky,
            browser=browser,
            device=device,
        )

    def set_total_tests(self, total: int):
        """Set the total number of tests."""
        self._total_tests = total

    def connect_client(
        self,
        client_id: str,
        subscriptions: Optional[Set[EventType]] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> ClientConnection:
        """Connect a client."""
        connection = ClientConnection(
            client_id=client_id,
            connected_at=datetime.now(),
            last_activity=datetime.now(),
            subscriptions=subscriptions or set(EventType),
            filters=filters or {},
        )

        self._clients[client_id] = connection
        return connection

    def disconnect_client(self, client_id: str) -> bool:
        """Disconnect a client."""
        if client_id in self._clients:
            del self._clients[client_id]
            return True
        return False

    def get_events(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
    ) -> List[DashboardEvent]:
        """Get recent events."""
        events = []

        # Drain queue to list
        while not self._event_queue.empty() and len(events) < self.config.max_event_buffer:
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break

        # Put back into queue
        for event in events:
            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                break

        # Filter
        if since:
            events = [e for e in events if e.timestamp >= since]

        if event_types:
            events = [e for e in events if e.event_type in event_types]

        # Sort by timestamp, newest first
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return events[:limit]

    def subscribe(
        self,
        event_type: str,
        callback: Callable[[DashboardEvent], None],
    ):
        """Subscribe to events."""
        if event_type not in self._callbacks:
            self._callbacks[event_type] = []
        self._callbacks[event_type].append(callback)

    def unsubscribe(
        self,
        event_type: str,
        callback: Callable[[DashboardEvent], None],
    ):
        """Unsubscribe from events."""
        if event_type in self._callbacks and callback in self._callbacks[event_type]:
            self._callbacks[event_type].remove(callback)

    def get_summary(self) -> Dict[str, Any]:
        """Get current dashboard summary."""
        elapsed_ms = 0
        if self._start_time:
            elapsed_ms = int((datetime.now() - self._start_time).total_seconds() * 1000)

        progress_pct = (
            self._completed_tests / self._total_tests
            if self._total_tests > 0 else 0
        )

        pass_rate = (
            self._passed_tests / self._completed_tests
            if self._completed_tests > 0 else 0
        )

        return {
            "status": self._status,
            "total_tests": self._total_tests,
            "completed_tests": self._completed_tests,
            "passed_tests": self._passed_tests,
            "failed_tests": self._failed_tests,
            "progress_pct": round(progress_pct * 100, 1),
            "pass_rate": round(pass_rate * 100, 1),
            "elapsed_ms": elapsed_ms,
            "active_alerts": len(self.alerts.get_active_alerts()),
            "connected_clients": len(self._clients),
        }

    def get_full_state(self) -> Dict[str, Any]:
        """Get complete dashboard state for new clients."""
        return {
            "summary": self.get_summary(),
            "metrics": self.metrics.get_dashboard_metrics(),
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity.value,
                    "message": a.message,
                    "triggered_at": a.triggered_at.isoformat(),
                }
                for a in self.alerts.get_active_alerts()
            ],
            "recent_events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type.value,
                    "timestamp": e.timestamp.isoformat(),
                    "data": e.data,
                    "severity": e.severity,
                }
                for e in self.get_events(limit=50)
            ],
        }

    def to_json(self) -> str:
        """Serialize dashboard state to JSON."""
        state = self.get_full_state()
        return json.dumps(state, default=str)

    def format_dashboard(self) -> str:
        """Format dashboard for terminal display."""
        summary = self.get_summary()

        lines = [
            "=" * 70,
            "  TESTAI REAL-TIME MONITORING DASHBOARD",
            "=" * 70,
            "",
            f"  Status: {summary['status'].upper()}",
            f"  Progress: {summary['progress_pct']}% ({summary['completed_tests']}/{summary['total_tests']})",
            f"  Pass Rate: {summary['pass_rate']}%",
            "",
            f"  ✅ Passed: {summary['passed_tests']}    ❌ Failed: {summary['failed_tests']}",
            f"  ⏱️ Elapsed: {summary['elapsed_ms']//1000}s",
            f"  🔔 Active Alerts: {summary['active_alerts']}",
            f"  👥 Connected Clients: {summary['connected_clients']}",
            "",
        ]

        # Metrics section
        lines.extend([
            "-" * 70,
            "  METRICS (Last Minute)",
            "-" * 70,
            "",
        ])

        metrics = self.metrics.get_dashboard_metrics()
        for metric_name, metric_data in list(metrics.items())[:4]:
            agg = metric_data.get("aggregations", {}).get("1m", {})
            if agg:
                lines.append(
                    f"  {metric_name}: avg={agg.get('avg', 0):.2f} "
                    f"min={agg.get('min', 0):.2f} max={agg.get('max', 0):.2f}"
                )

        # Alerts section
        active_alerts = self.alerts.get_active_alerts()
        if active_alerts:
            lines.extend([
                "",
                "-" * 70,
                f"  ACTIVE ALERTS ({len(active_alerts)})",
                "-" * 70,
                "",
            ])

            for alert in active_alerts[:5]:
                icon = {
                    AlertSeverity.INFO: "ℹ️",
                    AlertSeverity.WARNING: "⚠️",
                    AlertSeverity.ERROR: "❌",
                    AlertSeverity.CRITICAL: "🚨",
                }.get(alert.severity, "?")

                lines.append(f"  {icon} {alert.message}")

        # Recent events
        events = self.get_events(limit=5)
        if events:
            lines.extend([
                "",
                "-" * 70,
                "  RECENT EVENTS",
                "-" * 70,
                "",
            ])

            for event in events:
                time_str = event.timestamp.strftime("%H:%M:%S")
                lines.append(f"  [{time_str}] {event.event_type.value}: {event.data.get('test_name', event.data.get('status', ''))}")

        lines.extend(["", "=" * 70])
        return "\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        return {
            "status": self._status,
            "running": self._running,
            "event_count": self._event_counter,
            "connected_clients": len(self._clients),
            "metrics_stats": self.metrics.get_statistics(),
            "alert_stats": self.alerts.get_statistics(),
        }


def create_streaming_dashboard(
    metrics: Optional[MetricsCollector] = None,
    alerts: Optional[AlertManager] = None,
    config: Optional[StreamConfig] = None,
) -> StreamingDashboard:
    """Create a streaming dashboard instance."""
    return StreamingDashboard(metrics, alerts, config)
