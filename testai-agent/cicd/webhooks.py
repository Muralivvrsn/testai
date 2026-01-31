"""
TestAI Agent - Webhook Manager

Manages webhooks for test result notifications
and CI/CD pipeline events.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import json
import hashlib
import hmac


class WebhookEvent(Enum):
    """Types of webhook events."""
    TEST_STARTED = "test_started"
    TEST_COMPLETED = "test_completed"
    TEST_FAILED = "test_failed"
    SUITE_STARTED = "suite_started"
    SUITE_COMPLETED = "suite_completed"
    PIPELINE_STARTED = "pipeline_started"
    PIPELINE_COMPLETED = "pipeline_completed"
    COVERAGE_UPDATED = "coverage_updated"
    FLAKY_TEST_DETECTED = "flaky_test_detected"
    THRESHOLD_VIOLATED = "threshold_violated"


class DeliveryStatus(Enum):
    """Status of webhook delivery."""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    webhook_id: str
    name: str
    url: str
    events: List[WebhookEvent]
    secret: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    active: bool = True
    retry_count: int = 3
    timeout_sec: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookPayload:
    """Payload for a webhook delivery."""
    payload_id: str
    event: WebhookEvent
    data: Dict[str, Any]
    timestamp: datetime
    signature: Optional[str] = None


@dataclass
class DeliveryResult:
    """Result of a webhook delivery."""
    delivery_id: str
    webhook_id: str
    payload_id: str
    status: DeliveryStatus
    status_code: Optional[int]
    response_body: Optional[str]
    delivered_at: Optional[datetime]
    attempt: int
    error: Optional[str] = None


class WebhookManager:
    """
    Manages webhooks for test notifications.

    Features:
    - Multiple webhook endpoints
    - Event filtering
    - Signature verification
    - Retry logic
    """

    def __init__(
        self,
        max_retries: int = 3,
        timeout_sec: int = 30,
    ):
        """Initialize the manager."""
        self._max_retries = max_retries
        self._timeout = timeout_sec
        self._webhooks: Dict[str, WebhookConfig] = {}
        self._deliveries: List[DeliveryResult] = []
        self._webhook_counter = 0
        self._payload_counter = 0
        self._delivery_counter = 0

    def register_webhook(
        self,
        name: str,
        url: str,
        events: List[WebhookEvent],
        secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> WebhookConfig:
        """Register a new webhook endpoint."""
        self._webhook_counter += 1
        webhook_id = f"WH-{self._webhook_counter:05d}"

        config = WebhookConfig(
            webhook_id=webhook_id,
            name=name,
            url=url,
            events=events,
            secret=secret,
            headers=headers or {},
            retry_count=self._max_retries,
            timeout_sec=self._timeout,
        )

        self._webhooks[webhook_id] = config
        return config

    def update_webhook(
        self,
        webhook_id: str,
        events: Optional[List[WebhookEvent]] = None,
        active: Optional[bool] = None,
        url: Optional[str] = None,
    ) -> Optional[WebhookConfig]:
        """Update an existing webhook."""
        config = self._webhooks.get(webhook_id)
        if not config:
            return None

        if events is not None:
            config.events = events
        if active is not None:
            config.active = active
        if url is not None:
            config.url = url

        return config

    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook."""
        if webhook_id in self._webhooks:
            del self._webhooks[webhook_id]
            return True
        return False

    def create_payload(
        self,
        event: WebhookEvent,
        data: Dict[str, Any],
        secret: Optional[str] = None,
    ) -> WebhookPayload:
        """Create a webhook payload."""
        self._payload_counter += 1
        payload_id = f"PL-{self._payload_counter:05d}"

        timestamp = datetime.now()

        payload = WebhookPayload(
            payload_id=payload_id,
            event=event,
            data=data,
            timestamp=timestamp,
        )

        if secret:
            payload.signature = self._sign_payload(payload, secret)

        return payload

    def _sign_payload(
        self,
        payload: WebhookPayload,
        secret: str,
    ) -> str:
        """Sign a payload with HMAC-SHA256."""
        body = json.dumps({
            "event": payload.event.value,
            "data": payload.data,
            "timestamp": payload.timestamp.isoformat(),
        }, sort_keys=True)

        signature = hmac.new(
            secret.encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"sha256={signature}"

    def verify_signature(
        self,
        payload_body: str,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify a webhook signature."""
        expected = hmac.new(
            secret.encode(),
            payload_body.encode(),
            hashlib.sha256
        ).hexdigest()

        expected_sig = f"sha256={expected}"
        return hmac.compare_digest(signature, expected_sig)

    def trigger(
        self,
        event: WebhookEvent,
        data: Dict[str, Any],
        simulate: bool = True,
    ) -> List[DeliveryResult]:
        """Trigger webhooks for an event."""
        results = []

        # Find matching webhooks
        for webhook in self._webhooks.values():
            if not webhook.active:
                continue
            if event not in webhook.events:
                continue

            # Create payload
            payload = self.create_payload(event, data, webhook.secret)

            # Deliver (simulated by default)
            result = self._deliver(webhook, payload, simulate)
            results.append(result)

        return results

    def _deliver(
        self,
        webhook: WebhookConfig,
        payload: WebhookPayload,
        simulate: bool = True,
    ) -> DeliveryResult:
        """Deliver a webhook payload."""
        self._delivery_counter += 1
        delivery_id = f"DLV-{self._delivery_counter:05d}"

        if simulate:
            # Simulated delivery
            result = DeliveryResult(
                delivery_id=delivery_id,
                webhook_id=webhook.webhook_id,
                payload_id=payload.payload_id,
                status=DeliveryStatus.DELIVERED,
                status_code=200,
                response_body='{"ok": true}',
                delivered_at=datetime.now(),
                attempt=1,
            )
        else:
            # Real delivery would happen here
            # For now, mark as pending
            result = DeliveryResult(
                delivery_id=delivery_id,
                webhook_id=webhook.webhook_id,
                payload_id=payload.payload_id,
                status=DeliveryStatus.PENDING,
                status_code=None,
                response_body=None,
                delivered_at=None,
                attempt=0,
            )

        self._deliveries.append(result)
        return result

    def get_delivery_history(
        self,
        webhook_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[DeliveryResult]:
        """Get delivery history."""
        history = self._deliveries

        if webhook_id:
            history = [d for d in history if d.webhook_id == webhook_id]

        return history[-limit:]

    def get_failed_deliveries(self) -> List[DeliveryResult]:
        """Get failed deliveries."""
        return [
            d for d in self._deliveries
            if d.status == DeliveryStatus.FAILED
        ]

    def retry_delivery(self, delivery_id: str) -> Optional[DeliveryResult]:
        """Retry a failed delivery."""
        delivery = next(
            (d for d in self._deliveries if d.delivery_id == delivery_id),
            None
        )

        if not delivery:
            return None

        webhook = self._webhooks.get(delivery.webhook_id)
        if not webhook:
            return None

        # Increment attempt
        delivery.attempt += 1
        delivery.status = DeliveryStatus.RETRYING

        # Simulate retry
        delivery.status = DeliveryStatus.DELIVERED
        delivery.status_code = 200
        delivery.delivered_at = datetime.now()

        return delivery

    def format_payload_json(
        self,
        payload: WebhookPayload,
    ) -> str:
        """Format payload as JSON."""
        return json.dumps({
            "event": payload.event.value,
            "payload_id": payload.payload_id,
            "timestamp": payload.timestamp.isoformat(),
            "data": payload.data,
            "signature": payload.signature,
        }, indent=2)

    def get_webhook(self, webhook_id: str) -> Optional[WebhookConfig]:
        """Get a webhook by ID."""
        return self._webhooks.get(webhook_id)

    def list_webhooks(self) -> List[WebhookConfig]:
        """List all webhooks."""
        return list(self._webhooks.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        status_counts = {s.value: 0 for s in DeliveryStatus}
        for delivery in self._deliveries:
            status_counts[delivery.status.value] += 1

        return {
            "total_webhooks": len(self._webhooks),
            "active_webhooks": sum(1 for w in self._webhooks.values() if w.active),
            "total_deliveries": len(self._deliveries),
            "deliveries_by_status": status_counts,
        }

    def format_webhook(self, config: WebhookConfig) -> str:
        """Format a webhook for display."""
        lines = [
            "=" * 50,
            f"  WEBHOOK: {config.name}",
            "=" * 50,
            "",
            f"  ID: {config.webhook_id}",
            f"  URL: {config.url}",
            f"  Active: {'Yes' if config.active else 'No'}",
            "",
            "-" * 50,
            "  EVENTS",
            "-" * 50,
            "",
        ]

        for event in config.events:
            lines.append(f"  • {event.value}")

        lines.append("")
        lines.append("=" * 50)
        return "\n".join(lines)


def create_webhook_manager(
    max_retries: int = 3,
    timeout_sec: int = 30,
) -> WebhookManager:
    """Create a webhook manager instance."""
    return WebhookManager(
        max_retries=max_retries,
        timeout_sec=timeout_sec,
    )
