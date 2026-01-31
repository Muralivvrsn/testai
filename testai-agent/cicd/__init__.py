"""
TestAI Agent - CI/CD Integration

Integration connectors for popular CI/CD platforms
including GitHub Actions, GitLab CI, Jenkins, and more.
"""

from .connectors import (
    CICDConnector,
    ConnectorType,
    PipelineStatus,
    PipelineResult,
    create_connector,
)

from .webhooks import (
    WebhookManager,
    WebhookEvent,
    WebhookPayload,
    WebhookConfig,
    create_webhook_manager,
)

from .artifacts import (
    ArtifactManager,
    TestArtifact,
    ArtifactType,
    ArtifactUploadResult,
    create_artifact_manager,
)

__all__ = [
    # Connectors
    "CICDConnector",
    "ConnectorType",
    "PipelineStatus",
    "PipelineResult",
    "create_connector",
    # Webhooks
    "WebhookManager",
    "WebhookEvent",
    "WebhookPayload",
    "WebhookConfig",
    "create_webhook_manager",
    # Artifacts
    "ArtifactManager",
    "TestArtifact",
    "ArtifactType",
    "ArtifactUploadResult",
    "create_artifact_manager",
]
