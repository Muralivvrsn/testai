"""
TestAI Agent - Test Environment Management

Environment provisioning, configuration, and lifecycle
management for test execution.
"""

from .manager import (
    EnvironmentManager,
    Environment,
    EnvironmentConfig,
    EnvironmentStatus,
    create_environment_manager,
)

from .provisioner import (
    EnvironmentProvisioner,
    ProvisioningPlan,
    ProvisionResult,
    create_provisioner,
)

from .config import (
    ConfigManager,
    ConfigProfile,
    ConfigSource,
    create_config_manager,
)

__all__ = [
    # Manager
    "EnvironmentManager",
    "Environment",
    "EnvironmentConfig",
    "EnvironmentStatus",
    "create_environment_manager",
    # Provisioner
    "EnvironmentProvisioner",
    "ProvisioningPlan",
    "ProvisionResult",
    "create_provisioner",
    # Config
    "ConfigManager",
    "ConfigProfile",
    "ConfigSource",
    "create_config_manager",
]
