"""
TestAI Agent - Environment Manager

Central management for test environments with
lifecycle control and resource tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class EnvironmentStatus(Enum):
    """Status of an environment."""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    ERROR = "error"


class EnvironmentType(Enum):
    """Types of test environments."""
    LOCAL = "local"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    HYBRID = "hybrid"


@dataclass
class EnvironmentConfig:
    """Configuration for an environment."""
    config_id: str
    name: str
    env_type: EnvironmentType
    base_url: Optional[str] = None
    api_url: Optional[str] = None
    database_url: Optional[str] = None
    resources: Dict[str, Any] = field(default_factory=dict)
    variables: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Environment:
    """A test environment instance."""
    env_id: str
    name: str
    config: EnvironmentConfig
    status: EnvironmentStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    terminated_at: Optional[datetime] = None
    endpoints: Dict[str, str] = field(default_factory=dict)
    health: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EnvironmentManager:
    """
    Test environment manager.

    Features:
    - Environment lifecycle management
    - Resource allocation
    - Health monitoring
    - Multi-environment support
    """

    def __init__(
        self,
        max_environments: int = 5,
        default_timeout: int = 300,
    ):
        """Initialize the manager."""
        self._max_environments = max_environments
        self._default_timeout = default_timeout
        self._environments: Dict[str, Environment] = {}
        self._configs: Dict[str, EnvironmentConfig] = {}
        self._env_counter = 0
        self._config_counter = 0

        # Initialize built-in configs
        self._init_builtin_configs()

    def _init_builtin_configs(self):
        """Initialize built-in environment configs."""
        configs = [
            EnvironmentConfig(
                config_id="local-dev",
                name="Local Development",
                env_type=EnvironmentType.LOCAL,
                base_url="http://localhost:3000",
                api_url="http://localhost:8080/api",
                database_url="postgresql://localhost:5432/testdb",
                resources={"cpu": "2", "memory": "4Gi"},
                variables={"NODE_ENV": "development", "DEBUG": "true"},
            ),
            EnvironmentConfig(
                config_id="docker-test",
                name="Docker Test",
                env_type=EnvironmentType.DOCKER,
                base_url="http://app:3000",
                api_url="http://api:8080/api",
                database_url="postgresql://db:5432/testdb",
                resources={"cpu": "1", "memory": "2Gi"},
                variables={"NODE_ENV": "test"},
            ),
            EnvironmentConfig(
                config_id="k8s-staging",
                name="Kubernetes Staging",
                env_type=EnvironmentType.KUBERNETES,
                base_url="https://staging.example.com",
                api_url="https://api-staging.example.com",
                resources={"cpu": "4", "memory": "8Gi", "replicas": "2"},
                variables={"NODE_ENV": "staging"},
            ),
            EnvironmentConfig(
                config_id="cloud-prod",
                name="Cloud Production",
                env_type=EnvironmentType.CLOUD,
                base_url="https://app.example.com",
                api_url="https://api.example.com",
                resources={"cpu": "8", "memory": "16Gi", "replicas": "4"},
                variables={"NODE_ENV": "production"},
            ),
        ]

        for config in configs:
            self._configs[config.config_id] = config

    def create_config(
        self,
        name: str,
        env_type: EnvironmentType,
        base_url: Optional[str] = None,
        api_url: Optional[str] = None,
        database_url: Optional[str] = None,
        resources: Optional[Dict[str, Any]] = None,
        variables: Optional[Dict[str, str]] = None,
    ) -> EnvironmentConfig:
        """Create a new environment configuration."""
        self._config_counter += 1
        config_id = f"config-{self._config_counter:04d}"

        config = EnvironmentConfig(
            config_id=config_id,
            name=name,
            env_type=env_type,
            base_url=base_url,
            api_url=api_url,
            database_url=database_url,
            resources=resources or {},
            variables=variables or {},
        )

        self._configs[config_id] = config
        return config

    def get_config(self, config_id: str) -> Optional[EnvironmentConfig]:
        """Get a configuration by ID."""
        return self._configs.get(config_id)

    def list_configs(self) -> List[EnvironmentConfig]:
        """List all configurations."""
        return list(self._configs.values())

    def create(
        self,
        name: str,
        config_id: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Environment:
        """Create a new environment."""
        config = self._configs.get(config_id)
        if not config:
            raise ValueError(f"Unknown config: {config_id}")

        if len(self._environments) >= self._max_environments:
            raise RuntimeError(f"Maximum environments ({self._max_environments}) reached")

        self._env_counter += 1
        env_id = f"ENV-{self._env_counter:05d}"

        # Apply overrides to config
        if overrides:
            config = EnvironmentConfig(
                config_id=config.config_id,
                name=config.name,
                env_type=config.env_type,
                base_url=overrides.get("base_url", config.base_url),
                api_url=overrides.get("api_url", config.api_url),
                database_url=overrides.get("database_url", config.database_url),
                resources={**config.resources, **overrides.get("resources", {})},
                variables={**config.variables, **overrides.get("variables", {})},
            )

        env = Environment(
            env_id=env_id,
            name=name,
            config=config,
            status=EnvironmentStatus.PENDING,
            created_at=datetime.now(),
            endpoints={},
            health={"status": "unknown"},
        )

        self._environments[env_id] = env
        return env

    def start(self, env_id: str) -> Environment:
        """Start an environment."""
        env = self._environments.get(env_id)
        if not env:
            raise ValueError(f"Unknown environment: {env_id}")

        env.status = EnvironmentStatus.PROVISIONING
        # Simulate provisioning
        env.status = EnvironmentStatus.READY
        env.started_at = datetime.now()

        # Set up endpoints
        if env.config.base_url:
            env.endpoints["app"] = env.config.base_url
        if env.config.api_url:
            env.endpoints["api"] = env.config.api_url

        env.health = {
            "status": "healthy",
            "checked_at": datetime.now().isoformat(),
        }

        return env

    def stop(self, env_id: str) -> Environment:
        """Stop an environment."""
        env = self._environments.get(env_id)
        if not env:
            raise ValueError(f"Unknown environment: {env_id}")

        env.status = EnvironmentStatus.PAUSED
        return env

    def terminate(self, env_id: str) -> Environment:
        """Terminate an environment."""
        env = self._environments.get(env_id)
        if not env:
            raise ValueError(f"Unknown environment: {env_id}")

        env.status = EnvironmentStatus.TERMINATING
        # Simulate cleanup
        env.status = EnvironmentStatus.TERMINATED
        env.terminated_at = datetime.now()

        return env

    def get(self, env_id: str) -> Optional[Environment]:
        """Get an environment by ID."""
        return self._environments.get(env_id)

    def list(
        self,
        status: Optional[EnvironmentStatus] = None,
    ) -> List[Environment]:
        """List environments, optionally filtered by status."""
        envs = list(self._environments.values())

        if status:
            envs = [e for e in envs if e.status == status]

        return envs

    def check_health(self, env_id: str) -> Dict[str, Any]:
        """Check the health of an environment."""
        env = self._environments.get(env_id)
        if not env:
            return {"status": "unknown", "error": "Environment not found"}

        if env.status != EnvironmentStatus.READY:
            return {"status": "unavailable", "env_status": env.status.value}

        # Simulate health check
        env.health = {
            "status": "healthy",
            "checked_at": datetime.now().isoformat(),
            "endpoints": {k: "ok" for k in env.endpoints},
        }

        return env.health

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        status_counts = {s.value: 0 for s in EnvironmentStatus}
        type_counts: Dict[str, int] = {}

        for env in self._environments.values():
            status_counts[env.status.value] += 1
            env_type = env.config.env_type.value
            type_counts[env_type] = type_counts.get(env_type, 0) + 1

        return {
            "total_environments": len(self._environments),
            "total_configs": len(self._configs),
            "max_environments": self._max_environments,
            "environments_by_status": status_counts,
            "environments_by_type": type_counts,
        }

    def format_environment(self, env: Environment) -> str:
        """Format an environment for display."""
        status_icons = {
            EnvironmentStatus.PENDING: "⏳",
            EnvironmentStatus.PROVISIONING: "🔄",
            EnvironmentStatus.READY: "✅",
            EnvironmentStatus.RUNNING: "🏃",
            EnvironmentStatus.PAUSED: "⏸️",
            EnvironmentStatus.TERMINATING: "🛑",
            EnvironmentStatus.TERMINATED: "❌",
            EnvironmentStatus.ERROR: "⚠️",
        }

        icon = status_icons.get(env.status, "")

        lines = [
            "=" * 50,
            f"  ENVIRONMENT: {icon} {env.status.value.upper()}",
            "=" * 50,
            "",
            f"  ID: {env.env_id}",
            f"  Name: {env.name}",
            f"  Type: {env.config.env_type.value}",
            f"  Created: {env.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        if env.endpoints:
            lines.append("-" * 50)
            lines.append("  ENDPOINTS")
            lines.append("-" * 50)
            lines.append("")
            for name, url in env.endpoints.items():
                lines.append(f"  {name}: {url}")
            lines.append("")

        if env.config.variables:
            lines.append("-" * 50)
            lines.append("  VARIABLES")
            lines.append("-" * 50)
            lines.append("")
            for key, value in list(env.config.variables.items())[:5]:
                lines.append(f"  {key}={value}")
            lines.append("")

        lines.append("=" * 50)
        return "\n".join(lines)


def create_environment_manager(
    max_environments: int = 5,
    default_timeout: int = 300,
) -> EnvironmentManager:
    """Create an environment manager instance."""
    return EnvironmentManager(
        max_environments=max_environments,
        default_timeout=default_timeout,
    )
