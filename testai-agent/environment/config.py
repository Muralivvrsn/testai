"""
TestAI Agent - Configuration Manager

Environment configuration management with
multiple sources and profile support.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import copy


class ConfigSource(Enum):
    """Sources for configuration values."""
    DEFAULT = "default"
    FILE = "file"
    ENVIRONMENT = "environment"
    CLI = "cli"
    RUNTIME = "runtime"
    REMOTE = "remote"


class ConfigPriority(Enum):
    """Priority levels for configuration sources."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    OVERRIDE = 4


@dataclass
class ConfigValue:
    """A configuration value with metadata."""
    key: str
    value: Any
    source: ConfigSource
    priority: ConfigPriority
    set_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfigProfile:
    """A configuration profile."""
    profile_id: str
    name: str
    description: str
    values: Dict[str, ConfigValue]
    parent_profile: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """
    Configuration manager.

    Features:
    - Multiple configuration sources
    - Profile inheritance
    - Value interpolation
    - Change tracking
    """

    def __init__(self):
        """Initialize the config manager."""
        self._profiles: Dict[str, ConfigProfile] = {}
        self._active_profile: Optional[str] = None
        self._values: Dict[str, ConfigValue] = {}
        self._history: List[Dict[str, Any]] = []
        self._profile_counter = 0

        # Initialize default profile
        self._init_default_profile()

    def _init_default_profile(self):
        """Initialize the default configuration profile."""
        default_values = {
            # Test execution
            "test.timeout": 30000,
            "test.retries": 2,
            "test.parallel": True,
            "test.workers": 4,

            # Browser settings
            "browser.headless": True,
            "browser.viewport.width": 1920,
            "browser.viewport.height": 1080,
            "browser.slowMo": 0,

            # Reporting
            "report.format": "html",
            "report.screenshots": True,
            "report.videos": False,
            "report.outputDir": "./reports",

            # API settings
            "api.baseUrl": "http://localhost:8080",
            "api.timeout": 10000,

            # Database
            "db.host": "localhost",
            "db.port": 5432,
            "db.name": "testdb",

            # Logging
            "log.level": "info",
            "log.format": "json",
        }

        profile = ConfigProfile(
            profile_id="default",
            name="Default",
            description="Default configuration profile",
            values={
                k: ConfigValue(
                    key=k,
                    value=v,
                    source=ConfigSource.DEFAULT,
                    priority=ConfigPriority.LOW,
                    set_at=datetime.now(),
                )
                for k, v in default_values.items()
            },
        )

        self._profiles["default"] = profile
        self._active_profile = "default"
        self._values = copy.deepcopy(profile.values)

    def create_profile(
        self,
        name: str,
        description: str = "",
        parent: Optional[str] = None,
        values: Optional[Dict[str, Any]] = None,
    ) -> ConfigProfile:
        """Create a new configuration profile."""
        self._profile_counter += 1
        profile_id = f"profile-{self._profile_counter:04d}"

        # Start with parent's values if specified
        profile_values: Dict[str, ConfigValue] = {}

        if parent and parent in self._profiles:
            parent_profile = self._profiles[parent]
            profile_values = copy.deepcopy(parent_profile.values)

        # Apply new values
        if values:
            for key, value in values.items():
                profile_values[key] = ConfigValue(
                    key=key,
                    value=value,
                    source=ConfigSource.DEFAULT,
                    priority=ConfigPriority.MEDIUM,
                    set_at=datetime.now(),
                )

        profile = ConfigProfile(
            profile_id=profile_id,
            name=name,
            description=description,
            values=profile_values,
            parent_profile=parent,
        )

        self._profiles[profile_id] = profile
        return profile

    def activate_profile(self, profile_id: str) -> bool:
        """Activate a configuration profile."""
        if profile_id not in self._profiles:
            return False

        profile = self._profiles[profile_id]
        self._active_profile = profile_id
        self._values = copy.deepcopy(profile.values)

        self._history.append({
            "action": "activate_profile",
            "profile": profile_id,
            "timestamp": datetime.now().isoformat(),
        })

        return True

    def get(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """Get a configuration value."""
        if key in self._values:
            return self._values[key].value
        return default

    def set(
        self,
        key: str,
        value: Any,
        source: ConfigSource = ConfigSource.RUNTIME,
        priority: ConfigPriority = ConfigPriority.HIGH,
    ) -> ConfigValue:
        """Set a configuration value."""
        config_value = ConfigValue(
            key=key,
            value=value,
            source=source,
            priority=priority,
            set_at=datetime.now(),
        )

        # Only override if priority is high enough
        existing = self._values.get(key)
        if existing and existing.priority.value > priority.value:
            return existing

        self._values[key] = config_value

        self._history.append({
            "action": "set",
            "key": key,
            "value": value,
            "source": source.value,
            "timestamp": datetime.now().isoformat(),
        })

        return config_value

    def unset(self, key: str) -> bool:
        """Remove a configuration value."""
        if key in self._values:
            del self._values[key]
            self._history.append({
                "action": "unset",
                "key": key,
                "timestamp": datetime.now().isoformat(),
            })
            return True
        return False

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return {k: v.value for k, v in self._values.items()}

    def get_by_prefix(self, prefix: str) -> Dict[str, Any]:
        """Get configuration values by key prefix."""
        return {
            k: v.value
            for k, v in self._values.items()
            if k.startswith(prefix)
        }

    def merge(
        self,
        values: Dict[str, Any],
        source: ConfigSource = ConfigSource.RUNTIME,
    ):
        """Merge multiple configuration values."""
        for key, value in values.items():
            self.set(key, value, source=source)

    def load_from_dict(
        self,
        config: Dict[str, Any],
        prefix: str = "",
        source: ConfigSource = ConfigSource.FILE,
    ):
        """Load configuration from a dictionary (potentially nested)."""
        def flatten(d: Dict[str, Any], parent_key: str = "") -> Dict[str, Any]:
            items: List[tuple] = []
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten(v, new_key).items())
                else:
                    items.append((new_key, v))
            return dict(items)

        flat = flatten(config, prefix)
        for key, value in flat.items():
            self.set(key, value, source=source)

    def get_profile(self, profile_id: str) -> Optional[ConfigProfile]:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def list_profiles(self) -> List[ConfigProfile]:
        """List all profiles."""
        return list(self._profiles.values())

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get configuration change history."""
        return self._history[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get config manager statistics."""
        source_counts: Dict[str, int] = {}
        for value in self._values.values():
            source_counts[value.source.value] = source_counts.get(value.source.value, 0) + 1

        return {
            "total_profiles": len(self._profiles),
            "active_profile": self._active_profile,
            "total_values": len(self._values),
            "values_by_source": source_counts,
            "history_entries": len(self._history),
        }

    def format_profile(self, profile: ConfigProfile) -> str:
        """Format a profile for display."""
        lines = [
            "=" * 50,
            f"  CONFIG PROFILE: {profile.name}",
            "=" * 50,
            "",
            f"  ID: {profile.profile_id}",
            f"  Description: {profile.description or 'N/A'}",
            f"  Parent: {profile.parent_profile or 'None'}",
            f"  Values: {len(profile.values)}",
            "",
            "-" * 50,
            "  VALUES (sample)",
            "-" * 50,
            "",
        ]

        for key, value in list(profile.values.items())[:10]:
            lines.append(f"  {key} = {value.value}")

        if len(profile.values) > 10:
            lines.append(f"  ... and {len(profile.values) - 10} more")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_config_manager() -> ConfigManager:
    """Create a config manager instance."""
    return ConfigManager()
