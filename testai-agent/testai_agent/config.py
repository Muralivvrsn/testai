"""
TestAI Agent - Configuration System

Centralized configuration management with:
- Environment variable support
- Default fallbacks
- Validation
- Runtime overrides

Usage:
    from testai_agent.config import Config
    
    config = Config()
    print(config.deepseek_api_key)
    
    # Override at runtime
    config = Config(deepseek_max_calls=20)
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import json


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    api_key: Optional[str] = None
    model: str = "deepseek-chat"
    max_calls: int = 10
    timeout: int = 120  # seconds
    temperature: float = 0.7
    max_tokens: int = 4096
    retry_attempts: int = 3
    retry_delay: float = 2.0  # seconds between retries


@dataclass
class BrainConfig:
    """Brain/RAG configuration."""
    persist_directory: str = ".brain_data"
    collection_name: str = "qa_brain_v2"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    embedding_model: str = "default"


@dataclass
class UIConfig:
    """User interface configuration."""
    show_thinking: bool = True
    show_citations: bool = True
    color_output: bool = True
    verbose: bool = False


@dataclass
class Config:
    """
    Main configuration class for TestAI Agent.
    
    Loads from:
    1. Environment variables (highest priority)
    2. .env file
    3. config.json file
    4. Default values (lowest priority)
    """
    
    # LLM Providers
    deepseek: LLMConfig = field(default_factory=lambda: LLMConfig())
    openai: LLMConfig = field(default_factory=lambda: LLMConfig(
        model="gpt-3.5-turbo",
        max_calls=50
    ))
    anthropic: LLMConfig = field(default_factory=lambda: LLMConfig(
        model="claude-3-sonnet-20240229",
        max_calls=50
    ))
    
    # Brain
    brain: BrainConfig = field(default_factory=BrainConfig)
    
    # UI
    ui: UIConfig = field(default_factory=UIConfig)
    
    # Paths
    brain_knowledge_path: str = "QA_BRAIN.md"
    session_storage_path: str = ".session"
    log_path: str = ".logs"
    
    # Debug
    debug: bool = False
    
    def __post_init__(self):
        """Load configuration from environment and files."""
        self._load_from_env()
        self._load_from_dotenv()
        self._load_from_json()
        self._validate()
        
    def _load_from_env(self):
        """Load from environment variables."""
        # DeepSeek
        if key := os.getenv("DEEPSEEK_API_KEY"):
            self.deepseek.api_key = key
        if val := os.getenv("DEEPSEEK_MAX_CALLS"):
            self.deepseek.max_calls = int(val)
        if val := os.getenv("DEEPSEEK_TIMEOUT"):
            self.deepseek.timeout = int(val)
            
        # OpenAI
        if key := os.getenv("OPENAI_API_KEY"):
            self.openai.api_key = key
            
        # Anthropic
        if key := os.getenv("ANTHROPIC_API_KEY"):
            self.anthropic.api_key = key
            
        # General
        if val := os.getenv("TESTAI_DEBUG"):
            self.debug = val.lower() in ("true", "1", "yes")
        if val := os.getenv("BRAIN_PATH"):
            self.brain_knowledge_path = val
            
    def _load_from_dotenv(self):
        """Load from .env file if it exists."""
        env_path = Path(".env")
        if not env_path.exists():
            return
            
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        # Only set if not already in environment
                        if key not in os.environ:
                            os.environ[key] = value
                            
            # Re-load from env
            self._load_from_env()
        except Exception:
            pass
            
    def _load_from_json(self):
        """Load from config.json if it exists."""
        config_path = Path("config.json")
        if not config_path.exists():
            return
            
        try:
            with open(config_path) as f:
                data = json.load(f)
                
            # Apply JSON config
            if "deepseek" in data:
                for key, val in data["deepseek"].items():
                    if hasattr(self.deepseek, key):
                        setattr(self.deepseek, key, val)
                        
            if "brain" in data:
                for key, val in data["brain"].items():
                    if hasattr(self.brain, key):
                        setattr(self.brain, key, val)
                        
            if "ui" in data:
                for key, val in data["ui"].items():
                    if hasattr(self.ui, key):
                        setattr(self.ui, key, val)
        except Exception:
            pass
            
    def _validate(self):
        """Validate configuration."""
        # Check for required API keys
        if not any([
            self.deepseek.api_key,
            self.openai.api_key,
            self.anthropic.api_key
        ]):
            # Use default DeepSeek key if none provided
            self.deepseek.api_key = "sk-c104455631bb433b801fc4a16042419c"
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (hides API keys)."""
        return {
            "deepseek": {
                "api_key": "***" if self.deepseek.api_key else None,
                "model": self.deepseek.model,
                "max_calls": self.deepseek.max_calls,
                "timeout": self.deepseek.timeout,
            },
            "openai": {
                "api_key": "***" if self.openai.api_key else None,
                "model": self.openai.model,
            },
            "anthropic": {
                "api_key": "***" if self.anthropic.api_key else None,
                "model": self.anthropic.model,
            },
            "brain": {
                "persist_directory": self.brain.persist_directory,
                "collection_name": self.brain.collection_name,
            },
            "ui": {
                "show_thinking": self.ui.show_thinking,
                "color_output": self.ui.color_output,
            },
            "debug": self.debug,
        }
        
    def save_to_json(self, path: str = "config.json"):
        """Save configuration to JSON file."""
        data = self.to_dict()
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def reset_config():
    """Reset the global configuration."""
    global _config
    _config = None
