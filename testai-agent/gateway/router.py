"""
TestAI Agent - Smart Model Router

Routes requests to the right model based on task type.
Optimizes for cost while maintaining quality.

Routing Strategy:
- Simple classification → DeepSeek Chat (cheap)
- Test generation → DeepSeek Chat (good enough)
- Complex analysis → DeepSeek Reasoner (when needed)
- Code generation → DeepSeek Coder (specialized)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

from .base import (
    LLMProvider,
    LLMResponse,
    Message,
    ModelCapability,
    ProviderConfig,
)
from .deepseek import DeepSeekProvider


class TaskType(Enum):
    """Types of tasks the QA agent performs."""
    CLASSIFY_PAGE = "classify_page"           # Quick: What type of page is this?
    IDENTIFY_ELEMENTS = "identify_elements"   # Quick: Find testable elements
    GENERATE_TESTS = "generate_tests"         # Medium: Create test cases
    ANALYZE_SECURITY = "analyze_security"     # Deep: Security vulnerabilities
    ANALYZE_EDGE_CASES = "analyze_edge_cases" # Deep: Edge case detection
    GENERATE_CODE = "generate_code"           # Code: Playwright scripts
    EXPLAIN_FAILURE = "explain_failure"       # Medium: Why did test fail?
    SUGGEST_FIX = "suggest_fix"               # Medium: How to fix issue?
    CONVERSATION = "conversation"             # Light: Chat with user


@dataclass
class TaskConfig:
    """Configuration for a specific task type."""
    model: str
    temperature: float
    max_tokens: int
    priority: int = 1  # 1=low cost, 3=high quality


# Task routing configuration
TASK_CONFIGS: Dict[TaskType, TaskConfig] = {
    # Quick tasks - use cheap fast model
    TaskType.CLASSIFY_PAGE: TaskConfig(
        model="deepseek-chat",
        temperature=0.3,  # Low creativity for consistency
        max_tokens=256,
        priority=1,
    ),
    TaskType.IDENTIFY_ELEMENTS: TaskConfig(
        model="deepseek-chat",
        temperature=0.3,
        max_tokens=1024,
        priority=1,
    ),
    TaskType.CONVERSATION: TaskConfig(
        model="deepseek-chat",
        temperature=0.7,
        max_tokens=512,
        priority=1,
    ),

    # Medium tasks - balanced
    TaskType.GENERATE_TESTS: TaskConfig(
        model="deepseek-chat",
        temperature=0.6,
        max_tokens=4096,
        priority=2,
    ),
    TaskType.EXPLAIN_FAILURE: TaskConfig(
        model="deepseek-chat",
        temperature=0.5,
        max_tokens=1024,
        priority=2,
    ),
    TaskType.SUGGEST_FIX: TaskConfig(
        model="deepseek-chat",
        temperature=0.6,
        max_tokens=2048,
        priority=2,
    ),

    # Deep analysis - use reasoner for complex thinking
    TaskType.ANALYZE_SECURITY: TaskConfig(
        model="deepseek-chat",  # Reasoner is expensive, use chat for now
        temperature=0.4,
        max_tokens=4096,
        priority=3,
    ),
    TaskType.ANALYZE_EDGE_CASES: TaskConfig(
        model="deepseek-chat",
        temperature=0.5,
        max_tokens=4096,
        priority=3,
    ),

    # Code generation - specialized model
    TaskType.GENERATE_CODE: TaskConfig(
        model="deepseek-coder",
        temperature=0.3,  # Low for reliable code
        max_tokens=4096,
        priority=2,
    ),
}


@dataclass
class RouterStats:
    """Track router usage for monitoring."""
    total_requests: int = 0
    requests_by_task: Dict[str, int] = field(default_factory=dict)
    total_tokens: int = 0
    total_cost: float = 0.0
    errors: int = 0

    def record(self, task: TaskType, response: LLMResponse):
        """Record a completed request."""
        self.total_requests += 1
        task_name = task.value
        self.requests_by_task[task_name] = self.requests_by_task.get(task_name, 0) + 1
        self.total_tokens += response.tokens_used
        self.total_cost += response.cost_estimate
        if response.finish_reason == "error":
            self.errors += 1

    def summarize(self) -> str:
        """Human-friendly summary."""
        return (
            f"Router Stats: {self.total_requests} requests, "
            f"{self.total_tokens} tokens, ${self.total_cost:.4f} total cost, "
            f"{self.errors} errors"
        )


class ModelRouter:
    """
    Smart router that picks the right model for each task.

    Usage:
        router = ModelRouter(api_key="sk-xxx")

        # Route based on task type
        response = await router.route(
            TaskType.GENERATE_TESTS,
            prompt="Generate tests for login page",
            system="You are a QA expert..."
        )
    """

    def __init__(
        self,
        api_key: str,
        default_model: str = "deepseek-chat",
        budget_limit: Optional[float] = None,
    ):
        """
        Initialize the router.

        Args:
            api_key: DeepSeek API key
            default_model: Fallback model
            budget_limit: Max spend in USD (None = unlimited)
        """
        self.api_key = api_key
        self.default_model = default_model
        self.budget_limit = budget_limit
        self.stats = RouterStats()

        # Provider cache - create on demand
        self._providers: Dict[str, DeepSeekProvider] = {}

    def _get_provider(self, model: str) -> DeepSeekProvider:
        """Get or create a provider for the specified model."""
        if model not in self._providers:
            config = ProviderConfig(
                api_key=self.api_key,
                default_model=model,
            )
            self._providers[model] = DeepSeekProvider(config)
        return self._providers[model]

    async def route(
        self,
        task: TaskType,
        prompt: str,
        system: Optional[str] = None,
        context: Optional[str] = None,
        override_model: Optional[str] = None,
    ) -> LLMResponse:
        """
        Route a request to the appropriate model.

        Args:
            task: Type of task to perform
            prompt: The user's request
            system: System prompt (optional)
            context: Additional context to prepend (optional)
            override_model: Force a specific model (optional)

        Returns:
            LLMResponse from the selected model
        """
        # Check budget
        if self.budget_limit and self.stats.total_cost >= self.budget_limit:
            return LLMResponse(
                content="Budget limit reached. Please add more credits.",
                model="none",
                provider="router",
                finish_reason="budget_exceeded",
            )

        # Get task config
        config = TASK_CONFIGS.get(task, TASK_CONFIGS[TaskType.CONVERSATION])

        # Select model
        model = override_model or config.model

        # Get provider
        provider = self._get_provider(model)

        # Build full prompt with context
        full_prompt = prompt
        if context:
            full_prompt = f"{context}\n\n{prompt}"

        # Make the request
        response = await provider.complete(
            prompt=full_prompt,
            system=system,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )

        # Record stats
        self.stats.record(task, response)

        return response

    async def chat(
        self,
        task: TaskType,
        messages: List[Message],
        override_model: Optional[str] = None,
    ) -> LLMResponse:
        """
        Multi-turn conversation with routing.

        Args:
            task: Type of task
            messages: Conversation history
            override_model: Force a specific model

        Returns:
            LLMResponse with assistant's reply
        """
        # Check budget
        if self.budget_limit and self.stats.total_cost >= self.budget_limit:
            return LLMResponse(
                content="Budget limit reached.",
                model="none",
                provider="router",
                finish_reason="budget_exceeded",
            )

        config = TASK_CONFIGS.get(task, TASK_CONFIGS[TaskType.CONVERSATION])
        model = override_model or config.model
        provider = self._get_provider(model)

        response = await provider.chat(
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )

        self.stats.record(task, response)
        return response

    def get_recommended_model(self, task: TaskType) -> str:
        """Get the recommended model for a task type."""
        config = TASK_CONFIGS.get(task)
        return config.model if config else self.default_model

    def get_stats(self) -> RouterStats:
        """Get usage statistics."""
        return self.stats

    def get_status(self) -> Dict[str, Any]:
        """Get router status."""
        return {
            "active_providers": list(self._providers.keys()),
            "default_model": self.default_model,
            "budget_limit": self.budget_limit,
            "budget_used": self.stats.total_cost,
            "total_requests": self.stats.total_requests,
            "ready": bool(self.api_key),
        }


def create_router(
    api_key: str,
    budget_limit: float = 1.0,  # $1 default budget
) -> ModelRouter:
    """
    Create a configured model router.

    Args:
        api_key: DeepSeek API key
        budget_limit: Max spend in USD

    Returns:
        Configured ModelRouter
    """
    return ModelRouter(
        api_key=api_key,
        budget_limit=budget_limit,
    )
