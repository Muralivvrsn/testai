"""
TestAI Agent - Main Agent Interface

The intelligent QA agent that beats humans at testing.
Combines brain (knowledge), cortex (decisions), gateway (LLM), and personality (UX).

Usage:
    from agent import TestAIAgent

    agent = TestAIAgent(api_key="sk-xxx")

    # Load knowledge (once)
    await agent.load_brain("./QA_BRAIN.md")

    # Generate tests
    result = await agent.generate_tests(
        url="https://example.com/login",
        feature="User Login"
    )

    print(result)
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import our modules
from brain.vector_store import QABrain, create_brain
from gateway.router import ModelRouter, TaskType, create_router
from cortex.decision_engine import DecisionEngine, DecisionContext
from cortex.confidence import ConfidenceScorer
from personality.tone import ResponseStyler, Confidence
from personality.clarifier import Clarifier
from personality.celebrator import Celebrator
from generators.test_generator import TestGenerator, TestSuite, GenerationResult


@dataclass
class AgentConfig:
    """Configuration for the TestAI Agent."""
    api_key: str
    brain_path: str = "./.brain_data"
    budget_limit: float = 1.0  # USD
    confidence_threshold: float = 0.70
    max_clarifications: int = 3
    verbose: bool = False


@dataclass
class AgentStatus:
    """Current status of the agent."""
    brain_ready: bool = False
    brain_chunks: int = 0
    gateway_ready: bool = False
    budget_used: float = 0.0
    budget_remaining: float = 0.0
    requests_made: int = 0

    def summarize(self) -> str:
        status = "ready" if self.brain_ready and self.gateway_ready else "not ready"
        return (
            f"Agent Status: {status}\n"
            f"  Brain: {self.brain_chunks} knowledge chunks\n"
            f"  Budget: ${self.budget_used:.4f} used, ${self.budget_remaining:.4f} remaining\n"
            f"  Requests: {self.requests_made}"
        )


class TestAIAgent:
    """
    The intelligent QA agent.

    This is the main interface. It:
    - Loads and queries the knowledge brain
    - Makes intelligent decisions via cortex
    - Generates tests via LLM
    - Responds with human-like personality
    """

    def __init__(self, config: AgentConfig):
        """
        Initialize the agent.

        Args:
            config: Agent configuration
        """
        self.config = config

        # Initialize components
        self.brain = create_brain(config.brain_path)
        self.router = create_router(
            api_key=config.api_key,
            budget_limit=config.budget_limit,
        )
        self.cortex = DecisionEngine(
            confidence_threshold=config.confidence_threshold,
        )
        self.confidence_scorer = ConfidenceScorer(config.confidence_threshold)

        # Personality components
        self.styler = ResponseStyler(verbose=config.verbose)
        self.clarifier = Clarifier(max_questions=config.max_clarifications)
        self.celebrator = Celebrator(enthusiasm_level=1)

        # Test generator
        self.generator = TestGenerator(
            brain=self.brain,
            router=self.router,
        )

        # State
        self._last_decision = None
        self._conversation_history = []

    async def load_brain(
        self,
        qa_brain_path: str = "./QA_BRAIN.md",
        force_reload: bool = False,
    ) -> Dict[str, Any]:
        """
        Load the QA knowledge brain.

        Args:
            qa_brain_path: Path to QA_BRAIN.md
            force_reload: Force re-ingestion

        Returns:
            Status of the load operation
        """
        result = self.brain.ingest_knowledge(qa_brain_path, force_reload)

        if result.get("status") == "success":
            message = self.celebrator.milestone(
                "Knowledge loaded",
                progress=1.0,
            )
            result["message"] = message

        return result

    async def analyze_page(
        self,
        url: str,
        elements: List[Dict[str, Any]],
        page_title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a page and classify it.

        Args:
            url: Page URL
            elements: Extracted page elements
            page_title: Page title if available

        Returns:
            Analysis result with page type and confidence
        """
        # Build context
        context = DecisionContext(
            page_url=url,
            page_elements=elements,
        )

        # Query brain for relevant knowledge
        query = f"Testing rules for page with elements: {self._summarize_elements(elements)}"
        if page_title:
            query += f" title: {page_title}"

        knowledge = self.brain.search(query, limit=5) if self.brain.is_ready else None

        if knowledge:
            context.knowledge_chunks = knowledge.chunks
            context.knowledge_confidence = knowledge.confidence

        # Make decision
        decision = await self.cortex.decide(context)
        self._last_decision = decision

        # Detect page type from elements
        page_type = self._detect_page_type(elements, url)

        # Style the response
        response = self.styler.classify_page(
            page_type=page_type,
            confidence=Confidence.CONFIDENT if decision.confidence.can_proceed else Confidence.UNCERTAIN,
            elements_found=len(elements),
        )

        return {
            "page_type": page_type,
            "confidence": decision.confidence.score,
            "elements_found": len(elements),
            "response": str(response),
            "decision": decision,
        }

    async def generate_tests(
        self,
        feature: str,
        page_type: Optional[str] = None,
        elements: Optional[List[Dict]] = None,
        url: Optional[str] = None,
        context: Optional[str] = None,
    ) -> GenerationResult:
        """
        Generate comprehensive tests for a feature.

        Args:
            feature: Feature name (e.g., "User Login")
            page_type: Page type (auto-detected if not provided)
            elements: Page elements
            url: Page URL
            context: Additional context

        Returns:
            GenerationResult with test suite
        """
        # Auto-detect page type if not provided
        if not page_type and elements:
            page_type = self._detect_page_type(elements, url)
        elif not page_type:
            page_type = "form"  # Default

        # Generate tests
        result = await self.generator.generate(
            feature=feature,
            page_type=page_type,
            elements=elements,
            context=context,
        )

        # Add celebration
        if len(result.suite.tests) > 0:
            celebration = self.celebrator.summary(
                bugs_found=0,  # Not running tests yet
                tests_generated=len(result.suite.tests),
                critical_issues=len(result.suite.get_by_priority(
                    __import__("generators.test_generator", fromlist=["Priority"]).Priority.CRITICAL
                )),
            )
            result.warnings.insert(0, celebration)

        return result

    async def get_clarification(
        self,
        page_type: str,
        elements: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Get clarification questions for a page.

        Args:
            page_type: Type of page
            elements: Page elements

        Returns:
            Clarification bundle
        """
        element_names = [e.get("name", e.get("id", "")) for e in (elements or [])]

        bundle = self.clarifier.for_page_type(
            page_type=page_type,
            found_elements=element_names,
        )

        return {
            "title": bundle.title,
            "questions": [str(q) for q in bundle.questions],
            "required": bundle.required_before_proceed,
        }

    def get_status(self) -> AgentStatus:
        """Get current agent status."""
        router_status = self.router.get_status()
        brain_status = self.brain.get_status()

        return AgentStatus(
            brain_ready=brain_status["ready"],
            brain_chunks=brain_status["knowledge_chunks"],
            gateway_ready=router_status["ready"],
            budget_used=router_status["budget_used"],
            budget_remaining=self.config.budget_limit - router_status["budget_used"],
            requests_made=router_status["total_requests"],
        )

    def _summarize_elements(self, elements: List[Dict]) -> str:
        """Summarize elements for queries."""
        types = {}
        for el in elements:
            t = el.get("elementType", el.get("type", el.get("tag", "unknown")))
            types[t] = types.get(t, 0) + 1

        return ", ".join(f"{t}({c})" for t, c in types.items())

    def _detect_page_type(
        self,
        elements: List[Dict],
        url: Optional[str] = None,
    ) -> str:
        """Detect page type from elements and URL."""
        # Check URL patterns
        if url:
            url_lower = url.lower()
            if "login" in url_lower or "signin" in url_lower:
                return "login"
            if "signup" in url_lower or "register" in url_lower:
                return "signup"
            if "checkout" in url_lower or "cart" in url_lower:
                return "checkout"
            if "search" in url_lower:
                return "search"
            if "settings" in url_lower:
                return "settings"
            if "admin" in url_lower:
                return "admin"

        # Check element patterns
        element_texts = []
        for el in elements:
            element_texts.append(el.get("name", "").lower())
            element_texts.append(el.get("text", "").lower())
            element_texts.append(el.get("placeholder", "").lower())

        combined = " ".join(element_texts)

        if "password" in combined and ("login" in combined or "email" in combined):
            return "login"
        if "password" in combined and ("confirm" in combined or "register" in combined):
            return "signup"
        if "card" in combined or "payment" in combined:
            return "checkout"
        if "search" in combined:
            return "search"

        return "form"


def create_agent(
    api_key: str,
    brain_path: str = "./.brain_data",
    budget_limit: float = 1.0,
) -> TestAIAgent:
    """
    Create a TestAI Agent.

    Args:
        api_key: DeepSeek API key
        brain_path: Path to brain storage
        budget_limit: Max spend in USD

    Returns:
        Configured TestAIAgent
    """
    config = AgentConfig(
        api_key=api_key,
        brain_path=brain_path,
        budget_limit=budget_limit,
    )
    return TestAIAgent(config)


# Quick usage example
async def demo():
    """Demo the agent (don't run - saves API calls!)."""
    print("TestAI Agent Demo")
    print("=" * 50)

    # This would be the real usage:
    # agent = create_agent(api_key="sk-xxx")
    # await agent.load_brain("./QA_BRAIN.md")
    # result = await agent.generate_tests(
    #     feature="User Login",
    #     page_type="login",
    #     elements=[{"type": "input", "name": "email"}, ...]
    # )
    # print(result.suite.summarize())

    print("Agent is ready! See agent.py for usage examples.")


if __name__ == "__main__":
    asyncio.run(demo())
