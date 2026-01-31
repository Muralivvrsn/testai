"""
TestAI Agent - Citation-Aware Reasoning Engine

The Cortex's reasoning layer that:
1. Queries the Brain for relevant knowledge
2. Tracks citations for zero-hallucination
3. Uses the Gateway for LLM calls (with limits)
4. Generates test plans with full traceability

Design Philosophy:
- Every claim must be backed by a source
- Never hallucinate - cite or admit uncertainty
- Show your work (visible reasoning)
- Be humble about confidence

Zero-Hallucination Approach:
- All knowledge comes from Brain (ChromaDB)
- Every Brain chunk has a citation (section, tags)
- LLM augments but doesn't invent facts
- Output always includes "Source: X" references
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import asyncio
import os
import sys

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.vector_store import QABrain, SearchResult, KnowledgeChunk
from connectors.llm_gateway import LLMGateway, GatewayResponse, Citation, create_gateway
from cortex.confidence import ConfidenceScorer, ConfidenceResult, ConfidenceLevel
from cortex.decision_engine import DecisionEngine, DecisionContext, Decision, ActionType


class ReasoningPhase(Enum):
    """Phases of the reasoning process."""
    UNDERSTANDING = "understanding"  # Parse what user wants
    RETRIEVING = "retrieving"        # Query Brain for knowledge
    PLANNING = "planning"            # Plan the approach
    GENERATING = "generating"        # Generate tests/analysis
    VALIDATING = "validating"        # Check results
    EXPLAINING = "explaining"        # Format output


@dataclass
class RetrievedKnowledge:
    """Knowledge retrieved from Brain with citations."""
    chunks: List[SearchResult]
    citations: List[Citation]
    total_relevance: float
    topics_covered: List[str]

    @property
    def has_knowledge(self) -> bool:
        return len(self.chunks) > 0

    @property
    def best_match(self) -> Optional[SearchResult]:
        return self.chunks[0] if self.chunks else None

    def format_for_prompt(self, max_chunks: int = 5) -> str:
        """Format knowledge for LLM prompt."""
        if not self.chunks:
            return "No specific knowledge found. Use general QA principles."

        lines = ["## Relevant Knowledge from QA Brain:\n"]
        for i, result in enumerate(self.chunks[:max_chunks], 1):
            chunk = result.chunk
            lines.append(f"### [{i}] {chunk.section}")
            lines.append(f"Tags: {', '.join(chunk.tags)}")
            lines.append(f"Relevance: {result.confidence:.0%}")
            lines.append(f"Content:\n{chunk.content[:500]}...")
            lines.append("")

        return "\n".join(lines)


@dataclass
class ReasoningResult:
    """Result of reasoning with full traceability."""
    phase: ReasoningPhase
    thinking: str              # Visible reasoning
    output: str               # The actual result
    citations: List[Citation]  # Sources used
    confidence: ConfidenceResult
    llm_response: Optional[GatewayResponse] = None
    knowledge_used: Optional[RetrievedKnowledge] = None

    @property
    def is_confident(self) -> bool:
        return self.confidence.can_proceed

    def format_with_sources(self) -> str:
        """Format output with sources appended."""
        result = self.output
        if self.citations:
            result += "\n\n---\n📚 **Sources:**\n"
            for i, citation in enumerate(self.citations, 1):
                conf_pct = int(citation.confidence * 100)
                result += f"  {i}. {citation.source} ({conf_pct}% match)\n"
                if citation.excerpt:
                    result += f"     > \"{citation.excerpt[:100]}...\"\n"
        return result


class Reasoner:
    """
    Citation-aware reasoning engine.

    Combines:
    - Brain (knowledge retrieval)
    - Gateway (LLM calls)
    - Decision Engine (confidence/actions)

    Usage:
        reasoner = Reasoner()

        # Reason about a feature
        result = await reasoner.reason_about_feature(
            feature="login page",
            user_request="Generate comprehensive tests"
        )

        print(result.format_with_sources())
    """

    # Expert QA prompts for different tasks
    PROMPTS = {
        "test_generation": '''You are Maya, a 12-year QA veteran. Generate test cases for this feature.

{knowledge}

FEATURE: {feature}
USER REQUEST: {request}
PAGE TYPE: {page_type}

Generate 5-7 specific, actionable test cases. For each test:
1. Clear title
2. Specific steps (not vague like "enter valid email" but "enter maya.test@company.com")
3. Expected result
4. Priority (Critical/High/Medium/Low)
5. Risk category (Security/Data/UX/Functionality)

Focus on edge cases and scenarios humans often miss.
Format as structured test cases.''',

        "security_analysis": '''You are a security-focused QA expert. Analyze this feature for vulnerabilities.

{knowledge}

FEATURE: {feature}
PAGE TYPE: {page_type}
ELEMENTS: {elements}

Identify:
1. Potential security vulnerabilities (OWASP Top 10)
2. Input validation gaps
3. Authentication/authorization issues
4. Data exposure risks

Be specific about attack vectors and mitigation.''',

        "edge_case_detection": '''You are an edge case specialist. Find edge cases for this feature.

{knowledge}

FEATURE: {feature}
PAGE TYPE: {page_type}

Identify edge cases for:
1. Boundary values
2. Empty/null states
3. Concurrency issues
4. Error handling gaps
5. Browser/device variations
6. Network conditions

Be specific and actionable.''',

        "clarification": '''Based on the context, what clarifying questions should we ask?

FEATURE: {feature}
USER REQUEST: {request}
KNOWLEDGE GAPS: {gaps}

Generate 2-3 specific, helpful clarifying questions.
Focus on information that would significantly improve test coverage.'''
    }

    def __init__(
        self,
        brain: Optional[QABrain] = None,
        gateway: Optional[LLMGateway] = None,
        confidence_threshold: float = 0.70,
    ):
        """
        Initialize the reasoner.

        Args:
            brain: QA Brain for knowledge retrieval (creates default if None)
            gateway: LLM Gateway (creates default if None)
            confidence_threshold: Minimum confidence to proceed
        """
        self.brain = brain
        self.gateway = gateway or create_gateway()
        self.decision_engine = DecisionEngine(confidence_threshold=confidence_threshold)
        self.scorer = ConfidenceScorer(default_threshold=confidence_threshold)

        # Lazy load brain
        self._brain_loaded = False

    def _ensure_brain(self) -> QABrain:
        """Ensure brain is loaded."""
        if self.brain is None:
            self.brain = QABrain()
            self._brain_loaded = True
        return self.brain

    async def retrieve_knowledge(
        self,
        query: str,
        page_type: Optional[str] = None,
        n_results: int = 5,
    ) -> RetrievedKnowledge:
        """
        Retrieve relevant knowledge from Brain.

        Args:
            query: Search query
            page_type: Optional page type filter
            n_results: Number of results to retrieve

        Returns:
            RetrievedKnowledge with chunks and citations
        """
        brain = self._ensure_brain()

        # Search brain
        if page_type:
            results = brain.get_for_page_type(page_type, n_results=n_results)
        else:
            results = brain.search(query, n_results=n_results)

        # Build citations
        citations = []
        topics = set()
        total_relevance = 0.0

        for result in results:
            chunk = result.chunk
            citations.append(Citation(
                source=f"Brain: {chunk.section}",
                chunk_id=result.id,
                confidence=result.confidence,
                excerpt=chunk.content[:150] if chunk.content else "",
            ))
            topics.update(chunk.tags)
            total_relevance += result.confidence

        avg_relevance = total_relevance / len(results) if results else 0.0

        return RetrievedKnowledge(
            chunks=results,
            citations=citations,
            total_relevance=avg_relevance,
            topics_covered=list(topics),
        )

    async def reason_about_feature(
        self,
        feature: str,
        user_request: Optional[str] = None,
        page_type: Optional[str] = None,
        page_elements: Optional[List[Dict]] = None,
    ) -> ReasoningResult:
        """
        Reason about a feature to generate test plan.

        Args:
            feature: Feature description
            user_request: User's specific request
            page_type: Type of page (login, signup, etc.)
            page_elements: Elements found on page

        Returns:
            ReasoningResult with tests and citations
        """
        thinking_steps = []

        # Phase 1: Understanding
        thinking_steps.append("💭 Understanding the request...")

        # Phase 2: Retrieve knowledge
        thinking_steps.append("💭 Searching QA Brain for relevant knowledge...")
        knowledge = await self.retrieve_knowledge(
            query=f"{feature} {page_type or ''} testing",
            page_type=page_type,
            n_results=5,
        )

        if knowledge.has_knowledge:
            thinking_steps.append(f"💭 Found {len(knowledge.chunks)} relevant knowledge chunks")
            thinking_steps.append(f"💭 Topics covered: {', '.join(knowledge.topics_covered[:5])}")
        else:
            thinking_steps.append("💭 No specific knowledge found, using general QA principles")

        # Phase 3: Calculate confidence
        confidence = self.scorer.score_generation(
            feature=feature,
            context_available=bool(page_type or page_elements),
            knowledge_chunks=len(knowledge.chunks),
        )
        thinking_steps.append(f"💭 Confidence: {confidence.level.value} ({confidence.score:.0%})")

        # Phase 4: Check if we can proceed
        if not confidence.can_proceed and not knowledge.has_knowledge:
            return ReasoningResult(
                phase=ReasoningPhase.UNDERSTANDING,
                thinking="\n".join(thinking_steps),
                output=f"I need more information to generate tests. {confidence.reasoning}",
                citations=knowledge.citations,
                confidence=confidence,
                knowledge_used=knowledge,
            )

        # Phase 5: Generate via LLM
        thinking_steps.append("💭 Generating test cases...")

        prompt = self.PROMPTS["test_generation"].format(
            knowledge=knowledge.format_for_prompt(),
            feature=feature,
            request=user_request or "Generate comprehensive tests",
            page_type=page_type or "unknown",
        )

        system_prompt = """You are Maya, a 12-year QA veteran. You generate specific, actionable test cases.
Key principles:
- Use real test data, not placeholders (e.g., "maya.test@company.com" not "valid email")
- Focus on edge cases humans miss
- Prioritize security and data integrity
- Be specific about expected behavior
- Format tests clearly with steps, data, and expected results"""

        response = await self.gateway.complete(
            prompt=prompt,
            system=system_prompt,
            citations=knowledge.citations,
            temperature=0.6,
            max_tokens=4096,
        )

        thinking_steps.append("💭 Validating generated tests...")

        # Build final result
        return ReasoningResult(
            phase=ReasoningPhase.GENERATING,
            thinking="\n".join(thinking_steps),
            output=response.content,
            citations=knowledge.citations + response.citations,
            confidence=confidence,
            llm_response=response,
            knowledge_used=knowledge,
        )

    async def analyze_security(
        self,
        feature: str,
        page_type: Optional[str] = None,
        elements: Optional[List[Dict]] = None,
    ) -> ReasoningResult:
        """Analyze security aspects of a feature."""
        thinking_steps = ["💭 Starting security analysis..."]

        # Retrieve security-focused knowledge
        knowledge = await self.retrieve_knowledge(
            query=f"security vulnerabilities {feature} {page_type or ''}",
            n_results=5,
        )
        thinking_steps.append(f"💭 Found {len(knowledge.chunks)} security-related knowledge chunks")

        # Format elements for prompt
        elements_str = ""
        if elements:
            elements_str = "\n".join([
                f"- {e.get('tag', 'unknown')}: {e.get('type', '')} ({e.get('name', '')})"
                for e in elements[:10]
            ])

        prompt = self.PROMPTS["security_analysis"].format(
            knowledge=knowledge.format_for_prompt(),
            feature=feature,
            page_type=page_type or "unknown",
            elements=elements_str or "No elements provided",
        )

        response = await self.gateway.complete(
            prompt=prompt,
            system="You are a security-focused QA expert. Identify vulnerabilities and provide specific mitigation recommendations.",
            citations=knowledge.citations,
            temperature=0.4,
        )

        confidence = self.scorer.score_security_analysis(
            page_type=page_type or "unknown",
            has_auth_elements=any(e.get('type') in ['password', 'email'] for e in (elements or [])),
            has_input_elements=any(e.get('tag') in ['input', 'textarea'] for e in (elements or [])),
            knowledge_match=knowledge.total_relevance,
        )

        return ReasoningResult(
            phase=ReasoningPhase.GENERATING,
            thinking="\n".join(thinking_steps),
            output=response.content,
            citations=knowledge.citations + response.citations,
            confidence=confidence,
            llm_response=response,
            knowledge_used=knowledge,
        )

    async def find_edge_cases(
        self,
        feature: str,
        page_type: Optional[str] = None,
    ) -> ReasoningResult:
        """Find edge cases for a feature."""
        thinking_steps = ["💭 Looking for edge cases..."]

        knowledge = await self.retrieve_knowledge(
            query=f"edge cases boundary testing {feature}",
            n_results=5,
        )
        thinking_steps.append(f"💭 Retrieved {len(knowledge.chunks)} relevant patterns")

        prompt = self.PROMPTS["edge_case_detection"].format(
            knowledge=knowledge.format_for_prompt(),
            feature=feature,
            page_type=page_type or "unknown",
        )

        response = await self.gateway.complete(
            prompt=prompt,
            system="You are an edge case specialist. Find scenarios that typical testers miss.",
            citations=knowledge.citations,
            temperature=0.5,
        )

        confidence = self.scorer.score_generation(
            feature=feature,
            context_available=bool(page_type),
            knowledge_chunks=len(knowledge.chunks),
        )

        return ReasoningResult(
            phase=ReasoningPhase.GENERATING,
            thinking="\n".join(thinking_steps),
            output=response.content,
            citations=knowledge.citations,
            confidence=confidence,
            llm_response=response,
            knowledge_used=knowledge,
        )

    async def generate_clarifications(
        self,
        feature: str,
        user_request: Optional[str] = None,
        gaps: Optional[List[str]] = None,
    ) -> List[str]:
        """Generate clarifying questions."""
        gaps = gaps or ["page type", "test scope", "priority areas"]

        prompt = self.PROMPTS["clarification"].format(
            feature=feature,
            request=user_request or "General testing",
            gaps=", ".join(gaps),
        )

        response = await self.gateway.complete(
            prompt=prompt,
            system="Generate helpful clarifying questions.",
            temperature=0.7,
            max_tokens=512,
        )

        # Parse questions from response
        lines = response.content.split("\n")
        questions = [
            line.strip().lstrip("123456789.-) ")
            for line in lines
            if line.strip() and "?" in line
        ]

        return questions[:3]

    def get_status(self) -> Dict[str, Any]:
        """Get reasoner status."""
        gateway_status = self.gateway.get_status()
        brain_status = {"loaded": self._brain_loaded}
        if self.brain:
            brain_status["chunk_count"] = len(self.brain._chunks) if hasattr(self.brain, '_chunks') else "unknown"

        return {
            "gateway": gateway_status,
            "brain": brain_status,
            "confidence_threshold": self.decision_engine.confidence_threshold,
        }

    def format_usage(self) -> str:
        """Get formatted usage status."""
        return self.gateway.format_usage_status()


# Convenience function
async def quick_reason(
    feature: str,
    page_type: Optional[str] = None,
) -> ReasoningResult:
    """Quick reasoning about a feature."""
    reasoner = Reasoner()
    return await reasoner.reason_about_feature(
        feature=feature,
        page_type=page_type,
    )


if __name__ == "__main__":
    async def main():
        print("🧠 TestAI Reasoner Demo")
        print("=" * 50)

        reasoner = Reasoner()
        print(reasoner.format_usage())
        print()

        # Test reasoning
        print("Testing: Login page analysis")
        result = await reasoner.reason_about_feature(
            feature="login form",
            page_type="login",
            user_request="Generate security-focused tests",
        )

        print("\n💭 Thinking:")
        print(result.thinking)
        print("\n📝 Result:")
        print(result.format_with_sources())

    asyncio.run(main())
