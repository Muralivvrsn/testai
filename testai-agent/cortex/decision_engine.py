"""
TestAI Agent - Decision Engine

The executive function of the agent.
Decides what to do next based on context, knowledge, and confidence.

Decision Flow:
1. Receive input (page content, user request, etc.)
2. Query brain for relevant knowledge
3. Calculate confidence
4. Decide: act autonomously, ask questions, or escalate
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable, Awaitable
from enum import Enum
import asyncio

from .confidence import ConfidenceScorer, ConfidenceResult, ConfidenceLevel


class ActionType(Enum):
    """Types of actions the agent can take."""
    CLASSIFY_PAGE = "classify_page"
    GENERATE_TESTS = "generate_tests"
    ANALYZE_SECURITY = "analyze_security"
    FIND_EDGE_CASES = "find_edge_cases"
    ASK_CLARIFICATION = "ask_clarification"
    EXECUTE_TEST = "execute_test"
    REPORT_RESULTS = "report_results"
    WAIT_FOR_USER = "wait_for_user"


class DecisionOutcome(Enum):
    """Possible outcomes of a decision."""
    PROCEED = "proceed"           # Go ahead autonomously
    CLARIFY = "clarify"           # Ask questions first
    ESCALATE = "escalate"         # Need human help
    DEFER = "defer"               # Save for later
    SKIP = "skip"                 # Not relevant


@dataclass
class DecisionContext:
    """Context for making a decision."""
    # What we're working with
    page_url: Optional[str] = None
    page_type: Optional[str] = None
    page_elements: List[Dict[str, Any]] = field(default_factory=list)
    user_request: Optional[str] = None

    # What we know
    knowledge_chunks: List[Any] = field(default_factory=list)
    knowledge_confidence: float = 0.5

    # History
    previous_actions: List[str] = field(default_factory=list)
    clarifications_asked: int = 0

    # Constraints
    max_clarifications: int = 3
    allow_autonomous: bool = True

    def has_page_info(self) -> bool:
        """Do we have page information?"""
        return bool(self.page_url or self.page_elements)

    def has_knowledge(self) -> bool:
        """Do we have relevant knowledge?"""
        return len(self.knowledge_chunks) > 0

    def can_ask_more(self) -> bool:
        """Can we ask more clarifying questions?"""
        return self.clarifications_asked < self.max_clarifications


@dataclass
class Decision:
    """A decision made by the engine."""
    action: ActionType
    outcome: DecisionOutcome
    confidence: ConfidenceResult
    reasoning: str
    next_steps: List[str] = field(default_factory=list)
    clarification_questions: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"Decision: {self.action.value} → {self.outcome.value} "
            f"({self.confidence.level.value})\n"
            f"Reasoning: {self.reasoning}"
        )

    @property
    def should_proceed(self) -> bool:
        """Should we proceed with this action?"""
        return self.outcome == DecisionOutcome.PROCEED

    @property
    def needs_clarification(self) -> bool:
        """Do we need user input?"""
        return self.outcome in [DecisionOutcome.CLARIFY, DecisionOutcome.ESCALATE]


class DecisionEngine:
    """
    The brain's decision-making system.

    Usage:
        engine = DecisionEngine()

        # Make a decision about what to do
        context = DecisionContext(
            page_url="https://example.com/login",
            page_type="login",
            page_elements=[{"type": "input", "name": "email"}, ...],
            user_request="Generate comprehensive tests"
        )

        decision = await engine.decide(context)

        if decision.should_proceed:
            # Execute the action
            pass
        elif decision.needs_clarification:
            # Ask the questions
            for q in decision.clarification_questions:
                print(q)
    """

    def __init__(
        self,
        confidence_threshold: float = 0.70,
        brain_query_fn: Optional[Callable[[str], Awaitable[Any]]] = None,
    ):
        """
        Initialize the decision engine.

        Args:
            confidence_threshold: Minimum confidence to proceed autonomously
            brain_query_fn: Async function to query the knowledge brain
        """
        self.confidence_threshold = confidence_threshold
        self.scorer = ConfidenceScorer(default_threshold=confidence_threshold)
        self._brain_query = brain_query_fn

    async def decide(self, context: DecisionContext) -> Decision:
        """
        Make a decision based on context.

        Args:
            context: The current decision context

        Returns:
            Decision object with action, outcome, and reasoning
        """
        # First, determine what action type this is
        action_type = self._determine_action_type(context)

        # Calculate confidence based on context
        confidence = self._calculate_confidence(context, action_type)

        # Decide outcome based on confidence and context
        outcome = self._determine_outcome(confidence, context)

        # Generate reasoning
        reasoning = self._generate_reasoning(action_type, confidence, context)

        # Generate next steps or questions
        next_steps = []
        questions = []

        if outcome == DecisionOutcome.PROCEED:
            next_steps = self._generate_next_steps(action_type, context)
        elif outcome in [DecisionOutcome.CLARIFY, DecisionOutcome.ESCALATE]:
            questions = self._generate_questions(action_type, confidence, context)

        return Decision(
            action=action_type,
            outcome=outcome,
            confidence=confidence,
            reasoning=reasoning,
            next_steps=next_steps,
            clarification_questions=questions,
            payload=self._build_payload(action_type, context),
        )

    async def decide_test_strategy(self, context: DecisionContext) -> Decision:
        """Specialized decision for test generation strategy."""
        # Override action type
        context_with_strategy = context

        # Check what we have
        has_page = context.has_page_info()
        has_knowledge = context.has_knowledge()

        if not has_page and not context.user_request:
            # Can't do anything without input
            return Decision(
                action=ActionType.WAIT_FOR_USER,
                outcome=DecisionOutcome.ESCALATE,
                confidence=self.scorer.score_generation("", False, 0),
                reasoning="I need a page URL or feature description to generate tests.",
                clarification_questions=["What would you like me to test?"],
            )

        return await self.decide(context_with_strategy)

    def _determine_action_type(self, context: DecisionContext) -> ActionType:
        """Determine the appropriate action type."""
        request = (context.user_request or "").lower()

        # Check explicit requests
        if "security" in request or "vulnerab" in request:
            return ActionType.ANALYZE_SECURITY
        if "edge" in request or "boundary" in request:
            return ActionType.FIND_EDGE_CASES
        if "test" in request or "generate" in request:
            return ActionType.GENERATE_TESTS
        if "run" in request or "execute" in request:
            return ActionType.EXECUTE_TEST

        # Default based on what we have
        if not context.page_type and context.has_page_info():
            return ActionType.CLASSIFY_PAGE

        if context.page_type:
            return ActionType.GENERATE_TESTS

        return ActionType.WAIT_FOR_USER

    def _calculate_confidence(
        self,
        context: DecisionContext,
        action_type: ActionType,
    ) -> ConfidenceResult:
        """Calculate confidence for the action."""
        if action_type == ActionType.CLASSIFY_PAGE:
            return self.scorer.score_classification(
                page_type=context.page_type or "unknown",
                found_elements=[e.get("tag", "") for e in context.page_elements],
                knowledge_match_score=context.knowledge_confidence,
            )

        elif action_type == ActionType.GENERATE_TESTS:
            return self.scorer.score_generation(
                feature=context.page_type or "unknown",
                context_available=context.has_page_info(),
                knowledge_chunks=len(context.knowledge_chunks),
            )

        elif action_type == ActionType.ANALYZE_SECURITY:
            has_auth = any(
                e.get("type") in ["password", "email", "login"]
                for e in context.page_elements
            )
            has_inputs = any(
                e.get("tag") in ["input", "textarea"]
                for e in context.page_elements
            )
            return self.scorer.score_security_analysis(
                page_type=context.page_type or "unknown",
                has_auth_elements=has_auth,
                has_input_elements=has_inputs,
                knowledge_match=context.knowledge_confidence,
            )

        else:
            # Default scoring
            return self.scorer.score_generation(
                feature="general",
                context_available=context.has_page_info(),
                knowledge_chunks=len(context.knowledge_chunks),
            )

    def _determine_outcome(
        self,
        confidence: ConfidenceResult,
        context: DecisionContext,
    ) -> DecisionOutcome:
        """Determine the outcome based on confidence and context."""
        # Check if we can proceed autonomously
        if not context.allow_autonomous:
            return DecisionOutcome.CLARIFY

        # High confidence = proceed
        if confidence.can_proceed:
            return DecisionOutcome.PROCEED

        # Moderate confidence = clarify (if we can)
        if confidence.level == ConfidenceLevel.MODERATE:
            if context.can_ask_more():
                return DecisionOutcome.CLARIFY
            else:
                # We've asked enough, just proceed with caveats
                return DecisionOutcome.PROCEED

        # Low confidence
        if confidence.level == ConfidenceLevel.LOW:
            if context.can_ask_more():
                return DecisionOutcome.CLARIFY
            else:
                return DecisionOutcome.ESCALATE

        # Very low = escalate
        return DecisionOutcome.ESCALATE

    def _generate_reasoning(
        self,
        action_type: ActionType,
        confidence: ConfidenceResult,
        context: DecisionContext,
    ) -> str:
        """Generate human-readable reasoning."""
        action_names = {
            ActionType.CLASSIFY_PAGE: "classify this page",
            ActionType.GENERATE_TESTS: "generate tests",
            ActionType.ANALYZE_SECURITY: "analyze security",
            ActionType.FIND_EDGE_CASES: "find edge cases",
            ActionType.EXECUTE_TEST: "execute tests",
            ActionType.ASK_CLARIFICATION: "ask questions",
            ActionType.WAIT_FOR_USER: "wait for input",
            ActionType.REPORT_RESULTS: "report results",
        }

        action_name = action_names.get(action_type, "proceed")

        if confidence.can_proceed:
            return f"I'm confident enough to {action_name}. {confidence.reasoning}"
        elif confidence.level == ConfidenceLevel.MODERATE:
            return f"I can {action_name}, but a few clarifications would help. {confidence.reasoning}"
        else:
            return f"I need more information before I can {action_name}. {confidence.reasoning}"

    def _generate_next_steps(
        self,
        action_type: ActionType,
        context: DecisionContext,
    ) -> List[str]:
        """Generate next steps for proceeding."""
        steps = []

        if action_type == ActionType.CLASSIFY_PAGE:
            steps = [
                "Identify page type based on elements",
                "Extract testable elements",
                "Prepare for test generation",
            ]
        elif action_type == ActionType.GENERATE_TESTS:
            steps = [
                f"Query brain for {context.page_type or 'general'} testing rules",
                "Generate tests for each category",
                "Prioritize by risk level",
            ]
        elif action_type == ActionType.ANALYZE_SECURITY:
            steps = [
                "Check for common vulnerabilities",
                "Analyze input handling",
                "Review authentication flow",
            ]
        elif action_type == ActionType.FIND_EDGE_CASES:
            steps = [
                "Identify boundary conditions",
                "Check error states",
                "Test unusual inputs",
            ]

        return steps

    def _generate_questions(
        self,
        action_type: ActionType,
        confidence: ConfidenceResult,
        context: DecisionContext,
    ) -> List[str]:
        """Generate clarification questions."""
        questions = []

        # Use confidence suggestions
        questions.extend(confidence.suggestions)

        # Action-specific questions
        if action_type == ActionType.CLASSIFY_PAGE and not context.page_type:
            questions.append("What type of page is this?")

        if action_type == ActionType.GENERATE_TESTS:
            if not context.page_type:
                questions.append("What feature should I focus on?")
            if len(context.knowledge_chunks) == 0:
                questions.append("Any specific testing requirements I should know?")

        if action_type == ActionType.ANALYZE_SECURITY:
            questions.append("Are there any known security concerns?")

        # Limit questions
        return questions[:3]

    def _build_payload(
        self,
        action_type: ActionType,
        context: DecisionContext,
    ) -> Dict[str, Any]:
        """Build payload for the action."""
        return {
            "action": action_type.value,
            "page_type": context.page_type,
            "element_count": len(context.page_elements),
            "knowledge_chunks": len(context.knowledge_chunks),
            "url": context.page_url,
        }


# Convenience function
def quick_decide(
    page_type: Optional[str] = None,
    elements: Optional[List[Dict]] = None,
    request: Optional[str] = None,
) -> Decision:
    """Quick synchronous decision (for simple cases)."""
    context = DecisionContext(
        page_type=page_type,
        page_elements=elements or [],
        user_request=request,
    )

    engine = DecisionEngine()
    return asyncio.get_event_loop().run_until_complete(engine.decide(context))
