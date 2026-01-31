"""
TestAI Agent - Unified Agent

The main agent class that orchestrates all components into a single
intelligent QA system. This is the "brain" that ties everything together.

This agent:
1. Understands what you want to test
2. Retrieves relevant knowledge from the Brain
3. Generates comprehensive test cases with citations
4. Learns from execution results
5. Identifies coverage gaps
6. Prioritizes tests by risk
7. Improves continuously

It's designed to be smarter than a human QA engineer because it:
- Never forgets (persistent learning)
- Never gets tired (consistent quality)
- Has perfect recall (instant knowledge retrieval)
- Learns from every execution (continuous improvement)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import asyncio


# Import all the components
from generators.cited_generator import CitedTestGenerator, create_generator_for_page_type
from generators.test_data import TestDataGenerator, create_test_data_generator, InputType
from generators.executive_summary import ExecutiveSummaryGenerator, StakeholderType
from understanding.feature_analyzer import FeatureAnalyzer
from cortex.risk_intelligence import RiskIntelligence, create_risk_intelligence
from cortex.coverage_analyzer import CoverageAnalyzer, create_coverage_analyzer, GapSeverity
from cortex.prioritizer import TestPrioritizer
from learning.feedback_loop import FeedbackLoop, create_feedback_loop, TestFeedback, FeedbackType
from learning.pattern_learner import PatternLearner, create_pattern_learner
from learning.knowledge_updater import KnowledgeUpdater, create_knowledge_updater
from analyzer.result_analyzer import TestResultAnalyzer, create_analyzer, TestRunResult, TestStatus
from conversation.memory import ConversationalMemory, MemoryType
from conversation.persistence import SessionStore


class AgentState(Enum):
    """Current state of the agent."""
    IDLE = "idle"
    UNDERSTANDING = "understanding"
    RETRIEVING = "retrieving"
    GENERATING = "generating"
    ANALYZING = "analyzing"
    LEARNING = "learning"


@dataclass
class AgentCapabilities:
    """What the agent can do."""
    can_generate_tests: bool = True
    can_learn: bool = True
    can_analyze_coverage: bool = True
    can_prioritize: bool = True
    can_generate_code: bool = True
    can_analyze_results: bool = True
    has_brain: bool = True
    has_memory: bool = True


@dataclass
class AgentConfig:
    """Configuration for the unified agent."""
    # Learning settings
    enable_learning: bool = True
    auto_apply_insights: bool = False
    min_confidence_for_auto_apply: float = 0.85

    # Generation settings
    max_tests_per_request: int = 30
    default_stakeholder: str = "executive"

    # Storage
    storage_dir: Optional[str] = None

    # Callbacks
    on_state_change: Optional[Callable[[AgentState], None]] = None
    on_thinking: Optional[Callable[[str], None]] = None


@dataclass
class GenerationResult:
    """Result of test generation."""
    success: bool
    feature: str
    page_type: str

    # Generated tests
    tests: List[Dict[str, Any]]
    test_count: int

    # Quality metrics
    coverage_percentage: float
    gaps_identified: int
    critical_gaps: int

    # Risk assessment
    risk_summary: Dict[str, int]

    # Citations
    citations: List[str]

    # Timing
    generation_time_ms: float

    # Recommendations
    recommendations: List[str]

    # Summary
    summary: str
    ship_decision: str


class UnifiedAgent:
    """
    The unified TestAI Agent that orchestrates all components.

    This is the main interface for using the testing system.
    It combines:
    - Test generation with citations
    - Learning from executions
    - Risk-based prioritization
    - Coverage gap analysis
    - Executive reporting
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        """Initialize the unified agent."""
        self.config = config or AgentConfig()
        self._state = AgentState.IDLE

        # Storage directory
        if self.config.storage_dir:
            self._storage = Path(self.config.storage_dir)
        else:
            self._storage = Path.home() / ".testai_agent"
        self._storage.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self._init_components()

        # Session state
        self._current_feature: Optional[str] = None
        self._current_page_type: Optional[str] = None
        self._current_tests: List[Dict[str, Any]] = []

        # Statistics
        self._stats = {
            "generations": 0,
            "tests_generated": 0,
            "tests_executed": 0,
            "insights_learned": 0,
            "gaps_identified": 0,
        }

    def _init_components(self) -> None:
        """Initialize all agent components."""
        # Feature understanding
        self._feature_analyzer = FeatureAnalyzer()

        # Test generation
        self._test_data_gen = create_test_data_generator()
        self._summary_gen = ExecutiveSummaryGenerator()
        self._prioritizer = TestPrioritizer()

        # Learning
        if self.config.enable_learning:
            self._feedback_loop = create_feedback_loop(
                storage_dir=str(self._storage / "feedback"),
                min_samples=3,
            )
            self._pattern_learner = create_pattern_learner()
            self._knowledge_updater = create_knowledge_updater(
                storage_dir=str(self._storage / "knowledge"),
                auto_apply_threshold=self.config.min_confidence_for_auto_apply,
            )
        else:
            self._feedback_loop = None
            self._pattern_learner = None
            self._knowledge_updater = None

        # Analysis
        self._risk_intel = create_risk_intelligence()
        self._coverage_analyzer = create_coverage_analyzer()
        self._result_analyzer = create_analyzer()

        # Memory
        self._memory = ConversationalMemory()
        self._session_store = SessionStore(session_dir=str(self._storage / "sessions"))

    def _set_state(self, state: AgentState) -> None:
        """Update agent state and notify callback."""
        self._state = state
        if self.config.on_state_change:
            self.config.on_state_change(state)

    def _think(self, thought: str) -> None:
        """Emit a thinking message."""
        if self.config.on_thinking:
            self.config.on_thinking(thought)

    @property
    def state(self) -> AgentState:
        """Get current agent state."""
        return self._state

    @property
    def capabilities(self) -> AgentCapabilities:
        """Get agent capabilities."""
        return AgentCapabilities(
            can_generate_tests=True,
            can_learn=self.config.enable_learning,
            can_analyze_coverage=True,
            can_prioritize=True,
            can_generate_code=True,
            can_analyze_results=True,
            has_brain=True,
            has_memory=True,
        )

    async def generate_tests(
        self,
        feature: str,
        page_type: Optional[str] = None,
        stakeholder: Optional[str] = None,
        max_tests: Optional[int] = None,
    ) -> GenerationResult:
        """
        Generate comprehensive test cases for a feature.

        This is the main entry point for test generation.
        It orchestrates all components to produce high-quality,
        citation-backed test cases.
        """
        start_time = datetime.now()
        self._stats["generations"] += 1

        # Update memory
        self._memory.add_user_turn(f"Generate tests for: {feature}")

        # 1. Understand the request
        self._set_state(AgentState.UNDERSTANDING)
        self._think("Understanding your request...")

        context = self._feature_analyzer.from_request(feature)
        detected_page_type = page_type or context.page_type or "general"

        self._memory.set_working_context(
            feature=feature,
            page_type=detected_page_type,
        )

        self._think(f"Detected page type: {detected_page_type}")

        # 2. Retrieve relevant knowledge
        self._set_state(AgentState.RETRIEVING)
        self._think("Retrieving testing rules from knowledge base...")

        generator = create_generator_for_page_type(detected_page_type)

        # 3. Generate tests
        self._set_state(AgentState.GENERATING)
        self._think("Generating test cases...")

        plan = generator.generate(
            feature=feature,
            page_type=detected_page_type,
            max_tests=max_tests or self.config.max_tests_per_request,
        )

        # Convert to dict format
        tests = []
        citations = set()
        for test in plan.tests:
            test_dict = {
                "id": test.id,  # CitedTestCase uses 'id' not 'test_id'
                "title": test.title,
                "description": test.description,
                "category": test.category.value,
                "priority": test.priority.value,
                "page_type": detected_page_type,
                "steps": test.steps,
                "expected_result": test.expected_result,
                "citations": [c.section_id for c in test.citations],
            }
            tests.append(test_dict)

            for c in test.citations:
                citations.add(c.section_id)

        self._stats["tests_generated"] += len(tests)

        # 4. Prioritize by risk
        self._think("Prioritizing tests by risk...")
        prioritized_tests = self._risk_intel.prioritize_tests(tests)

        # 5. Analyze coverage
        self._set_state(AgentState.ANALYZING)
        self._think("Analyzing test coverage...")

        coverage_report = self._coverage_analyzer.analyze_coverage(
            detected_page_type,
            prioritized_tests,
        )

        self._stats["gaps_identified"] += len(coverage_report.gaps)

        # 6. Generate summary
        stakeholder_type = self._map_stakeholder(
            stakeholder or self.config.default_stakeholder
        )

        summary = self._summary_gen.create_summary(feature, prioritized_tests)
        formatted_summary = self._summary_gen.format_for_stakeholder(
            summary, stakeholder_type
        )

        # 7. Generate recommendations
        recommendations = []

        # From coverage gaps
        if coverage_report.critical_gaps > 0:
            recommendations.append(
                f"⚠️ {coverage_report.critical_gaps} critical coverage gaps - "
                "review required before release"
            )

        if coverage_report.high_gaps > 0:
            recommendations.append(
                f"Consider adding {coverage_report.high_gaps} high-priority tests"
            )

        # From risk analysis
        risk_recs = self._risk_intel.get_recommendations(detected_page_type)
        recommendations.extend(risk_recs[:3])

        # From learning
        if self._feedback_loop:
            learned_recs = self._feedback_loop.get_recommendations_for_page(
                detected_page_type
            )
            recommendations.extend(learned_recs[:2])

        # Calculate timing
        elapsed = (datetime.now() - start_time).total_seconds() * 1000

        # Store current state
        self._current_feature = feature
        self._current_page_type = detected_page_type
        self._current_tests = prioritized_tests

        # Return to idle
        self._set_state(AgentState.IDLE)

        # Count risk levels
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for test in prioritized_tests:
            level = test.get("_risk_level", "medium")
            if level in risk_summary:
                risk_summary[level] += 1

        return GenerationResult(
            success=True,
            feature=feature,
            page_type=detected_page_type,
            tests=prioritized_tests,
            test_count=len(prioritized_tests),
            coverage_percentage=coverage_report.coverage_percentage,
            gaps_identified=len(coverage_report.gaps),
            critical_gaps=coverage_report.critical_gaps,
            risk_summary=risk_summary,
            citations=list(citations),
            generation_time_ms=elapsed,
            recommendations=recommendations,
            summary=formatted_summary,
            ship_decision=summary.ship_decision.value if summary.ship_decision else "unknown",
        )

    def record_test_result(
        self,
        test_id: str,
        passed: bool,
        execution_time_ms: float = 0,
        error_message: Optional[str] = None,
        test_title: str = "",
        category: str = "",
    ) -> None:
        """
        Record a test execution result for learning.

        This is how the agent learns from every test run.
        """
        if not self.config.enable_learning:
            return

        self._stats["tests_executed"] += 1

        # Record in feedback loop
        feedback = TestFeedback(
            test_id=test_id,
            feedback_type=FeedbackType.TEST_PASSED if passed else FeedbackType.TEST_FAILED,
            test_title=test_title,
            test_category=category,
            page_type=self._current_page_type or "",
            execution_time_ms=execution_time_ms,
            error_message=error_message,
        )

        self._feedback_loop.add_feedback(feedback)

        # Record in risk intelligence
        self._risk_intel.record_test_result(
            test_id=test_id,
            passed=passed,
            execution_time_ms=execution_time_ms,
        )

        # Analyze failure patterns if failed
        if not passed and error_message:
            patterns = self._pattern_learner.analyze_failure(
                error_message=error_message,
                page_type=self._current_page_type or "",
                category=category,
            )

            # If patterns found, get prevention strategies
            if patterns:
                strategies = self._pattern_learner.get_prevention_strategies(error_message)
                self._memory.remember(
                    MemoryType.INSIGHT,
                    f"Failure pattern in {test_id}: {patterns[0].name}. "
                    f"Prevention: {strategies[0] if strategies else 'Review test'}"
                )

    def get_learning_insights(self) -> List[Dict[str, Any]]:
        """Get insights learned from test executions."""
        if not self.config.enable_learning:
            return []

        insights = self._feedback_loop.get_insights(min_confidence=0.5)
        self._stats["insights_learned"] = len(insights)

        return [
            {
                "description": i.description,
                "confidence": i.confidence,
                "recommendations": i.recommendations,
                "applied": i.applied,
            }
            for i in insights
        ]

    def get_coverage_gaps(self, page_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get coverage gaps for a page type."""
        pt = page_type or self._current_page_type or "login"
        report = self._coverage_analyzer.analyze_coverage(pt, self._current_tests)

        return [gap.to_dict() for gap in report.gaps]

    def generate_test_data(
        self,
        input_type: str,
        include_security: bool = True,
    ) -> Dict[str, List[Dict[str, str]]]:
        """Generate test data for an input type."""
        try:
            it = InputType(input_type)
        except ValueError:
            it = InputType.TEXT

        data_set = self._test_data_gen.generate(it)

        result = {
            "valid": [{"value": i.value, "description": i.description} for i in data_set.get_valid()],
            "invalid": [{"value": i.value, "description": i.description} for i in data_set.get_invalid()],
            "edge_cases": [{"value": i.value, "description": i.description} for i in data_set.get_edge_cases()],
        }

        if include_security:
            result["security"] = [
                {"value": i.value, "description": i.description}
                for i in data_set.get_security()
            ]

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        stats = {**self._stats}

        if self.config.enable_learning:
            stats["learning"] = self._feedback_loop.get_stats()
            stats["risk"] = self._risk_intel.get_risk_summary()

        return stats

    def save_session(self, session_id: Optional[str] = None) -> str:
        """Save current session for later resumption."""
        return self._session_store.save_session(self._memory, session_id)

    def load_session(self, session_id: str) -> bool:
        """Load a previous session."""
        loaded = self._session_store.load_session(session_id)
        if loaded:
            self._memory = loaded
            if self._memory.working:
                self._current_feature = self._memory.working.current_feature
                self._current_page_type = self._memory.working.current_page_type
            return True
        return False

    def _map_stakeholder(self, stakeholder: str) -> StakeholderType:
        """Map stakeholder string to enum."""
        mapping = {
            "executive": StakeholderType.EXECUTIVE,
            "product": StakeholderType.PRODUCT,
            "engineering": StakeholderType.ENGINEERING,
            "qa": StakeholderType.QA,
        }
        return mapping.get(stakeholder.lower(), StakeholderType.EXECUTIVE)


def create_agent(config: Optional[AgentConfig] = None) -> UnifiedAgent:
    """Create a unified agent instance."""
    return UnifiedAgent(config)
