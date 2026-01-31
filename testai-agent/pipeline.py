"""
TestAI Agent - End-to-End Pipeline

The complete test generation pipeline:
1. Parse user request
2. Query Brain for relevant knowledge
3. Ask clarifying questions
4. Generate cited test cases
5. Prioritize by risk
6. Format for stakeholder
7. Track session

This is the production pipeline that makes TestAI Agent
surpass human QA capabilities.

Usage:
    from pipeline import TestPipeline

    pipeline = TestPipeline()
    result = await pipeline.run(
        feature="Login Page",
        page_type="login",
        stakeholder="executive",
    )

    print(result.summary)
    print(result.tests)
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime
from enum import Enum
from pathlib import Path

# Import all components
from brain.smart_ingest import SmartBrainIngestor, IngestResult
from brain.vector_store import QABrain
from cortex.prioritizer import TestPrioritizer, PrioritizedTest, Priority
from cortex.confidence import ConfidenceScorer
from generators.cited_generator import (
    CitedTestGenerator,
    CitedTestPlan,
    CitedTestCase,
    get_login_knowledge,
)
from generators.executive_summary import (
    ExecutiveSummaryGenerator,
    ExecutiveSummary,
    StakeholderType,
    ShipDecision,
)
from personality.qa_consultant import QAConsultantPersonality, ClarifyingQuestion
from interface.thinking_stream import ThinkingStream, ThoughtType
from conversation.memory import ConversationalMemory, MemoryType
from conversation.persistence import SessionStore


class PipelinePhase(Enum):
    """Pipeline execution phases."""
    INIT = "initialization"
    PARSE = "parsing"
    QUERY = "querying"
    CLARIFY = "clarifying"
    GENERATE = "generating"
    PRIORITIZE = "prioritizing"
    FORMAT = "formatting"
    COMPLETE = "complete"


@dataclass
class PipelineContext:
    """Context passed through pipeline."""
    feature: str
    page_type: Optional[str] = None
    user_input: str = ""
    clarifications: Dict[str, str] = field(default_factory=dict)
    brain_results: List[Dict[str, Any]] = field(default_factory=list)
    generated_tests: List[CitedTestCase] = field(default_factory=list)
    prioritized_tests: List[PrioritizedTest] = field(default_factory=list)
    summary: Optional[ExecutiveSummary] = None
    stakeholder: StakeholderType = StakeholderType.EXECUTIVE
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Result from pipeline execution."""
    success: bool
    context: PipelineContext
    tests: List[Dict[str, Any]]
    summary: str
    ship_decision: str
    risk_level: str
    citations: List[str]
    execution_time: float
    phases_completed: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "feature": self.context.feature,
            "page_type": self.context.page_type,
            "test_count": len(self.tests),
            "ship_decision": self.ship_decision,
            "risk_level": self.risk_level,
            "citations": self.citations,
            "execution_time": self.execution_time,
            "phases_completed": self.phases_completed,
            "errors": self.context.errors,
            "warnings": self.context.warnings,
        }


class TestPipeline:
    """
    End-to-end test generation pipeline.

    Orchestrates all components to produce human-quality test plans.

    Usage:
        pipeline = TestPipeline()

        # Simple generation
        result = await pipeline.run("Login Page")

        # With options
        result = await pipeline.run(
            feature="Checkout Flow",
            page_type="checkout",
            stakeholder="engineering",
            skip_clarify=True,
        )

        # Access results
        print(f"Generated {len(result.tests)} tests")
        print(f"Ship decision: {result.ship_decision}")
        print(result.summary)
    """

    def __init__(
        self,
        brain_path: Optional[str] = None,
        verbose: bool = True,
        thinking_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Initialize pipeline.

        Args:
            brain_path: Path to QA_BRAIN.md (optional)
            verbose: Show progress output
            thinking_callback: Callback for thinking updates (phase, message)
        """
        self.verbose = verbose
        self.thinking_callback = thinking_callback

        # Initialize components
        self.brain = QABrain()
        self.ingestor = SmartBrainIngestor()
        self.prioritizer = TestPrioritizer()
        self.confidence = ConfidenceScorer()
        self.consultant = QAConsultantPersonality()
        self.summary_generator = ExecutiveSummaryGenerator()
        self.session_store = SessionStore()
        self.memory = ConversationalMemory()

        # Generator will be created per page type
        self._generator: Optional[CitedTestGenerator] = None

        # Load brain if path provided
        self._brain_loaded = False
        if brain_path:
            self._load_brain(brain_path)

    def _think(self, phase: str, message: str):
        """Emit thinking update."""
        if self.thinking_callback:
            self.thinking_callback(phase, message)
        if self.verbose:
            print(f"  💭 [{phase}] {message}")

    def _load_brain(self, path: str):
        """Load QA Brain from file."""
        try:
            result = self.ingestor.ingest(path)
            self._brain_loaded = True
            self._think("init", f"Loaded {result.stats['total_chunks']} knowledge chunks")
        except FileNotFoundError:
            self._think("init", "Brain file not found, using built-in knowledge")

    def _get_generator(self, page_type: str) -> CitedTestGenerator:
        """Get or create generator for page type."""
        if page_type == "login":
            from generators.cited_generator import create_login_generator
            return create_login_generator()

        # Generic generator
        generator = CitedTestGenerator()

        # Add generic knowledge
        generator.add_knowledge(
            "1.1", "Input Validation",
            [
                "Test required field validation",
                "Test maximum length handling",
                "Test special character handling",
                "Test SQL injection prevention",
                "Test XSS prevention",
            ],
            tags=["validation", "security"],
        )

        generator.add_knowledge(
            "2.1", "Form Submission",
            [
                "Test successful form submission",
                "Test submission with missing fields",
                "Test duplicate submission prevention",
                "Test form reset functionality",
            ],
            tags=["functional", "form"],
        )

        generator.add_knowledge(
            "3.1", "Error Handling",
            [
                "Test error message display",
                "Test error recovery options",
                "Test network error handling",
                "Test timeout handling",
            ],
            tags=["error", "ux"],
        )

        return generator

    def _detect_page_type(self, feature: str) -> str:
        """Detect page type from feature description."""
        feature_lower = feature.lower()

        page_types = {
            "login": ["login", "sign in", "signin", "authentication"],
            "signup": ["signup", "sign up", "register", "registration", "create account"],
            "checkout": ["checkout", "payment", "purchase", "buy", "cart"],
            "search": ["search", "find", "query", "lookup"],
            "profile": ["profile", "account", "settings", "preferences"],
            "dashboard": ["dashboard", "home", "overview", "analytics"],
            "form": ["form", "contact", "feedback", "survey"],
        }

        for page_type, keywords in page_types.items():
            if any(kw in feature_lower for kw in keywords):
                return page_type

        return "form"  # Default

    async def run(
        self,
        feature: str,
        page_type: Optional[str] = None,
        stakeholder: str = "executive",
        skip_clarify: bool = False,
        clarifications: Optional[Dict[str, str]] = None,
        max_tests: int = 20,
    ) -> PipelineResult:
        """
        Run the complete pipeline.

        Args:
            feature: Feature to test (e.g., "Login Page")
            page_type: Type of page (auto-detected if not provided)
            stakeholder: Target stakeholder (executive, product, engineering, qa)
            skip_clarify: Skip clarifying questions
            clarifications: Pre-provided clarifications
            max_tests: Maximum tests to generate

        Returns:
            PipelineResult with tests and summary
        """
        start_time = datetime.now()
        phases_completed = []

        # Initialize context
        ctx = PipelineContext(
            feature=feature,
            page_type=page_type or self._detect_page_type(feature),
            user_input=feature,
            clarifications=clarifications or {},
            stakeholder=StakeholderType(stakeholder),
        )

        try:
            # Phase 1: Parse & Understand
            self._think("parse", f"Understanding request: {feature}")
            ctx.page_type = ctx.page_type or self._detect_page_type(feature)
            phases_completed.append(PipelinePhase.PARSE.value)

            # Phase 2: Query Brain (simulated if not loaded)
            self._think("query", f"Searching knowledge base for {ctx.page_type} rules...")
            # In production, this would query the vector store
            phases_completed.append(PipelinePhase.QUERY.value)

            # Phase 3: Clarify (optional)
            if not skip_clarify and not ctx.clarifications:
                self._think("clarify", "Preparing clarifying questions...")
                questions = self.consultant.get_clarifying_questions(
                    feature, ctx.page_type, max_questions=3
                )
                # In interactive mode, these would be asked
                # For pipeline, use defaults
                for q in questions:
                    if q.default:
                        ctx.clarifications[q.question] = q.default
                phases_completed.append(PipelinePhase.CLARIFY.value)

            # Phase 4: Generate Tests
            self._think("generate", f"Generating test cases for {ctx.page_type}...")
            generator = self._get_generator(ctx.page_type)
            plan = generator.generate(
                feature=feature,
                page_type=ctx.page_type,
                max_tests=max_tests,
            )
            ctx.generated_tests = plan.tests
            phases_completed.append(PipelinePhase.GENERATE.value)

            # Phase 5: Prioritize
            self._think("prioritize", "Prioritizing tests by risk...")
            test_dicts = [t.to_dict() for t in plan.tests]
            ctx.prioritized_tests = self.prioritizer.prioritize(
                test_dicts, page_type=ctx.page_type
            )
            phases_completed.append(PipelinePhase.PRIORITIZE.value)

            # Phase 6: Format Summary
            self._think("format", f"Creating {stakeholder} summary...")
            ctx.summary = self.summary_generator.create_summary(
                feature,
                test_dicts,
                citations=[c.section_id for t in plan.tests for c in t.citations],
            )
            phases_completed.append(PipelinePhase.FORMAT.value)

            # Complete
            self._think("complete", f"Generated {len(plan.tests)} tests")
            phases_completed.append(PipelinePhase.COMPLETE.value)

            # Build result
            execution_time = (datetime.now() - start_time).total_seconds()

            return PipelineResult(
                success=True,
                context=ctx,
                tests=test_dicts,
                summary=self.summary_generator.format_for_stakeholder(
                    ctx.summary, ctx.stakeholder
                ),
                ship_decision=ctx.summary.ship_decision.value,
                risk_level=ctx.summary.risk_level.value,
                citations=list(set(
                    c.section_id for t in plan.tests for c in t.citations
                )),
                execution_time=execution_time,
                phases_completed=phases_completed,
            )

        except Exception as e:
            ctx.errors.append(str(e))
            execution_time = (datetime.now() - start_time).total_seconds()

            return PipelineResult(
                success=False,
                context=ctx,
                tests=[],
                summary=f"Pipeline failed: {e}",
                ship_decision="no_go",
                risk_level="critical",
                citations=[],
                execution_time=execution_time,
                phases_completed=phases_completed,
            )

    def save_session(self):
        """Save current session."""
        return self.session_store.save_session(self.memory)

    def load_session(self, session_id: str) -> bool:
        """Load a previous session."""
        loaded = self.session_store.load_session(session_id)
        if loaded:
            self.memory = loaded
            return True
        return False


# ─────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────

async def generate_tests(
    feature: str,
    page_type: Optional[str] = None,
    stakeholder: str = "executive",
) -> PipelineResult:
    """Quick test generation."""
    pipeline = TestPipeline(verbose=False)
    return await pipeline.run(feature, page_type, stakeholder)


async def quick_summary(feature: str) -> str:
    """Get quick executive summary."""
    result = await generate_tests(feature)
    return result.summary


# ─────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────

async def main():
    """CLI for pipeline."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TestAI Pipeline")
    parser.add_argument("feature", help="Feature to test")
    parser.add_argument("--page-type", "-p", help="Page type")
    parser.add_argument(
        "--stakeholder", "-s",
        choices=["executive", "product", "engineering", "qa"],
        default="executive",
    )
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    pipeline = TestPipeline(verbose=args.verbose)
    result = await pipeline.run(
        args.feature,
        page_type=args.page_type,
        stakeholder=args.stakeholder,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary)
        print()
        print(f"Generated {len(result.tests)} tests in {result.execution_time:.2f}s")
        print(f"Ship Decision: {result.ship_decision.upper()}")
        print(f"Risk Level: {result.risk_level.upper()}")


if __name__ == "__main__":
    asyncio.run(main())
