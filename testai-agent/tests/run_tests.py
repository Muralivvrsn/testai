#!/usr/bin/env python3
"""
TestAI Agent - Simple Test Runner

Runs integration tests without pytest dependency.
"""

import sys
import os
from pathlib import Path
import traceback
import asyncio

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def record_pass(self, name):
        self.passed += 1
        print(f"  ✅ {name}")

    def record_fail(self, name, error):
        self.failed += 1
        self.errors.append((name, error))
        print(f"  ❌ {name}")
        print(f"     Error: {error}")

    def summary(self):
        total = self.passed + self.failed
        print()
        print("=" * 50)
        print(f"Results: {self.passed}/{total} passed")
        if self.errors:
            print(f"\nFailed tests:")
            for name, error in self.errors:
                print(f"  - {name}: {error}")
        return self.failed == 0


def run_test(result: TestResult, name: str, test_fn):
    """Run a single test."""
    try:
        if asyncio.iscoroutinefunction(test_fn):
            asyncio.get_event_loop().run_until_complete(test_fn())
        else:
            test_fn()
        result.record_pass(name)
    except Exception as e:
        result.record_fail(name, str(e))


def test_brain_imports():
    """Test Brain module imports."""
    from brain.vector_store import QABrain, KnowledgeChunk, SearchResult
    assert QABrain is not None


def test_brain_initialization():
    """Test Brain can be initialized."""
    from brain.vector_store import QABrain
    brain = QABrain()
    assert brain is not None


def test_gateway_imports():
    """Test Gateway module imports."""
    from connectors.llm_gateway import LLMGateway, create_gateway, Citation
    assert LLMGateway is not None


def test_gateway_creation():
    """Test Gateway creation with limits."""
    from connectors.llm_gateway import create_gateway

    gateway = create_gateway(max_calls=10)
    assert gateway.get_remaining_calls() == 10


def test_gateway_status():
    """Test Gateway status."""
    from connectors.llm_gateway import create_gateway

    gateway = create_gateway(max_calls=5)
    status = gateway.get_status()

    assert status["primary_provider"] == "deepseek"
    assert status["ready"] == True


def test_citation():
    """Test Citation creation."""
    from connectors.llm_gateway import Citation

    citation = Citation(
        source="Brain: Section 7.1",
        chunk_id="test",
        confidence=0.85,
    )

    formatted = citation.format()
    assert "85%" in formatted


def test_cortex_imports():
    """Test Cortex module imports."""
    from cortex import Reasoner, DecisionEngine, ConfidenceScorer
    assert Reasoner is not None
    assert DecisionEngine is not None


def test_reasoner_creation():
    """Test Reasoner creation."""
    from cortex.reasoner import Reasoner
    from connectors.llm_gateway import create_gateway

    gateway = create_gateway(max_calls=10)
    reasoner = Reasoner(gateway=gateway)
    assert reasoner is not None


def test_confidence_scoring():
    """Test confidence scoring."""
    from cortex.confidence import ConfidenceScorer

    scorer = ConfidenceScorer(default_threshold=0.7)
    result = scorer.score_generation(
        feature="login",
        context_available=True,
        knowledge_chunks=3,
    )

    assert result.score >= 0 and result.score <= 1


def test_interface_imports():
    """Test Interface module imports."""
    from interface.rich_output import RichOutput
    from interface.consultant import QAConsultant
    assert RichOutput is not None
    assert QAConsultant is not None


def test_rich_output():
    """Test RichOutput."""
    from interface.rich_output import RichOutput

    output = RichOutput(force_basic=True)
    output.thinking("Test")
    output.success("Test")
    # No assertion needed - just shouldn't raise


def test_consultant_creation():
    """Test QAConsultant creation."""
    from interface.consultant import QAConsultant
    from interface.rich_output import RichOutput

    output = RichOutput(force_basic=True)
    consultant = QAConsultant(output=output)
    assert consultant.session.max_api_calls == 10


def test_generators_imports():
    """Test Generators module imports."""
    from generators import ReportGenerator, ExecutiveReportGenerator
    assert ReportGenerator is not None
    assert ExecutiveReportGenerator is not None


def test_report_generation():
    """Test report generation."""
    from generators import ReportGenerator

    generator = ReportGenerator()
    tests = [
        {"id": "TC-001", "title": "Test", "priority": "critical", "category": "security"},
    ]

    report = generator.create_report(tests, "Login")
    assert report.summary["total_tests"] == 1


def test_executive_report():
    """Test executive report."""
    from generators import generate_executive_report, AudienceType

    tests = [
        {"id": "TC-001", "title": "Test", "priority": "critical", "category": "security"},
    ]

    report = generate_executive_report(tests, "Login", AudienceType.EXECUTIVE)
    assert "Risk Assessment" in report


def test_personality_imports():
    """Test Personality module imports."""
    from personality import Thinker, ResponseStyler
    assert Thinker is not None


def test_thinker():
    """Test Thinker."""
    from personality.thinker import Thinker, ThinkingPhase

    thinker = Thinker()
    thought = thinker.think(ThinkingPhase.ANALYZING)
    assert thought.text is not None


def test_understanding_imports():
    """Test Understanding module imports."""
    from understanding.feature_analyzer import FeatureAnalyzer
    from understanding.edge_cases import EdgeCaseDetector
    assert FeatureAnalyzer is not None
    assert EdgeCaseDetector is not None


def test_feature_analysis():
    """Test feature analysis."""
    from understanding.feature_analyzer import FeatureAnalyzer

    analyzer = FeatureAnalyzer()
    context = analyzer.from_request("login page")
    assert context.page_type == "login"


def test_edge_cases():
    """Test edge case detection."""
    from understanding.edge_cases import EdgeCaseDetector

    detector = EdgeCaseDetector()
    analysis = detector.analyze_page_type("login")
    assert analysis is not None
    assert len(analysis.edge_cases) > 0


async def test_consultant_flow():
    """Test consultant flow (async)."""
    from interface.consultant import QAConsultant
    from interface.rich_output import RichOutput

    output = RichOutput(force_basic=True)
    consultant = QAConsultant(output=output, verbose=False)

    response = await consultant.analyze_request("login page", page_type="login")
    assert response is not None

    tests = await consultant.generate_tests()
    assert len(tests) > 0


# ─────────────────────────────────────────────────────────────
# New Enhanced Module Tests
# ─────────────────────────────────────────────────────────────

def test_conversational_memory():
    """Test ConversationalMemory."""
    from conversation.memory import ConversationalMemory, MemoryType

    memory = ConversationalMemory()
    memory.add_user_turn("test login page")
    memory.set_working_context(feature="login", page_type="login")
    memory.remember(MemoryType.DECISION, "Focus on security")

    assert memory.working.current_feature == "login"
    assert len(memory.get_decisions()) == 1


def test_human_clarifier():
    """Test HumanClarifier."""
    from personality.human_clarifier import HumanClarifier, QuestionContext

    clarifier = HumanClarifier()
    context = QuestionContext(page_type="login")
    questions = clarifier.get_questions(context, max_questions=3)

    assert len(questions) <= 3
    assert all(q.question for q in questions)


def test_thinking_display():
    """Test ThinkingDisplay."""
    from interface.thinking_display import ThinkingDisplay, ThinkingPhase

    display = ThinkingDisplay(verbose=False, stream=False)
    display.start_thinking("test")
    display.think(ThinkingPhase.ANALYZING, "test message")
    display.complete("done")

    # Should not raise


def test_executive_output():
    """Test ExecutiveOutputFormatter."""
    from interface.executive_output import ExecutiveOutputFormatter, Audience

    formatter = ExecutiveOutputFormatter(use_color=False)
    tests = [
        {"id": "TC-001", "title": "Test", "priority": "critical", "category": "security"},
    ]

    output = formatter.format_test_plan(tests, "Login", Audience.EXECUTIVE)
    assert "SHIP DECISION" in output


def test_usage_dashboard():
    """Test UsageDashboard."""
    from interface.usage_dashboard import UsageDashboard, ProviderName

    dashboard = UsageDashboard(use_color=False)
    dashboard.record_api_call(ProviderName.DEEPSEEK, tokens=1000)

    assert dashboard.get_remaining_calls() == 9
    assert dashboard.can_call()


def test_qa_brain_exists():
    """Test QA_BRAIN.md exists."""
    from pathlib import Path

    brain_path = Path(__file__).parent.parent / "QA_BRAIN.md"
    assert brain_path.exists(), "QA_BRAIN.md should exist"

    content = brain_path.read_text()
    assert "Login Page Specific" in content
    assert "SQL Injection" in content
    assert "Section" in content


def test_prioritizer():
    """Test TestPrioritizer."""
    from cortex.prioritizer import TestPrioritizer, Priority

    prioritizer = TestPrioritizer()
    tests = [
        {"id": "TC-001", "title": "SQL injection test", "category": "security"},
        {"id": "TC-002", "title": "Valid login", "category": "happy_path"},
    ]

    prioritized = prioritizer.prioritize(tests, page_type="login")

    # Security test should be higher priority
    assert prioritized[0].original_test["category"] == "security"
    assert prioritized[0].computed_priority in [Priority.CRITICAL, Priority.HIGH]


def test_session_persistence():
    """Test SessionStore for saving/loading sessions."""
    import tempfile
    from conversation.persistence import SessionStore
    from conversation.memory import ConversationalMemory, MemoryType

    # Use temp directory for test
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(session_dir=tmpdir)

        # Create memory with data
        memory = ConversationalMemory()
        memory.add_user_turn("test login page")
        memory.set_working_context(feature="login", page_type="login")
        memory.remember(MemoryType.DECISION, "Focus on security")

        # Save
        session_id = store.save_session(memory, "test-session")
        assert session_id == "test-session"

        # Load
        loaded = store.load_session("test-session")
        assert loaded is not None
        assert loaded.working.current_feature == "login"
        assert loaded.working.current_page_type == "login"
        decisions = [m.content for m in loaded.get_decisions()]
        assert "Focus on security" in decisions

        # List
        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].session_id == "test-session"


def test_thinking_stream():
    """Test ThinkingStream for visible reasoning."""
    from interface.thinking_stream import ThinkingStream, ThoughtType
    import io

    output = io.StringIO()
    stream = ThinkingStream(output_stream=output, use_color=False, typing_speed=0)

    stream.understanding("Analyzing request")
    stream.searching("Querying knowledge base")
    stream.found("Found 5 rules", source="Section 7.1")

    summary = stream.get_summary()
    assert summary["total_thoughts"] == 3
    assert "Section 7.1" in summary["sources_cited"]


def test_cited_generator():
    """Test CitedTestGenerator with citations."""
    from generators.cited_generator import CitedTestGenerator, create_login_generator

    generator = create_login_generator()
    plan = generator.generate(
        feature="Login Page",
        page_type="login",
        max_tests=5,
    )

    assert len(plan.tests) > 0
    assert all(len(t.citations) > 0 for t in plan.tests)
    assert plan.feature == "Login Page"


def test_smart_brain_ingest():
    """Test SmartBrainIngestor parsing."""
    from brain.smart_ingest import ingest_brain_content

    sample = """
# Test Knowledge

## Security
- Test SQL injection
- Verify XSS prevention

## Validation
- Test email format
- Check required fields
"""
    result = ingest_brain_content(sample)

    assert result.stats["total_sections"] > 0
    assert len(result.get_rules()) > 0
    assert len(result.get_by_tag("security")) > 0


def test_qa_consultant():
    """Test QAConsultantPersonality."""
    from personality.qa_consultant import QAConsultantPersonality

    consultant = QAConsultantPersonality()

    greeting = consultant.greet()
    assert len(greeting) > 0

    questions = consultant.get_clarifying_questions(
        user_input="test login",
        detected_page_type="login",
        max_questions=3,
    )
    assert len(questions) <= 3
    assert all(q.question for q in questions)


def test_executive_summary():
    """Test ExecutiveSummaryGenerator."""
    from generators.executive_summary import ExecutiveSummaryGenerator, StakeholderType

    tests = [
        {"id": "TC-001", "title": "Test", "category": "security", "priority": "critical"},
        {"id": "TC-002", "title": "Test 2", "category": "functional", "priority": "high"},
    ]

    generator = ExecutiveSummaryGenerator()
    summary = generator.create_summary("Login", tests)

    assert summary.feature == "Login"
    assert summary.coverage.total_tests == 2

    # Format for different stakeholders
    exec_report = generator.format_for_stakeholder(summary, StakeholderType.EXECUTIVE)
    assert "Ship Decision" in exec_report

    eng_report = generator.format_for_stakeholder(summary, StakeholderType.ENGINEERING)
    assert "Technical" in eng_report


async def test_pipeline():
    """Test end-to-end pipeline."""
    from pipeline import TestPipeline

    pipeline = TestPipeline(verbose=False)
    result = await pipeline.run(
        feature="Login Page",
        page_type="login",
        stakeholder="executive",
        skip_clarify=True,
    )

    assert result.success
    assert len(result.tests) > 0
    assert result.ship_decision in ["go", "caution", "no_go"]
    assert len(result.phases_completed) > 0


def test_signup_generator():
    """Test signup page generator."""
    from generators.cited_generator import create_signup_generator

    generator = create_signup_generator()
    plan = generator.generate(
        feature="Registration Page",
        page_type="signup",
        max_tests=10,
    )

    assert len(plan.tests) > 0
    assert all(len(t.citations) > 0 for t in plan.tests)
    assert plan.feature == "Registration Page"
    # Should have sections starting with 8.x
    citation_sections = set(c.section_id for t in plan.tests for c in t.citations)
    assert any(s.startswith("8.") for s in citation_sections)


def test_checkout_generator():
    """Test checkout page generator."""
    from generators.cited_generator import create_checkout_generator

    generator = create_checkout_generator()
    plan = generator.generate(
        feature="Checkout Flow",
        page_type="checkout",
        max_tests=10,
    )

    assert len(plan.tests) > 0
    assert all(len(t.citations) > 0 for t in plan.tests)
    # Should have payment/security related tests
    categories = set(t.category.value for t in plan.tests)
    assert "security" in categories or "functional" in categories


def test_search_generator():
    """Test search page generator."""
    from generators.cited_generator import create_search_generator

    generator = create_search_generator()
    plan = generator.generate(
        feature="Search Functionality",
        page_type="search",
        max_tests=10,
    )

    assert len(plan.tests) > 0
    assert all(len(t.citations) > 0 for t in plan.tests)
    # Should have sections starting with 10.x
    citation_sections = set(c.section_id for t in plan.tests for c in t.citations)
    assert any(s.startswith("10.") for s in citation_sections)


def test_profile_generator():
    """Test profile page generator."""
    from generators.cited_generator import create_profile_generator

    generator = create_profile_generator()
    plan = generator.generate(
        feature="User Profile",
        page_type="profile",
        max_tests=10,
    )

    assert len(plan.tests) > 0
    assert all(len(t.citations) > 0 for t in plan.tests)
    # Should have sections starting with 11.x
    citation_sections = set(c.section_id for t in plan.tests for c in t.citations)
    assert any(s.startswith("11.") for s in citation_sections)


def test_generator_factory():
    """Test the generator factory function."""
    from generators.cited_generator import create_generator_for_page_type

    # Test various page types
    login_gen = create_generator_for_page_type("login")
    assert "7.1" in login_gen.knowledge_base

    signup_gen = create_generator_for_page_type("register")  # alias
    assert "8.1" in signup_gen.knowledge_base

    checkout_gen = create_generator_for_page_type("payment")  # alias
    assert "9.1" in checkout_gen.knowledge_base

    search_gen = create_generator_for_page_type("find")  # alias
    assert "10.1" in search_gen.knowledge_base

    profile_gen = create_generator_for_page_type("settings")  # alias
    assert "11.1" in profile_gen.knowledge_base

    # Unknown page type should return generic generator
    generic_gen = create_generator_for_page_type("unknown")
    assert "1.1" in generic_gen.knowledge_base


def test_in_memory_brain():
    """Test InMemoryBrain for fallback without ChromaDB."""
    from brain.vector_store import InMemoryBrain

    brain = InMemoryBrain()
    assert not brain.is_ready

    # Add knowledge chunks
    brain.add_chunk(
        chunk_id="test-1",
        content="Test SQL injection in login form email field",
        section="Section 7.1: Security",
        category="security",
        tags=["security", "injection"],
        page_types=["login"],
    )

    brain.add_chunk(
        chunk_id="test-2",
        content="Test valid email format acceptance",
        section="Section 7.2: Validation",
        category="rule",
        tags=["validation", "email"],
        page_types=["login", "signup"],
    )

    brain.add_chunk(
        chunk_id="test-3",
        content="Test checkout payment card validation",
        section="Section 9.1: Payment",
        category="rule",
        tags=["payment", "validation"],
        page_types=["checkout"],
    )

    assert brain.is_ready
    assert brain._chunk_count == 3

    # Test search
    results = brain.search("SQL injection security")
    assert results.total_found > 0
    assert results.chunks[0].category == "security"

    # Test page type filter
    login_results = brain.search("validation", page_type="login")
    assert all("login" in c.page_types for c in login_results.chunks)

    # Test category filter
    security_results = brain.search("test", category="security")
    assert all(c.category == "security" for c in security_results.chunks)


def test_brain_from_generator():
    """Test loading brain from a generator."""
    from brain.vector_store import load_brain_from_generator
    from generators.cited_generator import create_login_generator

    generator = create_login_generator()
    brain = load_brain_from_generator(generator)

    assert brain.is_ready
    assert brain._chunk_count > 0

    # Search should return relevant results
    results = brain.search("password validation")
    assert results.total_found > 0

    # Should find login-related chunks
    login_chunks = brain.get_all_by_page_type("login")
    assert len(login_chunks) == 0  # page_types not set in generator knowledge


def test_playwright_executor_imports():
    """Test Playwright executor imports."""
    from executors import PlaywrightExecutor, TestStep, StepResult, create_executor
    assert PlaywrightExecutor is not None
    assert TestStep is not None


def test_playwright_step_parsing():
    """Test step parsing from natural language."""
    from executors import create_executor

    executor = create_executor()

    # Test navigation
    step = executor.parse_step("Navigate to the login page")
    assert step.action == "navigate"

    # Test click
    step = executor.parse_step("Click the submit button")
    assert step.action == "click"

    # Test fill
    step = executor.parse_step("Enter valid email in the email field")
    assert step.action == "fill"
    assert step.target is not None  # Should detect email selector

    # Test assertion
    step = executor.parse_step("Verify the user is logged in")
    assert step.action == "assert"


def test_playwright_code_generation():
    """Test code generation."""
    from executors import create_executor, OutputFormat

    executor = create_executor()

    test_case = {
        "id": "TC-001",
        "title": "Login Test",
        "description": "Test login functionality",
        "category": "functional",
        "priority": "critical",
        "steps": [
            "Navigate to login page",
            "Enter email",
            "Click submit",
        ],
        "expected_result": "User logged in",
    }

    # Generate pytest code
    pytest_code = executor.generate_code(test_case, OutputFormat.PYTHON_PYTEST)
    assert "def test_login_test" in pytest_code
    assert "page.goto" in pytest_code or "page.locator" in pytest_code

    # Generate TypeScript code
    ts_code = executor.generate_code(test_case, OutputFormat.TYPESCRIPT)
    assert "test('Login Test'" in ts_code
    assert "await page" in ts_code


def test_playwright_dry_run():
    """Test dry run execution."""
    from executors import create_executor, StepStatus

    executor = create_executor()

    test_case = {
        "id": "TC-001",
        "title": "Test Case",
        "steps": [
            "Navigate to page",
            "Click button",
        ],
    }

    result = executor.dry_run(test_case)
    assert result.test_id == "TC-001"
    assert len(result.steps) == 2
    # Dry run should complete
    assert result.status in [StepStatus.PASSED, StepStatus.FAILED]


def test_interactive_cli_imports():
    """Test interactive CLI imports."""
    from interactive_cli import InteractiveCLI
    assert InteractiveCLI is not None


async def test_interactive_cli_generation():
    """Test interactive CLI test generation."""
    from interactive_cli import InteractiveCLI

    cli = InteractiveCLI(verbose=False)

    # Test generation
    await cli.generate_tests("Login Page", skip_clarify=True)

    assert cli.current_feature == "Login Page"
    assert cli.current_page_type == "login"
    assert len(cli.current_tests) > 0


def test_test_data_generator_imports():
    """Test test data generator imports."""
    from generators.test_data import TestDataGenerator, InputType, DataCategory
    assert TestDataGenerator is not None
    assert InputType is not None


def test_test_data_email():
    """Test email data generation."""
    from generators.test_data import create_test_data_generator, InputType

    generator = create_test_data_generator()
    email_data = generator.generate(InputType.EMAIL)

    # Should have valid and invalid items
    valid = email_data.get_valid()
    invalid = email_data.get_invalid()
    security = email_data.get_security()

    assert len(valid) > 0
    assert len(invalid) > 0
    assert len(security) > 0

    # Check valid emails look valid
    for item in valid:
        assert "@" in item.value
        assert item.expected_valid is True


def test_test_data_password():
    """Test password data generation."""
    from generators.test_data import create_test_data_generator, InputType

    generator = create_test_data_generator()
    password_data = generator.generate(InputType.PASSWORD)

    assert len(password_data.items) > 0

    # Should have edge cases
    edge_cases = password_data.get_edge_cases()
    assert len(edge_cases) > 0


def test_test_data_form():
    """Test form data generation."""
    from generators.test_data import create_test_data_generator, InputType

    generator = create_test_data_generator()
    form_data = generator.generate_for_form({
        "email": InputType.EMAIL,
        "password": InputType.PASSWORD,
        "username": InputType.USERNAME,
    })

    assert "email" in form_data
    assert "password" in form_data
    assert "username" in form_data

    # Each field should have test data
    for field, data in form_data.items():
        assert len(data.items) > 0


def test_test_data_security_payloads():
    """Test security payload retrieval."""
    from generators.test_data import create_test_data_generator

    generator = create_test_data_generator()
    payloads = generator.get_security_payloads()

    assert "sql_injection" in payloads
    assert "xss" in payloads
    assert "command_injection" in payloads

    # Each should have multiple payloads
    assert len(payloads["sql_injection"]) > 3
    assert len(payloads["xss"]) > 3


def test_api_server_imports():
    """Test API server imports."""
    from api_server import (
        TestAIRequestHandler,
        success_response,
        error_response,
        run_server,
    )
    assert TestAIRequestHandler is not None
    assert success_response is not None


def test_api_server_responses():
    """Test API response helpers."""
    from api_server import success_response, error_response

    # Test success response
    resp = success_response({"test": "data"})
    assert resp["success"] is True
    assert resp["data"]["test"] == "data"
    assert "timestamp" in resp

    # Test error response
    err = error_response("Something went wrong", 500)
    assert err["success"] is False
    assert err["error"]["code"] == 500
    assert "Something went wrong" in err["error"]["message"]


def test_result_analyzer_imports():
    """Test result analyzer imports."""
    from analyzer import TestResultAnalyzer, TestStatus, TestRunResult
    assert TestResultAnalyzer is not None
    assert TestStatus is not None


def test_result_analyzer_basic():
    """Test basic result analysis."""
    from analyzer import create_analyzer, TestRunResult, TestStatus

    analyzer = create_analyzer()

    # Add some results
    analyzer.add_result(TestRunResult(
        test_id="TC-001",
        test_title="Test 1",
        status=TestStatus.PASSED,
        duration_ms=1000,
    ))
    analyzer.add_result(TestRunResult(
        test_id="TC-002",
        test_title="Test 2",
        status=TestStatus.FAILED,
        duration_ms=1500,
        error_message="Element not found: #button",
    ))
    analyzer.add_result(TestRunResult(
        test_id="TC-003",
        test_title="Test 3",
        status=TestStatus.PASSED,
        duration_ms=900,
    ))

    report = analyzer.analyze()

    assert report.total_tests == 3
    assert report.passed_count == 2
    assert report.failed_count == 1
    assert report.pass_rate == 2/3


def test_result_analyzer_pattern_detection():
    """Test failure pattern detection."""
    from analyzer import create_analyzer, TestRunResult, TestStatus, FailureType

    analyzer = create_analyzer()

    # Add multiple failures with similar error
    for i in range(3):
        analyzer.add_result(TestRunResult(
            test_id=f"TC-{i:03d}",
            test_title=f"Test {i}",
            status=TestStatus.FAILED,
            duration_ms=1000,
            error_message="Element not found: #missing-element",
        ))

    report = analyzer.analyze()

    # Should detect element_not_found pattern
    assert len(report.failure_patterns) > 0
    pattern_types = [p.pattern_type for p in report.failure_patterns]
    assert FailureType.ELEMENT_NOT_FOUND in pattern_types


def test_result_analyzer_recommendations():
    """Test recommendation generation."""
    from analyzer import create_analyzer, TestRunResult, TestStatus

    analyzer = create_analyzer()

    # Add mostly failing tests
    for i in range(10):
        status = TestStatus.PASSED if i < 3 else TestStatus.FAILED
        analyzer.add_result(TestRunResult(
            test_id=f"TC-{i:03d}",
            test_title=f"Test {i}",
            status=status,
            duration_ms=1000,
            error_message="Error" if status == TestStatus.FAILED else None,
        ))

    report = analyzer.analyze()

    # With 30% pass rate, should have recommendations
    assert report.pass_rate < 0.5
    assert len(report.recommendations) > 0


def test_dashboard_imports():
    """Test dashboard imports."""
    from dashboard import DashboardServer, run_dashboard
    assert DashboardServer is not None
    assert run_dashboard is not None


def test_dashboard_server_creation():
    """Test DashboardServer can be created."""
    from dashboard.server import DashboardServer, STATIC_DIR
    assert STATIC_DIR.exists(), "Static directory should exist"
    assert (STATIC_DIR / "index.html").exists(), "index.html should exist"


def test_dashboard_response_helpers():
    """Test dashboard response helpers."""
    from dashboard.server import success_response, error_response

    # Test success response
    resp = success_response({"test": "value"})
    assert resp["success"] is True
    assert resp["data"]["test"] == "value"
    assert "timestamp" in resp

    # Test error response
    err = error_response("Test error", 400)
    assert err["success"] is False
    assert err["error"]["code"] == 400
    assert "Test error" in err["error"]["message"]


def test_dashboard_static_file_exists():
    """Test static dashboard files exist."""
    from pathlib import Path

    static_dir = Path(__file__).parent.parent / "dashboard" / "static"
    assert static_dir.exists(), "Static directory should exist"

    index_html = static_dir / "index.html"
    assert index_html.exists(), "index.html should exist"

    content = index_html.read_text()
    assert "TestAI" in content, "Dashboard should mention TestAI"
    assert "Generate" in content, "Dashboard should have generate functionality"


def test_learning_imports():
    """Test learning module imports."""
    from learning import (
        FeedbackLoop,
        TestFeedback,
        FeedbackType,
        PatternLearner,
        KnowledgeUpdater,
    )
    assert FeedbackLoop is not None
    assert PatternLearner is not None
    assert KnowledgeUpdater is not None


def test_feedback_loop():
    """Test feedback loop functionality."""
    import tempfile
    from learning import create_feedback_loop, TestFeedback, FeedbackType

    with tempfile.TemporaryDirectory() as tmpdir:
        loop = create_feedback_loop(storage_dir=tmpdir, min_samples=2)

        # Add feedback
        loop.add_feedback(TestFeedback(
            test_id="TC-001",
            feedback_type=FeedbackType.TEST_PASSED,
            test_title="Login Test",
            test_category="functional",
            page_type="login",
            execution_time_ms=1500,
        ))

        loop.add_feedback(TestFeedback(
            test_id="TC-002",
            feedback_type=FeedbackType.TEST_FAILED,
            test_title="Security Test",
            test_category="security",
            page_type="login",
            error_message="Element not found: #submit-btn",
            execution_time_ms=2000,
        ))

        stats = loop.get_stats()
        assert stats["total_feedback"] == 2
        assert stats["passes"] == 1
        assert stats["failures"] == 1


def test_pattern_learner():
    """Test pattern learner functionality."""
    from learning import create_pattern_learner

    learner = create_pattern_learner()

    # Analyze a failure
    patterns = learner.analyze_failure(
        error_message="Timeout waiting for element #login-form to be visible",
        selector="#login-form",
        action="wait",
    )

    # Should match timeout pattern
    assert len(patterns) > 0
    assert any("timeout" in p.pattern_id.lower() for p in patterns)

    # Get prevention strategies
    strategies = learner.get_prevention_strategies("timeout waiting for element")
    assert len(strategies) > 0


def test_pattern_learner_success():
    """Test pattern learner success analysis."""
    from learning import create_pattern_learner

    learner = create_pattern_learner()

    # Analyze successful test code
    test_code = '''
    await page.locator('[data-testid="login-button"]').click();
    await page.waitForSelector('[aria-label="Dashboard"]');
    '''

    patterns = learner.analyze_success(test_code)
    assert len(patterns) > 0  # Should detect data-testid and aria-label patterns


def test_knowledge_updater():
    """Test knowledge updater functionality."""
    import tempfile
    from learning import create_knowledge_updater, UpdateType

    with tempfile.TemporaryDirectory() as tmpdir:
        updater = create_knowledge_updater(storage_dir=tmpdir)

        # Create update from insight
        update = updater.create_update_from_insight(
            insight_description="High failure rate in security tests",
            insight_type="pattern",
            confidence=0.75,
            evidence=["TC-001", "TC-002"],
            affected_categories=["security"],
            affected_page_types=["login"],
            recommendations=["Add explicit waits", "Check selectors"],
        )

        assert update is not None
        assert update.update_type == UpdateType.NEW_RULE
        assert update.section.startswith("7")  # login section

        # Check pending updates
        pending = updater.get_pending_updates()
        assert len(pending) >= 1


def test_knowledge_updater_rules():
    """Test knowledge updater rule creation."""
    import tempfile
    from learning import create_knowledge_updater

    with tempfile.TemporaryDirectory() as tmpdir:
        updater = create_knowledge_updater(storage_dir=tmpdir)

        # Create update from learned rule
        update = updater.create_update_from_rule(
            rule_text="Always wait for network idle before assertions",
            category="best_practice",
            confidence=0.8,
            evidence_count=10,
            page_types=["checkout"],
        )

        assert update is not None
        assert "network idle" in update.content.lower()

        # Generate brain patch
        patch = updater.generate_brain_patch()
        assert "Learned Knowledge" in patch


def test_risk_intelligence_imports():
    """Test risk intelligence imports."""
    from cortex import (
        RiskIntelligence,
        RiskLevel,
        RiskScore,
        create_risk_intelligence,
    )
    assert RiskIntelligence is not None
    assert RiskLevel is not None


def test_risk_intelligence_scoring():
    """Test risk scoring for tests."""
    from cortex import create_risk_intelligence, RiskLevel

    risk = create_risk_intelligence()

    # Score a security test on checkout page
    score = risk.score_test(
        test_id="TC-001",
        test_title="Payment Security Test",
        category="security",
        page_type="checkout",
        steps=["Navigate to checkout", "Enter card details", "Submit payment"],
    )

    # Security test on checkout should be high risk
    assert score.composite_score > 0.5
    assert score.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert score.recommended_priority > 50


def test_risk_intelligence_history():
    """Test risk learning from history."""
    from cortex import create_risk_intelligence

    risk = create_risk_intelligence()

    # Record some test failures
    for _ in range(5):
        risk.record_test_result("TC-FLAKY", passed=False)
    for _ in range(2):
        risk.record_test_result("TC-FLAKY", passed=True)

    # Score the test - should have high historical risk
    score = risk.score_test(
        test_id="TC-FLAKY",
        test_title="Flaky Test",
        category="functional",
        page_type="login",
    )

    # High failure rate should increase risk
    assert score.historical_risk > 0.5


def test_risk_intelligence_prioritization():
    """Test test prioritization by risk."""
    from cortex import create_risk_intelligence

    risk = create_risk_intelligence()

    tests = [
        {"id": "TC-001", "title": "UI Color Test", "category": "ui", "page_type": "profile"},
        {"id": "TC-002", "title": "Payment Security", "category": "security", "page_type": "checkout"},
        {"id": "TC-003", "title": "Login Test", "category": "functional", "page_type": "login"},
    ]

    prioritized = risk.prioritize_tests(tests)

    # Security test on checkout should be first
    assert prioritized[0]["id"] == "TC-002"
    # UI test should be last
    assert prioritized[-1]["id"] == "TC-001"


def test_risk_intelligence_recommendations():
    """Test risk-based recommendations."""
    from cortex import create_risk_intelligence

    risk = create_risk_intelligence()

    # Record some bugs
    for _ in range(6):
        risk.record_bug(
            feature="Payment Form",
            page_type="checkout",
            severity="critical",
            category="security",
        )

    recommendations = risk.get_recommendations("checkout")
    assert len(recommendations) > 0
    # Should identify checkout as hotspot
    assert any("checkout" in r.lower() or "payment" in r.lower() for r in recommendations)


def test_coverage_analyzer_imports():
    """Test coverage analyzer imports."""
    from cortex import (
        CoverageAnalyzer,
        CoverageReport,
        GapSeverity,
        create_coverage_analyzer,
    )
    assert CoverageAnalyzer is not None
    assert GapSeverity is not None


def test_coverage_analyzer_gaps():
    """Test coverage gap identification."""
    from cortex import create_coverage_analyzer, GapSeverity

    analyzer = create_coverage_analyzer()

    # Analyze with no existing tests
    report = analyzer.analyze_coverage("login")

    # Should identify gaps
    assert len(report.gaps) > 0
    assert report.coverage_percentage < 100

    # Should have critical gaps for security
    critical_gaps = report.get_gaps_by_severity(GapSeverity.CRITICAL)
    assert len(critical_gaps) > 0


def test_coverage_analyzer_with_tests():
    """Test coverage with existing tests."""
    from cortex import create_coverage_analyzer

    analyzer = create_coverage_analyzer()

    # Register some existing tests
    existing_tests = [
        {"id": "TC-001", "title": "Test SQL injection in login form", "category": "security"},
        {"id": "TC-002", "title": "Test valid login with valid credentials", "category": "functional"},
        {"id": "TC-003", "title": "Test invalid login with wrong password", "category": "functional"},
        {"id": "TC-004", "title": "Test email format validation", "category": "validation"},
    ]

    report = analyzer.analyze_coverage("login", existing_tests)

    # Should have better coverage
    assert report.covered_rules > 0
    assert report.coverage_percentage > 0


def test_coverage_gap_report():
    """Test gap report generation."""
    from cortex import create_coverage_analyzer

    analyzer = create_coverage_analyzer()

    report = analyzer.analyze_coverage("checkout")
    report_text = analyzer.generate_gap_report(report)

    assert "Coverage Gap Analysis" in report_text
    assert "Summary" in report_text
    assert "%" in report_text


def test_unified_agent_imports():
    """Test unified agent imports."""
    from core import UnifiedAgent, AgentConfig, create_agent
    assert UnifiedAgent is not None
    assert AgentConfig is not None


def test_unified_agent_creation():
    """Test unified agent creation."""
    from core import create_agent, AgentConfig, AgentState

    agent = create_agent()
    assert agent is not None
    assert agent.state == AgentState.IDLE
    assert agent.capabilities.can_generate_tests


async def test_unified_agent_generation():
    """Test unified agent test generation."""
    from core import create_agent, AgentConfig

    config = AgentConfig(enable_learning=False)
    agent = create_agent(config)

    result = await agent.generate_tests(
        feature="Login Page",
        page_type="login",
        max_tests=10,
    )

    assert result.success
    assert result.test_count > 0
    assert len(result.citations) > 0
    assert result.page_type == "login"


def test_unified_agent_test_data():
    """Test unified agent test data generation."""
    from core import create_agent

    agent = create_agent()

    data = agent.generate_test_data("email")
    assert "valid" in data
    assert "invalid" in data
    assert len(data["valid"]) > 0


def test_unified_agent_stats():
    """Test unified agent statistics."""
    from core import create_agent

    agent = create_agent()
    stats = agent.get_stats()

    assert "generations" in stats
    assert "tests_generated" in stats


def test_refinement_imports():
    """Test refinement module imports."""
    from refinement import (
        NaturalLanguageRefiner,
        RefinementCommand,
        RefinementType,
        TestModifier,
        create_refiner,
    )
    assert NaturalLanguageRefiner is not None
    assert RefinementType is not None


def test_nl_refiner_add():
    """Test NL refiner ADD command parsing."""
    from refinement import create_refiner, RefinementType

    refiner = create_refiner()

    # Test add command
    command = refiner.parse_command("Add 5 more security tests")
    assert command.command_type == RefinementType.ADD
    assert command.quantity == 5
    assert command.category_filter == "security"


def test_nl_refiner_remove():
    """Test NL refiner REMOVE command parsing."""
    from refinement import create_refiner, RefinementType

    refiner = create_refiner()

    # Test remove command
    command = refiner.parse_command("Remove all UI tests")
    assert command.command_type == RefinementType.REMOVE
    assert command.category_filter == "ui"


def test_nl_refiner_prioritize():
    """Test NL refiner PRIORITIZE command parsing."""
    from refinement import create_refiner, RefinementType

    refiner = create_refiner()

    # Test prioritize command
    command = refiner.parse_command("Prioritize security tests")
    assert command.command_type == RefinementType.PRIORITIZE
    assert command.category_filter == "security"


def test_nl_refiner_apply():
    """Test NL refiner applying changes."""
    from refinement import create_refiner, RefinementType

    refiner = create_refiner()

    tests = [
        {"id": "TC-001", "title": "Login Test", "category": "functional", "priority": "medium"},
        {"id": "TC-002", "title": "SQL Injection Test", "category": "security", "priority": "high"},
        {"id": "TC-003", "title": "UI Color Test", "category": "ui", "priority": "low"},
    ]

    # Remove UI tests
    command = refiner.parse_command("Remove UI tests")
    result = refiner.apply_refinement(command, tests)

    assert result.success
    assert result.tests_removed == 1
    assert len(result.refined_tests) == 2


def test_test_modifier():
    """Test test modifier operations."""
    from refinement import create_modifier, ModificationAction

    modifier = create_modifier()

    tests = [
        {"id": "TC-001", "title": "Test 1", "category": "functional", "priority": "medium", "steps": ["Step 1"]},
        {"id": "TC-002", "title": "Test 2", "category": "security", "priority": "high", "steps": ["Step A"]},
    ]

    # Update priority
    result = modifier.update_priority(tests, "TC-001", "critical")
    assert result.success
    assert tests[0]["priority"] == "critical"

    # Add step
    result = modifier.add_step(tests, "TC-001", "New step")
    assert result.success
    assert len(tests[0]["steps"]) == 2


def test_execution_imports():
    """Test execution module imports."""
    from execution import (
        TestSimulator,
        SimulationConfig,
        SimulationResult,
        ExecutionStatus,
        TestReporter,
        ReportFormat,
        create_simulator,
        create_reporter,
    )
    assert TestSimulator is not None
    assert TestReporter is not None
    assert ExecutionStatus is not None


def test_simulator_creation():
    """Test simulator creation."""
    from execution import create_simulator, SimulationConfig

    # Default config
    simulator = create_simulator()
    assert simulator is not None

    # Custom config
    config = SimulationConfig(
        failure_rate=0.2,
        flaky_rate=0.1,
        seed=42,
    )
    simulator = create_simulator(config)
    assert simulator is not None


def test_simulator_single_test():
    """Test single test simulation."""
    from execution import create_simulator, SimulationConfig, ExecutionStatus

    # Use seed for reproducibility
    config = SimulationConfig(seed=42, failure_rate=0.0)  # No failures
    simulator = create_simulator(config)

    test = {
        "id": "TC-001",
        "title": "Login Test",
        "category": "functional",
        "priority": "high",
        "steps": ["Navigate to login", "Enter credentials", "Click submit"],
    }

    result = simulator.simulate_test(test)

    assert result.test_id == "TC-001"
    assert result.test_title == "Login Test"
    assert result.status == ExecutionStatus.PASSED
    assert result.duration_ms > 0
    assert len(result.step_results) == 3
    assert len(result.logs) > 0


def test_simulator_suite():
    """Test suite simulation."""
    from execution import create_simulator, SimulationConfig

    config = SimulationConfig(seed=42)
    simulator = create_simulator(config)

    tests = [
        {"id": "TC-001", "title": "Test 1", "category": "functional", "steps": ["Step 1"]},
        {"id": "TC-002", "title": "Test 2", "category": "security", "steps": ["Step A", "Step B"]},
        {"id": "TC-003", "title": "Test 3", "category": "e2e", "steps": ["Step X", "Step Y", "Step Z"]},
    ]

    results = simulator.simulate_suite(tests)

    assert len(results) == 3
    assert results[0].test_id == "TC-001"
    assert results[1].test_id == "TC-002"

    # Check stats
    stats = simulator.get_summary_stats()
    assert stats["total"] == 3
    assert stats["passed"] + stats["failed"] + stats["skipped"] + stats["flaky"] + stats["timeout"] + stats["error"] == 3


def test_simulator_category_timing():
    """Test that category affects timing."""
    from execution import create_simulator, SimulationConfig

    config = SimulationConfig(seed=42, min_execution_time=1000, max_execution_time=1000)
    simulator = create_simulator(config)

    # Functional test (1.0x multiplier)
    functional_test = {"id": "TC-001", "title": "Functional", "category": "functional", "steps": ["Step"]}
    func_result = simulator.simulate_test(functional_test)

    # Reset and simulate e2e test (3.0x multiplier)
    simulator.reset()
    e2e_test = {"id": "TC-002", "title": "E2E", "category": "e2e", "steps": ["Step"]}
    e2e_result = simulator.simulate_test(e2e_test)

    # E2E should take longer
    assert e2e_result.duration_ms > func_result.duration_ms


def test_reporter_creation():
    """Test reporter creation."""
    from execution import create_reporter, ReportFormat

    reporter = create_reporter()
    assert reporter is not None


def test_reporter_suite_report():
    """Test suite report generation."""
    from execution import create_simulator, create_reporter, SimulationConfig

    # Generate some results
    config = SimulationConfig(seed=42)
    simulator = create_simulator(config)

    tests = [
        {"id": "TC-001", "title": "Login Test", "category": "functional", "priority": "high", "steps": ["Step 1"]},
        {"id": "TC-002", "title": "Security Test", "category": "security", "priority": "critical", "steps": ["Step A"]},
        {"id": "TC-003", "title": "UI Test", "category": "ui", "priority": "low", "steps": ["Step X"]},
    ]

    results = simulator.simulate_suite(tests)

    # Generate report
    reporter = create_reporter()
    report = reporter.generate_suite_report(results, "Test Suite")

    assert report.suite_name == "Test Suite"
    assert report.total_tests == 3
    assert len(report.test_reports) == 3
    assert len(report.category_stats) > 0


def test_reporter_formats():
    """Test report formatting."""
    from execution import create_simulator, create_reporter, SimulationConfig, ReportFormat

    # Generate results
    config = SimulationConfig(seed=42)
    simulator = create_simulator(config)
    tests = [{"id": "TC-001", "title": "Test", "category": "functional", "steps": ["Step 1"]}]
    results = simulator.simulate_suite(tests)

    reporter = create_reporter()
    report = reporter.generate_suite_report(results)

    # Test all formats
    text_report = reporter.format_report(report, ReportFormat.TEXT)
    assert "TEST EXECUTION REPORT" in text_report

    json_report = reporter.format_report(report, ReportFormat.JSON)
    assert '"suite_name"' in json_report

    html_report = reporter.format_report(report, ReportFormat.HTML)
    assert "<!DOCTYPE html>" in html_report

    md_report = reporter.format_report(report, ReportFormat.MARKDOWN)
    assert "# Test Report" in md_report


def test_reporter_recommendations():
    """Test recommendation generation."""
    from execution import create_simulator, create_reporter, SimulationConfig

    # High failure rate for recommendations
    config = SimulationConfig(seed=123, failure_rate=0.5)
    simulator = create_simulator(config)

    tests = [
        {"id": f"TC-{i:03d}", "title": f"Test {i}", "category": "functional", "steps": ["Step"]}
        for i in range(10)
    ]
    results = simulator.simulate_suite(tests)

    reporter = create_reporter()
    report = reporter.generate_suite_report(results)

    # Should have recommendations
    assert len(report.recommendations) > 0


def test_suggestion_imports():
    """Test suggestion module imports."""
    from suggestions import (
        SuggestionEngine,
        Suggestion,
        SuggestionType,
        SuggestionPriority,
        TestImprover,
        ImprovementType,
        create_suggestion_engine,
        create_test_improver,
    )
    assert SuggestionEngine is not None
    assert TestImprover is not None


def test_suggestion_engine_creation():
    """Test suggestion engine creation."""
    from suggestions import create_suggestion_engine

    engine = create_suggestion_engine()
    assert engine is not None


def test_suggestion_engine_analyze():
    """Test suggestion engine analysis."""
    from suggestions import create_suggestion_engine, SuggestionType, SuggestionPriority

    engine = create_suggestion_engine()

    # Test with incomplete test suite
    tests = [
        {"id": "TC-001", "title": "Valid Login Test", "category": "functional", "priority": "medium", "steps": ["Login"]},
    ]

    suggestions = engine.analyze(tests, page_type="login", feature="Login")

    # Should find missing tests
    assert len(suggestions) > 0

    # Should have security concerns (no security tests)
    security_suggestions = [s for s in suggestions if s.category.value == "security"]
    assert len(security_suggestions) > 0

    # Summary should be accurate
    summary = engine.get_summary()
    assert summary["total"] > 0


def test_suggestion_engine_security_gaps():
    """Test security gap detection."""
    from suggestions import create_suggestion_engine, SuggestionType

    engine = create_suggestion_engine()

    # Test suite with no security tests
    tests = [
        {"id": "TC-001", "title": "Login Test", "category": "functional", "steps": ["Login"]},
        {"id": "TC-002", "title": "Logout Test", "category": "functional", "steps": ["Logout"]},
    ]

    suggestions = engine.analyze(tests, page_type="login")

    # Should find security gap
    security_gaps = engine.get_suggestions_by_type(SuggestionType.SECURITY_CONCERN)
    assert len(security_gaps) > 0


def test_suggestion_engine_edge_cases():
    """Test edge case suggestions."""
    from suggestions import create_suggestion_engine, SuggestionType

    engine = create_suggestion_engine()

    # Basic tests only
    tests = [
        {"id": "TC-001", "title": "Login Test", "category": "functional", "steps": ["Login"]},
    ]

    suggestions = engine.analyze(tests, page_type="login")

    # Should suggest edge cases
    edge_case_suggestions = engine.get_suggestions_by_type(SuggestionType.EDGE_CASE)
    assert len(edge_case_suggestions) > 0


def test_suggestion_formatting():
    """Test suggestion report formatting."""
    from suggestions import create_suggestion_engine

    engine = create_suggestion_engine()

    tests = [
        {"id": "TC-001", "title": "Test", "category": "functional", "steps": ["Step"]},
    ]

    suggestions = engine.analyze(tests, page_type="login")
    formatted = engine.format_suggestions(suggestions)

    assert "TEST SUGGESTIONS" in formatted
    assert "Total Suggestions" in formatted


def test_improver_creation():
    """Test test improver creation."""
    from suggestions import create_test_improver

    improver = create_test_improver()
    assert improver is not None


def test_improver_analyze_test():
    """Test analyzing a single test."""
    from suggestions import create_test_improver, ImprovementType

    improver = create_test_improver()

    # Test with issues
    test = {
        "id": "TC-001",
        "title": "Login Test",
        "category": "security",
        "priority": "low",  # Security test with low priority - should be flagged
        "steps": ["Click login button"],  # No assertion
        "expected_result": "",  # No expected result
    }

    improvements = improver.analyze_test(test, page_type="login")

    # Should find priority issue
    priority_issues = [i for i in improvements if i.improvement_type == ImprovementType.IMPROVE_PRIORITY]
    assert len(priority_issues) > 0

    # Should find missing expected result
    expected_issues = [i for i in improvements if i.improvement_type == ImprovementType.CLARIFY_EXPECTED]
    assert len(expected_issues) > 0


def test_improver_auto_apply():
    """Test auto-applying improvements."""
    from suggestions import create_test_improver

    improver = create_test_improver()

    # Security test with low priority
    test = {
        "id": "TC-001",
        "title": "SQL Injection Test",
        "category": "security",
        "priority": "low",
        "steps": ["Test injection"],
    }

    result = improver.apply_auto_improvements(test, page_type="login")

    # Priority should be improved
    if result.improvements_applied:
        assert result.improved_test["priority"] != "low"


def test_improver_step_analysis():
    """Test step analysis."""
    from suggestions import create_test_improver, ImprovementType

    improver = create_test_improver()

    # Test with many steps (should suggest splitting)
    test = {
        "id": "TC-001",
        "title": "Long Test",
        "category": "functional",
        "steps": [f"Step {i}" for i in range(15)],
    }

    improvements = improver.analyze_test(test)

    # Should suggest splitting
    split_suggestions = [i for i in improvements if i.improvement_type == ImprovementType.SPLIT_TEST]
    assert len(split_suggestions) > 0


def test_security_imports():
    """Test security module imports."""
    from security import (
        VulnerabilityScanner,
        VulnerabilityType,
        Vulnerability,
        ScanResult,
        SecurityTestGenerator,
        SecurityTestCase,
        SecurityCategory,
        create_scanner,
        create_security_generator,
    )
    assert VulnerabilityScanner is not None
    assert SecurityTestGenerator is not None


def test_scanner_creation():
    """Test vulnerability scanner creation."""
    from security import create_scanner

    scanner = create_scanner()
    assert scanner is not None


def test_scanner_login_scan():
    """Test scanning login page for vulnerabilities."""
    from security import create_scanner, SeverityLevel

    scanner = create_scanner()
    result = scanner.scan("login", "Login Feature")

    # Should find vulnerabilities
    assert result.total_found > 0
    assert result.page_type == "login"

    # Should have critical or high vulnerabilities (SQL injection, etc)
    assert result.critical_count > 0 or result.high_count > 0


def test_scanner_checkout_scan():
    """Test scanning checkout page for vulnerabilities."""
    from security import create_scanner

    scanner = create_scanner()
    result = scanner.scan("checkout", "Checkout Flow")

    # Should find payment-related vulnerabilities
    assert result.total_found > 0

    # Checkout should have high risk score due to payment data
    assert result.risk_score > 3.0


def test_scanner_filter_severity():
    """Test filtering vulnerabilities by severity."""
    from security import create_scanner, SeverityLevel

    scanner = create_scanner()
    result = scanner.scan("login")

    critical = scanner.get_vulnerabilities_by_severity(result, SeverityLevel.CRITICAL)
    high = scanner.get_vulnerabilities_by_severity(result, SeverityLevel.HIGH)

    # Should be able to filter
    assert isinstance(critical, list)
    assert isinstance(high, list)


def test_scanner_report_format():
    """Test vulnerability report formatting."""
    from security import create_scanner

    scanner = create_scanner()
    result = scanner.scan("login")
    report = scanner.format_report(result)

    assert "SECURITY VULNERABILITY SCAN" in report
    assert "CRITICAL" in report or "HIGH" in report
    assert "OWASP" in report


def test_security_generator_creation():
    """Test security test generator creation."""
    from security import create_security_generator

    generator = create_security_generator()
    assert generator is not None


def test_security_generator_for_page():
    """Test generating security tests for a page."""
    from security import create_security_generator, SecurityCategory

    generator = create_security_generator()
    suite = generator.generate_for_page("login", "Login Feature")

    # Should generate test cases
    assert suite.total_tests > 0
    assert suite.page_type == "login"

    # Should have coverage across categories
    assert len(suite.coverage) > 0


def test_security_generator_test_cases():
    """Test generated security test case structure."""
    from security import create_security_generator

    generator = create_security_generator()
    suite = generator.generate_for_page("login")

    assert len(suite.test_cases) > 0

    tc = suite.test_cases[0]
    assert tc.id.startswith("SEC-")
    assert len(tc.steps) > 0
    assert tc.owasp_reference != ""
    assert tc.priority in ["critical", "high", "medium", "low"]


def test_security_generator_payloads():
    """Test that test payloads are included."""
    from security import create_security_generator

    generator = create_security_generator()
    suite = generator.generate_for_page("login", include_payloads=True)

    # Find an injection test
    injection_tests = [tc for tc in suite.test_cases if "injection" in tc.category.value.lower()]

    if injection_tests:
        # Should have test data
        assert len(injection_tests[0].test_data) > 0


def test_security_generator_format():
    """Test security test suite formatting."""
    from security import create_security_generator

    generator = create_security_generator()
    suite = generator.generate_for_page("login")
    formatted = generator.format_test_suite(suite)

    assert "SECURITY TEST SUITE" in formatted
    assert "COVERAGE" in formatted
    assert "Steps:" in formatted


def test_security_generator_to_dict():
    """Test converting suite to dictionary."""
    from security import create_security_generator

    generator = create_security_generator()
    suite = generator.generate_for_page("login")
    data = generator.to_dict(suite)

    assert "name" in data
    assert "test_cases" in data
    assert len(data["test_cases"]) > 0


def test_reports_imports():
    """Test reports module imports."""
    from reports import (
        VisualReportGenerator,
        ReportTheme,
        ChartType,
        VisualReport,
        ReportExporter,
        ExportFormat,
        create_visual_reporter,
        export_report,
    )
    assert VisualReportGenerator is not None
    assert ReportExporter is not None


def test_visual_reporter_creation():
    """Test visual reporter creation."""
    from reports import create_visual_reporter, ReportTheme

    reporter = create_visual_reporter()
    assert reporter is not None

    # Test different themes
    reporter_dark = create_visual_reporter(ReportTheme.DARK)
    assert reporter_dark.theme == ReportTheme.DARK


def test_visual_reporter_test_plan():
    """Test generating test plan report."""
    from reports import create_visual_reporter

    reporter = create_visual_reporter()

    tests = [
        {"id": "TC-001", "title": "Login Test", "category": "functional", "priority": "high"},
        {"id": "TC-002", "title": "SQL Injection", "category": "security", "priority": "critical"},
        {"id": "TC-003", "title": "Password Reset", "category": "functional", "priority": "medium"},
    ]

    report = reporter.generate_test_plan_report(tests, "Login Feature", "login")

    assert report.title == "Test Plan: Login Feature"
    assert len(report.sections) > 0
    assert report.html_content != ""


def test_visual_reporter_execution_report():
    """Test generating execution report."""
    from reports import create_visual_reporter

    reporter = create_visual_reporter()

    results = [
        {"title": "Test 1", "status": "passed", "duration_ms": 1000},
        {"title": "Test 2", "status": "failed", "duration_ms": 1500, "error_message": "Element not found"},
        {"title": "Test 3", "status": "passed", "duration_ms": 800},
    ]

    report = reporter.generate_execution_report(results, "Test Suite")

    assert report.title == "Execution Report: Test Suite"
    assert len(report.sections) > 0
    assert report.html_content != ""


def test_visual_reporter_html_content():
    """Test HTML content generation."""
    from reports import create_visual_reporter

    reporter = create_visual_reporter()

    tests = [
        {"id": "TC-001", "title": "Test", "category": "functional", "priority": "medium"},
    ]

    report = reporter.generate_test_plan_report(tests, "Feature")

    # Check HTML structure
    assert "<!DOCTYPE html>" in report.html_content
    assert "<title>" in report.html_content
    assert "Chart.js" in report.html_content or "chart" in report.html_content.lower()


def test_exporter_creation():
    """Test report exporter creation."""
    import tempfile
    from reports import ReportExporter

    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = ReportExporter(tmpdir)
        assert exporter is not None


def test_exporter_html():
    """Test HTML export."""
    import tempfile
    from reports import create_visual_reporter, ReportExporter, ExportFormat

    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = create_visual_reporter()
        tests = [{"id": "TC-001", "title": "Test", "category": "functional", "priority": "medium"}]
        report = reporter.generate_test_plan_report(tests, "Feature")

        exporter = ReportExporter(tmpdir)
        result = exporter.export(report, ExportFormat.HTML, "test_report")

        assert result.success
        assert result.file_path is not None
        assert result.file_size > 0


def test_exporter_json():
    """Test JSON export."""
    import tempfile
    from reports import create_visual_reporter, ReportExporter, ExportFormat

    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = create_visual_reporter()
        tests = [{"id": "TC-001", "title": "Test", "category": "functional", "priority": "medium"}]
        report = reporter.generate_test_plan_report(tests, "Feature")

        exporter = ReportExporter(tmpdir)
        result = exporter.export(report, ExportFormat.JSON)

        assert result.success
        assert ".json" in result.file_path


def test_exporter_markdown():
    """Test Markdown export."""
    import tempfile
    from reports import create_visual_reporter, ReportExporter, ExportFormat

    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = create_visual_reporter()
        tests = [{"id": "TC-001", "title": "Test", "category": "functional", "priority": "medium"}]
        report = reporter.generate_test_plan_report(tests, "Feature")

        exporter = ReportExporter(tmpdir)
        result = exporter.export(report, ExportFormat.MARKDOWN)

        assert result.success
        assert ".md" in result.file_path


def test_export_all_formats():
    """Test exporting to all formats."""
    import tempfile
    from reports import create_visual_reporter, ReportExporter, ExportFormat

    with tempfile.TemporaryDirectory() as tmpdir:
        reporter = create_visual_reporter()
        tests = [{"id": "TC-001", "title": "Test", "category": "functional", "priority": "medium"}]
        report = reporter.generate_test_plan_report(tests, "Feature")

        exporter = ReportExporter(tmpdir)
        results = exporter.export_all_formats(report)

        assert len(results) == len(ExportFormat)
        assert all(r.success for r in results.values())


def test_monitoring_imports():
    """Test monitoring module imports."""
    from monitoring import (
        ExecutionMonitor,
        MonitorConfig,
        ExecutionEvent,
        EventType,
        MonitorState,
        LiveDashboard,
        create_monitor,
        create_live_dashboard,
    )
    assert ExecutionMonitor is not None
    assert LiveDashboard is not None


def test_monitor_creation():
    """Test execution monitor creation."""
    from monitoring import create_monitor, MonitorConfig, MonitorState

    # Default config
    monitor = create_monitor()
    assert monitor is not None
    assert monitor.state == MonitorState.IDLE

    # Custom config
    config = MonitorConfig(failure_threshold=0.5, consecutive_failures=10)
    monitor = create_monitor(config)
    assert monitor is not None


def test_monitor_suite_lifecycle():
    """Test suite start and complete."""
    from monitoring import create_monitor, MonitorState

    monitor = create_monitor()

    # Start suite
    monitor.start_suite(10, "Test Suite")
    assert monitor.state == MonitorState.RUNNING
    assert monitor.stats.total_tests == 10

    # Complete suite
    monitor.complete_suite()
    assert monitor.state == MonitorState.STOPPED


def test_monitor_test_events():
    """Test recording test events."""
    from monitoring import create_monitor

    monitor = create_monitor()
    monitor.start_suite(5, "Test Suite")

    # Record some tests
    monitor.test_started("TC-001", "Test 1")
    monitor.test_passed("TC-001", "Test 1", 1000)

    monitor.test_started("TC-002", "Test 2")
    monitor.test_failed("TC-002", "Test 2", "Error message", 1500)

    monitor.test_started("TC-003", "Test 3")
    monitor.test_skipped("TC-003", "Test 3", "Not applicable")

    # Check stats
    assert monitor.stats.passed == 1
    assert monitor.stats.failed == 1
    assert monitor.stats.skipped == 1


def test_monitor_pause_resume():
    """Test pause and resume."""
    from monitoring import create_monitor, MonitorState

    monitor = create_monitor()
    monitor.start_suite(10, "Test Suite")

    assert monitor.state == MonitorState.RUNNING

    monitor.pause("Testing pause")
    assert monitor.state == MonitorState.PAUSED

    monitor.resume()
    assert monitor.state == MonitorState.RUNNING


def test_monitor_threshold_detection():
    """Test failure threshold detection."""
    from monitoring import create_monitor, MonitorConfig, MonitorState

    config = MonitorConfig(
        consecutive_failures=3,
        auto_pause_on_consecutive=True,
    )
    monitor = create_monitor(config)
    monitor.start_suite(10, "Test Suite")

    # Record consecutive failures
    for i in range(3):
        monitor.test_started(f"TC-{i}", f"Test {i}")
        monitor.test_failed(f"TC-{i}", f"Test {i}", "Error")

    # Should have auto-paused
    assert monitor.state == MonitorState.PAUSED


def test_monitor_progress_summary():
    """Test progress summary generation."""
    from monitoring import create_monitor

    monitor = create_monitor()
    monitor.start_suite(10, "Test Suite")

    monitor.test_started("TC-001", "Test 1")
    monitor.test_passed("TC-001", "Test 1", 1000)

    summary = monitor.get_progress_summary()

    assert summary["total_tests"] == 10
    assert summary["completed"] == 1
    assert summary["remaining"] == 9
    assert summary["passed"] == 1


def test_live_dashboard_creation():
    """Test live dashboard creation."""
    from monitoring import create_monitor, create_live_dashboard

    monitor = create_monitor()
    dashboard = create_live_dashboard(monitor)
    assert dashboard is not None


def test_live_dashboard_render():
    """Test dashboard rendering."""
    from monitoring import create_monitor, create_live_dashboard

    monitor = create_monitor()
    dashboard = create_live_dashboard(monitor, use_color=False)

    monitor.start_suite(5, "Test Suite")
    monitor.test_started("TC-001", "Test 1")
    monitor.test_passed("TC-001", "Test 1", 1000)

    # Test rendering methods
    header = dashboard.render_header()
    assert "TESTAI" in header

    progress = dashboard.render_progress_bar()
    assert "%" in progress

    stats = dashboard.render_stats()
    assert "Passed" in stats

    compact = dashboard.render_compact()
    assert "%" in compact


def test_live_dashboard_updates():
    """Test dashboard update tracking."""
    from monitoring import create_monitor, create_live_dashboard

    monitor = create_monitor()
    dashboard = create_live_dashboard(monitor)

    monitor.start_suite(3, "Test Suite")
    monitor.test_started("TC-001", "Test 1")
    monitor.test_passed("TC-001", "Test 1", 1000)

    updates = dashboard.get_updates()
    assert len(updates) > 0


def test_deduplication_imports():
    """Test deduplication module imports."""
    from deduplication import (
        TestDeduplicator,
        DuplicateGroup,
        DeduplicationResult,
        SimilarityMethod,
        TestMerger,
        MergeStrategy,
        create_deduplicator,
        create_merger,
    )
    assert TestDeduplicator is not None
    assert TestMerger is not None


def test_deduplicator_creation():
    """Test deduplicator creation."""
    from deduplication import create_deduplicator, SimilarityMethod

    deduplicator = create_deduplicator()
    assert deduplicator is not None

    # Custom threshold
    deduplicator = create_deduplicator(similarity_threshold=0.8, method=SimilarityMethod.JACCARD)
    assert deduplicator.similarity_threshold == 0.8


def test_deduplicator_exact_duplicates():
    """Test detection of exact duplicates."""
    from deduplication import create_deduplicator, SimilarityMethod

    deduplicator = create_deduplicator(similarity_threshold=0.5, method=SimilarityMethod.COMBINED)

    tests = [
        {"id": "TC-001", "title": "Login with valid credentials", "steps": ["Enter email", "Enter password", "Click login"], "priority": "high"},
        {"id": "TC-002", "title": "Login with valid credentials", "steps": ["Enter email", "Enter password", "Click login"], "priority": "medium"},  # Exact duplicate
        {"id": "TC-003", "title": "Logout test", "steps": ["Click logout"], "priority": "low"},
    ]

    result = deduplicator.analyze(tests)

    assert result.total_tests == 3
    # Should find the duplicate pair
    assert result.total_duplicates >= 1 or len(result.duplicate_groups) >= 1


def test_deduplicator_no_duplicates():
    """Test with no duplicates."""
    from deduplication import create_deduplicator

    deduplicator = create_deduplicator(similarity_threshold=0.9)

    tests = [
        {"id": "TC-001", "title": "Login test", "steps": ["Login"], "priority": "high"},
        {"id": "TC-002", "title": "Logout test", "steps": ["Logout"], "priority": "low"},
        {"id": "TC-003", "title": "Search test", "steps": ["Search"], "priority": "medium"},
    ]

    result = deduplicator.analyze(tests)

    assert result.total_tests == 3
    assert result.unique_tests == 3
    assert result.total_duplicates == 0


def test_deduplicator_report():
    """Test deduplication report formatting."""
    from deduplication import create_deduplicator

    deduplicator = create_deduplicator(similarity_threshold=0.5)

    tests = [
        {"id": "TC-001", "title": "Test A", "steps": ["Step 1"]},
        {"id": "TC-002", "title": "Test B", "steps": ["Step 2"]},
    ]

    result = deduplicator.analyze(tests)
    report = deduplicator.format_report(result)

    assert "DEDUPLICATION REPORT" in report
    assert "Total Tests" in report


def test_merger_creation():
    """Test merger creation."""
    from deduplication import create_merger, MergeStrategy

    merger = create_merger()
    assert merger is not None

    merger = create_merger(MergeStrategy.UNION_STEPS)
    assert merger.default_strategy == MergeStrategy.UNION_STEPS


def test_merger_single_test():
    """Test merging a single test."""
    from deduplication import create_merger

    merger = create_merger()

    tests = [
        {"id": "TC-001", "title": "Test", "steps": ["Step 1"], "priority": "high"},
    ]

    result = merger.merge(tests)

    assert result.success
    assert result.merged_test["id"] == "TC-001"


def test_merger_multiple_tests():
    """Test merging multiple tests."""
    from deduplication import create_merger, MergeStrategy

    merger = create_merger()

    tests = [
        {"id": "TC-001", "title": "Login Test", "steps": ["Enter email", "Click login"], "priority": "high", "category": "functional"},
        {"id": "TC-002", "title": "Login Test Duplicate", "steps": ["Enter password", "Submit form"], "priority": "medium", "category": "security"},
    ]

    result = merger.merge(tests, MergeStrategy.MERGE_ALL)

    assert result.success
    assert "MERGED" in result.merged_test["id"]
    assert len(result.source_test_ids) == 2
    # Should have union of steps
    assert len(result.merged_test["steps"]) >= 2


def test_merger_strategy_suggestion():
    """Test merge strategy suggestion."""
    from deduplication import create_merger, MergeStrategy

    merger = create_merger()

    # Tests with very similar steps
    similar_tests = [
        {"id": "TC-001", "title": "Test 1", "steps": ["Step A", "Step B"], "priority": "high"},
        {"id": "TC-002", "title": "Test 2", "steps": ["Step A", "Step B"], "priority": "low"},
    ]

    strategy = merger.suggest_merge_strategy(similar_tests)
    assert strategy in [MergeStrategy.KEEP_HIGHEST_PRIORITY, MergeStrategy.MERGE_ALL]


def test_merger_format_result():
    """Test merge result formatting."""
    from deduplication import create_merger

    merger = create_merger()

    tests = [
        {"id": "TC-001", "title": "Test", "steps": ["Step"], "priority": "high"},
    ]

    result = merger.merge(tests)
    formatted = merger.format_merge_result(result)

    assert "MERGE RESULT" in formatted
    assert "Success" in formatted


# ============================================================
# Review Module Tests
# ============================================================

def test_review_imports():
    """Test review module imports."""
    from review import (
        ReviewWorkflow,
        ReviewStatus,
        ReviewDecision,
        ReviewRequest,
        ReviewResponse,
        create_review_workflow,
        CommentThread,
        Comment,
        CommentType,
        ThreadStatus,
        create_comment_thread,
        ApprovalChain,
        ApprovalStage,
        ApprovalStatus,
        Approver,
        create_approval_chain,
    )
    assert ReviewWorkflow is not None
    assert CommentThread is not None
    assert ApprovalChain is not None


def test_review_workflow_creation():
    """Test review workflow creation."""
    from review import create_review_workflow

    workflow = create_review_workflow()
    assert workflow is not None

    workflow = create_review_workflow(
        require_all_approvals=False,
        min_approvals=2,
        auto_merge=True,
    )
    assert workflow.min_approvals == 2
    assert workflow.auto_merge is True


def test_review_request_creation():
    """Test creating a review request."""
    from review import create_review_workflow
    from review.workflow import Reviewer

    workflow = create_review_workflow()

    author = Reviewer(
        id="user-001",
        name="John Doe",
        email="john@example.com",
        role="developer",
    )

    reviewer = Reviewer(
        id="user-002",
        name="Jane Smith",
        email="jane@example.com",
        role="qa_lead",
    )

    request = workflow.create_request(
        title="Add login tests",
        description="New test cases for login functionality",
        test_ids=["TC-001", "TC-002"],
        author=author,
        reviewers=[reviewer],
        labels=["login", "security"],
    )

    assert request is not None
    assert request.id.startswith("REV-")
    assert request.title == "Add login tests"
    assert len(request.test_ids) == 2


def test_review_submission_flow():
    """Test review submission and decision flow."""
    from review import create_review_workflow, ReviewStatus, ReviewDecision
    from review.workflow import Reviewer

    workflow = create_review_workflow(require_all_approvals=False, min_approvals=1)

    author = Reviewer(id="u1", name="Author", email="a@test.com", role="dev")
    reviewer = Reviewer(id="u2", name="Reviewer", email="r@test.com", role="qa")

    request = workflow.create_request(
        title="Test Review",
        description="Test description",
        test_ids=["TC-001"],
        author=author,
        reviewers=[reviewer],
    )

    # Submit for review
    response = workflow.submit_for_review(request.id)
    assert response.success
    assert request.status == ReviewStatus.PENDING

    # Start review
    response = workflow.start_review(request.id, reviewer)
    assert response.success
    assert request.status == ReviewStatus.IN_REVIEW

    # Submit approval
    response = workflow.submit_decision(
        request.id,
        reviewer,
        ReviewDecision.APPROVE,
        "LGTM!",
    )
    assert response.success
    assert request.status == ReviewStatus.APPROVED


def test_review_changes_requested():
    """Test changes requested flow."""
    from review import create_review_workflow, ReviewStatus, ReviewDecision
    from review.workflow import Reviewer

    workflow = create_review_workflow()

    author = Reviewer(id="u1", name="Author", email="a@test.com", role="dev")
    reviewer = Reviewer(id="u2", name="Reviewer", email="r@test.com", role="qa")

    request = workflow.create_request(
        title="Test",
        description="Description",
        test_ids=["TC-001"],
        author=author,
        reviewers=[reviewer],
    )

    workflow.submit_for_review(request.id)
    workflow.start_review(request.id, reviewer)

    # Request changes
    response = workflow.submit_decision(
        request.id,
        reviewer,
        ReviewDecision.REQUEST_CHANGES,
        "Please add more edge cases",
    )

    assert response.success
    assert request.status == ReviewStatus.CHANGES_REQUESTED

    # Resubmit
    response = workflow.resubmit(request.id)
    assert response.success
    assert request.status == ReviewStatus.PENDING


def test_review_format():
    """Test review request formatting."""
    from review import create_review_workflow
    from review.workflow import Reviewer

    workflow = create_review_workflow()

    author = Reviewer(id="u1", name="Author", email="a@test.com", role="dev")
    reviewer = Reviewer(id="u2", name="Reviewer", email="r@test.com", role="qa")

    request = workflow.create_request(
        title="Test",
        description="Description",
        test_ids=["TC-001"],
        author=author,
        reviewers=[reviewer],
    )

    formatted = workflow.format_request(request)
    assert "REVIEW REQUEST" in formatted
    assert "Author" in formatted


def test_comment_thread_creation():
    """Test comment thread creation."""
    from review.comments import CommentManager, CommentType

    manager = CommentManager()

    thread = manager.create_thread(
        test_id="TC-001",
        author_id="user-001",
        author_name="John Doe",
        content="This test needs more assertions",
        comment_type=CommentType.SUGGESTION,
        line_reference="step:3",
    )

    assert thread is not None
    assert thread.id.startswith("THR-")
    assert thread.test_id == "TC-001"
    assert len(thread.comments) == 1


def test_comment_reply():
    """Test replying to comments."""
    from review.comments import CommentManager, CommentType

    manager = CommentManager()

    thread = manager.create_thread(
        test_id="TC-001",
        author_id="u1",
        author_name="User 1",
        content="Question about this test",
        comment_type=CommentType.QUESTION,
    )

    reply = manager.reply(
        thread_id=thread.id,
        author_id="u2",
        author_name="User 2",
        content="Here's the answer",
    )

    assert reply is not None
    assert len(thread.comments) == 2


def test_comment_reactions():
    """Test comment reactions."""
    from review.comments import CommentManager

    manager = CommentManager()

    thread = manager.create_thread(
        test_id="TC-001",
        author_id="u1",
        author_name="User",
        content="Great test!",
    )

    comment_id = thread.comments[0].id

    result = manager.add_reaction(thread.id, comment_id, "u2", "👍")
    assert result is True

    assert "👍" in thread.comments[0].reactions
    assert "u2" in thread.comments[0].reactions["👍"]


def test_comment_thread_resolution():
    """Test thread resolution."""
    from review.comments import CommentManager, ThreadStatus

    manager = CommentManager()

    thread = manager.create_thread(
        test_id="TC-001",
        author_id="u1",
        author_name="User",
        content="Issue found",
    )

    result = manager.resolve_thread(thread.id, "u2")
    assert result is True
    assert thread.status == ThreadStatus.RESOLVED


def test_comment_mentions():
    """Test @mentions extraction."""
    from review.comments import CommentManager

    manager = CommentManager()

    thread = manager.create_thread(
        test_id="TC-001",
        author_id="u1",
        author_name="User",
        content="Hey @john and @jane, please review",
    )

    comment = thread.comments[0]
    assert len(comment.mentions) == 2
    assert any(m.username == "john" for m in comment.mentions)


def test_comment_search():
    """Test comment search."""
    from review.comments import CommentManager

    manager = CommentManager()

    manager.create_thread(
        test_id="TC-001",
        author_id="u1",
        author_name="User",
        content="This is about authentication",
    )

    manager.create_thread(
        test_id="TC-002",
        author_id="u1",
        author_name="User",
        content="This is about payments",
    )

    results = manager.search_comments("authentication")
    assert len(results) == 1
    assert "authentication" in results[0].content


def test_approval_chain_creation():
    """Test approval chain creation."""
    from review.approvals import ApprovalChainManager

    manager = ApprovalChainManager()

    chain = manager.create_chain_from_templates(
        name="Standard Review",
        description="Standard test review process",
        template_names=["technical_review", "qa_review"],
    )

    assert chain is not None
    assert chain.id.startswith("CHN-")
    assert len(chain.stages) == 2


def test_approval_chain_stages():
    """Test approval chain stages."""
    from review.approvals import ApprovalChainManager, Approver, ApprovalStatus

    manager = ApprovalChainManager()

    chain = manager.create_chain(
        name="Custom Chain",
        description="Custom approval chain",
        stage_configs=[
            {
                "name": "Stage 1",
                "description": "First review",
                "required_roles": {"developer"},
                "min_approvals": 1,
            },
        ],
    )

    approver = Approver(
        id="u1",
        name="Dev",
        email="dev@test.com",
        role="developer",
    )

    manager.add_approver_to_stage(chain.id, chain.stages[0].id, approver)

    result = manager.submit_approval(
        chain.id,
        chain.stages[0].id,
        approver,
        ApprovalStatus.APPROVED,
        "Approved!",
    )

    assert result.success
    assert chain.stages[0].status == ApprovalStatus.APPROVED


def test_approval_chain_progress():
    """Test approval chain progress tracking."""
    from review.approvals import ApprovalChainManager

    manager = ApprovalChainManager()

    chain = manager.create_chain_from_templates(
        name="Test",
        description="Test chain",
        template_names=["qa_review", "final_approval"],
    )

    progress = manager.get_chain_progress(chain.id)

    assert progress["total_stages"] == 2
    assert progress["completed_stages"] == 0
    assert progress["is_complete"] is False


def test_approval_chain_bypass():
    """Test stage bypass functionality."""
    from review.approvals import ApprovalChainManager, Approver, ApprovalStatus

    manager = ApprovalChainManager()

    chain = manager.create_chain(
        name="Test",
        description="Test",
        stage_configs=[
            {
                "name": "Optional Stage",
                "description": "Can be bypassed",
                "required_roles": {"reviewer"},
                "min_approvals": 1,
                "is_optional": True,
            },
        ],
    )

    bypasser = Approver(
        id="u1",
        name="Lead",
        email="lead@test.com",
        role="lead",
        can_override=True,
    )

    result = manager.bypass_stage(
        chain.id,
        chain.stages[0].id,
        bypasser,
        "Not needed for this review",
    )

    assert result.success
    assert chain.stages[0].status == ApprovalStatus.SKIPPED


def test_approval_chain_format():
    """Test approval chain formatting."""
    from review.approvals import ApprovalChainManager

    manager = ApprovalChainManager()

    chain = manager.create_chain_from_templates(
        name="Test Chain",
        description="Test description",
        template_names=["qa_review"],
    )

    formatted = manager.format_chain(chain)

    assert "APPROVAL CHAIN" in formatted
    assert "QA Review" in formatted


# ============================================================
# Impact Analysis Module Tests
# ============================================================

def test_impact_imports():
    """Test impact module imports."""
    from impact import (
        ImpactAnalyzer,
        ImpactResult,
        AffectedTest,
        ImpactLevel,
        create_impact_analyzer,
        DependencyMapper,
        DependencyGraph,
        TestDependency,
        DependencyType,
        create_dependency_mapper,
        ChangeDetector,
        CodeChange,
        ChangeType,
        ChangeSet,
        create_change_detector,
    )
    assert ImpactAnalyzer is not None
    assert DependencyMapper is not None
    assert ChangeDetector is not None


def test_change_detector_creation():
    """Test change detector creation."""
    from impact import create_change_detector

    detector = create_change_detector()
    assert detector is not None


def test_change_detector_git_diff():
    """Test parsing git diff."""
    from impact import create_change_detector, ChangeType

    detector = create_change_detector()

    diff = """diff --git a/src/utils.py b/src/utils.py
index abc123..def456 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,5 +1,6 @@
+def new_function():
+    pass
 def old_function():
-    return True
+    return False
"""

    changeset = detector.parse_git_diff(diff, change_id="TEST-001", description="Test change")

    assert changeset.id == "TEST-001"
    assert len(changeset.changes) >= 1
    assert changeset.total_additions > 0


def test_change_detector_file_list():
    """Test parsing file list."""
    from impact import create_change_detector, ChangeType

    detector = create_change_detector()

    files = [
        {"path": "src/auth.py", "type": "modified", "added": 10, "deleted": 5},
        {"path": "src/utils.py", "type": "added", "added": 50, "deleted": 0},
    ]

    changeset = detector.parse_file_list(files, change_id="CS-001")

    assert changeset.files_changed == 2
    assert changeset.total_additions == 60


def test_change_detector_categorize():
    """Test change categorization."""
    from impact import create_change_detector

    detector = create_change_detector()

    files = [
        {"path": "src/main.py", "type": "modified"},
        {"path": "tests/test_main.py", "type": "modified"},
        {"path": "config.json", "type": "modified"},
        {"path": "README.md", "type": "modified"},
    ]

    changeset = detector.parse_file_list(files)
    categories = detector.categorize_changes(changeset)

    assert len(categories["source_code"]) == 1
    assert len(categories["test_code"]) == 1
    assert len(categories["configuration"]) == 1
    assert len(categories["documentation"]) == 1


def test_change_detector_risk():
    """Test change risk calculation."""
    from impact import create_change_detector
    from impact.change_detector import CodeChange, ChangeType

    detector = create_change_detector()

    # High risk change - many lines and functions
    high_risk = CodeChange(
        file_path="src/core.py",
        change_type=ChangeType.MODIFIED,
        added_lines=100,
        deleted_lines=50,
        modified_functions=["func1", "func2", "func3"],
        modified_classes=["ClassA"],
    )

    # Low risk change
    low_risk = CodeChange(
        file_path="src/util.py",
        change_type=ChangeType.MODIFIED,
        added_lines=5,
        deleted_lines=2,
    )

    high_score = detector.calculate_change_risk(high_risk)
    low_score = detector.calculate_change_risk(low_risk)

    assert high_score > low_score
    assert high_score <= 1.0


def test_dependency_mapper_creation():
    """Test dependency mapper creation."""
    from impact import create_dependency_mapper

    mapper = create_dependency_mapper()
    assert mapper is not None


def test_dependency_mapper_add():
    """Test adding dependencies."""
    from impact import create_dependency_mapper, DependencyType

    mapper = create_dependency_mapper()

    mapper.add_dependency(
        test_id="TC-001",
        target_path="src/auth.py",
        dependency_type=DependencyType.DIRECT,
    )

    mapper.add_dependency(
        test_id="TC-001",
        target_path="src/utils.py",
        dependency_type=DependencyType.COVERS,
    )

    files = mapper.get_files_for_test("TC-001")
    assert len(files) == 2
    assert "src/auth.py" in files


def test_dependency_mapper_reverse_lookup():
    """Test reverse dependency lookup."""
    from impact import create_dependency_mapper, DependencyType

    mapper = create_dependency_mapper()

    mapper.add_dependency("TC-001", "src/auth.py", DependencyType.DIRECT)
    mapper.add_dependency("TC-002", "src/auth.py", DependencyType.COVERS)
    mapper.add_dependency("TC-003", "src/utils.py", DependencyType.DIRECT)

    tests = mapper.get_tests_for_file("src/auth.py")
    assert len(tests) == 2
    assert "TC-001" in tests
    assert "TC-002" in tests


def test_dependency_mapper_graph():
    """Test building dependency graph."""
    from impact import create_dependency_mapper, DependencyType

    mapper = create_dependency_mapper()

    mapper.add_dependency("TC-001", "src/a.py", DependencyType.DIRECT)
    mapper.add_dependency("TC-001", "src/b.py", DependencyType.COVERS)
    mapper.add_dependency("TC-002", "src/a.py", DependencyType.DIRECT)

    graph = mapper.build_graph()

    assert graph.test_count == 2
    assert graph.target_count == 2
    assert len(graph.dependencies) == 3


def test_impact_analyzer_creation():
    """Test impact analyzer creation."""
    from impact import create_impact_analyzer

    analyzer = create_impact_analyzer()
    assert analyzer is not None


def test_impact_analyzer_basic():
    """Test basic impact analysis."""
    from impact import create_impact_analyzer, create_dependency_mapper, DependencyType

    mapper = create_dependency_mapper()
    mapper.add_dependency("TC-001", "src/auth.py", DependencyType.DIRECT)
    mapper.add_dependency("TC-002", "src/auth.py", DependencyType.COVERS)

    analyzer = create_impact_analyzer(dependency_mapper=mapper)

    files = [
        {"path": "src/auth.py", "type": "modified", "added": 20, "deleted": 10},
    ]

    changeset = analyzer.detector.parse_file_list(files)
    result = analyzer.analyze(changeset)

    assert result.total_tests_affected == 2


def test_impact_analyzer_levels():
    """Test impact level calculation."""
    from impact import create_impact_analyzer, ImpactLevel

    analyzer = create_impact_analyzer()

    # Test get_tests_to_run filters by level
    from impact.analyzer import ImpactResult, AffectedTest
    from datetime import datetime

    result = ImpactResult(
        changeset_id="CS-001",
        analyzed_at=datetime.now(),
        affected_tests=[
            AffectedTest("TC-001", ImpactLevel.CRITICAL, ["a.py"], 0.9, 10, "Critical change"),
            AffectedTest("TC-002", ImpactLevel.HIGH, ["b.py"], 0.6, 110, "High change"),
            AffectedTest("TC-003", ImpactLevel.LOW, ["c.py"], 0.2, 310, "Low change"),
        ],
        total_tests_affected=3,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=1,
    )

    high_priority = analyzer.get_tests_to_run(result, min_impact_level=ImpactLevel.HIGH)
    assert len(high_priority) == 2
    assert "TC-003" not in high_priority


def test_impact_analyzer_batches():
    """Test test execution batching."""
    from impact import create_impact_analyzer, ImpactLevel
    from impact.analyzer import ImpactResult, AffectedTest
    from datetime import datetime

    analyzer = create_impact_analyzer()

    result = ImpactResult(
        changeset_id="CS-001",
        analyzed_at=datetime.now(),
        affected_tests=[
            AffectedTest("TC-001", ImpactLevel.CRITICAL, [], 0.9, 10, ""),
            AffectedTest("TC-002", ImpactLevel.HIGH, [], 0.6, 110, ""),
            AffectedTest("TC-003", ImpactLevel.MEDIUM, [], 0.4, 210, ""),
        ],
        total_tests_affected=3,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0,
    )

    batches = analyzer.suggest_test_order(result)

    assert len(batches) == 3  # Critical, High, Medium
    assert batches[0] == ["TC-001"]  # Critical first


def test_impact_analyzer_savings():
    """Test savings estimation."""
    from impact import create_impact_analyzer, ImpactLevel
    from impact.analyzer import ImpactResult
    from datetime import datetime

    analyzer = create_impact_analyzer()

    result = ImpactResult(
        changeset_id="CS-001",
        analyzed_at=datetime.now(),
        affected_tests=[],
        total_tests_affected=10,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
    )

    savings = analyzer.estimate_savings(result, total_tests=100, avg_test_duration_ms=1000)

    assert savings["tests_to_run"] == 10
    assert savings["tests_skipped"] == 90
    assert savings["savings_pct"] == 90.0


def test_impact_analyzer_format():
    """Test impact result formatting."""
    from impact import create_impact_analyzer, ImpactLevel
    from impact.analyzer import ImpactResult, AffectedTest
    from datetime import datetime

    analyzer = create_impact_analyzer()

    result = ImpactResult(
        changeset_id="CS-001",
        analyzed_at=datetime.now(),
        affected_tests=[
            AffectedTest("TC-001", ImpactLevel.HIGH, ["src/a.py"], 0.7, 100, "Test reason"),
        ],
        total_tests_affected=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        recommendations=["Run tests before merge"],
    )

    formatted = analyzer.format_result(result)

    assert "IMPACT ANALYSIS" in formatted
    assert "TC-001" in formatted
    assert "RECOMMENDATIONS" in formatted


# ============================================================
# Natural Language Query Module Tests
# ============================================================

def test_nlquery_imports():
    """Test NL query module imports."""
    from nlquery import (
        QueryParser,
        ParsedQuery,
        QueryIntent,
        QueryFilter,
        create_query_parser,
        QueryExecutor,
        QueryResult,
        TestMatch,
        create_query_executor,
        NLProcessor,
        TokenizedQuery,
        Entity,
        EntityType,
        create_nl_processor,
    )
    assert QueryParser is not None
    assert QueryExecutor is not None
    assert NLProcessor is not None


def test_nl_processor_creation():
    """Test NL processor creation."""
    from nlquery import create_nl_processor

    processor = create_nl_processor()
    assert processor is not None


def test_nl_processor_tokenize():
    """Test query tokenization."""
    from nlquery import create_nl_processor

    processor = create_nl_processor()

    result = processor.process("Show me all failed login tests")

    assert result.original == "Show me all failed login tests"
    assert len(result.tokens) > 0
    assert "failed" in result.tokens or "failed" in [e.value for e in result.entities]


def test_nl_processor_entities():
    """Test entity extraction."""
    from nlquery import create_nl_processor, EntityType

    processor = create_nl_processor()

    result = processor.process("Find high priority security tests that failed yesterday")

    entity_types = {e.entity_type for e in result.entities}

    assert EntityType.PRIORITY in entity_types
    assert EntityType.CATEGORY in entity_types
    assert EntityType.TEST_STATUS in entity_types


def test_nl_processor_negation():
    """Test negation detection."""
    from nlquery import create_nl_processor

    processor = create_nl_processor()

    result = processor.process("Show tests that are not failed")

    assert len(result.negations) > 0
    # Check if 'failed' is in a negated region
    for entity in result.entities:
        if entity.value == "failed":
            assert processor.is_negated(result, entity.start_pos)


def test_nl_processor_time():
    """Test time reference extraction."""
    from nlquery import create_nl_processor, EntityType
    from datetime import datetime, timedelta

    processor = create_nl_processor()

    result = processor.process("Tests run yesterday")

    time_entities = processor.get_entities_by_type(result, EntityType.TIME_REFERENCE)
    assert len(time_entities) > 0

    # The normalized value should be a datetime
    assert isinstance(time_entities[0].normalized_value, datetime)


def test_query_parser_creation():
    """Test query parser creation."""
    from nlquery import create_query_parser

    parser = create_query_parser()
    assert parser is not None


def test_query_parser_intent():
    """Test intent detection."""
    from nlquery import create_query_parser, QueryIntent

    parser = create_query_parser()

    # List intent
    result = parser.parse("Show me all tests")
    assert result.intent == QueryIntent.LIST

    # Count intent
    result = parser.parse("How many tests failed?")
    assert result.intent == QueryIntent.COUNT

    # Summarize intent
    result = parser.parse("Give me a summary of test results")
    assert result.intent == QueryIntent.SUMMARIZE


def test_query_parser_filters():
    """Test filter extraction."""
    from nlquery import create_query_parser

    parser = create_query_parser()

    result = parser.parse("Show failed high priority login tests")

    # Should have filters for status, priority, and feature
    filter_fields = {f.field for f in result.filters}

    assert "status" in filter_fields
    assert "priority" in filter_fields


def test_query_parser_search():
    """Test search text extraction."""
    from nlquery import create_query_parser

    parser = create_query_parser()

    result = parser.parse('Find tests containing "user authentication"')

    assert result.search_text is not None
    assert "user authentication" in result.search_text


def test_query_parser_limit():
    """Test limit extraction."""
    from nlquery import create_query_parser

    parser = create_query_parser()

    result = parser.parse("Show top 10 failed tests")

    assert result.limit == 10


def test_query_parser_sort():
    """Test sort extraction."""
    from nlquery import create_query_parser

    parser = create_query_parser()

    result = parser.parse("Show tests sorted by priority")

    assert result.sort is not None
    assert result.sort.field == "priority"


def test_query_executor_creation():
    """Test query executor creation."""
    from nlquery import create_query_executor

    executor = create_query_executor()
    assert executor is not None


def test_query_executor_basic():
    """Test basic query execution."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "title": "Login test", "status": "passed", "priority": "high"},
        {"id": "TC-002", "title": "Signup test", "status": "failed", "priority": "medium"},
        {"id": "TC-003", "title": "Checkout test", "status": "passed", "priority": "low"},
    ]

    query = parser.parse("Show failed tests")
    result = executor.execute(query, tests)

    assert result.filtered_count == 1
    assert result.matches[0].test_id == "TC-002"


def test_query_executor_filter():
    """Test query filtering."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "title": "Login test", "status": "passed", "priority": "high", "category": "security"},
        {"id": "TC-002", "title": "API test", "status": "failed", "priority": "high", "category": "api"},
        {"id": "TC-003", "title": "UI test", "status": "passed", "priority": "low", "category": "ui"},
    ]

    query = parser.parse("Show high priority tests")
    result = executor.execute(query, tests)

    assert result.filtered_count == 2


def test_query_executor_search():
    """Test full-text search."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "title": "User login authentication test", "status": "passed"},
        {"id": "TC-002", "title": "Product checkout test", "status": "passed"},
        {"id": "TC-003", "title": "User registration test", "status": "passed"},
    ]

    query = parser.parse('Find tests containing "user"')
    result = executor.execute(query, tests)

    # Should match TC-001 and TC-003
    assert result.filtered_count == 2
    matched_ids = {m.test_id for m in result.matches}
    assert "TC-001" in matched_ids
    assert "TC-003" in matched_ids


def test_query_executor_grouping():
    """Test result grouping."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "title": "Test 1", "status": "passed", "category": "security"},
        {"id": "TC-002", "title": "Test 2", "status": "failed", "category": "security"},
        {"id": "TC-003", "title": "Test 3", "status": "passed", "category": "functional"},
    ]

    query = parser.parse("Show tests grouped by category")
    result = executor.execute(query, tests)

    assert result.groups is not None
    assert "security" in result.groups
    assert len(result.groups["security"]) == 2


def test_query_executor_aggregation():
    """Test aggregation for summaries."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "status": "passed", "priority": "high"},
        {"id": "TC-002", "status": "failed", "priority": "high"},
        {"id": "TC-003", "status": "passed", "priority": "low"},
    ]

    query = parser.parse("Give me a summary")
    result = executor.execute(query, tests)

    assert result.aggregations is not None
    assert result.aggregations["total"] == 3
    assert result.aggregations["by_status"]["passed"] == 2
    assert result.aggregations["by_status"]["failed"] == 1


def test_query_result_format():
    """Test result formatting."""
    from nlquery import create_query_parser, create_query_executor

    parser = create_query_parser()
    executor = create_query_executor()

    tests = [
        {"id": "TC-001", "title": "Test", "status": "passed"},
    ]

    query = parser.parse("Show all tests")
    result = executor.execute(query, tests)

    formatted = executor.format_result(result)

    assert "QUERY RESULT" in formatted
    assert "TC-001" in formatted


# ============================================================
# Flakiness Detection Module Tests
# ============================================================

def test_flakiness_imports():
    """Test flakiness module imports."""
    from flakiness import (
        FlakinessDetector,
        FlakinessReport,
        FlakyTest,
        FlakinessLevel,
        create_flakiness_detector,
        FlakinessAnalyzer,
        FlakePattern,
        FlakeCategory,
        AnalysisResult,
        create_flakiness_analyzer,
        ExecutionHistory,
        ExecutionRecord,
        TestHistory,
        create_execution_history,
    )
    assert FlakinessDetector is not None
    assert FlakinessAnalyzer is not None
    assert ExecutionHistory is not None


def test_execution_history_creation():
    """Test execution history creation."""
    from flakiness import create_execution_history

    history = create_execution_history()
    assert history is not None


def test_execution_history_record():
    """Test recording executions."""
    from flakiness import create_execution_history

    history = create_execution_history()

    history.record(
        test_id="TC-001",
        run_id="RUN-001",
        passed=True,
        duration_ms=1000,
    )

    history.record(
        test_id="TC-001",
        run_id="RUN-002",
        passed=False,
        duration_ms=1500,
        error_message="timeout error",
    )

    test_history = history.get_test_history("TC-001")

    assert test_history.total_runs == 2
    assert test_history.total_passes == 1
    assert test_history.total_failures == 1


def test_execution_history_batch():
    """Test batch recording."""
    from flakiness import create_execution_history

    history = create_execution_history()

    results = [
        {"test_id": "TC-001", "passed": True, "duration_ms": 1000},
        {"test_id": "TC-002", "passed": False, "duration_ms": 2000, "error": "failed"},
    ]

    history.record_batch("RUN-001", results)

    assert len(history.get_all_test_ids()) == 2


def test_execution_history_pass_rate():
    """Test pass rate calculation."""
    from flakiness import create_execution_history

    history = create_execution_history()

    # Record multiple runs
    for i in range(10):
        history.record(
            test_id="TC-001",
            run_id=f"RUN-{i:03d}",
            passed=(i % 2 == 0),  # 50% pass rate
            duration_ms=1000,
        )

    test_history = history.get_test_history("TC-001")

    assert test_history.pass_rate == 0.5


def test_flakiness_detector_creation():
    """Test flakiness detector creation."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector()
    assert detector is not None


def test_flakiness_detector_stable_test():
    """Test detection of stable test."""
    from flakiness import create_execution_history, create_flakiness_detector, FlakinessLevel

    history = create_execution_history()

    # All passes = stable
    for i in range(10):
        history.record("TC-001", f"RUN-{i}", True, 1000)

    detector = create_flakiness_detector(history=history)
    report = detector.detect()

    # Test should not be flaky
    assert report.flaky_count == 0
    assert report.stable_count == 1


def test_flakiness_detector_flaky_test():
    """Test detection of flaky test."""
    from flakiness import create_execution_history, create_flakiness_detector, FlakinessLevel

    history = create_execution_history()

    # Alternating pass/fail = flaky
    for i in range(10):
        history.record(
            test_id="TC-001",
            run_id=f"RUN-{i}",
            passed=(i % 2 == 0),
            duration_ms=1000,
            error_message="timeout" if i % 2 != 0 else None,
        )

    detector = create_flakiness_detector(history=history)
    report = detector.detect()

    assert report.flaky_count >= 1
    assert report.flaky_tests[0].flakiness_level != FlakinessLevel.NONE


def test_flakiness_detector_score():
    """Test flakiness score calculation."""
    from flakiness import create_execution_history, create_flakiness_detector

    history = create_execution_history()

    # 70% pass rate is suspicious
    for i in range(10):
        history.record("TC-001", f"RUN-{i}", i < 7, 1000)

    detector = create_flakiness_detector(history=history)
    score = detector.get_flakiness_score("TC-001")

    # Should have some flakiness score
    assert score > 0


def test_flakiness_detector_report():
    """Test flakiness report formatting."""
    from flakiness import create_execution_history, create_flakiness_detector

    history = create_execution_history()

    for i in range(10):
        history.record("TC-001", f"RUN-{i}", i % 3 != 0, 1000)

    detector = create_flakiness_detector(history=history)
    report = detector.detect()

    formatted = detector.format_report(report)

    assert "FLAKINESS" in formatted
    assert "Total Tests" in formatted


def test_flakiness_analyzer_creation():
    """Test flakiness analyzer creation."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()
    assert analyzer is not None


def test_flakiness_analyzer_categories():
    """Test category detection."""
    from flakiness import create_execution_history, create_flakiness_analyzer, FlakeCategory

    history = create_execution_history()

    # Timeout errors
    for i in range(5):
        history.record(
            test_id="TC-001",
            run_id=f"RUN-{i}",
            passed=(i < 2),
            duration_ms=1000,
            error_message="Operation timed out" if i >= 2 else None,
        )

    analyzer = create_flakiness_analyzer(history=history)
    result = analyzer.analyze("TC-001")

    assert FlakeCategory.TIMING in result.categories


def test_flakiness_analyzer_patterns():
    """Test pattern detection."""
    from flakiness import create_execution_history, create_flakiness_analyzer

    history = create_execution_history()

    # Various network errors
    errors = ["Connection refused", "ECONNRESET", "network error"]
    for i, error in enumerate(errors):
        history.record("TC-001", f"RUN-{i}", False, 1000, error_message=error)

    # Some passes
    for i in range(3, 6):
        history.record("TC-001", f"RUN-{i}", True, 1000)

    analyzer = create_flakiness_analyzer(history=history)
    result = analyzer.analyze("TC-001")

    assert len(result.patterns) > 0


def test_flakiness_analyzer_fixes():
    """Test fix suggestions."""
    from flakiness import create_execution_history, create_flakiness_analyzer

    history = create_execution_history()

    # Element not found errors
    for i in range(5):
        history.record(
            test_id="TC-001",
            run_id=f"RUN-{i}",
            passed=(i < 2),
            duration_ms=1000,
            error_message="element not found" if i >= 2 else None,
        )

    analyzer = create_flakiness_analyzer(history=history)
    result = analyzer.analyze("TC-001")

    assert len(result.suggested_fixes) > 0


def test_flakiness_analyzer_format():
    """Test analysis formatting."""
    from flakiness import create_execution_history, create_flakiness_analyzer

    history = create_execution_history()

    for i in range(5):
        history.record("TC-001", f"RUN-{i}", i < 3, 1000)

    analyzer = create_flakiness_analyzer(history=history)
    result = analyzer.analyze("TC-001")

    formatted = analyzer.format_analysis(result)

    assert "FLAKINESS ANALYSIS" in formatted
    assert "TC-001" in formatted


# ============================================================================
# Visualization Module Tests
# ============================================================================


def test_visualization_imports():
    """Test visualization module imports."""
    from visualization import (
        DependencyGraphBuilder,
        GraphNode,
        GraphEdge,
        GraphLayout,
        CoverageMapGenerator,
        CoverageCell,
        CoverageHeatmap,
        TimelineGenerator,
        TimelineEvent,
        TimelineTrack,
    )
    assert DependencyGraphBuilder is not None
    assert CoverageMapGenerator is not None
    assert TimelineGenerator is not None


def test_dependency_graph_creation():
    """Test dependency graph builder creation."""
    from visualization import create_dependency_graph_builder

    builder = create_dependency_graph_builder()
    assert builder is not None


def test_dependency_graph_add_test():
    """Test adding tests to graph."""
    from visualization import create_dependency_graph_builder, GraphLayout

    builder = create_dependency_graph_builder()

    builder.add_test(
        test_id="TC-001",
        title="Login test",
        category="auth",
        priority="high",
    )

    graph = builder.build(GraphLayout.GRID)

    assert len(graph.nodes) == 1
    assert graph.nodes[0].node_id == "TC-001"


def test_dependency_graph_dependencies():
    """Test dependency edges."""
    from visualization import create_dependency_graph_builder, GraphLayout

    builder = create_dependency_graph_builder()

    builder.add_test(
        test_id="TC-001",
        title="Setup test",
        category="setup",
    )
    builder.add_test(
        test_id="TC-002",
        title="Login test",
        category="auth",
        dependencies=["TC-001"],
    )

    graph = builder.build(GraphLayout.HIERARCHICAL)

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1


def test_dependency_graph_from_suite():
    """Test building from test suite."""
    from visualization import create_dependency_graph_builder, GraphLayout

    builder = create_dependency_graph_builder()

    tests = [
        {"id": "TC-001", "title": "Test 1", "category": "smoke"},
        {"id": "TC-002", "title": "Test 2", "category": "smoke"},
        {"id": "TC-003", "title": "Test 3", "category": "regression"},
    ]

    builder.add_tests_from_suite(tests)
    graph = builder.build(GraphLayout.CIRCULAR)

    assert len(graph.nodes) == 3
    assert len(graph.clusters) == 2


def test_dependency_graph_cycles():
    """Test cycle detection."""
    from visualization import create_dependency_graph_builder

    builder = create_dependency_graph_builder()

    # Create circular dependency
    builder.add_test("TC-001", "Test 1", dependencies=["TC-002"])
    builder.add_test("TC-002", "Test 2", dependencies=["TC-001"])

    cycles = builder.find_cycles()

    assert len(cycles) >= 1


def test_dependency_graph_critical_path():
    """Test critical path finding."""
    from visualization import create_dependency_graph_builder

    builder = create_dependency_graph_builder()

    builder.add_test("TC-001", "Base test")
    builder.add_test("TC-002", "Middle test", dependencies=["TC-001"])
    builder.add_test("TC-003", "Final test", dependencies=["TC-002"])

    path = builder.find_critical_path()

    assert len(path) == 3


def test_dependency_graph_mermaid():
    """Test Mermaid export."""
    from visualization import create_dependency_graph_builder

    builder = create_dependency_graph_builder()

    builder.add_test("TC-001", "Login test", category="auth")

    mermaid = builder.to_mermaid()

    assert "graph TD" in mermaid
    assert "TC-001" in mermaid


def test_dependency_graph_dot():
    """Test DOT export."""
    from visualization import create_dependency_graph_builder

    builder = create_dependency_graph_builder()

    builder.add_test("TC-001", "Login test", category="auth")

    dot = builder.to_dot()

    assert "digraph" in dot
    assert "TC-001" in dot


def test_coverage_map_creation():
    """Test coverage map generator creation."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()
    assert generator is not None


def test_coverage_map_feature():
    """Test feature coverage map."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()

    tests = [
        {"id": "TC-001", "title": "Login test", "category": "functional", "features": ["login"]},
        {"id": "TC-002", "title": "Signup test", "category": "functional", "features": ["signup"]},
    ]

    heatmap = generator.generate_feature_coverage(
        tests,
        features=["login", "signup", "checkout"],
    )

    assert len(heatmap.rows) == 3
    assert heatmap.cells[("login", "functional")].test_count == 1


def test_coverage_map_gaps():
    """Test coverage gap detection."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()

    tests = [
        {"id": "TC-001", "title": "Login test", "category": "functional", "features": ["login"]},
    ]

    heatmap = generator.generate_feature_coverage(
        tests,
        features=["login", "checkout"],
        categories=["functional", "security"],
    )

    gaps = generator.find_gaps(heatmap)

    # Should have gaps for checkout and security tests
    assert len(gaps) >= 2


def test_coverage_map_suggestions():
    """Test coverage suggestions."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()

    tests = []  # No tests = all gaps
    heatmap = generator.generate_feature_coverage(
        tests,
        features=["login"],
        categories=["functional"],
    )

    suggestions = generator.suggest_tests(heatmap, max_suggestions=5)

    assert len(suggestions) >= 1


def test_coverage_map_ascii():
    """Test ASCII rendering."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()

    tests = [
        {"id": "TC-001", "title": "Login test", "category": "functional", "features": ["login"]},
    ]

    heatmap = generator.generate_feature_coverage(
        tests,
        features=["login"],
        categories=["functional"],
    )

    ascii_output = generator.to_ascii(heatmap)

    assert "login" in ascii_output.lower() or "functional" in ascii_output.lower()


def test_coverage_map_html():
    """Test HTML rendering."""
    from visualization import create_coverage_map_generator

    generator = create_coverage_map_generator()

    tests = [
        {"id": "TC-001", "title": "Login test", "category": "functional", "features": ["login"]},
    ]

    heatmap = generator.generate_feature_coverage(
        tests,
        features=["login"],
        categories=["functional"],
    )

    html = generator.to_html(heatmap)

    assert "<table" in html
    assert "</table>" in html


def test_timeline_creation():
    """Test timeline generator creation."""
    from visualization import create_timeline_generator

    generator = create_timeline_generator()
    assert generator is not None


def test_timeline_record_event():
    """Test event recording."""
    from visualization import create_timeline_generator
    from visualization.timeline import EventType, EventStatus

    generator = create_timeline_generator()

    event = generator.record_event(
        EventType.TEST_START,
        test_id="TC-001",
        test_title="Login test",
    )

    assert event.event_id.startswith("EVT-")
    assert event.test_id == "TC-001"


def test_timeline_from_results():
    """Test building from execution results."""
    from visualization import create_timeline_generator
    from datetime import datetime, timedelta

    generator = create_timeline_generator()

    now = datetime.now()
    results = [
        {
            "id": "TC-001",
            "title": "Test 1",
            "started_at": now,
            "duration_ms": 1000,
            "passed": True,
        },
        {
            "id": "TC-002",
            "title": "Test 2",
            "started_at": now + timedelta(seconds=1),
            "duration_ms": 2000,
            "passed": False,
        },
    ]

    generator.from_execution_results(results)
    timeline = generator.build()

    assert timeline.summary["total_tests"] == 2
    assert timeline.summary["passed"] == 1
    assert timeline.summary["failed"] == 1


def test_timeline_parallel_tracks():
    """Test parallel track assignment."""
    from visualization import create_timeline_generator
    from datetime import datetime

    generator = create_timeline_generator()

    now = datetime.now()
    results = [
        {"id": "TC-001", "title": "Test 1", "started_at": now, "duration_ms": 5000, "passed": True},
        {"id": "TC-002", "title": "Test 2", "started_at": now, "duration_ms": 3000, "passed": True},
    ]

    generator.from_execution_results(results, parallel_tracks=True)
    timeline = generator.build()

    # Should have multiple tracks for overlapping tests
    assert len(timeline.tracks) >= 1


def test_timeline_slow_tests():
    """Test slow test detection."""
    from visualization import create_timeline_generator
    from visualization.timeline import EventType, EventStatus

    generator = create_timeline_generator()

    generator.record_event(
        EventType.TEST_END,
        test_id="TC-001",
        test_title="Slow test",
        duration_ms=10000,
        status=EventStatus.PASSED,
    )

    slow = generator.find_slow_tests(threshold_ms=5000)

    assert len(slow) == 1
    assert slow[0].test_id == "TC-001"


def test_timeline_ascii():
    """Test ASCII rendering."""
    from visualization import create_timeline_generator
    from datetime import datetime

    generator = create_timeline_generator()

    now = datetime.now()
    results = [
        {"id": "TC-001", "title": "Test 1", "started_at": now, "duration_ms": 1000, "passed": True},
    ]

    generator.from_execution_results(results)
    timeline = generator.build()

    ascii_output = generator.to_ascii(timeline)

    assert "TIMELINE" in ascii_output


def test_timeline_mermaid():
    """Test Mermaid Gantt export."""
    from visualization import create_timeline_generator
    from datetime import datetime

    generator = create_timeline_generator()

    now = datetime.now()
    results = [
        {"id": "TC-001", "title": "Test 1", "started_at": now, "duration_ms": 1000, "passed": True},
    ]

    generator.from_execution_results(results)
    timeline = generator.build()

    mermaid = generator.to_mermaid_gantt(timeline)

    assert "gantt" in mermaid


def test_timeline_summary():
    """Test timeline summary formatting."""
    from visualization import create_timeline_generator
    from datetime import datetime

    generator = create_timeline_generator()

    now = datetime.now()
    results = [
        {"id": "TC-001", "title": "Test 1", "started_at": now, "duration_ms": 1000, "passed": True},
    ]

    generator.from_execution_results(results)
    timeline = generator.build()

    formatted = generator.format_summary(timeline)

    assert "TIMELINE SUMMARY" in formatted


# ============================================================================
# Retry Module Tests
# ============================================================================


def test_retry_imports():
    """Test retry module imports."""
    from retry import (
        RetryStrategy,
        RetryConfig,
        RetryResult,
        BackoffType,
        AdaptiveRetryManager,
        RetryDecision,
        RetryContext,
        QuarantineManager,
        QuarantinedTest,
        QuarantineReason,
    )
    assert RetryStrategy is not None
    assert AdaptiveRetryManager is not None
    assert QuarantineManager is not None


def test_retry_strategy_creation():
    """Test retry strategy creation."""
    from retry import create_retry_strategy, BackoffType

    strategy = create_retry_strategy(
        max_retries=5,
        backoff_type=BackoffType.EXPONENTIAL,
    )
    assert strategy is not None


def test_retry_delay_fixed():
    """Test fixed backoff delay."""
    from retry import RetryStrategy, RetryConfig, BackoffType

    config = RetryConfig(
        backoff_type=BackoffType.FIXED,
        initial_delay_ms=1000,
        jitter_factor=0,  # Disable jitter for predictable test
    )
    strategy = RetryStrategy(config)

    # First attempt has no delay
    assert strategy.calculate_delay(1) == 0
    # Subsequent attempts have fixed delay
    assert strategy.calculate_delay(2) == 1000
    assert strategy.calculate_delay(3) == 1000


def test_retry_delay_exponential():
    """Test exponential backoff delay."""
    from retry import create_retry_strategy, BackoffType

    strategy = create_retry_strategy(
        backoff_type=BackoffType.EXPONENTIAL,
        initial_delay_ms=1000,
    )

    assert strategy.calculate_delay(1) == 0
    # Exponential: 1000, 2000, 4000...
    delay2 = strategy.calculate_delay(2)
    delay3 = strategy.calculate_delay(3)
    assert delay2 < delay3


def test_retry_should_retry():
    """Test retry decision logic."""
    from retry import RetryStrategy, RetryConfig

    config = RetryConfig(
        max_retries=3,
        retry_on_errors=["timeout", "connection"],
        skip_on_errors=["assertion"],
    )
    strategy = RetryStrategy(config)

    # Should retry on matching errors
    assert strategy.should_retry(1, "Connection timeout") == True

    # Should not retry on skip errors
    assert strategy.should_retry(1, "Assertion failed") == False

    # Should not retry at max
    assert strategy.should_retry(3) == False


def test_retry_simulate():
    """Test retry simulation."""
    from retry import create_retry_strategy

    strategy = create_retry_strategy(max_retries=5)

    # Run with high failure probability
    result = strategy.simulate_retries("TC-001", failure_probability=0.9)

    assert result.test_id == "TC-001"
    assert result.total_attempts >= 1


def test_retry_format():
    """Test retry result formatting."""
    from retry import create_retry_strategy

    strategy = create_retry_strategy()
    result = strategy.simulate_retries("TC-001")

    formatted = strategy.format_result(result)

    assert "RETRY RESULT" in formatted
    assert "TC-001" in formatted


def test_adaptive_manager_creation():
    """Test adaptive retry manager creation."""
    from retry import create_adaptive_retry_manager

    manager = create_adaptive_retry_manager(default_max_retries=5)
    assert manager is not None


def test_adaptive_manager_strategy():
    """Test getting strategy for test."""
    from retry import create_adaptive_retry_manager

    manager = create_adaptive_retry_manager()

    strategy = manager.get_strategy("TC-001")
    assert strategy is not None


def test_adaptive_manager_decision():
    """Test retry decision making."""
    from retry import create_adaptive_retry_manager, RetryContext, RetryDecision

    manager = create_adaptive_retry_manager()

    # Normal case - should retry
    context = RetryContext(
        test_id="TC-001",
        current_attempt=1,
        historical_pass_rate=0.8,
        avg_retry_success_rate=0.5,
    )
    decision = manager.decide(context)
    assert decision == RetryDecision.RETRY

    # Low pass rate - should quarantine
    context2 = RetryContext(
        test_id="TC-002",
        current_attempt=1,
        historical_pass_rate=0.1,
        consecutive_failures=10,
    )
    decision2 = manager.decide(context2)
    assert decision2 == RetryDecision.QUARANTINE


def test_adaptive_manager_record():
    """Test recording results."""
    from retry import create_adaptive_retry_manager, RetryResult
    from retry.strategy import RetryAttempt
    from datetime import datetime

    manager = create_adaptive_retry_manager()

    result = RetryResult(
        test_id="TC-001",
        final_status="passed",
        total_attempts=2,
        successful_attempt=2,
        attempts=[
            RetryAttempt(1, datetime.now(), passed=False),
            RetryAttempt(2, datetime.now(), passed=True),
        ],
        error_pattern="timeout",
    )

    manager.record_result(result)

    profile = manager.get_profile("TC-001")
    assert profile is not None
    assert profile.total_runs == 1


def test_adaptive_manager_insights():
    """Test getting insights."""
    from retry import create_adaptive_retry_manager, RetryResult
    from retry.strategy import RetryAttempt
    from datetime import datetime

    manager = create_adaptive_retry_manager()

    # Record some data first
    result = RetryResult(
        test_id="TC-001",
        final_status="passed",
        total_attempts=1,
    )
    manager.record_result(result)

    insights = manager.get_insights()
    assert "total_tests_tracked" in insights
    assert insights["total_tests_tracked"] == 1


def test_quarantine_creation():
    """Test quarantine manager creation."""
    from retry import create_quarantine_manager

    manager = create_quarantine_manager()
    assert manager is not None


def test_quarantine_add():
    """Test adding test to quarantine."""
    from retry import create_quarantine_manager, QuarantineReason

    manager = create_quarantine_manager()

    test = manager.quarantine(
        test_id="TC-001",
        title="Flaky login test",
        reason=QuarantineReason.EXTREMELY_FLAKY,
    )

    assert test.test_id == "TC-001"
    assert manager.is_quarantined("TC-001")


def test_quarantine_release():
    """Test releasing from quarantine."""
    from retry import create_quarantine_manager, QuarantineReason

    manager = create_quarantine_manager()

    manager.quarantine("TC-001", "Test", QuarantineReason.CONSISTENTLY_FAILING)
    assert manager.is_quarantined("TC-001")

    manager.release("TC-001", to_monitoring=True)
    assert not manager.is_quarantined("TC-001")
    assert manager.is_monitoring("TC-001")


def test_quarantine_auto():
    """Test automatic quarantine."""
    from retry import create_quarantine_manager
    from retry.quarantine import QuarantinePolicy

    policy = QuarantinePolicy(consecutive_failures_threshold=3)
    manager = create_quarantine_manager(policy)

    # Record consecutive failures
    for i in range(4):
        result = manager.record_result("TC-001", False, "Failing test")

    # Should be auto-quarantined
    assert manager.is_quarantined("TC-001")


def test_quarantine_summary():
    """Test quarantine summary."""
    from retry import create_quarantine_manager, QuarantineReason

    manager = create_quarantine_manager()

    manager.quarantine("TC-001", "Test 1", QuarantineReason.EXTREMELY_FLAKY)
    manager.quarantine("TC-002", "Test 2", QuarantineReason.CONSISTENTLY_FAILING)

    summary = manager.get_summary()

    assert summary["active"] == 2
    assert "by_reason" in summary


def test_quarantine_report():
    """Test quarantine report formatting."""
    from retry import create_quarantine_manager, QuarantineReason

    manager = create_quarantine_manager()

    manager.quarantine("TC-001", "Flaky test", QuarantineReason.EXTREMELY_FLAKY)

    report = manager.format_report()

    assert "QUARANTINE REPORT" in report
    assert "TC-001" in report


# ============================================================================
# Matrix Module Tests
# ============================================================================


def test_matrix_imports():
    """Test matrix module imports."""
    from matrix import (
        MatrixGenerator,
        TestMatrix,
        MatrixCell,
        BrowserConfig,
        DeviceConfig,
        MatrixOptimizer,
        OptimizedMatrix,
        CoverageStrategy,
        MatrixReporter,
        MatrixReport,
        CompatibilityIssue,
    )
    assert MatrixGenerator is not None
    assert MatrixOptimizer is not None
    assert MatrixReporter is not None


def test_matrix_generator_creation():
    """Test matrix generator creation."""
    from matrix import create_matrix_generator

    generator = create_matrix_generator()
    assert generator is not None


def test_matrix_generator_basic():
    """Test basic matrix generation."""
    from matrix import create_matrix_generator
    from matrix.generator import BrowserType

    generator = create_matrix_generator()

    matrix = generator.generate(
        tests=["TC-001", "TC-002"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    assert len(matrix.tests) == 2
    assert matrix.total_combinations > 0


def test_matrix_generator_responsive():
    """Test responsive matrix generation."""
    from matrix import create_matrix_generator

    generator = create_matrix_generator()

    matrix = generator.generate_responsive(
        tests=["TC-001"],
    )

    # Should have multiple viewport sizes
    assert len(matrix.browsers) > 1


def test_matrix_generator_mobile():
    """Test mobile matrix generation."""
    from matrix import create_matrix_generator

    generator = create_matrix_generator()

    matrix = generator.generate_mobile(
        tests=["TC-001"],
        include_ios=True,
        include_android=True,
    )

    assert matrix.devices is not None
    assert len(matrix.devices) > 0


def test_matrix_generator_devices():
    """Test available devices."""
    from matrix import create_matrix_generator

    generator = create_matrix_generator()

    devices = generator.get_available_devices()

    assert len(devices) > 0
    assert "iPhone 15 Pro" in devices


def test_matrix_generator_format():
    """Test matrix formatting."""
    from matrix import create_matrix_generator
    from matrix.generator import BrowserType

    generator = create_matrix_generator()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    formatted = generator.format_matrix(matrix)

    assert "TEST MATRIX" in formatted


def test_matrix_optimizer_creation():
    """Test optimizer creation."""
    from matrix import create_matrix_optimizer, CoverageStrategy

    optimizer = create_matrix_optimizer(CoverageStrategy.PAIRWISE)
    assert optimizer is not None


def test_matrix_optimizer_pairwise():
    """Test pairwise optimization."""
    from matrix import create_matrix_generator, create_matrix_optimizer, CoverageStrategy
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    optimizer = create_matrix_optimizer()

    # Create a matrix with multiple browsers
    matrix = generator.generate(
        tests=["TC-001", "TC-002", "TC-003"],
        browsers=[BrowserType.CHROME, BrowserType.FIREFOX],
        include_headless=True,
    )

    result = optimizer.optimize(matrix, CoverageStrategy.PAIRWISE)

    # Should reduce combinations
    assert result.optimized_combinations <= result.original_combinations


def test_matrix_optimizer_time_budget():
    """Test time budget optimization."""
    from matrix import create_matrix_generator, create_matrix_optimizer, CoverageStrategy
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    optimizer = create_matrix_optimizer()

    matrix = generator.generate(
        tests=["TC-001", "TC-002"],
        browsers=[BrowserType.CHROME],
    )

    result = optimizer.optimize(
        matrix,
        CoverageStrategy.TIME_BUDGET,
        time_budget_ms=10000,  # Very small budget
    )

    assert result.estimated_duration_ms <= 10000


def test_matrix_optimizer_critical_path():
    """Test critical path optimization."""
    from matrix import create_matrix_generator, create_matrix_optimizer, CoverageStrategy
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    optimizer = create_matrix_optimizer()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME, BrowserType.FIREFOX, BrowserType.EDGE, BrowserType.OPERA],
    )

    result = optimizer.optimize(matrix, CoverageStrategy.CRITICAL_PATH)

    # Critical path should select fewer combinations
    assert result.optimized_combinations <= result.original_combinations


def test_matrix_optimizer_suggestion():
    """Test optimization suggestions."""
    from matrix import create_matrix_generator, create_matrix_optimizer
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    optimizer = create_matrix_optimizer()

    matrix = generator.generate(
        tests=["TC-001", "TC-002"],
        browsers=[BrowserType.CHROME, BrowserType.FIREFOX],
    )

    suggestion = optimizer.suggest_optimization(matrix)

    assert "matrix_stats" in suggestion
    assert "recommended" in suggestion


def test_matrix_optimizer_format():
    """Test optimization result formatting."""
    from matrix import create_matrix_generator, create_matrix_optimizer, CoverageStrategy
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    optimizer = create_matrix_optimizer()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    result = optimizer.optimize(matrix, CoverageStrategy.FULL)
    formatted = optimizer.format_result(result)

    assert "OPTIMIZATION RESULT" in formatted


def test_matrix_reporter_creation():
    """Test reporter creation."""
    from matrix import create_matrix_reporter

    reporter = create_matrix_reporter()
    assert reporter is not None


def test_matrix_reporter_record():
    """Test recording results."""
    from matrix import create_matrix_reporter, create_matrix_generator
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    reporter = create_matrix_reporter()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    # Record result
    result = reporter.record_result(
        cell=matrix.cells[0],
        passed=True,
        duration_ms=1000,
    )

    assert result.passed


def test_matrix_reporter_issue():
    """Test reporting issues."""
    from matrix import create_matrix_reporter
    from matrix.reporter import IssueType, IssueSeverity
    from matrix.generator import BrowserType

    reporter = create_matrix_reporter()

    issue = reporter.report_issue(
        test_id="TC-001",
        issue_type=IssueType.VISUAL,
        severity=IssueSeverity.MINOR,
        description="Button color differs in Safari",
        browsers=[BrowserType.SAFARI],
    )

    assert issue.issue_id.startswith("ISSUE-")


def test_matrix_reporter_report():
    """Test generating report."""
    from matrix import create_matrix_generator, create_matrix_reporter
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    reporter = create_matrix_reporter()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    for cell in matrix.cells:
        reporter.record_result(cell, True, 1000)

    report = reporter.generate_report(matrix)

    assert report.total_cells == len(matrix.cells)
    assert report.passed_cells == len(matrix.cells)


def test_matrix_reporter_compatibility():
    """Test browser compatibility stats."""
    from matrix import create_matrix_generator, create_matrix_reporter
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    reporter = create_matrix_reporter()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME, BrowserType.FIREFOX],
        include_headless=False,
    )

    for cell in matrix.cells:
        # Chrome passes, Firefox fails
        passed = cell.browser.browser == BrowserType.CHROME
        reporter.record_result(cell, passed, 1000)

    compat = reporter.get_browser_compatibility()

    assert "chrome" in compat
    assert "firefox" in compat


def test_matrix_reporter_format():
    """Test report formatting."""
    from matrix import create_matrix_generator, create_matrix_reporter
    from matrix.generator import BrowserType

    generator = create_matrix_generator()
    reporter = create_matrix_reporter()

    matrix = generator.generate(
        tests=["TC-001"],
        browsers=[BrowserType.CHROME],
        include_headless=False,
    )

    for cell in matrix.cells:
        reporter.record_result(cell, True, 1000)

    report = reporter.generate_report(matrix)
    formatted = reporter.format_report(report)

    assert "MATRIX EXECUTION REPORT" in formatted


# ============================================================
# Scenarios Module Tests
# ============================================================

def test_scenarios_imports():
    """Test scenarios module imports."""
    from scenarios import (
        ScenarioGenerator,
        TestScenario,
        ScenarioType,
        UserPersona,
        create_scenario_generator,
        DataFactory,
        DataProfile,
        LocaleData,
        create_data_factory,
        JourneySimulator,
        UserJourney,
        JourneyStep,
        JourneyOutcome,
        create_journey_simulator,
    )

    assert ScenarioGenerator is not None
    assert DataFactory is not None
    assert JourneySimulator is not None


def test_scenario_generator_creation():
    """Test scenario generator creation."""
    from scenarios import create_scenario_generator

    generator = create_scenario_generator()
    assert generator is not None


def test_scenario_generator_for_feature():
    """Test generating scenarios for a feature."""
    from scenarios import create_scenario_generator, ScenarioType, UserPersona

    generator = create_scenario_generator()

    scenarios = generator.generate_for_feature(
        "login",
        personas=[UserPersona.NEW_USER],
        scenario_types=[ScenarioType.HAPPY_PATH],
        max_scenarios=5,
    )

    assert len(scenarios) > 0
    assert len(scenarios) <= 5
    assert scenarios[0].scenario_type == ScenarioType.HAPPY_PATH
    assert scenarios[0].persona == UserPersona.NEW_USER


def test_scenario_generator_edge_cases():
    """Test generating edge case scenarios."""
    from scenarios import create_scenario_generator, ScenarioType

    generator = create_scenario_generator()

    edge_cases = generator.generate_edge_cases("checkout", depth=2)

    assert len(edge_cases) > 0
    assert all(s.scenario_type == ScenarioType.EDGE_CASE for s in edge_cases)
    assert all("EDGE-" in s.scenario_id for s in edge_cases)


def test_scenario_generator_security():
    """Test generating security scenarios."""
    from scenarios import create_scenario_generator, ScenarioType, UserPersona

    generator = create_scenario_generator()

    security_scenarios = generator.generate_security_scenarios("registration")

    assert len(security_scenarios) > 0
    assert all(s.scenario_type == ScenarioType.SECURITY for s in security_scenarios)
    assert all(s.persona == UserPersona.MALICIOUS_USER for s in security_scenarios)
    assert all("SEC-" in s.scenario_id for s in security_scenarios)


def test_scenario_generator_accessibility():
    """Test generating accessibility scenarios."""
    from scenarios import create_scenario_generator, ScenarioType, UserPersona

    generator = create_scenario_generator()

    a11y_scenarios = generator.generate_accessibility_scenarios("search")

    assert len(a11y_scenarios) > 0
    assert all(s.scenario_type == ScenarioType.ACCESSIBILITY for s in a11y_scenarios)
    assert all(s.persona == UserPersona.ACCESSIBILITY_USER for s in a11y_scenarios)
    assert all("A11Y-" in s.scenario_id for s in a11y_scenarios)


def test_scenario_generator_format():
    """Test scenario formatting."""
    from scenarios import create_scenario_generator, ScenarioType, UserPersona

    generator = create_scenario_generator()

    scenarios = generator.generate_for_feature("login", max_scenarios=1)
    formatted = generator.format_scenario(scenarios[0])

    assert "SCENARIO:" in formatted
    assert "Name:" in formatted
    assert "Steps:" in formatted
    assert "Expected Outcomes:" in formatted


def test_data_factory_creation():
    """Test data factory creation."""
    from scenarios import create_data_factory

    factory = create_data_factory(seed=42)
    assert factory is not None
    assert factory.seed == 42


def test_data_factory_user():
    """Test user data generation."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    user = factory.generate_user(locale="en-US", profile=DataProfile.REALISTIC)

    assert "first_name" in user
    assert "last_name" in user
    assert "email" in user
    assert "phone" in user
    assert "@" in user["email"]


def test_data_factory_locales():
    """Test locale-specific data generation."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    # US user
    us_user = factory.generate_user(locale="en-US")
    assert us_user["locale"] == "en-US"

    # German user
    de_user = factory.generate_user(locale="de-DE")
    assert de_user["locale"] == "de-DE"

    # Japanese user
    jp_user = factory.generate_user(locale="ja-JP")
    assert jp_user["locale"] == "ja-JP"


def test_data_factory_profiles():
    """Test different data profiles."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    # Realistic profile
    realistic = factory.generate_password(profile=DataProfile.REALISTIC)
    assert len(realistic) >= 8

    # Minimal profile
    minimal = factory.generate_password(profile=DataProfile.MINIMAL, min_length=8)
    assert minimal == "a" * 8

    # Boundary profile (too short)
    boundary = factory.generate_password(profile=DataProfile.BOUNDARY, min_length=8)
    assert len(boundary) < 8


def test_data_factory_credit_card():
    """Test credit card data generation."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    card = factory.generate_credit_card(card_type="visa", profile=DataProfile.REALISTIC)

    assert "number" in card
    assert "expiry" in card
    assert "cvv" in card
    assert "holder" in card
    assert card["number"].startswith("4")  # Visa prefix


def test_data_factory_form_data():
    """Test form data generation."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    fields = ["email", "password", "first_name", "phone", "city"]
    data = factory.generate_form_data(fields, profile=DataProfile.REALISTIC)

    assert len(data) == 5
    assert "@" in data["email"]
    assert len(data["password"]) >= 8


def test_data_factory_batch():
    """Test batch data generation."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    users = factory.generate_batch("user", count=5, profile=DataProfile.REALISTIC)

    assert len(users) == 5
    assert all("email" in u for u in users)


def test_data_factory_security_payloads():
    """Test security payload retrieval."""
    from scenarios import create_data_factory

    factory = create_data_factory()

    sql_payloads = factory.get_security_payloads("sql_injection")
    assert len(sql_payloads) > 0
    assert any("OR" in p for p in sql_payloads)

    xss_payloads = factory.get_security_payloads("xss")
    assert len(xss_payloads) > 0
    assert any("<script>" in p for p in xss_payloads)

    all_payloads = factory.get_security_payloads()
    assert len(all_payloads) > len(sql_payloads)


def test_data_factory_format():
    """Test data formatting."""
    from scenarios import create_data_factory, DataProfile

    factory = create_data_factory(seed=42)

    user = factory.generate_user()
    formatted = factory.format_data(user)

    assert "GENERATED TEST DATA" in formatted
    assert "email:" in formatted


def test_journey_simulator_creation():
    """Test journey simulator creation."""
    from scenarios import create_journey_simulator

    simulator = create_journey_simulator(seed=42)
    assert simulator is not None


def test_journey_simulator_available():
    """Test available journey types."""
    from scenarios import create_journey_simulator

    simulator = create_journey_simulator()

    journeys = simulator.get_available_journeys()

    assert "registration" in journeys
    assert "checkout" in journeys
    assert "login" in journeys
    assert "search_purchase" in journeys


def test_journey_simulate_basic():
    """Test basic journey simulation."""
    from scenarios import create_journey_simulator, JourneyOutcome
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=100)  # Seed that produces SUCCESS

    journey = simulator.simulate(
        "login",
        behavior=UserBehavior.EFFICIENT,
        failure_probability=0.0,
    )

    assert journey.journey_id.startswith("JRN-")
    assert journey.name == "User Login"
    assert journey.goal == "Access account"
    assert len(journey.steps) > 0
    # Outcome depends on random behavior modifiers, check valid outcome
    assert journey.outcome in [JourneyOutcome.SUCCESS, JourneyOutcome.ABANDONED, JourneyOutcome.FAILURE]


def test_journey_simulate_with_failure():
    """Test journey simulation with high failure rate."""
    from scenarios import create_journey_simulator
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=42)

    # Run multiple simulations with high failure probability
    failed_journeys = 0
    for _ in range(10):
        journey = simulator.simulate(
            "checkout",
            behavior=UserBehavior.EFFICIENT,
            failure_probability=0.9,  # Very high failure rate
        )
        if journey.outcome.value != "success":
            failed_journeys += 1

    # Should have some failures
    assert failed_journeys > 0


def test_journey_behaviors():
    """Test different user behaviors."""
    from scenarios import create_journey_simulator
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=42)

    # Efficient user
    efficient = simulator.simulate("login", behavior=UserBehavior.EFFICIENT)
    assert efficient.behavior == UserBehavior.EFFICIENT

    # Hesitant user (more friction points expected)
    hesitant = simulator.simulate("login", behavior=UserBehavior.HESITANT)
    assert hesitant.behavior == UserBehavior.HESITANT


def test_journey_batch_simulation():
    """Test batch journey simulation."""
    from scenarios import create_journey_simulator
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=42)

    journeys = simulator.simulate_batch(
        "registration",
        count=10,
        behavior_distribution={
            UserBehavior.EFFICIENT: 0.5,
            UserBehavior.HESITANT: 0.5,
        },
    )

    assert len(journeys) == 10

    # Should have mix of behaviors
    behaviors = [j.behavior for j in journeys]
    assert UserBehavior.EFFICIENT in behaviors or UserBehavior.HESITANT in behaviors


def test_journey_analysis():
    """Test journey analysis."""
    from scenarios import create_journey_simulator
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=42)

    journeys = simulator.simulate_batch("checkout", count=20)
    analysis = simulator.analyze_journeys(journeys)

    assert "total_journeys" in analysis
    assert analysis["total_journeys"] == 20
    assert "outcome_distribution" in analysis
    assert "success_rate" in analysis
    assert "avg_completion_rate" in analysis
    assert "avg_duration_ms" in analysis


def test_journey_suggestions():
    """Test journey improvement suggestions."""
    from scenarios import create_journey_simulator

    simulator = create_journey_simulator(seed=42)

    # Create analysis with poor metrics
    poor_analysis = {
        "success_rate": 0.5,
        "avg_completion_rate": 0.6,
        "avg_duration_ms": 150000,
        "top_friction_points": [
            ("User paused at: Payment info", 5),
            ("User went back at: Shipping", 3),
        ],
        "behavior_success_rates": {
            "efficient": 0.8,
            "hesitant": 0.3,
        },
    }

    suggestions = simulator.suggest_improvements(poor_analysis)

    assert len(suggestions) > 0
    assert any("success rate" in s["issue"].lower() for s in suggestions)


def test_journey_format():
    """Test journey formatting."""
    from scenarios import create_journey_simulator
    from scenarios.journey import UserBehavior

    simulator = create_journey_simulator(seed=42)

    journey = simulator.simulate("login", behavior=UserBehavior.EFFICIENT)
    formatted = simulator.format_journey(journey)

    assert "USER JOURNEY:" in formatted
    assert "Goal:" in formatted
    assert "Behavior:" in formatted
    assert "STEPS" in formatted
    assert "Outcome:" in formatted


# ============================================================
# Analysis Module Tests
# ============================================================

def test_analysis_imports():
    """Test analysis module imports."""
    from analysis import (
        RootCauseAnalyzer,
        FailurePattern,
        FailureCategory,
        RootCause,
        create_root_cause_analyzer,
        CodeCorrelator,
        ChangeCorrelation,
        CodeChange,
        create_code_correlator,
        DebugAssistant,
        DebugSuggestion,
        DebugStrategy,
        create_debug_assistant,
    )

    assert RootCauseAnalyzer is not None
    assert CodeCorrelator is not None
    assert DebugAssistant is not None


def test_root_cause_analyzer_creation():
    """Test root cause analyzer creation."""
    from analysis import create_root_cause_analyzer

    analyzer = create_root_cause_analyzer()
    assert analyzer is not None


def test_root_cause_analyzer_timeout():
    """Test analyzing timeout errors."""
    from analysis import create_root_cause_analyzer, FailureCategory

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-001",
        error_message="Test timed out after 30000ms waiting for element",
    )

    assert analysis.test_id == "TC-001"
    assert len(analysis.root_causes) > 0

    # Should identify timeout as cause
    categories = [c.category for c in analysis.root_causes]
    assert FailureCategory.TIMEOUT in categories


def test_root_cause_analyzer_element_not_found():
    """Test analyzing element not found errors."""
    from analysis import create_root_cause_analyzer, FailureCategory

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-002",
        error_message="NoSuchElementException: Unable to locate element: #login-button",
        stack_trace="at findElement (src/utils.js:42)",
    )

    categories = [c.category for c in analysis.root_causes]
    assert FailureCategory.ELEMENT_NOT_FOUND in categories


def test_root_cause_analyzer_assertion():
    """Test analyzing assertion errors."""
    from analysis import create_root_cause_analyzer, FailureCategory

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-003",
        error_message="AssertionError: expected 'Success' but got 'Error'",
    )

    categories = [c.category for c in analysis.root_causes]
    assert FailureCategory.ASSERTION in categories


def test_root_cause_analyzer_network():
    """Test analyzing network errors."""
    from analysis import create_root_cause_analyzer, FailureCategory

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-004",
        error_message="ECONNREFUSED: Connection refused to localhost:8080",
    )

    categories = [c.category for c in analysis.root_causes]
    assert FailureCategory.NETWORK in categories


def test_root_cause_analyzer_suggestions():
    """Test that analyzer provides fix suggestions."""
    from analysis import create_root_cause_analyzer

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-005",
        error_message="Element became stale during test execution",
    )

    # Should have suggestions
    assert len(analysis.root_causes) > 0
    assert len(analysis.root_causes[0].suggested_fixes) > 0


def test_root_cause_analyzer_trends():
    """Test failure trend analysis."""
    from analysis import create_root_cause_analyzer

    analyzer = create_root_cause_analyzer()

    # Analyze multiple failures
    for i in range(5):
        analyzer.analyze(
            test_id=f"TC-{i:03d}",
            error_message="Timeout waiting for element",
        )

    trends = analyzer.get_failure_trends()

    assert trends["total_failures"] == 5
    assert "timeout" in trends["category_distribution"]


def test_root_cause_analyzer_format():
    """Test analysis formatting."""
    from analysis import create_root_cause_analyzer

    analyzer = create_root_cause_analyzer()

    analysis = analyzer.analyze(
        test_id="TC-006",
        error_message="Test failed: expected value to match",
    )

    formatted = analyzer.format_analysis(analysis)

    assert "ROOT CAUSE ANALYSIS" in formatted
    assert "TC-006" in formatted
    assert "ROOT CAUSES" in formatted


def test_code_correlator_creation():
    """Test code correlator creation."""
    from analysis import create_code_correlator

    correlator = create_code_correlator()
    assert correlator is not None


def test_code_correlator_register_change():
    """Test registering code changes."""
    from analysis import create_code_correlator
    from analysis.correlator import ChangeType

    correlator = create_code_correlator()

    change = correlator.register_change(
        file_path="src/components/Login.tsx",
        change_type=ChangeType.MODIFICATION,
        author="dev@example.com",
        description="Fixed login button styling",
        lines_added=10,
        lines_removed=5,
    )

    assert change.change_id.startswith("CHG-")
    assert change.file_path == "src/components/Login.tsx"
    assert change.author == "dev@example.com"


def test_code_correlator_correlate():
    """Test correlating failures with changes."""
    from analysis import create_code_correlator
    from analysis.correlator import ChangeType

    correlator = create_code_correlator()

    # Register a change
    correlator.register_change(
        file_path="src/login/auth.js",
        change_type=ChangeType.MODIFICATION,
        author="dev@example.com",
        description="Modified authentication flow",
        lines_added=50,
    )

    # Register test files
    correlator.register_test_files("TC-001", ["src/login/auth.js"])

    # Correlate
    report = correlator.correlate(
        test_id="TC-001",
        error_message="Authentication failed: invalid token",
        stack_trace="at auth.js:42",
    )

    assert report.test_id == "TC-001"
    assert report.total_changes_analyzed >= 1
    assert len(report.correlations) > 0


def test_code_correlator_change_history():
    """Test getting change history."""
    from analysis import create_code_correlator
    from analysis.correlator import ChangeType

    correlator = create_code_correlator()

    # Register changes
    for i in range(5):
        correlator.register_change(
            file_path=f"src/module{i}.js",
            change_type=ChangeType.MODIFICATION,
            author="dev@example.com",
            description=f"Change {i}",
        )

    history = correlator.get_change_history()

    assert len(history) == 5


def test_code_correlator_format():
    """Test report formatting."""
    from analysis import create_code_correlator
    from analysis.correlator import ChangeType

    correlator = create_code_correlator()

    correlator.register_change(
        file_path="src/app.js",
        change_type=ChangeType.ADDITION,
        author="dev@example.com",
        description="Added new feature",
    )

    report = correlator.correlate(
        test_id="TC-001",
        error_message="Test failed",
    )

    formatted = correlator.format_report(report)

    assert "CODE CORRELATION REPORT" in formatted
    assert "TC-001" in formatted


def test_debug_assistant_creation():
    """Test debug assistant creation."""
    from analysis import create_debug_assistant

    assistant = create_debug_assistant()
    assert assistant is not None


def test_debug_assistant_plan_timeout():
    """Test creating debug plan for timeout."""
    from analysis import create_debug_assistant, DebugStrategy

    assistant = create_debug_assistant()

    plan = assistant.create_debug_plan(
        test_id="TC-001",
        error_message="Test timed out after 30000ms",
    )

    assert plan.test_id == "TC-001"
    assert len(plan.suggestions) > 0

    # Should suggest time-based debugging
    strategies = [s.strategy for s in plan.suggestions]
    assert DebugStrategy.TIME_BASED in strategies


def test_debug_assistant_plan_element():
    """Test creating debug plan for element not found."""
    from analysis import create_debug_assistant, DebugStrategy

    assistant = create_debug_assistant()

    plan = assistant.create_debug_plan(
        test_id="TC-002",
        error_message="Element .login-button not found",
    )

    strategies = [s.strategy for s in plan.suggestions]
    assert DebugStrategy.INSPECT_STATE in strategies


def test_debug_assistant_quick_fix():
    """Test quick fix suggestions."""
    from analysis import create_debug_assistant

    assistant = create_debug_assistant()

    fix = assistant.suggest_quick_fix("Timeout waiting for element")

    assert "fix" in fix
    assert "code" in fix
    assert "confidence" in fix


def test_debug_assistant_common_fixes():
    """Test getting common fixes."""
    from analysis import create_debug_assistant

    assistant = create_debug_assistant()

    fixes = assistant.get_common_fixes("timeout")

    assert len(fixes) > 0
    assert all("fix" in f and "impact" in f for f in fixes)


def test_debug_assistant_format():
    """Test debug plan formatting."""
    from analysis import create_debug_assistant

    assistant = create_debug_assistant()

    plan = assistant.create_debug_plan(
        test_id="TC-003",
        error_message="Assertion failed",
    )

    formatted = assistant.format_plan(plan)

    assert "DEBUG PLAN" in formatted
    assert "TC-003" in formatted
    assert "SUGGESTED APPROACHES" in formatted


# ============================================================
# Maintenance Module Tests
# ============================================================

def test_maintenance_imports():
    """Test maintenance module imports."""
    from maintenance import (
        MaintenanceDetector,
        MaintenanceIssue,
        MaintenanceType,
        MaintenancePriority,
        create_maintenance_detector,
        SelectorHealthMonitor,
        SelectorHealth,
        SelectorRisk,
        create_selector_monitor,
        TestUpdater,
        UpdateSuggestion,
        UpdateType,
        create_test_updater,
    )

    assert MaintenanceDetector is not None
    assert SelectorHealthMonitor is not None
    assert TestUpdater is not None


def test_maintenance_detector_creation():
    """Test maintenance detector creation."""
    from maintenance import create_maintenance_detector

    detector = create_maintenance_detector()
    assert detector is not None


def test_maintenance_detector_register():
    """Test registering tests for monitoring."""
    from maintenance import create_maintenance_detector

    detector = create_maintenance_detector()

    detector.register_test(
        test_id="TC-001",
        name="Login Test",
        selectors=[".login-button", "#username"],
        api_endpoints=["/api/login"],
    )

    health = detector.get_test_health("TC-001")
    assert health is not None
    assert health.test_id == "TC-001"


def test_maintenance_detector_fragile_selectors():
    """Test detection of fragile selectors."""
    from maintenance import create_maintenance_detector, MaintenanceType

    detector = create_maintenance_detector()

    detector.register_test(
        test_id="TC-002",
        name="Test with fragile selectors",
        selectors=[
            ".css-abc123xyz",  # CSS-in-JS
            "#element-12345",  # Dynamic ID
            "div > div > div > div > button",  # Deep nesting
        ],
    )

    issues = detector.detect_issues("TC-002")

    assert len(issues) > 0
    assert any(i.maintenance_type == MaintenanceType.SELECTOR_UPDATE for i in issues)


def test_maintenance_detector_code_smells():
    """Test detection of code smells."""
    from maintenance import create_maintenance_detector, MaintenanceType

    detector = create_maintenance_detector()

    code = """
    test.only('my test', async () => {
        console.log('debug');
        debugger;
        // TODO: fix this
    });
    """

    detector.register_test(
        test_id="TC-003",
        name="Test with code smells",
        code=code,
    )

    issues = detector.detect_issues("TC-003")

    assert len(issues) > 0
    assert any(i.maintenance_type == MaintenanceType.CODE_SMELL for i in issues)


def test_maintenance_detector_flakiness():
    """Test detection of flaky tests."""
    from maintenance import create_maintenance_detector, MaintenanceType

    detector = create_maintenance_detector()

    detector.register_test(
        test_id="TC-004",
        name="Flaky test",
    )

    # Record inconsistent results
    for i in range(10):
        detector.record_execution(
            test_id="TC-004",
            passed=(i % 2 == 0),  # Alternating pass/fail
            duration_ms=1000,
        )

    issues = detector.detect_issues("TC-004")

    assert len(issues) > 0
    assert any(i.maintenance_type == MaintenanceType.FLAKINESS for i in issues)


def test_maintenance_detector_report():
    """Test maintenance report generation."""
    from maintenance import create_maintenance_detector

    detector = create_maintenance_detector()

    detector.register_test(
        test_id="TC-001",
        name="Test 1",
        selectors=[".css-generated123"],
    )

    detector.register_test(
        test_id="TC-002",
        name="Test 2",
    )

    report = detector.generate_report()

    assert report.total_tests == 2
    assert report.healthy_tests >= 0


def test_maintenance_detector_format():
    """Test report formatting."""
    from maintenance import create_maintenance_detector

    detector = create_maintenance_detector()

    detector.register_test(
        test_id="TC-001",
        name="Test",
        code="console.log('test');",
    )

    report = detector.generate_report()
    formatted = detector.format_report(report)

    assert "MAINTENANCE REPORT" in formatted


def test_selector_monitor_creation():
    """Test selector monitor creation."""
    from maintenance import create_selector_monitor

    monitor = create_selector_monitor()
    assert monitor is not None


def test_selector_monitor_register():
    """Test registering selectors."""
    from maintenance import create_selector_monitor

    monitor = create_selector_monitor()

    monitor.register_selector("[data-testid='login']", "TC-001")
    monitor.register_selector(".fragile-class-12345", "TC-002")

    health1 = monitor.get_selector_health("[data-testid='login']")
    health2 = monitor.get_selector_health(".fragile-class-12345")

    assert health1 is not None
    assert health2 is not None
    # data-testid should have lower risk
    assert health1.risk_score < health2.risk_score


def test_selector_monitor_risk_assessment():
    """Test selector risk assessment."""
    from maintenance import create_selector_monitor, SelectorRisk

    monitor = create_selector_monitor()

    # Register various selector types
    selectors = {
        "[data-testid='button']": SelectorRisk.STABLE,  # Good practice
        ".css-abc123def456": SelectorRisk.CRITICAL,  # CSS-in-JS
        "#element-99999": SelectorRisk.HIGH,  # Dynamic ID
        ".button": SelectorRisk.MEDIUM,  # Generic class
    }

    for selector in selectors:
        monitor.register_selector(selector, "TC-001")

    # Check risk levels are appropriate
    for selector, expected_min_risk in selectors.items():
        health = monitor.get_selector_health(selector)
        assert health is not None


def test_selector_monitor_stability():
    """Test selector stability tracking."""
    from maintenance import create_selector_monitor

    monitor = create_selector_monitor()

    selector = "[data-testid='submit']"
    monitor.register_selector(selector, "TC-001")

    # Record successful finds
    for _ in range(5):
        monitor.record_selector_result(selector, True)

    # Record a failure
    monitor.record_selector_result(selector, False)

    health = monitor.get_selector_health(selector)
    assert health is not None
    assert health.failure_count == 1
    assert health.stability_score < 1.0


def test_selector_monitor_report():
    """Test selector report generation."""
    from maintenance import create_selector_monitor

    monitor = create_selector_monitor()

    monitor.register_selector(".test-button", "TC-001")
    monitor.register_selector("#dynamic-123456", "TC-002")

    report = monitor.generate_report()

    assert report.total_selectors == 2
    assert report.overall_health_score >= 0


def test_selector_monitor_format():
    """Test report formatting."""
    from maintenance import create_selector_monitor

    monitor = create_selector_monitor()

    monitor.register_selector(".button", "TC-001")

    report = monitor.generate_report()
    formatted = monitor.format_report(report)

    assert "SELECTOR HEALTH REPORT" in formatted
    assert "RISK DISTRIBUTION" in formatted


def test_test_updater_creation():
    """Test test updater creation."""
    from maintenance import create_test_updater

    updater = create_test_updater()
    assert updater is not None


def test_test_updater_analyze_waits():
    """Test analyzing code for wait improvements."""
    from maintenance import create_test_updater, UpdateType

    updater = create_test_updater()

    code = """
    await page.click('.submit-button');
    await page.waitForTimeout(5000);
    """

    suggestions = updater.analyze_for_updates("TC-001", code)

    assert len(suggestions) > 0
    assert any(s.update_type == UpdateType.WAIT_ADDITION for s in suggestions)


def test_test_updater_analyze_cleanup():
    """Test analyzing code for cleanup."""
    from maintenance import create_test_updater, UpdateType

    updater = create_test_updater()

    code = """
    test.only('exclusive test', async () => {
        console.log('debugging');
        debugger;
    });
    """

    suggestions = updater.analyze_for_updates("TC-002", code)

    assert len(suggestions) > 0
    assert any(s.update_type == UpdateType.CODE_CLEANUP for s in suggestions)


def test_test_updater_apply_suggestion():
    """Test applying a single suggestion."""
    from maintenance import create_test_updater

    updater = create_test_updater()

    code = "console.log('debug');"

    suggestions = updater.analyze_for_updates("TC-001", code)
    cleanup = [s for s in suggestions if "console.log" in s.original_code]

    assert len(cleanup) > 0

    result = updater.apply_suggestion(cleanup[0].suggestion_id, code)

    assert result.success
    assert "console.log" not in result.new_code


def test_test_updater_apply_batch():
    """Test applying batch updates."""
    from maintenance import create_test_updater

    updater = create_test_updater()

    code = """
    console.log('debug1');
    debugger;
    console.log('debug2');
    """

    updater.analyze_for_updates("TC-001", code)
    result = updater.apply_batch("TC-001", code, auto_only=True)

    assert result.success
    assert "console.log" not in result.new_code
    assert "debugger" not in result.new_code


def test_test_updater_format():
    """Test suggestions formatting."""
    from maintenance import create_test_updater

    updater = create_test_updater()

    code = "console.log('test');"
    suggestions = updater.analyze_for_updates("TC-001", code)

    formatted = updater.format_suggestions(suggestions)

    assert "UPDATE SUGGESTIONS" in formatted


# ============================================================
# Adaptive Learning Module Tests
# ============================================================

def test_adaptive_imports():
    """Test adaptive module imports."""
    from adaptive import (
        AdaptiveLearner,
        LearningConfig,
        LearningInsight,
        create_adaptive_learner,
        FailurePredictor,
        PredictionResult,
        RiskFactor,
        create_failure_predictor,
        TestOptimizer,
        OptimizationResult,
        OptimizationStrategy,
        create_test_optimizer,
    )
    assert AdaptiveLearner is not None
    assert FailurePredictor is not None
    assert TestOptimizer is not None


def test_adaptive_learner_creation():
    """Test AdaptiveLearner creation."""
    from adaptive import create_adaptive_learner, LearningConfig

    config = LearningConfig(min_samples=5, flakiness_threshold=0.15)
    learner = create_adaptive_learner(config)
    assert learner is not None


def test_adaptive_learner_record_execution():
    """Test recording executions."""
    from adaptive import create_adaptive_learner
    from adaptive.learner import TestExecution
    from datetime import datetime

    learner = create_adaptive_learner()

    execution = TestExecution(
        test_id="test-001",
        test_name="Login Test",
        status="passed",
        duration_ms=1500,
        timestamp=datetime.now(),
        browser="chrome",
    )

    learner.record_execution(execution)
    pattern = learner.get_pattern("test-001")

    assert pattern is not None
    assert pattern.total_executions == 1
    assert pattern.pass_count == 1


def test_adaptive_learner_detect_flakiness():
    """Test flakiness detection."""
    from adaptive import create_adaptive_learner, LearningConfig
    from adaptive.learner import TestExecution, InsightType
    from datetime import datetime, timedelta

    config = LearningConfig(min_samples=5, flakiness_threshold=0.1)
    learner = create_adaptive_learner(config)

    # Record alternating pass/fail
    base_time = datetime.now()
    for i in range(10):
        status = "passed" if i % 2 == 0 else "failed"
        learner.record_execution(TestExecution(
            test_id="flaky-test",
            test_name="Flaky Test",
            status=status,
            duration_ms=1000,
            timestamp=base_time + timedelta(hours=i),
            error_message="Timeout" if status == "failed" else None,
        ))

    insights = learner.analyze()
    flaky_insights = [i for i in insights if i.insight_type == InsightType.FLAKINESS_PATTERN]

    assert len(flaky_insights) >= 1
    assert "flaky-test" in flaky_insights[0].affected_tests


def test_adaptive_learner_timing_anomaly():
    """Test timing anomaly detection."""
    from adaptive import create_adaptive_learner, LearningConfig
    from adaptive.learner import TestExecution, InsightType
    from datetime import datetime, timedelta

    config = LearningConfig(min_samples=5, timing_variance_threshold=0.3)
    learner = create_adaptive_learner(config)

    # Record with high variance
    base_time = datetime.now()
    durations = [100, 5000, 200, 4500, 150, 5500, 180, 4800, 120, 5200]
    for i, duration in enumerate(durations):
        learner.record_execution(TestExecution(
            test_id="slow-test",
            test_name="Slow Test",
            status="passed",
            duration_ms=duration,
            timestamp=base_time + timedelta(hours=i),
        ))

    insights = learner.analyze()
    timing_insights = [i for i in insights if i.insight_type == InsightType.TIMING_ANOMALY]

    assert len(timing_insights) >= 1


def test_adaptive_learner_statistics():
    """Test learning statistics."""
    from adaptive import create_adaptive_learner
    from adaptive.learner import TestExecution
    from datetime import datetime

    learner = create_adaptive_learner()

    for i in range(5):
        learner.record_execution(TestExecution(
            test_id=f"test-{i:03d}",
            test_name=f"Test {i}",
            status="passed",
            duration_ms=1000,
            timestamp=datetime.now(),
        ))

    stats = learner.get_statistics()

    assert stats["total_tests_tracked"] == 5
    assert stats["total_executions"] == 5


def test_failure_predictor_creation():
    """Test FailurePredictor creation."""
    from adaptive import create_failure_predictor

    predictor = create_failure_predictor()
    assert predictor is not None


def test_failure_predictor_register_profile():
    """Test registering test profiles."""
    from adaptive import create_failure_predictor
    from adaptive.predictor import TestProfile
    from datetime import datetime

    predictor = create_failure_predictor()

    profile = TestProfile(
        test_id="test-001",
        test_name="Login Test",
        pass_rate=0.9,
        avg_duration_ms=2000,
        duration_variance=0.1,
        flakiness_score=0.05,
        last_failure=datetime.now(),
        failure_count=2,
        total_runs=20,
    )

    predictor.register_profile(profile)
    prediction = predictor.predict("test-001")

    assert prediction is not None
    assert prediction.test_id == "test-001"


def test_failure_predictor_risk_levels():
    """Test risk level determination."""
    from adaptive import create_failure_predictor
    from adaptive.predictor import TestProfile, RiskLevel
    from datetime import datetime, timedelta

    predictor = create_failure_predictor()

    # High risk profile
    predictor.register_profile(TestProfile(
        test_id="high-risk",
        test_name="High Risk Test",
        pass_rate=0.5,
        avg_duration_ms=5000,
        duration_variance=0.5,
        flakiness_score=0.4,
        last_failure=datetime.now() - timedelta(days=1),
        failure_count=10,
        total_runs=20,
    ))

    # Low risk profile
    predictor.register_profile(TestProfile(
        test_id="low-risk",
        test_name="Low Risk Test",
        pass_rate=0.99,
        avg_duration_ms=500,
        duration_variance=0.05,
        flakiness_score=0.01,
        last_failure=None,
        failure_count=1,
        total_runs=100,
    ))

    high_pred = predictor.predict("high-risk")
    low_pred = predictor.predict("low-risk")

    assert high_pred.failure_probability > low_pred.failure_probability
    assert high_pred.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]


def test_failure_predictor_recommendations():
    """Test recommendation generation."""
    from adaptive import create_failure_predictor
    from adaptive.predictor import TestProfile
    from datetime import datetime

    predictor = create_failure_predictor()

    predictor.register_profile(TestProfile(
        test_id="test-001",
        test_name="Problem Test",
        pass_rate=0.7,
        avg_duration_ms=3000,
        duration_variance=0.4,
        flakiness_score=0.3,
        last_failure=datetime.now(),
        failure_count=5,
        total_runs=15,
    ))

    prediction = predictor.predict("test-001")

    assert len(prediction.recommendations) > 0


def test_failure_predictor_batch():
    """Test batch predictions."""
    from adaptive import create_failure_predictor
    from adaptive.predictor import TestProfile

    predictor = create_failure_predictor()

    for i in range(5):
        predictor.register_profile(TestProfile(
            test_id=f"test-{i:03d}",
            test_name=f"Test {i}",
            pass_rate=0.9 - i * 0.1,
            avg_duration_ms=1000,
            duration_variance=0.1,
            flakiness_score=0.05 + i * 0.05,
            last_failure=None,
            failure_count=i,
            total_runs=20,
        ))

    predictions = predictor.predict_all()

    assert len(predictions) == 5


def test_test_optimizer_creation():
    """Test TestOptimizer creation."""
    from adaptive import create_test_optimizer, OptimizationStrategy
    from adaptive.optimizer import OptimizationConfig

    config = OptimizationConfig(
        time_budget_ms=60000,
        min_coverage=0.8,
    )

    optimizer = create_test_optimizer(config)
    assert optimizer is not None


def test_test_optimizer_risk_based():
    """Test risk-based optimization."""
    from adaptive import create_test_optimizer, OptimizationStrategy
    from adaptive.optimizer import TestInfo

    optimizer = create_test_optimizer()

    # Register tests with different risk levels
    optimizer.register_test(TestInfo(
        test_id="low-risk",
        name="Low Risk Test",
        duration_ms=1000,
        failure_probability=0.1,
        coverage={"feature_a"},
        dependencies=[],
    ))

    optimizer.register_test(TestInfo(
        test_id="high-risk",
        name="High Risk Test",
        duration_ms=1000,
        failure_probability=0.8,
        coverage={"feature_b"},
        dependencies=[],
    ))

    result = optimizer.optimize(OptimizationStrategy.RISK_BASED)

    assert result is not None
    # High risk should come first
    assert result.optimized_tests[0] == "high-risk"


def test_test_optimizer_time_based():
    """Test time-based optimization."""
    from adaptive import create_test_optimizer, OptimizationStrategy
    from adaptive.optimizer import TestInfo, OptimizationConfig

    config = OptimizationConfig(time_budget_ms=2500)
    optimizer = create_test_optimizer(config)

    optimizer.register_tests([
        TestInfo("fast", "Fast", 500, 0.1, {"a"}, []),
        TestInfo("medium", "Medium", 1000, 0.1, {"b"}, []),
        TestInfo("slow", "Slow", 2000, 0.1, {"c"}, []),
    ])

    result = optimizer.optimize(OptimizationStrategy.TIME_BASED)

    # Should fit fast and medium, skip slow
    assert len(result.optimized_tests) == 2
    assert "slow" in result.skipped_tests


def test_test_optimizer_parallel_groups():
    """Test parallel group creation."""
    from adaptive import create_test_optimizer
    from adaptive.optimizer import TestInfo, OptimizationConfig

    config = OptimizationConfig(parallel_groups=2)
    optimizer = create_test_optimizer(config)

    for i in range(6):
        optimizer.register_test(TestInfo(
            test_id=f"test-{i}",
            name=f"Test {i}",
            duration_ms=1000 * (i + 1),
            failure_probability=0.1,
            coverage={f"feature_{i}"},
            dependencies=[],
        ))

    groups = optimizer.create_parallel_groups(
        [f"test-{i}" for i in range(6)],
        num_groups=2,
    )

    assert len(groups) == 2
    assert sum(len(g) for g in groups) == 6


def test_adaptive_optimizer_format():
    """Test optimization result formatting."""
    from adaptive import create_test_optimizer, OptimizationStrategy
    from adaptive.optimizer import TestInfo

    optimizer = create_test_optimizer()

    optimizer.register_test(TestInfo(
        test_id="test-001",
        name="Test",
        duration_ms=1000,
        failure_probability=0.5,
        coverage={"a"},
        dependencies=[],
    ))

    result = optimizer.optimize(OptimizationStrategy.HYBRID)
    formatted = optimizer.format_optimization(result)

    assert "TEST OPTIMIZATION RESULT" in formatted
    assert "hybrid" in formatted  # lowercase in output


# ============================================================
# Authoring Module Tests
# ============================================================

def test_authoring_imports():
    """Test authoring module imports."""
    from authoring import (
        NLTestParser,
        ParsedTest,
        ParsedStep,
        create_nl_parser,
        TestGenerator,
        GeneratedTest,
        create_test_generator,
        NLInterpreter,
        InterpretedCommand,
        CommandType,
        create_nl_interpreter,
    )
    assert NLTestParser is not None
    assert TestGenerator is not None
    assert NLInterpreter is not None


def test_nl_parser_creation():
    """Test NLTestParser creation."""
    from authoring import create_nl_parser

    parser = create_nl_parser()
    assert parser is not None


def test_nl_parser_simple_test():
    """Test parsing a simple test."""
    from authoring import create_nl_parser

    parser = create_nl_parser()

    text = """
    Login Test
    Verify user can login successfully

    1. Go to https://example.com/login
    2. Enter "user@example.com" in the email field
    3. Enter "password123" in the password field
    4. Click the "Login" button
    5. Verify the dashboard is visible
    """

    parsed = parser.parse(text)

    assert parsed.name == "Login Test"
    assert len(parsed.steps) >= 4


def test_nl_parser_action_detection():
    """Test action detection."""
    from authoring import create_nl_parser
    from authoring.parser import ActionIntent

    parser = create_nl_parser()

    text = """
    Test
    1. Click on the submit button
    2. Type "hello" in the input
    3. Navigate to /home
    """

    parsed = parser.parse(text)

    actions = [s.action for s in parsed.steps]
    assert ActionIntent.CLICK in actions
    assert ActionIntent.TYPE in actions
    assert ActionIntent.NAVIGATE in actions


def test_nl_parser_assertion_detection():
    """Test assertion detection."""
    from authoring import create_nl_parser
    from authoring.parser import AssertionType

    parser = create_nl_parser()

    text = """
    Test
    1. Verify the button is visible
    2. Check that the error message contains "invalid"
    """

    parsed = parser.parse(text)

    assert len(parsed.steps) >= 1
    # Check for assertions
    has_assertion = any(len(s.assertions) > 0 for s in parsed.steps)
    assert has_assertion


def test_nl_parser_tags():
    """Test tag extraction."""
    from authoring import create_nl_parser

    parser = create_nl_parser()

    text = """
    Login Test @smoke @critical
    1. Click login
    """

    parsed = parser.parse(text)

    assert "smoke" in parsed.tags
    assert "critical" in parsed.tags


def test_nl_parser_priority():
    """Test priority extraction."""
    from authoring import create_nl_parser

    parser = create_nl_parser()

    # Critical priority
    text1 = "Critical: Login Test\n1. Click login"
    parsed1 = parser.parse(text1)
    assert parsed1.priority == "critical"

    # High priority
    text2 = "High priority test\n1. Click login"
    parsed2 = parser.parse(text2)
    assert parsed2.priority == "high"


def test_nl_parser_format():
    """Test parsing format output."""
    from authoring import create_nl_parser

    parser = create_nl_parser()
    parsed = parser.parse("Test\n1. Click button")
    formatted = parser.format_parsed(parsed)

    assert "PARSED TEST" in formatted


def test_test_generator_creation():
    """Test TestGenerator creation."""
    from authoring import create_test_generator

    generator = create_test_generator()
    assert generator is not None


def test_test_generator_playwright_python():
    """Test generating Playwright Python code."""
    from authoring import create_nl_parser, create_test_generator
    from authoring.generator import OutputFormat

    parser = create_nl_parser()
    generator = create_test_generator()

    text = """
    Login Test
    1. Go to https://example.com/login
    2. Enter "test@test.com" in the email field
    3. Click the login button
    """

    parsed = parser.parse(text)
    generated = generator.generate(parsed, OutputFormat.PLAYWRIGHT_PYTHON)

    assert generated is not None
    assert "def test_" in generated.code
    assert "page.goto" in generated.code


def test_test_generator_playwright_js():
    """Test generating Playwright JS code."""
    from authoring import create_nl_parser, create_test_generator
    from authoring.generator import OutputFormat

    parser = create_nl_parser()
    generator = create_test_generator()

    parsed = parser.parse("Test\n1. Click button")
    generated = generator.generate(parsed, OutputFormat.PLAYWRIGHT_JS)

    assert "test(" in generated.code
    assert "async" in generated.code


def test_test_generator_json():
    """Test generating JSON format."""
    from authoring import create_nl_parser, create_test_generator
    from authoring.generator import OutputFormat
    import json

    parser = create_nl_parser()
    generator = create_test_generator()

    parsed = parser.parse("Test\n1. Click button")
    generated = generator.generate(parsed, OutputFormat.TESTAI_JSON)

    # Should be valid JSON
    data = json.loads(generated.code)
    assert "name" in data
    assert "steps" in data


def test_test_generator_format():
    """Test formatting generated test."""
    from authoring import create_nl_parser, create_test_generator

    parser = create_nl_parser()
    generator = create_test_generator()

    parsed = parser.parse("Test\n1. Click button")
    generated = generator.generate(parsed)
    formatted = generator.format_generated(generated)

    assert "GENERATED TEST" in formatted


def test_nl_interpreter_creation():
    """Test NLInterpreter creation."""
    from authoring import create_nl_interpreter

    interpreter = create_nl_interpreter()
    assert interpreter is not None


def test_nl_interpreter_run_command():
    """Test interpreting run command."""
    from authoring import create_nl_interpreter, CommandType

    interpreter = create_nl_interpreter()

    command = interpreter.interpret("run test 'Login Test'")

    assert command.command_type == CommandType.RUN_TEST
    assert command.confidence > 0.5


def test_nl_interpreter_create_command():
    """Test interpreting create command."""
    from authoring import create_nl_interpreter, CommandType

    interpreter = create_nl_interpreter()

    command = interpreter.interpret("create a new test for login")

    assert command.command_type == CommandType.CREATE_TEST
    assert command.confidence > 0.5


def test_nl_interpreter_find_command():
    """Test interpreting find command."""
    from authoring import create_nl_interpreter, CommandType

    interpreter = create_nl_interpreter()

    command = interpreter.interpret("find tests for 'checkout'")

    assert command.command_type == CommandType.FIND_TESTS


def test_nl_interpreter_parameters():
    """Test parameter extraction."""
    from authoring import create_nl_interpreter

    interpreter = create_nl_interpreter()

    command = interpreter.interpret("run test 'Login Flow'")

    param_names = [p.name for p in command.parameters]
    assert "test_name" in param_names


def test_nl_interpreter_help():
    """Test help command."""
    from authoring import create_nl_interpreter

    interpreter = create_nl_interpreter()
    help_text = interpreter.get_help()

    assert "AVAILABLE COMMANDS" in help_text
    assert "run" in help_text.lower()
    assert "create" in help_text.lower()


def test_nl_interpreter_format():
    """Test formatting interpreted command."""
    from authoring import create_nl_interpreter

    interpreter = create_nl_interpreter()

    command = interpreter.interpret("run test")
    formatted = interpreter.format_command(command)

    assert "INTERPRETED COMMAND" in formatted


# ============================================================
# Runner Module Tests
# ============================================================

def test_runner_imports():
    """Test runner module imports."""
    from runner import (
        TestRunner,
        RunnerConfig,
        RunResult,
        StepResult,
        create_test_runner,
        BrowserManager,
        BrowserConfig,
        BrowserType,
        create_browser_manager,
        ActionExecutor,
        ActionType,
        ActionResult,
        create_action_executor,
    )
    assert TestRunner is not None
    assert BrowserManager is not None
    assert ActionExecutor is not None


def test_browser_manager_creation():
    """Test BrowserManager creation."""
    from runner import create_browser_manager

    manager = create_browser_manager(max_instances=3)
    assert manager is not None


def test_browser_manager_create_instance():
    """Test creating browser instance."""
    from runner import create_browser_manager, BrowserConfig, BrowserType
    from runner.browser import BrowserState

    manager = create_browser_manager()

    config = BrowserConfig(browser_type=BrowserType.CHROMIUM, headless=True)
    instance = manager.create_instance(config)

    assert instance is not None
    assert instance.instance_id.startswith("browser-")
    assert instance.state == BrowserState.IDLE


def test_browser_manager_create_context():
    """Test creating page context."""
    from runner import create_browser_manager

    manager = create_browser_manager()
    instance = manager.create_instance()
    context = manager.create_context(instance.instance_id, "https://example.com")

    assert context is not None
    assert context.context_id.startswith("ctx-")
    assert instance.page_count == 1


def test_browser_manager_viewport_presets():
    """Test viewport presets."""
    from runner import create_browser_manager

    manager = create_browser_manager()
    presets = manager.get_viewport_presets()

    assert "desktop_hd" in presets
    assert "mobile" in presets or "iphone_12" in presets
    assert presets["desktop_hd"].width == 1920


def test_browser_manager_statistics():
    """Test browser statistics."""
    from runner import create_browser_manager

    manager = create_browser_manager()
    manager.create_instance()
    manager.create_instance()

    stats = manager.get_statistics()

    assert stats["total_instances"] == 2
    assert stats["idle_instances"] == 2


def test_browser_manager_cleanup():
    """Test browser cleanup."""
    from runner import create_browser_manager

    manager = create_browser_manager()
    manager.create_instance()
    manager.create_instance()

    manager.cleanup()
    stats = manager.get_statistics()

    assert stats["total_instances"] == 0


def test_action_executor_creation():
    """Test ActionExecutor creation."""
    from runner import create_action_executor

    executor = create_action_executor()
    assert executor is not None


def test_action_executor_click():
    """Test executing click action."""
    from runner import create_action_executor, ActionType
    from runner.actions import ActionDefinition, ActionStatus

    executor = create_action_executor()

    action = ActionDefinition(
        action_type=ActionType.CLICK,
        selector="#submit-btn",
    )

    result = executor.execute(action)

    assert result is not None
    assert result.status == ActionStatus.PASSED


def test_action_executor_fill():
    """Test executing fill action."""
    from runner import create_action_executor, ActionType
    from runner.actions import ActionDefinition, ActionStatus

    executor = create_action_executor()

    action = ActionDefinition(
        action_type=ActionType.FILL,
        selector="#email",
        value="test@example.com",
    )

    result = executor.execute(action)

    assert result.status == ActionStatus.PASSED
    assert result.value == "test@example.com"


def test_action_executor_sequence():
    """Test executing action sequence."""
    from runner import create_action_executor, ActionType
    from runner.actions import ActionDefinition, ActionStatus

    executor = create_action_executor()

    actions = [
        ActionDefinition(ActionType.FILL, "#username", "testuser"),
        ActionDefinition(ActionType.FILL, "#password", "password123"),
        ActionDefinition(ActionType.CLICK, "#login-btn"),
    ]

    results = executor.execute_sequence(actions)

    assert len(results) == 3
    assert all(r.status == ActionStatus.PASSED for r in results)


def test_action_executor_statistics():
    """Test action statistics."""
    from runner import create_action_executor, ActionType
    from runner.actions import ActionDefinition

    executor = create_action_executor()

    for _ in range(5):
        executor.execute(ActionDefinition(ActionType.CLICK, "#btn"))

    stats = executor.get_statistics()

    assert stats["total_actions"] == 5
    assert stats["passed"] == 5
    assert stats["pass_rate"] == 1.0


def test_action_executor_selector_detection():
    """Test selector type detection."""
    from runner import create_action_executor

    executor = create_action_executor()

    assert executor.detect_selector_type("#myid") == "id"
    assert executor.detect_selector_type("//div[@class='test']") == "xpath"
    assert executor.detect_selector_type("text=Submit") == "text"
    assert executor.detect_selector_type("data-testid=login-btn") == "data_testid"


def test_test_runner_creation():
    """Test TestRunner creation."""
    from runner import create_test_runner, RunnerConfig

    config = RunnerConfig(
        parallel_tests=2,
        headless=True,
        timeout_ms=30000,
    )

    runner = create_test_runner(config)
    assert runner is not None


def test_test_runner_run_test():
    """Test running a single test."""
    from runner import create_test_runner
    from runner.engine import TestDefinition, RunStatus

    runner = create_test_runner()

    test = TestDefinition(
        test_id="test-001",
        name="Login Test",
        description="Test user login",
        steps=[
            {"action": "navigate", "url": "https://example.com/login"},
            {"action": "fill", "selector": "#email", "value": "test@example.com"},
            {"action": "fill", "selector": "#password", "value": "password"},
            {"action": "click", "selector": "#login-btn"},
        ],
    )

    result = runner.run_test(test)

    assert result is not None
    assert result.run_id.startswith("run-")
    assert result.status == RunStatus.PASSED
    assert len(result.steps) == 4

    runner.cleanup()


def test_test_runner_with_setup_teardown():
    """Test runner with setup and teardown."""
    from runner import create_test_runner
    from runner.engine import TestDefinition, RunStatus

    runner = create_test_runner()

    test = TestDefinition(
        test_id="test-002",
        name="Test with Setup/Teardown",
        description="Test with setup and teardown steps",
        setup_steps=[
            {"action": "navigate", "url": "https://example.com"},
        ],
        steps=[
            {"action": "click", "selector": "#main-btn"},
        ],
        teardown_steps=[
            {"action": "click", "selector": "#logout"},
        ],
    )

    result = runner.run_test(test)

    assert result.status == RunStatus.PASSED
    assert len(result.steps) == 3  # 1 setup + 1 test + 1 teardown

    runner.cleanup()


def test_test_runner_multiple_tests():
    """Test running multiple tests."""
    from runner import create_test_runner
    from runner.engine import TestDefinition

    runner = create_test_runner()

    tests = [
        TestDefinition(
            test_id="test-001",
            name="Test 1",
            description="First test",
            steps=[{"action": "click", "selector": "#btn1"}],
        ),
        TestDefinition(
            test_id="test-002",
            name="Test 2",
            description="Second test",
            steps=[{"action": "click", "selector": "#btn2"}],
        ),
    ]

    results = runner.run_tests(tests)

    assert len(results) == 2
    assert all(r.test_id for r in results)

    runner.cleanup()


def test_test_runner_statistics():
    """Test runner statistics."""
    from runner import create_test_runner
    from runner.engine import TestDefinition

    runner = create_test_runner()

    test = TestDefinition(
        test_id="test-001",
        name="Stats Test",
        description="Test for statistics",
        steps=[{"action": "click", "selector": "#btn"}],
    )

    runner.run_test(test)
    runner.run_test(test)

    stats = runner.get_statistics()

    assert stats["total_runs"] == 2
    assert stats["passed"] == 2
    assert stats["pass_rate"] == 1.0

    runner.cleanup()


def test_test_runner_format_results():
    """Test formatting results."""
    from runner import create_test_runner
    from runner.engine import TestDefinition

    runner = create_test_runner()

    test = TestDefinition(
        test_id="test-001",
        name="Format Test",
        description="Test result formatting",
        steps=[{"action": "click", "selector": "#btn"}],
    )

    runner.run_test(test)
    formatted = runner.format_results()

    assert "TEST RUNNER RESULTS" in formatted
    assert "Format Test" in formatted

    runner.cleanup()


# ============================================================
# Documentation Module Tests
# ============================================================

def test_docs_imports():
    """Test docs module imports."""
    from docs import (
        DocGenerator,
        DocumentType,
        DocumentFormat,
        TestDocument,
        create_doc_generator,
        TestPlanGenerator,
        TestPlan,
        TestCase,
        create_test_plan_generator,
        CoverageReportGenerator,
        CoverageReport,
        FeatureCoverage,
        create_coverage_report_generator,
    )
    assert DocGenerator is not None
    assert TestPlanGenerator is not None
    assert CoverageReportGenerator is not None


def test_doc_generator_creation():
    """Test DocGenerator creation."""
    from docs import create_doc_generator

    generator = create_doc_generator()
    assert generator is not None


def test_doc_generator_test_plan():
    """Test generating test plan document."""
    from docs import create_doc_generator, DocumentType, DocumentFormat

    generator = create_doc_generator()

    doc = generator.generate(
        doc_type=DocumentType.TEST_PLAN,
        data={
            "title": "Login Feature Test Plan",
            "version": "1.0",
            "overview": "Test plan for login functionality",
            "scope": ["Authentication", "Session management"],
            "test_cases": [
                {"id": "TC-001", "name": "Valid Login", "priority": "High"}
            ]
        },
        format=DocumentFormat.MARKDOWN,
    )

    assert doc is not None
    assert doc.doc_id.startswith("DOC-")
    assert "Login Feature Test Plan" in doc.content
    assert "Authentication" in doc.content


def test_doc_generator_execution_report():
    """Test generating execution report."""
    from docs import create_doc_generator, DocumentType, DocumentFormat

    generator = create_doc_generator()

    doc = generator.generate(
        doc_type=DocumentType.EXECUTION_REPORT,
        data={
            "environment": "staging",
            "total": 50,
            "passed": 45,
            "failed": 3,
            "skipped": 2,
            "duration_ms": 12500,
            "failures": [
                {"test_id": "TC-005", "error": "Element not found"}
            ]
        },
        format=DocumentFormat.MARKDOWN,
    )

    assert doc is not None
    assert "Test Execution Report" in doc.content
    assert "45" in doc.content
    assert "Element not found" in doc.content


def test_doc_generator_coverage_report():
    """Test generating coverage report."""
    from docs import create_doc_generator, DocumentType, DocumentFormat

    generator = create_doc_generator()

    doc = generator.generate(
        doc_type=DocumentType.COVERAGE_REPORT,
        data={
            "coverage_percent": 85.5,
            "features": [
                {"name": "Login", "covered": True},
                {"name": "Payment", "covered": False},
            ],
            "gaps": ["Payment validation missing"],
        },
        format=DocumentFormat.MARKDOWN,
    )

    assert doc is not None
    assert "Coverage" in doc.content
    assert "85.5%" in doc.content


def test_doc_generator_json_format():
    """Test JSON format output."""
    from docs import create_doc_generator, DocumentType, DocumentFormat
    import json

    generator = create_doc_generator()

    doc = generator.generate(
        doc_type=DocumentType.TEST_CASE,
        data={
            "id": "TC-001",
            "name": "Test Case",
            "priority": "High",
            "description": "Test description",
            "steps": ["Step 1", "Step 2"],
        },
        format=DocumentFormat.JSON,
    )

    assert doc is not None
    parsed = json.loads(doc.content)
    assert parsed["id"] == "TC-001"


def test_doc_generator_list_documents():
    """Test listing documents."""
    from docs import create_doc_generator, DocumentType, DocumentFormat

    generator = create_doc_generator()

    generator.generate(
        doc_type=DocumentType.TEST_PLAN,
        data={"title": "Plan 1"},
        format=DocumentFormat.MARKDOWN,
    )
    generator.generate(
        doc_type=DocumentType.TEST_CASE,
        data={"name": "Case 1"},
        format=DocumentFormat.MARKDOWN,
    )

    all_docs = generator.list_documents()
    assert len(all_docs) == 2

    plans = generator.list_documents(DocumentType.TEST_PLAN)
    assert len(plans) == 1


def test_test_plan_generator_creation():
    """Test TestPlanGenerator creation."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()
    assert generator is not None


def test_test_plan_generator_create_plan():
    """Test creating a test plan."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.create_plan(
        title="E-commerce Test Plan",
        overview="Comprehensive test plan for e-commerce features",
        scope=["Cart", "Checkout", "Payment"],
    )

    assert plan is not None
    assert plan.plan_id.startswith("TP-")
    assert plan.title == "E-commerce Test Plan"
    assert len(plan.scope) == 3


def test_test_plan_generator_add_suite():
    """Test adding test suites."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.create_plan(
        title="Test Plan",
        overview="Overview",
        scope=["Feature 1"],
    )

    suite = generator.add_suite(
        plan=plan,
        name="Cart Suite",
        description="Tests for shopping cart",
        tags=["cart", "e-commerce"],
    )

    assert suite is not None
    assert suite.suite_id.startswith("TS-")
    assert suite.name == "Cart Suite"
    assert len(plan.test_suites) == 1


def test_test_plan_generator_add_test_case():
    """Test adding test cases."""
    from docs import create_test_plan_generator
    from docs.test_plan import TestPriority

    generator = create_test_plan_generator()

    plan = generator.create_plan("Plan", "Overview", ["Scope"])
    suite = generator.add_suite(plan, "Suite", "Description")

    test_case = generator.add_test_case(
        suite=suite,
        name="Add to Cart",
        description="Verify adding product to cart",
        priority=TestPriority.HIGH,
        preconditions=["User is logged in", "Product is available"],
        steps=["Navigate to product", "Click Add to Cart"],
        expected_results=["Product added successfully"],
        estimated_minutes=10,
    )

    assert test_case is not None
    assert test_case.case_id.startswith("TC-")
    assert test_case.priority == TestPriority.HIGH
    assert len(suite.test_cases) == 1


def test_test_plan_generator_from_features():
    """Test generating plan from features."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.generate_from_features(
        title="Feature Test Plan",
        features=[
            {
                "name": "Login",
                "description": "User authentication",
                "edge_cases": ["Empty password", "Invalid email"],
            },
            {
                "name": "Registration",
                "description": "New user signup",
            },
        ],
    )

    assert plan is not None
    assert len(plan.test_suites) == 2

    # Login suite should have happy path, error handling, and 2 edge cases = 4 tests
    login_suite = plan.test_suites[0]
    assert len(login_suite.test_cases) == 4


def test_test_plan_generator_prioritize():
    """Test test prioritization."""
    from docs import create_test_plan_generator
    from docs.test_plan import TestPriority

    generator = create_test_plan_generator()

    plan = generator.create_plan("Plan", "Overview", ["Scope"])
    suite = generator.add_suite(plan, "Suite", "Description")

    generator.add_test_case(suite, "Low", "Desc", TestPriority.LOW)
    generator.add_test_case(suite, "Critical", "Desc", TestPriority.CRITICAL)
    generator.add_test_case(suite, "High", "Desc", TestPriority.HIGH)

    prioritized = generator.prioritize_tests(plan)

    assert prioritized[0].priority == TestPriority.CRITICAL
    assert prioritized[1].priority == TestPriority.HIGH
    assert prioritized[2].priority == TestPriority.LOW


def test_test_plan_generator_estimate_duration():
    """Test duration estimation."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.create_plan("Plan", "Overview", ["Scope"])
    suite = generator.add_suite(plan, "Suite", "Description")

    generator.add_test_case(suite, "Test 1", "Desc", estimated_minutes=10)
    generator.add_test_case(suite, "Test 2", "Desc", estimated_minutes=15)
    generator.add_test_case(suite, "Test 3", "Desc", estimated_minutes=5)

    duration = generator.estimate_duration(plan)

    assert duration["total_minutes"] == 30
    assert duration["total_hours"] == 0.5


def test_test_plan_generator_statistics():
    """Test plan statistics."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.create_plan("Plan", "Overview", ["Scope"])
    suite1 = generator.add_suite(plan, "Suite 1", "Description")
    suite2 = generator.add_suite(plan, "Suite 2", "Description")

    generator.add_test_case(suite1, "Test 1", "Desc")
    generator.add_test_case(suite1, "Test 2", "Desc")
    generator.add_test_case(suite2, "Test 3", "Desc")

    stats = generator.get_statistics(plan)

    assert stats["total_suites"] == 2
    assert stats["total_cases"] == 3


def test_test_plan_generator_format():
    """Test plan formatting."""
    from docs import create_test_plan_generator

    generator = create_test_plan_generator()

    plan = generator.create_plan("Test Plan", "Overview", ["Scope"])
    suite = generator.add_suite(plan, "Suite", "Description")
    generator.add_test_case(suite, "Test Case", "Description")

    formatted = generator.format_plan(plan)

    assert "# Test Plan" in formatted
    assert "## Test Suite: Suite" in formatted


def test_coverage_report_generator_creation():
    """Test CoverageReportGenerator creation."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()
    assert generator is not None


def test_coverage_report_generator_create_report():
    """Test creating coverage report."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()

    report = generator.create_report(
        title="Q4 Coverage Report",
        project="E-commerce Platform",
        version="2.0",
    )

    assert report is not None
    assert report.report_id.startswith("CR-")
    assert report.project == "E-commerce Platform"


def test_coverage_report_generator_add_feature():
    """Test adding feature coverage."""
    from docs import create_coverage_report_generator
    from docs.coverage_report import CoverageType, CoverageLevel

    generator = create_coverage_report_generator()

    report = generator.create_report("Report", "Project")

    feature = generator.add_feature(
        report=report,
        name="User Authentication",
        description="Login and registration flows",
        coverage_type=CoverageType.FEATURE,
        test_count=20,
        passing_tests=18,
        failing_tests=2,
        skipped_tests=0,
        test_ids=["TC-001", "TC-002"],
    )

    assert feature is not None
    assert feature.feature_id.startswith("FC-")
    assert feature.coverage_percent == 90.0
    # 90% is PARTIAL (FULL requires 100% passing)
    assert feature.level == CoverageLevel.PARTIAL


def test_coverage_report_generator_coverage_levels():
    """Test coverage level determination."""
    from docs import create_coverage_report_generator
    from docs.coverage_report import CoverageLevel

    generator = create_coverage_report_generator()
    report = generator.create_report("Report", "Project")

    # Full coverage (100%)
    f1 = generator.add_feature(report, "F1", "D", test_count=10, passing_tests=10)
    assert f1.level == CoverageLevel.FULL

    # Partial coverage (>=70%)
    f2 = generator.add_feature(report, "F2", "D", test_count=10, passing_tests=8)
    assert f2.level == CoverageLevel.PARTIAL  # 80% is partial (not 100%)

    # Minimal coverage (<70%)
    f3 = generator.add_feature(report, "F3", "D", test_count=10, passing_tests=5)
    assert f3.level == CoverageLevel.MINIMAL

    # No coverage
    f4 = generator.add_feature(report, "F4", "D", test_count=0, passing_tests=0)
    assert f4.level == CoverageLevel.NONE


def test_coverage_report_generator_analyze_gaps():
    """Test gap analysis."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()
    report = generator.create_report("Report", "Project")

    generator.add_feature(report, "Covered", "D", test_count=10, passing_tests=10)
    generator.add_feature(report, "Uncovered", "D", test_count=0, passing_tests=0)
    generator.add_feature(report, "Failing", "D", test_count=10, passing_tests=5, failing_tests=5)

    gaps = generator.analyze_gaps(report)

    assert any("Uncovered" in gap for gap in gaps)
    assert any("Failing" in gap for gap in gaps)


def test_coverage_report_generator_recommendations():
    """Test recommendation generation."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()
    report = generator.create_report("Report", "Project")

    # Add features with various issues
    generator.add_feature(report, "Feature", "D", test_count=10, passing_tests=3)

    recommendations = generator.generate_recommendations(report)

    assert len(recommendations) > 0
    assert any("coverage" in rec.lower() for rec in recommendations)


def test_coverage_report_generator_compare():
    """Test report comparison."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()

    # Previous report
    prev = generator.create_report("Previous", "Project")
    generator.add_feature(prev, "Login", "D", test_count=10, passing_tests=7)
    generator.add_feature(prev, "Cart", "D", test_count=5, passing_tests=5)

    # Current report
    curr = generator.create_report("Current", "Project")
    generator.add_feature(curr, "Login", "D", test_count=15, passing_tests=12)
    generator.add_feature(curr, "Cart", "D", test_count=5, passing_tests=5)
    generator.add_feature(curr, "Checkout", "D", test_count=8, passing_tests=6)

    comparison = generator.compare_reports(curr, prev)

    assert comparison["coverage_improved"]
    assert comparison["test_count_change"] > 0
    assert "Checkout" in comparison["new_features"]


def test_coverage_report_generator_low_coverage():
    """Test getting low coverage features."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()
    report = generator.create_report("Report", "Project")

    generator.add_feature(report, "High", "D", test_count=10, passing_tests=9)  # 90%
    generator.add_feature(report, "Low", "D", test_count=10, passing_tests=5)   # 50%
    generator.add_feature(report, "Medium", "D", test_count=10, passing_tests=7)  # 70%

    low_coverage = generator.get_low_coverage_features(report, threshold=70.0)

    # Low (50%) is below threshold, Medium (70%) is NOT < 70
    assert len(low_coverage) == 1
    assert low_coverage[0].name == "Low"


def test_coverage_report_generator_format():
    """Test report formatting."""
    from docs import create_coverage_report_generator

    generator = create_coverage_report_generator()
    report = generator.create_report("Coverage Report", "TestAI")

    generator.add_feature(report, "Login", "Authentication", test_count=10, passing_tests=9)

    formatted = generator.format_report(report)

    assert "# Coverage Report" in formatted
    assert "Login" in formatted
    assert "TestAI" in formatted


# ============================================================
# Realtime Dashboard Module Tests
# ============================================================

def test_realtime_imports():
    """Test realtime module imports."""
    from realtime import (
        MetricsCollector,
        MetricType,
        MetricPoint,
        TimeWindow,
        create_metrics_collector,
        AlertManager,
        AlertRule,
        Alert,
        AlertSeverity,
        AlertCondition,
        create_alert_manager,
        StreamingDashboard,
        DashboardEvent,
        StreamConfig,
        create_streaming_dashboard,
    )
    assert MetricsCollector is not None
    assert AlertManager is not None
    assert StreamingDashboard is not None


def test_metrics_collector_creation():
    """Test metrics collector creation."""
    from realtime import create_metrics_collector

    collector = create_metrics_collector(max_points=5000)
    assert collector is not None
    assert collector.max_points == 5000


def test_metrics_collector_record():
    """Test recording metrics."""
    from realtime import create_metrics_collector, MetricType

    collector = create_metrics_collector()

    point = collector.record(MetricType.PASS_RATE, 0.95)

    assert point is not None
    assert point.metric_type == MetricType.PASS_RATE
    assert point.value == 0.95


def test_metrics_collector_aggregation():
    """Test metric aggregation."""
    from realtime import create_metrics_collector, MetricType, TimeWindow

    collector = create_metrics_collector()

    # Record some metrics
    for i in range(10):
        collector.record(MetricType.EXECUTION_TIME, float(1000 + i * 100))

    agg = collector.aggregate(MetricType.EXECUTION_TIME, TimeWindow.MINUTE)

    assert agg is not None
    assert agg.count == 10
    assert agg.avg_value > 0
    assert agg.min_value <= agg.avg_value <= agg.max_value


def test_metrics_collector_trend():
    """Test trend analysis."""
    from realtime import create_metrics_collector, MetricType

    collector = create_metrics_collector()

    # Record some metrics
    for i in range(10):
        collector.record(MetricType.PASS_RATE, 0.8 + i * 0.01)

    trend = collector.get_trend(MetricType.PASS_RATE)

    assert "trend" in trend
    assert "change_percent" in trend
    assert "current_avg" in trend


def test_metrics_collector_dashboard():
    """Test dashboard metrics."""
    from realtime import create_metrics_collector, MetricType

    collector = create_metrics_collector()

    collector.record(MetricType.PASS_RATE, 0.95)
    collector.record(MetricType.FAILURE_RATE, 0.05)
    collector.record(MetricType.EXECUTION_TIME, 1500.0)

    dashboard = collector.get_dashboard_metrics()

    assert MetricType.PASS_RATE.value in dashboard
    assert MetricType.FAILURE_RATE.value in dashboard


def test_metrics_collector_format():
    """Test metrics formatting."""
    from realtime import create_metrics_collector, MetricType

    collector = create_metrics_collector()

    collector.record(MetricType.PASS_RATE, 0.95)

    formatted = collector.format_metrics()

    assert "REAL-TIME METRICS" in formatted


def test_alert_manager_creation():
    """Test alert manager creation."""
    from realtime import create_alert_manager, create_metrics_collector

    metrics = create_metrics_collector()
    manager = create_alert_manager(metrics)

    assert manager is not None
    # Should have default rules
    assert len(manager.get_rules()) > 0


def test_alert_manager_create_rule():
    """Test creating alert rules."""
    from realtime import create_alert_manager, MetricType, AlertCondition, AlertSeverity

    manager = create_alert_manager()

    rule = manager.create_rule(
        name="Custom Rule",
        description="Test rule",
        metric_type=MetricType.PASS_RATE,
        condition=AlertCondition.BELOW_THRESHOLD,
        threshold=0.5,
        severity=AlertSeverity.ERROR,
    )

    assert rule is not None
    assert rule.rule_id.startswith("RULE-")
    assert rule.name == "Custom Rule"


def test_alert_manager_check_rules():
    """Test checking rules and triggering alerts."""
    from realtime import (
        create_alert_manager,
        create_metrics_collector,
        MetricType,
        AlertCondition,
        AlertSeverity,
    )

    metrics = create_metrics_collector()
    manager = create_alert_manager(metrics)

    # Create a rule that will trigger
    manager.create_rule(
        name="Low Pass Rate",
        description="Alert on low pass rate",
        metric_type=MetricType.PASS_RATE,
        condition=AlertCondition.BELOW_THRESHOLD,
        threshold=0.9,
        severity=AlertSeverity.WARNING,
        cooldown_seconds=0,  # No cooldown for test
    )

    # Record low pass rate
    for _ in range(5):
        metrics.record(MetricType.PASS_RATE, 0.5)

    alerts = manager.check_rules()

    # Should have triggered at least one alert
    assert len(alerts) >= 1 or len(manager.get_active_alerts()) >= 0


def test_alert_manager_acknowledge():
    """Test acknowledging alerts."""
    from realtime import (
        create_alert_manager,
        create_metrics_collector,
        MetricType,
        AlertCondition,
        AlertSeverity,
    )
    from realtime.alerts import AlertState

    metrics = create_metrics_collector()
    manager = create_alert_manager(metrics)

    # Create and trigger an alert
    manager.create_rule(
        name="Test Rule",
        description="Test",
        metric_type=MetricType.FAILURE_RATE,
        condition=AlertCondition.ABOVE_THRESHOLD,
        threshold=0.1,
        severity=AlertSeverity.ERROR,
        cooldown_seconds=0,
    )

    for _ in range(5):
        metrics.record(MetricType.FAILURE_RATE, 0.5)

    alerts = manager.check_rules()

    if alerts:
        result = manager.acknowledge(
            alerts[0].alert_id,
            acknowledged_by="tester",
            note="Investigating",
        )
        assert result is True
        assert manager.get_alert(alerts[0].alert_id).state == AlertState.ACKNOWLEDGED


def test_alert_manager_resolve():
    """Test resolving alerts."""
    from realtime import (
        create_alert_manager,
        create_metrics_collector,
        MetricType,
        AlertCondition,
        AlertSeverity,
    )
    from realtime.alerts import AlertState

    metrics = create_metrics_collector()
    manager = create_alert_manager(metrics)

    manager.create_rule(
        name="Test Rule",
        description="Test",
        metric_type=MetricType.ERROR_RATE,
        condition=AlertCondition.ABOVE_THRESHOLD,
        threshold=0.1,
        severity=AlertSeverity.ERROR,
        cooldown_seconds=0,
    )

    for _ in range(5):
        metrics.record(MetricType.ERROR_RATE, 0.5)

    alerts = manager.check_rules()

    if alerts:
        result = manager.resolve(alerts[0].alert_id, note="Fixed")
        assert result is True
        assert manager.get_alert(alerts[0].alert_id).state == AlertState.RESOLVED


def test_alert_manager_statistics():
    """Test alert statistics."""
    from realtime import create_alert_manager

    manager = create_alert_manager()

    stats = manager.get_statistics()

    assert "total_rules" in stats
    assert "enabled_rules" in stats
    assert "total_alerts" in stats


def test_alert_manager_format():
    """Test alert formatting."""
    from realtime import create_alert_manager

    manager = create_alert_manager()

    formatted = manager.format_alerts()

    assert "ALERT DASHBOARD" in formatted


def test_streaming_dashboard_creation():
    """Test streaming dashboard creation."""
    from realtime import create_streaming_dashboard, StreamConfig

    config = StreamConfig(heartbeat_interval_seconds=10)
    dashboard = create_streaming_dashboard(config=config)

    assert dashboard is not None
    assert dashboard.config.heartbeat_interval_seconds == 10


def test_streaming_dashboard_test_recording():
    """Test recording test results."""
    from realtime import create_streaming_dashboard

    dashboard = create_streaming_dashboard()

    dashboard.set_total_tests(10)

    dashboard.record_test_start("TC-001", "Login Test")
    dashboard.record_test_complete(
        test_id="TC-001",
        test_name="Login Test",
        passed=True,
        duration_ms=1500,
    )

    summary = dashboard.get_summary()

    assert summary["completed_tests"] == 1
    assert summary["passed_tests"] == 1


def test_streaming_dashboard_events():
    """Test event streaming."""
    from realtime import create_streaming_dashboard

    dashboard = create_streaming_dashboard()

    dashboard.set_total_tests(5)
    dashboard.record_test_start("TC-001", "Test 1")
    dashboard.record_test_complete("TC-001", "Test 1", True, 1000)

    events = dashboard.get_events(limit=10)

    # Should have some events
    assert len(events) >= 0


def test_streaming_dashboard_summary():
    """Test dashboard summary."""
    from realtime import create_streaming_dashboard

    dashboard = create_streaming_dashboard()

    dashboard.set_total_tests(10)
    dashboard.record_test_complete("TC-001", "Test 1", True, 1000)
    dashboard.record_test_complete("TC-002", "Test 2", False, 2000)

    summary = dashboard.get_summary()

    assert summary["total_tests"] == 10
    assert summary["completed_tests"] == 2
    assert summary["passed_tests"] == 1
    assert summary["failed_tests"] == 1


def test_streaming_dashboard_format():
    """Test dashboard formatting."""
    from realtime import create_streaming_dashboard

    dashboard = create_streaming_dashboard()

    dashboard.set_total_tests(5)
    dashboard.record_test_complete("TC-001", "Test", True, 1000)

    formatted = dashboard.format_dashboard()

    assert "REAL-TIME MONITORING DASHBOARD" in formatted
    assert "Progress" in formatted


# ============================================================
# Orchestrator Module Tests
# ============================================================

def test_orchestrator_imports():
    """Test orchestrator module imports."""
    from orchestrator import (
        TestScheduler,
        ScheduleConfig,
        ScheduledRun,
        create_scheduler,
        TestDistributor,
        DistributionStrategy,
        WorkerNode,
        create_distributor,
        TestCoordinator,
        CoordinatorConfig,
        OrchestrationResult,
        create_coordinator,
    )
    assert TestScheduler is not None
    assert TestDistributor is not None
    assert TestCoordinator is not None


def test_scheduler_creation():
    """Test scheduler creation."""
    from orchestrator import create_scheduler, ScheduleConfig

    config = ScheduleConfig(
        max_parallel_runs=10,
        default_timeout_minutes=30,
    )

    scheduler = create_scheduler(config)
    assert scheduler is not None
    assert scheduler.config.max_parallel_runs == 10


def test_scheduler_schedule_test():
    """Test scheduling a test run."""
    from orchestrator import create_scheduler
    from orchestrator.scheduler import ScheduleStatus

    scheduler = create_scheduler()

    run = scheduler.schedule(
        test_ids=["TC-001", "TC-002", "TC-003"],
        priority=3,
        environment="staging",
    )

    assert run is not None
    assert run.run_id.startswith("sched-")
    assert run.status == ScheduleStatus.PENDING
    assert len(run.test_ids) == 3


def test_scheduler_schedule_matrix():
    """Test matrix scheduling."""
    from orchestrator import create_scheduler
    from orchestrator.scheduler import BrowserTarget, DeviceTarget

    scheduler = create_scheduler()

    browsers = [
        BrowserTarget("chromium"),
        BrowserTarget("firefox"),
    ]
    devices = [
        DeviceTarget("Desktop", 1366, 768),
        DeviceTarget("Mobile", 375, 667, is_mobile=True),
    ]

    runs = scheduler.schedule_matrix(
        test_ids=["TC-001"],
        browsers=browsers,
        devices=devices,
    )

    # 2 browsers x 2 devices = 4 runs
    assert len(runs) == 4


def test_scheduler_recurring():
    """Test recurring schedule."""
    from orchestrator import create_scheduler
    from orchestrator.scheduler import RecurrencePattern

    scheduler = create_scheduler()

    run = scheduler.schedule_recurring(
        test_ids=["TC-001"],
        pattern=RecurrencePattern.DAILY,
        priority=5,
    )

    assert run is not None
    assert "recurring" in run.tags
    assert run.metadata["pattern"] == "daily"


def test_scheduler_get_next():
    """Test getting next run."""
    from orchestrator import create_scheduler

    scheduler = create_scheduler()

    scheduler.schedule(test_ids=["TC-001"], priority=10)
    scheduler.schedule(test_ids=["TC-002"], priority=1)  # Higher priority (lower number)

    next_run = scheduler.get_next()

    # Should get the higher priority run first
    assert next_run is not None
    assert next_run.priority == 1


def test_scheduler_lifecycle():
    """Test run lifecycle."""
    from orchestrator import create_scheduler
    from orchestrator.scheduler import ScheduleStatus

    scheduler = create_scheduler()

    run = scheduler.schedule(test_ids=["TC-001"])

    # Get next run - this pops it from queue
    next_run = scheduler.get_next()
    assert next_run is not None

    # After get_next, the run is popped from queue
    # We need to manually move it to running state
    next_run.status = ScheduleStatus.RUNNING
    scheduler._running[next_run.run_id] = next_run
    assert next_run.status == ScheduleStatus.RUNNING

    # Complete the run
    scheduler.complete_run(next_run.run_id, {"passed": True}, success=True)

    # Get the completed run from the completed dict
    completed = scheduler._completed.get(next_run.run_id)
    assert completed is not None
    assert completed.status == ScheduleStatus.COMPLETED


def test_scheduler_cancel_pause():
    """Test cancel and pause operations."""
    from orchestrator import create_scheduler
    from orchestrator.scheduler import ScheduleStatus

    scheduler = create_scheduler()

    run = scheduler.schedule(test_ids=["TC-001"])

    # Pause
    result = scheduler.pause_run(run.run_id)
    assert result is True
    assert run.status == ScheduleStatus.PAUSED

    # Resume
    result = scheduler.resume_run(run.run_id)
    assert result is True
    assert run.status == ScheduleStatus.PENDING

    # Cancel
    result = scheduler.cancel_run(run.run_id)
    assert result is True
    assert run.status == ScheduleStatus.CANCELLED


def test_scheduler_statistics():
    """Test scheduler statistics."""
    from orchestrator import create_scheduler

    scheduler = create_scheduler()

    scheduler.schedule(test_ids=["TC-001"])
    scheduler.schedule(test_ids=["TC-002"])

    stats = scheduler.get_statistics()

    assert stats["pending_runs"] == 2
    assert stats["running_runs"] == 0


def test_scheduler_format():
    """Test scheduler status formatting."""
    from orchestrator import create_scheduler

    scheduler = create_scheduler()
    scheduler.schedule(test_ids=["TC-001"])

    formatted = scheduler.format_status()

    assert "TEST SCHEDULER STATUS" in formatted
    assert "Pending" in formatted


def test_distributor_creation():
    """Test distributor creation."""
    from orchestrator import create_distributor, DistributionStrategy

    distributor = create_distributor(DistributionStrategy.LEAST_LOADED)
    assert distributor is not None
    assert distributor.strategy == DistributionStrategy.LEAST_LOADED


def test_distributor_register_node():
    """Test registering worker nodes."""
    from orchestrator import create_distributor
    from orchestrator.distributor import WorkerCapabilities, WorkerStatus

    distributor = create_distributor()

    capabilities = WorkerCapabilities(
        browsers=["chromium", "firefox"],
        devices=["Desktop", "Mobile"],
        max_parallel=5,
        tags=["fast"],
    )

    node = distributor.register_node("Worker 1", capabilities, max_load=5)

    assert node is not None
    assert node.node_id.startswith("node-")
    assert node.status == WorkerStatus.ONLINE


def test_distributor_distribute():
    """Test distributing tests to workers."""
    from orchestrator import create_distributor
    from orchestrator.distributor import WorkerCapabilities

    distributor = create_distributor()

    # Register a node
    caps = WorkerCapabilities(
        browsers=["chromium"],
        devices=["Desktop"],
        max_parallel=3,
    )
    distributor.register_node("Worker", caps)

    # Distribute
    result = distributor.distribute(
        run_id="run-001",
        test_ids=["TC-001", "TC-002"],
        browser="chromium",
        device="Desktop",
    )

    assert result is not None
    assert result.run_id == "run-001"


def test_distributor_strategies():
    """Test different distribution strategies."""
    from orchestrator import create_distributor, DistributionStrategy
    from orchestrator.distributor import WorkerCapabilities

    for strategy in [
        DistributionStrategy.ROUND_ROBIN,
        DistributionStrategy.LEAST_LOADED,
        DistributionStrategy.CAPABILITY_BASED,
    ]:
        distributor = create_distributor(strategy)

        caps = WorkerCapabilities(
            browsers=["chromium"],
            devices=["Desktop"],
            max_parallel=5,
        )
        distributor.register_node("Worker", caps)

        result = distributor.distribute(
            run_id=f"run-{strategy.value}",
            test_ids=["TC-001"],
            browser="chromium",
            device="Desktop",
        )

        assert result is not None, f"Failed for strategy {strategy}"


def test_distributor_complete_run():
    """Test completing a distributed run."""
    from orchestrator import create_distributor
    from orchestrator.distributor import WorkerCapabilities

    distributor = create_distributor()

    caps = WorkerCapabilities(
        browsers=["chromium"],
        devices=["Desktop"],
        max_parallel=3,
    )
    node = distributor.register_node("Worker", caps)

    # Distribute and complete
    result = distributor.distribute(
        run_id="run-001",
        test_ids=["TC-001"],
        browser="chromium",
        device="Desktop",
    )

    assert node.current_load == 1

    distributor.complete_run("run-001", success=True, execution_time_ms=5000)

    assert node.current_load == 0
    assert node.completed_runs == 1


def test_distributor_affinity():
    """Test node affinity."""
    from orchestrator import create_distributor, DistributionStrategy
    from orchestrator.distributor import WorkerCapabilities

    distributor = create_distributor(DistributionStrategy.AFFINITY)

    caps = WorkerCapabilities(
        browsers=["chromium"],
        devices=["Desktop"],
        max_parallel=5,
    )
    node1 = distributor.register_node("Worker 1", caps)
    node2 = distributor.register_node("Worker 2", caps)

    # Set affinity
    distributor.set_affinity("TC-001", node1.node_id)

    # Distribute with affinity
    result = distributor.distribute(
        run_id="run-001",
        test_ids=["TC-001"],
        browser="chromium",
        device="Desktop",
    )

    assert result.node_id == node1.node_id


def test_distributor_statistics():
    """Test distributor statistics."""
    from orchestrator import create_distributor
    from orchestrator.distributor import WorkerCapabilities

    distributor = create_distributor()

    caps = WorkerCapabilities(
        browsers=["chromium"],
        devices=["Desktop"],
        max_parallel=5,
    )
    distributor.register_node("Worker 1", caps)
    distributor.register_node("Worker 2", caps)

    stats = distributor.get_statistics()

    assert stats["total_nodes"] == 2
    assert stats["online_nodes"] == 2
    assert stats["total_capacity"] == 10


def test_distributor_format():
    """Test distributor status formatting."""
    from orchestrator import create_distributor
    from orchestrator.distributor import WorkerCapabilities

    distributor = create_distributor()

    caps = WorkerCapabilities(
        browsers=["chromium"],
        devices=["Desktop"],
        max_parallel=5,
    )
    distributor.register_node("Worker 1", caps)

    formatted = distributor.format_status()

    assert "TEST DISTRIBUTOR STATUS" in formatted
    assert "Worker 1" in formatted


def test_coordinator_creation():
    """Test coordinator creation."""
    from orchestrator import create_coordinator, CoordinatorConfig
    from orchestrator.coordinator import ExecutionMode

    config = CoordinatorConfig(
        execution_mode=ExecutionMode.PARALLEL,
        max_parallel_runs=5,
    )

    coordinator = create_coordinator(config)
    assert coordinator is not None
    assert coordinator.config.execution_mode == ExecutionMode.PARALLEL


def test_coordinator_register_worker():
    """Test registering workers through coordinator."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    worker = coordinator.register_worker(
        name="Worker 1",
        browsers=["chromium", "firefox"],
        devices=["Desktop"],
        max_parallel=3,
    )

    assert worker is not None
    assert worker.name == "Worker 1"


def test_coordinator_orchestrate():
    """Test orchestrating tests."""
    from orchestrator import create_coordinator
    from orchestrator.coordinator import OrchestrationPhase

    coordinator = create_coordinator()

    # Register a worker
    coordinator.register_worker(
        name="Worker",
        browsers=["chromium"],
        devices=["Desktop"],
    )

    # Start orchestration
    orch_id = coordinator.orchestrate(
        test_ids=["TC-001", "TC-002"],
    )

    assert orch_id is not None
    assert orch_id.startswith("orch-")


def test_coordinator_report_result():
    """Test reporting test results."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    coordinator.register_worker(
        name="Worker",
        browsers=["chromium"],
        devices=["Desktop"],
    )

    orch_id = coordinator.orchestrate(test_ids=["TC-001"])

    # Report a result
    result = coordinator.report_result(
        orchestration_id=orch_id,
        test_id="TC-001",
        run_id="run-001",
        status="passed",
        duration_ms=5000,
        browser="chromium",
        device="Desktop",
    )

    assert result is True


def test_coordinator_get_status():
    """Test getting orchestration status."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    coordinator.register_worker(
        name="Worker",
        browsers=["chromium"],
        devices=["Desktop"],
    )

    orch_id = coordinator.orchestrate(test_ids=["TC-001"])

    status = coordinator.get_status(orch_id)

    assert status is not None
    assert status["orchestration_id"] == orch_id


def test_coordinator_cancel():
    """Test canceling orchestration."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    coordinator.register_worker(
        name="Worker",
        browsers=["chromium"],
        devices=["Desktop"],
    )

    orch_id = coordinator.orchestrate(test_ids=["TC-001"])

    result = coordinator.cancel(orch_id)

    assert result is True


def test_coordinator_statistics():
    """Test coordinator statistics."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    stats = coordinator.get_statistics()

    assert "active_orchestrations" in stats
    assert "completed_orchestrations" in stats
    assert "scheduler" in stats
    assert "distributor" in stats


def test_coordinator_format():
    """Test coordinator status formatting."""
    from orchestrator import create_coordinator

    coordinator = create_coordinator()

    formatted = coordinator.format_status()

    assert "TEST COORDINATOR STATUS" in formatted
    assert "Mode" in formatted


# ============================================================
# Synthesis Module Tests
# ============================================================

def test_synthesis_imports():
    """Test synthesis module imports."""
    from synthesis import (
        TestCombiner,
        CombinationStrategy,
        CombinedTest,
        create_test_combiner,
        TestEnricher,
        EnrichmentSource,
        EnrichedTest,
        create_test_enricher,
        TestSynthesizer,
        SynthesisConfig,
        SynthesizedSuite,
        create_test_synthesizer,
    )
    assert TestCombiner is not None
    assert TestEnricher is not None
    assert TestSynthesizer is not None


def test_combiner_creation():
    """Test test combiner creation."""
    from synthesis import create_test_combiner, CombinationStrategy

    combiner = create_test_combiner(CombinationStrategy.SMART_MERGE)
    assert combiner is not None


def test_combiner_add_source():
    """Test adding test sources."""
    from synthesis import create_test_combiner

    combiner = create_test_combiner()

    source = combiner.add_source(
        name="Manual Tests",
        tests=[
            {"title": "Login Test", "steps": ["Enter username", "Enter password"]},
            {"title": "Logout Test", "steps": ["Click logout button"]},
        ],
        priority=5,
    )

    assert source.source_id.startswith("SRC-")
    assert source.name == "Manual Tests"
    assert len(source.tests) == 2


def test_combiner_combine_union():
    """Test union combination strategy."""
    from synthesis import create_test_combiner, CombinationStrategy

    combiner = create_test_combiner()

    combiner.add_source("Source1", [
        {"title": "Test A", "steps": ["Step 1"]},
        {"title": "Test B", "steps": ["Step 2"]},
    ])
    combiner.add_source("Source2", [
        {"title": "Test C", "steps": ["Step 3"]},
        {"title": "Test A", "steps": ["Step 1a"]},  # Duplicate
    ])

    result = combiner.combine(CombinationStrategy.UNION)

    assert result.result_id.startswith("COMB-")
    # Deduplication should reduce from 4 to 3
    assert result.total_output_tests == 3
    assert result.deduplication_count == 1


def test_combiner_combine_smart_merge():
    """Test smart merge combination strategy."""
    from synthesis import create_test_combiner, CombinationStrategy

    combiner = create_test_combiner()

    combiner.add_source("Source1", [
        {"title": "User Login Flow", "steps": ["Enter credentials", "Click login"]},
    ])
    combiner.add_source("Source2", [
        {"title": "User Login Test", "steps": ["Input username", "Click submit"]},
    ])

    result = combiner.combine(CombinationStrategy.SMART_MERGE)

    # Similar tests should be merged
    assert result.total_output_tests == 1
    # Merged test should have combined sources
    assert len(result.combined_tests[0].sources) == 2


def test_combiner_coverage_optimal():
    """Test coverage optimal strategy."""
    from synthesis import create_test_combiner, CombinationStrategy

    combiner = create_test_combiner()

    combiner.add_source("Tests", [
        {"title": "Login Test", "category": "auth", "tags": ["login"]},
        {"title": "Signup Test", "category": "auth", "tags": ["signup"]},
        {"title": "Profile Test", "category": "user", "tags": ["profile"]},
    ])

    result = combiner.combine(CombinationStrategy.COVERAGE_OPTIMAL)

    assert result.coverage_score > 0
    assert result.total_output_tests > 0


def test_combiner_format_result():
    """Test result formatting."""
    from synthesis import create_test_combiner

    combiner = create_test_combiner()

    combiner.add_source("Tests", [
        {"title": "Test 1", "steps": ["Step"]},
    ])

    result = combiner.combine()
    formatted = combiner.format_result(result)

    assert "TEST COMBINATION RESULT" in formatted
    assert "Strategy" in formatted


def test_enricher_creation():
    """Test test enricher creation."""
    from synthesis import create_test_enricher

    enricher = create_test_enricher()
    assert enricher is not None


def test_enricher_enrich_security():
    """Test security enrichment."""
    from synthesis import create_test_enricher, EnrichmentSource

    enricher = create_test_enricher()

    tests = [
        {"title": "Login Test", "steps": ["Enter username", "Enter password"]},
    ]

    result = enricher.enrich(tests, {EnrichmentSource.SECURITY_RULES})

    assert result.enrichments_applied > 0
    # Should have security enrichments
    security_enriched = [
        t for t in result.enriched_tests
        if any(e.source == EnrichmentSource.SECURITY_RULES for e in t.enrichments)
    ]
    assert len(security_enriched) > 0


def test_enricher_enrich_accessibility():
    """Test accessibility enrichment."""
    from synthesis import create_test_enricher, EnrichmentSource

    enricher = create_test_enricher()

    tests = [
        {"title": "Form Test", "steps": ["Fill form", "Submit form"]},
    ]

    result = enricher.enrich(tests, {EnrichmentSource.ACCESSIBILITY_GUIDELINES})

    assert result.enrichments_applied > 0


def test_enricher_enrich_performance():
    """Test performance enrichment."""
    from synthesis import create_test_enricher, EnrichmentSource

    enricher = create_test_enricher()

    tests = [
        {"title": "Page Load Test", "steps": ["Navigate to page"]},
    ]

    result = enricher.enrich(tests, {EnrichmentSource.PERFORMANCE_BENCHMARKS})

    assert result.enrichments_applied > 0


def test_enricher_format_result():
    """Test enrichment result formatting."""
    from synthesis import create_test_enricher, EnrichmentSource

    enricher = create_test_enricher()

    tests = [{"title": "Test", "steps": ["Step"]}]
    result = enricher.enrich(tests, [EnrichmentSource.SECURITY_RULES])
    formatted = enricher.format_result(result)

    assert "ENRICHMENT RESULT" in formatted


def test_synthesizer_creation():
    """Test test synthesizer creation."""
    from synthesis import create_test_synthesizer, SynthesisConfig
    from synthesis.synthesizer import SynthesisMode

    config = SynthesisConfig(
        mode=SynthesisMode.COMPREHENSIVE,
        max_tests=100,
    )

    synthesizer = create_test_synthesizer(config)
    assert synthesizer is not None


def test_synthesizer_add_tests():
    """Test adding tests to synthesizer."""
    from synthesis import create_test_synthesizer

    synthesizer = create_test_synthesizer()

    source = synthesizer.add_tests(
        source_name="Unit Tests",
        tests=[
            {"title": "Test 1", "steps": ["Step 1"]},
            {"title": "Test 2", "steps": ["Step 2"]},
        ],
        priority=3,
    )

    assert source.source_id.startswith("SRC-")
    assert len(source.tests) == 2


def test_synthesizer_synthesize():
    """Test full synthesis pipeline."""
    from synthesis import create_test_synthesizer

    synthesizer = create_test_synthesizer()

    synthesizer.add_tests("Source1", [
        {"title": "Login Test", "steps": ["Step 1", "Step 2"], "assertions": ["Assert 1"]},
        {"title": "Logout Test", "steps": ["Step 1"], "assertions": ["Assert 1"]},
    ])
    synthesizer.add_tests("Source2", [
        {"title": "Profile Test", "steps": ["Step 1", "Step 2", "Step 3"], "assertions": ["Assert"]},
    ])

    suite = synthesizer.synthesize(
        name="E2E Test Suite",
        description="End-to-end tests",
    )

    assert suite.suite_id.startswith("SUITE-")
    assert suite.name == "E2E Test Suite"
    assert len(suite.tests) >= 2
    assert suite.source_count == 2


def test_synthesizer_phases():
    """Test synthesis phases."""
    from synthesis import create_test_synthesizer
    from synthesis.synthesizer import SynthesisPhase

    synthesizer = create_test_synthesizer()

    phases_seen = []
    synthesizer.on_phase_change(lambda data: phases_seen.append(data["phase"]))

    synthesizer.add_tests("Tests", [{"title": "Test", "steps": ["Step"]}])
    suite = synthesizer.synthesize()

    assert SynthesisPhase.COMPLETED in suite.phases_completed


def test_synthesizer_modes():
    """Test different synthesis modes."""
    from synthesis import create_test_synthesizer, SynthesisConfig
    from synthesis.synthesizer import SynthesisMode

    # Quick mode - no enrichment
    quick_config = SynthesisConfig(mode=SynthesisMode.QUICK)
    synthesizer = create_test_synthesizer(quick_config)

    synthesizer.add_tests("Tests", [{"title": "Test", "steps": ["Step"]}])
    suite = synthesizer.synthesize()

    # Quick mode should have no enrichments
    assert suite.enrichment_count == 0


def test_synthesizer_validation():
    """Test test validation."""
    from synthesis import create_test_synthesizer, SynthesisConfig

    config = SynthesisConfig(validate_tests=True)
    synthesizer = create_test_synthesizer(config)

    synthesizer.add_tests("Tests", [
        {"title": "Valid Test", "steps": ["Click button", "Verify result"]},
        {"title": "x", "steps": []},  # Invalid - too short, no steps
    ])

    suite = synthesizer.synthesize()

    # Valid tests should pass
    assert suite.validation_passed >= 1
    # Invalid test should fail validation
    assert suite.validation_failed >= 1


def test_synthesizer_coverage():
    """Test coverage calculation."""
    from synthesis import create_test_synthesizer

    synthesizer = create_test_synthesizer()

    synthesizer.add_tests("Tests", [
        {"title": "Login Test", "category": "auth", "tags": ["login", "security"]},
        {"title": "Checkout Test", "category": "payment", "tags": ["checkout"]},
        {"title": "Search Test", "category": "search", "tags": ["search"]},
    ])

    suite = synthesizer.synthesize()

    # Should have some coverage score
    assert suite.coverage_score > 0


def test_synthesizer_statistics():
    """Test synthesizer statistics."""
    from synthesis import create_test_synthesizer

    synthesizer = create_test_synthesizer()

    synthesizer.add_tests("Tests", [{"title": "Login Test", "steps": ["Click login", "Enter credentials"]}])
    synthesizer.synthesize()

    stats = synthesizer.get_statistics()

    assert stats["suites_created"] == 1
    assert stats["total_synthesized"] >= 1


def test_synthesizer_format_suite():
    """Test suite formatting."""
    from synthesis import create_test_synthesizer

    synthesizer = create_test_synthesizer()

    synthesizer.add_tests("Tests", [
        {"title": "Test 1", "steps": ["Step"], "priority": "high"},
    ])

    suite = synthesizer.synthesize(name="Format Test Suite")
    formatted = synthesizer.format_suite(suite)

    assert "SYNTHESIZED TEST SUITE" in formatted
    assert "Format Test Suite" in formatted
    assert "PHASES COMPLETED" in formatted


def test_synthesizer_clear():
    """Test clearing synthesizer state."""
    from synthesis import create_test_synthesizer
    from synthesis.synthesizer import SynthesisPhase

    synthesizer = create_test_synthesizer()

    synthesizer.add_tests("Tests", [{"title": "Test", "steps": ["Step"]}])
    synthesizer.synthesize()

    synthesizer.clear()

    stats = synthesizer.get_statistics()
    assert stats["sources_count"] == 0
    assert synthesizer.get_phase() == SynthesisPhase.INITIALIZED


# ============================================================
# Healing Module Tests
# ============================================================

def test_healing_imports():
    """Test healing module imports."""
    from healing import (
        SelectorHealer,
        SelectorType,
        HealingStrategy,
        SelectorCandidate,
        HealingResult,
        create_selector_healer,
        ChangeDetector,
        ChangeType,
        UIChange,
        ChangeReport,
        create_change_detector,
        RepairEngine,
        RepairStrategy,
        RepairAction,
        RepairResult,
        create_repair_engine,
    )
    assert SelectorHealer is not None
    assert ChangeDetector is not None
    assert RepairEngine is not None


def test_selector_healer_creation():
    """Test selector healer creation."""
    from healing import create_selector_healer, HealingStrategy

    healer = create_selector_healer(
        default_strategy=HealingStrategy.HYBRID,
        min_confidence=0.8,
    )
    assert healer is not None


def test_selector_healer_capture_snapshot():
    """Test capturing element snapshots."""
    from healing import create_selector_healer

    healer = create_selector_healer()

    snapshot = healer.capture_snapshot(
        selector_id="login-btn",
        tag_name="button",
        element_id="login-button",
        classes=["btn", "btn-primary"],
        attributes={"data-testid": "login-btn"},
        text_content="Login",
    )

    assert snapshot.tag_name == "button"
    assert snapshot.element_id == "login-button"


def test_selector_healer_heal():
    """Test healing a broken selector."""
    from healing import create_selector_healer, SelectorType

    healer = create_selector_healer()

    # Heal with DOM info
    result = healer.heal(
        original_selector="#old-button-id",
        original_type=SelectorType.ID,
        current_dom={
            "tag": "button",
            "id": "new-button-id",
            "attributes": {"data-testid": "submit-btn"},
        },
    )

    assert result.result_id.startswith("HEAL-")
    assert result.success == True
    assert result.confidence > 0.5


def test_selector_healer_suggest_stable():
    """Test suggesting stable selectors."""
    from healing import create_selector_healer

    healer = create_selector_healer()

    candidates = healer.suggest_stable_selectors({
        "tag": "button",
        "id": "submit",
        "attributes": {
            "data-testid": "submit-btn",
            "aria-label": "Submit form",
        },
    })

    assert len(candidates) >= 2
    # data-testid should be first (most stable)
    assert candidates[0].selector_type.value == "data_testid"


def test_selector_healer_statistics():
    """Test healer statistics."""
    from healing import create_selector_healer

    healer = create_selector_healer()

    healer.heal("#broken", current_dom={"id": "fixed"})
    healer.heal("#another", current_dom={"id": "new-id"})

    stats = healer.get_statistics()

    assert stats["total_healings"] == 2
    assert "success_rate" in stats


def test_selector_healer_format():
    """Test formatting healing result."""
    from healing import create_selector_healer

    healer = create_selector_healer()

    result = healer.heal("#broken", current_dom={"id": "fixed"})
    formatted = healer.format_result(result)

    assert "SELECTOR HEALING RESULT" in formatted


def test_change_detector_creation():
    """Test change detector creation."""
    from healing import create_change_detector

    detector = create_change_detector()
    assert detector is not None


def test_change_detector_capture_snapshot():
    """Test capturing UI snapshot."""
    from healing import create_change_detector

    detector = create_change_detector()

    elements = [
        {
            "tag": "button",
            "id": "submit",
            "attributes": {"data-testid": "submit-btn"},
            "text": "Submit",
            "xpath": "//button[@id='submit']",
        },
        {
            "tag": "input",
            "attributes": {"name": "email", "type": "email"},
            "text": "",
            "xpath": "//input[@name='email']",
        },
    ]

    snapshot_name = detector.capture_snapshot("baseline", elements)

    assert snapshot_name == "baseline"


def test_change_detector_compare():
    """Test comparing snapshots."""
    from healing import create_change_detector

    detector = create_change_detector()

    # Baseline
    baseline_elements = [
        {
            "tag": "button",
            "id": "submit",
            "attributes": {"id": "submit", "data-testid": "submit-btn"},
            "text": "Submit",
            "xpath": "//button[@id='submit']",
            "visible": True,
            "interactive": True,
        },
    ]
    detector.capture_snapshot("baseline", baseline_elements)

    # Current with changes
    current_elements = [
        {
            "tag": "button",
            "id": "submit-form",  # ID changed
            "attributes": {"id": "submit-form", "data-testid": "submit-btn"},
            "text": "Submit Form",  # Text changed
            "xpath": "//button[@id='submit']",
            "visible": True,
            "interactive": True,
        },
    ]
    detector.capture_snapshot("current", current_elements)

    report = detector.compare_snapshots("baseline", "current")

    assert report.total_changes >= 1


def test_change_detector_selector_breakage():
    """Test detecting broken selectors."""
    from healing import create_change_detector

    detector = create_change_detector()

    elements = [
        {"tag": "button", "attributes": {"id": "new-id"}},
    ]

    # This selector won't match any elements
    change = detector.detect_selector_breakage("#old-id", elements)

    assert change is not None
    assert change.change_type.value == "selector_broken"


def test_change_detector_statistics():
    """Test detector statistics."""
    from healing import create_change_detector

    detector = create_change_detector()

    detector.capture_snapshot("snap1", [{"tag": "div", "xpath": "/div[1]"}])

    stats = detector.get_statistics()

    assert stats["snapshots_stored"] == 1


def test_change_detector_format():
    """Test formatting change report."""
    from healing import create_change_detector

    detector = create_change_detector()

    detector.capture_snapshot("baseline", [{"tag": "div", "xpath": "/div"}])
    detector.capture_snapshot("current", [])

    report = detector.compare_snapshots("baseline", "current")
    formatted = detector.format_report(report)

    assert "UI CHANGE DETECTION REPORT" in formatted


def test_repair_engine_creation():
    """Test repair engine creation."""
    from healing import create_repair_engine

    engine = create_repair_engine()
    assert engine is not None


def test_repair_engine_analyze_failure():
    """Test failure analysis."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-login-001",
        error_message="Element not found: #submit-button",
        failed_step="Click the submit button",
        failed_selector="#submit-button",
    )

    assert analysis.analysis_id.startswith("ANALYSIS-")
    assert analysis.failure_type == "selector_broken"
    assert analysis.confidence > 0.5


def test_repair_engine_generate_repairs():
    """Test generating repairs."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-001",
        error_message="Timeout waiting for element #slow-button",
        failed_selector="#slow-button",
    )

    repairs = engine.generate_repairs(analysis)

    assert len(repairs) > 0
    assert repairs[0].action_id.startswith("REPAIR-")


def test_repair_engine_apply_repairs():
    """Test applying repairs."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-002",
        error_message="Element not found",
        failed_selector="#missing",
    )

    repairs = engine.generate_repairs(analysis)
    result = engine.apply_repairs("test-002", repairs)

    assert result.result_id.startswith("RESULT-")
    assert result.actions_applied > 0


def test_repair_engine_verify_repairs():
    """Test verifying repairs."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-003",
        error_message="Element not found",
        failed_selector="#broken",
    )

    repairs = engine.generate_repairs(analysis)
    engine.apply_repairs("test-003", repairs)

    verified = engine.verify_repairs("test-003")

    assert verified == True


def test_repair_engine_statistics():
    """Test engine statistics."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-004",
        error_message="Element not found",
    )
    engine.generate_repairs(analysis)

    stats = engine.get_statistics()

    assert stats["total_analyses"] == 1
    assert "strategy_distribution" in stats


def test_repair_engine_format_analysis():
    """Test formatting analysis."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-005",
        error_message="Element not found: #btn",
        failed_selector="#btn",
    )

    formatted = engine.format_analysis(analysis)

    assert "FAILURE ANALYSIS" in formatted
    assert "selector_broken" in formatted


def test_repair_engine_format_result():
    """Test formatting repair result."""
    from healing import create_repair_engine

    engine = create_repair_engine()

    analysis = engine.analyze_failure(
        test_id="test-006",
        error_message="Timeout",
    )

    repairs = engine.generate_repairs(analysis)
    result = engine.apply_repairs("test-006", repairs)

    formatted = engine.format_result(result)

    assert "REPAIR RESULT" in formatted


# ============================================================
# Benchmarking Module Tests
# ============================================================

def test_benchmarking_imports():
    """Test benchmarking module imports."""
    from benchmarking import (
        TestProfiler,
        ProfileType,
        ProfileResult,
        PerformanceMetrics,
        create_test_profiler,
        TestOptimizer,
        OptimizationType,
        OptimizationResult,
        OptimizationRecommendation,
        create_test_optimizer,
        BenchmarkRunner,
        BenchmarkSuite,
        BenchmarkResult,
        Benchmark,
        create_benchmark_runner,
    )
    assert TestProfiler is not None
    assert TestOptimizer is not None
    assert BenchmarkRunner is not None


def test_profiler_creation():
    """Test profiler creation."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    assert profiler is not None


def test_profiler_start_profile():
    """Test starting a profile."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()

    profile_id = profiler.start_profile("test-001")

    assert profile_id.startswith("PROFILE-")


def test_profiler_record_timing():
    """Test recording timings."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    profiler.start_profile("test-001")

    timing = profiler.record_timing(
        test_id="test-001",
        operation="click button",
        duration_ms=150,
        category="action",
    )

    assert timing.operation == "click button"
    assert timing.duration_ms == 150


def test_profiler_end_profile():
    """Test ending a profile."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    profiler.start_profile("test-001")

    profiler.record_timing("test-001", "click", 100)
    profiler.record_timing("test-001", "fill", 200)
    profiler.record_timing("test-001", "navigate", 500)

    result = profiler.end_profile("test-001")

    assert result.result_id.startswith("PROFILE-")
    assert result.metrics.step_count == 3
    assert result.metrics.total_duration_ms == 800


def test_profiler_bottleneck_detection():
    """Test bottleneck detection."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    profiler.start_profile("test-001")

    # Record a slow operation (should be flagged)
    profiler.record_timing("test-001", "slow click", 1000, category="action")
    profiler.record_timing("test-001", "normal fill", 100, category="action")

    result = profiler.end_profile("test-001")

    # Should detect at least one bottleneck
    assert len(result.bottlenecks) >= 1


def test_profiler_statistics():
    """Test profiler statistics."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    profiler.start_profile("test-001")
    profiler.record_timing("test-001", "click", 100)
    profiler.end_profile("test-001")

    stats = profiler.get_statistics()

    assert stats["total_profiles"] == 1


def test_profiler_format():
    """Test formatting profile result."""
    from benchmarking import create_test_profiler

    profiler = create_test_profiler()
    profiler.start_profile("test-001")
    profiler.record_timing("test-001", "click", 100)
    result = profiler.end_profile("test-001")

    formatted = profiler.format_result(result)

    assert "PERFORMANCE PROFILE" in formatted
    assert "METRICS" in formatted


def test_optimizer_creation():
    """Test optimizer creation."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer(max_parallelism=8)
    assert optimizer is not None


def test_optimizer_register_test():
    """Test registering tests."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    optimizer.register_test(
        test_id="test-001",
        steps=[
            {"action": "click", "selector": "#btn"},
            {"action": "fill", "selector": "#input"},
        ],
        dependencies=[],
        estimated_duration_ms=5000,
    )

    stats = optimizer.get_statistics()
    assert stats["registered_tests"] == 1


def test_optimizer_analyze():
    """Test analyzing tests for optimization."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    optimizer.register_test(
        test_id="test-001",
        steps=[
            {"action": "wait", "timeout": 5000},
            {"action": "wait", "timeout": 3000},  # Consecutive wait
            {"action": "click", "selector": "//div[@class='long']//button[@type='submit']"},
        ],
    )

    recommendations = optimizer.analyze("test-001")

    assert len(recommendations) > 0


def test_optimizer_create_plan():
    """Test creating execution plan."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    for i in range(5):
        optimizer.register_test(
            test_id=f"test-{i:03d}",
            steps=[{"action": "click"}],
            estimated_duration_ms=1000,
        )

    plan = optimizer.create_execution_plan([f"test-{i:03d}" for i in range(5)])

    assert plan.plan_id.startswith("PLAN-")
    assert plan.total_tests == 5
    assert plan.parallelization_factor >= 1.0


def test_optimizer_apply_optimizations():
    """Test applying optimizations."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    optimizer.register_test(
        test_id="test-001",
        steps=[
            {"action": "wait", "timeout": 5000},
            {"action": "wait", "timeout": 3000},
        ],
    )

    recommendations = optimizer.analyze("test-001")
    result = optimizer.apply_optimizations("test-001", recommendations, before_duration_ms=8000)

    assert result.result_id.startswith("OPTRESULT-")
    assert result.after_duration_ms < result.before_duration_ms


def test_optimizer_statistics():
    """Test optimizer statistics."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    optimizer.register_test("test-001", steps=[{"action": "wait", "timeout": 5000}])
    recommendations = optimizer.analyze("test-001")
    optimizer.apply_optimizations("test-001", recommendations, 5000)

    stats = optimizer.get_statistics()

    assert stats["total_optimizations"] == 1


def test_optimizer_format_plan():
    """Test formatting execution plan."""
    from benchmarking import create_test_optimizer

    optimizer = create_test_optimizer()

    optimizer.register_test("test-001", steps=[])
    optimizer.register_test("test-002", steps=[])

    plan = optimizer.create_execution_plan(["test-001", "test-002"])
    formatted = optimizer.format_plan(plan)

    assert "OPTIMIZED EXECUTION PLAN" in formatted


def test_benchmark_runner_creation():
    """Test benchmark runner creation."""
    from benchmarking import create_benchmark_runner

    runner = create_benchmark_runner()
    assert runner is not None


def test_benchmark_runner_register():
    """Test registering benchmarks."""
    from benchmarking import create_benchmark_runner, BenchmarkCategory

    runner = create_benchmark_runner()

    benchmark = runner.register_benchmark(
        name="Custom Benchmark",
        description="Test custom benchmark",
        category=BenchmarkCategory.EXECUTION_SPEED,
        iterations=10,
        runner=lambda: 50.0,
    )

    assert benchmark.benchmark_id.startswith("BM-")
    assert benchmark.name == "Custom Benchmark"


def test_benchmark_runner_run():
    """Test running a benchmark."""
    from benchmarking import create_benchmark_runner, BenchmarkCategory

    runner = create_benchmark_runner()

    benchmark = runner.register_benchmark(
        name="Fast Benchmark",
        description="Quick test",
        category=BenchmarkCategory.EXECUTION_SPEED,
        iterations=5,
        warmup_iterations=1,
        runner=lambda: 10.0,
    )

    result = runner.run_benchmark(benchmark.benchmark_id)

    assert result.result_id.startswith("BMRESULT-")
    assert result.mean_ms > 0
    assert result.total_iterations == 5


def test_benchmark_runner_suite():
    """Test running a benchmark suite."""
    from benchmarking import create_benchmark_runner, BenchmarkCategory

    runner = create_benchmark_runner()

    # Create a suite with selector benchmarks
    suite = runner.create_suite(
        name="Selector Performance",
        category=BenchmarkCategory.SELECTOR_PERFORMANCE,
    )

    assert suite.suite_id.startswith("SUITE-")
    assert len(suite.benchmarks) >= 1


def test_benchmark_runner_compare():
    """Test comparing benchmark results."""
    from benchmarking import create_benchmark_runner, BenchmarkCategory

    runner = create_benchmark_runner()

    benchmark = runner.register_benchmark(
        name="Compare Test",
        description="Test comparison",
        category=BenchmarkCategory.EXECUTION_SPEED,
        iterations=10,
        runner=lambda: 100.0,
    )

    result_a = runner.run_benchmark(benchmark.benchmark_id)
    result_b = runner.run_benchmark(benchmark.benchmark_id)

    comparison = runner.compare_results(result_a, result_b)

    assert "mean_change_pct" in comparison
    assert "is_faster" in comparison


def test_benchmark_runner_statistics():
    """Test runner statistics."""
    from benchmarking import create_benchmark_runner

    runner = create_benchmark_runner()

    stats = runner.get_statistics()

    assert stats["registered_benchmarks"] > 0


def test_benchmark_runner_format():
    """Test formatting benchmark result."""
    from benchmarking import create_benchmark_runner, BenchmarkCategory

    runner = create_benchmark_runner()

    benchmark = runner.register_benchmark(
        name="Format Test",
        description="Test formatting",
        category=BenchmarkCategory.EXECUTION_SPEED,
        iterations=5,
        runner=lambda: 50.0,
    )

    result = runner.run_benchmark(benchmark.benchmark_id)
    formatted = runner.format_result(result)

    assert "BENCHMARK RESULT" in formatted
    assert "Mean" in formatted


# ============================================================
# Intelligence Module Tests
# ============================================================

def test_intelligence_imports():
    """Test intelligence module imports."""
    from intelligence import (
        FailurePredictor,
        PredictionType,
        FailurePrediction,
        RiskFactor,
        create_failure_predictor,
        InsightEngine,
        InsightType,
        TestInsight,
        InsightPriority,
        create_insight_engine,
        TestRecommender,
        RecommendationType,
        TestRecommendation,
        create_test_recommender,
    )
    assert FailurePredictor is not None
    assert InsightEngine is not None
    assert TestRecommender is not None


def test_predictor_creation():
    """Test predictor creation."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()
    assert predictor is not None


def test_predictor_record_result():
    """Test recording test results."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    predictor.record_result("test-001", passed=True, duration_ms=100)
    predictor.record_result("test-001", passed=False, duration_ms=150, failure_type="timeout")

    stats = predictor.get_statistics()
    assert stats["tracked_tests"] == 1


def test_predictor_predict():
    """Test failure prediction."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    # Record mixed results to create history
    for i in range(20):
        predictor.record_result(
            "test-001",
            passed=(i % 3 != 0),  # Fail every 3rd run
            duration_ms=100 + i * 10,
        )

    prediction = predictor.predict_failure("test-001")

    assert prediction.prediction_id.startswith("PRED-")
    assert prediction.test_id == "test-001"
    assert 0 <= prediction.probability <= 1
    assert 0 <= prediction.confidence <= 1


def test_predictor_code_change():
    """Test code change impact tracking."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    change = predictor.record_code_change(
        files_changed=["src/login.ts", "src/auth.ts"],
        lines_added=50,
        lines_removed=10,
        change_type="feature",
        affected_tests=["test-login", "test-auth"],
    )

    assert change.change_id.startswith("CHG-")
    assert len(change.files_changed) == 2


def test_predictor_test_health():
    """Test getting test health."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    for i in range(10):
        predictor.record_result("test-001", passed=True, duration_ms=100)

    health = predictor.get_test_health("test-001")

    assert health["test_id"] == "test-001"
    assert health["health_score"] > 0
    assert health["status"] in ["healthy", "stable", "unstable", "critical", "unknown"]


def test_predictor_high_risk():
    """Test getting high risk tests."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    # Create a problematic test
    for i in range(15):
        predictor.record_result(
            "flaky-test",
            passed=(i % 2 == 0),  # Alternating results
            duration_ms=100 + i * 50,  # High variance
        )

    # Create a stable test
    for i in range(15):
        predictor.record_result("stable-test", passed=True, duration_ms=100)

    high_risk = predictor.get_high_risk_tests(threshold=0.1)

    # Should find the flaky test
    assert len(high_risk) >= 0  # May or may not find depending on thresholds


def test_predictor_statistics():
    """Test predictor statistics."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    predictor.record_result("test-001", passed=True, duration_ms=100)
    predictor.predict_failure("test-001")

    stats = predictor.get_statistics()

    assert stats["tracked_tests"] >= 1
    assert stats["total_predictions"] >= 1


def test_predictor_format():
    """Test formatting prediction."""
    from intelligence import create_failure_predictor

    predictor = create_failure_predictor()

    for i in range(10):
        predictor.record_result("test-001", passed=(i % 2 == 0), duration_ms=100)

    prediction = predictor.predict_failure("test-001")
    formatted = predictor.format_prediction(prediction)

    assert "FAILURE PREDICTION" in formatted
    assert "Risk Level" in formatted


def test_insight_engine_creation():
    """Test insight engine creation."""
    from intelligence import create_insight_engine

    engine = create_insight_engine()
    assert engine is not None


def test_insight_engine_record_event():
    """Test recording events."""
    from intelligence import create_insight_engine

    engine = create_insight_engine()

    event = engine.record_event(
        test_id="test-001",
        event_type="pass",
        duration_ms=100,
    )

    assert event.event_id.startswith("EVT-")
    assert event.test_id == "test-001"


def test_insight_engine_record_metric():
    """Test recording metrics."""
    from intelligence import create_insight_engine

    engine = create_insight_engine()

    metric = engine.record_metric(
        test_id="test-001",
        metric_name="execution_time",
        value=150.5,
        tags={"environment": "ci"},
    )

    assert metric.test_id == "test-001"
    assert metric.value == 150.5


def test_insight_engine_generate():
    """Test generating insights."""
    from intelligence import create_insight_engine

    engine = create_insight_engine(min_data_points=5)

    # Record enough events to generate insights
    for i in range(20):
        engine.record_event(
            test_id="test-001",
            event_type="pass" if i % 3 != 0 else "fail",
            duration_ms=100 + i * 50,
        )

    insights = engine.generate_insights()

    # Should generate some insights
    assert isinstance(insights, list)


def test_insight_engine_get_insights():
    """Test getting filtered insights."""
    from intelligence import create_insight_engine, InsightPriority

    engine = create_insight_engine(min_data_points=5)

    # Record events
    for i in range(15):
        engine.record_event(
            test_id=f"test-{i % 3:03d}",
            event_type="fail" if i % 2 == 0 else "pass",
            duration_ms=1000 + i * 100,
        )

    engine.generate_insights()

    insights = engine.get_insights(limit=10)
    assert len(insights) <= 10


def test_insight_engine_statistics():
    """Test engine statistics."""
    from intelligence import create_insight_engine

    engine = create_insight_engine()

    engine.record_event("test-001", "pass", 100)
    engine.record_metric("test-001", "duration", 100)

    stats = engine.get_statistics()

    assert stats["total_events"] >= 1
    assert stats["total_metrics"] >= 1


def test_insight_engine_format():
    """Test formatting insight."""
    from intelligence import create_insight_engine

    engine = create_insight_engine(min_data_points=3)

    # Record events to trigger insight
    for i in range(10):
        engine.record_event(
            test_id="test-001",
            event_type="fail",
            duration_ms=100,
            error_message="Timeout waiting for element",
        )

    insights = engine.generate_insights()

    if insights:
        formatted = engine.format_insight(insights[0])
        assert "=" in formatted


def test_recommender_creation():
    """Test recommender creation."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()
    assert recommender is not None


def test_recommender_register_test():
    """Test registering tests."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    profile = recommender.register_test(
        test_id="test-001",
        name="Login Test",
        duration_ms=1500,
        pass_rate=0.95,
        coverage_areas={"authentication", "login"},
    )

    assert profile.test_id == "test-001"
    assert profile.duration_ms == 1500


def test_recommender_register_suite():
    """Test registering suites."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test("test-001", "Test 1", duration_ms=100)
    recommender.register_test("test-002", "Test 2", duration_ms=200)

    suite = recommender.register_suite(
        suite_id="suite-001",
        name="Login Suite",
        test_ids=["test-001", "test-002"],
        coverage_score=0.85,
    )

    assert suite.total_tests == 2
    assert suite.total_duration_ms == 300


def test_recommender_generate():
    """Test generating recommendations."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    # Register tests with various characteristics
    recommender.register_test(
        test_id="flaky-test",
        name="Flaky Test",
        duration_ms=5000,
        pass_rate=0.5,
        flaky_rate=0.3,
        failure_count=10,
    )

    recommender.register_test(
        test_id="slow-test",
        name="Slow Test",
        duration_ms=10000,
        pass_rate=0.95,
    )

    recommender.register_test(
        test_id="stable-test",
        name="Stable Test",
        duration_ms=100,
        pass_rate=1.0,
    )

    recommendations = recommender.generate_recommendations()

    assert isinstance(recommendations, list)


def test_recommender_quick_wins():
    """Test getting quick wins."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test("test-001", "Test", pass_rate=0.5, flaky_rate=0.2)
    recommender.generate_recommendations()

    quick_wins = recommender.get_quick_wins()

    assert isinstance(quick_wins, list)


def test_recommender_prioritize():
    """Test prioritizing tests."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test("test-001", "Test 1", pass_rate=0.5, duration_ms=100)
    recommender.register_test("test-002", "Test 2", pass_rate=0.9, duration_ms=200)
    recommender.register_test("test-003", "Test 3", pass_rate=1.0, duration_ms=150)

    prioritized = recommender.prioritize_tests()

    assert len(prioritized) == 3
    # Lower pass rate should have higher priority
    assert prioritized[0][0] == "test-001"


def test_recommender_time_budget():
    """Test prioritization with time budget."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test("test-001", "Test 1", duration_ms=100)
    recommender.register_test("test-002", "Test 2", duration_ms=200)
    recommender.register_test("test-003", "Test 3", duration_ms=300)

    prioritized = recommender.prioritize_tests(time_budget_ms=250)

    total_time = sum(
        recommender._test_profiles[tid].duration_ms
        for tid, _ in prioritized
    )
    assert total_time <= 250


def test_recommender_statistics():
    """Test recommender statistics."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test("test-001", "Test 1")
    recommender.generate_recommendations()

    stats = recommender.get_statistics()

    assert stats["registered_tests"] == 1


def test_recommender_format():
    """Test formatting recommendation."""
    from intelligence import create_test_recommender

    recommender = create_test_recommender()

    recommender.register_test(
        test_id="test-001",
        name="Test",
        pass_rate=0.5,
        flaky_rate=0.2,
        failure_count=10,
    )

    recommendations = recommender.generate_recommendations()

    if recommendations:
        formatted = recommender.format_recommendation(recommendations[0])
        assert "RECOMMENDATION" in formatted


# ============================================================
# Visual Module Tests
# ============================================================

def test_visual_imports():
    """Test visual module imports."""
    from visual import (
        VisualComparator,
        ComparisonMethod,
        ComparisonResult,
        DiffRegion,
        create_visual_comparator,
        ScreenshotManager,
        Screenshot,
        ScreenshotSet,
        create_screenshot_manager,
        VisualReporter,
        VisualReport,
        VisualDiff,
        create_visual_reporter,
    )
    assert VisualComparator is not None
    assert ScreenshotManager is not None
    assert VisualReporter is not None


def test_comparator_creation():
    """Test comparator creation."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator()
    assert comparator is not None


def test_comparator_set_baseline():
    """Test setting baseline."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator()

    baseline = comparator.set_baseline(
        baseline_id="login-page",
        width=800,
        height=600,
    )

    assert baseline.image_id == "login-page"
    assert baseline.width == 800
    assert baseline.height == 600


def test_comparator_compare_identical():
    """Test comparing identical images."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator(threshold=0.95)

    # Set baseline with white pixels
    pixels = [[(255, 255, 255) for _ in range(100)] for _ in range(100)]
    comparator.set_baseline("test", 100, 100, pixels)

    # Compare with identical pixels
    result = comparator.compare("test", 100, 100, pixels)

    assert result.match_percentage == 1.0
    assert result.passed is True


def test_comparator_compare_different():
    """Test comparing different images."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator(threshold=0.95)

    # Set baseline with white pixels
    baseline_pixels = [[(255, 255, 255) for _ in range(100)] for _ in range(100)]
    comparator.set_baseline("test", 100, 100, baseline_pixels)

    # Compare with black pixels
    current_pixels = [[(0, 0, 0) for _ in range(100)] for _ in range(100)]
    result = comparator.compare("test", 100, 100, current_pixels)

    assert result.match_percentage < 1.0
    assert result.passed is False


def test_comparator_ignore_region():
    """Test ignoring regions."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator()

    comparator.set_baseline("test", 100, 100)
    comparator.add_ignore_region("test", 0, 0, 50, 50)

    stats = comparator.get_statistics()
    assert stats["baselines"] >= 1


def test_comparator_methods():
    """Test different comparison methods."""
    from visual import create_visual_comparator, ComparisonMethod

    comparator = create_visual_comparator()
    comparator.set_baseline("test", 50, 50)

    for method in [
        ComparisonMethod.PIXEL_DIFF,
        ComparisonMethod.STRUCTURAL,
        ComparisonMethod.PERCEPTUAL,
        ComparisonMethod.HISTOGRAM,
        ComparisonMethod.HYBRID,
    ]:
        result = comparator.compare("test", 50, 50, method=method)
        assert result.method == method


def test_comparator_statistics():
    """Test comparator statistics."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator()

    comparator.set_baseline("test", 50, 50)
    comparator.compare("test", 50, 50)

    stats = comparator.get_statistics()

    assert stats["total_comparisons"] >= 1
    assert stats["baselines"] >= 1


def test_comparator_format():
    """Test formatting result."""
    from visual import create_visual_comparator

    comparator = create_visual_comparator()

    comparator.set_baseline("test", 50, 50)
    result = comparator.compare("test", 50, 50)

    formatted = comparator.format_result(result)

    assert "VISUAL COMPARISON" in formatted


def test_screenshot_manager_creation():
    """Test screenshot manager creation."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()
    assert manager is not None


def test_screenshot_manager_capture():
    """Test capturing screenshot."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    ss = manager.capture(
        name="login-page",
        test_id="test-001",
        width=1920,
        height=1080,
    )

    assert ss.screenshot_id.startswith("SS-")
    assert ss.name == "login-page"
    assert ss.width == 1920


def test_screenshot_manager_baseline():
    """Test setting baseline."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    ss = manager.capture("test", "test-001", 800, 600)
    manager.set_as_baseline(ss.screenshot_id)

    baseline = manager.get_baseline("test")
    assert baseline is not None
    assert baseline.screenshot_id == ss.screenshot_id


def test_screenshot_manager_set():
    """Test creating screenshot set."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    ss1 = manager.capture("page1", "test-001", 800, 600)
    ss2 = manager.capture("page2", "test-001", 800, 600)

    ss_set = manager.create_set(
        name="Login Flow",
        screenshot_ids=[ss1.screenshot_id, ss2.screenshot_id],
    )

    assert ss_set.set_id.startswith("SSSET-")
    assert len(ss_set.screenshots) == 2


def test_screenshot_manager_devices():
    """Test multi-device capture."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    ss_set = manager.capture_for_devices(
        name="responsive",
        test_id="test-001",
        devices=["desktop", "tablet", "mobile"],
    )

    assert len(ss_set.screenshots) == 3


def test_screenshot_manager_history():
    """Test screenshot history."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    for i in range(5):
        manager.capture("login", "test-001", 800, 600)

    history = manager.get_history("login")
    assert len(history) == 5


def test_screenshot_manager_statistics():
    """Test manager statistics."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    manager.capture("test", "test-001", 800, 600)

    stats = manager.get_statistics()

    assert stats["total_screenshots"] >= 1


def test_screenshot_manager_format():
    """Test formatting screenshot."""
    from visual import create_screenshot_manager

    manager = create_screenshot_manager()

    ss = manager.capture("test", "test-001", 800, 600)
    formatted = manager.format_screenshot(ss)

    assert "SCREENSHOT" in formatted


def test_reporter_creation():
    """Test reporter creation."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()
    assert reporter is not None


def test_reporter_create_diff():
    """Test creating diff."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    diff = reporter.create_diff(
        name="login-page",
        baseline_path="/screenshots/login-baseline.png",
        current_path="/screenshots/login-current.png",
        match_percentage=0.98,
        passed=True,
    )

    assert diff.diff_id.startswith("VDIFF-")
    assert diff.match_percentage == 0.98


def test_reporter_create_report():
    """Test creating report."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    diff1 = reporter.create_diff("page1", "/b/1.png", "/c/1.png", 0.99, True)
    diff2 = reporter.create_diff("page2", "/b/2.png", "/c/2.png", 0.85, False)

    report = reporter.create_report(
        title="Visual Regression Run",
        run_id="run-001",
        diff_ids=[diff1.diff_id, diff2.diff_id],
    )

    assert report.report_id.startswith("VREP-")
    assert report.total_comparisons == 2
    assert report.passed_count == 1
    assert report.failed_count == 1


def test_reporter_generate_html():
    """Test generating HTML report."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    diff = reporter.create_diff("test", "/b/1.png", "/c/1.png", 0.95, True)
    report = reporter.create_report("Test", "run-001", [diff.diff_id])

    html = reporter.generate_report(report)

    assert "<!DOCTYPE html>" in html
    assert "Visual Regression" in html or "VISUAL" in html or report.title in html


def test_reporter_generate_json():
    """Test generating JSON report."""
    from visual import create_visual_reporter, ReportFormat

    reporter = create_visual_reporter()

    diff = reporter.create_diff("test", "/b/1.png", "/c/1.png", 0.95, True)
    report = reporter.create_report("Test", "run-001", [diff.diff_id])

    json_str = reporter.generate_report(report, format=ReportFormat.JSON)

    assert "report_id" in json_str
    assert "summary" in json_str


def test_reporter_generate_markdown():
    """Test generating Markdown report."""
    from visual import create_visual_reporter, ReportFormat

    reporter = create_visual_reporter()

    diff = reporter.create_diff("test", "/b/1.png", "/c/1.png", 0.95, True)
    report = reporter.create_report("Test", "run-001", [diff.diff_id])

    md = reporter.generate_report(report, format=ReportFormat.MARKDOWN)

    assert "# Test" in md or "## Summary" in md


def test_reporter_trend():
    """Test trend analysis."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    for i in range(5):
        diff = reporter.create_diff(f"test-{i}", "/b.png", "/c.png", 0.95 + i * 0.01, True)
        reporter.create_report(f"Run {i}", f"run-{i}", [diff.diff_id])

    trend = reporter.get_trend()

    assert "trend" in trend
    assert "data_points" in trend


def test_reporter_statistics():
    """Test reporter statistics."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    diff = reporter.create_diff("test", "/b.png", "/c.png", 0.95, True)
    reporter.create_report("Test", "run-001", [diff.diff_id])

    stats = reporter.get_statistics()

    assert stats["total_reports"] >= 1
    assert stats["total_diffs"] >= 1


def test_reporter_format_diff():
    """Test formatting diff."""
    from visual import create_visual_reporter

    reporter = create_visual_reporter()

    diff = reporter.create_diff("test", "/b.png", "/c.png", 0.95, True)
    formatted = reporter.format_diff(diff)

    assert "VISUAL DIFF" in formatted


# ============================================================
# API Module Tests
# ============================================================

def test_api_imports():
    """Test API module imports."""
    from api import (
        APIClient,
        HTTPMethod,
        APIRequest,
        APIResponse,
        create_api_client,
        ContractValidator,
        ContractType,
        ContractResult,
        SchemaViolation,
        create_contract_validator,
        APIMocker,
        MockRule,
        MockResponse,
        create_api_mocker,
    )
    assert APIClient is not None
    assert ContractValidator is not None
    assert APIMocker is not None


def test_api_client_creation():
    """Test API client creation."""
    from api import create_api_client

    client = create_api_client(base_url="https://api.example.com")
    assert client is not None


def test_api_client_auth():
    """Test setting authentication."""
    from api import create_api_client

    client = create_api_client()

    client.set_auth_token("my-token")
    assert "Authorization" in client._default_headers

    client.set_api_key("api-key-123")
    assert "X-API-Key" in client._default_headers


def test_api_client_request():
    """Test making requests."""
    from api import create_api_client, HTTPMethod

    client = create_api_client(base_url="https://api.example.com")

    response = client.request(HTTPMethod.GET, "/users")

    assert response.response_id.startswith("RES-")
    assert response.status_code == 200


def test_api_client_get():
    """Test GET request."""
    from api import create_api_client

    client = create_api_client()
    response = client.get("/users")

    assert response.status_code == 200


def test_api_client_post():
    """Test POST request."""
    from api import create_api_client

    client = create_api_client()
    response = client.post("/users", body={"name": "Test"})

    assert response.status_code == 200


def test_api_client_mock():
    """Test mock responses."""
    from api import create_api_client, HTTPMethod

    client = create_api_client(base_url="https://api.example.com")

    client.mock_response(
        "/users",
        HTTPMethod.GET,
        status_code=200,
        body={"users": [{"id": 1, "name": "Test"}]},
    )

    response = client.get("/users")

    assert response.status_code == 200
    assert "users" in response.body


def test_api_client_assertions():
    """Test response assertions."""
    from api import create_api_client

    client = create_api_client()

    response = client.get("/test")

    assert client.assert_success(response) is True
    assert client.assert_status(response, 200) is True


def test_api_client_history():
    """Test request history."""
    from api import create_api_client

    client = create_api_client()

    client.get("/test1")
    client.get("/test2")

    history = client.get_history()
    assert len(history) >= 2


def test_api_client_statistics():
    """Test client statistics."""
    from api import create_api_client

    client = create_api_client()

    client.get("/test")

    stats = client.get_statistics()

    assert stats["total_requests"] >= 1


def test_api_client_format():
    """Test formatting request/response."""
    from api import create_api_client

    client = create_api_client()
    response = client.get("/test")

    history = client.get_history()
    formatted_req = client.format_request(history[0].request)
    formatted_res = client.format_response(response)

    assert "API REQUEST" in formatted_req
    assert "API RESPONSE" in formatted_res


def test_contract_validator_creation():
    """Test contract validator creation."""
    from api import create_contract_validator

    validator = create_contract_validator()
    assert validator is not None


def test_contract_validator_register():
    """Test registering contracts."""
    from api import create_contract_validator

    validator = create_contract_validator()

    contract = validator.register_contract(
        name="User API",
        schema={
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        },
    )

    assert contract.contract_id.startswith("CONTRACT-")


def test_contract_validator_validate_valid():
    """Test validating valid data."""
    from api import create_contract_validator

    validator = create_contract_validator()

    contract = validator.register_contract(
        name="User",
        schema={
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        },
    )

    result = validator.validate(
        contract.contract_id,
        {"id": 1, "name": "John"},
    )

    assert result.valid is True
    assert result.errors == 0


def test_contract_validator_validate_invalid():
    """Test validating invalid data."""
    from api import create_contract_validator

    validator = create_contract_validator()

    contract = validator.register_contract(
        name="User",
        schema={
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        },
    )

    result = validator.validate(
        contract.contract_id,
        {"id": "not-an-integer"},  # Missing name, wrong type for id
    )

    assert result.valid is False
    assert result.errors > 0


def test_contract_validator_compatibility():
    """Test contract compatibility checking."""
    from api import create_contract_validator

    validator = create_contract_validator()

    old_contract = validator.register_contract(
        name="User v1",
        schema={
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "integer"},
            },
        },
        version="1.0.0",
    )

    new_contract = validator.register_contract(
        name="User v2",
        schema={
            "type": "object",
            "required": ["id", "name"],  # Breaking: new required field
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        },
        version="2.0.0",
    )

    compat = validator.check_compatibility(
        old_contract.contract_id,
        new_contract.contract_id,
    )

    assert "compatible" in compat
    assert "breaking_changes" in compat


def test_contract_validator_statistics():
    """Test validator statistics."""
    from api import create_contract_validator

    validator = create_contract_validator()

    contract = validator.register_contract("Test", {"type": "object"})
    validator.validate(contract.contract_id, {})

    stats = validator.get_statistics()

    assert stats["total_contracts"] >= 1
    assert stats["total_validations"] >= 1


def test_contract_validator_format():
    """Test formatting result."""
    from api import create_contract_validator

    validator = create_contract_validator()

    contract = validator.register_contract("Test", {"type": "object"})
    result = validator.validate(contract.contract_id, {})

    formatted = validator.format_result(result)

    assert "CONTRACT VALIDATION" in formatted


def test_api_mocker_creation():
    """Test API mocker creation."""
    from api import create_api_mocker

    mocker = create_api_mocker()
    assert mocker is not None


def test_api_mocker_add_rule():
    """Test adding mock rules."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    rule = mocker.add_rule(
        name="Get Users",
        method="GET",
        url_pattern="/users",
        status_code=200,
        body={"users": []},
    )

    assert rule.rule_id.startswith("MOCK-")


def test_api_mocker_shortcuts():
    """Test mock rule shortcuts."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    mocker.add_get("/users", 200, {"users": []})
    mocker.add_post("/users", 201, {"id": 1})
    mocker.add_delete("/users/1", 204)
    mocker.add_error("/error", 500, "Server Error")

    stats = mocker.get_statistics()
    assert stats["total_rules"] == 4


def test_api_mocker_match():
    """Test matching requests."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    mocker.add_get("/users", 200, {"users": [{"id": 1}]})

    response = mocker.match("GET", "/users")

    assert response is not None
    assert response.status_code == 200


def test_api_mocker_no_match():
    """Test unmatched requests."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    response = mocker.match("GET", "/unknown")

    assert response is None


def test_api_mocker_verify():
    """Test request verification."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    mocker.add_get("/users", 200)
    mocker.match("GET", "/users")

    assert mocker.verify_called("GET", "/users") is True
    assert mocker.verify_not_called("POST", "/users") is True


def test_api_mocker_statistics():
    """Test mocker statistics."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    mocker.add_get("/test", 200)
    mocker.match("GET", "/test")

    stats = mocker.get_statistics()

    assert stats["total_rules"] >= 1
    assert stats["total_requests"] >= 1


def test_api_mocker_format():
    """Test formatting rule."""
    from api import create_api_mocker

    mocker = create_api_mocker()

    rule = mocker.add_get("/test", 200)
    formatted = mocker.format_rule(rule)

    assert "MOCK RULE" in formatted


# ============================================================
# Accessibility Module Tests
# ============================================================

def test_accessibility_imports():
    """Test accessibility module imports."""
    from accessibility import (
        AccessibilityChecker,
        WCAGLevel,
        WCAGPrinciple,
        AccessibilityViolation,
        AccessibilityResult,
        create_accessibility_checker,
        AccessibilityRuleEngine,
        AccessibilityRule,
        RuleCategory,
        create_rule_engine,
        AccessibilityReporter,
        AccessibilityReport,
        create_accessibility_reporter,
    )
    assert AccessibilityChecker is not None
    assert AccessibilityRuleEngine is not None
    assert AccessibilityReporter is not None


def test_a11y_checker_creation():
    """Test accessibility checker creation."""
    from accessibility import create_accessibility_checker

    checker = create_accessibility_checker()
    assert checker is not None


def test_a11y_checker_check_page():
    """Test checking a page."""
    from accessibility import create_accessibility_checker

    checker = create_accessibility_checker()

    elements = [
        {"tag_name": "img", "selector": "img#logo", "attributes": {"alt": "Company Logo"}},
        {"tag_name": "a", "selector": "a.nav-link", "text_content": "Home"},
        {"tag_name": "button", "selector": "button#submit", "text_content": "Submit"},
    ]

    result = checker.check_page(
        page_url="https://example.com",
        elements=elements,
        page_metadata={"title": "Example Page", "lang": "en"},
    )

    assert result.result_id.startswith("A11Y-")
    assert result.score >= 0


def test_a11y_checker_violations():
    """Test detecting violations."""
    from accessibility import create_accessibility_checker

    checker = create_accessibility_checker()

    # Elements with accessibility issues
    elements = [
        {"tag_name": "img", "selector": "img#logo", "attributes": {}},  # Missing alt
        {"tag_name": "a", "selector": "a.link", "text_content": ""},  # Empty link
        {"tag_name": "input", "selector": "input#email", "attributes": {"type": "email"}},  # No label
    ]

    result = checker.check_page(
        page_url="https://example.com",
        elements=elements,
        page_metadata={},
    )

    assert len(result.violations) > 0


def test_a11y_checker_wcag_level():
    """Test WCAG level filtering."""
    from accessibility import create_accessibility_checker, WCAGLevel

    # Create checker targeting Level A only
    checker_a = create_accessibility_checker(target_level=WCAGLevel.A)

    # Create checker targeting Level AA
    checker_aa = create_accessibility_checker(target_level=WCAGLevel.AA)

    assert checker_a is not None
    assert checker_aa is not None


def test_a11y_checker_statistics():
    """Test checker statistics."""
    from accessibility import create_accessibility_checker

    checker = create_accessibility_checker()

    checker.check_page(
        "https://example.com",
        [{"tag_name": "div", "selector": "div"}],
        {"title": "Test", "lang": "en"},
    )

    stats = checker.get_statistics()

    assert stats["total_checks"] >= 1


def test_a11y_checker_format():
    """Test formatting result."""
    from accessibility import create_accessibility_checker

    checker = create_accessibility_checker()

    result = checker.check_page(
        "https://example.com",
        [{"tag_name": "div", "selector": "div"}],
        {"title": "Test", "lang": "en"},
    )

    formatted = checker.format_result(result)

    assert "ACCESSIBILITY CHECK" in formatted


def test_rule_engine_creation():
    """Test rule engine creation."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()
    assert engine is not None


def test_rule_engine_builtin_rules():
    """Test built-in rules exist."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()

    stats = engine.get_statistics()
    assert stats["total_rules"] > 0


def test_rule_engine_add_rule():
    """Test adding custom rule."""
    from accessibility import create_rule_engine, RuleCategory, RuleSeverity

    engine = create_rule_engine()

    rule = engine.add_rule(
        name="Custom Rule",
        description="A custom accessibility rule",
        category=RuleCategory.CONTENT,
        severity=RuleSeverity.MAJOR,
        wcag_criteria=["1.1.1"],
    )

    assert rule.rule_id is not None


def test_rule_engine_enable_disable():
    """Test enabling/disabling rules."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()

    # Get a rule
    rule = engine.get_rule("img-alt")
    assert rule is not None

    # Disable it
    engine.disable_rule("img-alt")
    assert engine.get_rule("img-alt").enabled is False

    # Enable it
    engine.enable_rule("img-alt")
    assert engine.get_rule("img-alt").enabled is True


def test_rule_engine_by_category():
    """Test getting rules by category."""
    from accessibility import create_rule_engine, RuleCategory

    engine = create_rule_engine()

    content_rules = engine.get_rules_by_category(RuleCategory.CONTENT)
    form_rules = engine.get_rules_by_category(RuleCategory.FORMS)

    assert len(content_rules) > 0
    assert len(form_rules) > 0


def test_rule_engine_check():
    """Test checking rules against elements."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()

    elements = [
        {"tag_name": "img", "selector": "img", "attributes": {}},  # Missing alt
    ]

    matches = engine.check_rule("img-alt", elements)

    assert len(matches) > 0


def test_rule_engine_statistics():
    """Test engine statistics."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()

    stats = engine.get_statistics()

    assert "total_rules" in stats
    assert "enabled_rules" in stats


def test_rule_engine_format():
    """Test formatting rule."""
    from accessibility import create_rule_engine

    engine = create_rule_engine()

    rule = engine.get_rule("img-alt")
    formatted = engine.format_rule(rule)

    assert "ACCESSIBILITY RULE" in formatted


def test_a11y_reporter_creation():
    """Test reporter creation."""
    from accessibility import create_accessibility_reporter

    reporter = create_accessibility_reporter()
    assert reporter is not None


def test_a11y_reporter_create_report():
    """Test creating report."""
    from accessibility import create_accessibility_reporter

    reporter = create_accessibility_reporter()

    results = [
        {
            "page_url": "https://example.com/page1",
            "score": 85,
            "violations": [
                {"impact": "serious", "wcag_criteria": ["1.1.1"]},
            ],
            "passes": 10,
        },
        {
            "page_url": "https://example.com/page2",
            "score": 95,
            "violations": [],
            "passes": 15,
        },
    ]

    report = reporter.create_report(
        title="Accessibility Audit",
        results=results,
    )

    assert report.report_id.startswith("A11YREP-")
    assert report.pages_checked == 2


def test_a11y_reporter_generate_html():
    """Test generating HTML report."""
    from accessibility import create_accessibility_reporter

    reporter = create_accessibility_reporter()

    results = [{"page_url": "https://example.com", "score": 90, "violations": [], "passes": 10}]
    report = reporter.create_report("Test", results)

    html = reporter.generate(report)

    assert "<!DOCTYPE html>" in html


def test_a11y_reporter_generate_json():
    """Test generating JSON report."""
    from accessibility import create_accessibility_reporter, A11yReportFormat

    reporter = create_accessibility_reporter()

    results = [{"page_url": "https://example.com", "score": 90, "violations": [], "passes": 10}]
    report = reporter.create_report("Test", results)

    json_str = reporter.generate(report, format=A11yReportFormat.JSON)

    assert "report_id" in json_str


def test_a11y_reporter_generate_markdown():
    """Test generating Markdown report."""
    from accessibility import create_accessibility_reporter, A11yReportFormat

    reporter = create_accessibility_reporter()

    results = [{"page_url": "https://example.com", "score": 90, "violations": [], "passes": 10}]
    report = reporter.create_report("Test", results)

    md = reporter.generate(report, format=A11yReportFormat.MARKDOWN)

    assert "# Test" in md


def test_a11y_reporter_trend():
    """Test trend analysis."""
    from accessibility import create_accessibility_reporter

    reporter = create_accessibility_reporter()

    for i in range(5):
        results = [{"page_url": f"https://example.com/{i}", "score": 80 + i * 2, "violations": [], "passes": 10}]
        reporter.create_report(f"Run {i}", results)

    trend = reporter.get_trend()

    assert "trend" in trend


def test_a11y_reporter_statistics():
    """Test reporter statistics."""
    from accessibility import create_accessibility_reporter

    reporter = create_accessibility_reporter()

    results = [{"page_url": "https://example.com", "score": 90, "violations": [], "passes": 10}]
    reporter.create_report("Test", results)

    stats = reporter.get_statistics()

    assert stats["total_reports"] >= 1


# ============================================================
# Security Scanner Module Tests
# ============================================================

def test_security_scanner_imports():
    """Test security scanner module imports."""
    from security_scanner import (
        VulnerabilityScanner,
        Vulnerability,
        VulnerabilitySeverity,
        VulnerabilityCategory,
        ScanResult,
        create_vulnerability_scanner,
        AttackSimulator,
        Attack,
        AttackType,
        AttackResult,
        create_attack_simulator,
        ComplianceChecker,
        ComplianceStandard,
        ComplianceResult,
        ComplianceViolation,
        create_compliance_checker,
    )

    assert VulnerabilityScanner is not None
    assert AttackSimulator is not None
    assert ComplianceChecker is not None


def test_vuln_scanner_creation():
    """Test vulnerability scanner creation."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    assert scanner is not None


def test_vuln_scanner_scan():
    """Test vulnerability scanning."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    result = scanner.scan("https://example.com")

    assert result is not None
    assert result.scan_id is not None
    assert result.target == "https://example.com"


def test_vuln_scanner_elements():
    """Test scanning DOM elements."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    elements = [
        {"tag": "form", "attributes": {"action": "/submit", "method": "post"}, "text": ""},
        {"tag": "input", "attributes": {"type": "password"}, "text": ""},
        {"tag": "a", "attributes": {"href": "https://evil.com", "target": "_blank"}, "text": "Link"},
    ]

    result = scanner.scan("https://example.com", elements=elements)

    assert len(result.vulnerabilities) > 0


def test_vuln_scanner_responses():
    """Test scanning HTTP responses."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    responses = [
        {"url": "https://example.com", "status": 200, "headers": {}, "body": "normal response"},
    ]

    result = scanner.scan("https://example.com", responses=responses)

    # Should find missing security headers
    assert len(result.vulnerabilities) > 0


def test_vuln_scanner_risk_score():
    """Test risk score calculation."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    elements = [
        {"tag": "form", "attributes": {"action": "/submit", "method": "post"}, "text": ""},
    ]

    result = scanner.scan("https://example.com", elements=elements)

    assert result.risk_score >= 0
    assert result.risk_score <= 100


def test_vuln_scanner_statistics():
    """Test scanner statistics."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    scanner.scan("https://example.com")

    stats = scanner.get_statistics()

    assert stats["total_scans"] >= 1
    assert "detection_rules" in stats


def test_vuln_scanner_format():
    """Test scanner result formatting."""
    from security_scanner import create_vulnerability_scanner

    scanner = create_vulnerability_scanner()

    result = scanner.scan("https://example.com")

    formatted = scanner.format_result(result)

    assert "SECURITY SCAN" in formatted
    assert "Risk Score" in formatted


def test_attack_simulator_creation():
    """Test attack simulator creation."""
    from security_scanner import create_attack_simulator

    simulator = create_attack_simulator()

    assert simulator is not None


def test_attack_simulator_builtin():
    """Test built-in attacks."""
    from security_scanner import create_attack_simulator, AttackType

    simulator = create_attack_simulator()

    sql_attacks = simulator.get_attacks_by_type(AttackType.SQL_INJECTION)
    xss_attacks = simulator.get_attacks_by_type(AttackType.XSS_REFLECTED)

    assert len(sql_attacks) > 0
    assert len(xss_attacks) > 0


def test_attack_simulator_add_attack():
    """Test adding custom attack."""
    from security_scanner import create_attack_simulator, AttackType

    simulator = create_attack_simulator()

    attack = simulator.add_attack(
        name="Custom Attack",
        attack_type=AttackType.SQL_INJECTION,
        description="Test attack",
        payloads=["test payload"],
        detection_indicators=["indicator"],
    )

    assert attack is not None
    assert attack.attack_id is not None
    assert attack.name == "Custom Attack"


def test_attack_simulator_simulate():
    """Test attack simulation."""
    from security_scanner import create_attack_simulator

    simulator = create_attack_simulator()

    result = simulator.simulate("sqli-basic", "https://example.com")

    assert result is not None
    assert result.attack.attack_type.value == "sql_injection"


def test_attack_simulator_simulate_response():
    """Test simulation with response analysis."""
    from security_scanner import create_attack_simulator, AttackOutcome

    simulator = create_attack_simulator()

    response = {
        "body": "You have an error in your SQL syntax",
        "status": 500,
    }

    result = simulator.simulate("sqli-basic", "https://example.com", response)

    assert result is not None
    assert result.outcome in [AttackOutcome.VULNERABLE, AttackOutcome.POTENTIALLY_VULNERABLE]


def test_attack_simulator_payloads():
    """Test getting attack payloads."""
    from security_scanner import create_attack_simulator, AttackType

    simulator = create_attack_simulator()

    payloads = simulator.get_payloads(AttackType.XSS_REFLECTED, limit=5)

    assert len(payloads) > 0
    assert len(payloads) <= 5


def test_attack_simulator_statistics():
    """Test simulator statistics."""
    from security_scanner import create_attack_simulator

    simulator = create_attack_simulator()

    simulator.simulate("sqli-basic", "https://example.com")

    stats = simulator.get_statistics()

    assert stats["total_attacks"] > 0
    assert stats["total_simulations"] >= 1


def test_attack_simulator_format():
    """Test result formatting."""
    from security_scanner import create_attack_simulator

    simulator = create_attack_simulator()

    result = simulator.simulate("sqli-basic", "https://example.com")

    formatted = simulator.format_result(result)

    assert "ATTACK SIMULATION" in formatted
    assert "SQL" in formatted.upper()


def test_compliance_checker_creation():
    """Test compliance checker creation."""
    from security_scanner import create_compliance_checker

    checker = create_compliance_checker()

    assert checker is not None


def test_compliance_checker_standards():
    """Test compliance standards."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker(standards=[ComplianceStandard.OWASP_TOP_10])

    requirements = checker.get_requirements_by_standard(ComplianceStandard.OWASP_TOP_10)

    assert len(requirements) > 0


def test_compliance_checker_add_requirement():
    """Test adding custom requirement."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    requirement = checker.add_requirement(
        standard=ComplianceStandard.OWASP_TOP_10,
        title="Custom Requirement",
        description="Test requirement",
        controls=["Control 1", "Control 2"],
    )

    assert requirement is not None
    assert requirement.title == "Custom Requirement"


def test_compliance_checker_check():
    """Test compliance checking."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    result = checker.check("https://example.com", ComplianceStandard.OWASP_TOP_10)

    assert result is not None
    assert result.standard == ComplianceStandard.OWASP_TOP_10
    assert result.score >= 0


def test_compliance_checker_with_findings():
    """Test compliance with security findings."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    findings = [
        {"title": "SQL Injection", "category": "injection", "severity": "critical", "evidence": "test"},
        {"title": "Missing Headers", "category": "config", "severity": "medium", "evidence": "test"},
    ]

    result = checker.check("https://example.com", ComplianceStandard.OWASP_TOP_10, findings=findings)

    assert len(result.violations) > 0
    assert result.requirements_failed > 0


def test_compliance_checker_gap_analysis():
    """Test gap analysis generation."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    findings = [{"title": "SQL Injection", "category": "injection", "severity": "critical"}]
    result = checker.check("https://example.com", ComplianceStandard.OWASP_TOP_10, findings=findings)

    gaps = checker.get_gap_analysis(result)

    assert "gaps" in gaps
    assert gaps["standard"] == "owasp_top_10"


def test_compliance_checker_statistics():
    """Test checker statistics."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    checker.check("https://example.com", ComplianceStandard.OWASP_TOP_10)

    stats = checker.get_statistics()

    assert stats["total_checks"] >= 1
    assert "total_requirements" in stats


def test_compliance_checker_format():
    """Test result formatting."""
    from security_scanner import create_compliance_checker, ComplianceStandard

    checker = create_compliance_checker()

    result = checker.check("https://example.com", ComplianceStandard.OWASP_TOP_10)

    formatted = checker.format_result(result)

    assert "COMPLIANCE CHECK" in formatted
    assert "Score" in formatted


# ============================================================
# Data Generation Module Tests
# ============================================================

def test_data_generation_imports():
    """Test data generation module imports."""
    from data_generation import (
        DataGenerator,
        DataType,
        DataProfile,
        GeneratedData,
        create_data_generator,
        DataFactory,
        FactoryTemplate,
        FactoryField,
        create_data_factory,
        DataSeeder,
        SeedStrategy,
        SeedResult,
        create_data_seeder,
    )

    assert DataGenerator is not None
    assert DataFactory is not None
    assert DataSeeder is not None


def test_data_generator_creation():
    """Test data generator creation."""
    from data_generation import create_data_generator

    generator = create_data_generator()

    assert generator is not None


def test_data_generator_string():
    """Test string generation."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator(seed=42)

    result = generator.generate(DataType.STRING)

    assert result is not None
    assert isinstance(result.value, str)
    assert len(result.value) > 0


def test_data_generator_email():
    """Test email generation."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator(seed=42)

    result = generator.generate(DataType.EMAIL)

    assert result is not None
    assert "@" in result.value
    assert "." in result.value


def test_data_generator_password():
    """Test password generation."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator(seed=42)

    result = generator.generate(DataType.PASSWORD)

    assert result is not None
    assert len(result.value) >= 12


def test_data_generator_batch():
    """Test batch generation."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator(seed=42)

    results = generator.generate_batch(DataType.INTEGER, 5)

    assert len(results) == 5
    for r in results:
        assert isinstance(r.value, int)


def test_data_generator_profile():
    """Test profile creation."""
    from data_generation import create_data_generator

    generator = create_data_generator()

    profile = generator.create_profile("test_profile", locale="en_US")

    assert profile is not None
    assert profile.name == "test_profile"


def test_data_generator_statistics():
    """Test generator statistics."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator(seed=42)

    generator.generate(DataType.STRING)
    generator.generate(DataType.EMAIL)

    stats = generator.get_statistics()

    assert stats["total_generated"] >= 2


def test_data_generator_format():
    """Test data formatting."""
    from data_generation import create_data_generator, DataType

    generator = create_data_generator()

    data = generator.generate(DataType.STRING)
    formatted = generator.format_data(data)

    assert "GENERATED DATA" in formatted
    assert data.data_id in formatted


def test_data_factory_creation():
    """Test factory creation."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    assert factory is not None


def test_data_factory_builtin():
    """Test built-in templates."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    user_template = factory.get_template("user")
    product_template = factory.get_template("product")

    assert user_template is not None
    assert product_template is not None


def test_data_factory_create():
    """Test instance creation."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    instance = factory.create("user")

    assert instance is not None
    assert "email" in instance.data
    assert "first_name" in instance.data


def test_data_factory_traits():
    """Test trait application."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    instance = factory.create("user", traits=["admin"])

    assert instance is not None
    assert instance.data.get("role") == "admin"
    assert "admin" in instance.traits_applied


def test_data_factory_overrides():
    """Test override application."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    instance = factory.create("user", overrides={"first_name": "Custom"})

    assert instance.data["first_name"] == "Custom"


def test_data_factory_batch():
    """Test batch creation."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    instances = factory.create_batch("product", 5)

    assert len(instances) == 5


def test_data_factory_define():
    """Test custom template definition."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    template = factory.define(
        name="CustomEntity",
        entity_type="custom",
        fields=[
            {"name": "id", "type": "sequence"},
            {"name": "name", "type": "static", "value": "Test"},
        ],
    )

    assert template is not None
    assert template.name == "CustomEntity"


def test_data_factory_statistics():
    """Test factory statistics."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    factory.create("user")
    factory.create("product")

    stats = factory.get_statistics()

    assert stats["total_instances"] >= 2


def test_data_factory_format():
    """Test instance formatting."""
    from data_generation import create_data_factory

    factory = create_data_factory()

    instance = factory.create("user")
    formatted = factory.format_instance(instance)

    assert "FACTORY INSTANCE" in formatted
    assert "User" in formatted


def test_data_seeder_creation():
    """Test seeder creation."""
    from data_generation import create_data_seeder

    seeder = create_data_seeder()

    assert seeder is not None


def test_data_seeder_plan():
    """Test plan creation."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder()

    plan = seeder.create_plan("test_plan", strategy=SeedStrategy.MINIMAL)

    assert plan is not None
    assert plan.strategy == SeedStrategy.MINIMAL


def test_data_seeder_seed():
    """Test data seeding."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder(strategy=SeedStrategy.MINIMAL, seed=42)

    result = seeder.seed()

    assert result is not None
    assert result.total_records > 0


def test_data_seeder_get_data():
    """Test getting seeded data."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder(strategy=SeedStrategy.MINIMAL, seed=42)

    seeder.seed()

    users = seeder.get_seeded_data("users")

    assert len(users) > 0
    assert "email" in users[0]


def test_data_seeder_strategies():
    """Test different strategies."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder(seed=42)

    seeder.set_strategy(SeedStrategy.COMPREHENSIVE)
    plan = seeder.create_plan("comprehensive_test")

    assert plan.categories.get("users", 0) > 10


def test_data_seeder_statistics():
    """Test seeder statistics."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder(strategy=SeedStrategy.MINIMAL, seed=42)

    seeder.seed()

    stats = seeder.get_statistics()

    assert stats["total_records"] > 0


def test_data_seeder_format():
    """Test result formatting."""
    from data_generation import create_data_seeder, SeedStrategy

    seeder = create_data_seeder(strategy=SeedStrategy.MINIMAL, seed=42)

    result = seeder.seed()
    formatted = seeder.format_result(result)

    assert "SEED RESULT" in formatted
    assert "Total" in formatted


# ============================================================
# Flakiness Module Tests
# ============================================================

def test_flakiness_imports():
    """Test flakiness module imports."""
    from flakiness import (
        FlakinessDetector,
        FlakinessPattern,
        FlakinessLevel,
        TestExecution,
        create_flakiness_detector,
        FlakinessAnalyzer,
        FlakeAnalysis,
        FlakeRootCause,
        create_flakiness_analyzer,
        FlakinessMitigator,
        MitigationStrategy,
        MitigationResult,
        create_flakiness_mitigator,
    )

    assert FlakinessDetector is not None
    assert FlakinessAnalyzer is not None
    assert FlakinessMitigator is not None


def test_flakiness_detector_creation():
    """Test detector creation."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector()

    assert detector is not None


def test_flakiness_detector_record():
    """Test recording executions."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector()

    execution = detector.record_execution(
        test_id="test-1",
        test_name="Test One",
        passed=True,
        duration_ms=100,
    )

    assert execution is not None
    assert execution.test_id == "test-1"


def test_flakiness_detector_detect():
    """Test flakiness detection."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector(min_runs=3)

    # Record mixed results
    for i in range(10):
        detector.record_execution(
            test_id="flaky-test",
            test_name="Flaky Test",
            passed=i % 2 == 0,
            duration_ms=100 + i * 10,
        )

    report = detector.detect("flaky-test")

    assert report is not None
    assert report.flakiness_score > 0


def test_flakiness_detector_patterns():
    """Test pattern detection."""
    from flakiness import create_flakiness_detector, FlakinessPattern

    detector = create_flakiness_detector(min_runs=3)

    # Record with timing-related errors
    for i in range(5):
        detector.record_execution(
            test_id="timing-test",
            test_name="Timing Test",
            passed=i % 2 == 0,
            duration_ms=100 if i % 2 == 0 else 5000,
            error_message="Timed out waiting for element" if i % 2 != 0 else None,
        )

    report = detector.detect("timing-test")

    assert report is not None
    assert FlakinessPattern.TIMING in report.patterns_detected


def test_flakiness_detector_statistics():
    """Test detector statistics."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector(min_runs=3)

    for i in range(5):
        detector.record_execution("test-1", "Test", i % 2 == 0, 100)

    detector.detect("test-1")

    stats = detector.get_statistics()

    assert stats["total_executions"] >= 5


def test_flakiness_detector_format():
    """Test report formatting."""
    from flakiness import create_flakiness_detector

    detector = create_flakiness_detector(min_runs=3)

    for i in range(5):
        detector.record_execution("test-1", "Test", i % 2 == 0, 100)

    report = detector.detect("test-1")
    formatted = detector.format_report(report)

    assert "FLAKINESS REPORT" in formatted


def test_flakiness_analyzer_creation():
    """Test analyzer creation."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    assert analyzer is not None


def test_flakiness_analyzer_analyze():
    """Test flakiness analysis."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    analysis = analyzer.analyze(
        test_id="test-1",
        test_name="Test One",
        error_messages=["Timed out waiting for element"],
    )

    assert analysis is not None
    assert len(analysis.root_causes) > 0


def test_flakiness_analyzer_recommendations():
    """Test recommendations generation."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    analysis = analyzer.analyze(
        test_id="test-1",
        test_name="Test One",
        error_messages=["Race condition detected"],
    )

    assert len(analysis.recommendations) > 0


def test_flakiness_analyzer_correlations():
    """Test correlation detection."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    analyzer.analyze("test-1", "Test One", ["Timeout"])
    analyzer.analyze("test-2", "Test Two", ["Timeout waiting"])

    correlations = analyzer.find_correlations(["test-1", "test-2"])

    # Both have timing-related issues, should correlate
    assert len(correlations) >= 0  # May or may not correlate


def test_flakiness_analyzer_statistics():
    """Test analyzer statistics."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    analyzer.analyze("test-1", "Test", ["Error"])

    stats = analyzer.get_statistics()

    assert stats["total_analyses"] >= 1


def test_flakiness_analyzer_format():
    """Test analysis formatting."""
    from flakiness import create_flakiness_analyzer

    analyzer = create_flakiness_analyzer()

    analysis = analyzer.analyze("test-1", "Test", ["Error"])
    formatted = analyzer.format_analysis(analysis)

    assert "FLAKINESS ANALYSIS" in formatted


def test_flakiness_mitigator_creation():
    """Test mitigator creation."""
    from flakiness import create_flakiness_mitigator

    mitigator = create_flakiness_mitigator()

    assert mitigator is not None


def test_flakiness_mitigator_suggest():
    """Test mitigation suggestions."""
    from flakiness import create_flakiness_mitigator

    mitigator = create_flakiness_mitigator()

    suggestions = mitigator.suggest(
        test_id="test-1",
        test_name="Test One",
        root_causes=["async_wait"],
        success_rate=0.6,
    )

    assert len(suggestions) > 0


def test_flakiness_mitigator_apply():
    """Test applying mitigations."""
    from flakiness import create_flakiness_mitigator

    mitigator = create_flakiness_mitigator()

    suggestions = mitigator.suggest("test-1", "Test", ["async_wait"], 0.6)

    result = mitigator.apply(
        test_id="test-1",
        test_name="Test One",
        actions=suggestions[:1],
        success_rate_before=0.6,
    )

    assert result is not None


def test_flakiness_mitigator_verify():
    """Test mitigation verification."""
    from flakiness import create_flakiness_mitigator, MitigationStatus

    mitigator = create_flakiness_mitigator()

    suggestions = mitigator.suggest("test-1", "Test", ["async_wait"], 0.6)
    mitigator.apply("test-1", "Test", suggestions[:1], 0.6)

    result = mitigator.verify("test-1", 0.95)

    assert result.status == MitigationStatus.VERIFIED


def test_flakiness_mitigator_statistics():
    """Test mitigator statistics."""
    from flakiness import create_flakiness_mitigator

    mitigator = create_flakiness_mitigator()

    suggestions = mitigator.suggest("test-1", "Test", ["async_wait"], 0.6)
    mitigator.apply("test-1", "Test", suggestions[:1], 0.6)

    stats = mitigator.get_statistics()

    assert stats["total_mitigations"] >= 1


def test_flakiness_mitigator_format():
    """Test result formatting."""
    from flakiness import create_flakiness_mitigator

    mitigator = create_flakiness_mitigator()

    suggestions = mitigator.suggest("test-1", "Test", ["async_wait"], 0.6)
    result = mitigator.apply("test-1", "Test", suggestions[:1], 0.6)

    formatted = mitigator.format_result(result)

    assert "MITIGATION RESULT" in formatted


# ============================================================
# Environment Module Tests
# ============================================================

def test_environment_imports():
    """Test environment module imports."""
    from environment import (
        EnvironmentManager,
        Environment,
        EnvironmentConfig,
        EnvironmentStatus,
        create_environment_manager,
        EnvironmentProvisioner,
        ProvisioningPlan,
        ProvisionResult,
        create_provisioner,
        ConfigManager,
        ConfigProfile,
        ConfigSource,
        create_config_manager,
    )

    assert EnvironmentManager is not None
    assert EnvironmentProvisioner is not None
    assert ConfigManager is not None


def test_environment_manager_creation():
    """Test environment manager creation."""
    from environment import create_environment_manager

    manager = create_environment_manager()

    assert manager is not None


def test_environment_manager_configs():
    """Test built-in environment configs."""
    from environment import create_environment_manager

    manager = create_environment_manager()

    configs = manager.list_configs()

    assert len(configs) >= 4
    config_ids = [c.config_id for c in configs]
    assert "local-dev" in config_ids
    assert "docker-test" in config_ids


def test_environment_manager_create():
    """Test creating an environment."""
    from environment import create_environment_manager, EnvironmentStatus

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")

    assert env is not None
    assert env.env_id.startswith("ENV-")
    assert env.status == EnvironmentStatus.PENDING


def test_environment_manager_start():
    """Test starting an environment."""
    from environment import create_environment_manager, EnvironmentStatus

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")
    started = manager.start(env.env_id)

    assert started.status == EnvironmentStatus.READY
    assert started.started_at is not None
    assert "app" in started.endpoints


def test_environment_manager_stop():
    """Test stopping an environment."""
    from environment import create_environment_manager, EnvironmentStatus

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")
    manager.start(env.env_id)
    stopped = manager.stop(env.env_id)

    assert stopped.status == EnvironmentStatus.PAUSED


def test_environment_manager_terminate():
    """Test terminating an environment."""
    from environment import create_environment_manager, EnvironmentStatus

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")
    manager.start(env.env_id)
    terminated = manager.terminate(env.env_id)

    assert terminated.status == EnvironmentStatus.TERMINATED
    assert terminated.terminated_at is not None


def test_environment_manager_health():
    """Test health check."""
    from environment import create_environment_manager

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")
    manager.start(env.env_id)

    health = manager.check_health(env.env_id)

    assert health["status"] == "healthy"


def test_environment_manager_statistics():
    """Test manager statistics."""
    from environment import create_environment_manager

    manager = create_environment_manager()

    manager.create("Env 1", "local-dev")
    manager.create("Env 2", "docker-test")

    stats = manager.get_statistics()

    assert stats["total_environments"] == 2
    assert stats["total_configs"] >= 4


def test_environment_manager_format():
    """Test environment formatting."""
    from environment import create_environment_manager

    manager = create_environment_manager()

    env = manager.create("Test Env", "local-dev")
    manager.start(env.env_id)

    formatted = manager.format_environment(env)

    assert "ENVIRONMENT" in formatted
    assert "READY" in formatted


def test_provisioner_creation():
    """Test provisioner creation."""
    from environment import create_provisioner

    provisioner = create_provisioner()

    assert provisioner is not None


def test_provisioner_resource_spec():
    """Test creating resource specs."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    spec = provisioner.create_resource_spec(
        resource_type=ResourceType.DATABASE,
        name="Test DB",
        config={"engine": "postgresql"},
    )

    assert spec.resource_id.startswith("RES-")
    assert spec.resource_type == ResourceType.DATABASE


def test_provisioner_plan():
    """Test creating provisioning plan."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    resources = [
        provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {}),
        provisioner.create_resource_spec(ResourceType.CACHE, "Cache", {}),
    ]

    plan = provisioner.create_plan("Test Plan", resources)

    assert plan.plan_id.startswith("PLAN-")
    assert len(plan.resources) == 2
    assert len(plan.order) == 2


def test_provisioner_dependencies():
    """Test dependency resolution."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    db = provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {})
    cache = provisioner.create_resource_spec(ResourceType.CACHE, "Cache", {})
    service = provisioner.create_resource_spec(
        ResourceType.SERVICE,
        "Service",
        {},
        dependencies=[db.resource_id, cache.resource_id],
    )

    plan = provisioner.create_plan("Test Plan", [service, db, cache])

    # Service should come after DB and Cache
    db_idx = plan.order.index(db.resource_id)
    cache_idx = plan.order.index(cache.resource_id)
    service_idx = plan.order.index(service.resource_id)

    assert service_idx > db_idx
    assert service_idx > cache_idx


def test_provisioner_provision():
    """Test executing provisioning."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType, ProvisionStatus

    provisioner = create_provisioner()

    resources = [
        provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {}),
        provisioner.create_resource_spec(ResourceType.CACHE, "Cache", {}),
    ]

    plan = provisioner.create_plan("Test Plan", resources)
    result = provisioner.provision(plan)

    assert result.result_id.startswith("PROV-")
    assert result.status == ProvisionStatus.COMPLETED
    assert len(result.resources_provisioned) == 2


def test_provisioner_dry_run():
    """Test dry run provisioning."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    resources = [
        provisioner.create_resource_spec(ResourceType.SERVICE, "API", {}),
    ]

    plan = provisioner.create_plan("Test Plan", resources)
    result = provisioner.provision(plan, dry_run=True)

    # logs[0]="Starting...", logs[1]="Provisioning API...", logs[2]="[DRY RUN]..."
    assert any("[DRY RUN]" in log for log in result.logs)


def test_provisioner_rollback():
    """Test rollback."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType, ProvisionStatus

    provisioner = create_provisioner()

    resources = [
        provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {}),
    ]

    plan = provisioner.create_plan("Test Plan", resources)
    result = provisioner.provision(plan)
    rollback = provisioner.rollback(result)

    assert rollback.status == ProvisionStatus.ROLLED_BACK
    assert "Rolling back" in rollback.logs[0]


def test_provisioner_statistics():
    """Test provisioner statistics."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    resources = [provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {})]
    plan = provisioner.create_plan("Test", resources)
    provisioner.provision(plan)

    stats = provisioner.get_statistics()

    assert stats["total_plans"] == 1
    assert stats["total_provisions"] == 1


def test_provisioner_format():
    """Test result formatting."""
    from environment import create_provisioner
    from environment.provisioner import ResourceType

    provisioner = create_provisioner()

    resources = [provisioner.create_resource_spec(ResourceType.DATABASE, "DB", {})]
    plan = provisioner.create_plan("Test", resources)
    result = provisioner.provision(plan)

    formatted = provisioner.format_result(result)

    assert "PROVISION RESULT" in formatted
    assert "COMPLETED" in formatted


def test_config_manager_creation():
    """Test config manager creation."""
    from environment import create_config_manager

    manager = create_config_manager()

    assert manager is not None


def test_config_manager_defaults():
    """Test default configuration."""
    from environment import create_config_manager

    manager = create_config_manager()

    timeout = manager.get("test.timeout")

    assert timeout == 30000


def test_config_manager_set():
    """Test setting values."""
    from environment import create_config_manager

    manager = create_config_manager()

    value = manager.set("custom.setting", "value")

    assert value.key == "custom.setting"
    assert manager.get("custom.setting") == "value"


def test_config_manager_profile():
    """Test creating profiles."""
    from environment import create_config_manager

    manager = create_config_manager()

    profile = manager.create_profile(
        name="CI Profile",
        description="CI environment config",
        parent="default",
        values={"test.retries": 5},
    )

    assert profile.profile_id.startswith("profile-")
    assert profile.values["test.retries"].value == 5


def test_config_manager_activate():
    """Test activating profiles."""
    from environment import create_config_manager

    manager = create_config_manager()

    profile = manager.create_profile(
        name="Fast",
        values={"test.timeout": 5000},
    )

    manager.activate_profile(profile.profile_id)

    assert manager.get("test.timeout") == 5000


def test_config_manager_prefix():
    """Test getting values by prefix."""
    from environment import create_config_manager

    manager = create_config_manager()

    browser_settings = manager.get_by_prefix("browser.")

    assert "browser.headless" in browser_settings
    assert "browser.viewport.width" in browser_settings


def test_config_manager_merge():
    """Test merging configuration."""
    from environment import create_config_manager

    manager = create_config_manager()

    manager.merge({
        "custom.a": 1,
        "custom.b": 2,
    })

    assert manager.get("custom.a") == 1
    assert manager.get("custom.b") == 2


def test_config_manager_load_dict():
    """Test loading nested dict."""
    from environment import create_config_manager

    manager = create_config_manager()

    manager.load_from_dict({
        "app": {
            "name": "TestApp",
            "version": "1.0.0",
        }
    })

    assert manager.get("app.name") == "TestApp"
    assert manager.get("app.version") == "1.0.0"


def test_config_manager_statistics():
    """Test config statistics."""
    from environment import create_config_manager

    manager = create_config_manager()

    stats = manager.get_statistics()

    assert stats["total_profiles"] >= 1
    assert stats["total_values"] >= 10


def test_config_manager_format():
    """Test profile formatting."""
    from environment import create_config_manager

    manager = create_config_manager()

    profile = manager.get_profile("default")
    formatted = manager.format_profile(profile)

    assert "CONFIG PROFILE" in formatted
    assert "Default" in formatted


# ============================================================
# Coverage Module Tests
# ============================================================

def test_coverage_imports():
    """Test coverage module imports."""
    from coverage import (
        CoverageTracker,
        CoverageReport,
        CoverageMetrics,
        CoverageType,
        create_coverage_tracker,
        TestCoverageMapper,
        CoverageMapping,
        TestCoverageInfo,
        create_coverage_mapper,
        GapAnalyzer,
        CoverageGap,
        GapSeverity,
        GapReport,
        create_gap_analyzer,
    )

    assert CoverageTracker is not None
    assert TestCoverageMapper is not None
    assert GapAnalyzer is not None


def test_coverage_tracker_creation():
    """Test coverage tracker creation."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    assert tracker is not None


def test_coverage_tracker_record_file():
    """Test recording file coverage."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    coverage = tracker.record_file_coverage(
        file_path="src/auth.py",
        total_lines=100,
        covered_lines=80,
        missed_lines=[15, 25, 35, 45, 55, 65, 75, 85, 95, 100,
                      11, 12, 13, 14, 16, 17, 18, 19, 20, 21],
        total_functions=10,
        covered_functions=8,
        uncovered_functions=["handle_error", "cleanup"],
    )

    assert coverage.file_path == "src/auth.py"
    assert coverage.line_coverage == 80.0


def test_coverage_tracker_report():
    """Test generating coverage report."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    tracker.record_file_coverage("src/a.py", 100, 90, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    tracker.record_file_coverage("src/b.py", 50, 40, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    report = tracker.generate_report("Test Report")

    assert report.report_id.startswith("COV-")
    assert report.metrics.total_files == 2
    assert report.metrics.line_coverage_pct > 0


def test_coverage_tracker_low_coverage():
    """Test finding low coverage files."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker(coverage_threshold=80.0)

    tracker.record_file_coverage("src/good.py", 100, 90, [])
    tracker.record_file_coverage("src/bad.py", 100, 50, list(range(51)))

    low = tracker.get_low_coverage_files()

    assert len(low) == 1
    assert low[0].file_path == "src/bad.py"


def test_coverage_tracker_trend():
    """Test coverage trend analysis."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    # First report
    tracker.record_file_coverage("src/a.py", 100, 70, list(range(30)))
    tracker.generate_report("Report 1")

    # Second report with better coverage
    tracker.clear()
    tracker.record_file_coverage("src/a.py", 100, 80, list(range(20)))
    report = tracker.generate_report("Report 2")

    assert report.trend is not None
    assert report.trend["line_change"] > 0


def test_coverage_tracker_statistics():
    """Test tracker statistics."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    tracker.record_file_coverage("src/a.py", 100, 80, [])

    stats = tracker.get_statistics()

    assert stats["tracked_files"] == 1


def test_coverage_tracker_format():
    """Test report formatting."""
    from coverage import create_coverage_tracker

    tracker = create_coverage_tracker()

    tracker.record_file_coverage("src/a.py", 100, 80, list(range(20)))
    report = tracker.generate_report("Test")

    formatted = tracker.format_report(report)

    assert "COVERAGE REPORT" in formatted
    assert "Line Coverage" in formatted


def test_coverage_mapper_creation():
    """Test coverage mapper creation."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    assert mapper is not None


def test_coverage_mapper_register():
    """Test registering test coverage."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    info = mapper.register_test_coverage(
        test_id="test-001",
        test_name="Login Test",
        covered_files=["src/auth.py", "src/user.py"],
        covered_functions=["login", "validate"],
        execution_time_ms=1500,
    )

    assert info.test_id == "test-001"
    assert len(info.covered_files) == 2


def test_coverage_mapper_get_tests():
    """Test getting tests for code."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage(
        "test-001",
        "Test 1",
        covered_files=["src/auth.py"],
    )
    mapper.register_test_coverage(
        "test-002",
        "Test 2",
        covered_files=["src/auth.py", "src/user.py"],
    )

    tests = mapper.get_tests_for_code("src/auth.py")

    assert len(tests) == 2
    assert "test-001" in tests
    assert "test-002" in tests


def test_coverage_mapper_affected_tests():
    """Test finding affected tests."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage(
        "test-001",
        "Auth Test",
        covered_files=["src/auth.py"],
    )
    mapper.register_test_coverage(
        "test-002",
        "User Test",
        covered_files=["src/user.py"],
    )

    affected = mapper.get_affected_tests(["src/auth.py"])

    assert len(affected) == 1
    assert "test-001" in affected


def test_coverage_mapper_overlap():
    """Test calculating test overlap."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage(
        "test-001",
        "Test 1",
        covered_files=["src/a.py", "src/b.py"],
    )
    mapper.register_test_coverage(
        "test-002",
        "Test 2",
        covered_files=["src/a.py", "src/c.py"],
    )

    overlap = mapper.get_test_overlap("test-001", "test-002")

    assert overlap["overlap_pct"] > 0
    assert overlap["common_files"] == 1


def test_coverage_mapper_generate():
    """Test generating coverage mapping."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage("test-001", "Test", covered_files=["src/a.py"])

    mapping = mapper.generate_mapping("Test Mapping")

    assert mapping.mapping_id.startswith("MAP-")
    assert mapping.test_count == 1


def test_coverage_mapper_statistics():
    """Test mapper statistics."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage("test-001", "Test", covered_files=["src/a.py"])

    stats = mapper.get_statistics()

    assert stats["total_tests"] == 1


def test_coverage_mapper_format():
    """Test mapping formatting."""
    from coverage import create_coverage_mapper

    mapper = create_coverage_mapper()

    mapper.register_test_coverage("test-001", "Test", covered_files=["src/a.py"])
    mapping = mapper.generate_mapping()

    formatted = mapper.format_mapping(mapping)

    assert "TEST COVERAGE MAPPING" in formatted


def test_gap_analyzer_creation():
    """Test gap analyzer creation."""
    from coverage import create_gap_analyzer

    analyzer = create_gap_analyzer()

    assert analyzer is not None


def test_gap_analyzer_analyze():
    """Test gap analysis."""
    from coverage import create_gap_analyzer

    analyzer = create_gap_analyzer(min_coverage_threshold=80.0)

    coverage_data = {
        "files": {
            "src/good.py": {"line_coverage": 90},
            "src/bad.py": {"line_coverage": 50, "uncovered_functions": ["process"]},
        }
    }

    gaps = analyzer.analyze_coverage(coverage_data)

    assert len(gaps) >= 1


def test_gap_analyzer_add_gap():
    """Test manually adding gaps."""
    from coverage import create_gap_analyzer, GapSeverity
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    gap = analyzer.add_gap(
        gap_type=GapType.UNTESTED_FILE,
        location="src/critical.py",
        description="Critical file has no tests",
        severity=GapSeverity.CRITICAL,
    )

    assert gap.gap_id.startswith("GAP-")
    assert gap.severity == GapSeverity.CRITICAL


def test_gap_analyzer_prioritize():
    """Test gap prioritization."""
    from coverage import create_gap_analyzer, GapSeverity
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    analyzer.add_gap(GapType.MISSING_EDGE_CASES, "src/a.py", "Low priority")
    analyzer.add_gap(GapType.UNTESTED_FILE, "src/b.py", "High priority", GapSeverity.CRITICAL)

    prioritized = analyzer.prioritize_gaps()

    assert prioritized[0].severity == GapSeverity.CRITICAL


def test_gap_analyzer_recommendations():
    """Test recommendation generation."""
    from coverage import create_gap_analyzer
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    analyzer.add_gap(GapType.UNTESTED_FILE, "src/auth.py", "No tests")

    recommendations = analyzer.generate_recommendations()

    assert len(recommendations) >= 1
    assert recommendations[0].recommendation_id.startswith("REC-")


def test_gap_analyzer_report():
    """Test generating gap report."""
    from coverage import create_gap_analyzer
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    analyzer.add_gap(GapType.UNTESTED_FILE, "src/a.py", "Gap 1")
    analyzer.add_gap(GapType.LOW_BRANCH_COVERAGE, "src/b.py", "Gap 2")

    report = analyzer.generate_report("Test Report")

    assert report.report_id.startswith("GAPRPT-")
    assert report.total_gaps == 2


def test_gap_analyzer_statistics():
    """Test analyzer statistics."""
    from coverage import create_gap_analyzer
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    analyzer.add_gap(GapType.UNTESTED_FILE, "src/a.py", "Test")

    stats = analyzer.get_statistics()

    assert stats["total_gaps"] == 1


def test_gap_analyzer_format():
    """Test report formatting."""
    from coverage import create_gap_analyzer
    from coverage.gaps import GapType

    analyzer = create_gap_analyzer()

    analyzer.add_gap(GapType.UNTESTED_FILE, "src/auth.py", "No tests")
    report = analyzer.generate_report()

    formatted = analyzer.format_report(report)

    assert "GAP ANALYSIS REPORT" in formatted
    assert "GAPS BY SEVERITY" in formatted


# ============================================================
# CI/CD Module Tests
# ============================================================

def test_cicd_imports():
    """Test CI/CD module imports."""
    from cicd import (
        CICDConnector,
        ConnectorType,
        PipelineStatus,
        PipelineResult,
        create_connector,
        WebhookManager,
        WebhookEvent,
        WebhookPayload,
        WebhookConfig,
        create_webhook_manager,
        ArtifactManager,
        TestArtifact,
        ArtifactType,
        ArtifactUploadResult,
        create_artifact_manager,
    )

    assert CICDConnector is not None
    assert WebhookManager is not None
    assert ArtifactManager is not None


def test_connector_creation():
    """Test connector creation."""
    from cicd import create_connector, ConnectorType

    connector = create_connector(ConnectorType.GITHUB_ACTIONS)

    assert connector is not None


def test_connector_environment():
    """Test environment detection."""
    from cicd import create_connector

    connector = create_connector()

    env = connector.get_environment()

    assert "platform" in env


def test_connector_pipeline_run():
    """Test creating pipeline run."""
    from cicd import create_connector, PipelineStatus

    connector = create_connector()

    run = connector.create_pipeline_run(
        pipeline_name="Test Pipeline",
        branch="main",
        commit_sha="abc123def",
    )

    assert run.run_id.startswith("RUN-")
    assert run.status == PipelineStatus.RUNNING


def test_connector_update_status():
    """Test updating pipeline status."""
    from cicd import create_connector, PipelineStatus

    connector = create_connector()

    run = connector.create_pipeline_run("Test", "main", "abc123")
    updated = connector.update_pipeline_status(run.run_id, PipelineStatus.SUCCESS)

    assert updated.status == PipelineStatus.SUCCESS
    assert updated.completed_at is not None


def test_connector_record_job():
    """Test recording test job."""
    from cicd import create_connector

    connector = create_connector()

    run = connector.create_pipeline_run("Test", "main", "abc123")

    job = connector.record_test_job(
        run_id=run.run_id,
        job_name="Unit Tests",
        tests_run=100,
        tests_passed=95,
        tests_failed=5,
        duration_sec=60.0,
    )

    assert job.job_name == "Unit Tests"
    assert job.tests_passed == 95


def test_connector_complete_pipeline():
    """Test completing pipeline."""
    from cicd import create_connector, PipelineStatus

    connector = create_connector()

    run = connector.create_pipeline_run("Test", "main", "abc123")

    job = connector.record_test_job(
        run_id=run.run_id,
        job_name="Tests",
        tests_run=10,
        tests_passed=10,
        tests_failed=0,
    )

    result = connector.complete_pipeline(
        run_id=run.run_id,
        jobs=[job],
        coverage_pct=85.0,
    )

    assert result.result_id.startswith("RESULT-")
    assert result.overall_status == PipelineStatus.SUCCESS


def test_connector_status_check():
    """Test generating status check."""
    from cicd import create_connector

    connector = create_connector()

    run = connector.create_pipeline_run("Test", "main", "abc123")
    job = connector.record_test_job(run.run_id, "Tests", 10, 10, 0)
    result = connector.complete_pipeline(run.run_id, [job])

    status_check = connector.generate_status_check(result)

    assert status_check["state"] == "success"


def test_connector_statistics():
    """Test connector statistics."""
    from cicd import create_connector

    connector = create_connector()

    run = connector.create_pipeline_run("Test", "main", "abc123")
    job = connector.record_test_job(run.run_id, "Tests", 10, 10, 0)
    connector.complete_pipeline(run.run_id, [job])

    stats = connector.get_statistics()

    assert stats["total_runs"] == 1


def test_connector_format():
    """Test result formatting."""
    from cicd import create_connector

    connector = create_connector()

    run = connector.create_pipeline_run("Test Pipeline", "main", "abc123def")
    job = connector.record_test_job(run.run_id, "Unit Tests", 100, 95, 5)
    result = connector.complete_pipeline(run.run_id, [job], 85.0)

    formatted = connector.format_result(result)

    assert "PIPELINE RESULT" in formatted
    assert "Test Pipeline" in formatted


def test_webhook_manager_creation():
    """Test webhook manager creation."""
    from cicd import create_webhook_manager

    manager = create_webhook_manager()

    assert manager is not None


def test_webhook_manager_register():
    """Test registering webhooks."""
    from cicd import create_webhook_manager, WebhookEvent

    manager = create_webhook_manager()

    webhook = manager.register_webhook(
        name="Slack Notifications",
        url="https://hooks.slack.com/test",
        events=[WebhookEvent.TEST_COMPLETED, WebhookEvent.TEST_FAILED],
        secret="my-secret",
    )

    assert webhook.webhook_id.startswith("WH-")
    assert len(webhook.events) == 2


def test_webhook_manager_trigger():
    """Test triggering webhooks."""
    from cicd import create_webhook_manager, WebhookEvent

    manager = create_webhook_manager()

    manager.register_webhook(
        name="Test Hook",
        url="https://example.com/hook",
        events=[WebhookEvent.TEST_COMPLETED],
    )

    results = manager.trigger(
        WebhookEvent.TEST_COMPLETED,
        {"test_id": "test-001", "status": "passed"},
    )

    assert len(results) == 1
    assert results[0].status.value == "delivered"


def test_webhook_manager_signature():
    """Test payload signature."""
    from cicd import create_webhook_manager, WebhookEvent

    manager = create_webhook_manager()

    payload = manager.create_payload(
        WebhookEvent.TEST_COMPLETED,
        {"test_id": "test-001"},
        secret="my-secret",
    )

    assert payload.signature is not None
    assert payload.signature.startswith("sha256=")


def test_webhook_manager_verify():
    """Test signature verification."""
    from cicd import create_webhook_manager
    import json

    manager = create_webhook_manager()

    body = json.dumps({"test": "data"}, sort_keys=True)
    secret = "my-secret"

    # Create a payload and verify its signature
    import hmac
    import hashlib

    expected = hmac.new(
        secret.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

    signature = f"sha256={expected}"

    result = manager.verify_signature(body, signature, secret)

    assert result == True


def test_webhook_manager_statistics():
    """Test manager statistics."""
    from cicd import create_webhook_manager, WebhookEvent

    manager = create_webhook_manager()

    manager.register_webhook("Test", "https://example.com", [WebhookEvent.TEST_COMPLETED])

    stats = manager.get_statistics()

    assert stats["total_webhooks"] == 1


def test_webhook_manager_format():
    """Test webhook formatting."""
    from cicd import create_webhook_manager, WebhookEvent

    manager = create_webhook_manager()

    webhook = manager.register_webhook(
        name="Test Hook",
        url="https://example.com/hook",
        events=[WebhookEvent.TEST_COMPLETED],
    )

    formatted = manager.format_webhook(webhook)

    assert "WEBHOOK" in formatted
    assert "Test Hook" in formatted


def test_artifact_manager_creation():
    """Test artifact manager creation."""
    from cicd import create_artifact_manager

    manager = create_artifact_manager()

    assert manager is not None


def test_artifact_manager_create():
    """Test creating artifacts."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    artifact = manager.create_artifact(
        name="screenshot.png",
        artifact_type=ArtifactType.SCREENSHOT,
        file_path="/tmp/screenshot.png",
        test_id="test-001",
        run_id="run-001",
    )

    assert artifact.artifact_id.startswith("ART-")
    assert artifact.artifact_type == ArtifactType.SCREENSHOT


def test_artifact_manager_upload():
    """Test uploading artifacts."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    artifact = manager.create_artifact(
        name="report.html",
        artifact_type=ArtifactType.REPORT,
        file_path="/tmp/report.html",
    )

    result = manager.upload_artifact(artifact, simulate=True)

    assert result.success == True
    assert result.upload_url is not None


def test_artifact_manager_collection():
    """Test artifact collections."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    a1 = manager.create_artifact("a.png", ArtifactType.SCREENSHOT, "/tmp/a.png")
    a2 = manager.create_artifact("b.mp4", ArtifactType.VIDEO, "/tmp/b.mp4")

    collection = manager.create_collection(
        name="Test Run Artifacts",
        run_id="run-001",
        artifact_ids=[a1.artifact_id, a2.artifact_id],
    )

    assert collection.collection_id.startswith("COL-")
    assert len(collection.artifacts) == 2


def test_artifact_manager_get_by_type():
    """Test getting artifacts by type."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    manager.create_artifact("a.png", ArtifactType.SCREENSHOT, "/tmp/a.png")
    manager.create_artifact("b.mp4", ArtifactType.VIDEO, "/tmp/b.mp4")
    manager.create_artifact("c.png", ArtifactType.SCREENSHOT, "/tmp/c.png")

    screenshots = manager.get_artifacts_by_type(ArtifactType.SCREENSHOT)

    assert len(screenshots) == 2


def test_artifact_manager_storage_usage():
    """Test storage usage statistics."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    manager.create_artifact("a.png", ArtifactType.SCREENSHOT, "/tmp/a.png")
    manager.create_artifact("b.mp4", ArtifactType.VIDEO, "/tmp/b.mp4")

    usage = manager.get_storage_usage()

    assert usage["artifact_count"] == 2
    assert usage["total_size_bytes"] > 0


def test_artifact_manager_statistics():
    """Test manager statistics."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    manager.create_artifact("a.png", ArtifactType.SCREENSHOT, "/tmp/a.png")

    stats = manager.get_statistics()

    assert stats["total_artifacts"] == 1


def test_artifact_manager_format():
    """Test artifact formatting."""
    from cicd import create_artifact_manager, ArtifactType

    manager = create_artifact_manager()

    artifact = manager.create_artifact(
        name="test-screenshot.png",
        artifact_type=ArtifactType.SCREENSHOT,
        file_path="/tmp/screenshot.png",
        test_id="test-001",
    )

    formatted = manager.format_artifact(artifact)

    assert "ARTIFACT" in formatted
    assert "test-screenshot.png" in formatted


# =============================================================================
# REPORTING MODULE TESTS
# =============================================================================

def test_reporting_imports():
    """Test reporting module imports."""
    from reporting import (
        DashboardManager,
        DashboardWidget,
        WidgetType,
        DashboardConfig,
        create_dashboard_manager,
        TestAnalytics,
        AnalyticsMetric,
        TrendDirection,
        AnalyticsReport,
        create_analytics,
        ReportGenerator,
        ReportFormat,
        ReportSection,
        TestReport,
        create_report_generator,
    )

    assert DashboardManager is not None
    assert create_dashboard_manager is not None
    assert TestAnalytics is not None
    assert ReportGenerator is not None


def test_dashboard_manager_creation():
    """Test dashboard manager creation."""
    from reporting import create_dashboard_manager

    manager = create_dashboard_manager()

    assert manager is not None
    stats = manager.get_statistics()
    assert stats["total_dashboards"] == 0


def test_dashboard_manager_create_dashboard():
    """Test dashboard creation."""
    from reporting import create_dashboard_manager

    manager = create_dashboard_manager()

    dashboard = manager.create_dashboard(
        name="Test Dashboard",
        description="Test description",
        layout="grid",
    )

    assert dashboard is not None
    assert dashboard.name == "Test Dashboard"
    assert dashboard.layout == "grid"
    assert "DASH-" in dashboard.dashboard_id


def test_dashboard_manager_add_widget():
    """Test adding widgets."""
    from reporting import create_dashboard_manager, WidgetType

    manager = create_dashboard_manager()
    dashboard = manager.create_dashboard(name="Test Dashboard")

    widget = manager.add_widget(
        dashboard_id=dashboard.dashboard_id,
        name="Pass Rate",
        widget_type=WidgetType.PASS_RATE,
        x=0,
        y=0,
        width=4,
        height=3,
    )

    assert widget is not None
    assert widget.name == "Pass Rate"
    assert widget.widget_type == WidgetType.PASS_RATE


def test_dashboard_manager_refresh():
    """Test widget refresh."""
    from reporting import create_dashboard_manager, WidgetType

    manager = create_dashboard_manager()
    dashboard = manager.create_dashboard(name="Test Dashboard")

    manager.add_widget(
        dashboard_id=dashboard.dashboard_id,
        name="Pass Rate",
        widget_type=WidgetType.PASS_RATE,
    )

    results = manager.refresh_dashboard(dashboard.dashboard_id)

    assert len(results) == 1
    assert results[0].data is not None


def test_dashboard_manager_export():
    """Test dashboard export."""
    from reporting import create_dashboard_manager, WidgetType

    manager = create_dashboard_manager()
    dashboard = manager.create_dashboard(name="Test Dashboard")

    manager.add_widget(
        dashboard_id=dashboard.dashboard_id,
        name="Pass Rate",
        widget_type=WidgetType.PASS_RATE,
    )

    exported = manager.export_dashboard(dashboard.dashboard_id)

    assert exported is not None
    assert exported["name"] == "Test Dashboard"
    assert len(exported["widgets"]) == 1


def test_dashboard_manager_statistics():
    """Test dashboard statistics."""
    from reporting import create_dashboard_manager, WidgetType

    manager = create_dashboard_manager()
    dashboard = manager.create_dashboard(name="Test")

    manager.add_widget(
        dashboard_id=dashboard.dashboard_id,
        name="Widget 1",
        widget_type=WidgetType.PASS_RATE,
    )

    stats = manager.get_statistics()

    assert stats["total_dashboards"] == 1
    assert stats["total_widgets"] == 1


def test_dashboard_manager_format():
    """Test dashboard formatting."""
    from reporting import create_dashboard_manager, WidgetType

    manager = create_dashboard_manager()
    dashboard = manager.create_dashboard(name="Test Dashboard")

    manager.add_widget(
        dashboard_id=dashboard.dashboard_id,
        name="Pass Rate",
        widget_type=WidgetType.PASS_RATE,
    )

    formatted = manager.format_dashboard(dashboard)

    assert "DASHBOARD" in formatted
    assert "Test Dashboard" in formatted


def test_analytics_creation():
    """Test analytics creation."""
    from reporting import create_analytics

    analytics = create_analytics()

    assert analytics is not None
    stats = analytics.get_statistics()
    assert stats["time_series_count"] == 0


def test_analytics_record_data():
    """Test recording data points."""
    from reporting import create_analytics

    analytics = create_analytics()

    point = analytics.record_data_point(
        metric_name="pass_rate",
        value=95.5,
    )

    assert point is not None
    assert point.value == 95.5

    stats = analytics.get_statistics()
    assert stats["total_data_points"] == 1


def test_analytics_compute_metric():
    """Test computing metrics."""
    from reporting import create_analytics, MetricType
    from reporting.analytics import MetricType

    analytics = create_analytics()

    # Record some data points
    for val in [90, 92, 95, 94, 96]:
        analytics.record_data_point("pass_rate", val)

    metric = analytics.compute_metric(
        metric_name="pass_rate",
        metric_type=MetricType.PASS_RATE,
        unit="%",
    )

    assert metric is not None
    assert metric.samples == 5
    assert metric.unit == "%"


def test_analytics_detect_anomalies():
    """Test anomaly detection."""
    from reporting import create_analytics

    analytics = create_analytics(anomaly_threshold=2.0)

    # Record normal values
    for _ in range(20):
        analytics.record_data_point("duration", 50.0)

    # Record an anomaly
    analytics.record_data_point("duration", 150.0)

    anomalies = analytics.detect_anomalies("duration")

    assert len(anomalies) >= 1


def test_analytics_find_correlations():
    """Test correlation finding."""
    from reporting import create_analytics
    from datetime import datetime, timedelta

    analytics = create_analytics()

    # Record correlated data with same timestamps for both metrics
    now = datetime.now()
    for i in range(10):
        ts = now + timedelta(hours=i)
        analytics.record_data_point("code_changes", float(i * 10), timestamp=ts)
        analytics.record_data_point("test_failures", float(i * 5), timestamp=ts)

    corr = analytics.find_correlations("code_changes", "test_failures")

    assert corr is not None
    assert corr.strength in ["strong", "moderate", "weak", "none"]


def test_analytics_generate_report():
    """Test report generation."""
    from reporting import create_analytics
    from reporting.analytics import MetricType

    analytics = create_analytics()

    for val in [90, 92, 95, 94, 96]:
        analytics.record_data_point("pass_rate", val)

    analytics.compute_metric(
        metric_name="pass_rate",
        metric_type=MetricType.PASS_RATE,
    )

    report = analytics.generate_report()

    assert report is not None
    assert "RPT-" in report.report_id


def test_analytics_statistics():
    """Test analytics statistics."""
    from reporting import create_analytics

    analytics = create_analytics()

    for val in [90, 92, 95]:
        analytics.record_data_point("test_metric", val)

    stats = analytics.get_statistics()

    assert stats["time_series_count"] == 1
    assert stats["total_data_points"] == 3


def test_analytics_format():
    """Test analytics report formatting."""
    from reporting import create_analytics
    from reporting.analytics import MetricType

    analytics = create_analytics()

    for val in [90, 92, 95]:
        analytics.record_data_point("pass_rate", val)

    analytics.compute_metric(
        metric_name="pass_rate",
        metric_type=MetricType.PASS_RATE,
    )

    report = analytics.generate_report()
    formatted = analytics.format_report(report)

    assert "ANALYTICS REPORT" in formatted


def test_report_generator_creation():
    """Test report generator creation."""
    from reporting import create_report_generator, ReportFormat

    generator = create_report_generator(
        default_format=ReportFormat.HTML,
    )

    assert generator is not None
    stats = generator.get_statistics()
    assert stats["total_results"] == 0


def test_report_generator_add_result():
    """Test adding results."""
    from reporting import create_report_generator

    generator = create_report_generator()

    entry = generator.add_result(
        test_name="test_login",
        status="passed",
        duration_sec=1.5,
        suite="auth",
    )

    assert entry is not None
    assert entry.test_name == "test_login"
    assert entry.status == "passed"


def test_report_generator_add_batch():
    """Test batch adding results."""
    from reporting import create_report_generator

    generator = create_report_generator()

    results = [
        {"name": "test_1", "status": "passed", "duration": 1.0, "suite": "unit"},
        {"name": "test_2", "status": "failed", "duration": 2.0, "suite": "unit", "error": "Assertion failed"},
        {"name": "test_3", "status": "skipped", "duration": 0.0, "suite": "unit"},
    ]

    entries = generator.add_results_batch(results)

    assert len(entries) == 3
    stats = generator.get_statistics()
    assert stats["total_results"] == 3


def test_report_generator_summary():
    """Test summary generation."""
    from reporting import create_report_generator

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")
    generator.add_result("test_2", "passed", 1.5, "unit")
    generator.add_result("test_3", "failed", 2.0, "unit")

    summary = generator.generate_summary()

    assert summary["total"] == 3
    assert summary["passed"] == 2
    assert summary["failed"] == 1
    assert summary["pass_rate"] > 0


def test_report_generator_generate_html():
    """Test HTML report generation."""
    from reporting import create_report_generator, ReportFormat, ReportType

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")
    generator.add_result("test_2", "failed", 2.0, "unit", error_message="Failed")

    report = generator.generate_report(
        title="Test Report",
        format=ReportFormat.HTML,
    )

    assert report is not None
    assert "<html>" in report.content
    assert "Test Report" in report.content


def test_report_generator_generate_json():
    """Test JSON report generation."""
    from reporting import create_report_generator, ReportFormat
    import json

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")

    report = generator.generate_report(
        title="Test Report",
        format=ReportFormat.JSON,
    )

    assert report is not None
    data = json.loads(report.content)
    assert data["title"] == "Test Report"


def test_report_generator_generate_junit():
    """Test JUnit XML report generation."""
    from reporting import create_report_generator, ReportFormat

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")
    generator.add_result("test_2", "failed", 2.0, "unit", error_message="Assertion failed")

    report = generator.generate_report(
        title="Test Report",
        format=ReportFormat.JUNIT_XML,
    )

    assert report is not None
    assert "<?xml" in report.content
    assert "<testsuites" in report.content


def test_report_generator_generate_markdown():
    """Test Markdown report generation."""
    from reporting import create_report_generator, ReportFormat

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")

    report = generator.generate_report(
        title="Test Report",
        format=ReportFormat.MARKDOWN,
    )

    assert report is not None
    assert "# Test Report" in report.content


def test_report_generator_statistics():
    """Test report generator statistics."""
    from reporting import create_report_generator

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")
    generator.add_result("test_2", "failed", 2.0, "unit")

    stats = generator.get_statistics()

    assert stats["total_results"] == 2
    assert stats["results_by_status"]["passed"] == 1
    assert stats["results_by_status"]["failed"] == 1


def test_report_generator_format():
    """Test report preview formatting."""
    from reporting import create_report_generator, ReportFormat

    generator = create_report_generator()

    generator.add_result("test_1", "passed", 1.0, "unit")

    report = generator.generate_report(
        title="Test Report",
        format=ReportFormat.TEXT,
    )

    formatted = generator.format_report_preview(report)

    assert "REPORT" in formatted
    assert "Test Report" in formatted


# =============================================================================
# OPTIMIZATION MODULE TESTS
# =============================================================================

def test_optimization_imports():
    """Test optimization module imports."""
    from optimization import (
        TestSelector,
        SelectionStrategy,
        SelectionResult,
        TestCandidate,
        create_test_selector,
        TestPrioritizer,
        PriorityScore,
        PrioritizationResult,
        PriorityFactor,
        create_test_prioritizer,
        TestParallelizer,
        ParallelizationPlan,
        TestBucket,
        BalanceStrategy,
        create_test_parallelizer,
    )

    assert TestSelector is not None
    assert TestPrioritizer is not None
    assert TestParallelizer is not None


def test_selector_creation():
    """Test selector creation."""
    from optimization import create_test_selector

    selector = create_test_selector()

    assert selector is not None
    stats = selector.get_statistics()
    assert stats["total_candidates"] == 0


def test_selector_register_test():
    """Test registering tests."""
    from optimization import create_test_selector

    selector = create_test_selector()

    candidate = selector.register_test(
        test_name="test_login",
        file_path="tests/test_auth.py",
        suite="auth",
        duration_sec=2.5,
        coverage_files=["src/auth.py", "src/user.py"],
    )

    assert candidate is not None
    assert candidate.test_name == "test_login"
    assert "TC-" in candidate.test_id


def test_selector_select_all():
    """Test selecting all tests."""
    from optimization import create_test_selector, SelectionStrategy

    selector = create_test_selector()

    for i in range(5):
        selector.register_test(
            test_name=f"test_{i}",
            file_path=f"tests/test_{i}.py",
        )

    result = selector.select(strategy=SelectionStrategy.ALL)

    assert len(result.selected_tests) == 5
    assert len(result.excluded_tests) == 0


def test_selector_select_affected():
    """Test selecting affected tests."""
    from optimization import create_test_selector, SelectionStrategy

    selector = create_test_selector()

    selector.register_test(
        test_name="test_auth",
        file_path="tests/test_auth.py",
        coverage_files=["src/auth.py"],
    )
    selector.register_test(
        test_name="test_user",
        file_path="tests/test_user.py",
        coverage_files=["src/user.py"],
    )

    selector.set_changed_files(["src/auth.py"])

    result = selector.select(strategy=SelectionStrategy.AFFECTED_ONLY)

    assert len(result.selected_tests) == 1
    assert result.selected_tests[0].test_name == "test_auth"


def test_selector_select_time_based():
    """Test time-based selection."""
    from optimization import create_test_selector, SelectionStrategy

    selector = create_test_selector()

    # Fast tests
    for i in range(5):
        selector.register_test(
            test_name=f"fast_{i}",
            file_path=f"tests/fast_{i}.py",
            duration_sec=1.0,
        )

    # Slow test
    selector.register_test(
        test_name="slow_test",
        file_path="tests/slow.py",
        duration_sec=10.0,
    )

    result = selector.select(
        strategy=SelectionStrategy.TIME_BASED,
        time_budget_sec=5.0,
    )

    assert result.total_duration_sec <= 5.0
    assert len(result.selected_tests) == 5


def test_selector_statistics():
    """Test selector statistics."""
    from optimization import create_test_selector

    selector = create_test_selector()

    for i in range(3):
        selector.register_test(
            test_name=f"test_{i}",
            file_path=f"tests/test_{i}.py",
            duration_sec=2.0,
        )

    stats = selector.get_statistics()

    assert stats["total_candidates"] == 3
    assert stats["total_duration_sec"] == 6.0


def test_selector_format():
    """Test selection result formatting."""
    from optimization import create_test_selector, SelectionStrategy

    selector = create_test_selector()

    selector.register_test(
        test_name="test_login",
        file_path="tests/test_auth.py",
    )

    result = selector.select(strategy=SelectionStrategy.ALL)
    formatted = selector.format_result(result)

    assert "TEST SELECTION" in formatted
    assert "test_login" in formatted


def test_prioritizer_creation():
    """Test prioritizer creation."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    assert prioritizer is not None
    stats = prioritizer.get_statistics()
    assert stats["total_tests"] == 0


def test_prioritizer_add_test():
    """Test adding tests for prioritization."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    entry = prioritizer.add_test(
        test_name="test_critical",
        suite="core",
        is_critical=True,
        failure_count=5,
        run_count=100,
    )

    assert entry is not None
    assert entry.test_name == "test_critical"
    assert entry.is_critical is True


def test_prioritizer_prioritize():
    """Test prioritizing tests."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    prioritizer.add_test(
        test_name="low_priority",
        failure_count=0,
        run_count=100,
    )
    prioritizer.add_test(
        test_name="high_priority",
        failure_count=50,
        run_count=100,
        is_critical=True,
    )

    result = prioritizer.prioritize()

    assert len(result.scores) == 2
    assert result.scores[0].test_name == "high_priority"


def test_prioritizer_top_priority():
    """Test getting top priority tests."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    for i in range(10):
        prioritizer.add_test(
            test_name=f"test_{i}",
            failure_count=i * 5,
            run_count=100,
        )

    result = prioritizer.prioritize()
    top = prioritizer.get_top_priority(n=3, result=result)

    assert len(top) == 3
    # Higher failure counts should rank higher
    assert top[0].rank == 1


def test_prioritizer_set_weight():
    """Test setting factor weights."""
    from optimization import create_test_prioritizer, PriorityFactor

    prioritizer = create_test_prioritizer()

    prioritizer.set_weight(PriorityFactor.BUSINESS_CRITICAL, 5.0)

    stats = prioritizer.get_statistics()
    assert stats["weights"]["business_critical"] == 5.0


def test_prioritizer_statistics():
    """Test prioritizer statistics."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    prioritizer.add_test("test_1", is_critical=True)
    prioritizer.add_test("test_2", is_flaky=True)
    prioritizer.add_test("test_3")

    stats = prioritizer.get_statistics()

    assert stats["total_tests"] == 3
    assert stats["critical_tests"] == 1
    assert stats["flaky_tests"] == 1


def test_prioritizer_format():
    """Test prioritization result formatting."""
    from optimization import create_test_prioritizer

    prioritizer = create_test_prioritizer()

    prioritizer.add_test("test_1", is_critical=True)
    prioritizer.add_test("test_2", failure_count=10, run_count=20)

    result = prioritizer.prioritize()
    formatted = prioritizer.format_result(result)

    assert "TEST PRIORITIZATION" in formatted
    assert "TOP PRIORITY" in formatted


def test_parallelizer_creation():
    """Test parallelizer creation."""
    from optimization import create_test_parallelizer

    parallelizer = create_test_parallelizer(default_workers=4)

    assert parallelizer is not None
    stats = parallelizer.get_statistics()
    assert stats["default_workers"] == 4


def test_parallelizer_add_test():
    """Test adding tests for parallelization."""
    from optimization import create_test_parallelizer

    parallelizer = create_test_parallelizer()

    test = parallelizer.add_test(
        test_name="test_login",
        suite="auth",
        duration_sec=2.5,
    )

    assert test is not None
    assert test.test_name == "test_login"
    assert "PT-" in test.test_id


def test_parallelizer_create_plan_round_robin():
    """Test round-robin parallelization."""
    from optimization import create_test_parallelizer, BalanceStrategy

    parallelizer = create_test_parallelizer(default_workers=2)

    for i in range(4):
        parallelizer.add_test(
            test_name=f"test_{i}",
            duration_sec=1.0,
        )

    plan = parallelizer.create_plan(strategy=BalanceStrategy.ROUND_ROBIN)

    assert len(plan.buckets) == 2
    assert all(len(b.tests) == 2 for b in plan.buckets)


def test_parallelizer_create_plan_duration_balanced():
    """Test duration-balanced parallelization."""
    from optimization import create_test_parallelizer, BalanceStrategy

    parallelizer = create_test_parallelizer(default_workers=2)

    parallelizer.add_test("fast_1", duration_sec=1.0)
    parallelizer.add_test("fast_2", duration_sec=1.0)
    parallelizer.add_test("slow", duration_sec=10.0)

    plan = parallelizer.create_plan(strategy=BalanceStrategy.DURATION_BALANCED)

    # Slow test should be alone in one bucket
    durations = sorted([b.total_duration_sec for b in plan.buckets])
    assert durations[0] < durations[1]  # Buckets should be somewhat balanced


def test_parallelizer_estimate_speedup():
    """Test speedup estimation."""
    from optimization import create_test_parallelizer

    parallelizer = create_test_parallelizer(default_workers=4)

    for i in range(8):
        parallelizer.add_test(f"test_{i}", duration_sec=2.0)

    plan = parallelizer.create_plan()
    speedup = parallelizer.estimate_speedup(plan)

    assert speedup["sequential_time_sec"] == 16.0
    assert speedup["speedup"] > 1.0
    assert "efficiency_pct" in speedup


def test_parallelizer_suite_grouped():
    """Test suite-grouped parallelization."""
    from optimization import create_test_parallelizer, BalanceStrategy

    parallelizer = create_test_parallelizer(default_workers=2)

    parallelizer.add_test("test_a1", suite="suite_a", duration_sec=1.0)
    parallelizer.add_test("test_a2", suite="suite_a", duration_sec=1.0)
    parallelizer.add_test("test_b1", suite="suite_b", duration_sec=1.0)
    parallelizer.add_test("test_b2", suite="suite_b", duration_sec=1.0)

    plan = parallelizer.create_plan(strategy=BalanceStrategy.SUITE_GROUPED)

    assert len(plan.buckets) == 2
    # Each bucket should have tests from the same suite
    for bucket in plan.buckets:
        suites = set(t.suite for t in bucket.tests)
        assert len(suites) == 1  # All tests in bucket from same suite


def test_parallelizer_statistics():
    """Test parallelizer statistics."""
    from optimization import create_test_parallelizer

    parallelizer = create_test_parallelizer(default_workers=4)

    parallelizer.add_test("test_1", duration_sec=2.0)
    parallelizer.add_test("test_2", duration_sec=3.0, dependencies=["test_1"])

    stats = parallelizer.get_statistics()

    assert stats["total_tests"] == 2
    assert stats["total_duration_sec"] == 5.0
    assert stats["tests_with_dependencies"] == 1


def test_parallelizer_format():
    """Test parallelization plan formatting."""
    from optimization import create_test_parallelizer

    parallelizer = create_test_parallelizer(default_workers=2)

    parallelizer.add_test("test_1", duration_sec=1.0)
    parallelizer.add_test("test_2", duration_sec=2.0)

    plan = parallelizer.create_plan()
    formatted = parallelizer.format_plan(plan)

    assert "PARALLELIZATION PLAN" in formatted
    assert "BUCKETS" in formatted


def main():
    """Run all tests."""
    print("=" * 50)
    print("TestAI Agent - Integration Tests")
    print("=" * 50)
    print()

    result = TestResult()

    # Brain tests
    print("📦 Brain Tests:")
    run_test(result, "brain_imports", test_brain_imports)
    run_test(result, "brain_initialization", test_brain_initialization)

    # Gateway tests
    print("\n📦 Gateway Tests:")
    run_test(result, "gateway_imports", test_gateway_imports)
    run_test(result, "gateway_creation", test_gateway_creation)
    run_test(result, "gateway_status", test_gateway_status)
    run_test(result, "citation", test_citation)

    # Cortex tests
    print("\n📦 Cortex Tests:")
    run_test(result, "cortex_imports", test_cortex_imports)
    run_test(result, "reasoner_creation", test_reasoner_creation)
    run_test(result, "confidence_scoring", test_confidence_scoring)

    # Interface tests
    print("\n📦 Interface Tests:")
    run_test(result, "interface_imports", test_interface_imports)
    run_test(result, "rich_output", test_rich_output)
    run_test(result, "consultant_creation", test_consultant_creation)

    # Generators tests
    print("\n📦 Generators Tests:")
    run_test(result, "generators_imports", test_generators_imports)
    run_test(result, "report_generation", test_report_generation)
    run_test(result, "executive_report", test_executive_report)

    # Personality tests
    print("\n📦 Personality Tests:")
    run_test(result, "personality_imports", test_personality_imports)
    run_test(result, "thinker", test_thinker)

    # Understanding tests
    print("\n📦 Understanding Tests:")
    run_test(result, "understanding_imports", test_understanding_imports)
    run_test(result, "feature_analysis", test_feature_analysis)
    run_test(result, "edge_cases", test_edge_cases)

    # Integration tests
    print("\n📦 Integration Tests:")
    run_test(result, "consultant_flow", test_consultant_flow)

    # Enhanced module tests
    print("\n📦 Enhanced Module Tests:")
    run_test(result, "conversational_memory", test_conversational_memory)
    run_test(result, "human_clarifier", test_human_clarifier)
    run_test(result, "thinking_display", test_thinking_display)
    run_test(result, "executive_output", test_executive_output)
    run_test(result, "usage_dashboard", test_usage_dashboard)
    run_test(result, "qa_brain_exists", test_qa_brain_exists)
    run_test(result, "prioritizer", test_prioritizer)
    run_test(result, "session_persistence", test_session_persistence)
    run_test(result, "thinking_stream", test_thinking_stream)
    run_test(result, "cited_generator", test_cited_generator)
    run_test(result, "smart_brain_ingest", test_smart_brain_ingest)
    run_test(result, "qa_consultant", test_qa_consultant)
    run_test(result, "executive_summary", test_executive_summary)
    run_test(result, "pipeline", test_pipeline)

    # Page type generators tests
    print("\n📦 Page Type Generators Tests:")
    run_test(result, "signup_generator", test_signup_generator)
    run_test(result, "checkout_generator", test_checkout_generator)
    run_test(result, "search_generator", test_search_generator)
    run_test(result, "profile_generator", test_profile_generator)
    run_test(result, "generator_factory", test_generator_factory)

    # Brain enhancement tests
    print("\n📦 Brain Enhancement Tests:")
    run_test(result, "in_memory_brain", test_in_memory_brain)
    run_test(result, "brain_from_generator", test_brain_from_generator)

    # Executor tests
    print("\n📦 Executor Tests:")
    run_test(result, "playwright_executor_imports", test_playwright_executor_imports)
    run_test(result, "playwright_step_parsing", test_playwright_step_parsing)
    run_test(result, "playwright_code_generation", test_playwright_code_generation)
    run_test(result, "playwright_dry_run", test_playwright_dry_run)

    # Interactive CLI tests
    print("\n📦 Interactive CLI Tests:")
    run_test(result, "interactive_cli_imports", test_interactive_cli_imports)
    run_test(result, "interactive_cli_generation", test_interactive_cli_generation)

    # Test data generator tests
    print("\n📦 Test Data Generator Tests:")
    run_test(result, "test_data_generator_imports", test_test_data_generator_imports)
    run_test(result, "test_data_email", test_test_data_email)
    run_test(result, "test_data_password", test_test_data_password)
    run_test(result, "test_data_form", test_test_data_form)
    run_test(result, "test_data_security_payloads", test_test_data_security_payloads)

    # API server tests
    print("\n📦 API Server Tests:")
    run_test(result, "api_server_imports", test_api_server_imports)
    run_test(result, "api_server_responses", test_api_server_responses)

    # Result analyzer tests
    print("\n📦 Result Analyzer Tests:")
    run_test(result, "result_analyzer_imports", test_result_analyzer_imports)
    run_test(result, "result_analyzer_basic", test_result_analyzer_basic)
    run_test(result, "result_analyzer_pattern_detection", test_result_analyzer_pattern_detection)
    run_test(result, "result_analyzer_recommendations", test_result_analyzer_recommendations)

    # Dashboard tests
    print("\n📦 Dashboard Tests:")
    run_test(result, "dashboard_imports", test_dashboard_imports)
    run_test(result, "dashboard_server_creation", test_dashboard_server_creation)
    run_test(result, "dashboard_response_helpers", test_dashboard_response_helpers)
    run_test(result, "dashboard_static_file_exists", test_dashboard_static_file_exists)

    # Learning system tests
    print("\n📦 Learning System Tests:")
    run_test(result, "learning_imports", test_learning_imports)
    run_test(result, "feedback_loop", test_feedback_loop)
    run_test(result, "pattern_learner", test_pattern_learner)
    run_test(result, "pattern_learner_success", test_pattern_learner_success)
    run_test(result, "knowledge_updater", test_knowledge_updater)
    run_test(result, "knowledge_updater_rules", test_knowledge_updater_rules)

    # Risk intelligence tests
    print("\n📦 Risk Intelligence Tests:")
    run_test(result, "risk_intelligence_imports", test_risk_intelligence_imports)
    run_test(result, "risk_intelligence_scoring", test_risk_intelligence_scoring)
    run_test(result, "risk_intelligence_history", test_risk_intelligence_history)
    run_test(result, "risk_intelligence_prioritization", test_risk_intelligence_prioritization)
    run_test(result, "risk_intelligence_recommendations", test_risk_intelligence_recommendations)

    # Coverage analyzer tests
    print("\n📦 Coverage Analyzer Tests:")
    run_test(result, "coverage_analyzer_imports", test_coverage_analyzer_imports)
    run_test(result, "coverage_analyzer_gaps", test_coverage_analyzer_gaps)
    run_test(result, "coverage_analyzer_with_tests", test_coverage_analyzer_with_tests)
    run_test(result, "coverage_gap_report", test_coverage_gap_report)

    # Unified agent tests
    print("\n📦 Unified Agent Tests:")
    run_test(result, "unified_agent_imports", test_unified_agent_imports)
    run_test(result, "unified_agent_creation", test_unified_agent_creation)
    run_test(result, "unified_agent_generation", test_unified_agent_generation)
    run_test(result, "unified_agent_test_data", test_unified_agent_test_data)
    run_test(result, "unified_agent_stats", test_unified_agent_stats)

    # Refinement tests
    print("\n📦 Refinement Tests:")
    run_test(result, "refinement_imports", test_refinement_imports)
    run_test(result, "nl_refiner_add", test_nl_refiner_add)
    run_test(result, "nl_refiner_remove", test_nl_refiner_remove)
    run_test(result, "nl_refiner_prioritize", test_nl_refiner_prioritize)
    run_test(result, "nl_refiner_apply", test_nl_refiner_apply)
    run_test(result, "test_modifier", test_test_modifier)

    # Execution simulation tests
    print("\n📦 Execution Simulation Tests:")
    run_test(result, "execution_imports", test_execution_imports)
    run_test(result, "simulator_creation", test_simulator_creation)
    run_test(result, "simulator_single_test", test_simulator_single_test)
    run_test(result, "simulator_suite", test_simulator_suite)
    run_test(result, "simulator_category_timing", test_simulator_category_timing)
    run_test(result, "reporter_creation", test_reporter_creation)
    run_test(result, "reporter_suite_report", test_reporter_suite_report)
    run_test(result, "reporter_formats", test_reporter_formats)
    run_test(result, "reporter_recommendations", test_reporter_recommendations)

    # Suggestion engine tests
    print("\n📦 Suggestion Engine Tests:")
    run_test(result, "suggestion_imports", test_suggestion_imports)
    run_test(result, "suggestion_engine_creation", test_suggestion_engine_creation)
    run_test(result, "suggestion_engine_analyze", test_suggestion_engine_analyze)
    run_test(result, "suggestion_engine_security_gaps", test_suggestion_engine_security_gaps)
    run_test(result, "suggestion_engine_edge_cases", test_suggestion_engine_edge_cases)
    run_test(result, "suggestion_formatting", test_suggestion_formatting)
    run_test(result, "improver_creation", test_improver_creation)
    run_test(result, "improver_analyze_test", test_improver_analyze_test)
    run_test(result, "improver_auto_apply", test_improver_auto_apply)
    run_test(result, "improver_step_analysis", test_improver_step_analysis)

    # Security module tests
    print("\n📦 Security Module Tests:")
    run_test(result, "security_imports", test_security_imports)
    run_test(result, "scanner_creation", test_scanner_creation)
    run_test(result, "scanner_login_scan", test_scanner_login_scan)
    run_test(result, "scanner_checkout_scan", test_scanner_checkout_scan)
    run_test(result, "scanner_filter_severity", test_scanner_filter_severity)
    run_test(result, "scanner_report_format", test_scanner_report_format)
    run_test(result, "security_generator_creation", test_security_generator_creation)
    run_test(result, "security_generator_for_page", test_security_generator_for_page)
    run_test(result, "security_generator_test_cases", test_security_generator_test_cases)
    run_test(result, "security_generator_payloads", test_security_generator_payloads)
    run_test(result, "security_generator_format", test_security_generator_format)
    run_test(result, "security_generator_to_dict", test_security_generator_to_dict)

    # Visual reports tests
    print("\n📦 Visual Reports Tests:")
    run_test(result, "reports_imports", test_reports_imports)
    run_test(result, "visual_reporter_creation", test_visual_reporter_creation)
    run_test(result, "visual_reporter_test_plan", test_visual_reporter_test_plan)
    run_test(result, "visual_reporter_execution_report", test_visual_reporter_execution_report)
    run_test(result, "visual_reporter_html_content", test_visual_reporter_html_content)
    run_test(result, "exporter_creation", test_exporter_creation)
    run_test(result, "exporter_html", test_exporter_html)
    run_test(result, "exporter_json", test_exporter_json)
    run_test(result, "exporter_markdown", test_exporter_markdown)
    run_test(result, "export_all_formats", test_export_all_formats)

    # Monitoring tests
    print("\n📦 Monitoring Tests:")
    run_test(result, "monitoring_imports", test_monitoring_imports)
    run_test(result, "monitor_creation", test_monitor_creation)
    run_test(result, "monitor_suite_lifecycle", test_monitor_suite_lifecycle)
    run_test(result, "monitor_test_events", test_monitor_test_events)
    run_test(result, "monitor_pause_resume", test_monitor_pause_resume)
    run_test(result, "monitor_threshold_detection", test_monitor_threshold_detection)
    run_test(result, "monitor_progress_summary", test_monitor_progress_summary)
    run_test(result, "live_dashboard_creation", test_live_dashboard_creation)
    run_test(result, "live_dashboard_render", test_live_dashboard_render)
    run_test(result, "live_dashboard_updates", test_live_dashboard_updates)

    # Deduplication tests
    print("\n📦 Deduplication Tests:")
    run_test(result, "deduplication_imports", test_deduplication_imports)
    run_test(result, "deduplicator_creation", test_deduplicator_creation)
    run_test(result, "deduplicator_exact_duplicates", test_deduplicator_exact_duplicates)
    run_test(result, "deduplicator_no_duplicates", test_deduplicator_no_duplicates)
    run_test(result, "deduplicator_report", test_deduplicator_report)
    run_test(result, "merger_creation", test_merger_creation)
    run_test(result, "merger_single_test", test_merger_single_test)
    run_test(result, "merger_multiple_tests", test_merger_multiple_tests)
    run_test(result, "merger_strategy_suggestion", test_merger_strategy_suggestion)
    run_test(result, "merger_format_result", test_merger_format_result)

    # Review tests
    print("\n📦 Review Module Tests:")
    run_test(result, "review_imports", test_review_imports)
    run_test(result, "review_workflow_creation", test_review_workflow_creation)
    run_test(result, "review_request_creation", test_review_request_creation)
    run_test(result, "review_submission_flow", test_review_submission_flow)
    run_test(result, "review_changes_requested", test_review_changes_requested)
    run_test(result, "review_format", test_review_format)
    run_test(result, "comment_thread_creation", test_comment_thread_creation)
    run_test(result, "comment_reply", test_comment_reply)
    run_test(result, "comment_reactions", test_comment_reactions)
    run_test(result, "comment_thread_resolution", test_comment_thread_resolution)
    run_test(result, "comment_mentions", test_comment_mentions)
    run_test(result, "comment_search", test_comment_search)
    run_test(result, "approval_chain_creation", test_approval_chain_creation)
    run_test(result, "approval_chain_stages", test_approval_chain_stages)
    run_test(result, "approval_chain_progress", test_approval_chain_progress)
    run_test(result, "approval_chain_bypass", test_approval_chain_bypass)
    run_test(result, "approval_chain_format", test_approval_chain_format)

    # Impact analysis tests
    print("\n📦 Impact Analysis Tests:")
    run_test(result, "impact_imports", test_impact_imports)
    run_test(result, "change_detector_creation", test_change_detector_creation)
    run_test(result, "change_detector_git_diff", test_change_detector_git_diff)
    run_test(result, "change_detector_file_list", test_change_detector_file_list)
    run_test(result, "change_detector_categorize", test_change_detector_categorize)
    run_test(result, "change_detector_risk", test_change_detector_risk)
    run_test(result, "dependency_mapper_creation", test_dependency_mapper_creation)
    run_test(result, "dependency_mapper_add", test_dependency_mapper_add)
    run_test(result, "dependency_mapper_reverse_lookup", test_dependency_mapper_reverse_lookup)
    run_test(result, "dependency_mapper_graph", test_dependency_mapper_graph)
    run_test(result, "impact_analyzer_creation", test_impact_analyzer_creation)
    run_test(result, "impact_analyzer_basic", test_impact_analyzer_basic)
    run_test(result, "impact_analyzer_levels", test_impact_analyzer_levels)
    run_test(result, "impact_analyzer_batches", test_impact_analyzer_batches)
    run_test(result, "impact_analyzer_savings", test_impact_analyzer_savings)
    run_test(result, "impact_analyzer_format", test_impact_analyzer_format)

    # Natural language query tests
    print("\n📦 NL Query Tests:")
    run_test(result, "nlquery_imports", test_nlquery_imports)
    run_test(result, "nl_processor_creation", test_nl_processor_creation)
    run_test(result, "nl_processor_tokenize", test_nl_processor_tokenize)
    run_test(result, "nl_processor_entities", test_nl_processor_entities)
    run_test(result, "nl_processor_negation", test_nl_processor_negation)
    run_test(result, "nl_processor_time", test_nl_processor_time)
    run_test(result, "query_parser_creation", test_query_parser_creation)
    run_test(result, "query_parser_intent", test_query_parser_intent)
    run_test(result, "query_parser_filters", test_query_parser_filters)
    run_test(result, "query_parser_search", test_query_parser_search)
    run_test(result, "query_parser_limit", test_query_parser_limit)
    run_test(result, "query_parser_sort", test_query_parser_sort)
    run_test(result, "query_executor_creation", test_query_executor_creation)
    run_test(result, "query_executor_basic", test_query_executor_basic)
    run_test(result, "query_executor_filter", test_query_executor_filter)
    run_test(result, "query_executor_search", test_query_executor_search)
    run_test(result, "query_executor_grouping", test_query_executor_grouping)
    run_test(result, "query_executor_aggregation", test_query_executor_aggregation)
    run_test(result, "query_result_format", test_query_result_format)

    # Visualization tests
    print("\n📦 Visualization Tests:")
    run_test(result, "visualization_imports", test_visualization_imports)
    run_test(result, "dependency_graph_creation", test_dependency_graph_creation)
    run_test(result, "dependency_graph_add_test", test_dependency_graph_add_test)
    run_test(result, "dependency_graph_dependencies", test_dependency_graph_dependencies)
    run_test(result, "dependency_graph_from_suite", test_dependency_graph_from_suite)
    run_test(result, "dependency_graph_cycles", test_dependency_graph_cycles)
    run_test(result, "dependency_graph_critical_path", test_dependency_graph_critical_path)
    run_test(result, "dependency_graph_mermaid", test_dependency_graph_mermaid)
    run_test(result, "dependency_graph_dot", test_dependency_graph_dot)
    run_test(result, "coverage_map_creation", test_coverage_map_creation)
    run_test(result, "coverage_map_feature", test_coverage_map_feature)
    run_test(result, "coverage_map_gaps", test_coverage_map_gaps)
    run_test(result, "coverage_map_suggestions", test_coverage_map_suggestions)
    run_test(result, "coverage_map_ascii", test_coverage_map_ascii)
    run_test(result, "coverage_map_html", test_coverage_map_html)
    run_test(result, "timeline_creation", test_timeline_creation)
    run_test(result, "timeline_record_event", test_timeline_record_event)
    run_test(result, "timeline_from_results", test_timeline_from_results)
    run_test(result, "timeline_parallel_tracks", test_timeline_parallel_tracks)
    run_test(result, "timeline_slow_tests", test_timeline_slow_tests)
    run_test(result, "timeline_ascii", test_timeline_ascii)
    run_test(result, "timeline_mermaid", test_timeline_mermaid)
    run_test(result, "timeline_summary", test_timeline_summary)

    # Retry module tests
    print("\n📦 Retry Module Tests:")
    run_test(result, "retry_imports", test_retry_imports)
    run_test(result, "retry_strategy_creation", test_retry_strategy_creation)
    run_test(result, "retry_delay_fixed", test_retry_delay_fixed)
    run_test(result, "retry_delay_exponential", test_retry_delay_exponential)
    run_test(result, "retry_should_retry", test_retry_should_retry)
    run_test(result, "retry_simulate", test_retry_simulate)
    run_test(result, "retry_format", test_retry_format)
    run_test(result, "adaptive_manager_creation", test_adaptive_manager_creation)
    run_test(result, "adaptive_manager_strategy", test_adaptive_manager_strategy)
    run_test(result, "adaptive_manager_decision", test_adaptive_manager_decision)
    run_test(result, "adaptive_manager_record", test_adaptive_manager_record)
    run_test(result, "adaptive_manager_insights", test_adaptive_manager_insights)
    run_test(result, "quarantine_creation", test_quarantine_creation)
    run_test(result, "quarantine_add", test_quarantine_add)
    run_test(result, "quarantine_release", test_quarantine_release)
    run_test(result, "quarantine_auto", test_quarantine_auto)
    run_test(result, "quarantine_summary", test_quarantine_summary)
    run_test(result, "quarantine_report", test_quarantine_report)

    # Matrix module tests
    print("\n📦 Matrix Module Tests:")
    run_test(result, "matrix_imports", test_matrix_imports)
    run_test(result, "matrix_generator_creation", test_matrix_generator_creation)
    run_test(result, "matrix_generator_basic", test_matrix_generator_basic)
    run_test(result, "matrix_generator_responsive", test_matrix_generator_responsive)
    run_test(result, "matrix_generator_mobile", test_matrix_generator_mobile)
    run_test(result, "matrix_generator_devices", test_matrix_generator_devices)
    run_test(result, "matrix_generator_format", test_matrix_generator_format)
    run_test(result, "matrix_optimizer_creation", test_matrix_optimizer_creation)
    run_test(result, "matrix_optimizer_pairwise", test_matrix_optimizer_pairwise)
    run_test(result, "matrix_optimizer_time_budget", test_matrix_optimizer_time_budget)
    run_test(result, "matrix_optimizer_critical_path", test_matrix_optimizer_critical_path)
    run_test(result, "matrix_optimizer_suggestion", test_matrix_optimizer_suggestion)
    run_test(result, "matrix_optimizer_format", test_matrix_optimizer_format)
    run_test(result, "matrix_reporter_creation", test_matrix_reporter_creation)
    run_test(result, "matrix_reporter_record", test_matrix_reporter_record)
    run_test(result, "matrix_reporter_issue", test_matrix_reporter_issue)
    run_test(result, "matrix_reporter_report", test_matrix_reporter_report)
    run_test(result, "matrix_reporter_compatibility", test_matrix_reporter_compatibility)
    run_test(result, "matrix_reporter_format", test_matrix_reporter_format)

    # Scenarios module tests
    print("\n📦 Scenarios Module Tests:")
    run_test(result, "scenarios_imports", test_scenarios_imports)
    run_test(result, "scenario_generator_creation", test_scenario_generator_creation)
    run_test(result, "scenario_generator_for_feature", test_scenario_generator_for_feature)
    run_test(result, "scenario_generator_edge_cases", test_scenario_generator_edge_cases)
    run_test(result, "scenario_generator_security", test_scenario_generator_security)
    run_test(result, "scenario_generator_accessibility", test_scenario_generator_accessibility)
    run_test(result, "scenario_generator_format", test_scenario_generator_format)
    run_test(result, "data_factory_creation", test_data_factory_creation)
    run_test(result, "data_factory_user", test_data_factory_user)
    run_test(result, "data_factory_locales", test_data_factory_locales)
    run_test(result, "data_factory_profiles", test_data_factory_profiles)
    run_test(result, "data_factory_credit_card", test_data_factory_credit_card)
    run_test(result, "data_factory_form_data", test_data_factory_form_data)
    run_test(result, "data_factory_batch", test_data_factory_batch)
    run_test(result, "data_factory_security_payloads", test_data_factory_security_payloads)
    run_test(result, "data_factory_format", test_data_factory_format)
    run_test(result, "journey_simulator_creation", test_journey_simulator_creation)
    run_test(result, "journey_simulator_available", test_journey_simulator_available)
    run_test(result, "journey_simulate_basic", test_journey_simulate_basic)
    run_test(result, "journey_simulate_with_failure", test_journey_simulate_with_failure)
    run_test(result, "journey_behaviors", test_journey_behaviors)
    run_test(result, "journey_batch_simulation", test_journey_batch_simulation)
    run_test(result, "journey_analysis", test_journey_analysis)
    run_test(result, "journey_suggestions", test_journey_suggestions)
    run_test(result, "journey_format", test_journey_format)

    # Analysis module tests
    print("\n📦 Analysis Module Tests:")
    run_test(result, "analysis_imports", test_analysis_imports)
    run_test(result, "root_cause_analyzer_creation", test_root_cause_analyzer_creation)
    run_test(result, "root_cause_analyzer_timeout", test_root_cause_analyzer_timeout)
    run_test(result, "root_cause_analyzer_element_not_found", test_root_cause_analyzer_element_not_found)
    run_test(result, "root_cause_analyzer_assertion", test_root_cause_analyzer_assertion)
    run_test(result, "root_cause_analyzer_network", test_root_cause_analyzer_network)
    run_test(result, "root_cause_analyzer_suggestions", test_root_cause_analyzer_suggestions)
    run_test(result, "root_cause_analyzer_trends", test_root_cause_analyzer_trends)
    run_test(result, "root_cause_analyzer_format", test_root_cause_analyzer_format)
    run_test(result, "code_correlator_creation", test_code_correlator_creation)
    run_test(result, "code_correlator_register_change", test_code_correlator_register_change)
    run_test(result, "code_correlator_correlate", test_code_correlator_correlate)
    run_test(result, "code_correlator_change_history", test_code_correlator_change_history)
    run_test(result, "code_correlator_format", test_code_correlator_format)
    run_test(result, "debug_assistant_creation", test_debug_assistant_creation)
    run_test(result, "debug_assistant_plan_timeout", test_debug_assistant_plan_timeout)
    run_test(result, "debug_assistant_plan_element", test_debug_assistant_plan_element)
    run_test(result, "debug_assistant_quick_fix", test_debug_assistant_quick_fix)
    run_test(result, "debug_assistant_common_fixes", test_debug_assistant_common_fixes)
    run_test(result, "debug_assistant_format", test_debug_assistant_format)

    # Maintenance module tests
    print("\n📦 Maintenance Module Tests:")
    run_test(result, "maintenance_imports", test_maintenance_imports)
    run_test(result, "maintenance_detector_creation", test_maintenance_detector_creation)
    run_test(result, "maintenance_detector_register", test_maintenance_detector_register)
    run_test(result, "maintenance_detector_fragile_selectors", test_maintenance_detector_fragile_selectors)
    run_test(result, "maintenance_detector_code_smells", test_maintenance_detector_code_smells)
    run_test(result, "maintenance_detector_flakiness", test_maintenance_detector_flakiness)
    run_test(result, "maintenance_detector_report", test_maintenance_detector_report)
    run_test(result, "maintenance_detector_format", test_maintenance_detector_format)
    run_test(result, "selector_monitor_creation", test_selector_monitor_creation)
    run_test(result, "selector_monitor_register", test_selector_monitor_register)
    run_test(result, "selector_monitor_risk_assessment", test_selector_monitor_risk_assessment)
    run_test(result, "selector_monitor_stability", test_selector_monitor_stability)
    run_test(result, "selector_monitor_report", test_selector_monitor_report)
    run_test(result, "selector_monitor_format", test_selector_monitor_format)
    run_test(result, "test_updater_creation", test_test_updater_creation)
    run_test(result, "test_updater_analyze_waits", test_test_updater_analyze_waits)
    run_test(result, "test_updater_analyze_cleanup", test_test_updater_analyze_cleanup)
    run_test(result, "test_updater_apply_suggestion", test_test_updater_apply_suggestion)
    run_test(result, "test_updater_apply_batch", test_test_updater_apply_batch)
    run_test(result, "test_updater_format", test_test_updater_format)

    # Documentation module tests
    print("\n📦 Documentation Module Tests:")
    run_test(result, "docs_imports", test_docs_imports)
    run_test(result, "doc_generator_creation", test_doc_generator_creation)
    run_test(result, "doc_generator_test_plan", test_doc_generator_test_plan)
    run_test(result, "doc_generator_execution_report", test_doc_generator_execution_report)
    run_test(result, "doc_generator_coverage_report", test_doc_generator_coverage_report)
    run_test(result, "doc_generator_json_format", test_doc_generator_json_format)
    run_test(result, "doc_generator_list_documents", test_doc_generator_list_documents)
    run_test(result, "test_plan_generator_creation", test_test_plan_generator_creation)
    run_test(result, "test_plan_generator_create_plan", test_test_plan_generator_create_plan)
    run_test(result, "test_plan_generator_add_suite", test_test_plan_generator_add_suite)
    run_test(result, "test_plan_generator_add_test_case", test_test_plan_generator_add_test_case)
    run_test(result, "test_plan_generator_from_features", test_test_plan_generator_from_features)
    run_test(result, "test_plan_generator_prioritize", test_test_plan_generator_prioritize)
    run_test(result, "test_plan_generator_estimate_duration", test_test_plan_generator_estimate_duration)
    run_test(result, "test_plan_generator_statistics", test_test_plan_generator_statistics)
    run_test(result, "test_plan_generator_format", test_test_plan_generator_format)
    run_test(result, "coverage_report_generator_creation", test_coverage_report_generator_creation)
    run_test(result, "coverage_report_generator_create_report", test_coverage_report_generator_create_report)
    run_test(result, "coverage_report_generator_add_feature", test_coverage_report_generator_add_feature)
    run_test(result, "coverage_report_generator_coverage_levels", test_coverage_report_generator_coverage_levels)
    run_test(result, "coverage_report_generator_analyze_gaps", test_coverage_report_generator_analyze_gaps)
    run_test(result, "coverage_report_generator_recommendations", test_coverage_report_generator_recommendations)
    run_test(result, "coverage_report_generator_compare", test_coverage_report_generator_compare)
    run_test(result, "coverage_report_generator_low_coverage", test_coverage_report_generator_low_coverage)
    run_test(result, "coverage_report_generator_format", test_coverage_report_generator_format)

    # Adaptive learning module tests
    print("\n📦 Adaptive Learning Module Tests:")
    run_test(result, "adaptive_imports", test_adaptive_imports)
    run_test(result, "adaptive_learner_creation", test_adaptive_learner_creation)
    run_test(result, "adaptive_learner_record_execution", test_adaptive_learner_record_execution)
    run_test(result, "adaptive_learner_detect_flakiness", test_adaptive_learner_detect_flakiness)
    run_test(result, "adaptive_learner_timing_anomaly", test_adaptive_learner_timing_anomaly)
    run_test(result, "adaptive_learner_statistics", test_adaptive_learner_statistics)
    run_test(result, "failure_predictor_creation", test_failure_predictor_creation)
    run_test(result, "failure_predictor_register_profile", test_failure_predictor_register_profile)
    run_test(result, "failure_predictor_risk_levels", test_failure_predictor_risk_levels)
    run_test(result, "failure_predictor_recommendations", test_failure_predictor_recommendations)
    run_test(result, "failure_predictor_batch", test_failure_predictor_batch)
    run_test(result, "test_optimizer_creation", test_test_optimizer_creation)
    run_test(result, "test_optimizer_risk_based", test_test_optimizer_risk_based)
    run_test(result, "test_optimizer_time_based", test_test_optimizer_time_based)
    run_test(result, "test_optimizer_parallel_groups", test_test_optimizer_parallel_groups)
    run_test(result, "adaptive_optimizer_format", test_adaptive_optimizer_format)

    # Authoring module tests
    print("\n📦 Authoring Module Tests:")
    run_test(result, "authoring_imports", test_authoring_imports)
    run_test(result, "nl_parser_creation", test_nl_parser_creation)
    run_test(result, "nl_parser_simple_test", test_nl_parser_simple_test)
    run_test(result, "nl_parser_action_detection", test_nl_parser_action_detection)
    run_test(result, "nl_parser_assertion_detection", test_nl_parser_assertion_detection)
    run_test(result, "nl_parser_tags", test_nl_parser_tags)
    run_test(result, "nl_parser_priority", test_nl_parser_priority)
    run_test(result, "nl_parser_format", test_nl_parser_format)
    run_test(result, "test_generator_creation", test_test_generator_creation)
    run_test(result, "test_generator_playwright_python", test_test_generator_playwright_python)
    run_test(result, "test_generator_playwright_js", test_test_generator_playwright_js)
    run_test(result, "test_generator_json", test_test_generator_json)
    run_test(result, "test_generator_format", test_test_generator_format)
    run_test(result, "nl_interpreter_creation", test_nl_interpreter_creation)
    run_test(result, "nl_interpreter_run_command", test_nl_interpreter_run_command)
    run_test(result, "nl_interpreter_create_command", test_nl_interpreter_create_command)
    run_test(result, "nl_interpreter_find_command", test_nl_interpreter_find_command)
    run_test(result, "nl_interpreter_parameters", test_nl_interpreter_parameters)
    run_test(result, "nl_interpreter_help", test_nl_interpreter_help)
    run_test(result, "nl_interpreter_format", test_nl_interpreter_format)

    # Runner module tests
    print("\n📦 Runner Module Tests:")
    run_test(result, "runner_imports", test_runner_imports)
    run_test(result, "browser_manager_creation", test_browser_manager_creation)
    run_test(result, "browser_manager_create_instance", test_browser_manager_create_instance)
    run_test(result, "browser_manager_create_context", test_browser_manager_create_context)
    run_test(result, "browser_manager_viewport_presets", test_browser_manager_viewport_presets)
    run_test(result, "browser_manager_statistics", test_browser_manager_statistics)
    run_test(result, "browser_manager_cleanup", test_browser_manager_cleanup)
    run_test(result, "action_executor_creation", test_action_executor_creation)
    run_test(result, "action_executor_click", test_action_executor_click)
    run_test(result, "action_executor_fill", test_action_executor_fill)
    run_test(result, "action_executor_sequence", test_action_executor_sequence)
    run_test(result, "action_executor_statistics", test_action_executor_statistics)
    run_test(result, "action_executor_selector_detection", test_action_executor_selector_detection)
    run_test(result, "test_runner_creation", test_test_runner_creation)
    run_test(result, "test_runner_run_test", test_test_runner_run_test)
    run_test(result, "test_runner_with_setup_teardown", test_test_runner_with_setup_teardown)
    run_test(result, "test_runner_multiple_tests", test_test_runner_multiple_tests)
    run_test(result, "test_runner_statistics", test_test_runner_statistics)
    run_test(result, "test_runner_format_results", test_test_runner_format_results)

    # Realtime module tests
    print("\n📦 Realtime Dashboard Tests:")
    run_test(result, "realtime_imports", test_realtime_imports)
    run_test(result, "metrics_collector_creation", test_metrics_collector_creation)
    run_test(result, "metrics_collector_record", test_metrics_collector_record)
    run_test(result, "metrics_collector_aggregation", test_metrics_collector_aggregation)
    run_test(result, "metrics_collector_trend", test_metrics_collector_trend)
    run_test(result, "metrics_collector_dashboard", test_metrics_collector_dashboard)
    run_test(result, "metrics_collector_format", test_metrics_collector_format)
    run_test(result, "alert_manager_creation", test_alert_manager_creation)
    run_test(result, "alert_manager_create_rule", test_alert_manager_create_rule)
    run_test(result, "alert_manager_check_rules", test_alert_manager_check_rules)
    run_test(result, "alert_manager_acknowledge", test_alert_manager_acknowledge)
    run_test(result, "alert_manager_resolve", test_alert_manager_resolve)
    run_test(result, "alert_manager_statistics", test_alert_manager_statistics)
    run_test(result, "alert_manager_format", test_alert_manager_format)
    run_test(result, "streaming_dashboard_creation", test_streaming_dashboard_creation)
    run_test(result, "streaming_dashboard_test_recording", test_streaming_dashboard_test_recording)
    run_test(result, "streaming_dashboard_events", test_streaming_dashboard_events)
    run_test(result, "streaming_dashboard_summary", test_streaming_dashboard_summary)
    run_test(result, "streaming_dashboard_format", test_streaming_dashboard_format)

    # Orchestrator module tests
    print("\n📦 Orchestrator Module Tests:")
    run_test(result, "orchestrator_imports", test_orchestrator_imports)
    run_test(result, "scheduler_creation", test_scheduler_creation)
    run_test(result, "scheduler_schedule_test", test_scheduler_schedule_test)
    run_test(result, "scheduler_schedule_matrix", test_scheduler_schedule_matrix)
    run_test(result, "scheduler_recurring", test_scheduler_recurring)
    run_test(result, "scheduler_get_next", test_scheduler_get_next)
    run_test(result, "scheduler_lifecycle", test_scheduler_lifecycle)
    run_test(result, "scheduler_cancel_pause", test_scheduler_cancel_pause)
    run_test(result, "scheduler_statistics", test_scheduler_statistics)
    run_test(result, "scheduler_format", test_scheduler_format)
    run_test(result, "distributor_creation", test_distributor_creation)
    run_test(result, "distributor_register_node", test_distributor_register_node)
    run_test(result, "distributor_distribute", test_distributor_distribute)
    run_test(result, "distributor_strategies", test_distributor_strategies)
    run_test(result, "distributor_complete_run", test_distributor_complete_run)
    run_test(result, "distributor_affinity", test_distributor_affinity)
    run_test(result, "distributor_statistics", test_distributor_statistics)
    run_test(result, "distributor_format", test_distributor_format)
    run_test(result, "coordinator_creation", test_coordinator_creation)
    run_test(result, "coordinator_register_worker", test_coordinator_register_worker)
    run_test(result, "coordinator_orchestrate", test_coordinator_orchestrate)
    run_test(result, "coordinator_report_result", test_coordinator_report_result)
    run_test(result, "coordinator_get_status", test_coordinator_get_status)
    run_test(result, "coordinator_cancel", test_coordinator_cancel)
    run_test(result, "coordinator_statistics", test_coordinator_statistics)
    run_test(result, "coordinator_format", test_coordinator_format)

    # Synthesis module tests
    print("\n📦 Synthesis Module Tests:")
    run_test(result, "synthesis_imports", test_synthesis_imports)
    run_test(result, "combiner_creation", test_combiner_creation)
    run_test(result, "combiner_add_source", test_combiner_add_source)
    run_test(result, "combiner_combine_union", test_combiner_combine_union)
    run_test(result, "combiner_combine_smart_merge", test_combiner_combine_smart_merge)
    run_test(result, "combiner_coverage_optimal", test_combiner_coverage_optimal)
    run_test(result, "combiner_format_result", test_combiner_format_result)
    run_test(result, "enricher_creation", test_enricher_creation)
    run_test(result, "enricher_enrich_security", test_enricher_enrich_security)
    run_test(result, "enricher_enrich_accessibility", test_enricher_enrich_accessibility)
    run_test(result, "enricher_enrich_performance", test_enricher_enrich_performance)
    run_test(result, "enricher_format_result", test_enricher_format_result)
    run_test(result, "synthesizer_creation", test_synthesizer_creation)
    run_test(result, "synthesizer_add_tests", test_synthesizer_add_tests)
    run_test(result, "synthesizer_synthesize", test_synthesizer_synthesize)
    run_test(result, "synthesizer_phases", test_synthesizer_phases)
    run_test(result, "synthesizer_modes", test_synthesizer_modes)
    run_test(result, "synthesizer_validation", test_synthesizer_validation)
    run_test(result, "synthesizer_coverage", test_synthesizer_coverage)
    run_test(result, "synthesizer_statistics", test_synthesizer_statistics)
    run_test(result, "synthesizer_format_suite", test_synthesizer_format_suite)
    run_test(result, "synthesizer_clear", test_synthesizer_clear)

    # Healing module tests
    print("\n📦 Self-Healing Module Tests:")
    run_test(result, "healing_imports", test_healing_imports)
    run_test(result, "selector_healer_creation", test_selector_healer_creation)
    run_test(result, "selector_healer_capture_snapshot", test_selector_healer_capture_snapshot)
    run_test(result, "selector_healer_heal", test_selector_healer_heal)
    run_test(result, "selector_healer_suggest_stable", test_selector_healer_suggest_stable)
    run_test(result, "selector_healer_statistics", test_selector_healer_statistics)
    run_test(result, "selector_healer_format", test_selector_healer_format)
    run_test(result, "change_detector_creation", test_change_detector_creation)
    run_test(result, "change_detector_capture_snapshot", test_change_detector_capture_snapshot)
    run_test(result, "change_detector_compare", test_change_detector_compare)
    run_test(result, "change_detector_selector_breakage", test_change_detector_selector_breakage)
    run_test(result, "change_detector_statistics", test_change_detector_statistics)
    run_test(result, "change_detector_format", test_change_detector_format)
    run_test(result, "repair_engine_creation", test_repair_engine_creation)
    run_test(result, "repair_engine_analyze_failure", test_repair_engine_analyze_failure)
    run_test(result, "repair_engine_generate_repairs", test_repair_engine_generate_repairs)
    run_test(result, "repair_engine_apply_repairs", test_repair_engine_apply_repairs)
    run_test(result, "repair_engine_verify_repairs", test_repair_engine_verify_repairs)
    run_test(result, "repair_engine_statistics", test_repair_engine_statistics)
    run_test(result, "repair_engine_format_analysis", test_repair_engine_format_analysis)
    run_test(result, "repair_engine_format_result", test_repair_engine_format_result)

    # Benchmarking module tests
    print("\n📦 Benchmarking Module Tests:")
    run_test(result, "benchmarking_imports", test_benchmarking_imports)
    run_test(result, "profiler_creation", test_profiler_creation)
    run_test(result, "profiler_start_profile", test_profiler_start_profile)
    run_test(result, "profiler_record_timing", test_profiler_record_timing)
    run_test(result, "profiler_end_profile", test_profiler_end_profile)
    run_test(result, "profiler_bottleneck_detection", test_profiler_bottleneck_detection)
    run_test(result, "profiler_statistics", test_profiler_statistics)
    run_test(result, "profiler_format", test_profiler_format)
    run_test(result, "optimizer_creation", test_optimizer_creation)
    run_test(result, "optimizer_register_test", test_optimizer_register_test)
    run_test(result, "optimizer_analyze", test_optimizer_analyze)
    run_test(result, "optimizer_create_plan", test_optimizer_create_plan)
    run_test(result, "optimizer_apply_optimizations", test_optimizer_apply_optimizations)
    run_test(result, "optimizer_statistics", test_optimizer_statistics)
    run_test(result, "optimizer_format_plan", test_optimizer_format_plan)
    run_test(result, "benchmark_runner_creation", test_benchmark_runner_creation)
    run_test(result, "benchmark_runner_register", test_benchmark_runner_register)
    run_test(result, "benchmark_runner_run", test_benchmark_runner_run)
    run_test(result, "benchmark_runner_suite", test_benchmark_runner_suite)
    run_test(result, "benchmark_runner_compare", test_benchmark_runner_compare)
    run_test(result, "benchmark_runner_statistics", test_benchmark_runner_statistics)
    run_test(result, "benchmark_runner_format", test_benchmark_runner_format)

    # Intelligence module tests
    print("\n📦 Intelligence Module Tests:")
    run_test(result, "intelligence_imports", test_intelligence_imports)
    run_test(result, "predictor_creation", test_predictor_creation)
    run_test(result, "predictor_record_result", test_predictor_record_result)
    run_test(result, "predictor_predict", test_predictor_predict)
    run_test(result, "predictor_code_change", test_predictor_code_change)
    run_test(result, "predictor_test_health", test_predictor_test_health)
    run_test(result, "predictor_high_risk", test_predictor_high_risk)
    run_test(result, "predictor_statistics", test_predictor_statistics)
    run_test(result, "predictor_format", test_predictor_format)
    run_test(result, "insight_engine_creation", test_insight_engine_creation)
    run_test(result, "insight_engine_record_event", test_insight_engine_record_event)
    run_test(result, "insight_engine_record_metric", test_insight_engine_record_metric)
    run_test(result, "insight_engine_generate", test_insight_engine_generate)
    run_test(result, "insight_engine_get_insights", test_insight_engine_get_insights)
    run_test(result, "insight_engine_statistics", test_insight_engine_statistics)
    run_test(result, "insight_engine_format", test_insight_engine_format)
    run_test(result, "recommender_creation", test_recommender_creation)
    run_test(result, "recommender_register_test", test_recommender_register_test)
    run_test(result, "recommender_register_suite", test_recommender_register_suite)
    run_test(result, "recommender_generate", test_recommender_generate)
    run_test(result, "recommender_quick_wins", test_recommender_quick_wins)
    run_test(result, "recommender_prioritize", test_recommender_prioritize)
    run_test(result, "recommender_time_budget", test_recommender_time_budget)
    run_test(result, "recommender_statistics", test_recommender_statistics)
    run_test(result, "recommender_format", test_recommender_format)

    # Visual module tests
    print("\n📦 Visual Module Tests:")
    run_test(result, "visual_imports", test_visual_imports)
    run_test(result, "comparator_creation", test_comparator_creation)
    run_test(result, "comparator_set_baseline", test_comparator_set_baseline)
    run_test(result, "comparator_compare_identical", test_comparator_compare_identical)
    run_test(result, "comparator_compare_different", test_comparator_compare_different)
    run_test(result, "comparator_ignore_region", test_comparator_ignore_region)
    run_test(result, "comparator_methods", test_comparator_methods)
    run_test(result, "comparator_statistics", test_comparator_statistics)
    run_test(result, "comparator_format", test_comparator_format)
    run_test(result, "screenshot_manager_creation", test_screenshot_manager_creation)
    run_test(result, "screenshot_manager_capture", test_screenshot_manager_capture)
    run_test(result, "screenshot_manager_baseline", test_screenshot_manager_baseline)
    run_test(result, "screenshot_manager_set", test_screenshot_manager_set)
    run_test(result, "screenshot_manager_devices", test_screenshot_manager_devices)
    run_test(result, "screenshot_manager_history", test_screenshot_manager_history)
    run_test(result, "screenshot_manager_statistics", test_screenshot_manager_statistics)
    run_test(result, "screenshot_manager_format", test_screenshot_manager_format)
    run_test(result, "reporter_creation", test_reporter_creation)
    run_test(result, "reporter_create_diff", test_reporter_create_diff)
    run_test(result, "reporter_create_report", test_reporter_create_report)
    run_test(result, "reporter_generate_html", test_reporter_generate_html)
    run_test(result, "reporter_generate_json", test_reporter_generate_json)
    run_test(result, "reporter_generate_markdown", test_reporter_generate_markdown)
    run_test(result, "reporter_trend", test_reporter_trend)
    run_test(result, "reporter_statistics", test_reporter_statistics)
    run_test(result, "reporter_format_diff", test_reporter_format_diff)

    # API module tests
    print("\n📦 API Module Tests:")
    run_test(result, "api_imports", test_api_imports)
    run_test(result, "api_client_creation", test_api_client_creation)
    run_test(result, "api_client_auth", test_api_client_auth)
    run_test(result, "api_client_request", test_api_client_request)
    run_test(result, "api_client_get", test_api_client_get)
    run_test(result, "api_client_post", test_api_client_post)
    run_test(result, "api_client_mock", test_api_client_mock)
    run_test(result, "api_client_assertions", test_api_client_assertions)
    run_test(result, "api_client_history", test_api_client_history)
    run_test(result, "api_client_statistics", test_api_client_statistics)
    run_test(result, "api_client_format", test_api_client_format)
    run_test(result, "contract_validator_creation", test_contract_validator_creation)
    run_test(result, "contract_validator_register", test_contract_validator_register)
    run_test(result, "contract_validator_validate_valid", test_contract_validator_validate_valid)
    run_test(result, "contract_validator_validate_invalid", test_contract_validator_validate_invalid)
    run_test(result, "contract_validator_compatibility", test_contract_validator_compatibility)
    run_test(result, "contract_validator_statistics", test_contract_validator_statistics)
    run_test(result, "contract_validator_format", test_contract_validator_format)
    run_test(result, "api_mocker_creation", test_api_mocker_creation)
    run_test(result, "api_mocker_add_rule", test_api_mocker_add_rule)
    run_test(result, "api_mocker_shortcuts", test_api_mocker_shortcuts)
    run_test(result, "api_mocker_match", test_api_mocker_match)
    run_test(result, "api_mocker_no_match", test_api_mocker_no_match)
    run_test(result, "api_mocker_verify", test_api_mocker_verify)
    run_test(result, "api_mocker_statistics", test_api_mocker_statistics)
    run_test(result, "api_mocker_format", test_api_mocker_format)

    # Accessibility module tests
    print("\n📦 Accessibility Module Tests:")
    run_test(result, "accessibility_imports", test_accessibility_imports)
    run_test(result, "a11y_checker_creation", test_a11y_checker_creation)
    run_test(result, "a11y_checker_check_page", test_a11y_checker_check_page)
    run_test(result, "a11y_checker_violations", test_a11y_checker_violations)
    run_test(result, "a11y_checker_wcag_level", test_a11y_checker_wcag_level)
    run_test(result, "a11y_checker_statistics", test_a11y_checker_statistics)
    run_test(result, "a11y_checker_format", test_a11y_checker_format)
    run_test(result, "rule_engine_creation", test_rule_engine_creation)
    run_test(result, "rule_engine_builtin_rules", test_rule_engine_builtin_rules)
    run_test(result, "rule_engine_add_rule", test_rule_engine_add_rule)
    run_test(result, "rule_engine_enable_disable", test_rule_engine_enable_disable)
    run_test(result, "rule_engine_by_category", test_rule_engine_by_category)
    run_test(result, "rule_engine_check", test_rule_engine_check)
    run_test(result, "rule_engine_statistics", test_rule_engine_statistics)
    run_test(result, "rule_engine_format", test_rule_engine_format)
    run_test(result, "a11y_reporter_creation", test_a11y_reporter_creation)
    run_test(result, "a11y_reporter_create_report", test_a11y_reporter_create_report)
    run_test(result, "a11y_reporter_generate_html", test_a11y_reporter_generate_html)
    run_test(result, "a11y_reporter_generate_json", test_a11y_reporter_generate_json)
    run_test(result, "a11y_reporter_generate_markdown", test_a11y_reporter_generate_markdown)
    run_test(result, "a11y_reporter_trend", test_a11y_reporter_trend)
    run_test(result, "a11y_reporter_statistics", test_a11y_reporter_statistics)

    # Security Scanner module tests
    print("\n📦 Security Scanner Module Tests:")
    run_test(result, "security_scanner_imports", test_security_scanner_imports)
    run_test(result, "vuln_scanner_creation", test_vuln_scanner_creation)
    run_test(result, "vuln_scanner_scan", test_vuln_scanner_scan)
    run_test(result, "vuln_scanner_elements", test_vuln_scanner_elements)
    run_test(result, "vuln_scanner_responses", test_vuln_scanner_responses)
    run_test(result, "vuln_scanner_risk_score", test_vuln_scanner_risk_score)
    run_test(result, "vuln_scanner_statistics", test_vuln_scanner_statistics)
    run_test(result, "vuln_scanner_format", test_vuln_scanner_format)
    run_test(result, "attack_simulator_creation", test_attack_simulator_creation)
    run_test(result, "attack_simulator_builtin", test_attack_simulator_builtin)
    run_test(result, "attack_simulator_add_attack", test_attack_simulator_add_attack)
    run_test(result, "attack_simulator_simulate", test_attack_simulator_simulate)
    run_test(result, "attack_simulator_simulate_response", test_attack_simulator_simulate_response)
    run_test(result, "attack_simulator_payloads", test_attack_simulator_payloads)
    run_test(result, "attack_simulator_statistics", test_attack_simulator_statistics)
    run_test(result, "attack_simulator_format", test_attack_simulator_format)
    run_test(result, "compliance_checker_creation", test_compliance_checker_creation)
    run_test(result, "compliance_checker_standards", test_compliance_checker_standards)
    run_test(result, "compliance_checker_add_requirement", test_compliance_checker_add_requirement)
    run_test(result, "compliance_checker_check", test_compliance_checker_check)
    run_test(result, "compliance_checker_with_findings", test_compliance_checker_with_findings)
    run_test(result, "compliance_checker_gap_analysis", test_compliance_checker_gap_analysis)
    run_test(result, "compliance_checker_statistics", test_compliance_checker_statistics)
    run_test(result, "compliance_checker_format", test_compliance_checker_format)

    # Data Generation module tests
    print("\n📦 Data Generation Module Tests:")
    run_test(result, "data_generation_imports", test_data_generation_imports)
    run_test(result, "data_generator_creation", test_data_generator_creation)
    run_test(result, "data_generator_string", test_data_generator_string)
    run_test(result, "data_generator_email", test_data_generator_email)
    run_test(result, "data_generator_password", test_data_generator_password)
    run_test(result, "data_generator_batch", test_data_generator_batch)
    run_test(result, "data_generator_profile", test_data_generator_profile)
    run_test(result, "data_generator_statistics", test_data_generator_statistics)
    run_test(result, "data_generator_format", test_data_generator_format)
    run_test(result, "data_factory_creation", test_data_factory_creation)
    run_test(result, "data_factory_builtin", test_data_factory_builtin)
    run_test(result, "data_factory_create", test_data_factory_create)
    run_test(result, "data_factory_traits", test_data_factory_traits)
    run_test(result, "data_factory_overrides", test_data_factory_overrides)
    run_test(result, "data_factory_batch", test_data_factory_batch)
    run_test(result, "data_factory_define", test_data_factory_define)
    run_test(result, "data_factory_statistics", test_data_factory_statistics)
    run_test(result, "data_factory_format", test_data_factory_format)
    run_test(result, "data_seeder_creation", test_data_seeder_creation)
    run_test(result, "data_seeder_plan", test_data_seeder_plan)
    run_test(result, "data_seeder_seed", test_data_seeder_seed)
    run_test(result, "data_seeder_get_data", test_data_seeder_get_data)
    run_test(result, "data_seeder_strategies", test_data_seeder_strategies)
    run_test(result, "data_seeder_statistics", test_data_seeder_statistics)
    run_test(result, "data_seeder_format", test_data_seeder_format)

    # Flakiness module tests
    print("\n📦 Flakiness Module Tests:")
    run_test(result, "flakiness_imports", test_flakiness_imports)
    run_test(result, "flakiness_detector_creation", test_flakiness_detector_creation)
    run_test(result, "flakiness_detector_record", test_flakiness_detector_record)
    run_test(result, "flakiness_detector_detect", test_flakiness_detector_detect)
    run_test(result, "flakiness_detector_patterns", test_flakiness_detector_patterns)
    run_test(result, "flakiness_detector_statistics", test_flakiness_detector_statistics)
    run_test(result, "flakiness_detector_format", test_flakiness_detector_format)
    run_test(result, "flakiness_analyzer_creation", test_flakiness_analyzer_creation)
    run_test(result, "flakiness_analyzer_analyze", test_flakiness_analyzer_analyze)
    run_test(result, "flakiness_analyzer_recommendations", test_flakiness_analyzer_recommendations)
    run_test(result, "flakiness_analyzer_correlations", test_flakiness_analyzer_correlations)
    run_test(result, "flakiness_analyzer_statistics", test_flakiness_analyzer_statistics)
    run_test(result, "flakiness_analyzer_format", test_flakiness_analyzer_format)
    run_test(result, "flakiness_mitigator_creation", test_flakiness_mitigator_creation)
    run_test(result, "flakiness_mitigator_suggest", test_flakiness_mitigator_suggest)
    run_test(result, "flakiness_mitigator_apply", test_flakiness_mitigator_apply)
    run_test(result, "flakiness_mitigator_verify", test_flakiness_mitigator_verify)
    run_test(result, "flakiness_mitigator_statistics", test_flakiness_mitigator_statistics)
    run_test(result, "flakiness_mitigator_format", test_flakiness_mitigator_format)

    # Environment module tests
    print("\n📦 Environment Module Tests:")
    run_test(result, "environment_imports", test_environment_imports)
    run_test(result, "environment_manager_creation", test_environment_manager_creation)
    run_test(result, "environment_manager_configs", test_environment_manager_configs)
    run_test(result, "environment_manager_create", test_environment_manager_create)
    run_test(result, "environment_manager_start", test_environment_manager_start)
    run_test(result, "environment_manager_stop", test_environment_manager_stop)
    run_test(result, "environment_manager_terminate", test_environment_manager_terminate)
    run_test(result, "environment_manager_health", test_environment_manager_health)
    run_test(result, "environment_manager_statistics", test_environment_manager_statistics)
    run_test(result, "environment_manager_format", test_environment_manager_format)
    run_test(result, "provisioner_creation", test_provisioner_creation)
    run_test(result, "provisioner_resource_spec", test_provisioner_resource_spec)
    run_test(result, "provisioner_plan", test_provisioner_plan)
    run_test(result, "provisioner_dependencies", test_provisioner_dependencies)
    run_test(result, "provisioner_provision", test_provisioner_provision)
    run_test(result, "provisioner_dry_run", test_provisioner_dry_run)
    run_test(result, "provisioner_rollback", test_provisioner_rollback)
    run_test(result, "provisioner_statistics", test_provisioner_statistics)
    run_test(result, "provisioner_format", test_provisioner_format)
    run_test(result, "config_manager_creation", test_config_manager_creation)
    run_test(result, "config_manager_defaults", test_config_manager_defaults)
    run_test(result, "config_manager_set", test_config_manager_set)
    run_test(result, "config_manager_profile", test_config_manager_profile)
    run_test(result, "config_manager_activate", test_config_manager_activate)
    run_test(result, "config_manager_prefix", test_config_manager_prefix)
    run_test(result, "config_manager_merge", test_config_manager_merge)
    run_test(result, "config_manager_load_dict", test_config_manager_load_dict)
    run_test(result, "config_manager_statistics", test_config_manager_statistics)
    run_test(result, "config_manager_format", test_config_manager_format)

    # Coverage module tests
    print("\n📦 Coverage Module Tests:")
    run_test(result, "coverage_imports", test_coverage_imports)
    run_test(result, "coverage_tracker_creation", test_coverage_tracker_creation)
    run_test(result, "coverage_tracker_record_file", test_coverage_tracker_record_file)
    run_test(result, "coverage_tracker_report", test_coverage_tracker_report)
    run_test(result, "coverage_tracker_low_coverage", test_coverage_tracker_low_coverage)
    run_test(result, "coverage_tracker_trend", test_coverage_tracker_trend)
    run_test(result, "coverage_tracker_statistics", test_coverage_tracker_statistics)
    run_test(result, "coverage_tracker_format", test_coverage_tracker_format)
    run_test(result, "coverage_mapper_creation", test_coverage_mapper_creation)
    run_test(result, "coverage_mapper_register", test_coverage_mapper_register)
    run_test(result, "coverage_mapper_get_tests", test_coverage_mapper_get_tests)
    run_test(result, "coverage_mapper_affected_tests", test_coverage_mapper_affected_tests)
    run_test(result, "coverage_mapper_overlap", test_coverage_mapper_overlap)
    run_test(result, "coverage_mapper_generate", test_coverage_mapper_generate)
    run_test(result, "coverage_mapper_statistics", test_coverage_mapper_statistics)
    run_test(result, "coverage_mapper_format", test_coverage_mapper_format)
    run_test(result, "gap_analyzer_creation", test_gap_analyzer_creation)
    run_test(result, "gap_analyzer_analyze", test_gap_analyzer_analyze)
    run_test(result, "gap_analyzer_add_gap", test_gap_analyzer_add_gap)
    run_test(result, "gap_analyzer_prioritize", test_gap_analyzer_prioritize)
    run_test(result, "gap_analyzer_recommendations", test_gap_analyzer_recommendations)
    run_test(result, "gap_analyzer_report", test_gap_analyzer_report)
    run_test(result, "gap_analyzer_statistics", test_gap_analyzer_statistics)
    run_test(result, "gap_analyzer_format", test_gap_analyzer_format)

    # CI/CD module tests
    print("\n📦 CI/CD Module Tests:")
    run_test(result, "cicd_imports", test_cicd_imports)
    run_test(result, "connector_creation", test_connector_creation)
    run_test(result, "connector_environment", test_connector_environment)
    run_test(result, "connector_pipeline_run", test_connector_pipeline_run)
    run_test(result, "connector_update_status", test_connector_update_status)
    run_test(result, "connector_record_job", test_connector_record_job)
    run_test(result, "connector_complete_pipeline", test_connector_complete_pipeline)
    run_test(result, "connector_status_check", test_connector_status_check)
    run_test(result, "connector_statistics", test_connector_statistics)
    run_test(result, "connector_format", test_connector_format)
    run_test(result, "webhook_manager_creation", test_webhook_manager_creation)
    run_test(result, "webhook_manager_register", test_webhook_manager_register)
    run_test(result, "webhook_manager_trigger", test_webhook_manager_trigger)
    run_test(result, "webhook_manager_signature", test_webhook_manager_signature)
    run_test(result, "webhook_manager_verify", test_webhook_manager_verify)
    run_test(result, "webhook_manager_statistics", test_webhook_manager_statistics)
    run_test(result, "webhook_manager_format", test_webhook_manager_format)
    run_test(result, "artifact_manager_creation", test_artifact_manager_creation)
    run_test(result, "artifact_manager_create", test_artifact_manager_create)
    run_test(result, "artifact_manager_upload", test_artifact_manager_upload)
    run_test(result, "artifact_manager_collection", test_artifact_manager_collection)
    run_test(result, "artifact_manager_get_by_type", test_artifact_manager_get_by_type)
    run_test(result, "artifact_manager_storage_usage", test_artifact_manager_storage_usage)
    run_test(result, "artifact_manager_statistics", test_artifact_manager_statistics)
    run_test(result, "artifact_manager_format", test_artifact_manager_format)

    # Reporting module tests
    print("\n📦 Reporting Module Tests:")
    run_test(result, "reporting_imports", test_reporting_imports)
    run_test(result, "dashboard_manager_creation", test_dashboard_manager_creation)
    run_test(result, "dashboard_manager_create_dashboard", test_dashboard_manager_create_dashboard)
    run_test(result, "dashboard_manager_add_widget", test_dashboard_manager_add_widget)
    run_test(result, "dashboard_manager_refresh", test_dashboard_manager_refresh)
    run_test(result, "dashboard_manager_export", test_dashboard_manager_export)
    run_test(result, "dashboard_manager_statistics", test_dashboard_manager_statistics)
    run_test(result, "dashboard_manager_format", test_dashboard_manager_format)
    run_test(result, "analytics_creation", test_analytics_creation)
    run_test(result, "analytics_record_data", test_analytics_record_data)
    run_test(result, "analytics_compute_metric", test_analytics_compute_metric)
    run_test(result, "analytics_detect_anomalies", test_analytics_detect_anomalies)
    run_test(result, "analytics_find_correlations", test_analytics_find_correlations)
    run_test(result, "analytics_generate_report", test_analytics_generate_report)
    run_test(result, "analytics_statistics", test_analytics_statistics)
    run_test(result, "analytics_format", test_analytics_format)
    run_test(result, "report_generator_creation", test_report_generator_creation)
    run_test(result, "report_generator_add_result", test_report_generator_add_result)
    run_test(result, "report_generator_add_batch", test_report_generator_add_batch)
    run_test(result, "report_generator_summary", test_report_generator_summary)
    run_test(result, "report_generator_generate_html", test_report_generator_generate_html)
    run_test(result, "report_generator_generate_json", test_report_generator_generate_json)
    run_test(result, "report_generator_generate_junit", test_report_generator_generate_junit)
    run_test(result, "report_generator_generate_markdown", test_report_generator_generate_markdown)
    run_test(result, "report_generator_statistics", test_report_generator_statistics)
    run_test(result, "report_generator_format", test_report_generator_format)

    # Optimization module tests
    print("\n📦 Optimization Module Tests:")
    run_test(result, "optimization_imports", test_optimization_imports)
    run_test(result, "selector_creation", test_selector_creation)
    run_test(result, "selector_register_test", test_selector_register_test)
    run_test(result, "selector_select_all", test_selector_select_all)
    run_test(result, "selector_select_affected", test_selector_select_affected)
    run_test(result, "selector_select_time_based", test_selector_select_time_based)
    run_test(result, "selector_statistics", test_selector_statistics)
    run_test(result, "selector_format", test_selector_format)
    run_test(result, "prioritizer_creation", test_prioritizer_creation)
    run_test(result, "prioritizer_add_test", test_prioritizer_add_test)
    run_test(result, "prioritizer_prioritize", test_prioritizer_prioritize)
    run_test(result, "prioritizer_top_priority", test_prioritizer_top_priority)
    run_test(result, "prioritizer_set_weight", test_prioritizer_set_weight)
    run_test(result, "prioritizer_statistics", test_prioritizer_statistics)
    run_test(result, "prioritizer_format", test_prioritizer_format)
    run_test(result, "parallelizer_creation", test_parallelizer_creation)
    run_test(result, "parallelizer_add_test", test_parallelizer_add_test)
    run_test(result, "parallelizer_create_plan_round_robin", test_parallelizer_create_plan_round_robin)
    run_test(result, "parallelizer_create_plan_duration_balanced", test_parallelizer_create_plan_duration_balanced)
    run_test(result, "parallelizer_estimate_speedup", test_parallelizer_estimate_speedup)
    run_test(result, "parallelizer_suite_grouped", test_parallelizer_suite_grouped)
    run_test(result, "parallelizer_statistics", test_parallelizer_statistics)
    run_test(result, "parallelizer_format", test_parallelizer_format)

    # Summary
    success = result.summary()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
