"""
TestAI Agent - Comprehensive Integration Tests

Tests the complete flow from feature input to test generation.
Validates:
- Brain (knowledge retrieval)
- Cortex (reasoning with citations)
- Gateway (LLM calls with limits)
- Interface (human UX)
- Reports (executive output)
"""

import pytest
import asyncio
import sys
import os
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestBrain:
    """Test the Brain (knowledge storage and retrieval)."""

    def test_brain_import(self):
        """Test Brain module imports."""
        from brain.vector_store import QABrain, KnowledgeChunk, SearchResult
        assert QABrain is not None
        assert KnowledgeChunk is not None
        assert SearchResult is not None

    def test_brain_initialization(self):
        """Test Brain can be initialized."""
        from brain.vector_store import QABrain
        brain = QABrain()
        assert brain is not None

    def test_knowledge_chunk_creation(self):
        """Test KnowledgeChunk dataclass."""
        from brain.vector_store import KnowledgeChunk

        chunk = KnowledgeChunk(
            content="Test email validation rules",
            section="7.1 - Email Validation",
            category="input_validation",
            tags=["email", "validation", "security"],
            page_types=["login", "signup"],
        )

        assert chunk.section == "7.1 - Email Validation"
        assert "email" in chunk.tags
        assert "login" in chunk.page_types


class TestGateway:
    """Test the LLM Gateway."""

    def test_gateway_import(self):
        """Test Gateway module imports."""
        from connectors.llm_gateway import LLMGateway, create_gateway, Citation
        assert LLMGateway is not None
        assert create_gateway is not None
        assert Citation is not None

    def test_gateway_creation(self):
        """Test Gateway can be created with limits."""
        from connectors.llm_gateway import create_gateway

        gateway = create_gateway(max_calls=10)
        assert gateway is not None
        assert gateway.get_remaining_calls() == 10

    def test_gateway_usage_tracking(self):
        """Test Gateway tracks usage correctly."""
        from connectors.llm_gateway import create_gateway, ProviderName

        gateway = create_gateway(max_calls=5)

        # Check initial state
        assert gateway.can_call()
        remaining = gateway.get_remaining_calls()
        assert remaining == 5

        # Get status
        status = gateway.get_status()
        assert status["primary_provider"] == "deepseek"
        assert status["ready"] == True

    def test_citation_creation(self):
        """Test Citation dataclass."""
        from connectors.llm_gateway import Citation

        citation = Citation(
            source="Brain: Section 7.1 - Email Validation",
            chunk_id="test-123",
            confidence=0.85,
            excerpt="Email must be valid format...",
        )

        formatted = citation.format()
        assert "Section 7.1" in formatted
        assert "85%" in formatted


class TestCortex:
    """Test the Cortex (reasoning engine)."""

    def test_cortex_import(self):
        """Test Cortex module imports."""
        from cortex import Reasoner, ReasoningResult, DecisionEngine
        assert Reasoner is not None
        assert ReasoningResult is not None
        assert DecisionEngine is not None

    def test_reasoner_creation(self):
        """Test Reasoner can be created."""
        from cortex.reasoner import Reasoner
        from connectors.llm_gateway import create_gateway

        gateway = create_gateway(max_calls=10)
        reasoner = Reasoner(gateway=gateway)

        assert reasoner is not None
        assert reasoner.gateway is not None

    def test_confidence_scoring(self):
        """Test confidence scoring works."""
        from cortex.confidence import ConfidenceScorer, ConfidenceLevel

        scorer = ConfidenceScorer(default_threshold=0.7)

        result = scorer.score_generation(
            feature="login",
            context_available=True,
            knowledge_chunks=3,
        )

        assert result.score >= 0 and result.score <= 1
        assert result.level in ConfidenceLevel
        assert result.reasoning is not None


class TestInterface:
    """Test the Interface (human UX)."""

    def test_interface_import(self):
        """Test Interface module imports."""
        from interface.rich_output import RichOutput, console
        from interface.consultant import QAConsultant, ConsultationSession
        assert RichOutput is not None
        assert QAConsultant is not None

    def test_rich_output_basic(self):
        """Test RichOutput with basic mode."""
        from interface.rich_output import RichOutput

        output = RichOutput(force_basic=True)

        # Should not raise
        output.thinking("Test thinking")
        output.success("Test success")
        output.warning("Test warning")
        output.error("Test error")
        output.citation("Test source", 0.85)

    def test_consultant_creation(self):
        """Test QAConsultant creation."""
        from interface.consultant import QAConsultant
        from interface.rich_output import RichOutput

        output = RichOutput(force_basic=True)
        consultant = QAConsultant(output=output)

        assert consultant.session is not None
        assert consultant.session.max_api_calls == 10


class TestGenerators:
    """Test the Generators (report generation)."""

    def test_generators_import(self):
        """Test Generators module imports."""
        from generators import (
            ReportGenerator,
            ExecutiveReportGenerator,
            AudienceType,
            generate_report,
            generate_executive_report,
        )
        assert ReportGenerator is not None
        assert ExecutiveReportGenerator is not None

    def test_report_generation(self):
        """Test basic report generation."""
        from generators import ReportGenerator, ReportFormat

        generator = ReportGenerator()

        tests = [
            {
                "id": "TC-001",
                "title": "Login with valid credentials",
                "priority": "critical",
                "category": "happy_path",
            },
            {
                "id": "TC-002",
                "title": "SQL injection prevention",
                "priority": "critical",
                "category": "security",
            },
        ]

        report = generator.create_report(tests, "Login", page_type="login")

        assert report.metadata.feature == "Login"
        assert report.summary["total_tests"] == 2
        assert report.summary["critical_count"] == 2

    def test_markdown_output(self):
        """Test Markdown report output."""
        from generators import generate_report, ReportFormat

        tests = [
            {"id": "TC-001", "title": "Test", "priority": "high", "category": "security"},
        ]

        markdown = generate_report(tests, "Feature", format=ReportFormat.MARKDOWN)

        assert "# Test Report" in markdown
        assert "TC-001" in markdown

    def test_executive_report(self):
        """Test executive report generation."""
        from generators import generate_executive_report, AudienceType

        tests = [
            {"id": "TC-001", "title": "Critical Test", "priority": "critical", "category": "security"},
            {"id": "TC-002", "title": "High Test", "priority": "high", "category": "happy_path"},
        ]

        # Executive view (short)
        exec_report = generate_executive_report(tests, "Login", AudienceType.EXECUTIVE)
        assert "Risk Assessment" in exec_report
        assert "Ship Decision" in exec_report

        # QA view (detailed)
        qa_report = generate_executive_report(tests, "Login", AudienceType.QA)
        assert "Test Coverage" in qa_report
        assert "TC-001" in qa_report


class TestPersonality:
    """Test the Personality module."""

    def test_personality_import(self):
        """Test Personality module imports."""
        from personality import Thinker, ResponseStyler, Clarifier, Celebrator
        assert Thinker is not None
        assert ResponseStyler is not None

    def test_thinker(self):
        """Test Thinker generates thoughts."""
        from personality.thinker import Thinker, ThinkingPhase

        thinker = Thinker()
        thought = thinker.think(ThinkingPhase.ANALYZING)

        assert thought.text is not None
        assert thought.delay > 0

    def test_thinking_sequence(self):
        """Test thinking sequence generation."""
        from personality.thinker import think_sequence

        thoughts = think_sequence("login")

        assert len(thoughts) > 0
        assert any("login" in t.lower() or "analyz" in t.lower() for t in thoughts)


class TestUnderstanding:
    """Test the Understanding module."""

    def test_understanding_import(self):
        """Test Understanding module imports."""
        from understanding.feature_analyzer import FeatureAnalyzer
        from understanding.edge_cases import EdgeCaseDetector
        assert FeatureAnalyzer is not None
        assert EdgeCaseDetector is not None

    def test_feature_analysis(self):
        """Test feature analysis from request."""
        from understanding.feature_analyzer import FeatureAnalyzer

        analyzer = FeatureAnalyzer()
        context = analyzer.from_request("login page with email and password")

        assert context.page_type == "login"
        assert "email" in str(context.elements).lower() or context.page_type == "login"

    def test_edge_case_detection(self):
        """Test edge case detection."""
        from understanding.edge_cases import EdgeCaseDetector

        detector = EdgeCaseDetector()
        edge_cases = detector.get_universal_edge_cases()

        assert len(edge_cases) > 0
        assert any("network" in str(ec).lower() for ec in edge_cases)


class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_full_flow_offline(self):
        """Test complete flow in offline mode."""
        from interface.consultant import QAConsultant
        from interface.rich_output import RichOutput
        from generators import generate_executive_report, AudienceType

        # Create consultant with basic output
        output = RichOutput(force_basic=True)
        consultant = QAConsultant(output=output, verbose=False)

        # Analyze request
        response = await consultant.analyze_request("login page", page_type="login")

        # Generate tests (offline)
        tests = await consultant.generate_tests()

        assert len(tests) > 0
        assert tests[0].get("id") is not None

        # Generate report
        report = generate_executive_report(tests, "Login", AudienceType.QA)
        assert "Test" in report

    def test_citation_flow(self):
        """Test citation tracking through the system."""
        from connectors.llm_gateway import Citation, GatewayResponse, ProviderName

        # Create citations
        citations = [
            Citation(
                source="Brain: Section 7.1 - Email Validation",
                chunk_id="chunk-1",
                confidence=0.92,
                excerpt="Email validation rules...",
            ),
            Citation(
                source="Brain: Section 12.3 - SQL Injection",
                chunk_id="chunk-2",
                confidence=0.88,
                excerpt="Prevent SQL injection...",
            ),
        ]

        # Create response with citations
        response = GatewayResponse(
            content="Test content",
            provider=ProviderName.DEEPSEEK,
            model="deepseek-chat",
            tokens_used=100,
            cost=0.001,
            citations=citations,
        )

        assert response.has_citations
        assert len(response.citations) == 2

        # Format with citations
        formatted = response.format_with_citations()
        assert "Section 7.1" in formatted
        assert "92%" in formatted


def run_tests():
    """Run all tests."""
    pytest.main([__file__, "-v", "--tb=short"])


if __name__ == "__main__":
    run_tests()
