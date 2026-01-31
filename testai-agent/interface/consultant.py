"""
TestAI Agent - QA Consultant Interface

Behaves like a Senior European QA Consultant:
- Asks clarifying questions before assuming
- Shows thinking process (visible reasoning)
- Provides risk assessments
- Gives professional recommendations
- Cites sources (zero hallucination)

Design Philosophy:
- European: Direct but warm, professional but human
- Thoughtful: Thinks before acting, asks before assuming
- Expert: 12+ years of QA experience (Maya persona)
- Humble: Admits uncertainty, cites sources
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable, Awaitable
from enum import Enum
from datetime import datetime
import asyncio
import random
import sys
import os

# Add parent path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from interface.rich_output import RichOutput, console


class ConsultantMood(Enum):
    """Consultant's current mood/state."""
    GREETING = "greeting"
    THINKING = "thinking"
    CLARIFYING = "clarifying"
    CONFIDENT = "confident"
    UNCERTAIN = "uncertain"
    CELEBRATING = "celebrating"


@dataclass
class ConsultantResponse:
    """A response from the consultant."""
    message: str
    mood: ConsultantMood
    thinking: Optional[str] = None
    citations: List[Dict[str, Any]] = field(default_factory=list)
    follow_up_questions: List[str] = field(default_factory=list)
    confidence: float = 0.8


@dataclass
class ConsultationSession:
    """Tracks a consultation session."""
    started_at: datetime = field(default_factory=datetime.now)
    feature: Optional[str] = None
    page_type: Optional[str] = None
    clarifications: List[Dict[str, str]] = field(default_factory=list)
    tests_generated: int = 0
    api_calls_used: int = 0
    max_api_calls: int = 10


class QAConsultant:
    """
    Senior QA Consultant interface.

    Provides a human-like interaction experience:
    - Greets appropriately
    - Asks clarifying questions
    - Shows thinking process
    - Provides expert recommendations
    - Cites sources for transparency

    Usage:
        consultant = QAConsultant()

        # Start session
        consultant.greet()

        # Analyze request
        response = await consultant.analyze_request("test login page")

        # Answer questions
        consultant.answer_clarification("email validation", "Yes, include international emails")

        # Generate tests
        tests = await consultant.generate_tests()

        # Get recommendations
        consultant.provide_recommendations()
    """

    # Greeting phrases (European style - direct but warm)
    GREETINGS = {
        "first_time": [
            "Hello! I'm your QA consultant. Tell me about the feature you'd like to test.",
            "Hi there. Ready to help with your testing needs. What are we working on?",
            "Good to meet you. What feature should we focus on today?",
        ],
        "returning": [
            "Welcome back. What would you like to test this time?",
            "Hello again. Ready when you are.",
            "Back for more testing? Let's dive in.",
        ],
    }

    # Thinking phrases
    THINKING = {
        "analyzing": [
            "Let me analyze this...",
            "Looking at the structure here...",
            "Examining what we have...",
            "Processing this information...",
        ],
        "searching": [
            "Consulting my knowledge base...",
            "Searching for relevant testing patterns...",
            "Looking up best practices for this...",
            "Checking security guidelines...",
        ],
        "planning": [
            "Planning the test approach...",
            "Mapping out scenarios...",
            "Identifying edge cases...",
            "Prioritizing test cases...",
        ],
    }

    # Clarification patterns
    CLARIFICATIONS = {
        "vague_input": [
            "Before I proceed, I have a few questions to ensure comprehensive coverage.",
            "I want to make sure I understand correctly. A few clarifications:",
            "To provide the best tests, I need to understand a bit more:",
        ],
        "specific_need": [
            "One thing I'd like to clarify:",
            "Quick question about this:",
            "Just to confirm:",
        ],
    }

    # Celebration phrases (for good results)
    CELEBRATIONS = [
        "Found some interesting edge cases here!",
        "Good coverage on the security front.",
        "These tests should catch most issues.",
        "Solid test suite coming together.",
    ]

    # Uncertainty phrases (for low confidence)
    UNCERTAINTY = [
        "I'm not 100% sure about this, so I'd recommend verifying:",
        "This might need a closer look:",
        "My confidence isn't super high here - consider:",
    ]

    def __init__(
        self,
        output: Optional[RichOutput] = None,
        reasoner: Optional[Any] = None,  # Cortex reasoner
        verbose: bool = True,
    ):
        """
        Initialize the consultant.

        Args:
            output: RichOutput instance for display
            reasoner: Cortex Reasoner for generating tests
            verbose: Show detailed thinking process
        """
        self.output = output or console
        self.reasoner = reasoner
        self.verbose = verbose
        self.session = ConsultationSession()
        self._is_returning = False

    def greet(self, returning: bool = False):
        """Greet the user."""
        self._is_returning = returning

        greetings = self.GREETINGS["returning" if returning else "first_time"]
        greeting = random.choice(greetings)

        self.output.header("TestAI Consultant", "Your Senior QA Partner")
        self.output.newline()
        self.output.info(greeting)
        self.output.newline()

        # Show API limits
        remaining = self.session.max_api_calls - self.session.api_calls_used
        self.output.info(f"API calls available: {remaining}/{self.session.max_api_calls}")
        self.output.divider()

    def think(self, phase: str = "analyzing"):
        """Show thinking process."""
        if not self.verbose:
            return

        thoughts = self.THINKING.get(phase, self.THINKING["analyzing"])
        thought = random.choice(thoughts)
        self.output.thinking(thought)

    async def analyze_request(
        self,
        request: str,
        page_type: Optional[str] = None,
    ) -> ConsultantResponse:
        """
        Analyze a user request and determine what clarifications are needed.

        Args:
            request: User's request
            page_type: Optional page type hint

        Returns:
            ConsultantResponse with analysis and questions
        """
        self.session.feature = request
        self.session.page_type = page_type

        self.output.section("Analyzing Request")
        self.think("analyzing")

        # Determine what we know and what we need
        questions = []
        confidence = 0.8

        # Check if request is vague
        keywords = request.lower().split()
        feature_indicators = ["login", "signup", "checkout", "search", "form", "dashboard", "profile", "settings"]
        found_indicators = [k for k in keywords if k in feature_indicators]

        if not found_indicators and not page_type:
            confidence = 0.5
            questions.append("What type of page/feature is this? (login, signup, checkout, search, form, etc.)")

        # Check for scope clarity
        scope_keywords = ["all", "comprehensive", "full", "complete", "specific", "just", "only"]
        has_scope = any(k in keywords for k in scope_keywords)

        if not has_scope:
            questions.append("Should I focus on comprehensive coverage or specific areas?")

        # Check for priority hint
        priority_keywords = ["security", "critical", "important", "quick", "basic"]
        has_priority = any(k in keywords for k in priority_keywords)

        if not has_priority:
            questions.append("Any particular focus? (security, edge cases, happy paths)")

        # Show detected info
        detected_type = found_indicators[0] if found_indicators else page_type or "unknown"
        self.think("searching")

        self.output.newline()
        self.output.info(f"Detected feature type: {detected_type}")
        self.output.info(f"Confidence: {confidence:.0%}")

        # Ask clarifying questions if needed
        if questions and confidence < 0.8:
            self.output.newline()
            intro = random.choice(self.CLARIFICATIONS["vague_input"])
            self.output.info(intro)
            self.output.newline()

            for i, q in enumerate(questions, 1):
                self.output.info(f"  {i}. {q}")

            return ConsultantResponse(
                message=intro,
                mood=ConsultantMood.CLARIFYING,
                thinking=f"Detected: {detected_type}, but need more info",
                follow_up_questions=questions,
                confidence=confidence,
            )
        else:
            self.output.newline()
            self.output.success(f"Good - I have enough context to proceed with {detected_type} testing")

            return ConsultantResponse(
                message=f"Ready to generate tests for {detected_type}",
                mood=ConsultantMood.CONFIDENT,
                thinking=f"Clear request for {detected_type} testing",
                confidence=confidence,
            )

    def answer_clarification(self, question: str, answer: str):
        """
        Record an answer to a clarification question.

        Args:
            question: The question that was asked
            answer: User's answer
        """
        self.session.clarifications.append({
            "question": question,
            "answer": answer,
        })

        self.output.success(f"Got it: {answer}")

    async def generate_tests(
        self,
        use_brain: bool = True,
        max_tests: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Generate tests using the reasoner.

        Args:
            use_brain: Whether to use Brain for RAG
            max_tests: Maximum tests to generate

        Returns:
            List of test case dictionaries
        """
        self.output.section("Generating Tests")

        if self.session.api_calls_used >= self.session.max_api_calls:
            self.output.error("API call limit reached!")
            self.output.info("Use offline mode or reset the session.")
            return []

        self.think("planning")

        # If we have a reasoner, use it
        if self.reasoner:
            self.think("searching")
            self.session.api_calls_used += 1

            try:
                result = await self.reasoner.reason_about_feature(
                    feature=self.session.feature,
                    page_type=self.session.page_type,
                )

                # Show citations
                if result.citations:
                    self.output.newline()
                    self.output.section("Sources Used")
                    for citation in result.citations[:3]:
                        self.output.citation(citation.source, citation.confidence)

                # Parse tests from result
                tests = self._parse_tests_from_response(result.output)
                self.session.tests_generated = len(tests)

                self.output.newline()
                self.output.success(f"Generated {len(tests)} test cases")

                return tests

            except Exception as e:
                self.output.error(f"Generation failed: {str(e)}")
                return []
        else:
            # Offline mode - use templates
            self.output.warning("Running in offline mode (templates only)")

            from generators.prompts import get_template_tests

            tests = get_template_tests(
                self.session.page_type or "form",
                self.session.feature or "feature",
            )

            self.session.tests_generated = len(tests)
            self.output.success(f"Generated {len(tests)} template-based tests")

            return tests

    def _parse_tests_from_response(self, content: str) -> List[Dict[str, Any]]:
        """Parse test cases from LLM response."""
        tests = []

        # Simple parsing - look for numbered items or markdown headers
        current_test = {}
        lines = content.split('\n')

        for line in lines:
            line = line.strip()

            # New test case marker
            if line.startswith('##') or line.startswith('TC-') or (line and line[0].isdigit() and '.' in line[:5]):
                if current_test:
                    tests.append(current_test)
                current_test = {
                    "title": line.lstrip('#').lstrip('0123456789.-) ').strip(),
                    "priority": "medium",
                    "category": "general",
                    "steps": [],
                }

            # Priority detection
            elif 'critical' in line.lower():
                current_test["priority"] = "critical"
            elif 'high' in line.lower() and 'priority' in line.lower():
                current_test["priority"] = "high"
            elif 'low' in line.lower() and 'priority' in line.lower():
                current_test["priority"] = "low"

            # Category detection
            elif 'security' in line.lower():
                current_test["category"] = "security"
            elif 'edge' in line.lower():
                current_test["category"] = "edge_case"
            elif 'negative' in line.lower():
                current_test["category"] = "negative"

            # Steps
            elif line.startswith('-') or line.startswith('*') or (line and line[0].isdigit() and '.' in line[:3]):
                step = line.lstrip('-*0123456789.) ').strip()
                if step and current_test:
                    current_test.setdefault("steps", []).append(step)

            # Expected result
            elif 'expected' in line.lower():
                parts = line.split(':', 1)
                if len(parts) > 1:
                    current_test["expected_result"] = parts[1].strip()

        if current_test:
            tests.append(current_test)

        # Add IDs
        for i, test in enumerate(tests, 1):
            test["id"] = f"TC-{i:03d}"

        return tests[:10]  # Limit to 10

    def show_tests(self, tests: List[Dict[str, Any]], detailed: bool = False):
        """Display generated tests."""
        self.output.section(f"Test Cases ({len(tests)})")
        self.output.newline()

        for test in tests:
            self.output.test_case(
                test_id=test.get("id", "TC-XXX"),
                title=test.get("title", "Untitled"),
                priority=test.get("priority", "medium"),
                category=test.get("category"),
                show_details=detailed,
                steps=test.get("steps"),
                expected=test.get("expected_result"),
            )
            self.output.newline()

    def provide_recommendations(
        self,
        tests: List[Dict[str, Any]],
        citations: Optional[List[Dict]] = None,
    ):
        """Provide professional recommendations."""
        self.output.section("Recommendations")
        self.output.newline()

        # Calculate metrics
        critical_count = sum(1 for t in tests if t.get("priority") == "critical")
        high_count = sum(1 for t in tests if t.get("priority") == "high")
        security_count = sum(1 for t in tests if t.get("category") == "security")

        # Risk assessment
        if critical_count > 0 or security_count == 0:
            risk_level = "high"
            risk_icon = "⚠️"
        elif high_count > 3:
            risk_level = "moderate"
            risk_icon = "📋"
        else:
            risk_level = "low"
            risk_icon = "✅"

        self.output.info(f"{risk_icon} Risk Level: {risk_level.upper()}")
        self.output.newline()

        # Specific recommendations
        recommendations = []

        if critical_count > 0:
            recommendations.append(f"Execute {critical_count} critical test(s) before release - these are blockers.")

        if security_count == 0:
            recommendations.append("Consider adding security-focused tests (SQL injection, XSS, etc.).")

        if high_count > 3:
            recommendations.append(f"Prioritize the {high_count} high-priority tests for early execution.")

        # General advice
        recommendations.append("Run tests in staging environment before production.")
        recommendations.append("Consider edge cases with international users (unicode, timezones).")

        self.output.info("Action Items:")
        for rec in recommendations:
            self.output.info(f"  • {rec}")

        # Citations (zero hallucination)
        if citations:
            self.output.newline()
            self.output.info("Sources consulted:")
            for citation in citations[:3]:
                source = citation.get("source", "Unknown")
                conf = citation.get("confidence", 0)
                self.output.citation(source, conf)

        # Celebration
        self.output.newline()
        celebration = random.choice(self.CELEBRATIONS)
        self.output.success(celebration)

    def farewell(self):
        """End the session."""
        self.output.divider()
        self.output.newline()

        # Summary
        self.output.info("Session Summary:")
        self.output.info(f"  • Tests generated: {self.session.tests_generated}")
        self.output.info(f"  • API calls used: {self.session.api_calls_used}/{self.session.max_api_calls}")
        self.output.info(f"  • Clarifications: {len(self.session.clarifications)}")

        self.output.newline()
        self.output.info("Good luck with your testing! 👋")


async def run_consultation(feature: str, page_type: Optional[str] = None):
    """Run an interactive consultation session."""
    consultant = QAConsultant()

    # Greet
    consultant.greet()

    # Analyze
    response = await consultant.analyze_request(feature, page_type)

    # Handle clarifications
    if response.follow_up_questions:
        for question in response.follow_up_questions:
            answer = consultant.output.ask(question)
            consultant.answer_clarification(question, answer)

    # Generate tests
    tests = await consultant.generate_tests()

    if tests:
        # Show tests
        consultant.show_tests(tests, detailed=True)

        # Recommendations
        consultant.provide_recommendations(tests)

    # Farewell
    consultant.farewell()


if __name__ == "__main__":
    asyncio.run(run_consultation("login page with email and password"))
