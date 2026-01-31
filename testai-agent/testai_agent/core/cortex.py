"""
TestAI Agent - Cortex (Reasoning Engine)

The Cortex is the brain's decision-making center:
1. Analyzes user input to understand what needs testing
2. Queries the Brain for relevant rules
3. Uses LLM to generate comprehensive test plans
4. Ensures EVERY test case cites its source

Key Principles:
- Zero hallucination: All tests cite specific Brain sections
- Visible thinking: Shows reasoning process to user
- Human-centric: Asks clarifying questions when needed
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
import re

from ..brain.vector_store import QABrain, CitedKnowledge, RetrievalResult
from ..connectors.llm_gateway import LLMGateway, LLMMessage, LLMResponse


class TestCategory(Enum):
    """Test case categories."""
    SECURITY = "Security"
    FUNCTIONAL = "Functional"
    UI_UX = "UI/UX"
    PERFORMANCE = "Performance"
    EDGE_CASE = "Edge Cases"
    VALIDATION = "Input Validation"
    ACCESSIBILITY = "Accessibility"
    API = "API Testing"


class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class CitedTestCase:
    """
    A test case with FULL citation to its source.

    This is the core output format ensuring zero hallucination.
    """
    id: str
    title: str
    category: TestCategory
    risk_level: RiskLevel
    preconditions: List[str]
    steps: List[str]
    expected_result: str
    source_citation: str      # e.g., "Source: Section 7.1 - Email Validation"
    source_section_id: str    # e.g., "7.1"
    notes: Optional[str] = None

    def to_markdown(self) -> str:
        """Format as markdown."""
        lines = [
            f"### {self.id}: {self.title}",
            f"**Category:** {self.category.value}",
            f"**Risk Level:** {self.risk_level.value}",
            "",
            "**Preconditions:**",
        ]

        for pre in self.preconditions:
            lines.append(f"- {pre}")

        lines.append("")
        lines.append("**Steps:**")

        for i, step in enumerate(self.steps, 1):
            lines.append(f"{i}. {step}")

        lines.append("")
        lines.append(f"**Expected Result:** {self.expected_result}")

        if self.notes:
            lines.append("")
            lines.append(f"**Notes:** {self.notes}")

        lines.append("")
        lines.append(f"*{self.source_citation}*")

        return '\n'.join(lines)


@dataclass
class RiskAssessment:
    """Risk assessment for a feature."""
    feature: str
    overall_risk: RiskLevel
    security_risks: List[str]
    functional_risks: List[str]
    ui_risks: List[str]
    recommendations: List[str]
    citations: List[str]

    def to_markdown(self) -> str:
        """Format as markdown."""
        lines = [
            "## Risk Assessment",
            f"**Feature:** {self.feature}",
            f"**Overall Risk Level:** {self.overall_risk.value}",
            "",
        ]

        if self.security_risks:
            lines.append("### Security Risks")
            for risk in self.security_risks:
                lines.append(f"- 🔒 {risk}")
            lines.append("")

        if self.functional_risks:
            lines.append("### Functional Risks")
            for risk in self.functional_risks:
                lines.append(f"- ⚙️ {risk}")
            lines.append("")

        if self.ui_risks:
            lines.append("### UI/UX Risks")
            for risk in self.ui_risks:
                lines.append(f"- 🎨 {risk}")
            lines.append("")

        if self.recommendations:
            lines.append("### Recommendations")
            for rec in self.recommendations:
                lines.append(f"- ✅ {rec}")
            lines.append("")

        if self.citations:
            lines.append("### Sources Consulted")
            for cite in self.citations:
                lines.append(f"- {cite}")

        return '\n'.join(lines)


@dataclass
class TestPlan:
    """
    A complete test plan with citations.
    """
    feature: str
    risk_assessment: RiskAssessment
    test_cases: List[CitedTestCase]
    total_tests: int
    by_category: Dict[str, int]
    by_risk: Dict[str, int]
    all_citations: List[str]

    def to_markdown(self) -> str:
        """Format complete test plan as markdown."""
        lines = [
            f"# Test Plan: {self.feature}",
            "",
            self.risk_assessment.to_markdown(),
            "",
            "---",
            "",
            "## Test Cases",
            f"**Total Tests:** {self.total_tests}",
            "",
            "### Summary by Category",
        ]

        for cat, count in self.by_category.items():
            lines.append(f"- {cat}: {count}")

        lines.append("")
        lines.append("### Summary by Risk Level")

        for risk, count in self.by_risk.items():
            lines.append(f"- {risk}: {count}")

        lines.append("")
        lines.append("---")
        lines.append("")

        # Group tests by category
        by_cat: Dict[str, List[CitedTestCase]] = {}
        for tc in self.test_cases:
            cat = tc.category.value
            if cat not in by_cat:
                by_cat[cat] = []
            by_cat[cat].append(tc)

        for cat in ["Security", "Functional", "Input Validation", "UI/UX", "Edge Cases"]:
            if cat in by_cat:
                lines.append(f"## {cat} Tests")
                lines.append("")
                for tc in by_cat[cat]:
                    lines.append(tc.to_markdown())
                    lines.append("")
                lines.append("---")
                lines.append("")

        # All citations
        lines.append("## All Sources Referenced")
        for cite in sorted(set(self.all_citations)):
            lines.append(f"- {cite}")

        return '\n'.join(lines)


@dataclass
class ClarifyingQuestion:
    """A question to ask the user for clarification."""
    question: str
    options: List[str]
    context: str
    required: bool = True


class Cortex:
    """
    The Reasoning Engine.

    Responsibilities:
    1. Analyze user input
    2. Query Brain for relevant knowledge
    3. Generate test plans with citations
    4. Show thinking process to user
    5. Ask clarifying questions when needed
    """

    # System prompt for the QA consultant persona
    SYSTEM_PROMPT = """You are a Senior European QA Consultant with 15+ years of experience.

PERSONALITY:
- Precise, methodical, and thorough
- You think visible to the user (e.g., "Let me consult the security protocols...")
- You ask clarifying questions before making assumptions
- You cite your sources explicitly

WHEN GENERATING TEST CASES:
- You MUST cite the source section for EVERY test case
- Format: "[Section X.Y] Test case derived from rule about..."
- Group tests by: Security, Functional, UI/UX, Edge Cases
- Prioritize by risk: Critical > High > Medium > Low

OUTPUT FORMAT:
Each test case must include:
1. Test ID (e.g., SEC-001, FUNC-002)
2. Title
3. Category
4. Risk Level
5. Preconditions
6. Steps (numbered)
7. Expected Result
8. Source Citation (MANDATORY)

NEVER make up rules. If you don't have knowledge about something, say so.
"""

    def __init__(
        self,
        brain: QABrain,
        gateway: LLMGateway,
        thinking_callback: Optional[Callable[[str], None]] = None
    ):
        self.brain = brain
        self.gateway = gateway
        self.thinking_callback = thinking_callback
        self._conversation: List[LLMMessage] = []

    def think(self, thought: str):
        """Display thinking process to user."""
        if self.thinking_callback:
            self.thinking_callback(thought)

    async def analyze_feature(self, feature: str) -> Dict[str, Any]:
        """
        Analyze a feature to understand what needs testing.

        Returns analysis with detected page type, complexity, etc.
        """
        self.think(f"Analyzing feature: {feature}...")

        # Detect page/feature type
        feature_lower = feature.lower()
        page_type = "general"

        type_keywords = {
            "login": ["login", "signin", "sign in", "auth"],
            "signup": ["signup", "register", "sign up", "registration"],
            "checkout": ["checkout", "payment", "purchase", "cart"],
            "search": ["search", "find", "query"],
            "profile": ["profile", "account", "settings"],
            "form": ["form", "input", "submit"],
            "api": ["api", "endpoint", "rest"],
        }

        for ptype, keywords in type_keywords.items():
            if any(kw in feature_lower for kw in keywords):
                page_type = ptype
                break

        # Detect complexity indicators
        has_payment = any(w in feature_lower for w in ["payment", "card", "checkout", "purchase"])
        has_auth = any(w in feature_lower for w in ["login", "auth", "password", "session"])
        has_sensitive_data = any(w in feature_lower for w in ["personal", "email", "phone", "address"])

        complexity = "low"
        if has_payment or (has_auth and has_sensitive_data):
            complexity = "high"
        elif has_auth or has_sensitive_data:
            complexity = "medium"

        return {
            "feature": feature,
            "page_type": page_type,
            "complexity": complexity,
            "has_payment": has_payment,
            "has_auth": has_auth,
            "has_sensitive_data": has_sensitive_data,
        }

    async def check_for_clarification(self, feature: str) -> List[ClarifyingQuestion]:
        """
        Check if we need clarification before generating tests.

        A real QA consultant asks questions before assuming.
        """
        questions = []
        feature_lower = feature.lower()

        # Vague input check
        if len(feature.split()) <= 2:
            questions.append(ClarifyingQuestion(
                question="Could you provide more details about this feature?",
                options=[
                    "It's a web form with user inputs",
                    "It's an API endpoint",
                    "It's a user authentication flow",
                    "I'll provide more details"
                ],
                context="The input seems brief. More context helps generate better tests.",
                required=False
            ))

        # Payment-related clarification
        if any(w in feature_lower for w in ["checkout", "payment", "purchase"]):
            questions.append(ClarifyingQuestion(
                question="What payment methods are supported?",
                options=[
                    "Credit/Debit cards only",
                    "Cards + PayPal",
                    "Cards + Digital wallets (Apple Pay, Google Pay)",
                    "Not sure / All common methods"
                ],
                context="Different payment methods have different security requirements.",
                required=False
            ))

        # Auth-related clarification
        if any(w in feature_lower for w in ["login", "signin", "auth"]):
            questions.append(ClarifyingQuestion(
                question="Does this feature include any of the following?",
                options=[
                    "Two-factor authentication",
                    "Social login (Google, Facebook)",
                    "Password reset flow",
                    "None of these"
                ],
                context="Additional auth features require specific test coverage.",
                required=False
            ))

        return questions

    async def generate_risk_assessment(
        self,
        feature: str,
        analysis: Dict[str, Any]
    ) -> RiskAssessment:
        """
        Generate a risk assessment for the feature.
        """
        self.think("Consulting security protocols...")

        # Query brain for security knowledge
        security_result = self.brain.retrieve_security_rules(feature)

        self.think(f"Found {security_result.total_found} security-related knowledge items...")

        # Query brain for validation knowledge
        validation_result = self.brain.retrieve_validation_rules(feature)

        self.think(f"Found {validation_result.total_found} validation rules...")

        # Collect all knowledge
        all_knowledge = security_result.knowledge + validation_result.knowledge
        citations = list(set(k.citation for k in all_knowledge))

        # Determine overall risk
        if analysis.get("has_payment"):
            overall_risk = RiskLevel.CRITICAL
        elif analysis.get("has_auth"):
            overall_risk = RiskLevel.HIGH
        elif analysis.get("has_sensitive_data"):
            overall_risk = RiskLevel.MEDIUM
        else:
            overall_risk = RiskLevel.LOW

        # Build risk lists
        security_risks = []
        functional_risks = []
        ui_risks = []
        recommendations = []

        for knowledge in all_knowledge:
            content_lower = knowledge.content.lower()

            if knowledge.category.value == "security":
                if "injection" in content_lower:
                    security_risks.append(f"SQL/XSS Injection risk [{knowledge.section_id}]")
                if "auth" in content_lower:
                    security_risks.append(f"Authentication bypass risk [{knowledge.section_id}]")
                if "session" in content_lower:
                    security_risks.append(f"Session management risk [{knowledge.section_id}]")

            if "validation" in content_lower:
                functional_risks.append(f"Input validation requirements [{knowledge.section_id}]")

            if "display" in content_lower or "ui" in content_lower:
                ui_risks.append(f"Display/formatting issues [{knowledge.section_id}]")

        # Add standard recommendations based on analysis
        if analysis.get("has_payment"):
            recommendations.append("Conduct PCI-DSS compliance review")
            recommendations.append("Test payment gateway error handling")

        if analysis.get("has_auth"):
            recommendations.append("Test brute force protection")
            recommendations.append("Verify secure session handling")

        recommendations.append("Test with various input lengths and special characters")
        recommendations.append("Verify error messages don't leak sensitive info")

        return RiskAssessment(
            feature=feature,
            overall_risk=overall_risk,
            security_risks=security_risks[:5],
            functional_risks=functional_risks[:5],
            ui_risks=ui_risks[:3],
            recommendations=recommendations[:5],
            citations=citations
        )

    async def generate_test_plan(
        self,
        feature: str,
        context: Optional[str] = None
    ) -> TestPlan:
        """
        Generate a comprehensive test plan with CITED test cases.

        This is the main entry point for test generation.
        """
        self.think(f"Initiating test plan generation for: {feature}")

        # Step 1: Analyze the feature
        analysis = await self.analyze_feature(feature)
        self.think(f"Feature type detected: {analysis['page_type']}, Complexity: {analysis['complexity']}")

        # Step 2: Generate risk assessment
        risk_assessment = await self.generate_risk_assessment(feature, analysis)
        self.think(f"Risk assessment complete. Overall risk: {risk_assessment.overall_risk.value}")

        # Step 3: Query brain for all relevant knowledge
        self.think("Querying knowledge base for testing rules...")
        all_knowledge = self.brain.retrieve_for_feature(
            feature,
            page_type=analysis['page_type']
        )

        security_knowledge = self.brain.retrieve_security_rules(feature)
        validation_knowledge = self.brain.retrieve_validation_rules(feature)

        # Combine and deduplicate
        knowledge_map = {}
        for k in all_knowledge.knowledge + security_knowledge.knowledge + validation_knowledge.knowledge:
            if k.id not in knowledge_map:
                knowledge_map[k.id] = k

        combined_knowledge = list(knowledge_map.values())
        self.think(f"Retrieved {len(combined_knowledge)} unique knowledge items")

        # Step 4: Generate test cases using LLM
        self.think("Generating test cases from knowledge base...")
        test_cases = await self._generate_test_cases_with_llm(
            feature,
            combined_knowledge,
            analysis
        )

        # Step 5: Compile statistics
        by_category = {}
        by_risk = {}
        all_citations = []

        for tc in test_cases:
            cat = tc.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

            risk = tc.risk_level.value
            by_risk[risk] = by_risk.get(risk, 0) + 1

            all_citations.append(tc.source_citation)

        # Add risk assessment citations
        all_citations.extend(risk_assessment.citations)

        self.think(f"Generated {len(test_cases)} test cases across {len(by_category)} categories")

        return TestPlan(
            feature=feature,
            risk_assessment=risk_assessment,
            test_cases=test_cases,
            total_tests=len(test_cases),
            by_category=by_category,
            by_risk=by_risk,
            all_citations=list(set(all_citations))
        )

    async def _generate_test_cases_with_llm(
        self,
        feature: str,
        knowledge: List[CitedKnowledge],
        analysis: Dict[str, Any]
    ) -> List[CitedTestCase]:
        """
        Use LLM to generate test cases from knowledge.

        CRITICAL: Every test case must cite its source.
        """
        # Build knowledge context with explicit citations
        knowledge_context = "KNOWLEDGE BASE (cite these sections in your tests):\n\n"

        for k in knowledge[:15]:  # Limit to top 15 most relevant
            knowledge_context += f"[Section {k.section_id}] {k.section_title}\n"
            knowledge_context += f"Category: {k.category.value}\n"
            knowledge_context += f"Content: {k.content[:500]}\n"
            knowledge_context += "---\n\n"

        prompt = f"""Generate comprehensive test cases for: {feature}

Feature Analysis:
- Type: {analysis['page_type']}
- Complexity: {analysis['complexity']}
- Has Payment: {analysis.get('has_payment', False)}
- Has Auth: {analysis.get('has_auth', False)}

{knowledge_context}

REQUIREMENTS:
1. Generate at least 8 test cases covering Security, Functional, and UI/UX
2. EVERY test case MUST cite its source section (e.g., "Derived from Section 7.1")
3. Include specific test data values, not generic placeholders
4. Prioritize by risk level

OUTPUT FORMAT (strict JSON):
{{
    "test_cases": [
        {{
            "id": "SEC-001",
            "title": "Test title",
            "category": "Security|Functional|UI_UX|Edge_Case|Validation",
            "risk_level": "Critical|High|Medium|Low",
            "preconditions": ["Precondition 1", "Precondition 2"],
            "steps": ["Step 1", "Step 2", "Step 3"],
            "expected_result": "Expected outcome",
            "source_section_id": "7.1",
            "notes": "Optional notes"
        }}
    ]
}}

Generate the test cases now:"""

        messages = [
            LLMMessage(role="system", content=self.SYSTEM_PROMPT),
            LLMMessage(role="user", content=prompt)
        ]

        response = await self.gateway.chat(messages, temperature=0.7)

        # Parse response
        test_cases = self._parse_test_cases(response.content, knowledge)

        return test_cases

    def _parse_test_cases(
        self,
        llm_response: str,
        knowledge: List[CitedKnowledge]
    ) -> List[CitedTestCase]:
        """Parse LLM response into CitedTestCase objects."""
        import json

        # Build section lookup
        section_lookup = {k.section_id: k for k in knowledge}

        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', llm_response)
        if not json_match:
            return self._fallback_test_cases(knowledge)

        try:
            data = json.loads(json_match.group())
            raw_cases = data.get("test_cases", [])
        except json.JSONDecodeError:
            return self._fallback_test_cases(knowledge)

        test_cases = []

        for raw in raw_cases:
            # Map category
            cat_str = raw.get("category", "Functional")
            category = TestCategory.FUNCTIONAL
            for tc in TestCategory:
                if tc.value.lower().replace("/", "_").replace(" ", "_") == cat_str.lower().replace("/", "_").replace(" ", "_"):
                    category = tc
                    break

            # Map risk level
            risk_str = raw.get("risk_level", "Medium")
            risk_level = RiskLevel.MEDIUM
            for rl in RiskLevel:
                if rl.value.lower() == risk_str.lower():
                    risk_level = rl
                    break

            # Get source citation
            section_id = raw.get("source_section_id", "Unknown")
            if section_id in section_lookup:
                source_citation = section_lookup[section_id].citation
            else:
                source_citation = f"Source: Section {section_id}"

            test_case = CitedTestCase(
                id=raw.get("id", f"TC-{len(test_cases)+1:03d}"),
                title=raw.get("title", "Untitled Test"),
                category=category,
                risk_level=risk_level,
                preconditions=raw.get("preconditions", []),
                steps=raw.get("steps", []),
                expected_result=raw.get("expected_result", ""),
                source_citation=source_citation,
                source_section_id=section_id,
                notes=raw.get("notes")
            )
            test_cases.append(test_case)

        return test_cases

    def _fallback_test_cases(self, knowledge: List[CitedKnowledge]) -> List[CitedTestCase]:
        """Generate basic test cases when LLM parsing fails."""
        test_cases = []
        counter = {"SEC": 0, "FUNC": 0, "VAL": 0}

        for k in knowledge[:10]:
            if k.category.value == "security":
                counter["SEC"] += 1
                tc = CitedTestCase(
                    id=f"SEC-{counter['SEC']:03d}",
                    title=f"Security test from {k.section_title}",
                    category=TestCategory.SECURITY,
                    risk_level=RiskLevel.HIGH,
                    preconditions=["User has access to the feature"],
                    steps=["Test based on: " + k.content[:100]],
                    expected_result="Security requirements met",
                    source_citation=k.citation,
                    source_section_id=k.section_id
                )
            elif k.category.value == "validation":
                counter["VAL"] += 1
                tc = CitedTestCase(
                    id=f"VAL-{counter['VAL']:03d}",
                    title=f"Validation test from {k.section_title}",
                    category=TestCategory.VALIDATION,
                    risk_level=RiskLevel.MEDIUM,
                    preconditions=["User has access to the feature"],
                    steps=["Test based on: " + k.content[:100]],
                    expected_result="Validation works correctly",
                    source_citation=k.citation,
                    source_section_id=k.section_id
                )
            else:
                counter["FUNC"] += 1
                tc = CitedTestCase(
                    id=f"FUNC-{counter['FUNC']:03d}",
                    title=f"Functional test from {k.section_title}",
                    category=TestCategory.FUNCTIONAL,
                    risk_level=RiskLevel.MEDIUM,
                    preconditions=["User has access to the feature"],
                    steps=["Test based on: " + k.content[:100]],
                    expected_result="Feature works as expected",
                    source_citation=k.citation,
                    source_section_id=k.section_id
                )

            test_cases.append(tc)

        return test_cases


def create_cortex(
    brain: QABrain,
    gateway: LLMGateway,
    thinking_callback: Optional[Callable[[str], None]] = None
) -> Cortex:
    """Create a Cortex instance."""
    return Cortex(brain, gateway, thinking_callback)
