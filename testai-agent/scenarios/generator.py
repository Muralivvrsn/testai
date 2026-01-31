"""
TestAI Agent - Scenario Generator

Generates realistic test scenarios with user personas,
business contexts, and comprehensive edge cases.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import random


class ScenarioType(Enum):
    """Types of test scenarios."""
    HAPPY_PATH = "happy_path"
    ERROR_HANDLING = "error_handling"
    EDGE_CASE = "edge_case"
    SECURITY = "security"
    PERFORMANCE = "performance"
    ACCESSIBILITY = "accessibility"
    LOCALIZATION = "localization"
    CONCURRENCY = "concurrency"
    RECOVERY = "recovery"


class UserPersona(Enum):
    """User personas for scenario generation."""
    NEW_USER = "new_user"
    POWER_USER = "power_user"
    ADMIN = "admin"
    GUEST = "guest"
    MOBILE_USER = "mobile_user"
    SENIOR_USER = "senior_user"
    IMPATIENT_USER = "impatient_user"
    MALICIOUS_USER = "malicious_user"
    ACCESSIBILITY_USER = "accessibility_user"
    INTERNATIONAL_USER = "international_user"


@dataclass
class ScenarioContext:
    """Context for a test scenario."""
    persona: UserPersona
    device_type: str
    browser: str
    locale: str
    time_of_day: str
    network_condition: str
    session_state: str


@dataclass
class TestScenario:
    """A complete test scenario."""
    scenario_id: str
    name: str
    description: str
    scenario_type: ScenarioType
    persona: UserPersona
    context: ScenarioContext
    preconditions: List[str]
    steps: List[Dict[str, Any]]
    expected_outcomes: List[str]
    test_data: Dict[str, Any]
    tags: List[str]
    priority: str
    estimated_duration_ms: int


class ScenarioGenerator:
    """
    Generates realistic test scenarios.

    Features:
    - User persona-based scenarios
    - Business context awareness
    - Edge case discovery
    - Data-driven variations
    - Cross-functional scenarios
    """

    # Persona characteristics
    PERSONA_TRAITS = {
        UserPersona.NEW_USER: {
            "tech_savvy": False,
            "patience": "high",
            "attention_to_detail": "low",
            "likely_errors": ["wrong_field", "slow_input", "confused_navigation"],
        },
        UserPersona.POWER_USER: {
            "tech_savvy": True,
            "patience": "low",
            "attention_to_detail": "high",
            "likely_errors": ["impatient_actions", "keyboard_shortcuts"],
        },
        UserPersona.ADMIN: {
            "tech_savvy": True,
            "patience": "medium",
            "attention_to_detail": "high",
            "likely_errors": ["privilege_escalation", "bulk_operations"],
        },
        UserPersona.MALICIOUS_USER: {
            "tech_savvy": True,
            "patience": "high",
            "attention_to_detail": "high",
            "likely_errors": ["injection", "bypass_attempts", "parameter_tampering"],
        },
        UserPersona.ACCESSIBILITY_USER: {
            "tech_savvy": "varied",
            "patience": "high",
            "attention_to_detail": "high",
            "likely_errors": ["keyboard_only", "screen_reader", "high_contrast"],
        },
        UserPersona.IMPATIENT_USER: {
            "tech_savvy": "varied",
            "patience": "low",
            "attention_to_detail": "low",
            "likely_errors": ["double_submit", "navigation_during_load", "abandon"],
        },
    }

    # Feature-specific scenarios
    FEATURE_SCENARIOS = {
        "login": {
            "happy_paths": [
                "Valid credentials login",
                "Login with remember me",
                "Social login (OAuth)",
            ],
            "error_paths": [
                "Invalid password",
                "Non-existent user",
                "Account locked",
                "Session expired",
            ],
            "edge_cases": [
                "Login during maintenance",
                "Multiple tab login",
                "Login after password change",
                "Browser back after login",
            ],
            "security": [
                "SQL injection attempt",
                "XSS in username",
                "Brute force attempt",
                "Session fixation",
            ],
        },
        "registration": {
            "happy_paths": [
                "Standard registration",
                "Social signup",
                "Invite-based registration",
            ],
            "error_paths": [
                "Duplicate email",
                "Invalid email format",
                "Weak password",
                "Missing required fields",
            ],
            "edge_cases": [
                "Unicode username",
                "Maximum field lengths",
                "Email with plus sign",
                "Browser autofill issues",
            ],
            "security": [
                "Email enumeration",
                "CAPTCHA bypass",
                "Rate limiting test",
            ],
        },
        "checkout": {
            "happy_paths": [
                "Standard checkout",
                "Express checkout",
                "Guest checkout",
            ],
            "error_paths": [
                "Payment declined",
                "Out of stock",
                "Invalid coupon",
                "Address validation failure",
            ],
            "edge_cases": [
                "Cart expiry during checkout",
                "Price change during checkout",
                "International shipping",
                "Multiple payment methods",
            ],
            "security": [
                "Price manipulation",
                "Coupon reuse",
                "PCI compliance",
            ],
        },
        "search": {
            "happy_paths": [
                "Basic keyword search",
                "Filtered search",
                "Advanced search",
            ],
            "error_paths": [
                "No results",
                "Search timeout",
                "Invalid characters",
            ],
            "edge_cases": [
                "Special characters search",
                "Very long query",
                "Empty search",
                "Rapid consecutive searches",
            ],
            "security": [
                "XSS in search",
                "SQL injection",
                "Search result manipulation",
            ],
        },
    }

    def __init__(self):
        """Initialize the scenario generator."""
        self._scenario_counter = 0

    def generate_for_feature(
        self,
        feature: str,
        personas: Optional[List[UserPersona]] = None,
        scenario_types: Optional[List[ScenarioType]] = None,
        max_scenarios: int = 20,
    ) -> List[TestScenario]:
        """Generate scenarios for a specific feature."""
        scenarios = []
        feature_lower = feature.lower()

        # Get feature-specific scenarios
        feature_scenarios = self.FEATURE_SCENARIOS.get(
            feature_lower,
            self._get_generic_scenarios()
        )

        # Default personas
        if personas is None:
            personas = [
                UserPersona.NEW_USER,
                UserPersona.POWER_USER,
                UserPersona.MALICIOUS_USER,
            ]

        # Default scenario types
        if scenario_types is None:
            scenario_types = [
                ScenarioType.HAPPY_PATH,
                ScenarioType.ERROR_HANDLING,
                ScenarioType.EDGE_CASE,
                ScenarioType.SECURITY,
            ]

        # Generate scenarios
        for scenario_type in scenario_types:
            type_scenarios = self._get_scenarios_by_type(
                feature_scenarios, scenario_type
            )

            for scenario_name in type_scenarios:
                for persona in personas:
                    if len(scenarios) >= max_scenarios:
                        break

                    scenario = self._create_scenario(
                        feature=feature,
                        name=scenario_name,
                        scenario_type=scenario_type,
                        persona=persona,
                    )
                    scenarios.append(scenario)

        return scenarios[:max_scenarios]

    def generate_edge_cases(
        self,
        feature: str,
        depth: int = 3,
    ) -> List[TestScenario]:
        """Generate edge case scenarios."""
        edge_cases = []

        # Boundary conditions
        boundaries = [
            ("Empty input", "Submit with all fields empty"),
            ("Maximum length", "Fill all fields to maximum allowed length"),
            ("Minimum length", "Use single character where minimum is required"),
            ("Zero values", "Use zero in numeric fields"),
            ("Negative values", "Use negative numbers where applicable"),
            ("Future dates", "Use dates far in the future"),
            ("Past dates", "Use dates in the distant past"),
        ]

        # Unicode and special characters
        unicode_cases = [
            ("Unicode characters", "Use Unicode/emoji in text fields"),
            ("RTL text", "Use right-to-left text (Arabic/Hebrew)"),
            ("Very long strings", "Input extremely long strings"),
            ("SQL metacharacters", "Use SQL special characters"),
            ("HTML entities", "Use HTML entities in input"),
        ]

        # State transitions
        state_cases = [
            ("Back button", "Use browser back during flow"),
            ("Refresh during action", "Refresh page during submission"),
            ("Multiple tabs", "Same action in multiple tabs"),
            ("Session timeout", "Let session expire mid-action"),
            ("Network disconnect", "Lose connection during action"),
        ]

        all_cases = boundaries + unicode_cases + state_cases

        for name, description in all_cases[:depth * 5]:
            self._scenario_counter += 1
            scenario = TestScenario(
                scenario_id=f"EDGE-{self._scenario_counter:04d}",
                name=f"{feature}: {name}",
                description=description,
                scenario_type=ScenarioType.EDGE_CASE,
                persona=UserPersona.POWER_USER,
                context=self._create_context(UserPersona.POWER_USER),
                preconditions=[f"Access to {feature} feature"],
                steps=self._generate_edge_case_steps(name, feature),
                expected_outcomes=["System handles edge case gracefully"],
                test_data=self._generate_edge_case_data(name),
                tags=["edge_case", feature.lower(), name.lower().replace(" ", "_")],
                priority="medium",
                estimated_duration_ms=5000,
            )
            edge_cases.append(scenario)

        return edge_cases

    def generate_security_scenarios(
        self,
        feature: str,
    ) -> List[TestScenario]:
        """Generate security-focused scenarios."""
        security_scenarios = []

        attacks = [
            ("SQL Injection", "Attempt SQL injection in inputs", "' OR '1'='1"),
            ("XSS Stored", "Attempt stored XSS", "<script>alert('xss')</script>"),
            ("XSS Reflected", "Attempt reflected XSS", "<img onerror='alert(1)' src=x>"),
            ("CSRF", "Attempt cross-site request forgery", None),
            ("Path Traversal", "Attempt directory traversal", "../../../etc/passwd"),
            ("Command Injection", "Attempt OS command injection", "; ls -la"),
            ("Header Injection", "Attempt HTTP header injection", "X-Injected: true"),
            ("Parameter Tampering", "Modify hidden/restricted parameters", None),
            ("Session Hijacking", "Attempt to hijack user session", None),
            ("Privilege Escalation", "Attempt to access admin functions", None),
        ]

        for attack_name, description, payload in attacks:
            self._scenario_counter += 1
            scenario = TestScenario(
                scenario_id=f"SEC-{self._scenario_counter:04d}",
                name=f"{feature}: {attack_name}",
                description=description,
                scenario_type=ScenarioType.SECURITY,
                persona=UserPersona.MALICIOUS_USER,
                context=self._create_context(UserPersona.MALICIOUS_USER),
                preconditions=["Security testing authorization"],
                steps=self._generate_security_steps(attack_name, feature, payload),
                expected_outcomes=[
                    "Attack is blocked",
                    "No sensitive data exposed",
                    "Attempt is logged",
                ],
                test_data={"payload": payload} if payload else {},
                tags=["security", attack_name.lower().replace(" ", "_"), feature.lower()],
                priority="critical",
                estimated_duration_ms=3000,
            )
            security_scenarios.append(scenario)

        return security_scenarios

    def generate_accessibility_scenarios(
        self,
        feature: str,
    ) -> List[TestScenario]:
        """Generate accessibility-focused scenarios."""
        a11y_scenarios = []

        checks = [
            ("Keyboard Navigation", "Complete flow using keyboard only"),
            ("Screen Reader", "Verify screen reader compatibility"),
            ("High Contrast", "Test in high contrast mode"),
            ("Zoom 200%", "Test at 200% zoom level"),
            ("Focus Indicators", "Verify visible focus indicators"),
            ("Alt Text", "Check all images have alt text"),
            ("Form Labels", "Verify all inputs have labels"),
            ("Error Announcements", "Verify errors announced to screen readers"),
            ("Skip Links", "Verify skip navigation links work"),
            ("Color Contrast", "Verify WCAG color contrast ratios"),
        ]

        for check_name, description in checks:
            self._scenario_counter += 1
            scenario = TestScenario(
                scenario_id=f"A11Y-{self._scenario_counter:04d}",
                name=f"{feature}: {check_name}",
                description=description,
                scenario_type=ScenarioType.ACCESSIBILITY,
                persona=UserPersona.ACCESSIBILITY_USER,
                context=self._create_context(UserPersona.ACCESSIBILITY_USER),
                preconditions=["Screen reader available", "Accessibility tools enabled"],
                steps=self._generate_a11y_steps(check_name, feature),
                expected_outcomes=[
                    "WCAG 2.1 AA compliance",
                    "Feature usable with assistive technology",
                ],
                test_data={},
                tags=["accessibility", "wcag", check_name.lower().replace(" ", "_")],
                priority="high",
                estimated_duration_ms=8000,
            )
            a11y_scenarios.append(scenario)

        return a11y_scenarios

    def _create_scenario(
        self,
        feature: str,
        name: str,
        scenario_type: ScenarioType,
        persona: UserPersona,
    ) -> TestScenario:
        """Create a complete test scenario."""
        self._scenario_counter += 1

        context = self._create_context(persona)
        priority = self._determine_priority(scenario_type, persona)

        return TestScenario(
            scenario_id=f"SCN-{self._scenario_counter:04d}",
            name=f"{feature}: {name}",
            description=f"{name} as {persona.value}",
            scenario_type=scenario_type,
            persona=persona,
            context=context,
            preconditions=self._generate_preconditions(feature, persona),
            steps=self._generate_steps(feature, name, persona),
            expected_outcomes=self._generate_outcomes(scenario_type, name),
            test_data=self._generate_test_data(feature, persona),
            tags=self._generate_tags(feature, scenario_type, persona),
            priority=priority,
            estimated_duration_ms=self._estimate_duration(scenario_type),
        )

    def _create_context(self, persona: UserPersona) -> ScenarioContext:
        """Create scenario context for a persona."""
        contexts = {
            UserPersona.NEW_USER: ScenarioContext(
                persona=persona,
                device_type="desktop",
                browser="chrome",
                locale="en-US",
                time_of_day="afternoon",
                network_condition="good",
                session_state="new",
            ),
            UserPersona.MOBILE_USER: ScenarioContext(
                persona=persona,
                device_type="mobile",
                browser="safari",
                locale="en-US",
                time_of_day="evening",
                network_condition="4g",
                session_state="new",
            ),
            UserPersona.INTERNATIONAL_USER: ScenarioContext(
                persona=persona,
                device_type="desktop",
                browser="firefox",
                locale="de-DE",
                time_of_day="morning",
                network_condition="good",
                session_state="returning",
            ),
            UserPersona.MALICIOUS_USER: ScenarioContext(
                persona=persona,
                device_type="desktop",
                browser="chrome",
                locale="en-US",
                time_of_day="night",
                network_condition="good",
                session_state="anonymous",
            ),
        }
        return contexts.get(persona, ScenarioContext(
            persona=persona,
            device_type="desktop",
            browser="chrome",
            locale="en-US",
            time_of_day="afternoon",
            network_condition="good",
            session_state="authenticated",
        ))

    def _get_scenarios_by_type(
        self,
        feature_scenarios: Dict[str, List[str]],
        scenario_type: ScenarioType,
    ) -> List[str]:
        """Get scenario names by type."""
        type_mapping = {
            ScenarioType.HAPPY_PATH: "happy_paths",
            ScenarioType.ERROR_HANDLING: "error_paths",
            ScenarioType.EDGE_CASE: "edge_cases",
            ScenarioType.SECURITY: "security",
        }
        key = type_mapping.get(scenario_type, "happy_paths")
        return feature_scenarios.get(key, [])

    def _get_generic_scenarios(self) -> Dict[str, List[str]]:
        """Get generic scenarios for unknown features."""
        return {
            "happy_paths": ["Standard flow", "Alternative flow"],
            "error_paths": ["Invalid input", "Server error handling"],
            "edge_cases": ["Boundary values", "Special characters"],
            "security": ["Input sanitization", "Authorization check"],
        }

    def _generate_preconditions(
        self,
        feature: str,
        persona: UserPersona,
    ) -> List[str]:
        """Generate scenario preconditions."""
        preconditions = [f"User has access to {feature}"]

        if persona in {UserPersona.POWER_USER, UserPersona.ADMIN}:
            preconditions.append("User is authenticated")
        if persona == UserPersona.ADMIN:
            preconditions.append("User has admin privileges")

        return preconditions

    def _generate_steps(
        self,
        feature: str,
        scenario_name: str,
        persona: UserPersona,
    ) -> List[Dict[str, Any]]:
        """Generate scenario steps."""
        return [
            {"action": "navigate", "target": feature},
            {"action": "verify", "target": f"{feature} page loaded"},
            {"action": "interact", "target": "main_element"},
            {"action": "verify", "target": "expected_result"},
        ]

    def _generate_outcomes(
        self,
        scenario_type: ScenarioType,
        scenario_name: str,
    ) -> List[str]:
        """Generate expected outcomes."""
        if scenario_type == ScenarioType.HAPPY_PATH:
            return ["Operation completes successfully", "User sees success message"]
        elif scenario_type == ScenarioType.ERROR_HANDLING:
            return ["Error is displayed clearly", "User can recover"]
        elif scenario_type == ScenarioType.SECURITY:
            return ["Attack is blocked", "No data leaked"]
        return ["System behaves correctly"]

    def _generate_test_data(
        self,
        feature: str,
        persona: UserPersona,
    ) -> Dict[str, Any]:
        """Generate test data for scenario."""
        return {
            "feature": feature,
            "persona": persona.value,
            "timestamp": datetime.now().isoformat(),
        }

    def _generate_tags(
        self,
        feature: str,
        scenario_type: ScenarioType,
        persona: UserPersona,
    ) -> List[str]:
        """Generate scenario tags."""
        return [
            feature.lower(),
            scenario_type.value,
            persona.value,
        ]

    def _determine_priority(
        self,
        scenario_type: ScenarioType,
        persona: UserPersona,
    ) -> str:
        """Determine scenario priority."""
        if scenario_type == ScenarioType.SECURITY:
            return "critical"
        if scenario_type == ScenarioType.HAPPY_PATH:
            return "high"
        if persona == UserPersona.MALICIOUS_USER:
            return "critical"
        return "medium"

    def _estimate_duration(self, scenario_type: ScenarioType) -> int:
        """Estimate scenario duration in ms."""
        durations = {
            ScenarioType.HAPPY_PATH: 5000,
            ScenarioType.ERROR_HANDLING: 4000,
            ScenarioType.EDGE_CASE: 6000,
            ScenarioType.SECURITY: 3000,
            ScenarioType.ACCESSIBILITY: 8000,
            ScenarioType.PERFORMANCE: 10000,
        }
        return durations.get(scenario_type, 5000)

    def _generate_edge_case_steps(
        self,
        case_name: str,
        feature: str,
    ) -> List[Dict[str, Any]]:
        """Generate steps for edge case."""
        return [
            {"action": "setup", "description": f"Prepare {case_name} condition"},
            {"action": "navigate", "target": feature},
            {"action": "execute", "description": f"Trigger {case_name}"},
            {"action": "verify", "description": "Check system response"},
        ]

    def _generate_edge_case_data(self, case_name: str) -> Dict[str, Any]:
        """Generate data for edge case."""
        return {"case": case_name, "generated_at": datetime.now().isoformat()}

    def _generate_security_steps(
        self,
        attack_name: str,
        feature: str,
        payload: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Generate steps for security test."""
        steps = [
            {"action": "navigate", "target": feature},
            {"action": "identify", "description": "Find injection point"},
        ]
        if payload:
            steps.append({"action": "inject", "payload": payload})
        steps.append({"action": "verify", "description": "Check for vulnerability"})
        return steps

    def _generate_a11y_steps(
        self,
        check_name: str,
        feature: str,
    ) -> List[Dict[str, Any]]:
        """Generate steps for accessibility test."""
        return [
            {"action": "setup", "description": f"Enable {check_name} testing"},
            {"action": "navigate", "target": feature},
            {"action": "audit", "description": f"Perform {check_name} audit"},
            {"action": "verify", "description": "Check WCAG compliance"},
        ]

    def format_scenario(self, scenario: TestScenario) -> str:
        """Format scenario as readable text."""
        lines = [
            "=" * 60,
            f"  SCENARIO: {scenario.scenario_id}",
            "=" * 60,
            "",
            f"  Name: {scenario.name}",
            f"  Type: {scenario.scenario_type.value}",
            f"  Persona: {scenario.persona.value}",
            f"  Priority: {scenario.priority}",
            "",
            f"  Description: {scenario.description}",
            "",
        ]

        # Preconditions
        lines.append("  Preconditions:")
        for pre in scenario.preconditions:
            lines.append(f"    - {pre}")

        # Steps
        lines.extend(["", "  Steps:"])
        for i, step in enumerate(scenario.steps, 1):
            action = step.get("action", "")
            target = step.get("target", step.get("description", ""))
            lines.append(f"    {i}. {action}: {target}")

        # Expected outcomes
        lines.extend(["", "  Expected Outcomes:"])
        for outcome in scenario.expected_outcomes:
            lines.append(f"    - {outcome}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_scenario_generator() -> ScenarioGenerator:
    """Create a scenario generator instance."""
    return ScenarioGenerator()
