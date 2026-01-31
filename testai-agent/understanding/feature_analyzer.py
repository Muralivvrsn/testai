"""
TestAI Agent - Feature Analyzer

Understands user requests and extracts testing intent.
Thinks like a human QA: "What are they really trying to test?"

Key Capabilities:
- Extract feature name from natural language
- Identify page type from description or elements
- Suggest testing focus based on feature type
- Detect ambiguity and ask smart clarifying questions
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import re


class UserIntent(Enum):
    """What the user is trying to do."""
    GENERATE_TESTS = "generate_tests"        # Create test cases
    ANALYZE_PAGE = "analyze_page"            # Understand a page
    SECURITY_CHECK = "security_check"        # Focus on security
    ACCESSIBILITY_CHECK = "accessibility"    # Focus on a11y
    REGRESSION_TESTS = "regression"          # Tests for regression
    SMOKE_TESTS = "smoke"                    # Quick validation
    EXPLORATORY = "exploratory"              # Open-ended exploration
    UNKNOWN = "unknown"                      # Need clarification


@dataclass
class FeatureContext:
    """
    Everything we understand about what the user wants to test.
    """
    # Core identifiers
    feature_name: str
    page_type: Optional[str] = None
    url: Optional[str] = None

    # Intent and focus
    intent: UserIntent = UserIntent.GENERATE_TESTS
    focus_areas: List[str] = field(default_factory=list)

    # Elements detected
    elements: List[Dict[str, Any]] = field(default_factory=list)
    element_summary: Dict[str, int] = field(default_factory=dict)

    # User constraints
    constraints: List[str] = field(default_factory=list)  # "no api tests", "focus on mobile"

    # What we're not sure about
    ambiguities: List[str] = field(default_factory=list)
    clarification_needed: bool = False

    # Confidence
    confidence: float = 0.5

    def __str__(self) -> str:
        parts = [f"Feature: {self.feature_name}"]
        if self.page_type:
            parts.append(f"Page type: {self.page_type}")
        parts.append(f"Intent: {self.intent.value}")
        if self.focus_areas:
            parts.append(f"Focus: {', '.join(self.focus_areas)}")
        if self.ambiguities:
            parts.append(f"Unclear: {', '.join(self.ambiguities)}")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "page_type": self.page_type,
            "url": self.url,
            "intent": self.intent.value,
            "focus_areas": self.focus_areas,
            "element_count": len(self.elements),
            "element_summary": self.element_summary,
            "constraints": self.constraints,
            "ambiguities": self.ambiguities,
            "clarification_needed": self.clarification_needed,
            "confidence": self.confidence,
        }


class FeatureAnalyzer:
    """
    Analyzes user requests to understand what they want to test.

    Usage:
        analyzer = FeatureAnalyzer()

        # From natural language
        context = analyzer.from_request("Test the login page for security issues")

        # From page elements
        context = analyzer.from_elements(elements, url="https://example.com/login")

        # Get clarification questions
        questions = analyzer.get_clarification_questions(context)
    """

    # Keywords that indicate intent
    INTENT_KEYWORDS = {
        UserIntent.GENERATE_TESTS: ["test", "tests", "testing", "generate", "create", "write"],
        UserIntent.ANALYZE_PAGE: ["analyze", "check", "review", "look at", "examine"],
        UserIntent.SECURITY_CHECK: ["security", "secure", "vulnerability", "xss", "injection", "penetration", "pentest"],
        UserIntent.ACCESSIBILITY_CHECK: ["accessibility", "a11y", "screen reader", "wcag", "aria"],
        UserIntent.REGRESSION_TESTS: ["regression", "after change", "verify still works"],
        UserIntent.SMOKE_TESTS: ["smoke", "quick", "basic", "sanity"],
        UserIntent.EXPLORATORY: ["explore", "find bugs", "break it", "edge cases"],
    }

    # Page type detection patterns
    PAGE_TYPE_PATTERNS = {
        "login": ["login", "sign in", "signin", "log in", "authenticate"],
        "signup": ["signup", "sign up", "register", "registration", "create account"],
        "checkout": ["checkout", "payment", "purchase", "buy", "cart", "order"],
        "search": ["search", "find", "query", "filter", "results"],
        "settings": ["settings", "preferences", "configuration", "account settings"],
        "profile": ["profile", "my account", "user info", "personal"],
        "dashboard": ["dashboard", "overview", "home", "main page"],
        "form": ["form", "input", "submit", "application"],
        "list": ["list", "table", "grid", "items", "products"],
        "detail": ["detail", "view", "item page", "product page"],
    }

    # Focus area suggestions based on page type
    FOCUS_SUGGESTIONS = {
        "login": ["authentication", "session handling", "brute force", "password security"],
        "signup": ["validation", "email verification", "password strength", "duplicate accounts"],
        "checkout": ["payment security", "cart integrity", "price accuracy", "address validation"],
        "search": ["query handling", "result accuracy", "performance", "special characters"],
        "settings": ["data persistence", "permission changes", "notification preferences"],
        "profile": ["data privacy", "image upload", "field validation"],
        "form": ["validation", "required fields", "error messages", "data sanitization"],
    }

    def __init__(self):
        """Initialize the analyzer."""
        pass

    def from_request(self, request: str) -> FeatureContext:
        """
        Analyze a natural language request.

        Args:
            request: User's request in natural language

        Returns:
            FeatureContext with extracted information
        """
        request_lower = request.lower()

        # Extract intent
        intent = self._detect_intent(request_lower)

        # Extract feature name
        feature_name = self._extract_feature_name(request)

        # Detect page type
        page_type = self._detect_page_type(request_lower)

        # Extract URL if present
        url = self._extract_url(request)

        # Detect focus areas
        focus_areas = self._detect_focus_areas(request_lower, page_type)

        # Detect constraints
        constraints = self._detect_constraints(request_lower)

        # Calculate confidence and ambiguities
        ambiguities = []
        confidence = 0.7

        if not feature_name or feature_name == "Unknown Feature":
            ambiguities.append("feature name unclear")
            confidence -= 0.2

        if not page_type:
            ambiguities.append("page type not identified")
            confidence -= 0.1

        if intent == UserIntent.UNKNOWN:
            ambiguities.append("intent unclear")
            confidence -= 0.2

        return FeatureContext(
            feature_name=feature_name,
            page_type=page_type,
            url=url,
            intent=intent,
            focus_areas=focus_areas,
            constraints=constraints,
            ambiguities=ambiguities,
            clarification_needed=len(ambiguities) > 0,
            confidence=max(confidence, 0.1),
        )

    def from_elements(
        self,
        elements: List[Dict[str, Any]],
        url: Optional[str] = None,
        title: Optional[str] = None,
    ) -> FeatureContext:
        """
        Analyze a page from its elements.

        Args:
            elements: List of page elements
            url: Page URL
            title: Page title

        Returns:
            FeatureContext with detected information
        """
        # Summarize elements
        element_summary = {}
        element_texts = []

        for el in elements:
            el_type = el.get("elementType", el.get("type", el.get("tag", "unknown")))
            element_summary[el_type] = element_summary.get(el_type, 0) + 1

            # Collect text for analysis
            for field in ["name", "id", "text", "placeholder", "aria-label"]:
                if el.get(field):
                    element_texts.append(el[field].lower())

        combined_text = " ".join(element_texts)

        # Detect page type from elements
        page_type = self._detect_page_type_from_elements(element_summary, combined_text)

        # Also check URL
        if not page_type and url:
            page_type = self._detect_page_type(url.lower())

        # Generate feature name
        if title:
            feature_name = title
        elif page_type:
            feature_name = f"{page_type.title()} Page"
        else:
            feature_name = "Web Page"

        # Detect focus areas
        focus_areas = self._detect_focus_from_elements(element_summary, combined_text)

        # Calculate confidence
        confidence = 0.6
        ambiguities = []

        if not page_type:
            ambiguities.append("page type unclear from elements")
            confidence -= 0.1

        if len(elements) < 3:
            ambiguities.append("very few elements detected")
            confidence -= 0.1

        return FeatureContext(
            feature_name=feature_name,
            page_type=page_type,
            url=url,
            intent=UserIntent.GENERATE_TESTS,
            focus_areas=focus_areas,
            elements=elements,
            element_summary=element_summary,
            ambiguities=ambiguities,
            clarification_needed=len(ambiguities) > 0,
            confidence=max(confidence, 0.1),
        )

    def get_clarification_questions(self, context: FeatureContext) -> List[Dict[str, Any]]:
        """
        Generate smart clarification questions.

        Args:
            context: Current feature context

        Returns:
            List of questions with options
        """
        questions = []

        # If feature name is unclear
        if "feature name unclear" in context.ambiguities:
            questions.append({
                "question": "What feature or page would you like me to test?",
                "type": "open",
                "priority": "high",
                "examples": ["User login", "Checkout flow", "Search functionality"],
            })

        # If page type is unclear
        if "page type not identified" in context.ambiguities:
            questions.append({
                "question": "What type of page is this?",
                "type": "choice",
                "priority": "high",
                "options": ["Login", "Signup", "Checkout", "Search", "Form", "Other"],
            })

        # If intent is unclear
        if "intent unclear" in context.ambiguities:
            questions.append({
                "question": "What kind of testing would you like me to focus on?",
                "type": "choice",
                "priority": "medium",
                "options": [
                    "Comprehensive tests (all categories)",
                    "Security focused",
                    "Quick smoke tests",
                    "Accessibility check",
                ],
            })

        # Suggest focus areas if page type is known but no focus specified
        if context.page_type and not context.focus_areas:
            suggested = self.FOCUS_SUGGESTIONS.get(context.page_type, [])
            if suggested:
                questions.append({
                    "question": f"Any specific areas to focus on for this {context.page_type} page?",
                    "type": "multi-choice",
                    "priority": "low",
                    "options": suggested[:4],
                    "default": "All of the above",
                })

        return questions

    def _detect_intent(self, text: str) -> UserIntent:
        """Detect user intent from text."""
        for intent, keywords in self.INTENT_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return intent
        return UserIntent.UNKNOWN

    def _extract_feature_name(self, text: str) -> str:
        """Extract feature name from text."""
        # Common patterns
        patterns = [
            r"test(?:ing)?\s+(?:the\s+)?([a-z][a-z\s]+?)(?:\s+page|\s+feature|\s+flow|\s+for|\.|$)",
            r"(?:for|check|analyze)\s+(?:the\s+)?([a-z][a-z\s]+?)(?:\s+page|\s+feature|\s+flow|\.|$)",
            r"([a-z]+)\s+(?:page|feature|form|flow)",
        ]

        text_lower = text.lower()

        for pattern in patterns:
            match = re.search(pattern, text_lower)
            if match:
                name = match.group(1).strip()
                # Clean up common words
                name = re.sub(r'\b(the|a|an|some|any)\b', '', name).strip()
                if name and len(name) > 2:
                    return name.title()

        # Check for page type keywords as fallback
        for page_type in self.PAGE_TYPE_PATTERNS:
            if page_type in text_lower:
                return f"{page_type.title()} Feature"

        return "Unknown Feature"

    def _detect_page_type(self, text: str) -> Optional[str]:
        """Detect page type from text."""
        for page_type, patterns in self.PAGE_TYPE_PATTERNS.items():
            if any(p in text for p in patterns):
                return page_type
        return None

    def _detect_page_type_from_elements(
        self,
        element_summary: Dict[str, int],
        text: str,
    ) -> Optional[str]:
        """Detect page type from element patterns."""
        # Login page indicators
        if "password" in text and ("email" in text or "username" in text):
            if "confirm" in text or "verify" in text:
                return "signup"
            return "login"

        # Checkout indicators
        if "card" in text or "payment" in text or "cvv" in text:
            return "checkout"

        # Search indicators
        if "search" in text:
            return "search"

        # Form with many inputs
        input_count = element_summary.get("input", 0)
        if input_count > 5:
            return "form"

        return None

    def _detect_focus_areas(self, text: str, page_type: Optional[str]) -> List[str]:
        """Detect testing focus areas from text."""
        focus = []

        # Explicit focus keywords
        focus_keywords = {
            "security": ["security", "secure", "xss", "injection", "vulnerability"],
            "accessibility": ["accessibility", "a11y", "screen reader", "wcag"],
            "performance": ["performance", "speed", "load time", "fast"],
            "validation": ["validation", "validate", "verify", "check"],
            "edge cases": ["edge case", "corner case", "unusual", "extreme"],
            "error handling": ["error", "fail", "invalid", "wrong"],
        }

        for area, keywords in focus_keywords.items():
            if any(kw in text for kw in keywords):
                focus.append(area)

        # Add page-type specific focus if no explicit focus
        if not focus and page_type:
            suggested = self.FOCUS_SUGGESTIONS.get(page_type, [])
            focus = suggested[:2]  # Take top 2 suggestions

        return focus

    def _detect_focus_from_elements(
        self,
        element_summary: Dict[str, int],
        text: str,
    ) -> List[str]:
        """Detect focus areas from element patterns."""
        focus = []

        # Password fields suggest security focus
        if "password" in text:
            focus.append("authentication security")

        # Many inputs suggest validation focus
        input_count = element_summary.get("input", 0)
        if input_count > 3:
            focus.append("input validation")

        # File upload suggests upload security
        if "file" in text or "upload" in text:
            focus.append("file upload security")

        # Payment-related
        if "card" in text or "payment" in text:
            focus.append("payment security")

        return focus

    def _detect_constraints(self, text: str) -> List[str]:
        """Detect user constraints from text."""
        constraints = []

        constraint_patterns = [
            (r"no\s+(api|backend|server)\s+tests?", "no api tests"),
            (r"only\s+(ui|frontend|visual)", "frontend only"),
            (r"(mobile|responsive)", "include mobile"),
            (r"skip\s+(security|a11y|accessibility)", "skip security"),
            (r"quick|fast|brief", "brief tests"),
        ]

        for pattern, constraint in constraint_patterns:
            if re.search(pattern, text):
                constraints.append(constraint)

        return constraints

    def _extract_url(self, text: str) -> Optional[str]:
        """Extract URL from text."""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        match = re.search(url_pattern, text)
        return match.group(0) if match else None


def analyze_request(request: str) -> FeatureContext:
    """Quick helper to analyze a request."""
    analyzer = FeatureAnalyzer()
    return analyzer.from_request(request)


def analyze_page(elements: List[Dict], url: Optional[str] = None) -> FeatureContext:
    """Quick helper to analyze page elements."""
    analyzer = FeatureAnalyzer()
    return analyzer.from_elements(elements, url)
