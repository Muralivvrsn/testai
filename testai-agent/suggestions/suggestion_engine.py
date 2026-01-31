"""
TestAI Agent - Suggestion Engine

Proactively analyzes test suites and suggests improvements,
missing tests, and coverage opportunities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class SuggestionType(Enum):
    """Types of suggestions."""
    MISSING_TEST = "missing_test"
    COVERAGE_GAP = "coverage_gap"
    SECURITY_CONCERN = "security_concern"
    EDGE_CASE = "edge_case"
    PERFORMANCE = "performance"
    ACCESSIBILITY = "accessibility"
    IMPROVEMENT = "improvement"
    DUPLICATE = "duplicate"
    REDUNDANT = "redundant"


class SuggestionPriority(Enum):
    """Priority levels for suggestions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SuggestionCategory(Enum):
    """Categories for suggestions."""
    SECURITY = "security"
    FUNCTIONAL = "functional"
    VALIDATION = "validation"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    USABILITY = "usability"
    ERROR_HANDLING = "error_handling"
    EDGE_CASES = "edge_cases"


@dataclass
class Suggestion:
    """A test suggestion."""
    id: str
    suggestion_type: SuggestionType
    priority: SuggestionPriority
    category: SuggestionCategory
    title: str
    description: str
    rationale: str
    proposed_test: Optional[Dict[str, Any]] = None
    affected_test_ids: List[str] = field(default_factory=list)
    confidence: float = 0.8
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)


@dataclass
class AnalysisContext:
    """Context for suggestion analysis."""
    page_type: str
    feature: str
    existing_tests: List[Dict[str, Any]]
    test_categories: Set[str]
    test_priorities: Dict[str, int]
    keywords_found: Set[str]


class SuggestionEngine:
    """
    Intelligent engine that analyzes test suites and generates suggestions.

    This is the proactive brain of TestAI - it identifies what's missing
    before the user even asks.
    """

    # Required test patterns by page type
    REQUIRED_PATTERNS = {
        "login": {
            "security": [
                ("sql injection", "Test SQL injection in login fields"),
                ("xss", "Test XSS in login fields"),
                ("brute force", "Test brute force protection"),
                ("session", "Test session management"),
                ("csrf", "Test CSRF protection"),
            ],
            "functional": [
                ("valid credentials", "Test login with valid credentials"),
                ("invalid password", "Test login with invalid password"),
                ("invalid email", "Test login with invalid email"),
                ("remember me", "Test remember me functionality"),
            ],
            "validation": [
                ("email format", "Test email format validation"),
                ("empty fields", "Test empty field validation"),
                ("password requirements", "Test password requirements"),
            ],
            "accessibility": [
                ("screen reader", "Test screen reader compatibility"),
                ("keyboard", "Test keyboard navigation"),
            ],
        },
        "signup": {
            "security": [
                ("injection", "Test injection vulnerabilities"),
                ("password strength", "Test password strength requirements"),
                ("email verification", "Test email verification"),
            ],
            "functional": [
                ("valid registration", "Test valid registration flow"),
                ("duplicate email", "Test duplicate email handling"),
                ("terms acceptance", "Test terms acceptance"),
            ],
            "validation": [
                ("field validation", "Test field validation"),
                ("password match", "Test password confirmation match"),
            ],
        },
        "checkout": {
            "security": [
                ("payment", "Test payment data security"),
                ("card validation", "Test card validation"),
                ("ssl", "Test SSL/TLS encryption"),
            ],
            "functional": [
                ("order placement", "Test order placement"),
                ("cart update", "Test cart updates"),
                ("shipping", "Test shipping options"),
            ],
            "error_handling": [
                ("payment failure", "Test payment failure handling"),
                ("network error", "Test network error recovery"),
            ],
        },
        "search": {
            "functional": [
                ("basic search", "Test basic search functionality"),
                ("no results", "Test no results handling"),
                ("filters", "Test search filters"),
            ],
            "security": [
                ("injection", "Test search injection"),
            ],
            "performance": [
                ("response time", "Test search response time"),
                ("large results", "Test large result set handling"),
            ],
        },
        "profile": {
            "security": [
                ("data exposure", "Test sensitive data protection"),
                ("authorization", "Test authorization controls"),
            ],
            "functional": [
                ("update profile", "Test profile updates"),
                ("change password", "Test password change"),
            ],
        },
    }

    # Edge cases to suggest
    EDGE_CASES = {
        "login": [
            "Test login with maximum length credentials",
            "Test login with special characters in password",
            "Test login with unicode characters",
            "Test login immediately after logout",
            "Test login with expired session token",
            "Test concurrent login from multiple devices",
        ],
        "signup": [
            "Test registration with email at boundary length",
            "Test registration with international phone numbers",
            "Test double-submission of registration form",
            "Test registration with special characters in name",
        ],
        "checkout": [
            "Test checkout with expired card",
            "Test checkout with insufficient funds",
            "Test checkout with address at boundary length",
            "Test checkout timeout during payment",
            "Test checkout with cart modification during payment",
        ],
        "search": [
            "Test search with empty query",
            "Test search with very long query",
            "Test search with only special characters",
            "Test search with HTML tags in query",
        ],
        "profile": [
            "Test profile update with same data",
            "Test profile with invalid image format",
            "Test profile with oversized image",
        ],
    }

    # Security concerns to check
    SECURITY_CONCERNS = [
        ("sql", "SQL injection vulnerability"),
        ("xss", "Cross-site scripting vulnerability"),
        ("csrf", "CSRF protection missing"),
        ("injection", "Code injection vulnerability"),
        ("auth", "Authentication weakness"),
        ("session", "Session management issue"),
        ("password", "Password security concern"),
        ("encryption", "Encryption/SSL issue"),
        ("sensitive", "Sensitive data exposure"),
        ("rate limit", "Rate limiting missing"),
    ]

    def __init__(self):
        """Initialize the suggestion engine."""
        self._suggestion_count = 0
        self._suggestions: List[Suggestion] = []

    def analyze(
        self,
        tests: List[Dict[str, Any]],
        page_type: str = "generic",
        feature: str = "Feature",
    ) -> List[Suggestion]:
        """Analyze test suite and generate suggestions."""
        # Build analysis context
        context = self._build_context(tests, page_type, feature)

        suggestions = []

        # Check for missing required tests
        suggestions.extend(self._find_missing_tests(context))

        # Check for security concerns
        suggestions.extend(self._find_security_gaps(context))

        # Check for edge cases
        suggestions.extend(self._find_missing_edge_cases(context))

        # Check for improvements
        suggestions.extend(self._find_improvements(context))

        # Check for duplicates/redundancies
        suggestions.extend(self._find_redundancies(context))

        # Check for accessibility gaps
        suggestions.extend(self._find_accessibility_gaps(context))

        # Store suggestions
        self._suggestions.extend(suggestions)

        return suggestions

    def _build_context(
        self,
        tests: List[Dict[str, Any]],
        page_type: str,
        feature: str,
    ) -> AnalysisContext:
        """Build analysis context from tests."""
        # Extract categories
        categories = set()
        for test in tests:
            cat = test.get("category", "functional")
            categories.add(cat)

        # Count priorities
        priorities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for test in tests:
            priority = test.get("priority", "medium")
            priorities[priority] = priorities.get(priority, 0) + 1

        # Extract keywords from test titles/descriptions
        keywords = set()
        for test in tests:
            title = test.get("title", "").lower()
            description = test.get("description", "").lower()
            text = f"{title} {description}"

            # Extract significant words
            words = re.findall(r'\b[a-z]{3,}\b', text)
            keywords.update(words)

        return AnalysisContext(
            page_type=page_type,
            feature=feature,
            existing_tests=tests,
            test_categories=categories,
            test_priorities=priorities,
            keywords_found=keywords,
        )

    def _find_missing_tests(self, context: AnalysisContext) -> List[Suggestion]:
        """Find missing required tests."""
        suggestions = []
        page_type = context.page_type

        if page_type not in self.REQUIRED_PATTERNS:
            return suggestions

        patterns = self.REQUIRED_PATTERNS[page_type]

        for category, required_tests in patterns.items():
            for keyword, description in required_tests:
                # Check if any existing test covers this
                covered = False
                for test in context.existing_tests:
                    title = test.get("title", "").lower()
                    desc = test.get("description", "").lower()
                    if keyword.lower() in title or keyword.lower() in desc:
                        covered = True
                        break

                if not covered:
                    self._suggestion_count += 1
                    priority = SuggestionPriority.CRITICAL if category == "security" else SuggestionPriority.HIGH

                    suggestions.append(Suggestion(
                        id=f"SUG-{self._suggestion_count:04d}",
                        suggestion_type=SuggestionType.MISSING_TEST,
                        priority=priority,
                        category=SuggestionCategory[category.upper()] if category.upper() in SuggestionCategory.__members__ else SuggestionCategory.FUNCTIONAL,
                        title=f"Missing: {description}",
                        description=f"No test found covering '{keyword}' for {page_type} page",
                        rationale=f"Tests for '{keyword}' are essential for {page_type} pages to ensure proper coverage",
                        proposed_test={
                            "title": description,
                            "category": category,
                            "priority": priority.value,
                            "keywords": [keyword, page_type],
                        },
                        confidence=0.9,
                        tags=[keyword, category, page_type],
                    ))

        return suggestions

    def _find_security_gaps(self, context: AnalysisContext) -> List[Suggestion]:
        """Find security testing gaps."""
        suggestions = []

        # Check for security category tests
        security_tests = [
            t for t in context.existing_tests
            if t.get("category") == "security"
        ]

        # If no security tests at all
        if not security_tests:
            self._suggestion_count += 1
            suggestions.append(Suggestion(
                id=f"SUG-{self._suggestion_count:04d}",
                suggestion_type=SuggestionType.SECURITY_CONCERN,
                priority=SuggestionPriority.CRITICAL,
                category=SuggestionCategory.SECURITY,
                title="No Security Tests Found",
                description="The test suite has no security-focused tests",
                rationale="Security testing is critical for any web application to prevent vulnerabilities",
                proposed_test={
                    "title": "Add security test suite",
                    "category": "security",
                    "priority": "critical",
                },
                confidence=1.0,
                tags=["security", "critical"],
            ))
            return suggestions

        # Check for specific security concerns
        for keyword, concern in self.SECURITY_CONCERNS:
            found = False
            for test in security_tests:
                title = test.get("title", "").lower()
                desc = test.get("description", "").lower()
                if keyword in title or keyword in desc:
                    found = True
                    break

            # Only suggest if relevant to page type
            if not found and self._is_relevant_security(keyword, context.page_type):
                self._suggestion_count += 1
                suggestions.append(Suggestion(
                    id=f"SUG-{self._suggestion_count:04d}",
                    suggestion_type=SuggestionType.SECURITY_CONCERN,
                    priority=SuggestionPriority.HIGH,
                    category=SuggestionCategory.SECURITY,
                    title=f"Security Gap: {concern}",
                    description=f"No test found for {concern}",
                    rationale=f"Testing for {keyword} is important to prevent security vulnerabilities",
                    proposed_test={
                        "title": f"Test {concern}",
                        "category": "security",
                        "priority": "high",
                    },
                    confidence=0.75,
                    tags=["security", keyword],
                ))

        return suggestions

    def _is_relevant_security(self, keyword: str, page_type: str) -> bool:
        """Check if security concern is relevant to page type."""
        relevance = {
            "sql": ["login", "signup", "search", "profile"],
            "xss": ["login", "signup", "search", "profile"],
            "csrf": ["login", "signup", "checkout", "profile"],
            "injection": ["login", "signup", "search"],
            "auth": ["login", "signup", "profile"],
            "session": ["login", "profile", "checkout"],
            "password": ["login", "signup", "profile"],
            "encryption": ["checkout", "profile"],
            "sensitive": ["profile", "checkout"],
            "rate limit": ["login", "signup", "search"],
        }
        return page_type in relevance.get(keyword, [])

    def _find_missing_edge_cases(self, context: AnalysisContext) -> List[Suggestion]:
        """Find missing edge case tests."""
        suggestions = []
        page_type = context.page_type

        if page_type not in self.EDGE_CASES:
            return suggestions

        edge_cases = self.EDGE_CASES[page_type]

        for edge_case in edge_cases:
            # Check if any test covers this
            edge_keywords = set(re.findall(r'\b[a-z]{3,}\b', edge_case.lower()))

            covered = False
            for test in context.existing_tests:
                title = test.get("title", "").lower()
                desc = test.get("description", "").lower()
                test_keywords = set(re.findall(r'\b[a-z]{3,}\b', f"{title} {desc}"))

                # If significant overlap in keywords
                if len(edge_keywords & test_keywords) >= 3:
                    covered = True
                    break

            if not covered:
                self._suggestion_count += 1
                suggestions.append(Suggestion(
                    id=f"SUG-{self._suggestion_count:04d}",
                    suggestion_type=SuggestionType.EDGE_CASE,
                    priority=SuggestionPriority.MEDIUM,
                    category=SuggestionCategory.EDGE_CASES,
                    title=f"Edge Case: {edge_case[:50]}...",
                    description=edge_case,
                    rationale="Edge cases often reveal unexpected bugs that normal testing misses",
                    proposed_test={
                        "title": edge_case,
                        "category": "edge_case",
                        "priority": "medium",
                    },
                    confidence=0.7,
                    tags=["edge_case", page_type],
                ))

        return suggestions

    def _find_improvements(self, context: AnalysisContext) -> List[Suggestion]:
        """Find test improvement opportunities."""
        suggestions = []

        # Check priority distribution
        priorities = context.test_priorities
        total = sum(priorities.values())

        if total > 0:
            # If too many low priority tests
            low_ratio = priorities.get("low", 0) / total
            if low_ratio > 0.5:
                self._suggestion_count += 1
                suggestions.append(Suggestion(
                    id=f"SUG-{self._suggestion_count:04d}",
                    suggestion_type=SuggestionType.IMPROVEMENT,
                    priority=SuggestionPriority.MEDIUM,
                    category=SuggestionCategory.FUNCTIONAL,
                    title="Review Test Priorities",
                    description=f"{int(low_ratio*100)}% of tests are low priority",
                    rationale="A high ratio of low-priority tests may indicate missing critical test coverage",
                    confidence=0.6,
                    tags=["priority", "improvement"],
                ))

            # If no critical tests
            if priorities.get("critical", 0) == 0:
                self._suggestion_count += 1
                suggestions.append(Suggestion(
                    id=f"SUG-{self._suggestion_count:04d}",
                    suggestion_type=SuggestionType.IMPROVEMENT,
                    priority=SuggestionPriority.HIGH,
                    category=SuggestionCategory.FUNCTIONAL,
                    title="No Critical Tests Defined",
                    description="Test suite has no tests marked as critical priority",
                    rationale="Critical tests help identify must-pass scenarios before deployment",
                    confidence=0.8,
                    tags=["priority", "critical"],
                ))

        # Check for tests without steps
        tests_without_steps = [
            t for t in context.existing_tests
            if not t.get("steps") or len(t.get("steps", [])) == 0
        ]
        if tests_without_steps:
            self._suggestion_count += 1
            suggestions.append(Suggestion(
                id=f"SUG-{self._suggestion_count:04d}",
                suggestion_type=SuggestionType.IMPROVEMENT,
                priority=SuggestionPriority.LOW,
                category=SuggestionCategory.FUNCTIONAL,
                title="Tests Without Steps",
                description=f"{len(tests_without_steps)} tests have no defined steps",
                rationale="Tests with clear steps are easier to execute and maintain",
                affected_test_ids=[t.get("id", "") for t in tests_without_steps],
                confidence=0.9,
                tags=["improvement", "steps"],
            ))

        return suggestions

    def _find_redundancies(self, context: AnalysisContext) -> List[Suggestion]:
        """Find duplicate or redundant tests."""
        suggestions = []

        # Simple similarity check based on titles
        tests = context.existing_tests
        checked_pairs = set()

        for i, test1 in enumerate(tests):
            title1 = test1.get("title", "").lower()
            words1 = set(re.findall(r'\b[a-z]{3,}\b', title1))

            for j, test2 in enumerate(tests):
                if i >= j:
                    continue

                pair_key = (i, j)
                if pair_key in checked_pairs:
                    continue
                checked_pairs.add(pair_key)

                title2 = test2.get("title", "").lower()
                words2 = set(re.findall(r'\b[a-z]{3,}\b', title2))

                # Calculate similarity
                if words1 and words2:
                    intersection = len(words1 & words2)
                    union = len(words1 | words2)
                    similarity = intersection / union if union > 0 else 0

                    if similarity > 0.7:  # High similarity threshold
                        self._suggestion_count += 1
                        suggestions.append(Suggestion(
                            id=f"SUG-{self._suggestion_count:04d}",
                            suggestion_type=SuggestionType.DUPLICATE,
                            priority=SuggestionPriority.LOW,
                            category=SuggestionCategory.FUNCTIONAL,
                            title="Potentially Duplicate Tests",
                            description=f"Tests '{test1.get('title')}' and '{test2.get('title')}' appear similar",
                            rationale="Duplicate tests waste execution time and add maintenance burden",
                            affected_test_ids=[test1.get("id", ""), test2.get("id", "")],
                            confidence=similarity,
                            tags=["duplicate", "cleanup"],
                        ))

        return suggestions

    def _find_accessibility_gaps(self, context: AnalysisContext) -> List[Suggestion]:
        """Find accessibility testing gaps."""
        suggestions = []

        # Check if any accessibility tests exist
        accessibility_tests = [
            t for t in context.existing_tests
            if t.get("category") == "accessibility" or
            any(kw in t.get("title", "").lower() for kw in ["accessibility", "a11y", "screen reader", "keyboard"])
        ]

        if not accessibility_tests:
            self._suggestion_count += 1
            suggestions.append(Suggestion(
                id=f"SUG-{self._suggestion_count:04d}",
                suggestion_type=SuggestionType.COVERAGE_GAP,
                priority=SuggestionPriority.MEDIUM,
                category=SuggestionCategory.ACCESSIBILITY,
                title="No Accessibility Tests",
                description="Test suite has no accessibility-focused tests",
                rationale="Accessibility testing ensures your application is usable by everyone",
                proposed_test={
                    "title": "Test keyboard navigation",
                    "category": "accessibility",
                    "priority": "medium",
                },
                confidence=0.85,
                tags=["accessibility", "a11y"],
            ))

        return suggestions

    def get_suggestions_by_priority(
        self,
        priority: SuggestionPriority,
    ) -> List[Suggestion]:
        """Get suggestions filtered by priority."""
        return [s for s in self._suggestions if s.priority == priority]

    def get_suggestions_by_type(
        self,
        suggestion_type: SuggestionType,
    ) -> List[Suggestion]:
        """Get suggestions filtered by type."""
        return [s for s in self._suggestions if s.suggestion_type == suggestion_type]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all suggestions."""
        if not self._suggestions:
            return {
                "total": 0,
                "by_priority": {},
                "by_type": {},
                "by_category": {},
            }

        return {
            "total": len(self._suggestions),
            "by_priority": {
                p.value: sum(1 for s in self._suggestions if s.priority == p)
                for p in SuggestionPriority
            },
            "by_type": {
                t.value: sum(1 for s in self._suggestions if s.suggestion_type == t)
                for t in SuggestionType
            },
            "by_category": {
                c.value: sum(1 for s in self._suggestions if s.category == c)
                for c in SuggestionCategory
            },
        }

    def format_suggestions(self, suggestions: List[Suggestion]) -> str:
        """Format suggestions as a readable report."""
        if not suggestions:
            return "No suggestions generated."

        lines = [
            "=" * 60,
            "  TEST SUGGESTIONS",
            "=" * 60,
            "",
        ]

        # Group by priority
        for priority in SuggestionPriority:
            priority_suggestions = [s for s in suggestions if s.priority == priority]
            if priority_suggestions:
                priority_icon = {
                    SuggestionPriority.CRITICAL: "🔴",
                    SuggestionPriority.HIGH: "🟠",
                    SuggestionPriority.MEDIUM: "🟡",
                    SuggestionPriority.LOW: "🟢",
                }
                lines.append(f"{priority_icon[priority]} {priority.value.upper()} ({len(priority_suggestions)})")
                lines.append("-" * 40)

                for s in priority_suggestions:
                    lines.append(f"  [{s.id}] {s.title}")
                    lines.append(f"     {s.description[:60]}...")
                    lines.append(f"     Confidence: {s.confidence:.0%}")
                    lines.append("")

        # Summary
        lines.extend([
            "=" * 60,
            f"Total Suggestions: {len(suggestions)}",
            "=" * 60,
        ])

        return "\n".join(lines)

    def clear(self):
        """Clear all suggestions."""
        self._suggestions = []
        self._suggestion_count = 0


def create_suggestion_engine() -> SuggestionEngine:
    """Create a suggestion engine instance."""
    return SuggestionEngine()
