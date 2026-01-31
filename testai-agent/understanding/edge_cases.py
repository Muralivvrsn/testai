"""
TestAI Agent - Edge Case Detection

Automatically identifies edge cases that humans often miss.
This is where we beat human QA - pattern recognition at scale.

Edge Case Categories:
1. Boundary conditions (min/max values)
2. State transitions (empty → filled, logged out → in)
3. Timing issues (race conditions, timeouts)
4. Data edge cases (unicode, special chars, injection)
5. User behavior patterns (multi-tab, back button)
6. Integration points (third-party failures, API timeouts)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import re


class EdgeCaseCategory(Enum):
    """Categories of edge cases."""
    BOUNDARY = "boundary"           # Min/max values, limits
    STATE = "state"                 # State transitions
    TIMING = "timing"               # Race conditions, timeouts
    DATA = "data"                   # Special characters, injection
    BEHAVIOR = "behavior"           # User behavior patterns
    INTEGRATION = "integration"     # External dependencies
    SECURITY = "security"           # Security-specific edge cases
    ACCESSIBILITY = "accessibility" # A11y edge cases


@dataclass
class EdgeCase:
    """A detected edge case."""
    title: str
    description: str
    category: EdgeCaseCategory
    severity: str  # critical, high, medium, low
    test_suggestion: str
    test_data: Optional[Dict[str, Any]] = None


@dataclass
class EdgeCaseAnalysis:
    """Analysis results with detected edge cases."""
    feature: str
    page_type: Optional[str]
    edge_cases: List[EdgeCase] = field(default_factory=list)
    coverage_score: float = 0.0  # 0-1, how many patterns we checked

    def critical_count(self) -> int:
        return sum(1 for ec in self.edge_cases if ec.severity == "critical")

    def by_category(self) -> Dict[str, List[EdgeCase]]:
        result = {}
        for ec in self.edge_cases:
            cat = ec.category.value
            if cat not in result:
                result[cat] = []
            result[cat].append(ec)
        return result


class EdgeCaseDetector:
    """
    Detects potential edge cases based on page type and elements.

    This is where TestAI shines - finding edge cases humans miss through
    systematic pattern application.

    Usage:
        detector = EdgeCaseDetector()

        # From page type
        analysis = detector.analyze_page_type("login")

        # From elements
        analysis = detector.analyze_elements(elements, page_type="form")

        # Get all edge cases
        for ec in analysis.edge_cases:
            print(f"{ec.severity}: {ec.title}")
    """

    # Universal edge cases that apply to almost any feature
    UNIVERSAL_EDGE_CASES = [
        EdgeCase(
            title="Empty state handling",
            description="What happens when there's no data?",
            category=EdgeCaseCategory.STATE,
            severity="medium",
            test_suggestion="Navigate to the feature with no prior data and verify graceful empty state",
        ),
        EdgeCase(
            title="Double-click/double-submit",
            description="Rapidly clicking buttons can cause duplicate submissions",
            category=EdgeCaseCategory.BEHAVIOR,
            severity="high",
            test_suggestion="Click the primary action button multiple times rapidly",
        ),
        EdgeCase(
            title="Browser back button after submission",
            description="Using back after form submit can cause re-submission issues",
            category=EdgeCaseCategory.BEHAVIOR,
            severity="medium",
            test_suggestion="Complete an action, press browser back, observe behavior",
        ),
        EdgeCase(
            title="Session timeout during interaction",
            description="What if the session expires while user is filling a form?",
            category=EdgeCaseCategory.TIMING,
            severity="medium",
            test_suggestion="Start an action, wait for session to expire, try to complete",
        ),
        EdgeCase(
            title="Network interruption",
            description="What if network drops mid-request?",
            category=EdgeCaseCategory.INTEGRATION,
            severity="high",
            test_suggestion="Use DevTools to simulate offline mode during submission",
        ),
        EdgeCase(
            title="Slow network response",
            description="UI should handle slow responses gracefully",
            category=EdgeCaseCategory.TIMING,
            severity="medium",
            test_suggestion="Throttle network to slow 3G and observe loading states",
        ),
    ]

    # Page-type specific edge case patterns
    PAGE_EDGE_CASES = {
        "login": [
            EdgeCase(
                title="Email with plus sign (aliases)",
                description="Email aliases like user+test@mail.com should work",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Login with 'user+alias@company.com'",
                test_data={"email": "user+alias@company.com"},
            ),
            EdgeCase(
                title="Password with special characters",
                description="Passwords with !@#$%^&*() should be accepted",
                category=EdgeCaseCategory.DATA,
                severity="high",
                test_suggestion="Create account with password 'P@ss!w0rd#2024'",
                test_data={"password": "P@ss!w0rd#2024"},
            ),
            EdgeCase(
                title="Unicode in password",
                description="Emoji and international chars in password",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Test password with emoji: 'Secure🔐Pass日本語'",
                test_data={"password": "Secure🔐Pass日本語"},
            ),
            EdgeCase(
                title="Copy-paste password",
                description="Users should be able to paste passwords (for password managers)",
                category=EdgeCaseCategory.BEHAVIOR,
                severity="high",
                test_suggestion="Copy password to clipboard and paste into field",
            ),
            EdgeCase(
                title="Remember me on public computer",
                description="'Remember me' warning for shared computers",
                category=EdgeCaseCategory.SECURITY,
                severity="medium",
                test_suggestion="Check if 'remember me' shows security warning",
            ),
            EdgeCase(
                title="Multiple login tabs",
                description="Logging in from multiple tabs simultaneously",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Open login in 2 tabs, login in one, observe other",
            ),
            EdgeCase(
                title="Account lockout timing",
                description="Account lockout after N failed attempts",
                category=EdgeCaseCategory.SECURITY,
                severity="critical",
                test_suggestion="Try 5 wrong passwords, then try correct one",
            ),
            EdgeCase(
                title="Case sensitivity in email",
                description="Email should be case-insensitive",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Login with 'USER@Email.COM' for account 'user@email.com'",
            ),
        ],

        "signup": [
            EdgeCase(
                title="Very long name",
                description="Names can be 100+ characters in some cultures",
                category=EdgeCaseCategory.BOUNDARY,
                severity="low",
                test_suggestion="Enter 100-character name",
                test_data={"name": "A" * 100},
            ),
            EdgeCase(
                title="Name with special characters",
                description="O'Brien, José, Müller should all work",
                category=EdgeCaseCategory.DATA,
                severity="high",
                test_suggestion="Register with name: O'Brien-Müller",
                test_data={"name": "O'Brien-Müller"},
            ),
            EdgeCase(
                title="Already registered email",
                description="Clear error for duplicate email",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Try to register with existing email",
            ),
            EdgeCase(
                title="Password confirmation mismatch",
                description="Passwords don't match should show clear error",
                category=EdgeCaseCategory.DATA,
                severity="high",
                test_suggestion="Enter different passwords in password and confirm fields",
            ),
            EdgeCase(
                title="Terms checkbox required",
                description="Submitting without accepting terms",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Fill all fields but leave terms unchecked, submit",
            ),
            EdgeCase(
                title="Email verification timeout",
                description="What if user clicks verification link after it expires?",
                category=EdgeCaseCategory.TIMING,
                severity="medium",
                test_suggestion="Wait for verification link to expire, then click it",
            ),
            EdgeCase(
                title="Weak password feedback",
                description="Real-time password strength indicator",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Enter '123456' and verify strength indicator shows weak",
            ),
        ],

        "checkout": [
            EdgeCase(
                title="Item goes out of stock during checkout",
                description="Cart item becomes unavailable mid-checkout",
                category=EdgeCaseCategory.STATE,
                severity="critical",
                test_suggestion="Start checkout, have another user buy last item, complete checkout",
            ),
            EdgeCase(
                title="Price change during checkout",
                description="Price updates while user is checking out",
                category=EdgeCaseCategory.STATE,
                severity="critical",
                test_suggestion="Start checkout, change price in admin, complete checkout",
            ),
            EdgeCase(
                title="Coupon code expired",
                description="Using an expired coupon code",
                category=EdgeCaseCategory.TIMING,
                severity="high",
                test_suggestion="Apply coupon 'EXPIRED2023' and verify error message",
                test_data={"coupon": "EXPIRED2023"},
            ),
            EdgeCase(
                title="Coupon already used (single-use)",
                description="Trying to use a single-use coupon twice",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Apply same single-use coupon on second order",
            ),
            EdgeCase(
                title="Payment timeout",
                description="Payment processor takes too long",
                category=EdgeCaseCategory.TIMING,
                severity="critical",
                test_suggestion="Simulate slow payment response, verify UI doesn't freeze",
            ),
            EdgeCase(
                title="Double order submission",
                description="Clicking 'Place Order' twice quickly",
                category=EdgeCaseCategory.BEHAVIOR,
                severity="critical",
                test_suggestion="Click Place Order rapidly, verify only one order created",
            ),
            EdgeCase(
                title="International address format",
                description="Addresses outside US have different formats",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Enter UK address with postcode: 'SW1A 1AA'",
                test_data={"address": "10 Downing Street, London, SW1A 1AA, UK"},
            ),
            EdgeCase(
                title="Tax calculation changes",
                description="Shipping address change affects tax",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Enter CA address, change to OR (no sales tax), verify tax updates",
            ),
        ],

        "search": [
            EdgeCase(
                title="Search with only spaces",
                description="Searching for just whitespace",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Enter '     ' and submit search",
                test_data={"query": "     "},
            ),
            EdgeCase(
                title="Very long search query",
                description="Search with 1000+ characters",
                category=EdgeCaseCategory.BOUNDARY,
                severity="low",
                test_suggestion="Paste a 1000-character string into search",
                test_data={"query": "a" * 1000},
            ),
            EdgeCase(
                title="Search with quotes",
                description="Exact phrase search with quotes",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Search for '\"exact phrase\"' with quotes",
            ),
            EdgeCase(
                title="Search with boolean operators",
                description="Using AND, OR, NOT in search",
                category=EdgeCaseCategory.DATA,
                severity="low",
                test_suggestion="Search for 'blue AND shoes NOT sneakers'",
            ),
            EdgeCase(
                title="Rapid search queries",
                description="Typing fast with autocomplete",
                category=EdgeCaseCategory.TIMING,
                severity="medium",
                test_suggestion="Type quickly and verify debouncing works",
            ),
            EdgeCase(
                title="Search result pagination edge",
                description="Exactly at page boundary (10, 20, etc.)",
                category=EdgeCaseCategory.BOUNDARY,
                severity="low",
                test_suggestion="Search for something with exactly 20 results, verify pagination",
            ),
            EdgeCase(
                title="Zero results state",
                description="No results should show helpful message",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Search for 'xyznonexistent123'",
            ),
        ],

        "settings": [
            EdgeCase(
                title="Unsaved changes warning",
                description="Navigating away with unsaved changes",
                category=EdgeCaseCategory.BEHAVIOR,
                severity="high",
                test_suggestion="Make changes, don't save, click away, verify warning",
            ),
            EdgeCase(
                title="Concurrent settings changes",
                description="Same user changing settings in two tabs",
                category=EdgeCaseCategory.STATE,
                severity="medium",
                test_suggestion="Open settings in 2 tabs, make different changes, save both",
            ),
            EdgeCase(
                title="Change email to existing email",
                description="Changing email to one that's already registered",
                category=EdgeCaseCategory.STATE,
                severity="high",
                test_suggestion="Try to change email to another user's email",
            ),
            EdgeCase(
                title="Password change without current password",
                description="Security: must verify identity before password change",
                category=EdgeCaseCategory.SECURITY,
                severity="critical",
                test_suggestion="Try to change password without entering current password",
            ),
            EdgeCase(
                title="Delete account data retention",
                description="What data is kept after account deletion?",
                category=EdgeCaseCategory.SECURITY,
                severity="high",
                test_suggestion="Delete account, check if any data remains accessible",
            ),
        ],

        "profile": [
            EdgeCase(
                title="Profile picture with transparency",
                description="PNG with transparent background",
                category=EdgeCaseCategory.DATA,
                severity="low",
                test_suggestion="Upload PNG with alpha channel, verify display",
            ),
            EdgeCase(
                title="Profile picture with EXIF rotation",
                description="Photo rotated via EXIF metadata",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Upload phone photo, verify correct orientation",
            ),
            EdgeCase(
                title="Empty bio allowed",
                description="Bio should be optional",
                category=EdgeCaseCategory.STATE,
                severity="low",
                test_suggestion="Clear bio completely and save",
            ),
            EdgeCase(
                title="Links in bio",
                description="URLs in bio should be handled safely",
                category=EdgeCaseCategory.SECURITY,
                severity="high",
                test_suggestion="Enter 'javascript:alert(1)' as website URL",
                test_data={"bio_link": "javascript:alert(1)"},
            ),
            EdgeCase(
                title="Profile URL with special characters",
                description="Username with dashes, underscores in URL",
                category=EdgeCaseCategory.DATA,
                severity="medium",
                test_suggestion="Create user 'test-user_123' and verify profile URL works",
            ),
        ],

        "form": [
            EdgeCase(
                title="Tab order for accessibility",
                description="Tab key should navigate form logically",
                category=EdgeCaseCategory.ACCESSIBILITY,
                severity="high",
                test_suggestion="Press Tab repeatedly, verify logical order",
            ),
            EdgeCase(
                title="Form auto-fill",
                description="Browser auto-fill should work correctly",
                category=EdgeCaseCategory.BEHAVIOR,
                severity="medium",
                test_suggestion="Let browser auto-fill form, verify all fields populate",
            ),
            EdgeCase(
                title="Required field indicator",
                description="Required fields should be clearly marked",
                category=EdgeCaseCategory.ACCESSIBILITY,
                severity="high",
                test_suggestion="Verify * or 'required' label on mandatory fields",
            ),
            EdgeCase(
                title="Error focus management",
                description="On error, focus should move to first error field",
                category=EdgeCaseCategory.ACCESSIBILITY,
                severity="high",
                test_suggestion="Submit with errors, verify focus moves to error field",
            ),
            EdgeCase(
                title="Paste into all fields",
                description="Pasting should work in all text fields",
                category=EdgeCaseCategory.BEHAVIOR,
                severity="medium",
                test_suggestion="Try pasting text into each field",
            ),
        ],

        "dashboard": [
            EdgeCase(
                title="Widget load failure",
                description="One widget fails, others should still work",
                category=EdgeCaseCategory.INTEGRATION,
                severity="high",
                test_suggestion="Block one widget's API call, verify others load",
            ),
            EdgeCase(
                title="Stale data indicator",
                description="Show when data was last updated",
                category=EdgeCaseCategory.STATE,
                severity="low",
                test_suggestion="Check for 'last updated' timestamp on widgets",
            ),
            EdgeCase(
                title="Dashboard on mobile",
                description="Dashboard should be usable on small screens",
                category=EdgeCaseCategory.ACCESSIBILITY,
                severity="medium",
                test_suggestion="View dashboard at 375px width",
            ),
            EdgeCase(
                title="Real-time updates",
                description="Data should refresh without manual action",
                category=EdgeCaseCategory.STATE,
                severity="medium",
                test_suggestion="Wait for auto-refresh interval, verify data updates",
            ),
        ],
    }

    # Input field patterns and their edge cases
    INPUT_PATTERNS = {
        "email": [
            ("Plus sign in email", "user+test@company.com"),
            ("Very long email", "a" * 64 + "@company.com"),
            ("Subdomain email", "user@mail.company.co.uk"),
            ("Numbers in local part", "user123@company.com"),
        ],
        "password": [
            ("All special characters", "!@#$%^&*()_+-="),
            ("Unicode characters", "Пароль日本語🔐"),
            ("255 characters", "a" * 255),
            ("Space in password", "pass word 123"),
        ],
        "phone": [
            ("International format", "+44 20 7946 0958"),
            ("With extension", "555-123-4567 ext. 890"),
            ("Letters (vanity)", "1-800-FLOWERS"),
        ],
        "name": [
            ("Apostrophe", "O'Brien"),
            ("Hyphen", "Mary-Jane"),
            ("Unicode", "José García-Müller"),
            ("Single character", "X"),
        ],
        "url": [
            ("With port", "http://localhost:3000"),
            ("IP address", "http://192.168.1.1"),
            ("Unicode domain", "http://münchen.de"),
            ("Query string", "https://site.com?foo=bar&baz=qux"),
        ],
        "number": [
            ("Negative", "-1"),
            ("Zero", "0"),
            ("Decimal", "3.14159"),
            ("Scientific notation", "1e10"),
            ("Leading zeros", "007"),
        ],
    }

    def analyze_page_type(self, page_type: str) -> EdgeCaseAnalysis:
        """
        Get edge cases for a specific page type.

        Args:
            page_type: Type of page (login, signup, etc.)

        Returns:
            EdgeCaseAnalysis with detected edge cases
        """
        edge_cases = list(self.UNIVERSAL_EDGE_CASES)  # Start with universal

        # Add page-specific
        page_specific = self.PAGE_EDGE_CASES.get(page_type.lower(), [])
        edge_cases.extend(page_specific)

        # Calculate coverage score
        total_patterns = len(self.UNIVERSAL_EDGE_CASES) + len(self.PAGE_EDGE_CASES.get(page_type.lower(), []))
        coverage = len(edge_cases) / max(total_patterns, 1)

        return EdgeCaseAnalysis(
            feature=f"{page_type.title()} page",
            page_type=page_type,
            edge_cases=edge_cases,
            coverage_score=coverage,
        )

    def analyze_elements(
        self,
        elements: List[Dict[str, Any]],
        page_type: Optional[str] = None,
    ) -> EdgeCaseAnalysis:
        """
        Analyze elements to detect relevant edge cases.

        Args:
            elements: List of page elements
            page_type: Optional page type hint

        Returns:
            EdgeCaseAnalysis with detected edge cases
        """
        edge_cases = list(self.UNIVERSAL_EDGE_CASES)
        detected_input_types = set()

        # Analyze each element
        for el in elements:
            el_type = el.get("type", el.get("elementType", "")).lower()
            el_name = el.get("name", el.get("id", "")).lower()
            placeholder = el.get("placeholder", "").lower()

            # Detect input types
            if el_type in ["email", "password", "tel", "url", "number"]:
                detected_input_types.add(el_type)
            elif "email" in el_name or "email" in placeholder:
                detected_input_types.add("email")
            elif "password" in el_name or "password" in placeholder:
                detected_input_types.add("password")
            elif "phone" in el_name or "phone" in placeholder or "tel" in el_name:
                detected_input_types.add("phone")
            elif "name" in el_name or "name" in placeholder:
                detected_input_types.add("name")
            elif "url" in el_name or "website" in el_name:
                detected_input_types.add("url")

        # Add edge cases for detected input types
        for input_type in detected_input_types:
            patterns = self.INPUT_PATTERNS.get(input_type, [])
            for title, test_value in patterns:
                edge_cases.append(EdgeCase(
                    title=f"{input_type.title()} field: {title}",
                    description=f"Test {input_type} field with: {test_value[:50]}...",
                    category=EdgeCaseCategory.DATA,
                    severity="medium",
                    test_suggestion=f"Enter '{test_value}' in {input_type} field",
                    test_data={input_type: test_value},
                ))

        # Add page-specific if known
        if page_type:
            page_specific = self.PAGE_EDGE_CASES.get(page_type.lower(), [])
            edge_cases.extend(page_specific)

        return EdgeCaseAnalysis(
            feature="Analyzed page",
            page_type=page_type,
            edge_cases=edge_cases,
            coverage_score=min(1.0, len(edge_cases) / 20),  # Normalize
        )

    def get_critical_edge_cases(
        self,
        page_type: Optional[str] = None,
    ) -> List[EdgeCase]:
        """
        Get only critical edge cases.

        Args:
            page_type: Optional page type filter

        Returns:
            List of critical edge cases
        """
        if page_type:
            analysis = self.analyze_page_type(page_type)
        else:
            # Return critical cases from all page types
            all_cases = []
            for cases in self.PAGE_EDGE_CASES.values():
                all_cases.extend(cases)
            all_cases.extend(self.UNIVERSAL_EDGE_CASES)
            analysis = EdgeCaseAnalysis(
                feature="All",
                page_type=None,
                edge_cases=all_cases,
            )

        return [ec for ec in analysis.edge_cases if ec.severity == "critical"]


def detect_edge_cases(page_type: str) -> EdgeCaseAnalysis:
    """Quick helper to detect edge cases for a page type."""
    detector = EdgeCaseDetector()
    return detector.analyze_page_type(page_type)


def get_edge_case_tests(page_type: str) -> List[Dict[str, Any]]:
    """Convert detected edge cases to test case format."""
    detector = EdgeCaseDetector()
    analysis = detector.analyze_page_type(page_type)

    tests = []
    for i, ec in enumerate(analysis.edge_cases, 1):
        tests.append({
            "id": f"EC-{i:03d}",
            "title": ec.title,
            "description": ec.description,
            "category": ec.category.value,
            "priority": ec.severity,
            "steps": [ec.test_suggestion],
            "expected_result": "System handles edge case gracefully",
            "test_data": ec.test_data or {},
        })

    return tests
