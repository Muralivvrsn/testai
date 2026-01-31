"""
TestAI Agent - Test Data Factory

Generates realistic test data for various locales,
domains, and edge cases.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, date
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import random
import string
import hashlib


class DataProfile(Enum):
    """Data profiles for generation."""
    REALISTIC = "realistic"  # Production-like data
    BOUNDARY = "boundary"  # Edge case values
    MALICIOUS = "malicious"  # Security test data
    UNICODE = "unicode"  # International characters
    MINIMAL = "minimal"  # Minimum valid data
    MAXIMAL = "maximal"  # Maximum length data


@dataclass
class LocaleData:
    """Locale-specific data templates."""
    locale: str
    country: str
    first_names: List[str]
    last_names: List[str]
    cities: List[str]
    postal_pattern: str
    phone_pattern: str
    address_format: str
    currency: str
    date_format: str


class DataFactory:
    """
    Generates realistic test data.

    Features:
    - Locale-aware data generation
    - Domain-specific data (financial, medical, etc.)
    - Edge case data generation
    - Correlated data sets
    - Reproducible via seeds
    """

    # Locale data
    LOCALES = {
        "en-US": LocaleData(
            locale="en-US",
            country="United States",
            first_names=["James", "Mary", "John", "Patricia", "Robert", "Jennifer"],
            last_names=["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"],
            cities=["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"],
            postal_pattern="#####",
            phone_pattern="(###) ###-####",
            address_format="{street}, {city}, {state} {postal}",
            currency="USD",
            date_format="MM/DD/YYYY",
        ),
        "en-GB": LocaleData(
            locale="en-GB",
            country="United Kingdom",
            first_names=["Oliver", "Olivia", "Harry", "Amelia", "George", "Isla"],
            last_names=["Smith", "Jones", "Williams", "Taylor", "Brown", "Davies"],
            cities=["London", "Birmingham", "Manchester", "Leeds", "Liverpool"],
            postal_pattern="@## #@@",
            phone_pattern="+44 #### ######",
            address_format="{street}, {city}, {postal}",
            currency="GBP",
            date_format="DD/MM/YYYY",
        ),
        "de-DE": LocaleData(
            locale="de-DE",
            country="Germany",
            first_names=["Hans", "Anna", "Peter", "Maria", "Klaus", "Elisabeth"],
            last_names=["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer"],
            cities=["Berlin", "Hamburg", "München", "Köln", "Frankfurt"],
            postal_pattern="#####",
            phone_pattern="+49 ### #######",
            address_format="{street}, {postal} {city}",
            currency="EUR",
            date_format="DD.MM.YYYY",
        ),
        "ja-JP": LocaleData(
            locale="ja-JP",
            country="Japan",
            first_names=["太郎", "花子", "一郎", "美子", "健一", "幸子"],
            last_names=["佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺"],
            cities=["東京", "大阪", "名古屋", "札幌", "福岡"],
            postal_pattern="###-####",
            phone_pattern="+81 ## #### ####",
            address_format="{postal} {city} {street}",
            currency="JPY",
            date_format="YYYY/MM/DD",
        ),
    }

    # Domain patterns
    DOMAINS = [
        "example.com", "test.org", "sample.net", "demo.co",
        "testing.io", "qa.dev", "testmail.com"
    ]

    # Security payloads
    SECURITY_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1; SELECT * FROM users",
            "' UNION SELECT * FROM passwords --",
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img onerror='alert(1)' src=x>",
            "javascript:alert('XSS')",
            "<svg onload='alert(1)'>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//etc/passwd",
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
        ],
    }

    def __init__(self, seed: Optional[int] = None):
        """Initialize the data factory."""
        self.seed = seed
        if seed:
            random.seed(seed)
        self._sequence_counters: Dict[str, int] = {}

    def generate_user(
        self,
        locale: str = "en-US",
        profile: DataProfile = DataProfile.REALISTIC,
    ) -> Dict[str, Any]:
        """Generate a complete user profile."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])

        first_name = random.choice(locale_data.first_names)
        last_name = random.choice(locale_data.last_names)

        email = self._generate_email(first_name, last_name, profile)
        phone = self._format_pattern(locale_data.phone_pattern)

        return {
            "first_name": first_name,
            "last_name": last_name,
            "full_name": f"{first_name} {last_name}",
            "email": email,
            "phone": phone,
            "address": self._generate_address(locale_data, profile),
            "date_of_birth": self._generate_date_of_birth(profile),
            "username": self._generate_username(first_name, last_name),
            "password": self.generate_password(profile),
            "locale": locale,
        }

    def generate_email(
        self,
        profile: DataProfile = DataProfile.REALISTIC,
        locale: str = "en-US",
    ) -> str:
        """Generate an email address."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])
        first = random.choice(locale_data.first_names).lower()
        last = random.choice(locale_data.last_names).lower()
        return self._generate_email(first, last, profile)

    def generate_password(
        self,
        profile: DataProfile = DataProfile.REALISTIC,
        min_length: int = 8,
        max_length: int = 32,
    ) -> str:
        """Generate a password."""
        if profile == DataProfile.REALISTIC:
            return self._generate_strong_password(min_length)
        elif profile == DataProfile.MINIMAL:
            return "a" * min_length
        elif profile == DataProfile.MAXIMAL:
            return self._generate_strong_password(max_length)
        elif profile == DataProfile.BOUNDARY:
            return "a" * (min_length - 1)  # Too short
        elif profile == DataProfile.MALICIOUS:
            return random.choice(self.SECURITY_PAYLOADS["sql_injection"])
        return self._generate_strong_password(min_length)

    def generate_credit_card(
        self,
        card_type: str = "visa",
        profile: DataProfile = DataProfile.REALISTIC,
    ) -> Dict[str, str]:
        """Generate credit card test data."""
        prefixes = {
            "visa": "4",
            "mastercard": "5",
            "amex": "3",
            "discover": "6",
        }

        if profile == DataProfile.REALISTIC:
            prefix = prefixes.get(card_type, "4")
            number = prefix + "".join(random.choices(string.digits, k=15))
            # Apply Luhn check digit (simplified)
            return {
                "number": number,
                "expiry": f"{random.randint(1, 12):02d}/{random.randint(25, 30)}",
                "cvv": "".join(random.choices(string.digits, k=3 if card_type != "amex" else 4)),
                "holder": self._generate_card_holder_name(),
            }
        elif profile == DataProfile.BOUNDARY:
            return {
                "number": "4" * 16,  # All same digit
                "expiry": "01/00",  # Expired
                "cvv": "000",
                "holder": "",
            }
        elif profile == DataProfile.MALICIOUS:
            return {
                "number": random.choice(self.SECURITY_PAYLOADS["sql_injection"]),
                "expiry": "'; DROP TABLE cards; --",
                "cvv": "<script>",
                "holder": random.choice(self.SECURITY_PAYLOADS["xss"]),
            }

        return {"number": "4111111111111111", "expiry": "12/25", "cvv": "123", "holder": "Test User"}

    def generate_form_data(
        self,
        fields: List[str],
        profile: DataProfile = DataProfile.REALISTIC,
        locale: str = "en-US",
    ) -> Dict[str, Any]:
        """Generate data for form fields."""
        data = {}

        for field in fields:
            field_lower = field.lower()

            if "email" in field_lower:
                data[field] = self.generate_email(profile, locale)
            elif "password" in field_lower:
                data[field] = self.generate_password(profile)
            elif "phone" in field_lower or "tel" in field_lower:
                data[field] = self._generate_phone(locale, profile)
            elif "name" in field_lower:
                if "first" in field_lower:
                    data[field] = self._generate_first_name(locale, profile)
                elif "last" in field_lower:
                    data[field] = self._generate_last_name(locale, profile)
                else:
                    data[field] = self._generate_full_name(locale, profile)
            elif "date" in field_lower or "dob" in field_lower:
                data[field] = self._generate_date_of_birth(profile)
            elif "address" in field_lower:
                data[field] = self._generate_address_line(locale, profile)
            elif "city" in field_lower:
                data[field] = self._generate_city(locale, profile)
            elif "zip" in field_lower or "postal" in field_lower:
                data[field] = self._generate_postal(locale, profile)
            elif "country" in field_lower:
                data[field] = self._generate_country(locale, profile)
            elif "url" in field_lower or "website" in field_lower:
                data[field] = self._generate_url(profile)
            elif "number" in field_lower or "amount" in field_lower:
                data[field] = self._generate_number(profile)
            else:
                data[field] = self._generate_generic_text(profile)

        return data

    def generate_batch(
        self,
        data_type: str,
        count: int,
        profile: DataProfile = DataProfile.REALISTIC,
        locale: str = "en-US",
    ) -> List[Dict[str, Any]]:
        """Generate a batch of test data."""
        generators = {
            "user": lambda: self.generate_user(locale, profile),
            "email": lambda: {"email": self.generate_email(profile, locale)},
            "credit_card": lambda: self.generate_credit_card(profile=profile),
        }

        generator = generators.get(data_type, lambda: self.generate_user(locale, profile))
        return [generator() for _ in range(count)]

    def get_security_payloads(
        self,
        attack_type: Optional[str] = None,
    ) -> List[str]:
        """Get security test payloads."""
        if attack_type:
            return self.SECURITY_PAYLOADS.get(attack_type, [])

        # Return all payloads
        all_payloads = []
        for payloads in self.SECURITY_PAYLOADS.values():
            all_payloads.extend(payloads)
        return all_payloads

    def _generate_email(
        self,
        first: str,
        last: str,
        profile: DataProfile,
    ) -> str:
        """Generate email based on profile."""
        domain = random.choice(self.DOMAINS)

        if profile == DataProfile.REALISTIC:
            patterns = [
                f"{first}.{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}{random.randint(1, 99)}@{domain}",
            ]
            return random.choice(patterns).lower()
        elif profile == DataProfile.UNICODE:
            return f"ユーザー@{domain}"
        elif profile == DataProfile.BOUNDARY:
            return f"{'a' * 64}@{'b' * 63}.{'c' * 63}"  # Max length
        elif profile == DataProfile.MALICIOUS:
            return random.choice(self.SECURITY_PAYLOADS["xss"]) + "@test.com"
        elif profile == DataProfile.MINIMAL:
            return "a@b.co"

        return f"{first}.{last}@{domain}".lower()

    def _generate_phone(self, locale: str, profile: DataProfile) -> str:
        """Generate phone number."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])

        if profile == DataProfile.REALISTIC:
            return self._format_pattern(locale_data.phone_pattern)
        elif profile == DataProfile.BOUNDARY:
            return "1" * 20  # Very long
        elif profile == DataProfile.MALICIOUS:
            return "; rm -rf /"

        return self._format_pattern(locale_data.phone_pattern)

    def _generate_first_name(self, locale: str, profile: DataProfile) -> str:
        """Generate first name."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])

        if profile == DataProfile.REALISTIC:
            return random.choice(locale_data.first_names)
        elif profile == DataProfile.UNICODE:
            return "名前"  # Japanese
        elif profile == DataProfile.BOUNDARY:
            return "A" * 100
        elif profile == DataProfile.MINIMAL:
            return "A"

        return random.choice(locale_data.first_names)

    def _generate_last_name(self, locale: str, profile: DataProfile) -> str:
        """Generate last name."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])

        if profile == DataProfile.REALISTIC:
            return random.choice(locale_data.last_names)
        elif profile == DataProfile.UNICODE:
            return "苗字"
        elif profile == DataProfile.BOUNDARY:
            return "B" * 100
        elif profile == DataProfile.MINIMAL:
            return "B"

        return random.choice(locale_data.last_names)

    def _generate_full_name(self, locale: str, profile: DataProfile) -> str:
        """Generate full name."""
        first = self._generate_first_name(locale, profile)
        last = self._generate_last_name(locale, profile)
        return f"{first} {last}"

    def _generate_address(
        self,
        locale_data: LocaleData,
        profile: DataProfile,
    ) -> Dict[str, str]:
        """Generate address."""
        return {
            "street": f"{random.randint(1, 999)} {random.choice(['Main', 'Oak', 'Park'])} St",
            "city": random.choice(locale_data.cities),
            "postal": self._format_pattern(locale_data.postal_pattern),
            "country": locale_data.country,
        }

    def _generate_address_line(self, locale: str, profile: DataProfile) -> str:
        """Generate address line."""
        if profile == DataProfile.REALISTIC:
            return f"{random.randint(1, 999)} {random.choice(['Main', 'Oak', 'Park', 'First'])} Street"
        elif profile == DataProfile.MALICIOUS:
            return random.choice(self.SECURITY_PAYLOADS["path_traversal"])
        return "123 Test Street"

    def _generate_city(self, locale: str, profile: DataProfile) -> str:
        """Generate city."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])
        return random.choice(locale_data.cities)

    def _generate_postal(self, locale: str, profile: DataProfile) -> str:
        """Generate postal code."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])
        return self._format_pattern(locale_data.postal_pattern)

    def _generate_country(self, locale: str, profile: DataProfile) -> str:
        """Generate country."""
        locale_data = self.LOCALES.get(locale, self.LOCALES["en-US"])
        return locale_data.country

    def _generate_date_of_birth(self, profile: DataProfile) -> str:
        """Generate date of birth."""
        if profile == DataProfile.REALISTIC:
            age = random.randint(18, 80)
            dob = date.today() - timedelta(days=age * 365)
            return dob.strftime("%Y-%m-%d")
        elif profile == DataProfile.BOUNDARY:
            return "1900-01-01"  # Very old
        return "1990-01-15"

    def _generate_username(self, first: str, last: str) -> str:
        """Generate username."""
        patterns = [
            f"{first.lower()}{last.lower()}",
            f"{first.lower()}{random.randint(1, 999)}",
            f"{first.lower()}_{last.lower()}",
        ]
        return random.choice(patterns)

    def _generate_strong_password(self, length: int) -> str:
        """Generate a strong password."""
        chars = (
            random.choices(string.ascii_uppercase, k=2) +
            random.choices(string.ascii_lowercase, k=2) +
            random.choices(string.digits, k=2) +
            random.choices("!@#$%^&*", k=2) +
            random.choices(string.ascii_letters + string.digits, k=max(0, length - 8))
        )
        random.shuffle(chars)
        return "".join(chars)

    def _generate_card_holder_name(self) -> str:
        """Generate card holder name."""
        locale_data = self.LOCALES["en-US"]
        first = random.choice(locale_data.first_names)
        last = random.choice(locale_data.last_names)
        return f"{first} {last}".upper()

    def _generate_url(self, profile: DataProfile) -> str:
        """Generate URL."""
        if profile == DataProfile.REALISTIC:
            return f"https://www.{random.choice(self.DOMAINS)}/page"
        elif profile == DataProfile.MALICIOUS:
            return "javascript:alert('XSS')"
        return "https://example.com"

    def _generate_number(self, profile: DataProfile) -> int:
        """Generate a number."""
        if profile == DataProfile.REALISTIC:
            return random.randint(1, 1000)
        elif profile == DataProfile.BOUNDARY:
            return 2**31 - 1  # Max int32
        elif profile == DataProfile.MINIMAL:
            return 0
        return random.randint(1, 100)

    def _generate_generic_text(self, profile: DataProfile) -> str:
        """Generate generic text."""
        if profile == DataProfile.REALISTIC:
            return "Sample test data"
        elif profile == DataProfile.UNICODE:
            return "测试数据 テスト Тест"
        elif profile == DataProfile.BOUNDARY:
            return "A" * 500
        elif profile == DataProfile.MALICIOUS:
            return random.choice(self.SECURITY_PAYLOADS["xss"])
        return "Test"

    def _format_pattern(self, pattern: str) -> str:
        """Format a pattern (# = digit, @ = letter)."""
        result = []
        for char in pattern:
            if char == "#":
                result.append(random.choice(string.digits))
            elif char == "@":
                result.append(random.choice(string.ascii_uppercase))
            else:
                result.append(char)
        return "".join(result)

    def get_available_locales(self) -> List[str]:
        """Get available locales."""
        return list(self.LOCALES.keys())

    def format_data(self, data: Dict[str, Any]) -> str:
        """Format generated data as readable text."""
        lines = [
            "=" * 50,
            "  GENERATED TEST DATA",
            "=" * 50,
            "",
        ]

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for k, v in value.items():
                    lines.append(f"    {k}: {v}")
            else:
                lines.append(f"  {key}: {value}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_data_factory(seed: Optional[int] = None) -> DataFactory:
    """Create a data factory instance."""
    return DataFactory(seed)
