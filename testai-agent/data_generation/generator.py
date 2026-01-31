"""
TestAI Agent - Data Generator

Core data generation engine with type-aware
generation and customizable profiles.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Union
import random
import string
import hashlib
import uuid


class DataType(Enum):
    """Types of data that can be generated."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    PASSWORD = "password"
    PHONE = "phone"
    URL = "url"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    ADDRESS = "address"
    NAME = "name"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IP_ADDRESS = "ip_address"
    JSON = "json"
    ARRAY = "array"


@dataclass
class DataProfile:
    """Configuration profile for data generation."""
    profile_id: str
    name: str
    locale: str = "en_US"
    seed: Optional[int] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedData:
    """A generated data result."""
    data_id: str
    data_type: DataType
    value: Any
    profile: Optional[DataProfile] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataGenerator:
    """
    Intelligent data generator.

    Features:
    - Multiple data types
    - Customizable profiles
    - Reproducible generation
    - Locale support
    """

    # Sample data pools
    FIRST_NAMES = [
        "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
        "Michael", "Linda", "William", "Elizabeth", "David", "Barbara",
        "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah",
        "Emma", "Liam", "Olivia", "Noah", "Ava", "Oliver", "Isabella",
    ]

    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
        "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
        "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore",
        "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    ]

    STREET_NAMES = [
        "Main St", "Oak Ave", "Park Rd", "Maple Dr", "Cedar Ln",
        "Elm St", "Pine Ave", "Washington Blvd", "Lake View Dr",
        "Highland Ave", "River Rd", "Forest Way", "Sunset Blvd",
    ]

    CITIES = [
        "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
        "Philadelphia", "San Antonio", "San Diego", "Dallas", "Austin",
        "San Jose", "Seattle", "Denver", "Boston", "Portland",
    ]

    STATES = [
        "CA", "NY", "TX", "FL", "IL", "PA", "OH", "GA", "NC", "MI",
        "NJ", "VA", "WA", "AZ", "MA", "CO", "TN", "IN", "MO", "MD",
    ]

    EMAIL_DOMAINS = [
        "example.com", "test.org", "sample.net", "demo.io",
        "mail.test", "inbox.example", "email.sample",
    ]

    def __init__(
        self,
        seed: Optional[int] = None,
        locale: str = "en_US",
    ):
        """Initialize the generator."""
        self._seed = seed
        self._locale = locale
        self._rng = random.Random(seed)
        self._profiles: Dict[str, DataProfile] = {}
        self._history: List[GeneratedData] = []
        self._data_counter = 0
        self._profile_counter = 0

    def set_seed(self, seed: int):
        """Set the random seed for reproducibility."""
        self._seed = seed
        self._rng = random.Random(seed)

    def create_profile(
        self,
        name: str,
        locale: str = "en_US",
        seed: Optional[int] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> DataProfile:
        """Create a data generation profile."""
        self._profile_counter += 1
        profile_id = f"PROFILE-{self._profile_counter:04d}"

        profile = DataProfile(
            profile_id=profile_id,
            name=name,
            locale=locale,
            seed=seed,
            constraints=constraints or {},
        )

        self._profiles[profile_id] = profile
        return profile

    def generate(
        self,
        data_type: DataType,
        constraints: Optional[Dict[str, Any]] = None,
        profile: Optional[DataProfile] = None,
    ) -> GeneratedData:
        """Generate data of a specific type."""
        self._data_counter += 1
        data_id = f"DATA-{self._data_counter:06d}"

        # Use profile constraints if available
        if profile and profile.constraints:
            merged_constraints = {**profile.constraints, **(constraints or {})}
        else:
            merged_constraints = constraints or {}

        value = self._generate_value(data_type, merged_constraints)

        result = GeneratedData(
            data_id=data_id,
            data_type=data_type,
            value=value,
            profile=profile,
        )

        self._history.append(result)
        return result

    def generate_batch(
        self,
        data_type: DataType,
        count: int,
        constraints: Optional[Dict[str, Any]] = None,
        profile: Optional[DataProfile] = None,
    ) -> List[GeneratedData]:
        """Generate multiple data items."""
        return [
            self.generate(data_type, constraints, profile)
            for _ in range(count)
        ]

    def _generate_value(
        self,
        data_type: DataType,
        constraints: Dict[str, Any],
    ) -> Any:
        """Generate a value based on type and constraints."""
        generators = {
            DataType.STRING: self._gen_string,
            DataType.INTEGER: self._gen_integer,
            DataType.FLOAT: self._gen_float,
            DataType.BOOLEAN: self._gen_boolean,
            DataType.EMAIL: self._gen_email,
            DataType.PASSWORD: self._gen_password,
            DataType.PHONE: self._gen_phone,
            DataType.URL: self._gen_url,
            DataType.UUID: self._gen_uuid,
            DataType.DATE: self._gen_date,
            DataType.DATETIME: self._gen_datetime,
            DataType.ADDRESS: self._gen_address,
            DataType.NAME: self._gen_name,
            DataType.CREDIT_CARD: self._gen_credit_card,
            DataType.SSN: self._gen_ssn,
            DataType.IP_ADDRESS: self._gen_ip_address,
            DataType.JSON: self._gen_json,
            DataType.ARRAY: self._gen_array,
        }

        generator = generators.get(data_type, self._gen_string)
        return generator(constraints)

    def _gen_string(self, constraints: Dict[str, Any]) -> str:
        """Generate a random string."""
        min_len = constraints.get("min_length", 5)
        max_len = constraints.get("max_length", 20)
        charset = constraints.get("charset", string.ascii_letters + string.digits)
        prefix = constraints.get("prefix", "")
        suffix = constraints.get("suffix", "")

        length = self._rng.randint(min_len, max_len)
        value = "".join(self._rng.choices(charset, k=length))

        return f"{prefix}{value}{suffix}"

    def _gen_integer(self, constraints: Dict[str, Any]) -> int:
        """Generate a random integer."""
        min_val = constraints.get("min", 0)
        max_val = constraints.get("max", 10000)
        return self._rng.randint(min_val, max_val)

    def _gen_float(self, constraints: Dict[str, Any]) -> float:
        """Generate a random float."""
        min_val = constraints.get("min", 0.0)
        max_val = constraints.get("max", 1000.0)
        precision = constraints.get("precision", 2)
        return round(self._rng.uniform(min_val, max_val), precision)

    def _gen_boolean(self, constraints: Dict[str, Any]) -> bool:
        """Generate a random boolean."""
        probability = constraints.get("true_probability", 0.5)
        return self._rng.random() < probability

    def _gen_email(self, constraints: Dict[str, Any]) -> str:
        """Generate a random email address."""
        domain = constraints.get("domain")
        if not domain:
            domain = self._rng.choice(self.EMAIL_DOMAINS)

        first = self._rng.choice(self.FIRST_NAMES).lower()
        last = self._rng.choice(self.LAST_NAMES).lower()
        separator = self._rng.choice([".", "_", ""])
        suffix = str(self._rng.randint(1, 999)) if self._rng.random() > 0.5 else ""

        return f"{first}{separator}{last}{suffix}@{domain}"

    def _gen_password(self, constraints: Dict[str, Any]) -> str:
        """Generate a random password."""
        min_len = constraints.get("min_length", 12)
        max_len = constraints.get("max_length", 20)
        require_upper = constraints.get("require_upper", True)
        require_lower = constraints.get("require_lower", True)
        require_digit = constraints.get("require_digit", True)
        require_special = constraints.get("require_special", True)

        length = self._rng.randint(min_len, max_len)

        # Build character pool
        chars = []
        if require_lower:
            chars.extend(string.ascii_lowercase)
        if require_upper:
            chars.extend(string.ascii_uppercase)
        if require_digit:
            chars.extend(string.digits)
        if require_special:
            chars.extend("!@#$%^&*()_+-=[]{}|;:,.<>?")

        # Ensure at least one of each required type
        password = []
        if require_lower:
            password.append(self._rng.choice(string.ascii_lowercase))
        if require_upper:
            password.append(self._rng.choice(string.ascii_uppercase))
        if require_digit:
            password.append(self._rng.choice(string.digits))
        if require_special:
            password.append(self._rng.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

        # Fill remaining length
        remaining = length - len(password)
        password.extend(self._rng.choices(chars, k=remaining))

        # Shuffle
        self._rng.shuffle(password)

        return "".join(password)

    def _gen_phone(self, constraints: Dict[str, Any]) -> str:
        """Generate a random phone number."""
        format_style = constraints.get("format", "us")

        if format_style == "us":
            area = self._rng.randint(200, 999)
            prefix = self._rng.randint(200, 999)
            line = self._rng.randint(1000, 9999)
            return f"({area}) {prefix}-{line}"
        elif format_style == "international":
            country = self._rng.randint(1, 99)
            number = "".join(str(self._rng.randint(0, 9)) for _ in range(10))
            return f"+{country} {number}"
        else:
            return "".join(str(self._rng.randint(0, 9)) for _ in range(10))

    def _gen_url(self, constraints: Dict[str, Any]) -> str:
        """Generate a random URL."""
        protocols = constraints.get("protocols", ["https"])
        domains = constraints.get("domains", ["example.com", "test.org", "sample.net"])
        include_path = constraints.get("include_path", True)

        protocol = self._rng.choice(protocols)
        domain = self._rng.choice(domains)

        url = f"{protocol}://{domain}"

        if include_path:
            path_parts = self._rng.randint(1, 3)
            path = "/".join(
                self._gen_string({"min_length": 3, "max_length": 10, "charset": string.ascii_lowercase})
                for _ in range(path_parts)
            )
            url = f"{url}/{path}"

        return url

    def _gen_uuid(self, constraints: Dict[str, Any]) -> str:
        """Generate a UUID."""
        version = constraints.get("version", 4)
        if version == 4:
            return str(uuid.uuid4())
        else:
            return str(uuid.uuid4())

    def _gen_date(self, constraints: Dict[str, Any]) -> str:
        """Generate a random date."""
        min_date = constraints.get("min_date", datetime(2000, 1, 1))
        max_date = constraints.get("max_date", datetime.now())
        format_str = constraints.get("format", "%Y-%m-%d")

        if isinstance(min_date, str):
            min_date = datetime.fromisoformat(min_date)
        if isinstance(max_date, str):
            max_date = datetime.fromisoformat(max_date)

        days_range = (max_date - min_date).days
        random_days = self._rng.randint(0, max(1, days_range))
        date = min_date + timedelta(days=random_days)

        return date.strftime(format_str)

    def _gen_datetime(self, constraints: Dict[str, Any]) -> str:
        """Generate a random datetime."""
        constraints["format"] = constraints.get("format", "%Y-%m-%d %H:%M:%S")
        date_str = self._gen_date(constraints)

        # Add random time if not already in format
        if "H" not in constraints.get("format", ""):
            hour = self._rng.randint(0, 23)
            minute = self._rng.randint(0, 59)
            second = self._rng.randint(0, 59)
            return f"{date_str} {hour:02d}:{minute:02d}:{second:02d}"

        return date_str

    def _gen_address(self, constraints: Dict[str, Any]) -> Dict[str, str]:
        """Generate a random address."""
        include_unit = constraints.get("include_unit", self._rng.random() > 0.7)

        address = {
            "street": f"{self._rng.randint(100, 9999)} {self._rng.choice(self.STREET_NAMES)}",
            "city": self._rng.choice(self.CITIES),
            "state": self._rng.choice(self.STATES),
            "zip": f"{self._rng.randint(10000, 99999)}",
            "country": "USA",
        }

        if include_unit:
            unit_types = ["Apt", "Suite", "Unit", "#"]
            address["unit"] = f"{self._rng.choice(unit_types)} {self._rng.randint(1, 999)}"

        return address

    def _gen_name(self, constraints: Dict[str, Any]) -> Dict[str, str]:
        """Generate a random name."""
        include_middle = constraints.get("include_middle", self._rng.random() > 0.5)

        name = {
            "first": self._rng.choice(self.FIRST_NAMES),
            "last": self._rng.choice(self.LAST_NAMES),
        }

        if include_middle:
            name["middle"] = self._rng.choice(self.FIRST_NAMES)

        name["full"] = f"{name['first']} {name.get('middle', '')} {name['last']}".replace("  ", " ").strip()

        return name

    def _gen_credit_card(self, constraints: Dict[str, Any]) -> Dict[str, str]:
        """Generate a test credit card number (invalid for real transactions)."""
        card_type = constraints.get("type", "visa")

        # Test card prefixes (these are standardized test numbers)
        prefixes = {
            "visa": "4",
            "mastercard": "5",
            "amex": "3",
            "discover": "6",
        }

        prefix = prefixes.get(card_type, "4")

        # Generate remaining digits (not valid Luhn checksum)
        remaining = 15 if card_type == "amex" else 15
        number = prefix + "".join(str(self._rng.randint(0, 9)) for _ in range(remaining))

        # Generate expiry (future date)
        exp_month = self._rng.randint(1, 12)
        exp_year = datetime.now().year + self._rng.randint(1, 5) - 2000

        return {
            "number": number,
            "expiry": f"{exp_month:02d}/{exp_year:02d}",
            "cvv": "".join(str(self._rng.randint(0, 9)) for _ in range(3 if card_type != "amex" else 4)),
            "type": card_type,
            "test_card": True,  # Flag as test data
        }

    def _gen_ssn(self, constraints: Dict[str, Any]) -> str:
        """Generate a test SSN (invalid for real use)."""
        # Use invalid area numbers (900-999) to ensure it's clearly test data
        area = self._rng.randint(900, 999)
        group = self._rng.randint(10, 99)
        serial = self._rng.randint(1000, 9999)

        return f"{area}-{group}-{serial}"

    def _gen_ip_address(self, constraints: Dict[str, Any]) -> str:
        """Generate a random IP address."""
        version = constraints.get("version", 4)
        private = constraints.get("private", False)

        if version == 4:
            if private:
                # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                choice = self._rng.choice(["10", "172", "192"])
                if choice == "10":
                    return f"10.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
                elif choice == "172":
                    return f"172.{self._rng.randint(16, 31)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
                else:
                    return f"192.168.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
            else:
                return f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        else:
            # IPv6
            return ":".join(f"{self._rng.randint(0, 65535):04x}" for _ in range(8))

    def _gen_json(self, constraints: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a random JSON object."""
        schema = constraints.get("schema", {})

        if schema:
            return self._gen_from_schema(schema)
        else:
            # Generate random object
            return {
                "id": self._gen_uuid({}),
                "name": self._gen_name({})["full"],
                "email": self._gen_email({}),
                "active": self._gen_boolean({}),
                "score": self._gen_float({"min": 0, "max": 100}),
            }

    def _gen_from_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data from a schema definition."""
        result = {}

        for field_name, field_def in schema.items():
            if isinstance(field_def, str):
                # Simple type reference
                data_type = DataType[field_def.upper()]
                result[field_name] = self.generate(data_type).value
            elif isinstance(field_def, dict):
                # Type with constraints
                type_str = field_def.get("type", "string")
                constraints = field_def.get("constraints", {})
                data_type = DataType[type_str.upper()]
                result[field_name] = self.generate(data_type, constraints).value

        return result

    def _gen_array(self, constraints: Dict[str, Any]) -> List[Any]:
        """Generate an array of values."""
        item_type = constraints.get("item_type", DataType.STRING)
        min_items = constraints.get("min_items", 1)
        max_items = constraints.get("max_items", 10)
        item_constraints = constraints.get("item_constraints", {})

        if isinstance(item_type, str):
            item_type = DataType[item_type.upper()]

        count = self._rng.randint(min_items, max_items)
        return [self.generate(item_type, item_constraints).value for _ in range(count)]

    def get_history(self, limit: int = 100) -> List[GeneratedData]:
        """Get generation history."""
        return self._history[-limit:]

    def clear_history(self):
        """Clear generation history."""
        self._history.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics."""
        type_counts: Dict[str, int] = {}
        for item in self._history:
            type_name = item.data_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "total_generated": len(self._history),
            "profiles_created": len(self._profiles),
            "generation_by_type": type_counts,
            "seed": self._seed,
            "locale": self._locale,
        }

    def format_data(self, data: GeneratedData) -> str:
        """Format generated data for display."""
        lines = [
            "=" * 40,
            "  GENERATED DATA",
            "=" * 40,
            "",
            f"  ID: {data.data_id}",
            f"  Type: {data.data_type.value}",
            f"  Value: {data.value}",
            "",
            "=" * 40,
        ]

        return "\n".join(lines)


def create_data_generator(
    seed: Optional[int] = None,
    locale: str = "en_US",
) -> DataGenerator:
    """Create a data generator instance."""
    return DataGenerator(seed=seed, locale=locale)
