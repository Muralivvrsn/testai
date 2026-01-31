"""
TestAI Agent - Data Seeding

Database and test environment seeding with
intelligent data population strategies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import copy


class SeedStrategy(Enum):
    """Strategies for seeding data."""
    MINIMAL = "minimal"           # Just enough for basic tests
    STANDARD = "standard"         # Typical test coverage
    COMPREHENSIVE = "comprehensive"  # Full coverage with edge cases
    STRESS = "stress"             # Large volumes for load testing
    CUSTOM = "custom"             # User-defined


class SeedCategory(Enum):
    """Categories of seed data."""
    USERS = "users"
    PRODUCTS = "products"
    ORDERS = "orders"
    CATEGORIES = "categories"
    ADDRESSES = "addresses"
    PAYMENTS = "payments"
    SESSIONS = "sessions"
    LOGS = "logs"


@dataclass
class SeedPlan:
    """A plan for seeding data."""
    plan_id: str
    name: str
    strategy: SeedStrategy
    categories: Dict[str, int]
    relationships: List[Dict[str, Any]]
    constraints: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SeedResult:
    """Result of a seeding operation."""
    result_id: str
    plan: SeedPlan
    records_created: Dict[str, int]
    total_records: int
    relationships_created: int
    duration_ms: float
    timestamp: datetime
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SeedData:
    """Container for seeded data."""
    category: SeedCategory
    records: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataSeeder:
    """
    Test data seeding engine.

    Features:
    - Strategy-based seeding
    - Relationship handling
    - Reproducible seeds
    - Environment-aware
    """

    # Default quantities for each strategy
    STRATEGY_QUANTITIES = {
        SeedStrategy.MINIMAL: {
            "users": 3,
            "products": 5,
            "orders": 2,
            "categories": 3,
            "addresses": 3,
        },
        SeedStrategy.STANDARD: {
            "users": 10,
            "products": 25,
            "orders": 15,
            "categories": 8,
            "addresses": 10,
        },
        SeedStrategy.COMPREHENSIVE: {
            "users": 50,
            "products": 100,
            "orders": 75,
            "categories": 20,
            "addresses": 50,
        },
        SeedStrategy.STRESS: {
            "users": 1000,
            "products": 5000,
            "orders": 2000,
            "categories": 100,
            "addresses": 1000,
        },
    }

    def __init__(
        self,
        strategy: SeedStrategy = SeedStrategy.STANDARD,
        seed: Optional[int] = None,
    ):
        """Initialize the seeder."""
        self._strategy = strategy
        self._seed = seed
        self._plans: Dict[str, SeedPlan] = {}
        self._results: List[SeedResult] = []
        self._seeded_data: Dict[str, List[Dict[str, Any]]] = {}
        self._plan_counter = 0
        self._result_counter = 0

        import random
        self._rng = random.Random(seed)

    def set_strategy(self, strategy: SeedStrategy):
        """Set the seeding strategy."""
        self._strategy = strategy

    def create_plan(
        self,
        name: str,
        strategy: Optional[SeedStrategy] = None,
        categories: Optional[Dict[str, int]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> SeedPlan:
        """Create a seeding plan."""
        self._plan_counter += 1
        plan_id = f"PLAN-{self._plan_counter:04d}"

        strategy = strategy or self._strategy

        # Get default quantities for strategy
        if categories is None:
            categories = copy.deepcopy(
                self.STRATEGY_QUANTITIES.get(strategy, self.STRATEGY_QUANTITIES[SeedStrategy.STANDARD])
            )

        # Default relationships
        if relationships is None:
            relationships = [
                {"from": "orders", "to": "users", "field": "user_id", "type": "many_to_one"},
                {"from": "addresses", "to": "users", "field": "user_id", "type": "many_to_one"},
                {"from": "orders", "to": "products", "field": "product_ids", "type": "many_to_many"},
            ]

        plan = SeedPlan(
            plan_id=plan_id,
            name=name,
            strategy=strategy,
            categories=categories,
            relationships=relationships,
            constraints=constraints or {},
        )

        self._plans[plan_id] = plan
        return plan

    def seed(
        self,
        plan: Optional[SeedPlan] = None,
        dry_run: bool = False,
    ) -> SeedResult:
        """Execute a seeding plan."""
        if plan is None:
            plan = self.create_plan("default")

        self._result_counter += 1
        result_id = f"SEED-{self._result_counter:05d}"

        start_time = datetime.now()
        records_created: Dict[str, int] = {}
        errors: List[str] = []
        relationships_created = 0

        # Clear previous seeded data
        self._seeded_data.clear()

        # Seed each category
        for category, count in plan.categories.items():
            try:
                data = self._seed_category(category, count, plan.constraints)
                self._seeded_data[category] = data
                records_created[category] = len(data)
            except Exception as e:
                errors.append(f"Error seeding {category}: {str(e)}")

        # Create relationships
        if not dry_run:
            for rel in plan.relationships:
                try:
                    rel_count = self._create_relationships(rel)
                    relationships_created += rel_count
                except Exception as e:
                    errors.append(f"Error creating relationship: {str(e)}")

        end_time = datetime.now()
        duration_ms = (end_time - start_time).total_seconds() * 1000

        result = SeedResult(
            result_id=result_id,
            plan=plan,
            records_created=records_created,
            total_records=sum(records_created.values()),
            relationships_created=relationships_created,
            duration_ms=duration_ms,
            timestamp=start_time,
            errors=errors,
        )

        self._results.append(result)
        return result

    def _seed_category(
        self,
        category: str,
        count: int,
        constraints: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Seed a specific category of data."""
        generators = {
            "users": self._gen_users,
            "products": self._gen_products,
            "orders": self._gen_orders,
            "categories": self._gen_categories,
            "addresses": self._gen_addresses,
            "payments": self._gen_payments,
            "sessions": self._gen_sessions,
        }

        generator = generators.get(category, self._gen_generic)
        return generator(count, constraints)

    def _gen_users(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate user records."""
        first_names = ["John", "Jane", "Mike", "Sarah", "David", "Emily", "Chris", "Lisa"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
        domains = ["example.com", "test.org", "sample.net"]
        roles = ["user", "admin", "moderator"]

        users = []
        for i in range(count):
            first = self._rng.choice(first_names)
            last = self._rng.choice(last_names)
            domain = self._rng.choice(domains)

            user = {
                "id": i + 1,
                "email": f"{first.lower()}.{last.lower()}{self._rng.randint(1, 999)}@{domain}",
                "username": f"{first.lower()}{last.lower()}{self._rng.randint(1, 99)}",
                "first_name": first,
                "last_name": last,
                "role": self._rng.choice(roles) if self._rng.random() > 0.8 else "user",
                "is_active": self._rng.random() > 0.1,
                "created_at": self._random_datetime(),
            }
            users.append(user)

        return users

    def _gen_products(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate product records."""
        adjectives = ["Premium", "Deluxe", "Standard", "Basic", "Pro", "Ultra", "Eco"]
        nouns = ["Widget", "Gadget", "Device", "Tool", "Kit", "Pack", "Set"]
        categories_list = ["Electronics", "Home", "Office", "Sports", "Outdoor"]

        products = []
        for i in range(count):
            price = round(self._rng.uniform(5, 500), 2)
            discount = round(price * 0.1, 2) if self._rng.random() > 0.7 else 0

            product = {
                "id": i + 1,
                "sku": f"SKU-{1000 + i}",
                "name": f"{self._rng.choice(adjectives)} {self._rng.choice(nouns)}",
                "description": f"High quality {self._rng.choice(nouns).lower()} for everyday use.",
                "price": price,
                "discount": discount,
                "stock": self._rng.randint(0, 500),
                "category": self._rng.choice(categories_list),
                "is_available": self._rng.random() > 0.1,
                "rating": round(self._rng.uniform(1, 5), 1),
            }
            products.append(product)

        return products

    def _gen_orders(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate order records."""
        statuses = ["pending", "processing", "shipped", "delivered", "cancelled"]

        orders = []
        for i in range(count):
            status = self._rng.choice(statuses)
            total = round(self._rng.uniform(10, 1000), 2)

            order = {
                "id": i + 1,
                "order_number": f"ORD-{10000 + i}",
                "user_id": None,  # Will be set by relationships
                "total": total,
                "tax": round(total * 0.08, 2),
                "shipping": round(self._rng.uniform(0, 20), 2),
                "status": status,
                "items_count": self._rng.randint(1, 10),
                "created_at": self._random_datetime(),
                "shipped_at": self._random_datetime() if status in ["shipped", "delivered"] else None,
            }
            orders.append(order)

        return orders

    def _gen_categories(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate category records."""
        base_categories = [
            "Electronics", "Home & Garden", "Sports", "Fashion", "Books",
            "Toys", "Health", "Automotive", "Food", "Office",
        ]

        categories = []
        for i in range(min(count, len(base_categories))):
            category = {
                "id": i + 1,
                "name": base_categories[i],
                "slug": base_categories[i].lower().replace(" & ", "-").replace(" ", "-"),
                "description": f"All {base_categories[i].lower()} products",
                "parent_id": None,
                "is_active": True,
            }
            categories.append(category)

        # Generate additional if needed
        for i in range(len(base_categories), count):
            category = {
                "id": i + 1,
                "name": f"Category {i + 1}",
                "slug": f"category-{i + 1}",
                "description": f"Custom category {i + 1}",
                "parent_id": self._rng.randint(1, min(i, len(base_categories))) if i > 0 else None,
                "is_active": True,
            }
            categories.append(category)

        return categories

    def _gen_addresses(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate address records."""
        streets = ["Main St", "Oak Ave", "Park Rd", "Maple Dr", "Cedar Ln", "Elm St"]
        cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Seattle"]
        states = ["NY", "CA", "IL", "TX", "AZ", "WA"]

        addresses = []
        for i in range(count):
            address = {
                "id": i + 1,
                "user_id": None,  # Will be set by relationships
                "street": f"{self._rng.randint(100, 9999)} {self._rng.choice(streets)}",
                "city": self._rng.choice(cities),
                "state": self._rng.choice(states),
                "zip": str(self._rng.randint(10000, 99999)),
                "country": "USA",
                "is_default": i == 0,
                "type": self._rng.choice(["billing", "shipping"]),
            }
            addresses.append(address)

        return addresses

    def _gen_payments(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate payment records."""
        methods = ["credit_card", "debit_card", "paypal", "bank_transfer"]
        statuses = ["pending", "completed", "failed", "refunded"]

        payments = []
        for i in range(count):
            payment = {
                "id": i + 1,
                "order_id": None,
                "amount": round(self._rng.uniform(10, 1000), 2),
                "method": self._rng.choice(methods),
                "status": self._rng.choice(statuses),
                "transaction_id": f"TXN-{self._rng.randint(100000, 999999)}",
                "created_at": self._random_datetime(),
            }
            payments.append(payment)

        return payments

    def _gen_sessions(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate session records."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148",
        ]

        sessions = []
        for i in range(count):
            session = {
                "id": i + 1,
                "session_token": f"sess_{self._rng.randint(100000000, 999999999)}",
                "user_id": None,
                "ip_address": f"{self._rng.randint(1, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 255)}",
                "user_agent": self._rng.choice(user_agents),
                "created_at": self._random_datetime(),
                "expires_at": self._random_datetime(),
                "is_active": self._rng.random() > 0.3,
            }
            sessions.append(session)

        return sessions

    def _gen_generic(self, count: int, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate generic records."""
        return [
            {
                "id": i + 1,
                "name": f"Item {i + 1}",
                "value": self._rng.randint(1, 100),
                "created_at": self._random_datetime(),
            }
            for i in range(count)
        ]

    def _random_datetime(self) -> str:
        """Generate a random datetime string."""
        from datetime import datetime, timedelta

        days_ago = self._rng.randint(0, 365)
        hours = self._rng.randint(0, 23)
        minutes = self._rng.randint(0, 59)

        dt = datetime.now() - timedelta(days=days_ago, hours=hours, minutes=minutes)
        return dt.isoformat()

    def _create_relationships(self, relationship: Dict[str, Any]) -> int:
        """Create relationships between seeded data."""
        from_category = relationship["from"]
        to_category = relationship["to"]
        field_name = relationship["field"]
        rel_type = relationship.get("type", "many_to_one")

        from_data = self._seeded_data.get(from_category, [])
        to_data = self._seeded_data.get(to_category, [])

        if not from_data or not to_data:
            return 0

        relationships_created = 0

        for record in from_data:
            if rel_type == "many_to_one":
                # Assign a random ID from the target
                target = self._rng.choice(to_data)
                record[field_name] = target["id"]
                relationships_created += 1

            elif rel_type == "many_to_many":
                # Assign multiple random IDs
                count = self._rng.randint(1, min(5, len(to_data)))
                targets = self._rng.sample(to_data, count)
                record[field_name] = [t["id"] for t in targets]
                relationships_created += count

        return relationships_created

    def get_seeded_data(self, category: str) -> List[Dict[str, Any]]:
        """Get seeded data for a category."""
        return self._seeded_data.get(category, [])

    def get_all_seeded_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all seeded data."""
        return copy.deepcopy(self._seeded_data)

    def clear(self):
        """Clear all seeded data."""
        self._seeded_data.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get seeder statistics."""
        return {
            "strategy": self._strategy.value,
            "total_plans": len(self._plans),
            "total_seedings": len(self._results),
            "current_data": {k: len(v) for k, v in self._seeded_data.items()},
            "total_records": sum(len(v) for v in self._seeded_data.values()),
        }

    def format_result(self, result: SeedResult) -> str:
        """Format seeding result for display."""
        lines = [
            "=" * 50,
            f"  SEED RESULT: {result.plan.name}",
            "=" * 50,
            "",
            f"  ID: {result.result_id}",
            f"  Strategy: {result.plan.strategy.value}",
            f"  Duration: {result.duration_ms:.2f}ms",
            "",
            "-" * 50,
            "  RECORDS CREATED",
            "-" * 50,
            "",
        ]

        for category, count in result.records_created.items():
            lines.append(f"  {category}: {count}")

        lines.extend([
            "",
            f"  Total: {result.total_records}",
            f"  Relationships: {result.relationships_created}",
            "",
        ])

        if result.errors:
            lines.append("-" * 50)
            lines.append("  ERRORS")
            lines.append("-" * 50)
            for error in result.errors:
                lines.append(f"  • {error}")
            lines.append("")

        lines.append("=" * 50)
        return "\n".join(lines)


def create_data_seeder(
    strategy: SeedStrategy = SeedStrategy.STANDARD,
    seed: Optional[int] = None,
) -> DataSeeder:
    """Create a data seeder instance."""
    return DataSeeder(strategy=strategy, seed=seed)
