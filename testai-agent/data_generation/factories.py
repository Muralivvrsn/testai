"""
TestAI Agent - Data Factories

Factory pattern implementation for creating
complex test data objects with relationships.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import copy


class FieldType(Enum):
    """Types of factory fields."""
    STATIC = "static"
    SEQUENCE = "sequence"
    RANDOM = "random"
    COMPUTED = "computed"
    REFERENCE = "reference"
    FACTORY = "factory"


@dataclass
class FactoryField:
    """A field definition in a factory."""
    name: str
    field_type: FieldType
    value: Any = None
    generator: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    nullable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FactoryTemplate:
    """A factory template for generating objects."""
    template_id: str
    name: str
    entity_type: str
    fields: List[FactoryField]
    traits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    callbacks: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FactoryInstance:
    """An instance created by a factory."""
    instance_id: str
    template: FactoryTemplate
    data: Dict[str, Any]
    traits_applied: List[str]
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataFactory:
    """
    Factory pattern data generator.

    Features:
    - Template-based generation
    - Traits for variations
    - Sequences for unique IDs
    - Relationships between entities
    """

    def __init__(self):
        """Initialize the factory."""
        self._templates: Dict[str, FactoryTemplate] = {}
        self._sequences: Dict[str, int] = {}
        self._instances: List[FactoryInstance] = []
        self._template_counter = 0
        self._instance_counter = 0

        # Initialize built-in templates
        self._init_builtin_templates()

    def _init_builtin_templates(self):
        """Initialize built-in factory templates."""
        # User template
        user_template = FactoryTemplate(
            template_id="builtin-user",
            name="User",
            entity_type="user",
            fields=[
                FactoryField("id", FieldType.SEQUENCE, generator="user_id"),
                FactoryField("email", FieldType.RANDOM, generator="email"),
                FactoryField("username", FieldType.COMPUTED),
                FactoryField("first_name", FieldType.RANDOM, generator="first_name"),
                FactoryField("last_name", FieldType.RANDOM, generator="last_name"),
                FactoryField("password_hash", FieldType.RANDOM, generator="password"),
                FactoryField("created_at", FieldType.RANDOM, generator="datetime"),
                FactoryField("is_active", FieldType.STATIC, value=True),
                FactoryField("role", FieldType.STATIC, value="user"),
            ],
            traits={
                "admin": {"role": "admin", "is_active": True},
                "inactive": {"is_active": False},
                "premium": {"role": "premium", "subscription_tier": "premium"},
            },
        )

        # Product template
        product_template = FactoryTemplate(
            template_id="builtin-product",
            name="Product",
            entity_type="product",
            fields=[
                FactoryField("id", FieldType.SEQUENCE, generator="product_id"),
                FactoryField("sku", FieldType.SEQUENCE, generator="sku"),
                FactoryField("name", FieldType.RANDOM, generator="product_name"),
                FactoryField("description", FieldType.RANDOM, generator="text"),
                FactoryField("price", FieldType.RANDOM, generator="price", constraints={"min": 1, "max": 1000}),
                FactoryField("stock", FieldType.RANDOM, generator="integer", constraints={"min": 0, "max": 100}),
                FactoryField("category", FieldType.STATIC, value="general"),
                FactoryField("is_available", FieldType.STATIC, value=True),
            ],
            traits={
                "out_of_stock": {"stock": 0, "is_available": False},
                "expensive": {"price": 999.99, "category": "luxury"},
                "on_sale": {"on_sale": True, "discount_percent": 20},
            },
        )

        # Order template
        order_template = FactoryTemplate(
            template_id="builtin-order",
            name="Order",
            entity_type="order",
            fields=[
                FactoryField("id", FieldType.SEQUENCE, generator="order_id"),
                FactoryField("order_number", FieldType.SEQUENCE, generator="order_number"),
                FactoryField("user_id", FieldType.REFERENCE),
                FactoryField("total", FieldType.RANDOM, generator="price", constraints={"min": 10, "max": 500}),
                FactoryField("status", FieldType.STATIC, value="pending"),
                FactoryField("created_at", FieldType.RANDOM, generator="datetime"),
                FactoryField("items", FieldType.STATIC, value=[]),
            ],
            traits={
                "completed": {"status": "completed"},
                "cancelled": {"status": "cancelled"},
                "shipped": {"status": "shipped", "shipped_at": "2024-01-15"},
            },
        )

        # Address template
        address_template = FactoryTemplate(
            template_id="builtin-address",
            name="Address",
            entity_type="address",
            fields=[
                FactoryField("id", FieldType.SEQUENCE, generator="address_id"),
                FactoryField("user_id", FieldType.REFERENCE),
                FactoryField("street", FieldType.RANDOM, generator="street"),
                FactoryField("city", FieldType.RANDOM, generator="city"),
                FactoryField("state", FieldType.RANDOM, generator="state"),
                FactoryField("zip", FieldType.RANDOM, generator="zip"),
                FactoryField("country", FieldType.STATIC, value="USA"),
                FactoryField("is_default", FieldType.STATIC, value=False),
            ],
            traits={
                "default": {"is_default": True},
                "billing": {"address_type": "billing"},
                "shipping": {"address_type": "shipping"},
            },
        )

        self._templates = {
            "user": user_template,
            "product": product_template,
            "order": order_template,
            "address": address_template,
        }

    def define(
        self,
        name: str,
        entity_type: str,
        fields: List[Dict[str, Any]],
        traits: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> FactoryTemplate:
        """Define a new factory template."""
        self._template_counter += 1
        template_id = f"TEMPLATE-{self._template_counter:04d}"

        factory_fields = []
        for f in fields:
            field_type = FieldType[f.get("type", "static").upper()]
            factory_fields.append(FactoryField(
                name=f["name"],
                field_type=field_type,
                value=f.get("value"),
                generator=f.get("generator"),
                constraints=f.get("constraints", {}),
                nullable=f.get("nullable", False),
            ))

        template = FactoryTemplate(
            template_id=template_id,
            name=name,
            entity_type=entity_type,
            fields=factory_fields,
            traits=traits or {},
        )

        self._templates[name.lower()] = template
        return template

    def get_template(self, name: str) -> Optional[FactoryTemplate]:
        """Get a template by name."""
        return self._templates.get(name.lower())

    def create(
        self,
        template_name: str,
        overrides: Optional[Dict[str, Any]] = None,
        traits: Optional[List[str]] = None,
    ) -> FactoryInstance:
        """Create an instance from a template."""
        template = self._templates.get(template_name.lower())
        if not template:
            raise ValueError(f"Unknown template: {template_name}")

        self._instance_counter += 1
        instance_id = f"INST-{self._instance_counter:06d}"

        # Generate base data from fields
        data = self._generate_from_fields(template)

        # Apply traits
        applied_traits = []
        if traits:
            for trait_name in traits:
                if trait_name in template.traits:
                    trait_data = template.traits[trait_name]
                    data.update(trait_data)
                    applied_traits.append(trait_name)

        # Apply overrides
        if overrides:
            data.update(overrides)

        instance = FactoryInstance(
            instance_id=instance_id,
            template=template,
            data=data,
            traits_applied=applied_traits,
            created_at=datetime.now(),
        )

        self._instances.append(instance)
        return instance

    def create_batch(
        self,
        template_name: str,
        count: int,
        overrides: Optional[Dict[str, Any]] = None,
        traits: Optional[List[str]] = None,
    ) -> List[FactoryInstance]:
        """Create multiple instances from a template."""
        return [
            self.create(template_name, overrides, traits)
            for _ in range(count)
        ]

    def _generate_from_fields(
        self,
        template: FactoryTemplate,
    ) -> Dict[str, Any]:
        """Generate data from template fields."""
        import random

        data = {}

        for field in template.fields:
            if field.field_type == FieldType.STATIC:
                data[field.name] = field.value

            elif field.field_type == FieldType.SEQUENCE:
                seq_key = f"{template.entity_type}_{field.name}"
                if seq_key not in self._sequences:
                    self._sequences[seq_key] = 0
                self._sequences[seq_key] += 1
                data[field.name] = self._sequences[seq_key]

            elif field.field_type == FieldType.RANDOM:
                data[field.name] = self._generate_random(field.generator, field.constraints)

            elif field.field_type == FieldType.COMPUTED:
                # Computed fields depend on other fields
                if field.name == "username" and "email" in data:
                    data[field.name] = data["email"].split("@")[0]
                elif field.name == "full_name" and "first_name" in data and "last_name" in data:
                    data[field.name] = f"{data['first_name']} {data['last_name']}"
                else:
                    data[field.name] = None

            elif field.field_type == FieldType.REFERENCE:
                # References are typically set via overrides
                data[field.name] = None

            elif field.field_type == FieldType.FACTORY:
                # Nested factory - would need recursion
                data[field.name] = None

        return data

    def _generate_random(
        self,
        generator: Optional[str],
        constraints: Dict[str, Any],
    ) -> Any:
        """Generate random data based on generator type."""
        import random
        import string
        from datetime import datetime, timedelta

        first_names = ["John", "Jane", "Mike", "Sarah", "David", "Emily"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones"]
        product_names = ["Widget", "Gadget", "Device", "Tool", "Item"]
        adjectives = ["Premium", "Deluxe", "Standard", "Basic", "Pro"]

        if generator == "email":
            first = random.choice(first_names).lower()
            last = random.choice(last_names).lower()
            return f"{first}.{last}@example.com"

        elif generator == "first_name":
            return random.choice(first_names)

        elif generator == "last_name":
            return random.choice(last_names)

        elif generator == "password":
            chars = string.ascii_letters + string.digits + "!@#$%"
            return "".join(random.choices(chars, k=16))

        elif generator == "datetime":
            days_ago = random.randint(0, 365)
            dt = datetime.now() - timedelta(days=days_ago)
            return dt.isoformat()

        elif generator == "product_name":
            adj = random.choice(adjectives)
            noun = random.choice(product_names)
            return f"{adj} {noun}"

        elif generator == "text":
            words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur"]
            return " ".join(random.choices(words, k=random.randint(5, 20)))

        elif generator == "price":
            min_val = constraints.get("min", 1)
            max_val = constraints.get("max", 100)
            return round(random.uniform(min_val, max_val), 2)

        elif generator == "integer":
            min_val = constraints.get("min", 0)
            max_val = constraints.get("max", 100)
            return random.randint(min_val, max_val)

        elif generator == "street":
            num = random.randint(100, 9999)
            streets = ["Main St", "Oak Ave", "Park Rd", "Maple Dr"]
            return f"{num} {random.choice(streets)}"

        elif generator == "city":
            cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"]
            return random.choice(cities)

        elif generator == "state":
            states = ["CA", "NY", "TX", "FL", "IL"]
            return random.choice(states)

        elif generator == "zip":
            return str(random.randint(10000, 99999))

        else:
            return None

    def reset_sequences(self):
        """Reset all sequences to zero."""
        self._sequences.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get factory statistics."""
        template_usage: Dict[str, int] = {}
        for instance in self._instances:
            name = instance.template.name
            template_usage[name] = template_usage.get(name, 0) + 1

        trait_usage: Dict[str, int] = {}
        for instance in self._instances:
            for trait in instance.traits_applied:
                trait_usage[trait] = trait_usage.get(trait, 0) + 1

        return {
            "total_templates": len(self._templates),
            "total_instances": len(self._instances),
            "template_usage": template_usage,
            "trait_usage": trait_usage,
            "active_sequences": len(self._sequences),
        }

    def format_instance(self, instance: FactoryInstance) -> str:
        """Format an instance for display."""
        lines = [
            "=" * 50,
            f"  FACTORY INSTANCE: {instance.template.name}",
            "=" * 50,
            "",
            f"  ID: {instance.instance_id}",
            f"  Entity: {instance.template.entity_type}",
            f"  Created: {instance.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        if instance.traits_applied:
            lines.append(f"  Traits: {', '.join(instance.traits_applied)}")
            lines.append("")

        lines.append("  Data:")
        for key, value in instance.data.items():
            lines.append(f"    {key}: {value}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_data_factory() -> DataFactory:
    """Create a data factory instance."""
    return DataFactory()
