"""
TestAI Agent - Contract Validator

API contract validation with schema checking,
response verification, and compatibility testing.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid


class ContractType(Enum):
    """Types of API contracts."""
    JSON_SCHEMA = "json_schema"
    OPENAPI = "openapi"
    GRAPHQL = "graphql"
    PROTOBUF = "protobuf"
    CUSTOM = "custom"


class ViolationSeverity(Enum):
    """Severity of contract violations."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationScope(Enum):
    """Scope of validation."""
    REQUEST = "request"
    RESPONSE = "response"
    BOTH = "both"


@dataclass
class SchemaViolation:
    """A schema violation."""
    violation_id: str
    path: str
    message: str
    severity: ViolationSeverity
    expected: Any
    actual: Any
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContractResult:
    """Result of contract validation."""
    result_id: str
    contract_id: str
    valid: bool
    violations: List[SchemaViolation]
    warnings: int
    errors: int
    validated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Contract:
    """An API contract definition."""
    contract_id: str
    name: str
    contract_type: ContractType
    schema: Dict[str, Any]
    version: str
    created_at: datetime
    endpoints: List[str] = field(default_factory=list)


class ContractValidator:
    """
    API contract validator.

    Features:
    - JSON Schema validation
    - OpenAPI compliance
    - Response structure verification
    - Breaking change detection
    - Compatibility checking
    """

    # JSON Schema type mapping
    JSON_TYPES = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }

    def __init__(
        self,
        strict_mode: bool = False,
        allow_additional_properties: bool = True,
    ):
        """Initialize the validator."""
        self._strict_mode = strict_mode
        self._allow_additional = allow_additional_properties

        self._contracts: Dict[str, Contract] = {}
        self._results: List[ContractResult] = []

        self._contract_counter = 0
        self._result_counter = 0
        self._violation_counter = 0

    def register_contract(
        self,
        name: str,
        schema: Dict[str, Any],
        contract_type: ContractType = ContractType.JSON_SCHEMA,
        version: str = "1.0.0",
        endpoints: Optional[List[str]] = None,
    ) -> Contract:
        """Register an API contract."""
        self._contract_counter += 1
        contract_id = f"CONTRACT-{self._contract_counter:05d}"

        contract = Contract(
            contract_id=contract_id,
            name=name,
            contract_type=contract_type,
            schema=schema,
            version=version,
            created_at=datetime.now(),
            endpoints=endpoints or [],
        )

        self._contracts[contract_id] = contract
        return contract

    def validate(
        self,
        contract_id: str,
        data: Any,
        scope: ValidationScope = ValidationScope.RESPONSE,
    ) -> ContractResult:
        """Validate data against a contract."""
        self._result_counter += 1
        result_id = f"VALRESULT-{self._result_counter:05d}"

        contract = self._contracts.get(contract_id)
        if not contract:
            return ContractResult(
                result_id=result_id,
                contract_id=contract_id,
                valid=False,
                violations=[
                    self._create_violation(
                        path="",
                        message=f"Contract {contract_id} not found",
                        severity=ViolationSeverity.ERROR,
                        expected="Contract",
                        actual=None,
                    )
                ],
                warnings=0,
                errors=1,
                validated_at=datetime.now(),
            )

        violations = []

        if contract.contract_type == ContractType.JSON_SCHEMA:
            violations = self._validate_json_schema(data, contract.schema, "")
        elif contract.contract_type == ContractType.OPENAPI:
            violations = self._validate_openapi(data, contract.schema, scope)
        else:
            violations = self._validate_custom(data, contract.schema)

        errors = sum(1 for v in violations if v.severity == ViolationSeverity.ERROR)
        warnings = sum(1 for v in violations if v.severity == ViolationSeverity.WARNING)

        result = ContractResult(
            result_id=result_id,
            contract_id=contract_id,
            valid=errors == 0,
            violations=violations,
            warnings=warnings,
            errors=errors,
            validated_at=datetime.now(),
            metadata={"scope": scope.value},
        )

        self._results.append(result)
        return result

    def _create_violation(
        self,
        path: str,
        message: str,
        severity: ViolationSeverity,
        expected: Any,
        actual: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> SchemaViolation:
        """Create a schema violation."""
        self._violation_counter += 1

        return SchemaViolation(
            violation_id=f"VIOL-{self._violation_counter:05d}",
            path=path,
            message=message,
            severity=severity,
            expected=expected,
            actual=actual,
            context=context or {},
        )

    def _validate_json_schema(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str,
    ) -> List[SchemaViolation]:
        """Validate data against JSON schema."""
        violations = []

        # Check type
        expected_type = schema.get("type")
        if expected_type:
            if not self._check_type(data, expected_type):
                violations.append(self._create_violation(
                    path=path or "root",
                    message=f"Expected type '{expected_type}', got '{type(data).__name__}'",
                    severity=ViolationSeverity.ERROR,
                    expected=expected_type,
                    actual=type(data).__name__,
                ))
                return violations  # Can't continue if type is wrong

        # Check required properties
        if isinstance(data, dict):
            required = schema.get("required", [])
            for prop in required:
                if prop not in data:
                    violations.append(self._create_violation(
                        path=f"{path}.{prop}" if path else prop,
                        message=f"Required property '{prop}' is missing",
                        severity=ViolationSeverity.ERROR,
                        expected=prop,
                        actual=None,
                    ))

            # Check properties
            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                if prop_name in data:
                    prop_path = f"{path}.{prop_name}" if path else prop_name
                    violations.extend(
                        self._validate_json_schema(data[prop_name], prop_schema, prop_path)
                    )

            # Check additional properties
            if not self._allow_additional:
                extra = set(data.keys()) - set(properties.keys())
                for prop in extra:
                    violations.append(self._create_violation(
                        path=f"{path}.{prop}" if path else prop,
                        message=f"Additional property '{prop}' is not allowed",
                        severity=ViolationSeverity.WARNING,
                        expected=None,
                        actual=prop,
                    ))

        # Check array items
        if isinstance(data, list) and "items" in schema:
            items_schema = schema["items"]
            for i, item in enumerate(data):
                item_path = f"{path}[{i}]"
                violations.extend(
                    self._validate_json_schema(item, items_schema, item_path)
                )

        # Check string constraints
        if expected_type == "string" and isinstance(data, str):
            min_length = schema.get("minLength", 0)
            max_length = schema.get("maxLength", float("inf"))

            if len(data) < min_length:
                violations.append(self._create_violation(
                    path=path,
                    message=f"String length {len(data)} is less than minimum {min_length}",
                    severity=ViolationSeverity.ERROR,
                    expected=f">= {min_length}",
                    actual=len(data),
                ))

            if len(data) > max_length:
                violations.append(self._create_violation(
                    path=path,
                    message=f"String length {len(data)} exceeds maximum {max_length}",
                    severity=ViolationSeverity.ERROR,
                    expected=f"<= {max_length}",
                    actual=len(data),
                ))

            # Check enum
            enum_values = schema.get("enum")
            if enum_values and data not in enum_values:
                violations.append(self._create_violation(
                    path=path,
                    message=f"Value '{data}' is not in allowed enum values",
                    severity=ViolationSeverity.ERROR,
                    expected=enum_values,
                    actual=data,
                ))

        # Check number constraints
        if expected_type in ("number", "integer") and isinstance(data, (int, float)):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")

            if minimum is not None and data < minimum:
                violations.append(self._create_violation(
                    path=path,
                    message=f"Value {data} is less than minimum {minimum}",
                    severity=ViolationSeverity.ERROR,
                    expected=f">= {minimum}",
                    actual=data,
                ))

            if maximum is not None and data > maximum:
                violations.append(self._create_violation(
                    path=path,
                    message=f"Value {data} exceeds maximum {maximum}",
                    severity=ViolationSeverity.ERROR,
                    expected=f"<= {maximum}",
                    actual=data,
                ))

        return violations

    def _validate_openapi(
        self,
        data: Any,
        schema: Dict[str, Any],
        scope: ValidationScope,
    ) -> List[SchemaViolation]:
        """Validate data against OpenAPI schema."""
        # Simplified OpenAPI validation using JSON Schema validation
        # In real implementation, this would parse OpenAPI spec

        if "schema" in schema:
            return self._validate_json_schema(data, schema["schema"], "")
        elif "properties" in schema or "type" in schema:
            return self._validate_json_schema(data, schema, "")

        return []

    def _validate_custom(
        self,
        data: Any,
        schema: Dict[str, Any],
    ) -> List[SchemaViolation]:
        """Validate data against custom schema rules."""
        violations = []

        # Custom rules support
        rules = schema.get("rules", [])
        for rule in rules:
            rule_type = rule.get("type")
            rule_path = rule.get("path", "")
            rule_value = rule.get("value")

            actual = self._get_value_at_path(data, rule_path)

            if rule_type == "equals":
                if actual != rule_value:
                    violations.append(self._create_violation(
                        path=rule_path,
                        message=f"Value does not equal expected",
                        severity=ViolationSeverity.ERROR,
                        expected=rule_value,
                        actual=actual,
                    ))

            elif rule_type == "exists":
                if actual is None:
                    violations.append(self._create_violation(
                        path=rule_path,
                        message=f"Path '{rule_path}' does not exist",
                        severity=ViolationSeverity.ERROR,
                        expected="exists",
                        actual=None,
                    ))

            elif rule_type == "type":
                if not isinstance(actual, self.JSON_TYPES.get(rule_value, type(None))):
                    violations.append(self._create_violation(
                        path=rule_path,
                        message=f"Type mismatch",
                        severity=ViolationSeverity.ERROR,
                        expected=rule_value,
                        actual=type(actual).__name__,
                    ))

        return violations

    def _check_type(self, data: Any, expected_type: str) -> bool:
        """Check if data matches expected JSON Schema type."""
        python_type = self.JSON_TYPES.get(expected_type)
        if python_type is None:
            return True  # Unknown type, allow
        return isinstance(data, python_type)

    def _get_value_at_path(self, data: Any, path: str) -> Any:
        """Get value at a dotted path."""
        if not path:
            return data

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list):
                try:
                    index = int(part)
                    current = current[index]
                except (ValueError, IndexError):
                    return None
            else:
                return None

        return current

    def check_compatibility(
        self,
        old_contract_id: str,
        new_contract_id: str,
    ) -> Dict[str, Any]:
        """Check compatibility between contract versions."""
        old_contract = self._contracts.get(old_contract_id)
        new_contract = self._contracts.get(new_contract_id)

        if not old_contract or not new_contract:
            return {
                "compatible": False,
                "error": "Contract not found",
            }

        breaking_changes = []
        additions = []
        removals = []

        old_props = old_contract.schema.get("properties", {})
        new_props = new_contract.schema.get("properties", {})
        old_required = set(old_contract.schema.get("required", []))
        new_required = set(new_contract.schema.get("required", []))

        # Check for removed required properties (breaking)
        for prop in old_required:
            if prop not in new_props:
                breaking_changes.append(f"Required property '{prop}' was removed")
                removals.append(prop)

        # Check for new required properties (breaking)
        for prop in new_required - old_required:
            if prop in new_props and prop not in old_props:
                breaking_changes.append(f"New required property '{prop}' was added")

        # Check for type changes (breaking)
        for prop in old_props:
            if prop in new_props:
                old_type = old_props[prop].get("type")
                new_type = new_props[prop].get("type")
                if old_type != new_type:
                    breaking_changes.append(
                        f"Property '{prop}' type changed from '{old_type}' to '{new_type}'"
                    )

        # Check for additions (non-breaking)
        for prop in new_props:
            if prop not in old_props:
                additions.append(prop)

        return {
            "compatible": len(breaking_changes) == 0,
            "breaking_changes": breaking_changes,
            "additions": additions,
            "removals": removals,
            "old_version": old_contract.version,
            "new_version": new_contract.version,
        }

    def get_contract(
        self,
        contract_id: str,
    ) -> Optional[Contract]:
        """Get a contract by ID."""
        return self._contracts.get(contract_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get validator statistics."""
        total_results = len(self._results)
        valid_count = sum(1 for r in self._results if r.valid)

        return {
            "total_contracts": len(self._contracts),
            "total_validations": total_results,
            "valid_count": valid_count,
            "invalid_count": total_results - valid_count,
            "pass_rate": valid_count / total_results if total_results > 0 else 1.0,
        }

    def format_result(self, result: ContractResult) -> str:
        """Format a validation result for display."""
        status = "✅ VALID" if result.valid else "❌ INVALID"

        lines = [
            "=" * 60,
            f"  {status} CONTRACT VALIDATION",
            "=" * 60,
            "",
            f"  Contract: {result.contract_id}",
            f"  Errors: {result.errors}",
            f"  Warnings: {result.warnings}",
            "",
        ]

        if result.violations:
            lines.append("-" * 60)
            lines.append("  VIOLATIONS")
            lines.append("-" * 60)

            for v in result.violations[:10]:
                severity_icon = "❌" if v.severity == ViolationSeverity.ERROR else "⚠️"
                lines.append(f"  {severity_icon} {v.path}: {v.message}")

            if len(result.violations) > 10:
                lines.append(f"  ... and {len(result.violations) - 10} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_contract_validator(
    strict_mode: bool = False,
    allow_additional_properties: bool = True,
) -> ContractValidator:
    """Create a contract validator instance."""
    return ContractValidator(
        strict_mode=strict_mode,
        allow_additional_properties=allow_additional_properties,
    )
