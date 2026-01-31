"""
TestAI Agent - Test Coverage Mapper

Maps tests to the code they cover, enabling
impact analysis and targeted test selection.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class CoverageScope(Enum):
    """Scope of coverage mapping."""
    FILE = "file"
    CLASS = "class"
    FUNCTION = "function"
    LINE = "line"


@dataclass
class TestCoverageInfo:
    """Coverage information for a single test."""
    test_id: str
    test_name: str
    covered_files: Set[str]
    covered_functions: Set[str]
    covered_lines: Dict[str, Set[int]]  # file -> line numbers
    execution_time_ms: float
    last_run: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeEntityCoverage:
    """Tests covering a specific code entity."""
    entity_path: str
    entity_type: str  # file, class, function
    covering_tests: Set[str]
    coverage_count: int
    last_covered: Optional[datetime]


@dataclass
class CoverageMapping:
    """Complete coverage mapping."""
    mapping_id: str
    created_at: datetime
    test_count: int
    file_count: int
    function_count: int
    tests_by_coverage: Dict[str, List[str]]  # code_path -> test_ids
    coverage_by_test: Dict[str, TestCoverageInfo]
    uncovered_code: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestCoverageMapper:
    """
    Maps tests to the code they cover.

    Features:
    - Test-to-code mapping
    - Code-to-test reverse mapping
    - Impact analysis support
    - Coverage aggregation
    """

    def __init__(
        self,
        scope: CoverageScope = CoverageScope.FUNCTION,
    ):
        """Initialize the mapper."""
        self._scope = scope
        self._test_coverage: Dict[str, TestCoverageInfo] = {}
        self._code_coverage: Dict[str, CodeEntityCoverage] = {}
        self._all_code_entities: Set[str] = set()
        self._mapping_counter = 0

    def register_code_entity(
        self,
        entity_path: str,
        entity_type: str = "function",
    ):
        """Register a code entity to track coverage for."""
        self._all_code_entities.add(entity_path)
        if entity_path not in self._code_coverage:
            self._code_coverage[entity_path] = CodeEntityCoverage(
                entity_path=entity_path,
                entity_type=entity_type,
                covering_tests=set(),
                coverage_count=0,
                last_covered=None,
            )

    def register_test_coverage(
        self,
        test_id: str,
        test_name: str,
        covered_files: Optional[List[str]] = None,
        covered_functions: Optional[List[str]] = None,
        covered_lines: Optional[Dict[str, List[int]]] = None,
        execution_time_ms: float = 0.0,
    ) -> TestCoverageInfo:
        """Register coverage data for a test."""
        now = datetime.now()

        info = TestCoverageInfo(
            test_id=test_id,
            test_name=test_name,
            covered_files=set(covered_files or []),
            covered_functions=set(covered_functions or []),
            covered_lines={
                f: set(lines) for f, lines in (covered_lines or {}).items()
            },
            execution_time_ms=execution_time_ms,
            last_run=now,
        )

        self._test_coverage[test_id] = info

        # Update reverse mapping
        for file_path in info.covered_files:
            self._update_code_coverage(file_path, "file", test_id, now)

        for func_path in info.covered_functions:
            self._update_code_coverage(func_path, "function", test_id, now)

        for file_path in info.covered_lines:
            for line_num in info.covered_lines[file_path]:
                line_path = f"{file_path}:{line_num}"
                self._update_code_coverage(line_path, "line", test_id, now)

        return info

    def _update_code_coverage(
        self,
        entity_path: str,
        entity_type: str,
        test_id: str,
        timestamp: datetime,
    ):
        """Update code coverage tracking."""
        if entity_path not in self._code_coverage:
            self._code_coverage[entity_path] = CodeEntityCoverage(
                entity_path=entity_path,
                entity_type=entity_type,
                covering_tests=set(),
                coverage_count=0,
                last_covered=None,
            )

        entity = self._code_coverage[entity_path]
        entity.covering_tests.add(test_id)
        entity.coverage_count += 1
        entity.last_covered = timestamp

    def get_tests_for_code(
        self,
        code_path: str,
        include_dependencies: bool = False,
    ) -> List[str]:
        """Get tests that cover a specific code path."""
        entity = self._code_coverage.get(code_path)
        if not entity:
            return []

        tests = list(entity.covering_tests)

        if include_dependencies:
            # Include tests that cover dependent code
            for other_path, other_entity in self._code_coverage.items():
                if self._is_dependent(code_path, other_path):
                    tests.extend(other_entity.covering_tests)

        return list(set(tests))

    def _is_dependent(self, code_a: str, code_b: str) -> bool:
        """Check if code_b depends on code_a (simplified)."""
        # Simple heuristic: same file = potentially dependent
        file_a = code_a.split(":")[0] if ":" in code_a else code_a
        file_b = code_b.split(":")[0] if ":" in code_b else code_b
        return file_a == file_b and code_a != code_b

    def get_coverage_for_test(self, test_id: str) -> Optional[TestCoverageInfo]:
        """Get coverage information for a test."""
        return self._test_coverage.get(test_id)

    def get_affected_tests(
        self,
        changed_files: List[str],
        changed_functions: Optional[List[str]] = None,
        changed_lines: Optional[Dict[str, List[int]]] = None,
    ) -> List[str]:
        """Get tests affected by code changes."""
        affected: Set[str] = set()

        # Tests covering changed files
        for file_path in changed_files:
            entity = self._code_coverage.get(file_path)
            if entity:
                affected.update(entity.covering_tests)

        # Tests covering changed functions
        if changed_functions:
            for func_path in changed_functions:
                entity = self._code_coverage.get(func_path)
                if entity:
                    affected.update(entity.covering_tests)

        # Tests covering changed lines
        if changed_lines:
            for file_path, lines in changed_lines.items():
                for line_num in lines:
                    line_path = f"{file_path}:{line_num}"
                    entity = self._code_coverage.get(line_path)
                    if entity:
                        affected.update(entity.covering_tests)

        return list(affected)

    def generate_mapping(self, name: str = "Coverage Mapping") -> CoverageMapping:
        """Generate a complete coverage mapping."""
        self._mapping_counter += 1
        mapping_id = f"MAP-{self._mapping_counter:05d}"

        # Build tests by coverage
        tests_by_coverage: Dict[str, List[str]] = {}
        for entity_path, entity in self._code_coverage.items():
            tests_by_coverage[entity_path] = list(entity.covering_tests)

        # Find uncovered code
        covered_entities = set(self._code_coverage.keys())
        uncovered = list(self._all_code_entities - covered_entities)

        # Count unique items
        files = set()
        functions = set()
        for info in self._test_coverage.values():
            files.update(info.covered_files)
            functions.update(info.covered_functions)

        return CoverageMapping(
            mapping_id=mapping_id,
            created_at=datetime.now(),
            test_count=len(self._test_coverage),
            file_count=len(files),
            function_count=len(functions),
            tests_by_coverage=tests_by_coverage,
            coverage_by_test=dict(self._test_coverage),
            uncovered_code=uncovered,
            metadata={"name": name},
        )

    def get_test_overlap(
        self,
        test_a: str,
        test_b: str,
    ) -> Dict[str, Any]:
        """Calculate coverage overlap between two tests."""
        info_a = self._test_coverage.get(test_a)
        info_b = self._test_coverage.get(test_b)

        if not info_a or not info_b:
            return {"overlap_pct": 0.0, "unique_a": 0, "unique_b": 0}

        # File overlap
        files_a = info_a.covered_files
        files_b = info_b.covered_files
        common_files = files_a & files_b

        # Function overlap
        funcs_a = info_a.covered_functions
        funcs_b = info_b.covered_functions
        common_funcs = funcs_a & funcs_b

        total_coverage = len(files_a | files_b) + len(funcs_a | funcs_b)
        common_coverage = len(common_files) + len(common_funcs)

        overlap_pct = (common_coverage / total_coverage * 100) if total_coverage else 0.0

        return {
            "overlap_pct": overlap_pct,
            "common_files": len(common_files),
            "common_functions": len(common_funcs),
            "unique_a": len(files_a - files_b) + len(funcs_a - funcs_b),
            "unique_b": len(files_b - files_a) + len(funcs_b - funcs_a),
        }

    def find_redundant_tests(
        self,
        overlap_threshold: float = 90.0,
    ) -> List[Dict[str, Any]]:
        """Find tests with high coverage overlap (potentially redundant)."""
        redundant = []
        test_ids = list(self._test_coverage.keys())

        for i, test_a in enumerate(test_ids):
            for test_b in test_ids[i + 1:]:
                overlap = self.get_test_overlap(test_a, test_b)
                if overlap["overlap_pct"] >= overlap_threshold:
                    redundant.append({
                        "test_a": test_a,
                        "test_b": test_b,
                        "overlap_pct": overlap["overlap_pct"],
                    })

        return sorted(redundant, key=lambda x: -x["overlap_pct"])

    def get_coverage_matrix(self) -> Dict[str, Dict[str, bool]]:
        """Generate test-to-code coverage matrix."""
        matrix: Dict[str, Dict[str, bool]] = {}

        for test_id, info in self._test_coverage.items():
            matrix[test_id] = {}

            for file_path in info.covered_files:
                matrix[test_id][file_path] = True

            for func_path in info.covered_functions:
                matrix[test_id][func_path] = True

        return matrix

    def get_statistics(self) -> Dict[str, Any]:
        """Get mapper statistics."""
        total_coverage_points = sum(
            len(info.covered_files) + len(info.covered_functions)
            for info in self._test_coverage.values()
        )

        return {
            "total_tests": len(self._test_coverage),
            "total_code_entities": len(self._code_coverage),
            "registered_entities": len(self._all_code_entities),
            "total_coverage_points": total_coverage_points,
            "scope": self._scope.value,
        }

    def format_mapping(self, mapping: CoverageMapping) -> str:
        """Format a coverage mapping for display."""
        lines = [
            "=" * 55,
            f"  TEST COVERAGE MAPPING",
            "=" * 55,
            "",
            f"  Mapping ID: {mapping.mapping_id}",
            f"  Created: {mapping.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 55,
            "  SUMMARY",
            "-" * 55,
            "",
            f"  Tests Mapped: {mapping.test_count}",
            f"  Files Covered: {mapping.file_count}",
            f"  Functions Covered: {mapping.function_count}",
            "",
        ]

        if mapping.uncovered_code:
            lines.append("-" * 55)
            lines.append("  UNCOVERED CODE")
            lines.append("-" * 55)
            lines.append("")
            for path in mapping.uncovered_code[:10]:
                lines.append(f"  • {path}")
            if len(mapping.uncovered_code) > 10:
                lines.append(f"  ... and {len(mapping.uncovered_code) - 10} more")
            lines.append("")

        # Top covered code
        top_covered = sorted(
            mapping.tests_by_coverage.items(),
            key=lambda x: -len(x[1])
        )[:5]

        if top_covered:
            lines.append("-" * 55)
            lines.append("  MOST TESTED CODE")
            lines.append("-" * 55)
            lines.append("")
            for path, tests in top_covered:
                lines.append(f"  {path}: {len(tests)} tests")
            lines.append("")

        lines.append("=" * 55)
        return "\n".join(lines)


def create_coverage_mapper(
    scope: CoverageScope = CoverageScope.FUNCTION,
) -> TestCoverageMapper:
    """Create a coverage mapper instance."""
    return TestCoverageMapper(scope=scope)
