"""
TestAI Agent - Dependency Mapper

Maps dependencies between tests and source code
to enable accurate impact analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


class DependencyType(Enum):
    """Types of dependencies."""
    DIRECT = "direct"  # Test directly imports/uses code
    INDIRECT = "indirect"  # Dependency through another module
    COVERS = "covers"  # Test covers this code path
    FIXTURE = "fixture"  # Test uses fixture from this file
    MOCK = "mock"  # Test mocks this code


@dataclass
class TestDependency:
    """A dependency relationship."""
    test_id: str
    target_path: str
    dependency_type: DependencyType
    target_element: Optional[str] = None  # Function/class name
    confidence: float = 1.0  # How confident we are in this mapping
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyGraph:
    """Graph of all dependencies."""
    dependencies: List[TestDependency]
    test_count: int
    target_count: int
    built_at: datetime
    coverage_map: Dict[str, List[str]] = field(default_factory=dict)  # file -> [test_ids]
    test_map: Dict[str, List[str]] = field(default_factory=dict)  # test_id -> [file_paths]


class DependencyMapper:
    """
    Maps dependencies between tests and source code.

    Supports:
    - Import analysis
    - Coverage mapping
    - Fixture tracking
    - Mock tracking
    """

    # Patterns for import analysis
    IMPORT_PATTERNS = {
        "python": [
            re.compile(r"from\s+([\w.]+)\s+import", re.MULTILINE),
            re.compile(r"import\s+([\w.]+)", re.MULTILINE),
        ],
        "javascript": [
            re.compile(r"import\s+.*\s+from\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
            re.compile(r"require\s*\(\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
        ],
    }

    # Patterns for fixture usage
    FIXTURE_PATTERNS = {
        "python": re.compile(r"@pytest\.fixture|def\s+(\w+)\s*\(\s*(\w+)\s*\)", re.MULTILINE),
        "javascript": re.compile(r"beforeEach|beforeAll|afterEach|afterAll|describe", re.MULTILINE),
    }

    def __init__(self):
        """Initialize the dependency mapper."""
        self._dependencies: List[TestDependency] = []
        self._coverage_map: Dict[str, Set[str]] = {}  # file -> test_ids
        self._test_map: Dict[str, Set[str]] = {}  # test_id -> file_paths

    def add_dependency(
        self,
        test_id: str,
        target_path: str,
        dependency_type: DependencyType,
        target_element: Optional[str] = None,
        confidence: float = 1.0,
    ):
        """Add a dependency relationship."""
        dep = TestDependency(
            test_id=test_id,
            target_path=target_path,
            dependency_type=dependency_type,
            target_element=target_element,
            confidence=confidence,
        )
        self._dependencies.append(dep)

        # Update maps
        if target_path not in self._coverage_map:
            self._coverage_map[target_path] = set()
        self._coverage_map[target_path].add(test_id)

        if test_id not in self._test_map:
            self._test_map[test_id] = set()
        self._test_map[test_id].add(target_path)

    def analyze_test_file(
        self,
        test_id: str,
        test_content: str,
        test_file_path: str,
        language: str = "python",
    ) -> List[TestDependency]:
        """Analyze a test file and extract dependencies."""
        dependencies = []

        # Extract imports
        import_patterns = self.IMPORT_PATTERNS.get(language, [])
        for pattern in import_patterns:
            matches = pattern.findall(test_content)
            for match in matches:
                # Convert module path to file path approximation
                if language == "python":
                    file_path = match.replace(".", "/") + ".py"
                else:
                    file_path = match

                dep = TestDependency(
                    test_id=test_id,
                    target_path=file_path,
                    dependency_type=DependencyType.DIRECT,
                    confidence=0.8,
                )
                dependencies.append(dep)
                self.add_dependency(
                    test_id, file_path, DependencyType.DIRECT, confidence=0.8
                )

        return dependencies

    def add_coverage_mapping(
        self,
        test_id: str,
        covered_files: List[str],
        covered_functions: Optional[Dict[str, List[str]]] = None,
    ):
        """Add coverage mapping from test execution."""
        for file_path in covered_files:
            self.add_dependency(
                test_id,
                file_path,
                DependencyType.COVERS,
                confidence=1.0,
            )

        if covered_functions:
            for file_path, functions in covered_functions.items():
                for func in functions:
                    self.add_dependency(
                        test_id,
                        file_path,
                        DependencyType.COVERS,
                        target_element=func,
                        confidence=1.0,
                    )

    def get_tests_for_file(
        self,
        file_path: str,
        include_indirect: bool = True,
    ) -> List[str]:
        """Get tests that depend on a file."""
        direct_tests = self._coverage_map.get(file_path, set())

        if not include_indirect:
            return list(direct_tests)

        # Find indirect dependencies
        all_tests = set(direct_tests)

        # Check for files that import this file
        for dep in self._dependencies:
            if dep.target_path == file_path and dep.dependency_type == DependencyType.DIRECT:
                # Find tests that depend on the importing file
                if dep.test_id in self._test_map:
                    all_tests.add(dep.test_id)

        return list(all_tests)

    def get_files_for_test(
        self,
        test_id: str,
    ) -> List[str]:
        """Get files that a test depends on."""
        return list(self._test_map.get(test_id, set()))

    def get_dependencies_by_type(
        self,
        dependency_type: DependencyType,
    ) -> List[TestDependency]:
        """Get all dependencies of a specific type."""
        return [d for d in self._dependencies if d.dependency_type == dependency_type]

    def build_graph(self) -> DependencyGraph:
        """Build the complete dependency graph."""
        return DependencyGraph(
            dependencies=self._dependencies.copy(),
            test_count=len(self._test_map),
            target_count=len(self._coverage_map),
            built_at=datetime.now(),
            coverage_map={k: list(v) for k, v in self._coverage_map.items()},
            test_map={k: list(v) for k, v in self._test_map.items()},
        )

    def find_orphan_tests(
        self,
        all_test_ids: List[str],
    ) -> List[str]:
        """Find tests with no known dependencies."""
        return [t for t in all_test_ids if t not in self._test_map or not self._test_map[t]]

    def find_uncovered_files(
        self,
        all_files: List[str],
    ) -> List[str]:
        """Find source files with no test coverage."""
        return [f for f in all_files if f not in self._coverage_map or not self._coverage_map[f]]

    def get_coverage_score(
        self,
        file_path: str,
    ) -> float:
        """Get coverage score for a file (based on test count)."""
        tests = self._coverage_map.get(file_path, set())
        if not tests:
            return 0.0

        # More tests = higher coverage (up to a point)
        return min(len(tests) / 5, 1.0)

    def get_test_breadth(
        self,
        test_id: str,
    ) -> float:
        """Get breadth score for a test (how many files it covers)."""
        files = self._test_map.get(test_id, set())
        if not files:
            return 0.0

        # More files = broader test
        return min(len(files) / 10, 1.0)

    def merge_with(self, other: "DependencyMapper"):
        """Merge another mapper's data into this one."""
        for dep in other._dependencies:
            self._dependencies.append(dep)

            if dep.target_path not in self._coverage_map:
                self._coverage_map[dep.target_path] = set()
            self._coverage_map[dep.target_path].add(dep.test_id)

            if dep.test_id not in self._test_map:
                self._test_map[dep.test_id] = set()
            self._test_map[dep.test_id].add(dep.target_path)

    def clear(self):
        """Clear all mappings."""
        self._dependencies.clear()
        self._coverage_map.clear()
        self._test_map.clear()

    def format_graph(self, graph: DependencyGraph) -> str:
        """Format the dependency graph as readable text."""
        lines = [
            "=" * 60,
            "  DEPENDENCY GRAPH",
            "=" * 60,
            "",
            f"  Built At: {graph.built_at.strftime('%Y-%m-%d %H:%M')}",
            f"  Tests: {graph.test_count}",
            f"  Source Files: {graph.target_count}",
            f"  Total Dependencies: {len(graph.dependencies)}",
            "",
        ]

        # Group by dependency type
        by_type: Dict[DependencyType, int] = {}
        for dep in graph.dependencies:
            by_type[dep.dependency_type] = by_type.get(dep.dependency_type, 0) + 1

        lines.extend([
            "-" * 60,
            "  DEPENDENCY TYPES",
            "-" * 60,
        ])

        for dep_type, count in by_type.items():
            lines.append(f"  {dep_type.value}: {count}")

        # Show top covered files
        sorted_files = sorted(
            graph.coverage_map.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )[:10]

        if sorted_files:
            lines.extend([
                "",
                "-" * 60,
                "  TOP COVERED FILES",
                "-" * 60,
            ])

            for file_path, test_ids in sorted_files:
                lines.append(f"  {file_path}: {len(test_ids)} tests")

        # Show broadest tests
        sorted_tests = sorted(
            graph.test_map.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )[:10]

        if sorted_tests:
            lines.extend([
                "",
                "-" * 60,
                "  BROADEST TESTS",
                "-" * 60,
            ])

            for test_id, file_paths in sorted_tests:
                lines.append(f"  {test_id}: {len(file_paths)} files")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_dependency_mapper() -> DependencyMapper:
    """Create a dependency mapper instance."""
    return DependencyMapper()
