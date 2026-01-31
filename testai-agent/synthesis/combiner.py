"""
TestAI Agent - Test Combiner

Combines tests from multiple sources using intelligent
strategies to create comprehensive test coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import uuid
import re


class CombinationStrategy(Enum):
    """Strategies for combining tests."""
    UNION = "union"  # Include all tests from all sources
    INTERSECTION = "intersection"  # Only tests present in all sources
    PRIORITY_BASED = "priority_based"  # Higher priority sources win
    COVERAGE_OPTIMAL = "coverage_optimal"  # Maximize coverage with minimal tests
    SMART_MERGE = "smart_merge"  # Intelligently merge similar tests


@dataclass
class TestSource:
    """A source of test cases."""
    source_id: str
    name: str
    priority: int
    tests: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CombinedTest:
    """A combined test from multiple sources."""
    test_id: str
    title: str
    description: str
    steps: List[str]
    assertions: List[str]
    priority: str
    category: str
    sources: List[str]  # Source IDs that contributed
    coverage_areas: Set[str]
    tags: List[str]
    estimated_duration_ms: int = 5000
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CombinationResult:
    """Result of combining tests."""
    result_id: str
    strategy: CombinationStrategy
    combined_tests: List[CombinedTest]
    source_count: int
    total_input_tests: int
    total_output_tests: int
    deduplication_count: int
    coverage_score: float
    combined_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestCombiner:
    """
    Combines tests from multiple sources.

    Features:
    - Multiple combination strategies
    - Intelligent deduplication
    - Coverage optimization
    - Source attribution
    """

    def __init__(self, default_strategy: CombinationStrategy = CombinationStrategy.SMART_MERGE):
        """Initialize the combiner."""
        self.default_strategy = default_strategy
        self._sources: Dict[str, TestSource] = {}
        self._result_counter = 0

    def add_source(
        self,
        name: str,
        tests: List[Dict[str, Any]],
        priority: int = 5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestSource:
        """Add a test source."""
        source_id = f"SRC-{len(self._sources) + 1:03d}"

        source = TestSource(
            source_id=source_id,
            name=name,
            priority=priority,
            tests=tests,
            metadata=metadata or {},
        )

        self._sources[source_id] = source
        return source

    def combine(
        self,
        strategy: Optional[CombinationStrategy] = None,
        source_ids: Optional[List[str]] = None,
    ) -> CombinationResult:
        """Combine tests from sources."""
        self._result_counter += 1
        result_id = f"COMB-{self._result_counter:05d}"

        strategy = strategy or self.default_strategy

        # Get sources to combine
        if source_ids:
            sources = [self._sources[sid] for sid in source_ids if sid in self._sources]
        else:
            sources = list(self._sources.values())

        if not sources:
            return CombinationResult(
                result_id=result_id,
                strategy=strategy,
                combined_tests=[],
                source_count=0,
                total_input_tests=0,
                total_output_tests=0,
                deduplication_count=0,
                coverage_score=0.0,
                combined_at=datetime.now(),
            )

        total_input = sum(len(s.tests) for s in sources)

        # Apply combination strategy
        if strategy == CombinationStrategy.UNION:
            combined = self._combine_union(sources)
        elif strategy == CombinationStrategy.INTERSECTION:
            combined = self._combine_intersection(sources)
        elif strategy == CombinationStrategy.PRIORITY_BASED:
            combined = self._combine_priority_based(sources)
        elif strategy == CombinationStrategy.COVERAGE_OPTIMAL:
            combined = self._combine_coverage_optimal(sources)
        else:
            combined = self._combine_smart_merge(sources)

        # Calculate deduplication
        dedup_count = total_input - len(combined)

        # Calculate coverage score
        coverage = self._calculate_coverage(combined)

        return CombinationResult(
            result_id=result_id,
            strategy=strategy,
            combined_tests=combined,
            source_count=len(sources),
            total_input_tests=total_input,
            total_output_tests=len(combined),
            deduplication_count=dedup_count,
            coverage_score=coverage,
            combined_at=datetime.now(),
        )

    def _combine_union(self, sources: List[TestSource]) -> List[CombinedTest]:
        """Union all tests with deduplication."""
        seen_titles: Set[str] = set()
        combined = []

        for source in sorted(sources, key=lambda s: s.priority):
            for test in source.tests:
                title = test.get("title", test.get("name", ""))
                if title and title not in seen_titles:
                    seen_titles.add(title)
                    combined.append(self._to_combined_test(test, [source.source_id]))

        return combined

    def _combine_intersection(self, sources: List[TestSource]) -> List[CombinedTest]:
        """Only tests present in all sources."""
        if not sources:
            return []

        # Get titles from first source
        first_titles = {
            test.get("title", test.get("name", ""))
            for test in sources[0].tests
        }

        # Intersect with other sources
        for source in sources[1:]:
            source_titles = {
                test.get("title", test.get("name", ""))
                for test in source.tests
            }
            first_titles &= source_titles

        # Build combined tests
        combined = []
        source_ids = [s.source_id for s in sources]

        for source in sources:
            for test in source.tests:
                title = test.get("title", test.get("name", ""))
                if title in first_titles:
                    first_titles.discard(title)  # Only add once
                    combined.append(self._to_combined_test(test, source_ids))

        return combined

    def _combine_priority_based(self, sources: List[TestSource]) -> List[CombinedTest]:
        """Higher priority sources win on conflicts."""
        sorted_sources = sorted(sources, key=lambda s: s.priority)
        seen_titles: Dict[str, CombinedTest] = {}

        for source in sorted_sources:
            for test in source.tests:
                title = test.get("title", test.get("name", ""))
                if title:
                    # Higher priority replaces lower
                    combined = self._to_combined_test(test, [source.source_id])
                    if title in seen_titles:
                        # Merge source IDs
                        combined.sources.extend(seen_titles[title].sources)
                    seen_titles[title] = combined

        return list(seen_titles.values())

    def _combine_coverage_optimal(self, sources: List[TestSource]) -> List[CombinedTest]:
        """Maximize coverage with minimal tests."""
        all_tests: List[Tuple[Dict[str, Any], str]] = []

        for source in sources:
            for test in source.tests:
                all_tests.append((test, source.source_id))

        # Calculate coverage for each test
        test_coverage: List[Tuple[Dict[str, Any], str, Set[str]]] = []

        for test, source_id in all_tests:
            coverage = self._extract_coverage(test)
            test_coverage.append((test, source_id, coverage))

        # Greedy selection for maximum coverage
        selected: List[CombinedTest] = []
        covered: Set[str] = set()

        # Sort by coverage size descending
        test_coverage.sort(key=lambda x: len(x[2] - covered), reverse=True)

        for test, source_id, coverage in test_coverage:
            new_coverage = coverage - covered
            if new_coverage:  # Only add if provides new coverage
                covered |= new_coverage
                combined = self._to_combined_test(test, [source_id])
                combined.coverage_areas = coverage
                selected.append(combined)

        return selected

    def _combine_smart_merge(self, sources: List[TestSource]) -> List[CombinedTest]:
        """Intelligently merge similar tests."""
        all_tests: List[Tuple[Dict[str, Any], str]] = []

        for source in sources:
            for test in source.tests:
                all_tests.append((test, source.source_id))

        # Group similar tests
        groups: List[List[Tuple[Dict[str, Any], str]]] = []

        for test, source_id in all_tests:
            # Find similar group
            found = False
            for group in groups:
                if self._is_similar(test, group[0][0]):
                    group.append((test, source_id))
                    found = True
                    break

            if not found:
                groups.append([(test, source_id)])

        # Merge each group
        combined = []
        for group in groups:
            merged = self._merge_group(group)
            combined.append(merged)

        return combined

    def _is_similar(self, test1: Dict[str, Any], test2: Dict[str, Any]) -> bool:
        """Check if two tests are similar."""
        title1 = test1.get("title", test1.get("name", "")).lower()
        title2 = test2.get("title", test2.get("name", "")).lower()

        # Simple word overlap check
        words1 = set(re.findall(r'\w+', title1))
        words2 = set(re.findall(r'\w+', title2))

        if not words1 or not words2:
            return False

        overlap = len(words1 & words2) / max(len(words1), len(words2))
        return overlap > 0.6

    def _merge_group(
        self,
        group: List[Tuple[Dict[str, Any], str]],
    ) -> CombinedTest:
        """Merge a group of similar tests."""
        source_ids = [sid for _, sid in group]
        primary = group[0][0]

        # Combine steps from all tests
        all_steps: List[str] = []
        all_assertions: List[str] = []
        all_tags: Set[str] = set()
        all_coverage: Set[str] = set()

        for test, _ in group:
            steps = test.get("steps", [])
            if isinstance(steps, list):
                all_steps.extend(steps)

            assertions = test.get("assertions", test.get("expected_results", []))
            if isinstance(assertions, list):
                all_assertions.extend(assertions)

            tags = test.get("tags", [])
            if isinstance(tags, list):
                all_tags.update(tags)

            all_coverage |= self._extract_coverage(test)

        # Deduplicate
        unique_steps = list(dict.fromkeys(all_steps))
        unique_assertions = list(dict.fromkeys(all_assertions))

        test_id = f"TC-{uuid.uuid4().hex[:8]}"

        return CombinedTest(
            test_id=test_id,
            title=primary.get("title", primary.get("name", "Merged Test")),
            description=primary.get("description", ""),
            steps=unique_steps,
            assertions=unique_assertions,
            priority=primary.get("priority", "medium"),
            category=primary.get("category", "functional"),
            sources=list(set(source_ids)),
            coverage_areas=all_coverage,
            tags=list(all_tags),
            metadata={"merged_count": len(group)},
        )

    def _to_combined_test(
        self,
        test: Dict[str, Any],
        source_ids: List[str],
    ) -> CombinedTest:
        """Convert a test dict to CombinedTest."""
        test_id = test.get("id", f"TC-{uuid.uuid4().hex[:8]}")

        steps = test.get("steps", [])
        if isinstance(steps, str):
            steps = [steps]

        assertions = test.get("assertions", test.get("expected_results", []))
        if isinstance(assertions, str):
            assertions = [assertions]

        tags = test.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        return CombinedTest(
            test_id=test_id,
            title=test.get("title", test.get("name", "Untitled")),
            description=test.get("description", ""),
            steps=steps,
            assertions=assertions,
            priority=test.get("priority", "medium"),
            category=test.get("category", "functional"),
            sources=source_ids,
            coverage_areas=self._extract_coverage(test),
            tags=tags,
            estimated_duration_ms=test.get("estimated_duration_ms", 5000),
        )

    def _extract_coverage(self, test: Dict[str, Any]) -> Set[str]:
        """Extract coverage areas from a test."""
        coverage = set()

        # From explicit coverage field
        if "coverage" in test:
            cov = test["coverage"]
            if isinstance(cov, list):
                coverage.update(cov)
            elif isinstance(cov, str):
                coverage.add(cov)

        # From category
        if "category" in test:
            coverage.add(f"category:{test['category']}")

        # From tags
        tags = test.get("tags", [])
        for tag in tags:
            coverage.add(f"tag:{tag}")

        # From title keywords
        title = test.get("title", test.get("name", "")).lower()
        keywords = ["login", "signup", "checkout", "payment", "search", "profile", "admin"]
        for kw in keywords:
            if kw in title:
                coverage.add(f"feature:{kw}")

        return coverage

    def _calculate_coverage(self, tests: List[CombinedTest]) -> float:
        """Calculate overall coverage score."""
        if not tests:
            return 0.0

        all_areas: Set[str] = set()
        for test in tests:
            all_areas |= test.coverage_areas

        # Simple coverage score based on area count
        expected_areas = 20  # Expected number of coverage areas
        coverage = min(len(all_areas) / expected_areas, 1.0)

        return round(coverage, 2)

    def get_sources(self) -> List[TestSource]:
        """Get all sources."""
        return list(self._sources.values())

    def clear_sources(self):
        """Clear all sources."""
        self._sources.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get combiner statistics."""
        total_tests = sum(len(s.tests) for s in self._sources.values())

        return {
            "source_count": len(self._sources),
            "total_tests": total_tests,
            "default_strategy": self.default_strategy.value,
        }

    def format_result(self, result: CombinationResult) -> str:
        """Format combination result."""
        lines = [
            "=" * 60,
            "  TEST COMBINATION RESULT",
            "=" * 60,
            "",
            f"  Result ID: {result.result_id}",
            f"  Strategy: {result.strategy.value}",
            f"  Sources: {result.source_count}",
            "",
            f"  Input Tests: {result.total_input_tests}",
            f"  Output Tests: {result.total_output_tests}",
            f"  Deduplicated: {result.deduplication_count}",
            f"  Coverage Score: {result.coverage_score:.0%}",
            "",
        ]

        if result.combined_tests:
            lines.extend(["-" * 60, "  COMBINED TESTS", "-" * 60, ""])

            for test in result.combined_tests[:10]:
                sources_str = ", ".join(test.sources)
                lines.extend([
                    f"  {test.test_id}: {test.title}",
                    f"    Priority: {test.priority} | Category: {test.category}",
                    f"    Sources: {sources_str}",
                    f"    Steps: {len(test.steps)} | Assertions: {len(test.assertions)}",
                    "",
                ])

            if len(result.combined_tests) > 10:
                lines.append(f"  ... and {len(result.combined_tests) - 10} more tests")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_combiner(
    default_strategy: CombinationStrategy = CombinationStrategy.SMART_MERGE,
) -> TestCombiner:
    """Create a test combiner instance."""
    return TestCombiner(default_strategy)
