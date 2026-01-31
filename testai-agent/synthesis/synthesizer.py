"""
TestAI Agent - Test Synthesizer

The main synthesis engine that orchestrates test combination,
enrichment, and generation to create comprehensive test suites.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable
import uuid

from .combiner import (
    TestCombiner,
    CombinationStrategy,
    CombinedTest,
    TestSource,
)
from .enricher import (
    TestEnricher,
    EnrichmentSource,
    EnrichedTest,
)


class SynthesisMode(Enum):
    """Modes for test synthesis."""
    COMPREHENSIVE = "comprehensive"  # Full synthesis with all sources
    QUICK = "quick"  # Fast synthesis with minimal enrichment
    SECURITY_FOCUSED = "security_focused"  # Prioritize security tests
    ACCESSIBILITY_FOCUSED = "accessibility_focused"  # Prioritize a11y tests
    PERFORMANCE_FOCUSED = "performance_focused"  # Prioritize perf tests
    CUSTOM = "custom"  # User-defined configuration


class SynthesisPhase(Enum):
    """Phases of the synthesis process."""
    INITIALIZED = "initialized"
    COLLECTING = "collecting"
    COMBINING = "combining"
    ENRICHING = "enriching"
    OPTIMIZING = "optimizing"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SynthesisConfig:
    """Configuration for test synthesis."""
    mode: SynthesisMode = SynthesisMode.COMPREHENSIVE
    combination_strategy: CombinationStrategy = CombinationStrategy.SMART_MERGE
    enrichment_sources: List[EnrichmentSource] = field(default_factory=lambda: [
        EnrichmentSource.SECURITY_RULES,
        EnrichmentSource.ACCESSIBILITY_GUIDELINES,
        EnrichmentSource.PERFORMANCE_BENCHMARKS,
    ])
    max_tests: int = 500
    min_coverage_score: float = 0.7
    deduplicate: bool = True
    validate_tests: bool = True
    include_edge_cases: bool = True
    parallel_enrichment: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestValidation:
    """Validation result for a test."""
    test_id: str
    is_valid: bool
    issues: List[str]
    warnings: List[str]
    suggestions: List[str]


@dataclass
class SynthesizedTest:
    """A fully synthesized test ready for execution."""
    test_id: str
    title: str
    description: str
    steps: List[str]
    assertions: List[str]
    priority: str
    category: str
    tags: List[str]
    coverage_areas: Set[str]
    enrichments: List[str]
    sources: List[str]
    validation: Optional[TestValidation]
    estimated_duration_ms: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SynthesizedSuite:
    """A complete synthesized test suite."""
    suite_id: str
    name: str
    description: str
    tests: List[SynthesizedTest]
    config: SynthesisConfig
    source_count: int
    total_input_tests: int
    coverage_score: float
    enrichment_count: int
    validation_passed: int
    validation_failed: int
    phases_completed: List[SynthesisPhase]
    synthesized_at: datetime
    duration_ms: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestSynthesizer:
    """
    Main test synthesis engine.

    Orchestrates the complete synthesis pipeline:
    1. Collect tests from multiple sources
    2. Combine using intelligent strategies
    3. Enrich with domain knowledge
    4. Optimize for coverage
    5. Validate test quality

    Features:
    - Multiple synthesis modes
    - Configurable pipeline
    - Quality validation
    - Coverage optimization
    - Source attribution
    """

    def __init__(self, config: Optional[SynthesisConfig] = None):
        """Initialize the synthesizer."""
        self.config = config or SynthesisConfig()
        self.combiner = TestCombiner(self.config.combination_strategy)
        self.enricher = TestEnricher()

        self._phase = SynthesisPhase.INITIALIZED
        self._phases_completed: List[SynthesisPhase] = []
        self._suite_counter = 0
        self._callbacks: Dict[str, List[Callable]] = {}

        # Statistics
        self._total_synthesized = 0
        self._total_enrichments = 0
        self._total_validations = 0

    def add_tests(
        self,
        source_name: str,
        tests: List[Dict[str, Any]],
        priority: int = 5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TestSource:
        """Add tests from a source."""
        return self.combiner.add_source(
            name=source_name,
            tests=tests,
            priority=priority,
            metadata=metadata,
        )

    def synthesize(
        self,
        name: str = "Synthesized Suite",
        description: str = "",
        config: Optional[SynthesisConfig] = None,
    ) -> SynthesizedSuite:
        """
        Run the complete synthesis pipeline.

        Returns a fully synthesized test suite with
        combined, enriched, and validated tests.
        """
        start_time = datetime.now()
        config = config or self.config
        self._suite_counter += 1
        suite_id = f"SUITE-{self._suite_counter:05d}"

        self._phases_completed = []

        try:
            # Phase 1: Collecting
            self._set_phase(SynthesisPhase.COLLECTING)
            sources = self.combiner.get_sources()
            total_input = sum(len(s.tests) for s in sources)

            # Phase 2: Combining
            self._set_phase(SynthesisPhase.COMBINING)
            combination_result = self.combiner.combine(
                strategy=config.combination_strategy,
            )
            combined_tests = combination_result.combined_tests

            # Phase 3: Enriching
            self._set_phase(SynthesisPhase.ENRICHING)
            enriched_tests = self._enrich_tests(combined_tests, config)

            # Phase 4: Optimizing
            self._set_phase(SynthesisPhase.OPTIMIZING)
            optimized_tests = self._optimize_tests(enriched_tests, config)

            # Phase 5: Validating
            self._set_phase(SynthesisPhase.VALIDATING)
            synthesized_tests, validation_stats = self._validate_and_convert(
                optimized_tests, config
            )

            # Apply max tests limit
            if len(synthesized_tests) > config.max_tests:
                synthesized_tests = synthesized_tests[:config.max_tests]

            # Calculate coverage
            coverage_score = self._calculate_coverage(synthesized_tests)

            # Phase 6: Completed
            self._set_phase(SynthesisPhase.COMPLETED)

            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            self._total_synthesized += len(synthesized_tests)

            return SynthesizedSuite(
                suite_id=suite_id,
                name=name,
                description=description or f"Synthesized from {len(sources)} sources",
                tests=synthesized_tests,
                config=config,
                source_count=len(sources),
                total_input_tests=total_input,
                coverage_score=coverage_score,
                enrichment_count=self._count_enrichments(synthesized_tests),
                validation_passed=validation_stats["passed"],
                validation_failed=validation_stats["failed"],
                phases_completed=self._phases_completed.copy(),
                synthesized_at=datetime.now(),
                duration_ms=duration_ms,
            )

        except Exception as e:
            self._set_phase(SynthesisPhase.FAILED)
            raise SynthesisError(f"Synthesis failed: {str(e)}") from e

    def _set_phase(self, phase: SynthesisPhase):
        """Set the current phase."""
        self._phase = phase
        self._phases_completed.append(phase)
        self._notify("phase_change", {"phase": phase.value})

    def _enrich_tests(
        self,
        tests: List[CombinedTest],
        config: SynthesisConfig,
    ) -> List[EnrichedTest]:
        """Enrich combined tests."""
        # Convert to dict format for enricher
        test_dicts = [
            {
                "id": t.test_id,
                "title": t.title,
                "description": t.description,
                "steps": t.steps,
                "assertions": t.assertions,
                "priority": t.priority,
                "category": t.category,
                "tags": t.tags,
                "coverage": list(t.coverage_areas),
                "sources": t.sources,
                "estimated_duration_ms": t.estimated_duration_ms,
            }
            for t in tests
        ]

        # Determine enrichment sources based on mode
        sources = self._get_enrichment_sources(config)

        # Run enrichment (convert to set for enricher)
        sources_set = set(sources) if sources else None
        result = self.enricher.enrich(test_dicts, sources_set)
        self._total_enrichments += result.enrichments_applied

        return result.enriched_tests

    def _get_enrichment_sources(self, config: SynthesisConfig) -> List[EnrichmentSource]:
        """Get enrichment sources based on mode."""
        if config.mode == SynthesisMode.QUICK:
            return []  # No enrichment for quick mode

        if config.mode == SynthesisMode.SECURITY_FOCUSED:
            return [EnrichmentSource.SECURITY_RULES]

        if config.mode == SynthesisMode.ACCESSIBILITY_FOCUSED:
            return [EnrichmentSource.ACCESSIBILITY_GUIDELINES]

        if config.mode == SynthesisMode.PERFORMANCE_FOCUSED:
            return [EnrichmentSource.PERFORMANCE_BENCHMARKS]

        # Comprehensive or custom mode
        return config.enrichment_sources

    def _optimize_tests(
        self,
        tests: List[EnrichedTest],
        config: SynthesisConfig,
    ) -> List[EnrichedTest]:
        """Optimize tests for coverage and efficiency."""
        if not tests:
            return tests

        optimized = tests.copy()

        # Deduplicate if enabled
        if config.deduplicate:
            optimized = self._deduplicate_tests(optimized)

        # Sort by priority and coverage
        optimized = self._sort_by_priority(optimized)

        # Add edge cases if enabled
        if config.include_edge_cases:
            optimized = self._add_edge_cases(optimized)

        return optimized

    def _deduplicate_tests(self, tests: List[EnrichedTest]) -> List[EnrichedTest]:
        """Remove duplicate tests."""
        seen_titles: Set[str] = set()
        unique = []

        for test in tests:
            normalized = test.title.lower().strip()
            if normalized not in seen_titles:
                seen_titles.add(normalized)
                unique.append(test)

        return unique

    def _sort_by_priority(self, tests: List[EnrichedTest]) -> List[EnrichedTest]:
        """Sort tests by priority."""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        return sorted(
            tests,
            key=lambda t: (
                priority_order.get(t.priority.lower(), 2),
                -len(t.coverage_areas),  # More coverage = higher priority
            )
        )

    def _add_edge_cases(self, tests: List[EnrichedTest]) -> List[EnrichedTest]:
        """Add edge case tests based on existing tests."""
        edge_cases = []

        for test in tests:
            # Generate boundary tests for input fields
            if "input" in test.category.lower() or any("input" in s.lower() for s in test.steps):
                edge_cases.extend(self._generate_input_edge_cases(test))

            # Generate error handling tests
            if "form" in test.title.lower() or "submit" in test.title.lower():
                edge_cases.extend(self._generate_error_edge_cases(test))

        # Limit edge cases to avoid explosion
        max_edge_cases = min(len(tests), 20)
        return tests + edge_cases[:max_edge_cases]

    def _generate_input_edge_cases(self, test: EnrichedTest) -> List[EnrichedTest]:
        """Generate edge cases for input tests."""
        edge_cases = []

        # Empty input edge case
        empty_case = EnrichedTest(
            test_id=f"{test.test_id}-edge-empty",
            original_id=test.original_id,
            title=f"{test.title} - Empty Input",
            description=f"Edge case: {test.description} with empty input",
            steps=test.steps + ["Leave input field empty"],
            assertions=["System handles empty input gracefully"],
            preconditions=test.preconditions,
            test_data=[],
            priority="medium",
            category=test.category,
            tags=list(test.tags) + ["edge-case", "empty-input"],
            enrichments=[],
            coverage_score=test.coverage_score,
            quality_score=test.quality_score,
            coverage_areas=test.coverage_areas | {"edge:empty-input"},
            original_sources=test.original_sources,
        )
        edge_cases.append(empty_case)

        # Max length edge case
        max_case = EnrichedTest(
            test_id=f"{test.test_id}-edge-maxlen",
            original_id=test.original_id,
            title=f"{test.title} - Maximum Length Input",
            description=f"Edge case: {test.description} with maximum length input",
            steps=test.steps + ["Enter maximum allowed characters"],
            assertions=["System handles maximum length input correctly"],
            preconditions=test.preconditions,
            test_data=[],
            priority="low",
            category=test.category,
            tags=list(test.tags) + ["edge-case", "max-length"],
            enrichments=[],
            coverage_score=test.coverage_score,
            quality_score=test.quality_score,
            coverage_areas=test.coverage_areas | {"edge:max-length"},
            original_sources=test.original_sources,
        )
        edge_cases.append(max_case)

        return edge_cases

    def _generate_error_edge_cases(self, test: EnrichedTest) -> List[EnrichedTest]:
        """Generate error handling edge cases."""
        error_case = EnrichedTest(
            test_id=f"{test.test_id}-edge-error",
            original_id=test.original_id,
            title=f"{test.title} - Error Handling",
            description=f"Edge case: {test.description} error scenarios",
            steps=test.steps + ["Trigger error condition", "Verify error handling"],
            assertions=[
                "Error message is displayed",
                "User can recover from error",
                "Form state is preserved",
            ],
            preconditions=test.preconditions,
            test_data=[],
            priority="medium",
            category=test.category,
            tags=list(test.tags) + ["edge-case", "error-handling"],
            enrichments=[],
            coverage_score=test.coverage_score,
            quality_score=test.quality_score,
            coverage_areas=test.coverage_areas | {"edge:error-handling"},
            original_sources=test.original_sources,
        )
        return [error_case]

    def _validate_and_convert(
        self,
        tests: List[EnrichedTest],
        config: SynthesisConfig,
    ) -> tuple[List[SynthesizedTest], Dict[str, int]]:
        """Validate tests and convert to synthesized format."""
        synthesized = []
        stats = {"passed": 0, "failed": 0}

        for test in tests:
            validation = None

            if config.validate_tests:
                validation = self._validate_test(test)
                self._total_validations += 1

                if validation.is_valid:
                    stats["passed"] += 1
                else:
                    stats["failed"] += 1
                    # Skip invalid tests unless they only have warnings
                    if validation.issues:
                        continue
            else:
                stats["passed"] += 1

            synthesized.append(SynthesizedTest(
                test_id=test.test_id,
                title=test.title,
                description=test.description,
                steps=test.steps,
                assertions=test.assertions,
                priority=test.priority,
                category=test.category,
                tags=test.tags,
                coverage_areas=test.coverage_areas,
                enrichments=test.enrichments,
                sources=test.original_sources,
                validation=validation,
                estimated_duration_ms=test.estimated_duration_ms,
            ))

        return synthesized, stats

    def _validate_test(self, test: EnrichedTest) -> TestValidation:
        """Validate a single test for quality."""
        issues = []
        warnings = []
        suggestions = []

        # Check required fields
        if not test.title or len(test.title) < 5:
            issues.append("Title is missing or too short")

        if not test.steps:
            issues.append("No test steps defined")
        elif len(test.steps) < 2:
            warnings.append("Test has very few steps")

        if not test.assertions:
            warnings.append("No assertions defined")

        # Check for vague language
        vague_words = ["something", "stuff", "thing", "etc"]
        for word in vague_words:
            if word in test.title.lower():
                warnings.append(f"Vague language in title: '{word}'")
                break

        # Check step quality
        for i, step in enumerate(test.steps):
            if len(step) < 10:
                warnings.append(f"Step {i+1} is very short")
            if not any(verb in step.lower() for verb in
                      ["click", "enter", "select", "verify", "navigate", "open", "check", "wait"]):
                suggestions.append(f"Step {i+1} may need clearer action verb")

        # Suggest improvements
        if not test.tags:
            suggestions.append("Consider adding tags for better organization")

        if len(test.assertions) < len(test.steps) // 2:
            suggestions.append("Consider adding more assertions for better verification")

        return TestValidation(
            test_id=test.test_id,
            is_valid=len(issues) == 0,
            issues=issues,
            warnings=warnings,
            suggestions=suggestions,
        )

    def _calculate_coverage(self, tests: List[SynthesizedTest]) -> float:
        """Calculate overall coverage score."""
        if not tests:
            return 0.0

        all_areas: Set[str] = set()
        for test in tests:
            all_areas |= test.coverage_areas

        # Expected coverage areas
        expected = 25
        coverage = min(len(all_areas) / expected, 1.0)

        return round(coverage, 2)

    def _count_enrichments(self, tests: List[SynthesizedTest]) -> int:
        """Count total enrichments across all tests."""
        return sum(len(t.enrichments) for t in tests)

    def _notify(self, event: str, data: Dict[str, Any]):
        """Notify callbacks of an event."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception:
                pass

    def on_phase_change(self, callback: Callable[[Dict[str, Any]], None]):
        """Register callback for phase changes."""
        if "phase_change" not in self._callbacks:
            self._callbacks["phase_change"] = []
        self._callbacks["phase_change"].append(callback)

    def get_phase(self) -> SynthesisPhase:
        """Get current synthesis phase."""
        return self._phase

    def get_statistics(self) -> Dict[str, Any]:
        """Get synthesizer statistics."""
        return {
            "current_phase": self._phase.value,
            "suites_created": self._suite_counter,
            "total_synthesized": self._total_synthesized,
            "total_enrichments": self._total_enrichments,
            "total_validations": self._total_validations,
            "sources_count": len(self.combiner.get_sources()),
        }

    def clear(self):
        """Clear all sources and reset state."""
        self.combiner.clear_sources()
        self._phase = SynthesisPhase.INITIALIZED
        self._phases_completed = []

    def format_suite(self, suite: SynthesizedSuite) -> str:
        """Format a synthesized suite for display."""
        lines = [
            "=" * 70,
            "  SYNTHESIZED TEST SUITE",
            "=" * 70,
            "",
            f"  Suite ID: {suite.suite_id}",
            f"  Name: {suite.name}",
            f"  Description: {suite.description}",
            "",
            f"  Mode: {suite.config.mode.value}",
            f"  Strategy: {suite.config.combination_strategy.value}",
            "",
            "-" * 70,
            "  SYNTHESIS SUMMARY",
            "-" * 70,
            "",
            f"  Sources: {suite.source_count}",
            f"  Input Tests: {suite.total_input_tests}",
            f"  Output Tests: {len(suite.tests)}",
            f"  Coverage Score: {suite.coverage_score:.0%}",
            "",
            f"  Enrichments Added: {suite.enrichment_count}",
            f"  Validation Passed: {suite.validation_passed}",
            f"  Validation Failed: {suite.validation_failed}",
            "",
            f"  Duration: {suite.duration_ms}ms",
            "",
        ]

        # Phases
        lines.extend([
            "-" * 70,
            "  PHASES COMPLETED",
            "-" * 70,
            "",
        ])

        for phase in suite.phases_completed:
            icon = "✓" if phase != SynthesisPhase.FAILED else "✗"
            lines.append(f"  {icon} {phase.value}")

        # Tests by category
        lines.extend([
            "",
            "-" * 70,
            "  TESTS BY CATEGORY",
            "-" * 70,
            "",
        ])

        categories: Dict[str, int] = {}
        for test in suite.tests:
            cat = test.category
            categories[cat] = categories.get(cat, 0) + 1

        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat}: {count}")

        # Sample tests
        lines.extend([
            "",
            "-" * 70,
            "  SAMPLE TESTS",
            "-" * 70,
            "",
        ])

        for test in suite.tests[:5]:
            priority_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(test.priority.lower(), "⚪")

            lines.extend([
                f"  {priority_icon} {test.test_id}: {test.title}",
                f"     Steps: {len(test.steps)} | Assertions: {len(test.assertions)}",
                f"     Tags: {', '.join(test.tags[:3])}{'...' if len(test.tags) > 3 else ''}",
                "",
            ])

        if len(suite.tests) > 5:
            lines.append(f"  ... and {len(suite.tests) - 5} more tests")

        lines.extend(["", "=" * 70])
        return "\n".join(lines)


class SynthesisError(Exception):
    """Error during test synthesis."""
    pass


def create_test_synthesizer(
    config: Optional[SynthesisConfig] = None,
) -> TestSynthesizer:
    """Create a test synthesizer instance."""
    return TestSynthesizer(config)
