"""
TestAI Agent - Test Enricher

Enriches tests with additional context, data, and
intelligence from multiple sources.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import uuid
import re


class EnrichmentSource(Enum):
    """Sources of enrichment data."""
    SECURITY_RULES = "security_rules"
    ACCESSIBILITY_GUIDELINES = "accessibility"
    PERFORMANCE_BENCHMARKS = "performance"
    BROWSER_COMPATIBILITY = "browser_compat"
    USER_PATTERNS = "user_patterns"
    ERROR_HISTORY = "error_history"
    DOMAIN_KNOWLEDGE = "domain_knowledge"
    BEST_PRACTICES = "best_practices"


class EnrichmentType(Enum):
    """Types of enrichment."""
    ADD_STEPS = "add_steps"
    ADD_ASSERTIONS = "add_assertions"
    ADD_DATA = "add_data"
    ADD_PRECONDITIONS = "add_preconditions"
    ADD_TAGS = "add_tags"
    IMPROVE_COVERAGE = "improve_coverage"
    ADD_EDGE_CASES = "add_edge_cases"


@dataclass
class EnrichmentRule:
    """A rule for enriching tests."""
    rule_id: str
    source: EnrichmentSource
    pattern: str  # Regex pattern to match tests
    enrichment_type: EnrichmentType
    enrichment_data: Any
    priority: int = 5
    enabled: bool = True


@dataclass
class EnrichmentApplication:
    """Record of an enrichment applied to a test."""
    rule_id: str
    source: EnrichmentSource
    enrichment_type: EnrichmentType
    description: str
    applied_at: datetime


@dataclass
class EnrichedTest:
    """A test with enrichment applied."""
    test_id: str
    original_id: str
    title: str
    description: str
    steps: List[str]
    assertions: List[str]
    preconditions: List[str]
    test_data: List[Dict[str, Any]]
    priority: str
    category: str
    tags: List[str]
    enrichments: List[EnrichmentApplication]
    coverage_score: float
    quality_score: float
    coverage_areas: Set[str] = field(default_factory=set)
    original_sources: List[str] = field(default_factory=list)
    estimated_duration_ms: int = 5000
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichmentResult:
    """Result of enrichment process."""
    result_id: str
    tests_processed: int
    tests_enriched: int
    enrichments_applied: int
    average_quality_improvement: float
    enriched_tests: List[EnrichedTest]
    enriched_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestEnricher:
    """
    Enriches tests with additional context and intelligence.

    Features:
    - Rule-based enrichment
    - Multiple enrichment sources
    - Quality scoring
    - Coverage improvement
    """

    # Default security enrichment rules
    SECURITY_RULES = {
        "input_validation": {
            "pattern": r"(input|form|field|enter|type)",
            "steps": [
                "Test with SQL injection payload",
                "Test with XSS payload",
                "Test with extremely long input",
                "Test with special characters",
                "Test with empty input",
            ],
            "assertions": [
                "Verify input is sanitized",
                "Verify error message does not expose system details",
            ],
        },
        "authentication": {
            "pattern": r"(login|signin|auth|password)",
            "steps": [
                "Test with brute force attempts",
                "Test session timeout behavior",
                "Test password complexity requirements",
                "Test account lockout mechanism",
            ],
            "assertions": [
                "Verify failed login attempts are logged",
                "Verify session is properly invalidated on logout",
            ],
        },
        "authorization": {
            "pattern": r"(admin|role|permission|access)",
            "steps": [
                "Test accessing resource without authentication",
                "Test accessing resource with insufficient privileges",
                "Test privilege escalation attempts",
            ],
            "assertions": [
                "Verify proper 403 Forbidden response",
                "Verify no sensitive data leakage",
            ],
        },
    }

    # Default accessibility rules
    ACCESSIBILITY_RULES = {
        "keyboard": {
            "pattern": r"(click|button|link|navigate)",
            "steps": [
                "Navigate using keyboard only (Tab, Enter, Space)",
                "Verify focus indicators are visible",
                "Test skip links functionality",
            ],
            "assertions": [
                "Verify all interactive elements are keyboard accessible",
                "Verify focus order is logical",
            ],
        },
        "screen_reader": {
            "pattern": r"(form|input|image|button)",
            "steps": [
                "Test with screen reader (VoiceOver/NVDA)",
                "Verify all images have alt text",
                "Verify form labels are associated with inputs",
            ],
            "assertions": [
                "Verify ARIA labels are descriptive",
                "Verify form errors are announced",
            ],
        },
    }

    # Default performance rules
    PERFORMANCE_RULES = {
        "loading": {
            "pattern": r"(load|page|navigate|open)",
            "steps": [
                "Measure initial page load time",
                "Measure Time to First Byte (TTFB)",
                "Measure Largest Contentful Paint (LCP)",
            ],
            "assertions": [
                "Verify page loads within 3 seconds",
                "Verify TTFB is under 200ms",
                "Verify LCP is under 2.5 seconds",
            ],
        },
        "interaction": {
            "pattern": r"(click|submit|search|filter)",
            "steps": [
                "Measure response time for user interaction",
                "Measure First Input Delay (FID)",
            ],
            "assertions": [
                "Verify response time under 100ms",
                "Verify FID under 100ms",
            ],
        },
    }

    def __init__(
        self,
        enabled_sources: Optional[Set[EnrichmentSource]] = None,
    ):
        """Initialize the enricher."""
        self.enabled_sources = enabled_sources or set(EnrichmentSource)
        self._rules: List[EnrichmentRule] = []
        self._rule_counter = 0
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """Set up default enrichment rules."""
        # Security rules
        if EnrichmentSource.SECURITY_RULES in self.enabled_sources:
            for name, data in self.SECURITY_RULES.items():
                self.add_rule(
                    source=EnrichmentSource.SECURITY_RULES,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_STEPS,
                    enrichment_data=data["steps"],
                    priority=1,
                )
                self.add_rule(
                    source=EnrichmentSource.SECURITY_RULES,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_ASSERTIONS,
                    enrichment_data=data["assertions"],
                    priority=1,
                )

        # Accessibility rules
        if EnrichmentSource.ACCESSIBILITY_GUIDELINES in self.enabled_sources:
            for name, data in self.ACCESSIBILITY_RULES.items():
                self.add_rule(
                    source=EnrichmentSource.ACCESSIBILITY_GUIDELINES,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_STEPS,
                    enrichment_data=data["steps"],
                    priority=2,
                )
                self.add_rule(
                    source=EnrichmentSource.ACCESSIBILITY_GUIDELINES,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_ASSERTIONS,
                    enrichment_data=data["assertions"],
                    priority=2,
                )

        # Performance rules
        if EnrichmentSource.PERFORMANCE_BENCHMARKS in self.enabled_sources:
            for name, data in self.PERFORMANCE_RULES.items():
                self.add_rule(
                    source=EnrichmentSource.PERFORMANCE_BENCHMARKS,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_STEPS,
                    enrichment_data=data["steps"],
                    priority=3,
                )
                self.add_rule(
                    source=EnrichmentSource.PERFORMANCE_BENCHMARKS,
                    pattern=data["pattern"],
                    enrichment_type=EnrichmentType.ADD_ASSERTIONS,
                    enrichment_data=data["assertions"],
                    priority=3,
                )

    def add_rule(
        self,
        source: EnrichmentSource,
        pattern: str,
        enrichment_type: EnrichmentType,
        enrichment_data: Any,
        priority: int = 5,
    ) -> EnrichmentRule:
        """Add an enrichment rule."""
        self._rule_counter += 1
        rule_id = f"ER-{self._rule_counter:04d}"

        rule = EnrichmentRule(
            rule_id=rule_id,
            source=source,
            pattern=pattern,
            enrichment_type=enrichment_type,
            enrichment_data=enrichment_data,
            priority=priority,
        )

        self._rules.append(rule)
        return rule

    def enrich(
        self,
        tests: List[Dict[str, Any]],
        sources: Optional[Set[EnrichmentSource]] = None,
    ) -> EnrichmentResult:
        """Enrich a list of tests."""
        result_id = f"ENR-{uuid.uuid4().hex[:8]}"
        sources = sources or self.enabled_sources

        enriched_tests = []
        total_enrichments = 0
        quality_improvements = []

        for test in tests:
            enriched, applications = self._enrich_single(test, sources)
            enriched_tests.append(enriched)
            total_enrichments += len(applications)

            if applications:
                quality_improvements.append(enriched.quality_score)

        avg_improvement = (
            sum(quality_improvements) / len(quality_improvements)
            if quality_improvements else 0
        )

        return EnrichmentResult(
            result_id=result_id,
            tests_processed=len(tests),
            tests_enriched=len([t for t in enriched_tests if t.enrichments]),
            enrichments_applied=total_enrichments,
            average_quality_improvement=avg_improvement,
            enriched_tests=enriched_tests,
            enriched_at=datetime.now(),
        )

    def _enrich_single(
        self,
        test: Dict[str, Any],
        sources: Set[EnrichmentSource],
    ) -> tuple[EnrichedTest, List[EnrichmentApplication]]:
        """Enrich a single test."""
        title = test.get("title", test.get("name", ""))
        description = test.get("description", "")
        text_to_match = f"{title} {description}".lower()

        # Original data
        steps = list(test.get("steps", []))
        assertions = list(test.get("assertions", test.get("expected_results", [])))
        preconditions = list(test.get("preconditions", []))
        test_data = list(test.get("test_data", []))
        tags = set(test.get("tags", []))

        applications = []

        # Apply matching rules
        for rule in sorted(self._rules, key=lambda r: r.priority):
            if not rule.enabled:
                continue
            if rule.source not in sources:
                continue

            if re.search(rule.pattern, text_to_match, re.IGNORECASE):
                application = self._apply_rule(
                    rule, steps, assertions, preconditions, test_data, tags
                )
                if application:
                    applications.append(application)

        # Calculate scores
        original_quality = self._calculate_quality(test)
        coverage_score = self._calculate_coverage_score(steps, assertions, tags)
        quality_score = self._calculate_quality_score(
            steps, assertions, preconditions, len(applications)
        )

        test_id = f"ENR-{test.get('id', uuid.uuid4().hex[:8])}"

        # Extract coverage areas from test
        coverage_areas = self._extract_coverage_areas(test, tags)

        enriched = EnrichedTest(
            test_id=test_id,
            original_id=test.get("id", ""),
            title=title,
            description=description,
            steps=steps,
            assertions=assertions,
            preconditions=preconditions,
            test_data=test_data,
            priority=test.get("priority", "medium"),
            category=test.get("category", "functional"),
            tags=list(tags),
            enrichments=applications,
            coverage_score=coverage_score,
            quality_score=quality_score,
            coverage_areas=coverage_areas,
            original_sources=test.get("sources", []),
            estimated_duration_ms=test.get("estimated_duration_ms", 5000),
            metadata={
                "original_quality": original_quality,
                "quality_improvement": quality_score - original_quality,
            },
        )

        return enriched, applications

    def _apply_rule(
        self,
        rule: EnrichmentRule,
        steps: List[str],
        assertions: List[str],
        preconditions: List[str],
        test_data: List[Dict[str, Any]],
        tags: Set[str],
    ) -> Optional[EnrichmentApplication]:
        """Apply a single rule to a test."""
        applied = False

        if rule.enrichment_type == EnrichmentType.ADD_STEPS:
            for step in rule.enrichment_data:
                if step not in steps:
                    steps.append(step)
                    applied = True

        elif rule.enrichment_type == EnrichmentType.ADD_ASSERTIONS:
            for assertion in rule.enrichment_data:
                if assertion not in assertions:
                    assertions.append(assertion)
                    applied = True

        elif rule.enrichment_type == EnrichmentType.ADD_PRECONDITIONS:
            for pre in rule.enrichment_data:
                if pre not in preconditions:
                    preconditions.append(pre)
                    applied = True

        elif rule.enrichment_type == EnrichmentType.ADD_DATA:
            test_data.extend(rule.enrichment_data)
            applied = True

        elif rule.enrichment_type == EnrichmentType.ADD_TAGS:
            new_tags = set(rule.enrichment_data) - tags
            if new_tags:
                tags.update(new_tags)
                applied = True

        if applied:
            return EnrichmentApplication(
                rule_id=rule.rule_id,
                source=rule.source,
                enrichment_type=rule.enrichment_type,
                description=f"Applied {rule.enrichment_type.value} from {rule.source.value}",
                applied_at=datetime.now(),
            )

        return None

    def _calculate_quality(self, test: Dict[str, Any]) -> float:
        """Calculate quality score for original test."""
        score = 0.0

        # Has steps
        steps = test.get("steps", [])
        if steps:
            score += min(len(steps) * 0.1, 0.3)

        # Has assertions
        assertions = test.get("assertions", test.get("expected_results", []))
        if assertions:
            score += min(len(assertions) * 0.15, 0.3)

        # Has description
        if test.get("description"):
            score += 0.1

        # Has priority
        if test.get("priority"):
            score += 0.1

        # Has tags
        if test.get("tags"):
            score += 0.1

        # Has preconditions
        if test.get("preconditions"):
            score += 0.1

        return min(score, 1.0)

    def _calculate_coverage_score(
        self,
        steps: List[str],
        assertions: List[str],
        tags: Set[str],
    ) -> float:
        """Calculate coverage score."""
        score = 0.0

        # More steps = more coverage
        score += min(len(steps) * 0.05, 0.3)

        # More assertions = more coverage
        score += min(len(assertions) * 0.08, 0.4)

        # Security/accessibility/performance tags
        for tag in tags:
            if tag.lower() in ["security", "a11y", "accessibility", "performance"]:
                score += 0.1

        return min(score, 1.0)

    def _extract_coverage_areas(
        self,
        test: Dict[str, Any],
        tags: Set[str],
    ) -> Set[str]:
        """Extract coverage areas from a test."""
        coverage = set()

        # From explicit coverage field
        if "coverage" in test:
            cov = test["coverage"]
            if isinstance(cov, list):
                coverage.update(cov)
            elif isinstance(cov, str):
                coverage.add(cov)
            elif isinstance(cov, set):
                coverage.update(cov)

        # From category
        if "category" in test:
            coverage.add(f"category:{test['category']}")

        # From tags
        for tag in tags:
            coverage.add(f"tag:{tag}")

        # From title keywords
        title = test.get("title", test.get("name", "")).lower()
        keywords = ["login", "signup", "checkout", "payment", "search", "profile", "admin", "form", "input"]
        for kw in keywords:
            if kw in title:
                coverage.add(f"feature:{kw}")

        return coverage

    def _calculate_quality_score(
        self,
        steps: List[str],
        assertions: List[str],
        preconditions: List[str],
        enrichment_count: int,
    ) -> float:
        """Calculate overall quality score."""
        score = 0.0

        # Steps
        score += min(len(steps) * 0.05, 0.25)

        # Assertions
        score += min(len(assertions) * 0.08, 0.3)

        # Preconditions
        score += min(len(preconditions) * 0.1, 0.15)

        # Enrichments applied
        score += min(enrichment_count * 0.05, 0.3)

        return min(score, 1.0)

    def get_rules(
        self,
        source: Optional[EnrichmentSource] = None,
    ) -> List[EnrichmentRule]:
        """Get enrichment rules."""
        rules = self._rules
        if source:
            rules = [r for r in rules if r.source == source]
        return rules

    def enable_source(self, source: EnrichmentSource):
        """Enable an enrichment source."""
        self.enabled_sources.add(source)

    def disable_source(self, source: EnrichmentSource):
        """Disable an enrichment source."""
        self.enabled_sources.discard(source)

    def get_statistics(self) -> Dict[str, Any]:
        """Get enricher statistics."""
        rules_by_source = {}
        for rule in self._rules:
            source = rule.source.value
            rules_by_source[source] = rules_by_source.get(source, 0) + 1

        return {
            "total_rules": len(self._rules),
            "enabled_sources": [s.value for s in self.enabled_sources],
            "rules_by_source": rules_by_source,
        }

    def format_result(self, result: EnrichmentResult) -> str:
        """Format enrichment result."""
        lines = [
            "=" * 60,
            "  TEST ENRICHMENT RESULT",
            "=" * 60,
            "",
            f"  Result ID: {result.result_id}",
            f"  Tests Processed: {result.tests_processed}",
            f"  Tests Enriched: {result.tests_enriched}",
            f"  Enrichments Applied: {result.enrichments_applied}",
            f"  Avg Quality Improvement: {result.average_quality_improvement:.0%}",
            "",
        ]

        if result.enriched_tests:
            lines.extend(["-" * 60, "  ENRICHED TESTS", "-" * 60, ""])

            for test in result.enriched_tests[:5]:
                lines.extend([
                    f"  {test.test_id}: {test.title}",
                    f"    Quality: {test.quality_score:.0%} | Coverage: {test.coverage_score:.0%}",
                    f"    Steps: {len(test.steps)} | Assertions: {len(test.assertions)}",
                    f"    Enrichments: {len(test.enrichments)}",
                    "",
                ])

                for enr in test.enrichments[:3]:
                    lines.append(f"      - {enr.source.value}: {enr.enrichment_type.value}")

                lines.append("")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_test_enricher(
    enabled_sources: Optional[Set[EnrichmentSource]] = None,
) -> TestEnricher:
    """Create a test enricher instance."""
    return TestEnricher(enabled_sources)
