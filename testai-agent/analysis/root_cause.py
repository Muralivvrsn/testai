"""
TestAI Agent - Root Cause Analyzer

Analyzes test failures to identify root causes using
pattern recognition and historical data.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re


class FailureCategory(Enum):
    """Categories of test failures."""
    ASSERTION = "assertion"
    TIMEOUT = "timeout"
    ELEMENT_NOT_FOUND = "element_not_found"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    DATA_MISMATCH = "data_mismatch"
    STATE_CORRUPTION = "state_corruption"
    RACE_CONDITION = "race_condition"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    ENVIRONMENT = "environment"
    UNKNOWN = "unknown"


class FailureSeverity(Enum):
    """Severity levels for failures."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class FailurePattern:
    """A recognized failure pattern."""
    pattern_id: str
    name: str
    description: str
    category: FailureCategory
    indicators: List[str]
    frequency: int = 0
    last_seen: Optional[datetime] = None


@dataclass
class RootCause:
    """Identified root cause of a failure."""
    cause_id: str
    test_id: str
    category: FailureCategory
    severity: FailureSeverity
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    suggested_fixes: List[str]
    related_tests: List[str]
    code_locations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class FailureAnalysis:
    """Complete failure analysis result."""
    test_id: str
    error_message: str
    stack_trace: Optional[str]
    root_causes: List[RootCause]
    patterns_matched: List[FailurePattern]
    historical_occurrences: int
    similar_failures: List[str]
    recommended_priority: str


class RootCauseAnalyzer:
    """
    Analyzes test failures to identify root causes.

    Features:
    - Pattern-based failure classification
    - Stack trace analysis
    - Historical correlation
    - Confidence scoring
    - Fix suggestions
    """

    # Error patterns for classification
    ERROR_PATTERNS = {
        FailureCategory.ASSERTION: [
            r"assert(ion)?.*failed",
            r"expected.*but (got|was|received)",
            r"not equal",
            r"should (be|have|equal|match)",
            r"does not match",
        ],
        FailureCategory.TIMEOUT: [
            r"timeout",
            r"timed? out",
            r"exceeded.*time",
            r"wait.*expired",
            r"deadline",
        ],
        FailureCategory.ELEMENT_NOT_FOUND: [
            r"element.*not.*found",
            r"no such element",
            r"unable to locate",
            r"selector.*not.*found",
            r"cannot find.*element",
            r"NoSuchElementException",
        ],
        FailureCategory.NETWORK: [
            r"connection.*refused",
            r"connection.*reset",
            r"network.*error",
            r"ECONNREFUSED",
            r"ERR_CONNECTION",
            r"socket.*error",
            r"dns.*failed",
        ],
        FailureCategory.AUTHENTICATION: [
            r"unauthorized",
            r"authentication.*failed",
            r"invalid.*token",
            r"session.*expired",
            r"access.*denied",
            r"forbidden",
            r"401",
            r"403",
        ],
        FailureCategory.DATA_MISMATCH: [
            r"data.*mismatch",
            r"unexpected.*value",
            r"invalid.*data",
            r"schema.*validation",
            r"type.*error",
        ],
        FailureCategory.STATE_CORRUPTION: [
            r"state.*corrupt",
            r"inconsistent.*state",
            r"invalid.*state",
            r"state.*transition",
        ],
        FailureCategory.RACE_CONDITION: [
            r"race.*condition",
            r"concurrent",
            r"deadlock",
            r"stale.*element",
            r"element.*stale",
            r"element.*detached",
            r"StaleElementReferenceException",
        ],
        FailureCategory.RESOURCE_EXHAUSTION: [
            r"out of memory",
            r"memory.*exceeded",
            r"resource.*exhausted",
            r"too many.*connections",
            r"quota.*exceeded",
        ],
        FailureCategory.CONFIGURATION: [
            r"config.*error",
            r"missing.*config",
            r"invalid.*setting",
            r"environment.*variable",
        ],
        FailureCategory.DEPENDENCY: [
            r"dependency.*failed",
            r"service.*unavailable",
            r"upstream.*error",
            r"external.*service",
        ],
        FailureCategory.ENVIRONMENT: [
            r"environment.*error",
            r"platform.*specific",
            r"os.*error",
            r"permission.*denied",
        ],
    }

    # Fix suggestions by category
    FIX_SUGGESTIONS = {
        FailureCategory.ASSERTION: [
            "Verify expected values match current system state",
            "Check for recent data changes that may affect assertions",
            "Review test data setup for correctness",
            "Consider adding tolerance for floating-point comparisons",
        ],
        FailureCategory.TIMEOUT: [
            "Increase timeout value if legitimate slowness",
            "Add explicit waits for asynchronous operations",
            "Check for performance regression in the application",
            "Review network conditions and server load",
        ],
        FailureCategory.ELEMENT_NOT_FOUND: [
            "Verify selector is still valid after UI changes",
            "Add wait for element visibility before interaction",
            "Check if element is inside iframe or shadow DOM",
            "Review dynamic content loading timing",
        ],
        FailureCategory.NETWORK: [
            "Verify service is running and accessible",
            "Check network configuration and firewall rules",
            "Add retry logic for transient failures",
            "Review DNS resolution and connectivity",
        ],
        FailureCategory.AUTHENTICATION: [
            "Verify credentials are current and valid",
            "Check token expiration and refresh logic",
            "Review session management configuration",
            "Ensure proper headers are being sent",
        ],
        FailureCategory.DATA_MISMATCH: [
            "Verify test data matches expected schema",
            "Check for data type conversions",
            "Review API response format changes",
            "Validate data transformation logic",
        ],
        FailureCategory.STATE_CORRUPTION: [
            "Add test isolation to prevent shared state issues",
            "Review setup and teardown procedures",
            "Check for parallel test interference",
            "Implement proper state reset between tests",
        ],
        FailureCategory.RACE_CONDITION: [
            "Add proper synchronization mechanisms",
            "Use explicit waits for element stability",
            "Review parallel execution configuration",
            "Implement retry for stale element references",
        ],
        FailureCategory.RESOURCE_EXHAUSTION: [
            "Review memory usage and leaks",
            "Implement proper resource cleanup",
            "Reduce test parallelism if needed",
            "Monitor system resources during execution",
        ],
        FailureCategory.CONFIGURATION: [
            "Verify configuration file exists and is valid",
            "Check environment variables are set",
            "Review default value handling",
            "Validate configuration against schema",
        ],
        FailureCategory.DEPENDENCY: [
            "Verify external services are available",
            "Implement service health checks",
            "Add retry logic for external calls",
            "Consider using mocks for reliability",
        ],
        FailureCategory.ENVIRONMENT: [
            "Check platform-specific requirements",
            "Verify file and directory permissions",
            "Review OS-specific path handling",
            "Ensure consistent environment setup",
        ],
    }

    def __init__(self):
        """Initialize the root cause analyzer."""
        self._patterns: Dict[str, FailurePattern] = {}
        self._failure_history: Dict[str, List[RootCause]] = {}
        self._pattern_counter = 0
        self._cause_counter = 0
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for faster matching."""
        self._compiled_patterns: Dict[FailureCategory, List[re.Pattern]] = {}
        for category, patterns in self.ERROR_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze(
        self,
        test_id: str,
        error_message: str,
        stack_trace: Optional[str] = None,
        test_context: Optional[Dict[str, Any]] = None,
    ) -> FailureAnalysis:
        """Analyze a test failure to identify root causes."""
        # Classify the error
        categories = self._classify_error(error_message, stack_trace)

        # Generate root causes
        root_causes = []
        for category, confidence in categories:
            self._cause_counter += 1
            cause = RootCause(
                cause_id=f"RC-{self._cause_counter:05d}",
                test_id=test_id,
                category=category,
                severity=self._determine_severity(category, error_message),
                description=self._generate_description(category, error_message),
                confidence=confidence,
                evidence=self._extract_evidence(error_message, stack_trace),
                suggested_fixes=self.FIX_SUGGESTIONS.get(category, []),
                related_tests=self._find_related_tests(test_id, category),
                code_locations=self._extract_code_locations(stack_trace),
            )
            root_causes.append(cause)

            # Store in history
            if test_id not in self._failure_history:
                self._failure_history[test_id] = []
            self._failure_history[test_id].append(cause)

        # Match patterns
        matched_patterns = self._match_patterns(error_message, stack_trace)

        # Find similar failures
        similar = self._find_similar_failures(error_message, categories)

        # Count historical occurrences
        history_count = len(self._failure_history.get(test_id, []))

        return FailureAnalysis(
            test_id=test_id,
            error_message=error_message,
            stack_trace=stack_trace,
            root_causes=root_causes,
            patterns_matched=matched_patterns,
            historical_occurrences=history_count,
            similar_failures=similar,
            recommended_priority=self._recommend_priority(root_causes),
        )

    def _classify_error(
        self,
        error_message: str,
        stack_trace: Optional[str],
    ) -> List[Tuple[FailureCategory, float]]:
        """Classify error into categories with confidence scores."""
        combined_text = error_message
        if stack_trace:
            combined_text += " " + stack_trace

        matches: List[Tuple[FailureCategory, float]] = []

        for category, patterns in self._compiled_patterns.items():
            match_count = 0
            for pattern in patterns:
                if pattern.search(combined_text):
                    match_count += 1

            if match_count > 0:
                # Calculate confidence based on match ratio
                confidence = min(0.95, 0.5 + (match_count / len(patterns)) * 0.45)
                matches.append((category, confidence))

        # Sort by confidence
        matches.sort(key=lambda x: -x[1])

        # If no matches, return unknown
        if not matches:
            matches.append((FailureCategory.UNKNOWN, 0.3))

        return matches[:3]  # Top 3 most likely causes

    def _determine_severity(
        self,
        category: FailureCategory,
        error_message: str,
    ) -> FailureSeverity:
        """Determine severity based on category and error."""
        critical_categories = {
            FailureCategory.AUTHENTICATION,
            FailureCategory.STATE_CORRUPTION,
            FailureCategory.RESOURCE_EXHAUSTION,
        }

        high_categories = {
            FailureCategory.NETWORK,
            FailureCategory.DEPENDENCY,
            FailureCategory.RACE_CONDITION,
        }

        medium_categories = {
            FailureCategory.TIMEOUT,
            FailureCategory.ELEMENT_NOT_FOUND,
            FailureCategory.DATA_MISMATCH,
        }

        if category in critical_categories:
            return FailureSeverity.CRITICAL
        elif category in high_categories:
            return FailureSeverity.HIGH
        elif category in medium_categories:
            return FailureSeverity.MEDIUM
        return FailureSeverity.LOW

    def _generate_description(
        self,
        category: FailureCategory,
        error_message: str,
    ) -> str:
        """Generate human-readable description of the cause."""
        descriptions = {
            FailureCategory.ASSERTION: "Test assertion failed - actual value doesn't match expected",
            FailureCategory.TIMEOUT: "Operation exceeded time limit",
            FailureCategory.ELEMENT_NOT_FOUND: "UI element could not be located on the page",
            FailureCategory.NETWORK: "Network communication error occurred",
            FailureCategory.AUTHENTICATION: "Authentication or authorization failure",
            FailureCategory.DATA_MISMATCH: "Data validation or schema mismatch detected",
            FailureCategory.STATE_CORRUPTION: "Application state is inconsistent or corrupted",
            FailureCategory.RACE_CONDITION: "Timing-related issue or concurrent access problem",
            FailureCategory.RESOURCE_EXHAUSTION: "System resources depleted",
            FailureCategory.CONFIGURATION: "Configuration or settings error",
            FailureCategory.DEPENDENCY: "External dependency or service failure",
            FailureCategory.ENVIRONMENT: "Environment-specific issue detected",
            FailureCategory.UNKNOWN: "Unable to classify failure - manual investigation needed",
        }
        return descriptions.get(category, "Unknown failure type")

    def _extract_evidence(
        self,
        error_message: str,
        stack_trace: Optional[str],
    ) -> List[str]:
        """Extract evidence supporting the root cause analysis."""
        evidence = [f"Error: {error_message[:200]}"]

        if stack_trace:
            # Extract key lines from stack trace
            lines = stack_trace.split("\n")
            relevant_lines = [
                line.strip() for line in lines
                if line.strip() and not line.strip().startswith("at ")
            ][:3]
            evidence.extend(relevant_lines)

        return evidence

    def _extract_code_locations(
        self,
        stack_trace: Optional[str],
    ) -> List[str]:
        """Extract file paths and line numbers from stack trace."""
        if not stack_trace:
            return []

        locations = []

        # Match common stack trace patterns
        patterns = [
            r"at\s+.*\((.*?):(\d+)\)",  # at function (file:line)
            r"([\w./\\]+):(\d+)",  # file:line
            r"File \"(.*?)\", line (\d+)",  # Python style
        ]

        for pattern in patterns:
            matches = re.findall(pattern, stack_trace)
            for match in matches:
                if len(match) == 2:
                    locations.append(f"{match[0]}:{match[1]}")

        return locations[:5]  # Top 5 locations

    def _find_related_tests(
        self,
        test_id: str,
        category: FailureCategory,
    ) -> List[str]:
        """Find tests with similar failures."""
        related = []

        for tid, causes in self._failure_history.items():
            if tid == test_id:
                continue
            for cause in causes:
                if cause.category == category:
                    related.append(tid)
                    break

        return related[:5]

    def _match_patterns(
        self,
        error_message: str,
        stack_trace: Optional[str],
    ) -> List[FailurePattern]:
        """Match against known failure patterns."""
        matched = []
        combined = error_message + (stack_trace or "")

        for pattern in self._patterns.values():
            for indicator in pattern.indicators:
                if indicator.lower() in combined.lower():
                    pattern.frequency += 1
                    pattern.last_seen = datetime.now()
                    matched.append(pattern)
                    break

        return matched

    def _find_similar_failures(
        self,
        error_message: str,
        categories: List[Tuple[FailureCategory, float]],
    ) -> List[str]:
        """Find similar failures in history."""
        similar = []
        primary_category = categories[0][0] if categories else FailureCategory.UNKNOWN

        for test_id, causes in self._failure_history.items():
            for cause in causes:
                if cause.category == primary_category:
                    similar.append(test_id)
                    break

        return similar[:10]

    def _recommend_priority(
        self,
        root_causes: List[RootCause],
    ) -> str:
        """Recommend investigation priority."""
        if not root_causes:
            return "low"

        # Get highest severity
        severities = [c.severity for c in root_causes]

        if FailureSeverity.CRITICAL in severities:
            return "critical"
        elif FailureSeverity.HIGH in severities:
            return "high"
        elif FailureSeverity.MEDIUM in severities:
            return "medium"
        return "low"

    def register_pattern(
        self,
        name: str,
        description: str,
        category: FailureCategory,
        indicators: List[str],
    ) -> FailurePattern:
        """Register a custom failure pattern."""
        self._pattern_counter += 1
        pattern = FailurePattern(
            pattern_id=f"PAT-{self._pattern_counter:04d}",
            name=name,
            description=description,
            category=category,
            indicators=indicators,
        )
        self._patterns[pattern.pattern_id] = pattern
        return pattern

    def get_failure_trends(
        self,
        test_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get failure trends and statistics."""
        if test_id:
            history = self._failure_history.get(test_id, [])
        else:
            history = [c for causes in self._failure_history.values() for c in causes]

        if not history:
            return {
                "total_failures": 0,
                "category_distribution": {},
                "severity_distribution": {},
                "top_patterns": [],
            }

        # Category distribution
        category_counts: Dict[str, int] = {}
        for cause in history:
            cat = cause.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Severity distribution
        severity_counts: Dict[str, int] = {}
        for cause in history:
            sev = cause.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Top patterns
        pattern_list = sorted(
            self._patterns.values(),
            key=lambda p: -p.frequency
        )[:5]

        return {
            "total_failures": len(history),
            "category_distribution": category_counts,
            "severity_distribution": severity_counts,
            "top_patterns": [
                {"name": p.name, "frequency": p.frequency}
                for p in pattern_list
            ],
        }

    def format_analysis(self, analysis: FailureAnalysis) -> str:
        """Format analysis as readable text."""
        lines = [
            "=" * 60,
            "  ROOT CAUSE ANALYSIS",
            "=" * 60,
            "",
            f"  Test: {analysis.test_id}",
            f"  Priority: {analysis.recommended_priority.upper()}",
            f"  Historical Occurrences: {analysis.historical_occurrences}",
            "",
            "-" * 60,
            "  ERROR MESSAGE",
            "-" * 60,
            f"  {analysis.error_message[:200]}",
            "",
        ]

        # Root causes
        lines.extend([
            "-" * 60,
            "  ROOT CAUSES",
            "-" * 60,
        ])

        for i, cause in enumerate(analysis.root_causes, 1):
            lines.extend([
                f"",
                f"  {i}. {cause.category.value.upper()} (Confidence: {cause.confidence:.0%})",
                f"     Severity: {cause.severity.value}",
                f"     {cause.description}",
            ])

            if cause.evidence:
                lines.append("     Evidence:")
                for ev in cause.evidence[:2]:
                    lines.append(f"       - {ev[:80]}")

            if cause.code_locations:
                lines.append("     Locations:")
                for loc in cause.code_locations[:2]:
                    lines.append(f"       - {loc}")

        # Suggested fixes
        if analysis.root_causes:
            lines.extend([
                "",
                "-" * 60,
                "  SUGGESTED FIXES",
                "-" * 60,
            ])
            seen_fixes = set()
            for cause in analysis.root_causes:
                for fix in cause.suggested_fixes[:2]:
                    if fix not in seen_fixes:
                        lines.append(f"  - {fix}")
                        seen_fixes.add(fix)

        # Similar failures
        if analysis.similar_failures:
            lines.extend([
                "",
                "-" * 60,
                "  SIMILAR FAILURES",
                "-" * 60,
            ])
            for test in analysis.similar_failures[:5]:
                lines.append(f"  - {test}")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_root_cause_analyzer() -> RootCauseAnalyzer:
    """Create a root cause analyzer instance."""
    return RootCauseAnalyzer()
