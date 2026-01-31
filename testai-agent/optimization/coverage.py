"""
TestAI Agent - Coverage Optimizer

Identifies coverage gaps and suggests tests to
improve overall test coverage.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re


@dataclass
class CoverageGap:
    """A gap in test coverage."""
    gap_id: str
    area: str  # Feature area
    description: str
    severity: str  # critical, high, medium, low
    missing_scenarios: List[str]
    suggested_tests: List[Dict[str, Any]]


@dataclass
class CoverageSuggestion:
    """A suggestion for improving coverage."""
    suggestion_id: str
    area: str
    description: str
    test_template: Dict[str, Any]
    priority: int
    rationale: str


class CoverageOptimizer:
    """
    Optimizes test coverage by identifying gaps.

    Analyzes:
    - Feature coverage
    - Edge case coverage
    - Error handling coverage
    - Boundary coverage
    """

    # Required coverage areas by feature type
    COVERAGE_REQUIREMENTS = {
        "login": {
            "happy_path": ["Valid credentials", "Remember me"],
            "validation": ["Empty email", "Empty password", "Invalid format"],
            "security": ["SQL injection", "XSS", "Brute force protection", "CSRF"],
            "edge_cases": ["Long strings", "Special characters", "Multiple sessions"],
            "error_handling": ["Server error", "Network timeout", "Invalid response"],
            "accessibility": ["Keyboard navigation", "Screen reader", "Focus management"],
        },
        "signup": {
            "happy_path": ["Valid registration", "Email verification"],
            "validation": ["Required fields", "Email format", "Password strength"],
            "security": ["Duplicate email", "Rate limiting", "CAPTCHA"],
            "edge_cases": ["International characters", "Maximum lengths"],
            "error_handling": ["Service unavailable", "Timeout"],
        },
        "checkout": {
            "happy_path": ["Complete purchase", "Multiple items"],
            "validation": ["Card validation", "Address validation"],
            "security": ["PCI compliance", "Session handling"],
            "edge_cases": ["Empty cart", "Out of stock", "Price changes"],
            "error_handling": ["Payment failure", "Network issues"],
            "integration": ["Inventory update", "Email confirmation"],
        },
        "search": {
            "happy_path": ["Basic search", "Search with filters"],
            "validation": ["Empty query", "Special characters"],
            "performance": ["Large result sets", "Pagination"],
            "edge_cases": ["No results", "Single result", "Typos"],
            "accessibility": ["Keyboard shortcuts", "Screen reader results"],
        },
        "profile": {
            "happy_path": ["View profile", "Edit profile", "Change password"],
            "validation": ["Email format", "Phone format"],
            "security": ["Session validation", "Password requirements"],
            "edge_cases": ["Large files", "Special characters"],
            "error_handling": ["Save failures", "Upload failures"],
        },
    }

    # Common missing test scenarios
    COMMON_GAPS = {
        "boundary": [
            "Empty input",
            "Maximum length input",
            "Minimum length input",
            "Zero values",
            "Negative values",
        ],
        "error": [
            "Network timeout",
            "Server 500 error",
            "400 bad request",
            "401 unauthorized",
            "403 forbidden",
            "404 not found",
        ],
        "concurrency": [
            "Double submit",
            "Concurrent edits",
            "Session expiry during action",
        ],
        "browser": [
            "Back button behavior",
            "Refresh during action",
            "Multiple tabs",
        ],
    }

    def __init__(self):
        """Initialize the coverage optimizer."""
        self._gap_counter = 0
        self._suggestion_counter = 0

    def analyze(
        self,
        tests: List[Dict[str, Any]],
        feature_type: str,
    ) -> List[CoverageGap]:
        """Analyze coverage and identify gaps."""
        gaps = []

        # Get requirements for this feature type
        requirements = self.COVERAGE_REQUIREMENTS.get(
            feature_type.lower(),
            self._get_generic_requirements()
        )

        # Check each coverage area
        for area, scenarios in requirements.items():
            missing = self._find_missing_scenarios(tests, scenarios)

            if missing:
                self._gap_counter += 1
                severity = self._determine_severity(area, len(missing))

                gap = CoverageGap(
                    gap_id=f"GAP-{self._gap_counter:04d}",
                    area=area,
                    description=f"Missing {len(missing)} {area} scenarios",
                    severity=severity,
                    missing_scenarios=missing,
                    suggested_tests=self._generate_test_suggestions(
                        missing, area, feature_type
                    ),
                )
                gaps.append(gap)

        # Check common gaps
        common_gaps = self._check_common_gaps(tests)
        gaps.extend(common_gaps)

        return gaps

    def suggest_tests(
        self,
        gaps: List[CoverageGap],
        max_suggestions: int = 10,
    ) -> List[CoverageSuggestion]:
        """Generate test suggestions from gaps."""
        suggestions = []

        # Sort gaps by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(
            gaps,
            key=lambda g: severity_order.get(g.severity, 4)
        )

        for gap in sorted_gaps:
            for scenario in gap.missing_scenarios:
                if len(suggestions) >= max_suggestions:
                    break

                self._suggestion_counter += 1
                suggestions.append(CoverageSuggestion(
                    suggestion_id=f"SUG-{self._suggestion_counter:04d}",
                    area=gap.area,
                    description=f"Add test for: {scenario}",
                    test_template=self._create_test_template(scenario, gap.area),
                    priority=severity_order.get(gap.severity, 4) + 1,
                    rationale=f"Improves {gap.area} coverage",
                ))

        return suggestions

    def calculate_coverage_score(
        self,
        tests: List[Dict[str, Any]],
        feature_type: str,
    ) -> Dict[str, Any]:
        """Calculate coverage score."""
        requirements = self.COVERAGE_REQUIREMENTS.get(
            feature_type.lower(),
            self._get_generic_requirements()
        )

        total_scenarios = sum(len(scenarios) for scenarios in requirements.values())
        covered = 0
        by_area = {}

        for area, scenarios in requirements.items():
            missing = self._find_missing_scenarios(tests, scenarios)
            area_covered = len(scenarios) - len(missing)
            area_pct = area_covered / len(scenarios) if scenarios else 1.0

            by_area[area] = {
                "total": len(scenarios),
                "covered": area_covered,
                "percentage": area_pct,
            }

            covered += area_covered

        overall_score = covered / total_scenarios if total_scenarios > 0 else 0

        return {
            "overall_score": overall_score,
            "total_scenarios": total_scenarios,
            "covered_scenarios": covered,
            "by_area": by_area,
        }

    def _find_missing_scenarios(
        self,
        tests: List[Dict[str, Any]],
        scenarios: List[str],
    ) -> List[str]:
        """Find scenarios not covered by existing tests."""
        # Build searchable text from all tests
        test_content = []
        for test in tests:
            test_content.append(test.get("title", "").lower())
            test_content.append(test.get("description", "").lower())
            test_content.extend(s.lower() for s in test.get("steps", []))
            test_content.append(test.get("expected_result", "").lower())

        full_text = " ".join(test_content)

        missing = []
        for scenario in scenarios:
            # Check if scenario keywords are present
            keywords = scenario.lower().split()
            if not any(kw in full_text for kw in keywords):
                missing.append(scenario)

        return missing

    def _check_common_gaps(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[CoverageGap]:
        """Check for common missing scenarios."""
        gaps = []

        for category, scenarios in self.COMMON_GAPS.items():
            missing = self._find_missing_scenarios(tests, scenarios)

            if len(missing) > len(scenarios) // 2:
                self._gap_counter += 1
                gaps.append(CoverageGap(
                    gap_id=f"GAP-{self._gap_counter:04d}",
                    area=category,
                    description=f"Limited {category} testing coverage",
                    severity="medium",
                    missing_scenarios=missing,
                    suggested_tests=[],
                ))

        return gaps

    def _determine_severity(
        self,
        area: str,
        missing_count: int,
    ) -> str:
        """Determine gap severity."""
        critical_areas = {"security", "error_handling"}
        high_areas = {"validation", "happy_path"}

        if area in critical_areas:
            return "critical" if missing_count > 2 else "high"
        elif area in high_areas:
            return "high" if missing_count > 2 else "medium"
        else:
            return "medium" if missing_count > 2 else "low"

    def _generate_test_suggestions(
        self,
        missing_scenarios: List[str],
        area: str,
        feature_type: str,
    ) -> List[Dict[str, Any]]:
        """Generate test suggestions for missing scenarios."""
        suggestions = []

        for scenario in missing_scenarios[:5]:  # Limit to 5
            suggestions.append(self._create_test_template(scenario, area))

        return suggestions

    def _create_test_template(
        self,
        scenario: str,
        area: str,
    ) -> Dict[str, Any]:
        """Create a test template for a scenario."""
        # Determine category
        category = "functional"
        if area == "security":
            category = "security"
        elif area in {"validation", "boundary"}:
            category = "validation"
        elif area == "error":
            category = "error_handling"

        # Determine priority
        priority = "medium"
        if area in {"security", "happy_path"}:
            priority = "high"
        elif area in {"edge_cases", "browser"}:
            priority = "low"

        return {
            "title": f"Test {scenario}",
            "description": f"Verify {scenario.lower()} scenario",
            "category": category,
            "priority": priority,
            "steps": [
                f"Set up preconditions for {scenario.lower()}",
                "Execute the action",
                "Verify expected behavior",
            ],
            "expected_result": f"System handles {scenario.lower()} correctly",
        }

    def _get_generic_requirements(self) -> Dict[str, List[str]]:
        """Get generic coverage requirements."""
        return {
            "happy_path": ["Primary use case", "Secondary use case"],
            "validation": ["Required field", "Invalid input"],
            "security": ["Authentication", "Authorization"],
            "error_handling": ["Server error", "Network error"],
            "edge_cases": ["Empty state", "Maximum values"],
        }

    def format_gaps(self, gaps: List[CoverageGap]) -> str:
        """Format coverage gaps as readable text."""
        lines = [
            "=" * 60,
            "  COVERAGE GAP ANALYSIS",
            "=" * 60,
            "",
            f"  Total Gaps Found: {len(gaps)}",
            "",
        ]

        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }

        for gap in gaps:
            icon = severity_icons.get(gap.severity, "⚪")
            lines.append(f"  {icon} [{gap.gap_id}] {gap.area.upper()}")
            lines.append(f"     {gap.description}")
            lines.append(f"     Severity: {gap.severity}")
            lines.append("     Missing:")

            for scenario in gap.missing_scenarios[:5]:
                lines.append(f"       - {scenario}")

            if len(gap.missing_scenarios) > 5:
                lines.append(f"       ... and {len(gap.missing_scenarios) - 5} more")

            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


def create_coverage_optimizer() -> CoverageOptimizer:
    """Create a coverage optimizer instance."""
    return CoverageOptimizer()
