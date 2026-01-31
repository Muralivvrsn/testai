"""
TestAI Agent - Query Executor

Executes parsed queries against test collections
with filtering, sorting, and aggregation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable
import re

from .parser import ParsedQuery, QueryIntent, QueryFilter, QuerySort


@dataclass
class TestMatch:
    """A test that matches a query."""
    test_id: str
    test_data: Dict[str, Any]
    score: float  # Relevance score (0-1)
    matched_filters: List[str]  # Which filters matched
    highlights: Dict[str, str] = field(default_factory=dict)  # Highlighted matches


@dataclass
class QueryResult:
    """Result of executing a query."""
    query: ParsedQuery
    matches: List[TestMatch]
    total_count: int
    filtered_count: int
    groups: Optional[Dict[str, List[TestMatch]]] = None
    aggregations: Optional[Dict[str, Any]] = None
    execution_time_ms: int = 0
    message: str = ""


class QueryExecutor:
    """
    Executes parsed queries against test collections.

    Supports:
    - Filtering by any field
    - Full-text search
    - Sorting
    - Grouping
    - Aggregation
    """

    # Operator implementations
    OPERATORS = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "gt": lambda a, b: a > b,
        "lt": lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
        "contains": lambda a, b: str(b).lower() in str(a).lower(),
        "not_contains": lambda a, b: str(b).lower() not in str(a).lower(),
        "in": lambda a, b: a in b if isinstance(b, (list, set)) else False,
        "not_in": lambda a, b: a not in b if isinstance(b, (list, set)) else True,
        "matches": lambda a, b: bool(re.search(b, str(a), re.IGNORECASE)),
    }

    def __init__(
        self,
        default_limit: int = 100,
    ):
        """Initialize the executor."""
        self.default_limit = default_limit

    def execute(
        self,
        query: ParsedQuery,
        tests: List[Dict[str, Any]],
    ) -> QueryResult:
        """Execute a query against a test collection."""
        start_time = datetime.now()

        total_count = len(tests)

        # Apply filters
        filtered_tests = self._apply_filters(tests, query.filters)

        # Apply time range filter
        if query.time_range:
            filtered_tests = self._apply_time_range(filtered_tests, query.time_range)

        # Apply text search
        if query.search_text:
            filtered_tests = self._apply_search(filtered_tests, query.search_text)

        filtered_count = len(filtered_tests)

        # Create matches with scores
        matches = [
            TestMatch(
                test_id=t.get("id", "unknown"),
                test_data=t,
                score=self._calculate_relevance(t, query),
                matched_filters=[f.field for f in query.filters],
            )
            for t in filtered_tests
        ]

        # Apply sorting
        if query.sort:
            matches = self._apply_sort(matches, query.sort)
        else:
            # Default sort by relevance
            matches.sort(key=lambda m: m.score, reverse=True)

        # Apply grouping
        groups = None
        if query.group_by:
            groups = self._apply_grouping(matches, query.group_by)

        # Calculate aggregations
        aggregations = None
        if query.intent == QueryIntent.SUMMARIZE:
            aggregations = self._calculate_aggregations(matches)

        # Apply limit
        limit = query.limit or self.default_limit
        if query.offset:
            matches = matches[query.offset:query.offset + limit]
        else:
            matches = matches[:limit]

        # Calculate execution time
        execution_time = int((datetime.now() - start_time).total_seconds() * 1000)

        # Generate message
        message = self._generate_message(query, filtered_count, total_count)

        return QueryResult(
            query=query,
            matches=matches,
            total_count=total_count,
            filtered_count=filtered_count,
            groups=groups,
            aggregations=aggregations,
            execution_time_ms=execution_time,
            message=message,
        )

    def _apply_filters(
        self,
        tests: List[Dict[str, Any]],
        filters: List[QueryFilter],
    ) -> List[Dict[str, Any]]:
        """Apply filters to tests."""
        if not filters:
            return tests

        result = []

        for test in tests:
            matches = True

            for f in filters:
                value = self._get_field_value(test, f.field)
                operator_fn = self.OPERATORS.get(f.operator)

                if operator_fn:
                    try:
                        if not operator_fn(value, f.value):
                            matches = False
                            break
                    except (TypeError, ValueError):
                        # Type mismatch, filter doesn't match
                        matches = False
                        break

            if matches:
                result.append(test)

        return result

    def _apply_time_range(
        self,
        tests: List[Dict[str, Any]],
        time_range: tuple,
    ) -> List[Dict[str, Any]]:
        """Apply time range filter."""
        start, end = time_range
        result = []

        for test in tests:
            # Try different date fields
            for field in ["run_at", "created_at", "updated_at", "timestamp"]:
                value = test.get(field)
                if value:
                    if isinstance(value, datetime):
                        if start <= value <= end:
                            result.append(test)
                            break
                    elif isinstance(value, str):
                        try:
                            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                            if start <= dt <= end:
                                result.append(test)
                                break
                        except ValueError:
                            pass

        return result

    def _apply_search(
        self,
        tests: List[Dict[str, Any]],
        search_text: str,
    ) -> List[Dict[str, Any]]:
        """Apply full-text search."""
        search_lower = search_text.lower()
        search_words = search_lower.split()
        result = []

        for test in tests:
            # Build searchable text from test
            searchable = self._get_searchable_text(test)

            # Check if all search words are present
            if all(word in searchable for word in search_words):
                result.append(test)

        return result

    def _apply_sort(
        self,
        matches: List[TestMatch],
        sort: QuerySort,
    ) -> List[TestMatch]:
        """Apply sorting to matches."""
        def get_sort_key(match: TestMatch):
            value = self._get_field_value(match.test_data, sort.field)
            # Handle None values
            if value is None:
                return "" if isinstance(value, str) else 0
            return value

        return sorted(matches, key=get_sort_key, reverse=not sort.ascending)

    def _apply_grouping(
        self,
        matches: List[TestMatch],
        group_by: str,
    ) -> Dict[str, List[TestMatch]]:
        """Group matches by a field."""
        groups: Dict[str, List[TestMatch]] = {}

        for match in matches:
            value = self._get_field_value(match.test_data, group_by)
            key = str(value) if value is not None else "Unknown"

            if key not in groups:
                groups[key] = []
            groups[key].append(match)

        return groups

    def _calculate_aggregations(
        self,
        matches: List[TestMatch],
    ) -> Dict[str, Any]:
        """Calculate aggregations for summarize queries."""
        if not matches:
            return {
                "total": 0,
                "by_status": {},
                "by_priority": {},
                "by_category": {},
            }

        # Count by status
        by_status: Dict[str, int] = {}
        by_priority: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        durations: List[float] = []

        for match in matches:
            data = match.test_data

            status = data.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

            priority = data.get("priority", "unknown")
            by_priority[priority] = by_priority.get(priority, 0) + 1

            category = data.get("category", "unknown")
            by_category[category] = by_category.get(category, 0) + 1

            duration = data.get("duration")
            if duration is not None:
                durations.append(float(duration))

        aggregations = {
            "total": len(matches),
            "by_status": by_status,
            "by_priority": by_priority,
            "by_category": by_category,
        }

        if durations:
            aggregations["avg_duration"] = sum(durations) / len(durations)
            aggregations["min_duration"] = min(durations)
            aggregations["max_duration"] = max(durations)
            aggregations["total_duration"] = sum(durations)

        return aggregations

    def _get_field_value(
        self,
        test: Dict[str, Any],
        field: str,
    ) -> Any:
        """Get the value of a field from a test."""
        # Handle nested fields
        if "." in field:
            parts = field.split(".")
            value = test
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            return value

        return test.get(field)

    def _get_searchable_text(self, test: Dict[str, Any]) -> str:
        """Build searchable text from a test."""
        parts = [
            str(test.get("id", "")),
            str(test.get("title", "")),
            str(test.get("description", "")),
            str(test.get("category", "")),
            " ".join(str(s) for s in test.get("steps", [])),
            str(test.get("expected_result", "")),
            " ".join(str(t) for t in test.get("tags", [])),
        ]
        return " ".join(parts).lower()

    def _calculate_relevance(
        self,
        test: Dict[str, Any],
        query: ParsedQuery,
    ) -> float:
        """Calculate relevance score for a test."""
        score = 1.0

        # Boost for search text matches in title
        if query.search_text:
            title = str(test.get("title", "")).lower()
            search_lower = query.search_text.lower()

            if search_lower in title:
                score *= 1.5

            # Count word matches
            search_words = set(search_lower.split())
            title_words = set(title.split())
            overlap = len(search_words & title_words)
            score *= (1 + overlap * 0.1)

        # Boost high priority tests
        priority = test.get("priority", "medium")
        priority_boost = {
            "critical": 1.3,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.9,
        }
        score *= priority_boost.get(priority, 1.0)

        return min(score, 2.0)  # Cap at 2.0

    def _generate_message(
        self,
        query: ParsedQuery,
        filtered_count: int,
        total_count: int,
    ) -> str:
        """Generate a user-friendly message."""
        if filtered_count == 0:
            return "No tests found matching your query."

        if filtered_count == total_count:
            return f"Found all {total_count} tests."

        filter_desc = []
        for f in query.filters:
            if f.negated:
                filter_desc.append(f"not {f.field}={f.value}")
            else:
                filter_desc.append(f"{f.field}={f.value}")

        if filter_desc:
            return f"Found {filtered_count} of {total_count} tests matching: {', '.join(filter_desc)}"
        else:
            return f"Found {filtered_count} of {total_count} tests."

    def format_result(self, result: QueryResult) -> str:
        """Format a query result as readable text."""
        lines = [
            "=" * 60,
            "  QUERY RESULT",
            "=" * 60,
            "",
            f"  Query: {result.query.original_query}",
            f"  Found: {result.filtered_count} of {result.total_count} tests",
            f"  Execution: {result.execution_time_ms}ms",
            "",
        ]

        if result.aggregations:
            lines.extend([
                "-" * 60,
                "  SUMMARY",
                "-" * 60,
            ])

            agg = result.aggregations
            lines.append(f"\n  Total: {agg.get('total', 0)}")

            if agg.get("by_status"):
                lines.append("\n  By Status:")
                for status, count in agg["by_status"].items():
                    lines.append(f"    - {status}: {count}")

            if agg.get("by_priority"):
                lines.append("\n  By Priority:")
                for priority, count in agg["by_priority"].items():
                    lines.append(f"    - {priority}: {count}")

            if agg.get("avg_duration"):
                lines.append(f"\n  Avg Duration: {agg['avg_duration']:.1f}ms")

        if result.groups:
            lines.extend([
                "",
                "-" * 60,
                f"  GROUPED BY {result.query.group_by.upper()}",
                "-" * 60,
            ])

            for group_name, group_matches in result.groups.items():
                lines.append(f"\n  [{group_name}] ({len(group_matches)} tests)")
                for match in group_matches[:3]:
                    lines.append(f"    - {match.test_data.get('title', match.test_id)}")
                if len(group_matches) > 3:
                    lines.append(f"    ... and {len(group_matches) - 3} more")

        else:
            lines.extend([
                "",
                "-" * 60,
                "  MATCHES",
                "-" * 60,
            ])

            for match in result.matches[:10]:
                status = match.test_data.get("status", "?")
                status_icon = {
                    "passed": "✅",
                    "failed": "❌",
                    "skipped": "⏭",
                }.get(status, "○")

                title = match.test_data.get("title", match.test_id)
                lines.append(f"\n  {status_icon} {title}")
                lines.append(f"     ID: {match.test_id} | Score: {match.score:.2f}")

            if len(result.matches) > 10:
                lines.append(f"\n  ... and {len(result.matches) - 10} more")

        lines.extend([
            "",
            "-" * 60,
            f"  {result.message}",
            "=" * 60,
        ])

        return "\n".join(lines)


def create_query_executor(
    default_limit: int = 100,
) -> QueryExecutor:
    """Create a query executor instance."""
    return QueryExecutor(default_limit)
