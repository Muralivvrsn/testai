"""
TestAI Agent - Query Parser

Parses natural language queries into structured
query objects for execution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Union
import re

from .nlp import NLProcessor, TokenizedQuery, Entity, EntityType


class QueryIntent(Enum):
    """The intent of a query."""
    LIST = "list"  # List/show tests
    COUNT = "count"  # Count tests
    FILTER = "filter"  # Filter tests
    SEARCH = "search"  # Search by text
    COMPARE = "compare"  # Compare test sets
    SUMMARIZE = "summarize"  # Get summary/stats
    GROUP = "group"  # Group by attribute


@dataclass
class QueryFilter:
    """A filter to apply to tests."""
    field: str
    operator: str  # eq, ne, gt, lt, gte, lte, contains, in, not_in
    value: Any
    negated: bool = False


@dataclass
class QuerySort:
    """Sort specification."""
    field: str
    ascending: bool = True


@dataclass
class ParsedQuery:
    """A parsed query ready for execution."""
    intent: QueryIntent
    filters: List[QueryFilter]
    search_text: Optional[str] = None
    sort: Optional[QuerySort] = None
    group_by: Optional[str] = None
    limit: Optional[int] = None
    offset: int = 0
    time_range: Optional[tuple] = None  # (start, end)
    fields: List[str] = field(default_factory=list)  # Fields to return
    original_query: str = ""
    confidence: float = 1.0


class QueryParser:
    """
    Parses natural language queries into structured queries.

    Supports:
    - Intent detection
    - Filter extraction
    - Sort order parsing
    - Time range handling
    - Grouping operations
    """

    # Field name mappings
    FIELD_MAPPINGS = {
        "status": ["status", "state", "result", "outcome"],
        "priority": ["priority", "importance", "severity"],
        "category": ["category", "type", "kind", "group"],
        "title": ["title", "name", "test name"],
        "description": ["description", "desc", "details"],
        "created_at": ["created", "added", "created at"],
        "updated_at": ["updated", "modified", "changed", "updated at"],
        "run_at": ["run", "executed", "last run", "run at"],
        "duration": ["duration", "time", "runtime", "execution time"],
        "author": ["author", "creator", "owner", "created by"],
        "tags": ["tags", "labels", "tagged", "labeled"],
    }

    # Operator mappings
    OPERATOR_MAPPINGS = {
        "greater": "gt",
        "less": "lt",
        "equal": "eq",
        "at_least": "gte",
        "at_most": "lte",
        "contains": "contains",
        "in": "in",
    }

    def __init__(
        self,
        nl_processor: Optional[NLProcessor] = None,
    ):
        """Initialize the parser."""
        self.nlp = nl_processor or NLProcessor()
        self._build_reverse_mappings()

    def _build_reverse_mappings(self):
        """Build reverse mappings for lookup."""
        self._field_reverse = {}
        for canonical, aliases in self.FIELD_MAPPINGS.items():
            for alias in aliases:
                self._field_reverse[alias.lower()] = canonical

    def parse(self, query: str) -> ParsedQuery:
        """Parse a natural language query."""
        # Process with NLP
        tokenized = self.nlp.process(query)

        # Detect intent
        intent = self._detect_intent(tokenized)

        # Extract filters
        filters = self._extract_filters(tokenized)

        # Extract search text
        search_text = self._extract_search_text(tokenized)

        # Extract sort
        sort = self._extract_sort(tokenized)

        # Extract group by
        group_by = self._extract_group_by(tokenized)

        # Extract limit
        limit = self._extract_limit(tokenized)

        # Extract time range
        time_range = self._extract_time_range(tokenized)

        # Calculate confidence
        confidence = self._calculate_confidence(tokenized, filters)

        return ParsedQuery(
            intent=intent,
            filters=filters,
            search_text=search_text,
            sort=sort,
            group_by=group_by,
            limit=limit,
            time_range=time_range,
            original_query=query,
            confidence=confidence,
        )

    def _detect_intent(self, query: TokenizedQuery) -> QueryIntent:
        """Detect the intent of the query."""
        action_entities = self.nlp.get_entities_by_type(query, EntityType.ACTION)

        if action_entities:
            action = action_entities[0].normalized_value
            intent_map = {
                "show": QueryIntent.LIST,
                "count": QueryIntent.COUNT,
                "filter": QueryIntent.FILTER,
                "compare": QueryIntent.COMPARE,
                "summarize": QueryIntent.SUMMARIZE,
                "sort": QueryIntent.LIST,
                "group": QueryIntent.GROUP,
            }
            return intent_map.get(action, QueryIntent.LIST)

        # Look for specific patterns
        text_lower = query.original.lower()

        if "how many" in text_lower or "count" in text_lower:
            return QueryIntent.COUNT

        if "compare" in text_lower or "versus" in text_lower or " vs " in text_lower:
            return QueryIntent.COMPARE

        if "summary" in text_lower or "overview" in text_lower or "stats" in text_lower:
            return QueryIntent.SUMMARIZE

        if "group by" in text_lower or "grouped" in text_lower:
            return QueryIntent.GROUP

        # Default to list
        return QueryIntent.LIST

    def _extract_filters(self, query: TokenizedQuery) -> List[QueryFilter]:
        """Extract filters from the query."""
        filters = []

        # Status filter
        status_entities = self.nlp.get_entities_by_type(query, EntityType.TEST_STATUS)
        for entity in status_entities:
            negated = self.nlp.is_negated(query, entity.start_pos)
            filters.append(QueryFilter(
                field="status",
                operator="ne" if negated else "eq",
                value=entity.normalized_value,
                negated=negated,
            ))

        # Priority filter
        priority_entities = self.nlp.get_entities_by_type(query, EntityType.PRIORITY)
        for entity in priority_entities:
            negated = self.nlp.is_negated(query, entity.start_pos)
            filters.append(QueryFilter(
                field="priority",
                operator="ne" if negated else "eq",
                value=entity.normalized_value,
                negated=negated,
            ))

        # Category filter
        category_entities = self.nlp.get_entities_by_type(query, EntityType.CATEGORY)
        for entity in category_entities:
            negated = self.nlp.is_negated(query, entity.start_pos)
            filters.append(QueryFilter(
                field="category",
                operator="ne" if negated else "eq",
                value=entity.normalized_value,
                negated=negated,
            ))

        # Feature filter (search in title/description)
        feature_entities = self.nlp.get_entities_by_type(query, EntityType.FEATURE)
        for entity in feature_entities:
            negated = self.nlp.is_negated(query, entity.start_pos)
            operator = "not_contains" if negated else "contains"
            filters.append(QueryFilter(
                field="title",
                operator=operator,
                value=entity.normalized_value,
                negated=negated,
            ))

        # Comparator-based filters
        comparators = self.nlp.get_entities_by_type(query, EntityType.COMPARATOR)
        numbers = self.nlp.get_entities_by_type(query, EntityType.NUMBER)

        if comparators and numbers:
            # Try to pair comparators with numbers
            for comp in comparators:
                # Find nearest number
                nearest_num = min(
                    numbers,
                    key=lambda n: abs(n.start_pos - comp.end_pos),
                    default=None,
                )
                if nearest_num:
                    # Determine what field this applies to
                    field = self._infer_field_from_context(
                        query.original,
                        comp.start_pos,
                    )
                    if field:
                        filters.append(QueryFilter(
                            field=field,
                            operator=self.OPERATOR_MAPPINGS.get(comp.normalized_value, "eq"),
                            value=nearest_num.normalized_value,
                        ))

        return filters

    def _extract_search_text(self, query: TokenizedQuery) -> Optional[str]:
        """Extract free-text search terms."""
        # Look for quoted strings
        quotes = re.findall(r'"([^"]+)"', query.original)
        if quotes:
            return " ".join(quotes)

        # Common query words to exclude from search
        query_noise_words = {
            "show", "display", "list", "find", "search", "get", "fetch",
            "all", "tests", "test", "cases", "case", "me", "the", "a", "an",
            "give", "of", "for", "with", "that", "are", "is", "which",
            "results", "result", "please", "can", "could", "want", "need",
            # Filter-related words
            "priority", "status", "category", "type", "by", "grouped",
            "sorted", "ordered", "summary", "stats", "statistics",
        }

        # Use keywords that aren't already captured as entities or noise
        entity_values = {e.value.lower() for e in query.entities}
        search_words = [
            kw for kw in query.keywords
            if kw.lower() not in entity_values
            and kw.lower() not in query_noise_words
        ]

        if search_words:
            return " ".join(search_words)

        return None

    def _extract_sort(self, query: TokenizedQuery) -> Optional[QuerySort]:
        """Extract sort specification from the query."""
        text_lower = query.original.lower()

        # Look for sort indicators
        sort_patterns = [
            (r"sort(?:ed)?\s+by\s+(\w+)", True),
            (r"order(?:ed)?\s+by\s+(\w+)", True),
            (r"(\w+)\s+first", False),  # "newest first" -> sort by date desc
            (r"most\s+(\w+)", False),  # "most recent" -> sort by date desc
            (r"least\s+(\w+)", True),  # "least recent" -> sort by date asc
        ]

        for pattern, default_asc in sort_patterns:
            match = re.search(pattern, text_lower)
            if match:
                field_hint = match.group(1)
                field = self._resolve_field(field_hint)
                if field:
                    ascending = default_asc
                    if "desc" in text_lower or "newest" in text_lower or "latest" in text_lower:
                        ascending = False
                    elif "asc" in text_lower or "oldest" in text_lower or "earliest" in text_lower:
                        ascending = True
                    return QuerySort(field=field, ascending=ascending)

        return None

    def _extract_group_by(self, query: TokenizedQuery) -> Optional[str]:
        """Extract group by specification."""
        text_lower = query.original.lower()

        match = re.search(r"group(?:ed)?\s+by\s+(\w+)", text_lower)
        if match:
            field = self._resolve_field(match.group(1))
            return field

        match = re.search(r"per\s+(\w+)", text_lower)
        if match:
            field = self._resolve_field(match.group(1))
            return field

        return None

    def _extract_limit(self, query: TokenizedQuery) -> Optional[int]:
        """Extract limit from the query."""
        text_lower = query.original.lower()

        # Look for top/first N patterns
        patterns = [
            r"(?:top|first|last)\s+(\d+)",
            r"(\d+)\s+(?:tests?|results?)",
            r"limit\s+(\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text_lower)
            if match:
                return int(match.group(1))

        return None

    def _extract_time_range(
        self,
        query: TokenizedQuery,
    ) -> Optional[tuple]:
        """Extract time range from the query."""
        time_entities = self.nlp.get_entities_by_type(query, EntityType.TIME_REFERENCE)

        if time_entities:
            # Use the first time reference as start
            start = time_entities[0].normalized_value
            end = datetime.now()

            # Check for "between X and Y" pattern
            if len(time_entities) >= 2:
                end = time_entities[1].normalized_value

            return (start, end)

        return None

    def _resolve_field(self, hint: str) -> Optional[str]:
        """Resolve a field hint to a canonical field name."""
        hint_lower = hint.lower()

        # Direct match
        if hint_lower in self._field_reverse:
            return self._field_reverse[hint_lower]

        # Fuzzy match
        for alias, canonical in self._field_reverse.items():
            if hint_lower in alias or alias in hint_lower:
                return canonical

        return None

    def _infer_field_from_context(
        self,
        text: str,
        position: int,
    ) -> Optional[str]:
        """Infer the field from context around a position."""
        # Look for field hints before the position
        context = text[:position].lower()

        for canonical, aliases in self.FIELD_MAPPINGS.items():
            for alias in aliases:
                if alias in context[-50:]:  # Check last 50 chars
                    return canonical

        # Default inferences based on common patterns
        if "run" in context or "duration" in context:
            return "duration"
        if "time" in context or "date" in context:
            return "run_at"

        return None

    def _calculate_confidence(
        self,
        query: TokenizedQuery,
        filters: List[QueryFilter],
    ) -> float:
        """Calculate confidence in the parse result."""
        confidence = 1.0

        # Reduce confidence if query is very short
        if len(query.tokens) < 3:
            confidence *= 0.8

        # Reduce confidence if no entities found
        if not query.entities:
            confidence *= 0.7

        # Reduce confidence if no filters extracted
        if not filters:
            confidence *= 0.8

        # Reduce confidence if negations present (more complex)
        if query.negations:
            confidence *= 0.9

        return confidence

    def format_parsed(self, parsed: ParsedQuery) -> str:
        """Format a parsed query for debugging."""
        lines = [
            "=" * 50,
            f"  PARSED QUERY",
            "=" * 50,
            "",
            f"  Original: {parsed.original_query}",
            f"  Intent: {parsed.intent.value}",
            f"  Confidence: {parsed.confidence:.0%}",
            "",
        ]

        if parsed.filters:
            lines.append("  Filters:")
            for f in parsed.filters:
                neg = " (negated)" if f.negated else ""
                lines.append(f"    - {f.field} {f.operator} '{f.value}'{neg}")

        if parsed.search_text:
            lines.append(f"\n  Search: '{parsed.search_text}'")

        if parsed.sort:
            order = "ASC" if parsed.sort.ascending else "DESC"
            lines.append(f"\n  Sort: {parsed.sort.field} {order}")

        if parsed.group_by:
            lines.append(f"\n  Group By: {parsed.group_by}")

        if parsed.limit:
            lines.append(f"\n  Limit: {parsed.limit}")

        if parsed.time_range:
            start, end = parsed.time_range
            lines.append(f"\n  Time Range: {start} to {end}")

        lines.extend(["", "=" * 50])
        return "\n".join(lines)


def create_query_parser(
    nl_processor: Optional[NLProcessor] = None,
) -> QueryParser:
    """Create a query parser instance."""
    return QueryParser(nl_processor)
