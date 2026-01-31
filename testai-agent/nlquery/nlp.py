"""
TestAI Agent - NLP Processing

Natural language processing utilities for parsing
and understanding test queries.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re


class EntityType(Enum):
    """Types of entities that can be extracted."""
    TEST_STATUS = "test_status"  # passed, failed, skipped
    PRIORITY = "priority"  # high, medium, low, critical
    CATEGORY = "category"  # security, functional, ui
    TIME_REFERENCE = "time_reference"  # today, yesterday, last week
    NUMBER = "number"  # numeric values
    FEATURE = "feature"  # login, checkout, payment
    ACTION = "action"  # show, list, find, count
    COMPARATOR = "comparator"  # more than, less than, equal
    ORDER = "order"  # ascending, descending, first, last


@dataclass
class Entity:
    """An extracted entity from text."""
    entity_type: EntityType
    value: str
    normalized_value: Any
    start_pos: int
    end_pos: int
    confidence: float = 1.0


@dataclass
class TokenizedQuery:
    """A tokenized and processed query."""
    original: str
    tokens: List[str]
    entities: List[Entity]
    keywords: List[str]
    negations: List[Tuple[int, int]]  # Start/end positions of negated phrases
    metadata: Dict[str, Any] = field(default_factory=dict)


class NLProcessor:
    """
    Natural language processor for test queries.

    Handles:
    - Tokenization and normalization
    - Entity extraction
    - Keyword identification
    - Negation detection
    """

    # Status synonyms
    STATUS_SYNONYMS = {
        "passed": ["passed", "passing", "pass", "succeeded", "successful", "green", "ok"],
        "failed": ["failed", "failing", "fail", "broken", "red", "error", "errored"],
        "skipped": ["skipped", "skip", "ignored", "pending", "todo"],
        "flaky": ["flaky", "unstable", "intermittent", "inconsistent"],
    }

    # Priority synonyms
    PRIORITY_SYNONYMS = {
        "critical": ["critical", "blocker", "urgent", "emergency", "p0"],
        "high": ["high", "important", "severe", "major", "p1"],
        "medium": ["medium", "moderate", "normal", "p2"],
        "low": ["low", "minor", "trivial", "nice-to-have", "p3"],
    }

    # Category synonyms
    CATEGORY_SYNONYMS = {
        "security": ["security", "secure", "auth", "authentication", "authorization", "permission"],
        "functional": ["functional", "feature", "functionality", "business", "logic"],
        "ui": ["ui", "ux", "visual", "display", "interface", "frontend"],
        "api": ["api", "backend", "endpoint", "rest", "graphql", "service"],
        "integration": ["integration", "e2e", "end-to-end", "system"],
        "unit": ["unit", "component", "isolated"],
        "performance": ["performance", "speed", "load", "stress", "benchmark"],
    }

    # Time reference patterns
    TIME_PATTERNS = [
        (r"\btoday\b", lambda: datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)),
        (r"\byesterday\b", lambda: datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)),
        (r"\blast\s+week\b", lambda: datetime.now() - timedelta(weeks=1)),
        (r"\blast\s+month\b", lambda: datetime.now() - timedelta(days=30)),
        (r"\blast\s+(\d+)\s+days?\b", lambda m: datetime.now() - timedelta(days=int(m.group(1)))),
        (r"\blast\s+(\d+)\s+hours?\b", lambda m: datetime.now() - timedelta(hours=int(m.group(1)))),
        (r"\bthis\s+week\b", lambda: datetime.now() - timedelta(days=datetime.now().weekday())),
        (r"\brecently\b", lambda: datetime.now() - timedelta(days=7)),
    ]

    # Action synonyms
    ACTION_SYNONYMS = {
        "show": ["show", "display", "list", "get", "find", "search", "fetch", "retrieve"],
        "count": ["count", "number", "how many", "total"],
        "compare": ["compare", "diff", "difference", "versus", "vs"],
        "summarize": ["summarize", "summary", "overview", "stats", "statistics"],
        "filter": ["filter", "only", "just", "where", "with"],
        "sort": ["sort", "order", "rank", "arrange"],
        "group": ["group", "aggregate", "cluster", "categorize"],
    }

    # Comparator patterns
    COMPARATORS = {
        "greater": ["more than", "greater than", "above", "over", ">"],
        "less": ["less than", "fewer than", "below", "under", "<"],
        "equal": ["equal to", "exactly", "equals", "="],
        "at_least": ["at least", "minimum", "no less than", ">="],
        "at_most": ["at most", "maximum", "no more than", "<="],
    }

    # Negation patterns
    NEGATION_PATTERNS = [
        r"\bnot\s+",
        r"\bno\s+",
        r"\bwithout\s+",
        r"\bexcluding?\s+",
        r"\bexcept\s+",
        r"\bdoesn't\s+",
        r"\bdont\s+",
        r"\bdon't\s+",
        r"\bnever\s+",
    ]

    # Feature keywords (common test areas)
    FEATURE_KEYWORDS = [
        "login", "logout", "signup", "registration", "authentication",
        "checkout", "payment", "cart", "order", "shipping",
        "search", "filter", "sort", "pagination",
        "profile", "settings", "account", "password",
        "admin", "dashboard", "analytics", "reports",
        "email", "notification", "messaging",
        "upload", "download", "export", "import",
    ]

    def __init__(self):
        """Initialize the NL processor."""
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        for pattern, _ in self.TIME_PATTERNS:
            self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)

        for pattern in self.NEGATION_PATTERNS:
            self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)

    def process(self, query: str) -> TokenizedQuery:
        """Process a natural language query."""
        # Normalize
        normalized = self._normalize(query)

        # Tokenize
        tokens = self._tokenize(normalized)

        # Extract entities
        entities = self._extract_entities(query, tokens)

        # Identify keywords
        keywords = self._extract_keywords(tokens)

        # Detect negations
        negations = self._detect_negations(query)

        return TokenizedQuery(
            original=query,
            tokens=tokens,
            entities=entities,
            keywords=keywords,
            negations=negations,
        )

    def _normalize(self, text: str) -> str:
        """Normalize text for processing."""
        # Lowercase
        text = text.lower()

        # Replace contractions
        contractions = {
            "don't": "do not",
            "doesn't": "does not",
            "didn't": "did not",
            "won't": "will not",
            "can't": "cannot",
            "isn't": "is not",
            "aren't": "are not",
            "wasn't": "was not",
            "weren't": "were not",
        }
        for contraction, expansion in contractions.items():
            text = text.replace(contraction, expansion)

        # Remove extra whitespace
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words."""
        # Split on whitespace and punctuation (keeping some punctuation)
        tokens = re.findall(r"\b[\w']+\b", text)
        return tokens

    def _extract_entities(
        self,
        original: str,
        tokens: List[str],
    ) -> List[Entity]:
        """Extract entities from the query."""
        entities = []
        text_lower = original.lower()

        # Extract status entities
        for status, synonyms in self.STATUS_SYNONYMS.items():
            for synonym in synonyms:
                match = re.search(rf"\b{synonym}\b", text_lower)
                if match:
                    entities.append(Entity(
                        entity_type=EntityType.TEST_STATUS,
                        value=synonym,
                        normalized_value=status,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    ))
                    break

        # Extract priority entities
        for priority, synonyms in self.PRIORITY_SYNONYMS.items():
            for synonym in synonyms:
                match = re.search(rf"\b{synonym}\b", text_lower)
                if match:
                    entities.append(Entity(
                        entity_type=EntityType.PRIORITY,
                        value=synonym,
                        normalized_value=priority,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    ))
                    break

        # Extract category entities
        for category, synonyms in self.CATEGORY_SYNONYMS.items():
            for synonym in synonyms:
                match = re.search(rf"\b{synonym}\b", text_lower)
                if match:
                    entities.append(Entity(
                        entity_type=EntityType.CATEGORY,
                        value=synonym,
                        normalized_value=category,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    ))
                    break

        # Extract time references
        for pattern, resolver in self.TIME_PATTERNS:
            compiled = self._compiled_patterns.get(pattern)
            if compiled:
                match = compiled.search(text_lower)
                if match:
                    try:
                        if match.lastindex:
                            time_value = resolver(match)
                        else:
                            time_value = resolver()
                        entities.append(Entity(
                            entity_type=EntityType.TIME_REFERENCE,
                            value=match.group(0),
                            normalized_value=time_value,
                            start_pos=match.start(),
                            end_pos=match.end(),
                        ))
                    except (ValueError, TypeError):
                        pass

        # Extract numbers
        for match in re.finditer(r"\b(\d+)\b", original):
            entities.append(Entity(
                entity_type=EntityType.NUMBER,
                value=match.group(1),
                normalized_value=int(match.group(1)),
                start_pos=match.start(),
                end_pos=match.end(),
            ))

        # Extract feature keywords
        for feature in self.FEATURE_KEYWORDS:
            match = re.search(rf"\b{feature}\b", text_lower)
            if match:
                entities.append(Entity(
                    entity_type=EntityType.FEATURE,
                    value=feature,
                    normalized_value=feature,
                    start_pos=match.start(),
                    end_pos=match.end(),
                ))

        # Extract action entities
        for action, synonyms in self.ACTION_SYNONYMS.items():
            for synonym in synonyms:
                match = re.search(rf"\b{synonym}\b", text_lower)
                if match:
                    entities.append(Entity(
                        entity_type=EntityType.ACTION,
                        value=synonym,
                        normalized_value=action,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    ))
                    break

        # Extract comparators
        for comparator, synonyms in self.COMPARATORS.items():
            for synonym in synonyms:
                match = re.search(rf"\b{re.escape(synonym)}\b", text_lower)
                if match:
                    entities.append(Entity(
                        entity_type=EntityType.COMPARATOR,
                        value=synonym,
                        normalized_value=comparator,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    ))
                    break

        return entities

    def _extract_keywords(self, tokens: List[str]) -> List[str]:
        """Extract significant keywords from tokens."""
        # Stop words to ignore
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "dare", "ought", "to", "for", "of", "in", "on",
            "at", "by", "from", "with", "about", "into", "through", "during",
            "before", "after", "above", "below", "between", "under", "again",
            "further", "then", "once", "here", "there", "when", "where", "why",
            "how", "all", "each", "few", "more", "most", "other", "some", "such",
            "no", "nor", "not", "only", "own", "same", "so", "than", "too",
            "very", "just", "and", "but", "if", "or", "because", "as", "until",
            "while", "although", "though", "me", "my", "i", "you", "your",
            "he", "she", "it", "we", "they", "them", "their", "what", "which",
            "who", "whom", "this", "that", "these", "those", "am", "please",
        }

        keywords = []
        for token in tokens:
            if token.lower() not in stop_words and len(token) > 1:
                keywords.append(token)

        return keywords

    def _detect_negations(self, text: str) -> List[Tuple[int, int]]:
        """Detect negation positions in the text."""
        negations = []
        text_lower = text.lower()

        for pattern in self.NEGATION_PATTERNS:
            compiled = self._compiled_patterns.get(pattern)
            if compiled:
                for match in compiled.finditer(text_lower):
                    # Negation typically affects the next few words
                    # Find the end of the negated phrase
                    start = match.start()
                    # Look for the next clause boundary or end of sentence
                    end_match = re.search(r"[,.]|$", text_lower[match.end():])
                    if end_match:
                        end = match.end() + min(end_match.start(), 30)  # Max 30 chars
                    else:
                        end = min(match.end() + 30, len(text))

                    negations.append((start, end))

        return negations

    def is_negated(
        self,
        query: TokenizedQuery,
        position: int,
    ) -> bool:
        """Check if a position is within a negated phrase."""
        for start, end in query.negations:
            if start <= position < end:
                return True
        return False

    def get_entities_by_type(
        self,
        query: TokenizedQuery,
        entity_type: EntityType,
    ) -> List[Entity]:
        """Get all entities of a specific type."""
        return [e for e in query.entities if e.entity_type == entity_type]

    def format_query(self, query: TokenizedQuery) -> str:
        """Format a tokenized query for debugging."""
        lines = [
            "-" * 50,
            f"  Original: {query.original}",
            "-" * 50,
            "",
            f"  Tokens: {', '.join(query.tokens)}",
            f"  Keywords: {', '.join(query.keywords)}",
            "",
            "  Entities:",
        ]

        for entity in query.entities:
            lines.append(
                f"    - {entity.entity_type.value}: "
                f"'{entity.value}' -> {entity.normalized_value}"
            )

        if query.negations:
            lines.append("")
            lines.append("  Negations:")
            for start, end in query.negations:
                lines.append(f"    - [{start}:{end}] '{query.original[start:end]}'")

        lines.append("-" * 50)
        return "\n".join(lines)


def create_nl_processor() -> NLProcessor:
    """Create an NL processor instance."""
    return NLProcessor()
