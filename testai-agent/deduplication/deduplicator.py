"""
TestAI Agent - Test Deduplicator

Identifies duplicate and semantically similar test cases
using multiple similarity detection methods.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
import re
from collections import defaultdict
import math


class SimilarityMethod(Enum):
    """Methods for calculating test similarity."""
    EXACT = "exact"  # Exact title match
    NORMALIZED = "normalized"  # Normalized text comparison
    JACCARD = "jaccard"  # Jaccard similarity of tokens
    COSINE = "cosine"  # Cosine similarity of TF-IDF vectors
    STEP_OVERLAP = "step_overlap"  # Overlap of test steps
    COMBINED = "combined"  # Combination of multiple methods


@dataclass
class TestSimilarity:
    """Similarity score between two tests."""
    test_id_1: str
    test_id_2: str
    score: float
    method: SimilarityMethod
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DuplicateGroup:
    """A group of duplicate/similar tests."""
    group_id: str
    primary_test_id: str
    duplicate_test_ids: List[str]
    similarity_scores: List[float]
    avg_similarity: float
    recommendation: str


@dataclass
class DeduplicationResult:
    """Result of a deduplication analysis."""
    total_tests: int
    unique_tests: int
    duplicate_groups: List[DuplicateGroup]
    total_duplicates: int
    potential_savings: int
    analyzed_at: datetime = field(default_factory=datetime.now)


class TestDeduplicator:
    """
    Identifies duplicate and similar test cases.

    Uses multiple similarity methods to detect:
    - Exact duplicates (same title/steps)
    - Near duplicates (minor text differences)
    - Semantic duplicates (same intent, different wording)
    """

    # Stop words to ignore in similarity calculations
    STOP_WORDS = {
        "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
        "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "could", "should", "may", "might",
        "test", "verify", "check", "ensure", "validate", "that", "this", "with",
    }

    def __init__(
        self,
        similarity_threshold: float = 0.7,
        method: SimilarityMethod = SimilarityMethod.COMBINED,
    ):
        """Initialize the deduplicator."""
        self.similarity_threshold = similarity_threshold
        self.method = method
        self._idf_cache: Dict[str, float] = {}

    def analyze(
        self,
        tests: List[Dict[str, Any]],
    ) -> DeduplicationResult:
        """Analyze tests for duplicates."""
        if not tests:
            return DeduplicationResult(
                total_tests=0,
                unique_tests=0,
                duplicate_groups=[],
                total_duplicates=0,
                potential_savings=0,
            )

        # Calculate all pairwise similarities
        similarities = self._calculate_all_similarities(tests)

        # Group duplicates
        duplicate_groups = self._group_duplicates(tests, similarities)

        # Count unique tests
        duplicated_ids = set()
        for group in duplicate_groups:
            duplicated_ids.update(group.duplicate_test_ids)

        total_duplicates = len(duplicated_ids)
        unique_tests = len(tests) - total_duplicates

        return DeduplicationResult(
            total_tests=len(tests),
            unique_tests=unique_tests,
            duplicate_groups=duplicate_groups,
            total_duplicates=total_duplicates,
            potential_savings=total_duplicates,
        )

    def find_duplicates_for_test(
        self,
        test: Dict[str, Any],
        existing_tests: List[Dict[str, Any]],
    ) -> List[TestSimilarity]:
        """Find duplicates for a specific test against existing tests."""
        duplicates = []

        for existing in existing_tests:
            if test.get("id") == existing.get("id"):
                continue

            similarity = self._calculate_similarity(test, existing)
            if similarity.score >= self.similarity_threshold:
                duplicates.append(similarity)

        return sorted(duplicates, key=lambda x: x.score, reverse=True)

    def _calculate_all_similarities(
        self,
        tests: List[Dict[str, Any]],
    ) -> List[TestSimilarity]:
        """Calculate similarities between all test pairs."""
        similarities = []
        n = len(tests)

        # Build IDF cache for TFIDF-based methods
        if self.method in [SimilarityMethod.COSINE, SimilarityMethod.COMBINED]:
            self._build_idf_cache(tests)

        for i in range(n):
            for j in range(i + 1, n):
                similarity = self._calculate_similarity(tests[i], tests[j])
                if similarity.score >= self.similarity_threshold:
                    similarities.append(similarity)

        return similarities

    def _calculate_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> TestSimilarity:
        """Calculate similarity between two tests."""
        test_id_1 = test1.get("id", "unknown")
        test_id_2 = test2.get("id", "unknown")

        if self.method == SimilarityMethod.EXACT:
            score = self._exact_similarity(test1, test2)
        elif self.method == SimilarityMethod.NORMALIZED:
            score = self._normalized_similarity(test1, test2)
        elif self.method == SimilarityMethod.JACCARD:
            score = self._jaccard_similarity(test1, test2)
        elif self.method == SimilarityMethod.COSINE:
            score = self._cosine_similarity(test1, test2)
        elif self.method == SimilarityMethod.STEP_OVERLAP:
            score = self._step_overlap_similarity(test1, test2)
        else:  # COMBINED
            score = self._combined_similarity(test1, test2)

        return TestSimilarity(
            test_id_1=test_id_1,
            test_id_2=test_id_2,
            score=score,
            method=self.method,
            details={
                "title_1": test1.get("title", ""),
                "title_2": test2.get("title", ""),
            },
        )

    def _exact_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Check for exact matches."""
        title1 = test1.get("title", "").strip().lower()
        title2 = test2.get("title", "").strip().lower()

        if title1 == title2:
            return 1.0

        # Also check steps
        steps1 = " ".join(test1.get("steps", []))
        steps2 = " ".join(test2.get("steps", []))

        if steps1 and steps2 and steps1 == steps2:
            return 1.0

        return 0.0

    def _normalized_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate normalized text similarity."""
        text1 = self._normalize_text(self._get_test_text(test1))
        text2 = self._normalize_text(self._get_test_text(test2))

        if not text1 or not text2:
            return 0.0

        if text1 == text2:
            return 1.0

        # Character-level similarity
        common = len(set(text1) & set(text2))
        total = len(set(text1) | set(text2))

        return common / total if total > 0 else 0.0

    def _jaccard_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate Jaccard similarity of tokens."""
        tokens1 = self._tokenize(self._get_test_text(test1))
        tokens2 = self._tokenize(self._get_test_text(test2))

        if not tokens1 or not tokens2:
            return 0.0

        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        return intersection / union if union > 0 else 0.0

    def _cosine_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate cosine similarity using TF-IDF."""
        vec1 = self._get_tfidf_vector(test1)
        vec2 = self._get_tfidf_vector(test2)

        if not vec1 or not vec2:
            return 0.0

        # Calculate cosine similarity
        dot_product = sum(vec1.get(term, 0) * vec2.get(term, 0) for term in set(vec1) | set(vec2))
        magnitude1 = math.sqrt(sum(v ** 2 for v in vec1.values()))
        magnitude2 = math.sqrt(sum(v ** 2 for v in vec2.values()))

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def _step_overlap_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate similarity based on step overlap."""
        steps1 = test1.get("steps", [])
        steps2 = test2.get("steps", [])

        if not steps1 or not steps2:
            return 0.0

        # Normalize steps
        norm_steps1 = [self._normalize_text(s) for s in steps1]
        norm_steps2 = [self._normalize_text(s) for s in steps2]

        # Count matching steps
        matches = 0
        for s1 in norm_steps1:
            for s2 in norm_steps2:
                if s1 == s2 or self._jaccard_similarity(
                    {"title": s1}, {"title": s2}
                ) > 0.8:
                    matches += 1
                    break

        return matches / max(len(steps1), len(steps2))

    def _combined_similarity(
        self,
        test1: Dict[str, Any],
        test2: Dict[str, Any],
    ) -> float:
        """Calculate combined similarity using multiple methods."""
        # Weight each method
        weights = {
            "jaccard": 0.3,
            "cosine": 0.3,
            "step_overlap": 0.25,
            "normalized": 0.15,
        }

        jaccard = self._jaccard_similarity(test1, test2)
        cosine = self._cosine_similarity(test1, test2)
        step = self._step_overlap_similarity(test1, test2)
        normalized = self._normalized_similarity(test1, test2)

        return (
            weights["jaccard"] * jaccard +
            weights["cosine"] * cosine +
            weights["step_overlap"] * step +
            weights["normalized"] * normalized
        )

    def _get_test_text(self, test: Dict[str, Any]) -> str:
        """Get all text from a test for analysis."""
        parts = [
            test.get("title", ""),
            test.get("description", ""),
            " ".join(test.get("steps", [])),
            test.get("expected_result", ""),
        ]
        return " ".join(parts)

    def _normalize_text(self, text: str) -> str:
        """Normalize text for comparison."""
        # Lowercase
        text = text.lower()
        # Remove special characters
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        # Remove extra whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _tokenize(self, text: str) -> Set[str]:
        """Tokenize text, removing stop words."""
        text = self._normalize_text(text)
        tokens = set(text.split())
        return tokens - self.STOP_WORDS

    def _build_idf_cache(self, tests: List[Dict[str, Any]]):
        """Build IDF cache for TF-IDF calculations."""
        doc_count = len(tests)
        term_doc_counts: Dict[str, int] = defaultdict(int)

        for test in tests:
            tokens = self._tokenize(self._get_test_text(test))
            for token in tokens:
                term_doc_counts[token] += 1

        for term, count in term_doc_counts.items():
            self._idf_cache[term] = math.log(doc_count / (1 + count))

    def _get_tfidf_vector(self, test: Dict[str, Any]) -> Dict[str, float]:
        """Get TF-IDF vector for a test."""
        tokens = self._tokenize(self._get_test_text(test))
        if not tokens:
            return {}

        # Calculate TF
        tf: Dict[str, int] = defaultdict(int)
        for token in tokens:
            tf[token] += 1

        # Calculate TF-IDF
        max_tf = max(tf.values()) if tf else 1
        tfidf = {}
        for term, count in tf.items():
            normalized_tf = count / max_tf
            idf = self._idf_cache.get(term, 1.0)
            tfidf[term] = normalized_tf * idf

        return tfidf

    def _group_duplicates(
        self,
        tests: List[Dict[str, Any]],
        similarities: List[TestSimilarity],
    ) -> List[DuplicateGroup]:
        """Group duplicates using union-find."""
        # Build adjacency list
        adjacency: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        for sim in similarities:
            adjacency[sim.test_id_1].append((sim.test_id_2, sim.score))
            adjacency[sim.test_id_2].append((sim.test_id_1, sim.score))

        # Find connected components
        visited = set()
        groups = []
        group_count = 0

        test_lookup = {t.get("id", ""): t for t in tests}

        for test in tests:
            test_id = test.get("id", "")
            if test_id in visited:
                continue

            # BFS to find all connected tests
            component = []
            scores = []
            queue = [test_id]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)

                for neighbor, score in adjacency[current]:
                    if neighbor not in visited:
                        queue.append(neighbor)
                        scores.append(score)

            # Only create group if there are duplicates
            if len(component) > 1:
                group_count += 1

                # Choose primary (highest priority or first)
                primary = self._choose_primary(component, test_lookup)
                duplicates = [t for t in component if t != primary]

                avg_score = sum(scores) / len(scores) if scores else 0.0

                groups.append(DuplicateGroup(
                    group_id=f"DG-{group_count:04d}",
                    primary_test_id=primary,
                    duplicate_test_ids=duplicates,
                    similarity_scores=scores,
                    avg_similarity=avg_score,
                    recommendation=self._generate_recommendation(component, test_lookup),
                ))

        return groups

    def _choose_primary(
        self,
        test_ids: List[str],
        test_lookup: Dict[str, Dict[str, Any]],
    ) -> str:
        """Choose the primary test from a group of duplicates."""
        # Prioritize by: priority > number of steps > title length
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        def score(test_id: str) -> Tuple[int, int, int]:
            test = test_lookup.get(test_id, {})
            p = priority_order.get(test.get("priority", "medium"), 2)
            steps = len(test.get("steps", []))
            title_len = len(test.get("title", ""))
            return (p, -steps, -title_len)

        return min(test_ids, key=score)

    def _generate_recommendation(
        self,
        test_ids: List[str],
        test_lookup: Dict[str, Dict[str, Any]],
    ) -> str:
        """Generate a recommendation for handling duplicates."""
        if len(test_ids) == 2:
            return "Consider merging these two tests or removing one"
        else:
            return f"Consider consolidating these {len(test_ids)} tests into one comprehensive test"

    def format_report(self, result: DeduplicationResult) -> str:
        """Format deduplication result as a report."""
        lines = [
            "=" * 60,
            "  TEST DEDUPLICATION REPORT",
            "=" * 60,
            "",
            f"  Total Tests Analyzed: {result.total_tests}",
            f"  Unique Tests: {result.unique_tests}",
            f"  Duplicate Tests: {result.total_duplicates}",
            f"  Potential Savings: {result.potential_savings} tests",
            "",
        ]

        if result.duplicate_groups:
            lines.extend([
                "-" * 60,
                "  DUPLICATE GROUPS",
                "-" * 60,
            ])

            for group in result.duplicate_groups:
                lines.extend([
                    "",
                    f"  [{group.group_id}] Primary: {group.primary_test_id}",
                    f"    Duplicates: {', '.join(group.duplicate_test_ids)}",
                    f"    Avg Similarity: {group.avg_similarity:.1%}",
                    f"    Recommendation: {group.recommendation}",
                ])

        else:
            lines.append("  No duplicates found!")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_deduplicator(
    similarity_threshold: float = 0.7,
    method: SimilarityMethod = SimilarityMethod.COMBINED,
) -> TestDeduplicator:
    """Create a test deduplicator instance."""
    return TestDeduplicator(similarity_threshold, method)
