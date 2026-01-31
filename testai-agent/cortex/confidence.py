"""
TestAI Agent - Confidence Scoring

Calculates how confident the agent should be about its decisions.
Humans show confidence naturally - so should we.

Confidence Factors:
- Knowledge match quality (how relevant is our brain data?)
- Context completeness (do we have all the info?)
- Pattern recognition (have we seen this before?)
- Ambiguity level (how clear is the request?)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class ConfidenceLevel(Enum):
    """Human-readable confidence levels."""
    VERY_HIGH = "very_high"    # 90%+ - Proceed without hesitation
    HIGH = "high"              # 75-90% - Proceed with minor caveats
    MODERATE = "moderate"      # 50-75% - Ask clarifying questions
    LOW = "low"                # 25-50% - Need more info before proceeding
    VERY_LOW = "very_low"      # <25% - Cannot proceed, need help

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        """Convert numeric score to level."""
        if score >= 0.90:
            return cls.VERY_HIGH
        elif score >= 0.75:
            return cls.HIGH
        elif score >= 0.50:
            return cls.MODERATE
        elif score >= 0.25:
            return cls.LOW
        else:
            return cls.VERY_LOW

    @property
    def should_proceed(self) -> bool:
        """Can we proceed without asking?"""
        return self in [ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH]

    @property
    def should_clarify(self) -> bool:
        """Should we ask clarifying questions?"""
        return self in [ConfidenceLevel.MODERATE, ConfidenceLevel.LOW]


@dataclass
class ConfidenceResult:
    """Result of a confidence calculation."""
    score: float  # 0.0 to 1.0
    level: ConfidenceLevel
    factors: Dict[str, float]  # Individual factor scores
    reasoning: str
    suggestions: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.level.value} ({self.score:.0%}): {self.reasoning}"

    @property
    def can_proceed(self) -> bool:
        """Can we proceed autonomously?"""
        return self.level.should_proceed


@dataclass
class ConfidenceFactors:
    """Factors that contribute to confidence."""
    knowledge_relevance: float = 0.0   # How relevant is our brain data?
    context_completeness: float = 0.0  # Do we have all the info?
    pattern_match: float = 0.0         # Have we seen this before?
    clarity: float = 0.0               # How clear is the request?
    element_coverage: float = 0.0      # Did we find expected elements?
    user_history: float = 0.0          # Past interactions help?

    def to_dict(self) -> Dict[str, float]:
        return {
            "knowledge_relevance": self.knowledge_relevance,
            "context_completeness": self.context_completeness,
            "pattern_match": self.pattern_match,
            "clarity": self.clarity,
            "element_coverage": self.element_coverage,
            "user_history": self.user_history,
        }


class ConfidenceScorer:
    """
    Calculates confidence scores for agent decisions.

    Usage:
        scorer = ConfidenceScorer()

        # Score page classification confidence
        result = scorer.score_classification(
            page_type="login",
            found_elements=["email", "password", "submit"],
            knowledge_match_score=0.85
        )

        # Score test generation confidence
        result = scorer.score_generation(
            feature="user_login",
            context_available=True,
            knowledge_chunks=5
        )
    """

    # Weight each factor differently
    FACTOR_WEIGHTS = {
        "knowledge_relevance": 0.25,
        "context_completeness": 0.20,
        "pattern_match": 0.20,
        "clarity": 0.15,
        "element_coverage": 0.10,
        "user_history": 0.10,
    }

    def __init__(self, default_threshold: float = 0.70):
        """
        Initialize scorer.

        Args:
            default_threshold: Minimum confidence to proceed (0-1)
        """
        self.threshold = default_threshold

    def calculate(self, factors: ConfidenceFactors) -> ConfidenceResult:
        """Calculate weighted confidence score."""
        factor_dict = factors.to_dict()

        # Weighted average
        weighted_sum = sum(
            factor_dict[key] * self.FACTOR_WEIGHTS[key]
            for key in self.FACTOR_WEIGHTS
        )

        # Normalize (weights should sum to 1, but just in case)
        total_weight = sum(self.FACTOR_WEIGHTS.values())
        score = weighted_sum / total_weight

        # Determine level
        level = ConfidenceLevel.from_score(score)

        # Generate reasoning
        reasoning = self._generate_reasoning(factor_dict, level)

        # Generate suggestions for low confidence
        suggestions = self._generate_suggestions(factor_dict, level)

        return ConfidenceResult(
            score=score,
            level=level,
            factors=factor_dict,
            reasoning=reasoning,
            suggestions=suggestions,
        )

    def score_classification(
        self,
        page_type: str,
        found_elements: List[str],
        knowledge_match_score: float = 0.5,
        expected_elements: Optional[List[str]] = None,
    ) -> ConfidenceResult:
        """Score confidence for page type classification."""
        # Expected elements for common page types
        type_expectations = {
            "login": ["email", "password", "submit", "login", "sign in"],
            "signup": ["email", "password", "confirm", "register", "sign up", "name"],
            "checkout": ["payment", "card", "address", "shipping", "total", "order"],
            "search": ["search", "query", "filter", "results"],
            "form": ["input", "submit", "field"],
        }

        expected = expected_elements or type_expectations.get(page_type.lower(), [])

        # Calculate element coverage
        if expected and found_elements:
            found_lower = [e.lower() for e in found_elements]
            matches = sum(1 for exp in expected if any(exp in f for f in found_lower))
            element_coverage = matches / len(expected)
        else:
            element_coverage = 0.5  # Neutral if we can't compare

        # Clarity based on how distinct the page type is
        clarity = 0.8 if page_type.lower() in type_expectations else 0.5

        factors = ConfidenceFactors(
            knowledge_relevance=knowledge_match_score,
            context_completeness=0.7 if found_elements else 0.3,
            pattern_match=element_coverage,
            clarity=clarity,
            element_coverage=element_coverage,
            user_history=0.5,  # Neutral default
        )

        return self.calculate(factors)

    def score_generation(
        self,
        feature: str,
        context_available: bool,
        knowledge_chunks: int = 0,
        clarity_indicators: Optional[List[str]] = None,
    ) -> ConfidenceResult:
        """Score confidence for test generation."""
        # More knowledge chunks = higher relevance
        knowledge_score = min(knowledge_chunks / 5, 1.0)  # 5+ chunks = 100%

        # Context completeness
        context_score = 0.8 if context_available else 0.4

        # Clarity from indicators
        if clarity_indicators:
            clarity_score = len(clarity_indicators) / 5  # More indicators = clearer
        else:
            clarity_score = 0.5

        factors = ConfidenceFactors(
            knowledge_relevance=knowledge_score,
            context_completeness=context_score,
            pattern_match=0.6,  # Default for generation
            clarity=min(clarity_score, 1.0),
            element_coverage=0.7 if context_available else 0.4,
            user_history=0.5,
        )

        return self.calculate(factors)

    def score_security_analysis(
        self,
        page_type: str,
        has_auth_elements: bool,
        has_input_elements: bool,
        knowledge_match: float = 0.5,
    ) -> ConfidenceResult:
        """Score confidence for security analysis."""
        # Security analysis needs good knowledge
        knowledge_score = knowledge_match

        # Auth pages have clearer security patterns
        pattern_score = 0.8 if has_auth_elements else 0.5

        # Input elements create more attack surface
        context_score = 0.9 if has_input_elements else 0.6

        factors = ConfidenceFactors(
            knowledge_relevance=knowledge_score,
            context_completeness=context_score,
            pattern_match=pattern_score,
            clarity=0.7 if page_type in ["login", "signup", "checkout"] else 0.5,
            element_coverage=0.7,
            user_history=0.5,
        )

        return self.calculate(factors)

    def _generate_reasoning(
        self,
        factors: Dict[str, float],
        level: ConfidenceLevel,
    ) -> str:
        """Generate human-readable reasoning."""
        # Find weakest and strongest factors
        sorted_factors = sorted(factors.items(), key=lambda x: x[1])
        weakest = sorted_factors[0]
        strongest = sorted_factors[-1]

        if level.should_proceed:
            return f"Good confidence based on {strongest[0].replace('_', ' ')}."
        elif level == ConfidenceLevel.MODERATE:
            return f"Moderate confidence. {weakest[0].replace('_', ' ').title()} could be improved."
        else:
            return f"Low confidence due to limited {weakest[0].replace('_', ' ')}."

    def _generate_suggestions(
        self,
        factors: Dict[str, float],
        level: ConfidenceLevel,
    ) -> List[str]:
        """Generate suggestions for improving confidence."""
        suggestions = []

        if level.should_proceed:
            return suggestions

        # Suggest based on low factors
        if factors["knowledge_relevance"] < 0.5:
            suggestions.append("More context about the feature would help")

        if factors["context_completeness"] < 0.5:
            suggestions.append("Could you describe the expected behavior?")

        if factors["clarity"] < 0.5:
            suggestions.append("The request is a bit ambiguous - any specifics?")

        if factors["element_coverage"] < 0.5:
            suggestions.append("I found fewer elements than expected - is the page fully loaded?")

        return suggestions[:2]  # Limit to 2 suggestions


# Convenience function
def quick_confidence(
    knowledge_score: float,
    context_complete: bool,
    clarity: float = 0.7,
) -> ConfidenceResult:
    """Quick confidence calculation."""
    scorer = ConfidenceScorer()
    factors = ConfidenceFactors(
        knowledge_relevance=knowledge_score,
        context_completeness=0.8 if context_complete else 0.4,
        pattern_match=0.6,
        clarity=clarity,
        element_coverage=0.6,
        user_history=0.5,
    )
    return scorer.calculate(factors)
