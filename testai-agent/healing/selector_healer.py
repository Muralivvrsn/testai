"""
TestAI Agent - Selector Healer

Intelligent selector healing that automatically finds
alternative selectors when original selectors break.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable
import re
import uuid


class SelectorType(Enum):
    """Types of selectors."""
    CSS = "css"
    XPATH = "xpath"
    ID = "id"
    CLASS = "class"
    NAME = "name"
    DATA_TESTID = "data_testid"
    DATA_ATTR = "data_attr"
    TEXT = "text"
    ARIA_LABEL = "aria_label"
    ROLE = "role"
    LINK_TEXT = "link_text"
    PARTIAL_LINK_TEXT = "partial_link_text"


class HealingStrategy(Enum):
    """Strategies for healing selectors."""
    ATTRIBUTE_FALLBACK = "attribute_fallback"  # Try other attributes
    STRUCTURAL = "structural"  # Use DOM structure
    SEMANTIC = "semantic"  # Use semantic attributes
    TEXT_BASED = "text_based"  # Use text content
    HYBRID = "hybrid"  # Combine multiple strategies
    ML_ASSISTED = "ml_assisted"  # Machine learning suggestions


@dataclass
class ElementSnapshot:
    """Snapshot of an element's attributes at a point in time."""
    tag_name: str
    element_id: Optional[str]
    classes: List[str]
    attributes: Dict[str, str]
    text_content: str
    parent_tag: Optional[str]
    sibling_index: int
    xpath: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SelectorCandidate:
    """A candidate selector for healing."""
    selector: str
    selector_type: SelectorType
    confidence: float  # 0.0 to 1.0
    strategy: HealingStrategy
    stability_score: float  # How stable is this selector
    specificity_score: float  # How specific is this selector
    reasoning: str


@dataclass
class HealingResult:
    """Result of a selector healing attempt."""
    result_id: str
    original_selector: str
    original_type: SelectorType
    healed_selector: str
    healed_type: SelectorType
    confidence: float
    strategy_used: HealingStrategy
    candidates_evaluated: int
    healing_time_ms: int
    success: bool
    healed_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class SelectorHealer:
    """
    Intelligent selector healing system.

    Features:
    - Multiple healing strategies
    - Confidence scoring
    - Element fingerprinting
    - Historical pattern learning
    - Attribute fallback chains
    """

    # Selector stability rankings (higher = more stable)
    STABILITY_RANKINGS = {
        SelectorType.DATA_TESTID: 0.95,
        SelectorType.ID: 0.85,
        SelectorType.DATA_ATTR: 0.80,
        SelectorType.ARIA_LABEL: 0.75,
        SelectorType.NAME: 0.70,
        SelectorType.ROLE: 0.65,
        SelectorType.TEXT: 0.50,
        SelectorType.CLASS: 0.40,
        SelectorType.CSS: 0.35,
        SelectorType.XPATH: 0.30,
    }

    def __init__(
        self,
        default_strategy: HealingStrategy = HealingStrategy.HYBRID,
        min_confidence: float = 0.7,
    ):
        """Initialize the healer."""
        self.default_strategy = default_strategy
        self.min_confidence = min_confidence

        self._snapshots: Dict[str, ElementSnapshot] = {}
        self._healing_history: List[HealingResult] = []
        self._result_counter = 0

        # Pattern learning
        self._successful_patterns: List[Dict[str, Any]] = []

    def capture_snapshot(
        self,
        selector_id: str,
        tag_name: str,
        element_id: Optional[str] = None,
        classes: Optional[List[str]] = None,
        attributes: Optional[Dict[str, str]] = None,
        text_content: str = "",
        parent_tag: Optional[str] = None,
        sibling_index: int = 0,
        xpath: str = "",
    ) -> ElementSnapshot:
        """Capture a snapshot of an element for future healing."""
        snapshot = ElementSnapshot(
            tag_name=tag_name,
            element_id=element_id,
            classes=classes or [],
            attributes=attributes or {},
            text_content=text_content,
            parent_tag=parent_tag,
            sibling_index=sibling_index,
            xpath=xpath,
        )

        self._snapshots[selector_id] = snapshot
        return snapshot

    def heal(
        self,
        original_selector: str,
        original_type: SelectorType = SelectorType.CSS,
        current_dom: Optional[Dict[str, Any]] = None,
        strategy: Optional[HealingStrategy] = None,
    ) -> HealingResult:
        """Attempt to heal a broken selector."""
        start_time = datetime.now()
        self._result_counter += 1
        result_id = f"HEAL-{self._result_counter:05d}"

        strategy = strategy or self.default_strategy

        # Generate candidates
        candidates = self._generate_candidates(
            original_selector, original_type, current_dom, strategy
        )

        # Rank and select best candidate
        if candidates:
            candidates.sort(key=lambda c: c.confidence, reverse=True)
            best = candidates[0]

            if best.confidence >= self.min_confidence:
                healing_time = int((datetime.now() - start_time).total_seconds() * 1000)

                result = HealingResult(
                    result_id=result_id,
                    original_selector=original_selector,
                    original_type=original_type,
                    healed_selector=best.selector,
                    healed_type=best.selector_type,
                    confidence=best.confidence,
                    strategy_used=best.strategy,
                    candidates_evaluated=len(candidates),
                    healing_time_ms=healing_time,
                    success=True,
                    healed_at=datetime.now(),
                    metadata={
                        "reasoning": best.reasoning,
                        "stability_score": best.stability_score,
                    },
                )

                self._healing_history.append(result)
                self._learn_from_success(result)
                return result

        # Healing failed
        healing_time = int((datetime.now() - start_time).total_seconds() * 1000)

        result = HealingResult(
            result_id=result_id,
            original_selector=original_selector,
            original_type=original_type,
            healed_selector=original_selector,
            healed_type=original_type,
            confidence=0.0,
            strategy_used=strategy,
            candidates_evaluated=len(candidates),
            healing_time_ms=healing_time,
            success=False,
            healed_at=datetime.now(),
            metadata={"reason": "No suitable candidate found"},
        )

        self._healing_history.append(result)
        return result

    def _generate_candidates(
        self,
        original_selector: str,
        original_type: SelectorType,
        current_dom: Optional[Dict[str, Any]],
        strategy: HealingStrategy,
    ) -> List[SelectorCandidate]:
        """Generate healing candidates based on strategy."""
        candidates = []

        if strategy == HealingStrategy.ATTRIBUTE_FALLBACK:
            candidates.extend(self._attribute_fallback_candidates(original_selector, current_dom))
        elif strategy == HealingStrategy.STRUCTURAL:
            candidates.extend(self._structural_candidates(original_selector, current_dom))
        elif strategy == HealingStrategy.SEMANTIC:
            candidates.extend(self._semantic_candidates(original_selector, current_dom))
        elif strategy == HealingStrategy.TEXT_BASED:
            candidates.extend(self._text_based_candidates(original_selector, current_dom))
        elif strategy == HealingStrategy.HYBRID:
            # Try all strategies
            candidates.extend(self._attribute_fallback_candidates(original_selector, current_dom))
            candidates.extend(self._structural_candidates(original_selector, current_dom))
            candidates.extend(self._semantic_candidates(original_selector, current_dom))
            candidates.extend(self._text_based_candidates(original_selector, current_dom))

        return candidates

    def _attribute_fallback_candidates(
        self,
        original: str,
        dom: Optional[Dict[str, Any]],
    ) -> List[SelectorCandidate]:
        """Generate candidates using attribute fallback."""
        candidates = []

        # If we have DOM info, use it
        if dom:
            # Try data-testid
            if "data-testid" in dom.get("attributes", {}):
                testid = dom["attributes"]["data-testid"]
                candidates.append(SelectorCandidate(
                    selector=f'[data-testid="{testid}"]',
                    selector_type=SelectorType.DATA_TESTID,
                    confidence=0.95,
                    strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                    stability_score=0.95,
                    specificity_score=0.90,
                    reasoning="Using data-testid attribute (highly stable)",
                ))

            # Try ID
            if dom.get("id"):
                candidates.append(SelectorCandidate(
                    selector=f'#{dom["id"]}',
                    selector_type=SelectorType.ID,
                    confidence=0.85,
                    strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                    stability_score=0.85,
                    specificity_score=0.95,
                    reasoning="Using element ID",
                ))

            # Try name attribute
            if "name" in dom.get("attributes", {}):
                name = dom["attributes"]["name"]
                candidates.append(SelectorCandidate(
                    selector=f'[name="{name}"]',
                    selector_type=SelectorType.NAME,
                    confidence=0.75,
                    strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                    stability_score=0.70,
                    specificity_score=0.80,
                    reasoning="Using name attribute",
                ))

            # Try aria-label
            if "aria-label" in dom.get("attributes", {}):
                label = dom["attributes"]["aria-label"]
                candidates.append(SelectorCandidate(
                    selector=f'[aria-label="{label}"]',
                    selector_type=SelectorType.ARIA_LABEL,
                    confidence=0.80,
                    strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                    stability_score=0.75,
                    specificity_score=0.85,
                    reasoning="Using aria-label for accessibility",
                ))

        # Simulated fallback when no DOM provided
        else:
            # Extract info from original selector
            if original.startswith("#"):
                # ID selector - suggest data-testid alternative
                element_id = original[1:]
                candidates.append(SelectorCandidate(
                    selector=f'[data-testid="{element_id}"]',
                    selector_type=SelectorType.DATA_TESTID,
                    confidence=0.70,
                    strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                    stability_score=0.95,
                    specificity_score=0.80,
                    reasoning="Converted ID to data-testid",
                ))

        return candidates

    def _structural_candidates(
        self,
        original: str,
        dom: Optional[Dict[str, Any]],
    ) -> List[SelectorCandidate]:
        """Generate candidates using DOM structure."""
        candidates = []

        if dom:
            tag = dom.get("tag", "div")
            parent = dom.get("parent_tag", "div")
            index = dom.get("sibling_index", 0)

            # Parent-child relationship
            candidates.append(SelectorCandidate(
                selector=f"{parent} > {tag}:nth-child({index + 1})",
                selector_type=SelectorType.CSS,
                confidence=0.55,
                strategy=HealingStrategy.STRUCTURAL,
                stability_score=0.40,
                specificity_score=0.70,
                reasoning="Using parent-child structural relationship",
            ))

            # XPath based on structure
            xpath = f"//{parent}/{tag}[{index + 1}]"
            candidates.append(SelectorCandidate(
                selector=xpath,
                selector_type=SelectorType.XPATH,
                confidence=0.50,
                strategy=HealingStrategy.STRUCTURAL,
                stability_score=0.35,
                specificity_score=0.75,
                reasoning="Using XPath structural relationship",
            ))

        return candidates

    def _semantic_candidates(
        self,
        original: str,
        dom: Optional[Dict[str, Any]],
    ) -> List[SelectorCandidate]:
        """Generate candidates using semantic attributes."""
        candidates = []

        if dom:
            # Role-based selector
            if "role" in dom.get("attributes", {}):
                role = dom["attributes"]["role"]
                candidates.append(SelectorCandidate(
                    selector=f'[role="{role}"]',
                    selector_type=SelectorType.ROLE,
                    confidence=0.70,
                    strategy=HealingStrategy.SEMANTIC,
                    stability_score=0.65,
                    specificity_score=0.60,
                    reasoning="Using ARIA role for semantic selection",
                ))

            # Type-based for inputs
            tag = dom.get("tag", "")
            if tag.lower() == "input" and "type" in dom.get("attributes", {}):
                input_type = dom["attributes"]["type"]
                candidates.append(SelectorCandidate(
                    selector=f'input[type="{input_type}"]',
                    selector_type=SelectorType.CSS,
                    confidence=0.50,
                    strategy=HealingStrategy.SEMANTIC,
                    stability_score=0.45,
                    specificity_score=0.40,
                    reasoning="Using input type for semantic selection",
                ))

        return candidates

    def _text_based_candidates(
        self,
        original: str,
        dom: Optional[Dict[str, Any]],
    ) -> List[SelectorCandidate]:
        """Generate candidates using text content."""
        candidates = []

        if dom:
            text = dom.get("text_content", "").strip()

            if text and len(text) < 100:
                # Exact text match
                candidates.append(SelectorCandidate(
                    selector=f'text="{text}"',
                    selector_type=SelectorType.TEXT,
                    confidence=0.65,
                    strategy=HealingStrategy.TEXT_BASED,
                    stability_score=0.50,
                    specificity_score=0.70,
                    reasoning="Using exact text content match",
                ))

                # Partial text match
                if len(text) > 10:
                    partial = text[:20]
                    candidates.append(SelectorCandidate(
                        selector=f'//*[contains(text(), "{partial}")]',
                        selector_type=SelectorType.XPATH,
                        confidence=0.55,
                        strategy=HealingStrategy.TEXT_BASED,
                        stability_score=0.45,
                        specificity_score=0.55,
                        reasoning="Using partial text content match",
                    ))

        return candidates

    def _learn_from_success(self, result: HealingResult):
        """Learn from successful healing for future improvements."""
        if result.success:
            self._successful_patterns.append({
                "original_type": result.original_type.value,
                "healed_type": result.healed_type.value,
                "strategy": result.strategy_used.value,
                "confidence": result.confidence,
                "timestamp": result.healed_at.isoformat(),
            })

            # Keep only recent patterns
            if len(self._successful_patterns) > 1000:
                self._successful_patterns = self._successful_patterns[-500:]

    def suggest_stable_selectors(
        self,
        element_info: Dict[str, Any],
    ) -> List[SelectorCandidate]:
        """Suggest stable selectors for an element."""
        candidates = []

        # Prefer data-testid
        if "data-testid" in element_info.get("attributes", {}):
            testid = element_info["attributes"]["data-testid"]
            candidates.append(SelectorCandidate(
                selector=f'[data-testid="{testid}"]',
                selector_type=SelectorType.DATA_TESTID,
                confidence=0.98,
                strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                stability_score=0.95,
                specificity_score=0.90,
                reasoning="data-testid is the most stable selector strategy",
            ))

        # ID as second choice
        if element_info.get("id"):
            candidates.append(SelectorCandidate(
                selector=f'#{element_info["id"]}',
                selector_type=SelectorType.ID,
                confidence=0.90,
                strategy=HealingStrategy.ATTRIBUTE_FALLBACK,
                stability_score=0.85,
                specificity_score=0.95,
                reasoning="ID selectors are highly specific and stable",
            ))

        # aria-label for accessibility
        if "aria-label" in element_info.get("attributes", {}):
            label = element_info["attributes"]["aria-label"]
            candidates.append(SelectorCandidate(
                selector=f'[aria-label="{label}"]',
                selector_type=SelectorType.ARIA_LABEL,
                confidence=0.85,
                strategy=HealingStrategy.SEMANTIC,
                stability_score=0.75,
                specificity_score=0.85,
                reasoning="aria-label provides semantic stability",
            ))

        return sorted(candidates, key=lambda c: c.stability_score, reverse=True)

    def get_healing_history(
        self,
        success_only: bool = False,
        limit: int = 100,
    ) -> List[HealingResult]:
        """Get healing history."""
        results = self._healing_history

        if success_only:
            results = [r for r in results if r.success]

        return results[-limit:]

    def get_success_rate(self) -> float:
        """Get healing success rate."""
        if not self._healing_history:
            return 0.0

        successful = sum(1 for r in self._healing_history if r.success)
        return successful / len(self._healing_history)

    def get_statistics(self) -> Dict[str, Any]:
        """Get healer statistics."""
        strategy_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}

        for result in self._healing_history:
            if result.success:
                strategy = result.strategy_used.value
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

                healed_type = result.healed_type.value
                type_counts[healed_type] = type_counts.get(healed_type, 0) + 1

        return {
            "total_healings": len(self._healing_history),
            "successful_healings": sum(1 for r in self._healing_history if r.success),
            "success_rate": self.get_success_rate(),
            "snapshots_stored": len(self._snapshots),
            "patterns_learned": len(self._successful_patterns),
            "strategy_distribution": strategy_counts,
            "healed_type_distribution": type_counts,
        }

    def format_result(self, result: HealingResult) -> str:
        """Format a healing result."""
        status_icon = "✅" if result.success else "❌"

        lines = [
            "=" * 60,
            f"  {status_icon} SELECTOR HEALING RESULT",
            "=" * 60,
            "",
            f"  Result ID: {result.result_id}",
            f"  Success: {result.success}",
            f"  Confidence: {result.confidence:.0%}",
            "",
            f"  Original: {result.original_selector}",
            f"  Original Type: {result.original_type.value}",
            "",
            f"  Healed: {result.healed_selector}",
            f"  Healed Type: {result.healed_type.value}",
            "",
            f"  Strategy: {result.strategy_used.value}",
            f"  Candidates Evaluated: {result.candidates_evaluated}",
            f"  Healing Time: {result.healing_time_ms}ms",
            "",
            "=" * 60,
        ]

        return "\n".join(lines)


def create_selector_healer(
    default_strategy: HealingStrategy = HealingStrategy.HYBRID,
    min_confidence: float = 0.7,
) -> SelectorHealer:
    """Create a selector healer instance."""
    return SelectorHealer(default_strategy, min_confidence)
