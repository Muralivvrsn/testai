"""
TestAI Agent - Cortex Module

The decision-making center of the agent.
Decides when to ask, when to act, what to prioritize.

Components:
- DecisionEngine: Decides when to ask vs act
- ConfidenceScorer: Measures certainty
- Reasoner: Citation-aware reasoning (zero hallucination)
- TestPrioritizer: Risk-based test prioritization
- RiskIntelligence: Intelligent risk-based prioritization with learning
"""

from .decision_engine import DecisionEngine, Decision, DecisionContext, ActionType, DecisionOutcome
from .confidence import ConfidenceScorer, ConfidenceResult, ConfidenceLevel
from .reasoner import Reasoner, ReasoningResult, ReasoningPhase, RetrievedKnowledge, quick_reason
from .prioritizer import (
    TestPrioritizer,
    PrioritizedTest,
    RiskAssessment,
    RiskFactor,
    Priority,
    prioritize_tests,
    get_critical_tests,
)
from .risk_intelligence import (
    RiskIntelligence,
    RiskLevel,
    ImpactArea,
    HistoricalRisk,
    FeatureRisk,
    RiskScore,
    create_risk_intelligence,
)
from .coverage_analyzer import (
    CoverageAnalyzer,
    CoverageGap,
    CoverageReport,
    GapSeverity,
    CoverageCategory,
    create_coverage_analyzer,
)

__all__ = [
    # Decision Engine
    'DecisionEngine',
    'Decision',
    'DecisionContext',
    'ActionType',
    'DecisionOutcome',
    # Confidence
    'ConfidenceScorer',
    'ConfidenceResult',
    'ConfidenceLevel',
    # Reasoner
    'Reasoner',
    'ReasoningResult',
    'ReasoningPhase',
    'RetrievedKnowledge',
    'quick_reason',
    # Prioritizer
    'TestPrioritizer',
    'PrioritizedTest',
    'RiskAssessment',
    'RiskFactor',
    'Priority',
    'prioritize_tests',
    'get_critical_tests',
    # Risk Intelligence
    'RiskIntelligence',
    'RiskLevel',
    'ImpactArea',
    'HistoricalRisk',
    'FeatureRisk',
    'RiskScore',
    'create_risk_intelligence',
    # Coverage Analyzer (NEW)
    'CoverageAnalyzer',
    'CoverageGap',
    'CoverageReport',
    'GapSeverity',
    'CoverageCategory',
    'create_coverage_analyzer',
]
