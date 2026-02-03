/**
 * Yali Agent - Cortex Module (Complete)
 * The brain's cognitive layer - fully ported from Python testai-agent
 *
 * Components:
 * - Confidence Scoring: Calculate confidence levels
 * - Decision Engine: Decide what actions to take
 * - Prioritizer: Risk-based test prioritization
 * - QA Brain: Knowledge base for QA testing
 * - Reasoner: Citation-aware reasoning engine
 * - Coverage Analyzer: Identify test coverage gaps
 * - Risk Intelligence: Intelligent risk-based prioritization
 * - Memory: Conversational memory system
 * - Vulnerability Scanner: Security vulnerability detection
 * - Test Generator: Comprehensive test generation
 * - QA Consultant: Professional QA personality
 * - Adaptive Learner: Learn from test execution history
 * - Root Cause Analyzer: Diagnose test failures
 * - Unified Agent: Main orchestrator brain
 * - Failure Predictor: Predict failures before they happen
 * - Feature Analyzer: Understand user requests and intent
 * - Thinker: Human-like thinking aloud display
 * - Clarifier: Smart clarification questions
 * - Tone & Style: Human-like response styling
 * - Insight Engine: Pattern detection and anomaly identification
 * - Test Recommender: AI-powered test improvement recommendations
 * - Flakiness Detector: Detect flaky tests through statistical analysis
 * - Selector Healer: Self-healing selectors when tests break
 * - Edge Case Detector: Automatically identify edge cases humans miss
 * - Retry Manager: Smart retry strategies, adaptive learning, quarantine
 * - Test Scheduler: Schedule tests across browsers, devices, time windows
 * - Change Detector: Parse git diffs for impact analysis and test prioritization
 * - QA Orchestrator: TODO-driven exploration loop with full history logging
 */

// Core reasoning components
const {
  ConfidenceLevel,
  ConfidenceScorer,
  FACTOR_WEIGHTS,
  scoreToLevel,
  shouldProceed,
  shouldClarify,
  quickConfidence,
  createDefaultFactors
} = require('./confidence')

const {
  ActionType,
  DecisionOutcome,
  DecisionEngine,
  createDecisionContext,
  createDecision,
  quickDecide
} = require('./decision-engine')

const {
  RiskFactor,
  Priority,
  RISK_WEIGHTS,
  SECURITY_KEYWORDS,
  DATA_LOSS_KEYWORDS,
  REVENUE_KEYWORDS,
  USER_FRICTION_KEYWORDS,
  COMPLIANCE_KEYWORDS,
  PAGE_TYPE_RISK,
  TestPrioritizer,
  createRiskAssessment,
  prioritizeTests,
  getCriticalTests,
  scoreKeywords
} = require('./prioritizer')

const {
  QA_BRAIN,
  createSection,
  getAllSections,
  getSection,
  searchByTag,
  searchByKeyword,
  getForPageType,
  getTestsFromSections,
  formatForPrompt,
  getEdgeCases
} = require('./qa-brain')

const {
  ReasoningPhase,
  Reasoner,
  createRetrievedKnowledge,
  createReasoningResult,
  quickReason,
  PROMPTS
} = require('./reasoner')

// Coverage and analysis components
const {
  GapSeverity,
  CoverageCategory,
  REQUIRED_RULES,
  CoverageAnalyzer,
  createGap,
  createCoverageReport,
  quickCoverageCheck
} = require('./coverage-analyzer')

const {
  RiskLevel,
  ImpactArea,
  IMPACT_WEIGHTS,
  PAGE_TYPE_RISK: RISK_PAGE_TYPE,
  CATEGORY_RISK,
  RiskIntelligence,
  HistoricalRisk,
  createRiskScore,
  quickRiskScore
} = require('./risk-intelligence')

// Memory and conversation
const {
  MemoryType,
  ConversationalMemory,
  createMemory,
  createConversationTurn,
  createWorkingContext
} = require('./memory')

// Security
const {
  VulnerabilityType,
  SeverityLevel,
  VULNERABILITY_MAP,
  VulnerabilityScanner,
  createVulnerability,
  createScanResult,
  quickScan
} = require('./vulnerability-scanner')

// Test generation
const {
  TestCategory,
  TestPriority,
  TestGenerator,
  TEST_TEMPLATES,
  createTestCase,
  createTestSuite,
  quickGenerate
} = require('./test-generator')

// Personality
const {
  ConsultantMood,
  QuestionPriority,
  CLARIFYING_QUESTIONS,
  GREETINGS,
  THINKING_PHRASES,
  QAConsultantPersonality,
  createClarifyingQuestion,
  createThought,
  createRecommendation
} = require('./qa-consultant')

// Adaptive Learning
const {
  InsightType,
  ConfidenceLevel: LearnerConfidenceLevel,
  DEFAULT_CONFIG: LEARNER_CONFIG,
  AdaptiveLearner,
  createAdaptiveLearner,
  createInsight,
  createExecution,
  createPattern,
  categorizeError
} = require('./adaptive-learner')

// Root Cause Analysis
const {
  FailureCategory,
  FailureSeverity,
  ERROR_PATTERNS,
  FIX_SUGGESTIONS,
  CATEGORY_DESCRIPTIONS,
  RootCauseAnalyzer,
  createRootCauseAnalyzer,
  createRootCause,
  createFailurePattern,
  createAnalysisResult,
  quickAnalyze
} = require('./root-cause-analyzer')

// Unified Agent (The Brain)
const {
  AgentState,
  AgentCapabilities,
  DEFAULT_CONFIG: AGENT_CONFIG,
  UnifiedAgent,
  createUnifiedAgent,
  quickAgent,
  createGenerationResult
} = require('./unified-agent')

// Failure Predictor
const {
  PredictionType,
  RiskLevel: PredictorRiskLevel,
  DEFAULT_CONFIG: PREDICTOR_CONFIG,
  FailurePredictor,
  createFailurePredictor,
  createPrediction,
  createHistoricalData,
  createPredictionResult,
  quickPredict
} = require('./failure-predictor')

// Feature Analyzer
const {
  UserIntent,
  INTENT_KEYWORDS,
  PAGE_TYPE_PATTERNS,
  FOCUS_SUGGESTIONS,
  FeatureAnalyzer,
  createFeatureContext,
  analyzeRequest,
  analyzePage
} = require('./feature-analyzer')

// Thinker (Thinking Aloud)
const {
  ThinkingPhase,
  PATTERNS: THINKING_PATTERNS,
  PAGE_SPECIFIC_THOUGHTS,
  CONFIDENT_PREFIXES,
  UNCERTAIN_PREFIXES,
  PHASE_DELAYS,
  Thinker,
  createThought: createThinkerThought,
  think,
  thinkSequence,
  getThinkingPhrase
} = require('./thinker')

// Clarifier (Smart Questions)
const {
  QuestionPriority: ClarifierQuestionPriority,
  Clarifier,
  createClarificationQuestion: createClarifierQuestion,
  createClarificationBundle,
  clarifyForPage,
  clarifyFeature
} = require('./clarifier')

// Tone & Style (Human-like Responses)
const {
  Confidence,
  getConfidenceScore,
  CONFIDENCE_PHRASES,
  TRANSITIONS,
  GREETINGS: TONE_GREETINGS,
  CELEBRATIONS,
  SOFTENERS,
  EMPATHY_PHRASES,
  IMPORTANCE_PHRASES,
  ResponseStyler,
  createStyledResponse,
  styledResponse,
  getPhrase
} = require('./tone')

// Insight Engine (Pattern Detection)
const {
  InsightType: EngineInsightType,
  InsightPriority,
  InsightCategory,
  InsightEngine,
  createInsight: createEngineInsight,
  createTestEvent,
  createTestMetric,
  createInsightEngine
} = require('./insight-engine')

// Test Recommender (AI Recommendations)
const {
  RecommendationType,
  RecommendationImpact,
  RecommendationEffort,
  TestRecommender,
  createRecommendation: createTestRecommendation,
  createTestProfile,
  createSuiteProfile,
  createTestRecommender
} = require('./recommender')

// Flakiness Detector
const {
  FlakinessPattern,
  FlakinessLevel,
  FlakinessDetector,
  createTestExecution,
  createFlakinessReport,
  createFlakinessDetector
} = require('./flakiness-detector')

// Selector Healer (Self-Healing Tests)
const {
  SelectorType,
  HealingStrategy,
  STABILITY_RANKINGS,
  SelectorHealer,
  createSelectorCandidate,
  createHealingResult,
  createSelectorHealer
} = require('./selector-healer')

// Edge Case Detector
const {
  EdgeCaseCategory,
  UNIVERSAL_EDGE_CASES,
  PAGE_EDGE_CASES,
  INPUT_PATTERNS,
  EdgeCaseDetector,
  createEdgeCase,
  createEdgeCaseAnalysis,
  detectEdgeCases,
  getEdgeCaseTests
} = require('./edge-case-detector')

// Retry Manager (Smart Retries, Adaptive Learning, Quarantine)
const {
  BackoffType,
  RetryDecision,
  QuarantineReason,
  QuarantineStatus,
  RetryStrategy,
  createRetryStrategy,
  createRetryConfig,
  createRetryAttempt,
  createRetryResult,
  AdaptiveRetryManager,
  createAdaptiveRetryManager,
  QuarantineManager,
  createQuarantineManager
} = require('./retry-manager')

// Test Scheduler (Browser/Device Matrix, Recurring, Parallel)
const {
  ScheduleType,
  ScheduleStatus,
  RecurrencePattern,
  DEFAULT_BROWSERS,
  DEFAULT_DEVICES,
  createBrowserTarget,
  createDeviceTarget,
  createScheduleConfig,
  createScheduledRun,
  TestScheduler,
  createTestScheduler
} = require('./test-scheduler')

// Change Detector (Git Diff Analysis, Impact Assessment)
const {
  ChangeType,
  createCodeChange,
  createChangeSet,
  ChangeDetector,
  createChangeDetector
} = require('./change-detector')

// QA Orchestrator (TODO-driven exploration with full logging)
const {
  TaskPriority,
  TaskStatus,
  OrchestratorState,
  ActionType: OrchestratorActionType,
  createTask,
  createTaskStep,
  createActionRecord,
  createObservation,
  createDiscovery,
  createAIPromptLog,
  QAOrchestrator,
  createQAOrchestrator
} = require('./qa-orchestrator')

// Export everything
module.exports = {
  // ─────────────────────────────────────────────────────────────────
  // CONFIDENCE SCORING
  // ─────────────────────────────────────────────────────────────────
  ConfidenceLevel,
  ConfidenceScorer,
  FACTOR_WEIGHTS,
  scoreToLevel,
  shouldProceed,
  shouldClarify,
  quickConfidence,
  createDefaultFactors,

  // ─────────────────────────────────────────────────────────────────
  // DECISION ENGINE
  // ─────────────────────────────────────────────────────────────────
  ActionType,
  DecisionOutcome,
  DecisionEngine,
  createDecisionContext,
  createDecision,
  quickDecide,

  // ─────────────────────────────────────────────────────────────────
  // TEST PRIORITIZER
  // ─────────────────────────────────────────────────────────────────
  RiskFactor,
  Priority,
  RISK_WEIGHTS,
  SECURITY_KEYWORDS,
  DATA_LOSS_KEYWORDS,
  REVENUE_KEYWORDS,
  USER_FRICTION_KEYWORDS,
  COMPLIANCE_KEYWORDS,
  PAGE_TYPE_RISK,
  TestPrioritizer,
  createRiskAssessment,
  prioritizeTests,
  getCriticalTests,
  scoreKeywords,

  // ─────────────────────────────────────────────────────────────────
  // QA BRAIN (KNOWLEDGE BASE)
  // ─────────────────────────────────────────────────────────────────
  QA_BRAIN,
  createSection,
  getAllSections,
  getSection,
  searchByTag,
  searchByKeyword,
  getForPageType,
  getTestsFromSections,
  formatForPrompt,
  getEdgeCases,

  // ─────────────────────────────────────────────────────────────────
  // REASONER
  // ─────────────────────────────────────────────────────────────────
  ReasoningPhase,
  Reasoner,
  createRetrievedKnowledge,
  createReasoningResult,
  quickReason,
  PROMPTS,

  // ─────────────────────────────────────────────────────────────────
  // COVERAGE ANALYZER
  // ─────────────────────────────────────────────────────────────────
  GapSeverity,
  CoverageCategory,
  REQUIRED_RULES,
  CoverageAnalyzer,
  createGap,
  createCoverageReport,
  quickCoverageCheck,

  // ─────────────────────────────────────────────────────────────────
  // RISK INTELLIGENCE
  // ─────────────────────────────────────────────────────────────────
  RiskLevel,
  ImpactArea,
  IMPACT_WEIGHTS,
  RISK_PAGE_TYPE,
  CATEGORY_RISK,
  RiskIntelligence,
  HistoricalRisk,
  createRiskScore,
  quickRiskScore,

  // ─────────────────────────────────────────────────────────────────
  // CONVERSATIONAL MEMORY
  // ─────────────────────────────────────────────────────────────────
  MemoryType,
  ConversationalMemory,
  createMemory,
  createConversationTurn,
  createWorkingContext,

  // ─────────────────────────────────────────────────────────────────
  // VULNERABILITY SCANNER
  // ─────────────────────────────────────────────────────────────────
  VulnerabilityType,
  SeverityLevel,
  VULNERABILITY_MAP,
  VulnerabilityScanner,
  createVulnerability,
  createScanResult,
  quickScan,

  // ─────────────────────────────────────────────────────────────────
  // TEST GENERATOR
  // ─────────────────────────────────────────────────────────────────
  TestCategory,
  TestPriority,
  TestGenerator,
  TEST_TEMPLATES,
  createTestCase,
  createTestSuite,
  quickGenerate,

  // ─────────────────────────────────────────────────────────────────
  // QA CONSULTANT PERSONALITY
  // ─────────────────────────────────────────────────────────────────
  ConsultantMood,
  QuestionPriority,
  CLARIFYING_QUESTIONS,
  GREETINGS,
  THINKING_PHRASES,
  QAConsultantPersonality,
  createClarifyingQuestion,
  createThought,
  createRecommendation,

  // ─────────────────────────────────────────────────────────────────
  // ADAPTIVE LEARNER
  // ─────────────────────────────────────────────────────────────────
  InsightType,
  LearnerConfidenceLevel,
  LEARNER_CONFIG,
  AdaptiveLearner,
  createAdaptiveLearner,
  createInsight,
  createExecution,
  createPattern,
  categorizeError,

  // ─────────────────────────────────────────────────────────────────
  // ROOT CAUSE ANALYZER
  // ─────────────────────────────────────────────────────────────────
  FailureCategory,
  FailureSeverity,
  ERROR_PATTERNS,
  FIX_SUGGESTIONS,
  CATEGORY_DESCRIPTIONS,
  RootCauseAnalyzer,
  createRootCauseAnalyzer,
  createRootCause,
  createFailurePattern,
  createAnalysisResult,
  quickAnalyze,

  // ─────────────────────────────────────────────────────────────────
  // UNIFIED AGENT (THE BRAIN)
  // ─────────────────────────────────────────────────────────────────
  AgentState,
  AgentCapabilities,
  AGENT_CONFIG,
  UnifiedAgent,
  createUnifiedAgent,
  quickAgent,
  createGenerationResult,

  // ─────────────────────────────────────────────────────────────────
  // FAILURE PREDICTOR
  // ─────────────────────────────────────────────────────────────────
  PredictionType,
  PredictorRiskLevel,
  PREDICTOR_CONFIG,
  FailurePredictor,
  createFailurePredictor,
  createPrediction,
  createHistoricalData,
  createPredictionResult,
  quickPredict,

  // ─────────────────────────────────────────────────────────────────
  // FEATURE ANALYZER
  // ─────────────────────────────────────────────────────────────────
  UserIntent,
  INTENT_KEYWORDS,
  PAGE_TYPE_PATTERNS,
  FOCUS_SUGGESTIONS,
  FeatureAnalyzer,
  createFeatureContext,
  analyzeRequest,
  analyzePage,

  // ─────────────────────────────────────────────────────────────────
  // THINKER (THINKING ALOUD)
  // ─────────────────────────────────────────────────────────────────
  ThinkingPhase,
  THINKING_PATTERNS,
  PAGE_SPECIFIC_THOUGHTS,
  CONFIDENT_PREFIXES,
  UNCERTAIN_PREFIXES,
  PHASE_DELAYS,
  Thinker,
  createThinkerThought,
  think,
  thinkSequence,
  getThinkingPhrase,

  // ─────────────────────────────────────────────────────────────────
  // CLARIFIER (SMART QUESTIONS)
  // ─────────────────────────────────────────────────────────────────
  ClarifierQuestionPriority,
  Clarifier,
  createClarifierQuestion,
  createClarificationBundle,
  clarifyForPage,
  clarifyFeature,

  // ─────────────────────────────────────────────────────────────────
  // TONE & STYLE (HUMAN-LIKE RESPONSES)
  // ─────────────────────────────────────────────────────────────────
  Confidence,
  getConfidenceScore,
  CONFIDENCE_PHRASES,
  TRANSITIONS,
  TONE_GREETINGS,
  CELEBRATIONS,
  SOFTENERS,
  EMPATHY_PHRASES,
  IMPORTANCE_PHRASES,
  ResponseStyler,
  createStyledResponse,
  styledResponse,
  getPhrase,

  // ─────────────────────────────────────────────────────────────────
  // INSIGHT ENGINE (PATTERN DETECTION)
  // ─────────────────────────────────────────────────────────────────
  EngineInsightType,
  InsightPriority,
  InsightCategory,
  InsightEngine,
  createEngineInsight,
  createTestEvent,
  createTestMetric,
  createInsightEngine,

  // ─────────────────────────────────────────────────────────────────
  // TEST RECOMMENDER (AI RECOMMENDATIONS)
  // ─────────────────────────────────────────────────────────────────
  RecommendationType,
  RecommendationImpact,
  RecommendationEffort,
  TestRecommender,
  createTestRecommendation,
  createTestProfile,
  createSuiteProfile,
  createTestRecommender,

  // ─────────────────────────────────────────────────────────────────
  // FLAKINESS DETECTOR
  // ─────────────────────────────────────────────────────────────────
  FlakinessPattern,
  FlakinessLevel,
  FlakinessDetector,
  createTestExecution,
  createFlakinessReport,
  createFlakinessDetector,

  // ─────────────────────────────────────────────────────────────────
  // SELECTOR HEALER (SELF-HEALING TESTS)
  // ─────────────────────────────────────────────────────────────────
  SelectorType,
  HealingStrategy,
  STABILITY_RANKINGS,
  SelectorHealer,
  createSelectorCandidate,
  createHealingResult,
  createSelectorHealer,

  // ─────────────────────────────────────────────────────────────────
  // EDGE CASE DETECTOR
  // ─────────────────────────────────────────────────────────────────
  EdgeCaseCategory,
  UNIVERSAL_EDGE_CASES,
  PAGE_EDGE_CASES,
  INPUT_PATTERNS,
  EdgeCaseDetector,
  createEdgeCase,
  createEdgeCaseAnalysis,
  detectEdgeCases,
  getEdgeCaseTests,

  // ─────────────────────────────────────────────────────────────────
  // RETRY MANAGER (SMART RETRIES, ADAPTIVE LEARNING, QUARANTINE)
  // ─────────────────────────────────────────────────────────────────
  BackoffType,
  RetryDecision,
  QuarantineReason,
  QuarantineStatus,
  RetryStrategy,
  createRetryStrategy,
  createRetryConfig,
  createRetryAttempt,
  createRetryResult,
  AdaptiveRetryManager,
  createAdaptiveRetryManager,
  QuarantineManager,
  createQuarantineManager,

  // ─────────────────────────────────────────────────────────────────
  // TEST SCHEDULER (BROWSER/DEVICE MATRIX, RECURRING, PARALLEL)
  // ─────────────────────────────────────────────────────────────────
  ScheduleType,
  ScheduleStatus,
  RecurrencePattern,
  DEFAULT_BROWSERS,
  DEFAULT_DEVICES,
  createBrowserTarget,
  createDeviceTarget,
  createScheduleConfig,
  createScheduledRun,
  TestScheduler,
  createTestScheduler,

  // ─────────────────────────────────────────────────────────────────
  // CHANGE DETECTOR (GIT DIFF ANALYSIS, IMPACT ASSESSMENT)
  // ─────────────────────────────────────────────────────────────────
  ChangeType,
  createCodeChange,
  createChangeSet,
  ChangeDetector,
  createChangeDetector,

  // ─────────────────────────────────────────────────────────────────
  // QA ORCHESTRATOR (TODO-DRIVEN EXPLORATION WITH FULL LOGGING)
  // ─────────────────────────────────────────────────────────────────
  TaskPriority,
  TaskStatus,
  OrchestratorState,
  OrchestratorActionType,
  createTask,
  createTaskStep,
  createActionRecord,
  createObservation,
  createDiscovery,
  createAIPromptLog,
  QAOrchestrator,
  createQAOrchestrator
}
