/**
 * Yali Agent - Unified Agent (The Brain)
 * Ported from testai-agent/core/unified_agent.py
 *
 * The main agent class that orchestrates all components into a single
 * intelligent QA system. This is the "brain" that ties everything together.
 *
 * This agent:
 * 1. Understands what you want to test
 * 2. Retrieves relevant knowledge from the Brain
 * 3. Generates comprehensive test cases with citations
 * 4. Learns from execution results
 * 5. Identifies coverage gaps
 * 6. Prioritizes tests by risk
 * 7. Analyzes failures to find root causes
 * 8. Improves continuously
 *
 * It's designed to be smarter than a human QA engineer because it:
 * - Never forgets (persistent learning)
 * - Never gets tired (consistent quality)
 * - Has perfect recall (instant knowledge retrieval)
 * - Learns from every execution (continuous improvement)
 */

// Import all cortex components
const { ConfidenceScorer, ConfidenceLevel, quickConfidence, scoreToLevel, shouldProceed } = require('./confidence')
const { DecisionEngine, ActionType, DecisionOutcome, createDecisionContext, quickDecide } = require('./decision-engine')
const { TestPrioritizer, Priority, prioritizeTests, getCriticalTests } = require('./prioritizer')
const { getForPageType, formatForPrompt, getEdgeCases, getTestsFromSections, searchByKeyword, QA_BRAIN } = require('./qa-brain')
const { Reasoner, ReasoningPhase, quickReason, PROMPTS } = require('./reasoner')
const { CoverageAnalyzer, GapSeverity, createCoverageReport, quickCoverageCheck } = require('./coverage-analyzer')
const { RiskIntelligence, RiskLevel, createRiskScore, quickRiskScore } = require('./risk-intelligence')
const { ConversationalMemory, MemoryType, createMemory, createWorkingContext } = require('./memory')
const { VulnerabilityScanner, VulnerabilityType, quickScan } = require('./vulnerability-scanner')
const { TestGenerator, TestCategory, quickGenerate, TEST_TEMPLATES } = require('./test-generator')
const { QAConsultantPersonality, ConsultantMood, QuestionPriority } = require('./qa-consultant')
const { AdaptiveLearner, InsightType, createExecution } = require('./adaptive-learner')
const { RootCauseAnalyzer, FailureCategory, FailureSeverity, quickAnalyze } = require('./root-cause-analyzer')

/**
 * Agent states
 */
const AgentState = {
  IDLE: 'idle',
  UNDERSTANDING: 'understanding',
  RETRIEVING: 'retrieving',
  GENERATING: 'generating',
  ANALYZING: 'analyzing',
  EXECUTING: 'executing',
  LEARNING: 'learning',
  THINKING: 'thinking'
}

/**
 * Agent capabilities
 */
const AgentCapabilities = {
  CAN_GENERATE_TESTS: true,
  CAN_LEARN: true,
  CAN_ANALYZE_COVERAGE: true,
  CAN_PRIORITIZE: true,
  CAN_ANALYZE_SECURITY: true,
  CAN_ANALYZE_FAILURES: true,
  HAS_BRAIN: true,
  HAS_MEMORY: true
}

/**
 * Default agent configuration
 */
const DEFAULT_CONFIG = {
  enableLearning: true,
  autoApplyInsights: false,
  minConfidenceForAutoApply: 0.85,
  maxTestsPerRequest: 30,
  defaultStakeholder: 'engineering',
  storageDir: null,
  onStateChange: null,
  onThinking: null
}

/**
 * Create a generation result
 */
function createGenerationResult(feature, pageType, options = {}) {
  return {
    success: options.success !== false,
    feature,
    pageType,
    tests: options.tests || [],
    testCount: options.tests?.length || 0,
    coveragePercentage: options.coveragePercentage || 0,
    gapsIdentified: options.gapsIdentified || 0,
    criticalGaps: options.criticalGaps || 0,
    riskSummary: options.riskSummary || { critical: 0, high: 0, medium: 0, low: 0 },
    citations: options.citations || [],
    generationTimeMs: options.generationTimeMs || 0,
    recommendations: options.recommendations || [],
    summary: options.summary || '',
    shipDecision: options.shipDecision || 'unknown',
    confidence: options.confidence || 0.7,
    thinking: options.thinking || []
  }
}

/**
 * Unified Agent class - The main orchestrator
 */
class UnifiedAgent {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this._state = AgentState.IDLE
    this._thinkingLog = []

    // Initialize all components
    this._initComponents()

    // Session state
    this._currentFeature = null
    this._currentPageType = null
    this._currentTests = []

    // Statistics
    this._stats = {
      generations: 0,
      testsGenerated: 0,
      testsExecuted: 0,
      insightsLearned: 0,
      gapsIdentified: 0,
      failuresAnalyzed: 0,
      decisionssMade: 0
    }
  }

  /**
   * Initialize all agent components
   */
  _initComponents() {
    // Reasoning and confidence
    this._confidenceScorer = new ConfidenceScorer()
    this._decisionEngine = new DecisionEngine()
    this._reasoner = new Reasoner()

    // Test management
    this._prioritizer = new TestPrioritizer()
    this._testGenerator = new TestGenerator()

    // Analysis
    this._coverageAnalyzer = new CoverageAnalyzer()
    this._riskIntelligence = new RiskIntelligence()
    this._vulnerabilityScanner = new VulnerabilityScanner()
    this._rootCauseAnalyzer = new RootCauseAnalyzer()

    // Memory and learning
    this._memory = new ConversationalMemory()
    this._learner = new AdaptiveLearner()

    // Personality
    this._personality = new QAConsultantPersonality()
  }

  /**
   * Set agent state and notify callback
   */
  _setState(state) {
    this._state = state
    if (this.config.onStateChange) {
      this.config.onStateChange(state)
    }
  }

  /**
   * Log a thinking step
   */
  _think(thought) {
    this._thinkingLog.push({
      thought,
      state: this._state,
      timestamp: Date.now()
    })
    if (this.config.onThinking) {
      this.config.onThinking(thought)
    }
  }

  /**
   * Get current state
   */
  get state() {
    return this._state
  }

  /**
   * Get capabilities
   */
  get capabilities() {
    return {
      ...AgentCapabilities,
      canLearn: this.config.enableLearning
    }
  }

  /**
   * Process a user request - main entry point
   */
  async processRequest(request, context = {}) {
    this._thinkingLog = []
    const startTime = Date.now()

    // Add to memory
    this._memory.addUserTurn(request)

    // 1. Understand the request
    this._setState(AgentState.UNDERSTANDING)
    this._think(`Understanding request: "${request.slice(0, 50)}..."`)

    const intent = this._analyzeIntent(request)
    this._think(`Detected intent: ${intent.type} (confidence: ${(intent.confidence * 100).toFixed(0)}%)`)

    // 2. Make a decision
    this._setState(AgentState.THINKING)
    const decision = this._makeDecision(intent, context)
    this._stats.decisionssMade++
    this._think(`Decision: ${decision.action}`)

    // 3. Execute based on intent
    let result
    switch (intent.type) {
      case 'generate_tests':
        result = await this.generateTests(intent.feature, intent.pageType, context)
        break

      case 'analyze_security':
        result = await this.analyzeSecurityForContext(intent.feature, context)
        break

      case 'analyze_coverage':
        result = await this.analyzeCoverage(intent.pageType, context)
        break

      case 'find_edge_cases':
        result = await this.findEdgeCases(intent.feature, intent.pageType)
        break

      case 'explain':
        result = this._explainConcept(intent.topic)
        break

      case 'recommend':
        result = this._makeRecommendations(context)
        break

      default:
        result = this._handleGeneralRequest(request, context)
    }

    // Add response to memory
    const summary = this._summarizeResult(result)
    this._memory.addAssistantTurn(summary)

    result.processingTimeMs = Date.now() - startTime
    result.thinking = this._thinkingLog

    return result
  }

  /**
   * Analyze user intent from request
   */
  _analyzeIntent(request) {
    const lower = request.toLowerCase()

    // Check for test generation
    if (/generate|create|write|make/.test(lower) && /test|case|scenario/.test(lower)) {
      const pageType = this._detectPageType(lower)
      return {
        type: 'generate_tests',
        feature: request,
        pageType,
        confidence: 0.9
      }
    }

    // Check for security analysis
    if (/security|vulnerab|attack|owasp|xss|sql|inject/.test(lower)) {
      return {
        type: 'analyze_security',
        feature: request,
        confidence: 0.85
      }
    }

    // Check for coverage analysis
    if (/coverage|gap|missing|what.*test/.test(lower)) {
      const pageType = this._detectPageType(lower)
      return {
        type: 'analyze_coverage',
        pageType,
        confidence: 0.85
      }
    }

    // Check for edge cases
    if (/edge|boundary|corner|extreme|limit/.test(lower)) {
      const pageType = this._detectPageType(lower)
      return {
        type: 'find_edge_cases',
        feature: request,
        pageType,
        confidence: 0.8
      }
    }

    // Check for explanations
    if (/what is|explain|how does|why/.test(lower)) {
      return {
        type: 'explain',
        topic: request,
        confidence: 0.75
      }
    }

    // Check for recommendations
    if (/recommend|suggest|advise|should|best/.test(lower)) {
      return {
        type: 'recommend',
        confidence: 0.75
      }
    }

    // Default to general
    return {
      type: 'general',
      confidence: 0.5
    }
  }

  /**
   * Detect page type from text
   */
  _detectPageType(text) {
    if (/login|sign.?in|auth/.test(text)) return 'login'
    if (/sign.?up|register|create.*account/.test(text)) return 'signup'
    if (/checkout|payment|cart|purchase/.test(text)) return 'checkout'
    if (/search|find|filter/.test(text)) return 'search'
    if (/form|input|submit/.test(text)) return 'form'
    if (/profile|account|settings/.test(text)) return 'profile'
    if (/dashboard|admin|manage/.test(text)) return 'dashboard'
    return 'general'
  }

  /**
   * Make a decision based on intent and context
   */
  _makeDecision(intent, context) {
    const decisionContext = createDecisionContext({
      pageType: intent.pageType || context.pageType || 'general',
      hasElements: context.elements?.length > 0,
      confidence: intent.confidence,
      history: this._memory.getRecentTurns(5).map(t => t.content)
    })

    return quickDecide(decisionContext)
  }

  /**
   * Generate tests for a feature
   */
  async generateTests(feature, pageType = null, context = {}) {
    const startTime = Date.now()
    this._stats.generations++

    // 1. Understand the feature
    this._setState(AgentState.UNDERSTANDING)
    this._think(`Analyzing feature: ${feature}`)

    const detectedPageType = pageType || this._detectPageType(feature)
    this._memory.setWorkingContext({
      feature,
      pageType: detectedPageType
    })

    this._think(`Detected page type: ${detectedPageType}`)

    // 2. Retrieve knowledge
    this._setState(AgentState.RETRIEVING)
    this._think('Retrieving testing rules from knowledge base...')

    const knowledgeSections = getForPageType(detectedPageType)
    const citations = knowledgeSections.map(s => s.id || s.title)
    this._think(`Found ${knowledgeSections.length} relevant knowledge sections`)

    // 3. Generate tests
    this._setState(AgentState.GENERATING)
    this._think('Generating test cases...')

    const generated = this._testGenerator.generateForPageType(
      detectedPageType,
      context.elements || []
    )

    // Also get template-based tests
    const templateTests = TEST_TEMPLATES[detectedPageType] || []

    // Combine and deduplicate
    const allTests = [...generated.tests, ...templateTests]
    const uniqueTests = this._deduplicateTests(allTests)

    this._stats.testsGenerated += uniqueTests.length

    // 4. Prioritize by risk
    this._think('Prioritizing tests by risk...')
    const prioritizedTests = prioritizeTests(uniqueTests, detectedPageType)

    // 5. Analyze coverage
    this._setState(AgentState.ANALYZING)
    this._think('Analyzing test coverage...')

    const coverageReport = this._coverageAnalyzer.analyzeCoverage(detectedPageType, prioritizedTests)
    this._stats.gapsIdentified += coverageReport.gaps.length

    // 6. Generate recommendations
    const recommendations = []

    if (coverageReport.criticalGaps > 0) {
      recommendations.push(`⚠️ ${coverageReport.criticalGaps} critical coverage gaps - review required before release`)
    }
    if (coverageReport.highGaps > 0) {
      recommendations.push(`Consider adding ${coverageReport.highGaps} high-priority tests`)
    }

    // Risk-based recommendations
    const riskRecs = this._riskIntelligence.getRecommendations(detectedPageType)
    recommendations.push(...riskRecs.slice(0, 3))

    // Learning-based recommendations
    if (this.config.enableLearning) {
      const learnerRecs = this._learner.getRecommendations(feature)
      recommendations.push(...learnerRecs.slice(0, 2))
    }

    // Calculate confidence
    const confidence = this._confidenceScorer.scoreGeneration(
      feature,
      context.hasPage !== false,
      knowledgeSections.length,
      []
    )

    // Count risk levels
    const riskSummary = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const test of prioritizedTests) {
      const level = test.priority?.toLowerCase() || test._riskLevel || 'medium'
      if (riskSummary[level] !== undefined) {
        riskSummary[level]++
      }
    }

    // Store current state
    this._currentFeature = feature
    this._currentPageType = detectedPageType
    this._currentTests = prioritizedTests

    // Return to idle
    this._setState(AgentState.IDLE)

    // Generate ship decision
    let shipDecision = 'ready'
    if (coverageReport.criticalGaps > 0) {
      shipDecision = 'block'
    } else if (coverageReport.highGaps > 2) {
      shipDecision = 'caution'
    }

    return createGenerationResult(feature, detectedPageType, {
      tests: prioritizedTests.slice(0, this.config.maxTestsPerRequest),
      coveragePercentage: coverageReport.coveragePercentage,
      gapsIdentified: coverageReport.gaps.length,
      criticalGaps: coverageReport.criticalGaps,
      riskSummary,
      citations,
      generationTimeMs: Date.now() - startTime,
      recommendations,
      summary: `Generated ${prioritizedTests.length} tests with ${coverageReport.coveragePercentage.toFixed(0)}% coverage`,
      shipDecision,
      confidence: confidence.score
    })
  }

  /**
   * Deduplicate tests by title
   */
  _deduplicateTests(tests) {
    const seen = new Set()
    return tests.filter(test => {
      const key = (test.title || test.name || '').toLowerCase()
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  /**
   * Analyze security for given context
   */
  async analyzeSecurityForContext(feature, context = {}) {
    this._setState(AgentState.ANALYZING)
    this._think('Analyzing security concerns...')

    const pageType = context.pageType || this._detectPageType(feature)
    const elements = context.elements || []

    // Use vulnerability scanner
    const scanResult = this._vulnerabilityScanner.scanPageType(pageType)

    // Get security-specific edge cases
    const securityEdgeCases = {
      email: getEdgeCases('email'),
      password: getEdgeCases('password'),
      text: getEdgeCases('text')
    }

    // Prioritize vulnerabilities by severity
    const vulnerabilities = scanResult.vulnerabilities
      .sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 }
        return (order[a.severity] || 4) - (order[b.severity] || 4)
      })

    this._setState(AgentState.IDLE)

    return {
      success: true,
      pageType,
      vulnerabilities,
      riskScore: scanResult.riskScore,
      securityEdgeCases,
      recommendations: scanResult.recommendations,
      thinking: this._thinkingLog
    }
  }

  /**
   * Analyze coverage gaps
   */
  async analyzeCoverage(pageType, context = {}) {
    this._setState(AgentState.ANALYZING)
    this._think('Analyzing test coverage gaps...')

    const tests = context.tests || this._currentTests || []
    const detectedPageType = pageType || this._currentPageType || 'general'

    const report = this._coverageAnalyzer.analyzeCoverage(detectedPageType, tests)

    this._setState(AgentState.IDLE)

    return {
      success: true,
      pageType: detectedPageType,
      coveragePercentage: report.coveragePercentage,
      gaps: report.gaps,
      criticalGaps: report.criticalGaps,
      highGaps: report.highGaps,
      hasCriticalGaps: report.hasCriticalGaps,
      recommendations: report.recommendations,
      thinking: this._thinkingLog
    }
  }

  /**
   * Find edge cases for a feature
   */
  async findEdgeCases(feature, pageType = null) {
    this._setState(AgentState.RETRIEVING)
    this._think('Finding edge cases from knowledge base...')

    const detectedPageType = pageType || this._detectPageType(feature)

    // Get edge cases from brain
    const edgeCases = {
      email: getEdgeCases('email'),
      password: getEdgeCases('password'),
      text: getEdgeCases('text'),
      number: getEdgeCases('number'),
      date: getEdgeCases('date'),
      url: getEdgeCases('url'),
      phone: getEdgeCases('phone')
    }

    // Get page-specific knowledge
    const pageKnowledge = getForPageType(detectedPageType)
    const pageEdgeCases = pageKnowledge
      .filter(s => s.tags?.includes('edge_cases') || s.category === 'edge_cases')
      .flatMap(s => s.tests || s.edgeCases || [])

    this._setState(AgentState.IDLE)

    return {
      success: true,
      feature,
      pageType: detectedPageType,
      fieldEdgeCases: edgeCases,
      pageSpecificEdgeCases: pageEdgeCases,
      thinking: this._thinkingLog
    }
  }

  /**
   * Explain a QA concept
   */
  _explainConcept(topic) {
    // Search knowledge base for relevant info
    const results = searchByKeyword(topic)

    if (results.length === 0) {
      return {
        success: false,
        message: `I don't have specific information about "${topic}" in my knowledge base. Would you like me to explain something else?`
      }
    }

    const explanation = formatForPrompt(results.slice(0, 3))

    return {
      success: true,
      topic,
      explanation,
      sources: results.map(r => r.title || r.id),
      thinking: this._thinkingLog
    }
  }

  /**
   * Make recommendations based on context
   */
  _makeRecommendations(context = {}) {
    const pageType = context.pageType || this._currentPageType || 'general'
    const recommendations = []

    // Get personality-based recommendations
    const personality = this._personality.makeRecommendations(
      pageType,
      this._coverageAnalyzer.getLastReport(),
      { riskScore: this._riskIntelligence.getQuickScore(pageType) }
    )
    recommendations.push(...personality)

    // Get risk-based recommendations
    const riskRecs = this._riskIntelligence.getRecommendations(pageType)
    recommendations.push(...riskRecs)

    // Get learner insights
    if (this.config.enableLearning) {
      const insights = this._learner.getInsights()
      for (const insight of insights.slice(0, 3)) {
        recommendations.push({
          title: insight.title,
          description: insight.description,
          priority: insight.confidence > 0.8 ? QuestionPriority.CRITICAL : QuestionPriority.IMPORTANT,
          actionItems: insight.recommendations
        })
      }
    }

    return {
      success: true,
      pageType,
      recommendations,
      thinking: this._thinkingLog
    }
  }

  /**
   * Handle general requests
   */
  _handleGeneralRequest(request, context) {
    // Use personality to respond
    const greeting = this._personality.greet(context.isReturning ? 'returning' : 'new_session')

    return {
      success: true,
      response: greeting,
      clarifyingQuestions: this._personality.getClarifyingQuestions(
        context.pageType || this._currentPageType || 'general',
        3
      ),
      thinking: this._thinkingLog
    }
  }

  /**
   * Summarize a result for memory
   */
  _summarizeResult(result) {
    if (result.tests) {
      return `Generated ${result.testCount || result.tests.length} tests for ${result.pageType}`
    }
    if (result.vulnerabilities) {
      return `Found ${result.vulnerabilities.length} security concerns`
    }
    if (result.gaps) {
      return `Analyzed coverage: ${result.coveragePercentage?.toFixed(0) || 0}% with ${result.gaps.length} gaps`
    }
    if (result.explanation) {
      return `Explained: ${result.topic}`
    }
    return 'Processed request'
  }

  /**
   * Record a test execution result for learning
   */
  recordTestResult(testId, passed, options = {}) {
    if (!this.config.enableLearning) return

    this._stats.testsExecuted++

    // Record in learner
    const execution = createExecution(
      testId,
      options.testName || testId,
      passed ? 'passed' : 'failed',
      options.executionTimeMs || 0,
      {
        browser: options.browser || '',
        environment: options.environment || '',
        errorMessage: options.errorMessage || null
      }
    )
    this._learner.recordExecution(execution)

    // Record in risk intelligence
    this._riskIntelligence.recordTestResult(testId, passed, options.executionTimeMs || 0)

    // Analyze failure if failed
    if (!passed && options.errorMessage) {
      this._setState(AgentState.LEARNING)
      this._think('Analyzing test failure...')

      const analysis = this._rootCauseAnalyzer.analyze(
        testId,
        options.errorMessage,
        options.stackTrace || null
      )

      this._stats.failuresAnalyzed++

      // Store insight in memory
      if (analysis.rootCauses.length > 0) {
        const cause = analysis.rootCauses[0]
        this._memory.remember(
          MemoryType.INSIGHT,
          `Failure in ${testId}: ${cause.category} - ${cause.description.slice(0, 100)}`,
          { importance: 0.8 }
        )
        this._stats.insightsLearned++
      }

      this._setState(AgentState.IDLE)
      return analysis
    }

    return null
  }

  /**
   * Analyze a failure
   */
  analyzeFailure(testId, errorMessage, stackTrace = null) {
    return this._rootCauseAnalyzer.analyze(testId, errorMessage, stackTrace)
  }

  /**
   * Get learning insights
   */
  getLearningInsights() {
    if (!this.config.enableLearning) return []

    // Analyze patterns first
    this._learner.analyze()

    const insights = this._learner.getInsights()
    this._stats.insightsLearned = insights.length

    return insights.map(i => ({
      title: i.title,
      description: i.description,
      confidence: i.confidenceScore,
      recommendations: i.recommendations,
      affectedTests: i.affectedTests
    }))
  }

  /**
   * Get agent statistics
   */
  getStats() {
    const stats = { ...this._stats }

    if (this.config.enableLearning) {
      stats.learning = this._learner.getStatistics()
      stats.risk = this._riskIntelligence.getStats()
    }

    stats.memory = this._memory.getStats()

    return stats
  }

  /**
   * Get thinking phrase for current activity
   */
  getThinkingPhrase(phase = 'analyzing') {
    return this._personality.getThinkingPhrase(phase)
  }

  /**
   * Get greeting
   */
  greet(context = 'new_session') {
    return this._personality.greet(context)
  }

  /**
   * Save session for later resumption
   */
  saveSession() {
    return {
      memory: this._memory.exportSession(),
      learner: this._learner.exportState(),
      currentFeature: this._currentFeature,
      currentPageType: this._currentPageType,
      currentTests: this._currentTests,
      stats: this._stats,
      savedAt: new Date().toISOString()
    }
  }

  /**
   * Load a previous session
   */
  loadSession(data) {
    if (data.memory) {
      this._memory.importSession(data.memory)
    }
    if (data.learner) {
      this._learner.importState(data.learner)
    }
    if (data.currentFeature) {
      this._currentFeature = data.currentFeature
    }
    if (data.currentPageType) {
      this._currentPageType = data.currentPageType
    }
    if (data.currentTests) {
      this._currentTests = data.currentTests
    }
    if (data.stats) {
      this._stats = { ...this._stats, ...data.stats }
    }
    return true
  }

  /**
   * Clear all state
   */
  clear() {
    this._memory.clear()
    this._learner.clear()
    this._rootCauseAnalyzer.clear()
    this._currentFeature = null
    this._currentPageType = null
    this._currentTests = []
    this._thinkingLog = []
    this._setState(AgentState.IDLE)
  }
}

/**
 * Create a unified agent instance
 */
function createUnifiedAgent(config = {}) {
  return new UnifiedAgent(config)
}

/**
 * Quick agent for simple operations
 */
function quickAgent() {
  return new UnifiedAgent({
    enableLearning: false
  })
}

module.exports = {
  AgentState,
  AgentCapabilities,
  DEFAULT_CONFIG,
  UnifiedAgent,
  createUnifiedAgent,
  quickAgent,
  createGenerationResult
}
