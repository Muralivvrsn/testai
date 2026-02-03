/**
 * Yali Agent - Adaptive Learner
 * Ported from testai-agent/adaptive/learner.py
 *
 * Learns from test execution history to improve
 * test quality and prediction accuracy.
 * Like a human QA who remembers past failures and improves.
 */

/**
 * Types of learning insights
 */
const InsightType = {
  FLAKINESS_PATTERN: 'flakiness_pattern',
  TIMING_ANOMALY: 'timing_anomaly',
  FAILURE_CORRELATION: 'failure_correlation',
  SELECTOR_STABILITY: 'selector_stability',
  ENVIRONMENT_IMPACT: 'environment_impact',
  COVERAGE_GAP: 'coverage_gap',
  OPTIMIZATION_OPPORTUNITY: 'optimization_opportunity'
}

/**
 * Confidence levels for insights
 */
const ConfidenceLevel = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNCERTAIN: 'uncertain'
}

/**
 * Default learning configuration
 */
const DEFAULT_CONFIG = {
  minSamples: 10,
  flakinessThreshold: 0.1,
  timingVarianceThreshold: 0.3,
  correlationThreshold: 0.7,
  learningRate: 0.1,
  decayFactor: 0.95,
  lookbackDays: 30
}

/**
 * Create a learning insight
 */
function createInsight(type, title, description, options = {}) {
  return {
    insightId: `insight_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    insightType: type,
    title,
    description,
    confidence: options.confidence || ConfidenceLevel.MEDIUM,
    confidenceScore: options.confidenceScore || 0.7,
    affectedTests: options.affectedTests || [],
    recommendations: options.recommendations || [],
    data: options.data || {},
    createdAt: Date.now()
  }
}

/**
 * Create a test execution record
 */
function createExecution(testId, testName, status, durationMs, options = {}) {
  return {
    testId,
    testName,
    status, // passed, failed, skipped
    durationMs,
    timestamp: Date.now(),
    browser: options.browser || '',
    environment: options.environment || '',
    errorMessage: options.errorMessage || null,
    selectorsUsed: options.selectorsUsed || [],
    tags: options.tags || []
  }
}

/**
 * Create a test pattern (learned behavior)
 */
function createPattern(testId, executions) {
  const total = executions.length
  const passed = executions.filter(e => e.status === 'passed').length
  const failed = executions.filter(e => e.status === 'failed').length

  const durations = executions.map(e => e.durationMs)
  const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length

  // Calculate variance
  let durationVariance = 0
  if (durations.length > 1) {
    const variance = durations.reduce((sum, d) => sum + Math.pow(d - avgDuration, 2), 0) / durations.length
    const stdDev = Math.sqrt(variance)
    durationVariance = avgDuration > 0 ? stdDev / avgDuration : 0
  }

  // Calculate flakiness (ratio of status changes)
  let flakiness = 0
  if (total > 1) {
    let changes = 0
    for (let i = 1; i < executions.length; i++) {
      if (executions[i].status !== executions[i - 1].status) {
        changes++
      }
    }
    flakiness = changes / (total - 1)
  }

  // Find last failure
  let lastFailure = null
  for (let i = executions.length - 1; i >= 0; i--) {
    if (executions[i].status === 'failed') {
      lastFailure = executions[i].timestamp
      break
    }
  }

  // Count failure patterns
  const failurePatterns = {}
  for (const exec of executions) {
    if (exec.status === 'failed' && exec.errorMessage) {
      const errorType = categorizeError(exec.errorMessage)
      failurePatterns[errorType] = (failurePatterns[errorType] || 0) + 1
    }
  }

  // Track environment results
  const environmentResults = {}
  for (const exec of executions) {
    const env = exec.environment || 'default'
    if (!environmentResults[env]) {
      environmentResults[env] = { passed: 0, failed: 0 }
    }
    if (exec.status === 'passed') {
      environmentResults[env].passed++
    } else if (exec.status === 'failed') {
      environmentResults[env].failed++
    }
  }

  return {
    testId,
    totalExecutions: total,
    passCount: passed,
    failCount: failed,
    avgDurationMs: avgDuration,
    durationVariance,
    flakinessScore: flakiness,
    lastFailure,
    failurePatterns,
    environmentResults
  }
}

/**
 * Categorize an error message
 */
function categorizeError(errorMessage) {
  const msg = errorMessage.toLowerCase()

  if (msg.includes('timeout')) return 'timeout'
  if (msg.includes('element') && msg.includes('not found')) return 'element_not_found'
  if (msg.includes('stale')) return 'stale_element'
  if (msg.includes('assertion')) return 'assertion'
  if (msg.includes('network') || msg.includes('connection')) return 'network'
  if (msg.includes('permission') || msg.includes('auth')) return 'permission'

  return 'other'
}

/**
 * Adaptive Learner class
 * Learns from test execution history and provides insights
 */
class AdaptiveLearner {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.executions = new Map() // testId -> [executions]
    this.patterns = new Map() // testId -> pattern
    this.insights = []
    this.correlations = new Map() // "testA|testB" -> correlation
  }

  /**
   * Record a test execution
   */
  recordExecution(execution) {
    const testId = execution.testId

    if (!this.executions.has(testId)) {
      this.executions.set(testId, [])
    }

    this.executions.get(testId).push(execution)
    this._updatePattern(testId)
  }

  /**
   * Record multiple executions
   */
  recordBatch(executionList) {
    for (const exec of executionList) {
      this.recordExecution(exec)
    }
  }

  /**
   * Update pattern for a test
   */
  _updatePattern(testId) {
    const execs = this.executions.get(testId) || []
    if (execs.length === 0) return

    const pattern = createPattern(testId, execs)
    this.patterns.set(testId, pattern)
  }

  /**
   * Analyze patterns and generate insights
   */
  analyze() {
    const insights = []

    // Detect flaky tests
    insights.push(...this._detectFlakyTests())

    // Detect timing anomalies
    insights.push(...this._detectTimingAnomalies())

    // Detect failure correlations
    insights.push(...this._detectFailureCorrelations())

    // Detect environment-specific issues
    insights.push(...this._detectEnvironmentIssues())

    this.insights.push(...insights)
    return insights
  }

  /**
   * Detect flaky tests
   */
  _detectFlakyTests() {
    const insights = []

    for (const [testId, pattern] of this.patterns) {
      if (pattern.totalExecutions < this.config.minSamples) continue

      if (pattern.flakinessScore > this.config.flakinessThreshold) {
        // Determine confidence
        let confidence = ConfidenceLevel.LOW
        let confidenceScore = 0.5

        if (pattern.flakinessScore > 0.3) {
          confidence = ConfidenceLevel.HIGH
          confidenceScore = 0.9
        } else if (pattern.flakinessScore > 0.2) {
          confidence = ConfidenceLevel.MEDIUM
          confidenceScore = 0.7
        }

        // Generate recommendations
        const recommendations = [
          'Add explicit waits for dynamic elements',
          'Review test isolation - ensure no shared state',
          'Check for race conditions in async operations'
        ]

        if (pattern.failurePatterns) {
          const topError = Object.keys(pattern.failurePatterns).reduce((a, b) =>
            pattern.failurePatterns[a] > pattern.failurePatterns[b] ? a : b
          , null)

          if (topError === 'timeout') {
            recommendations.unshift('Increase timeout or optimize page load')
          } else if (topError === 'stale_element') {
            recommendations.unshift('Re-fetch element references after page changes')
          }
        }

        insights.push(createInsight(
          InsightType.FLAKINESS_PATTERN,
          `Flaky Test Detected: ${testId}`,
          `Test shows ${(pattern.flakinessScore * 100).toFixed(1)}% flakiness rate over ${pattern.totalExecutions} executions`,
          {
            confidence,
            confidenceScore,
            affectedTests: [testId],
            recommendations,
            data: {
              flakinessScore: pattern.flakinessScore,
              totalExecutions: pattern.totalExecutions,
              failurePatterns: pattern.failurePatterns
            }
          }
        ))
      }
    }

    return insights
  }

  /**
   * Detect timing anomalies
   */
  _detectTimingAnomalies() {
    const insights = []

    for (const [testId, pattern] of this.patterns) {
      if (pattern.totalExecutions < this.config.minSamples) continue

      if (pattern.durationVariance > this.config.timingVarianceThreshold) {
        insights.push(createInsight(
          InsightType.TIMING_ANOMALY,
          `Timing Variance: ${testId}`,
          `Test duration varies by ${(pattern.durationVariance * 100).toFixed(1)}% (avg: ${Math.round(pattern.avgDurationMs)}ms)`,
          {
            confidence: ConfidenceLevel.MEDIUM,
            confidenceScore: 0.7,
            affectedTests: [testId],
            recommendations: [
              'Investigate network dependencies',
              'Check for resource contention',
              'Consider mocking external services'
            ],
            data: {
              avgDurationMs: pattern.avgDurationMs,
              variance: pattern.durationVariance
            }
          }
        ))
      }
    }

    return insights
  }

  /**
   * Detect tests that fail together
   */
  _detectFailureCorrelations() {
    const insights = []
    const testIds = Array.from(this.executions.keys())

    // Build correlation matrix
    for (let i = 0; i < testIds.length; i++) {
      for (let j = i + 1; j < testIds.length; j++) {
        const testA = testIds[i]
        const testB = testIds[j]
        const correlation = this._calculateCorrelation(testA, testB)

        if (correlation > this.config.correlationThreshold) {
          this.correlations.set(`${testA}|${testB}`, correlation)
        }
      }
    }

    // Group correlated tests
    const groups = this._findCorrelationGroups()

    for (const group of groups) {
      if (group.size >= 2) {
        insights.push(createInsight(
          InsightType.FAILURE_CORRELATION,
          `Correlated Failures (${group.size} tests)`,
          'These tests tend to fail together, suggesting a common dependency or shared state',
          {
            confidence: ConfidenceLevel.HIGH,
            confidenceScore: 0.85,
            affectedTests: Array.from(group),
            recommendations: [
              'Identify shared dependencies',
              'Check for common setup/teardown issues',
              'Consider running these tests in isolation'
            ],
            data: { groupSize: group.size }
          }
        ))
      }
    }

    return insights
  }

  /**
   * Calculate failure correlation between two tests
   */
  _calculateCorrelation(testA, testB) {
    const execsA = this.executions.get(testA) || []
    const execsB = this.executions.get(testB) || []

    if (!execsA.length || !execsB.length) return 0

    // Match executions by timestamp (within 1 hour)
    const matches = []
    for (const ea of execsA) {
      for (const eb of execsB) {
        if (Math.abs(ea.timestamp - eb.timestamp) < 3600000) {
          matches.push([
            ea.status === 'failed' ? 1 : 0,
            eb.status === 'failed' ? 1 : 0
          ])
        }
      }
    }

    if (matches.length < 5) return 0

    const bothFailed = matches.filter(([a, b]) => a === 1 && b === 1).length
    const eitherFailed = matches.filter(([a, b]) => a === 1 || b === 1).length

    if (eitherFailed === 0) return 0

    return bothFailed / eitherFailed
  }

  /**
   * Find groups of correlated tests
   */
  _findCorrelationGroups() {
    const groups = []

    for (const [key, corr] of this.correlations) {
      if (corr < this.config.correlationThreshold) continue

      const [testA, testB] = key.split('|')

      // Find existing group
      let foundGroup = null
      for (const group of groups) {
        if (group.has(testA) || group.has(testB)) {
          foundGroup = group
          break
        }
      }

      if (foundGroup) {
        foundGroup.add(testA)
        foundGroup.add(testB)
      } else {
        groups.push(new Set([testA, testB]))
      }
    }

    return groups
  }

  /**
   * Detect environment-specific issues
   */
  _detectEnvironmentIssues() {
    const insights = []

    for (const [testId, pattern] of this.patterns) {
      const envResults = pattern.environmentResults
      if (Object.keys(envResults).length < 2) continue

      // Calculate pass rates per environment
      const passRates = {}
      for (const [env, results] of Object.entries(envResults)) {
        const total = results.passed + results.failed
        if (total > 0) {
          passRates[env] = results.passed / total
        }
      }

      if (Object.keys(passRates).length < 2) continue

      const rates = Object.values(passRates)
      const maxRate = Math.max(...rates)
      const minRate = Math.min(...rates)

      // Check for significant differences
      if (maxRate - minRate > 0.3) {
        const worstEnv = Object.keys(passRates).reduce((a, b) =>
          passRates[a] < passRates[b] ? a : b
        )
        const bestEnv = Object.keys(passRates).reduce((a, b) =>
          passRates[a] > passRates[b] ? a : b
        )

        insights.push(createInsight(
          InsightType.ENVIRONMENT_IMPACT,
          `Environment Impact: ${testId}`,
          `Test performs differently across environments: ${bestEnv} (${(passRates[bestEnv] * 100).toFixed(0)}%) vs ${worstEnv} (${(passRates[worstEnv] * 100).toFixed(0)}%)`,
          {
            confidence: ConfidenceLevel.HIGH,
            confidenceScore: 0.8,
            affectedTests: [testId],
            recommendations: [
              `Investigate ${worstEnv} environment configuration`,
              'Check for environment-specific dependencies',
              'Ensure consistent test data across environments'
            ],
            data: { passRatesByEnvironment: passRates }
          }
        ))
      }
    }

    return insights
  }

  /**
   * Get pattern for a test
   */
  getPattern(testId) {
    return this.patterns.get(testId)
  }

  /**
   * Get insights, optionally filtered
   */
  getInsights(type = null) {
    if (type) {
      return this.insights.filter(i => i.insightType === type)
    }
    return [...this.insights]
  }

  /**
   * Get recommendations for a specific test
   */
  getRecommendations(testId) {
    const recommendations = []

    for (const insight of this.insights) {
      if (insight.affectedTests.includes(testId)) {
        recommendations.push(...insight.recommendations)
      }
    }

    return [...new Set(recommendations)]
  }

  /**
   * Predict flakiness probability for a test
   */
  predictFlakiness(testId) {
    const pattern = this.patterns.get(testId)
    if (!pattern) return 0

    let score = pattern.flakinessScore

    // Adjust based on recent failures
    if (pattern.lastFailure) {
      const daysSince = (Date.now() - pattern.lastFailure) / (1000 * 60 * 60 * 24)
      if (daysSince < 7) {
        score *= 1.2 // Recent failures increase prediction
      }
    }

    return Math.min(score, 1.0)
  }

  /**
   * Get learning statistics
   */
  getStatistics() {
    let totalTests = this.patterns.size
    let flakyTests = 0

    for (const pattern of this.patterns.values()) {
      if (pattern.flakinessScore > this.config.flakinessThreshold) {
        flakyTests++
      }
    }

    const insightsByType = {}
    for (const type of Object.values(InsightType)) {
      insightsByType[type] = this.insights.filter(i => i.insightType === type).length
    }

    return {
      totalTestsTracked: totalTests,
      totalExecutions: Array.from(this.patterns.values())
        .reduce((sum, p) => sum + p.totalExecutions, 0),
      flakyTests,
      totalInsights: this.insights.length,
      insightsByType,
      correlationsFound: this.correlations.size
    }
  }

  /**
   * Format insights as readable text
   */
  formatInsights() {
    const lines = [
      '═'.repeat(60),
      '  ADAPTIVE LEARNING INSIGHTS',
      '═'.repeat(60),
      ''
    ]

    const stats = this.getStatistics()
    lines.push(
      `  Tests Tracked: ${stats.totalTestsTracked}`,
      `  Total Executions: ${stats.totalExecutions}`,
      `  Flaky Tests: ${stats.flakyTests}`,
      `  Insights Generated: ${stats.totalInsights}`,
      ''
    )

    if (this.insights.length > 0) {
      lines.push('─'.repeat(60), '  INSIGHTS', '─'.repeat(60))

      for (const insight of this.insights.slice(0, 10)) {
        const icon = {
          [InsightType.FLAKINESS_PATTERN]: '⚠️',
          [InsightType.TIMING_ANOMALY]: '⏱️',
          [InsightType.FAILURE_CORRELATION]: '🔗',
          [InsightType.ENVIRONMENT_IMPACT]: '🌍'
        }[insight.insightType] || '💡'

        const confidenceIcon = {
          [ConfidenceLevel.HIGH]: '🟢',
          [ConfidenceLevel.MEDIUM]: '🟡',
          [ConfidenceLevel.LOW]: '🟠'
        }[insight.confidence] || '⚪'

        lines.push(
          '',
          `  ${icon} ${insight.title}`,
          `     ${confidenceIcon} Confidence: ${insight.confidence}`,
          `     ${insight.description}`
        )

        if (insight.recommendations.length > 0) {
          lines.push('     Recommendations:')
          for (const rec of insight.recommendations.slice(0, 2)) {
            lines.push(`       • ${rec}`)
          }
        }
      }
    }

    lines.push('', '═'.repeat(60))
    return lines.join('\n')
  }

  /**
   * Export state for persistence
   */
  exportState() {
    return {
      executions: Object.fromEntries(this.executions),
      patterns: Object.fromEntries(this.patterns),
      insights: this.insights,
      correlations: Object.fromEntries(this.correlations),
      exportedAt: new Date().toISOString()
    }
  }

  /**
   * Import state from persistence
   */
  importState(data) {
    if (data.executions) {
      this.executions = new Map(Object.entries(data.executions))
    }
    if (data.patterns) {
      this.patterns = new Map(Object.entries(data.patterns))
    }
    if (data.insights) {
      this.insights = data.insights
    }
    if (data.correlations) {
      this.correlations = new Map(Object.entries(data.correlations))
    }
  }

  /**
   * Clear all learned data
   */
  clear() {
    this.executions.clear()
    this.patterns.clear()
    this.insights = []
    this.correlations.clear()
  }
}

/**
 * Create an adaptive learner instance
 */
function createAdaptiveLearner(config = {}) {
  return new AdaptiveLearner(config)
}

module.exports = {
  InsightType,
  ConfidenceLevel,
  DEFAULT_CONFIG,
  AdaptiveLearner,
  createAdaptiveLearner,
  createInsight,
  createExecution,
  createPattern,
  categorizeError
}
