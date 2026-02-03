/**
 * Yali Agent - Insight Engine
 * Ported from testai-agent/intelligence/insights.py
 *
 * Generates intelligent insights from test data, identifying
 * patterns, anomalies, and opportunities for improvement.
 */

/**
 * Types of insights
 */
const InsightType = {
  PATTERN: 'pattern',
  ANOMALY: 'anomaly',
  TREND: 'trend',
  OPPORTUNITY: 'opportunity',
  WARNING: 'warning',
  ACHIEVEMENT: 'achievement'
}

/**
 * Insight priority levels
 */
const InsightPriority = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
}

/**
 * Insight categories
 */
const InsightCategory = {
  PERFORMANCE: 'performance',
  RELIABILITY: 'reliability',
  COVERAGE: 'coverage',
  MAINTENANCE: 'maintenance',
  EFFICIENCY: 'efficiency',
  QUALITY: 'quality'
}

/**
 * Create a test insight
 */
function createInsight(options) {
  return {
    insightId: options.insightId || `INS-${Date.now()}`,
    insightType: options.insightType,
    priority: options.priority,
    category: options.category,
    title: options.title,
    description: options.description,
    affectedTests: options.affectedTests || [],
    evidence: options.evidence || {},
    suggestions: options.suggestions || [],
    createdAt: options.createdAt || new Date(),
    expiresAt: options.expiresAt || null,
    metadata: options.metadata || {}
  }
}

/**
 * Create a test event
 */
function createTestEvent(testId, eventType, durationMs, options = {}) {
  return {
    eventId: options.eventId || `EVT-${Math.random().toString(36).substr(2, 8)}`,
    testId,
    eventType, // pass, fail, skip, flaky
    durationMs,
    timestamp: options.timestamp || new Date(),
    errorMessage: options.errorMessage || null,
    metadata: options.metadata || {}
  }
}

/**
 * Create a test metric
 */
function createTestMetric(testId, metricName, value, options = {}) {
  return {
    testId,
    metricName,
    value,
    timestamp: options.timestamp || new Date(),
    tags: options.tags || {}
  }
}

/**
 * Insight Engine class
 */
class InsightEngine {
  // Thresholds
  static SLOW_TEST_THRESHOLD_MS = 5000
  static FLAKY_THRESHOLD = 0.15
  static FAILURE_STREAK_THRESHOLD = 3
  static PERFORMANCE_DEGRADATION_PCT = 0.20
  static HIGH_COVERAGE_GAP_PCT = 0.30

  constructor(options = {}) {
    this._insightTtl = options.insightTtlHours || 24
    this._minDataPoints = options.minDataPoints || 10

    this._events = []
    this._metrics = []
    this._insights = []
    this._insightCounter = 0
  }

  /**
   * Record a test event
   */
  recordEvent(testId, eventType, durationMs, errorMessage = null, metadata = null) {
    const event = createTestEvent(testId, eventType, durationMs, {
      errorMessage,
      metadata
    })

    this._events.push(event)

    // Prune old events (keep last 30 days)
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    this._events = this._events.filter(e => e.timestamp > cutoff)

    return event
  }

  /**
   * Record a test metric
   */
  recordMetric(testId, metricName, value, tags = null) {
    const metric = createTestMetric(testId, metricName, value, { tags })
    this._metrics.push(metric)

    // Prune old metrics
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    this._metrics = this._metrics.filter(m => m.timestamp > cutoff)

    return metric
  }

  /**
   * Generate all insights from current data
   */
  generateInsights() {
    let insights = []

    // Analyze patterns
    insights = insights.concat(this._analyzeFailurePatterns())
    insights = insights.concat(this._analyzePerformancePatterns())
    insights = insights.concat(this._analyzeFlakiness())

    // Analyze anomalies
    insights = insights.concat(this._detectDurationAnomalies())
    insights = insights.concat(this._detectFailureSpikes())

    // Analyze trends
    insights = insights.concat(this._analyzeReliabilityTrends())
    insights = insights.concat(this._analyzePerformanceTrends())

    // Identify opportunities
    insights = insights.concat(this._identifyOptimizationOpportunities())

    this._insights = this._insights.concat(insights)
    return insights
  }

  /**
   * Get insights with optional filtering
   */
  getInsights(options = {}) {
    let insights = this._insights

    if (options.priority) {
      insights = insights.filter(i => i.priority === options.priority)
    }

    if (options.category) {
      insights = insights.filter(i => i.category === options.category)
    }

    // Filter expired insights
    const now = new Date()
    insights = insights.filter(i => !i.expiresAt || i.expiresAt > now)

    // Sort by priority
    const priorityOrder = {
      [InsightPriority.CRITICAL]: 0,
      [InsightPriority.HIGH]: 1,
      [InsightPriority.MEDIUM]: 2,
      [InsightPriority.LOW]: 3,
      [InsightPriority.INFO]: 4
    }
    insights.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority])

    const limit = options.limit || 20
    return insights.slice(0, limit)
  }

  /**
   * Get insights for a specific test
   */
  getInsightsForTest(testId) {
    return this._insights.filter(i => i.affectedTests.includes(testId))
  }

  _createInsight(options) {
    this._insightCounter++
    const expiresAt = new Date(Date.now() + this._insightTtl * 60 * 60 * 1000)

    return createInsight({
      insightId: `INS-${String(this._insightCounter).padStart(5, '0')}`,
      ...options,
      expiresAt
    })
  }

  _groupEventsByTest() {
    const testEvents = {}
    for (const event of this._events) {
      if (!testEvents[event.testId]) {
        testEvents[event.testId] = []
      }
      testEvents[event.testId].push(event)
    }
    return testEvents
  }

  _mean(values) {
    if (values.length === 0) return 0
    return values.reduce((a, b) => a + b, 0) / values.length
  }

  _stdev(values) {
    if (values.length < 2) return 0
    const mean = this._mean(values)
    const squaredDiffs = values.map(v => Math.pow(v - mean, 2))
    return Math.sqrt(this._mean(squaredDiffs))
  }

  _analyzeFailurePatterns() {
    const insights = []
    const testEvents = this._groupEventsByTest()

    for (const [testId, events] of Object.entries(testEvents)) {
      if (events.length < this._minDataPoints) continue

      // Check for failure streaks
      const recent = [...events].sort((a, b) => a.timestamp - b.timestamp).slice(-10)
      let consecutiveFailures = 0
      let maxStreak = 0

      for (const event of recent) {
        if (event.eventType === 'fail') {
          consecutiveFailures++
          maxStreak = Math.max(maxStreak, consecutiveFailures)
        } else {
          consecutiveFailures = 0
        }
      }

      if (maxStreak >= InsightEngine.FAILURE_STREAK_THRESHOLD) {
        insights.push(this._createInsight({
          insightType: InsightType.PATTERN,
          priority: InsightPriority.HIGH,
          category: InsightCategory.RELIABILITY,
          title: 'Consecutive Failure Pattern',
          description: `Test ${testId} has ${maxStreak} consecutive failures`,
          affectedTests: [testId],
          evidence: {
            consecutiveFailures: maxStreak,
            totalEvents: events.length
          },
          suggestions: [
            'Review recent changes to this test',
            'Check for environment issues',
            'Verify test dependencies are stable'
          ]
        }))
      }

      // Check for common error patterns
      const errorMessages = events.filter(e => e.errorMessage).map(e => e.errorMessage)
      if (errorMessages.length >= 3) {
        const errorCounts = {}
        for (const msg of errorMessages) {
          const shortMsg = msg ? msg.slice(0, 100) : 'Unknown'
          errorCounts[shortMsg] = (errorCounts[shortMsg] || 0) + 1
        }

        const topError = Object.entries(errorCounts).reduce(
          (max, [msg, count]) => count > max[1] ? [msg, count] : max,
          ['', 0]
        )

        if (topError[1] >= 3) {
          insights.push(this._createInsight({
            insightType: InsightType.PATTERN,
            priority: InsightPriority.MEDIUM,
            category: InsightCategory.RELIABILITY,
            title: 'Recurring Error Pattern',
            description: `Same error occurring repeatedly in ${testId}`,
            affectedTests: [testId],
            evidence: {
              errorMessage: topError[0],
              occurrences: topError[1]
            },
            suggestions: [
              'Investigate root cause of recurring error',
              'Add better error handling'
            ]
          }))
        }
      }
    }

    return insights
  }

  _analyzePerformancePatterns() {
    const insights = []
    const testEvents = this._groupEventsByTest()

    const slowTests = []
    for (const [testId, events] of Object.entries(testEvents)) {
      const durations = events.map(e => e.durationMs)
      const avgDuration = this._mean(durations)

      if (avgDuration > InsightEngine.SLOW_TEST_THRESHOLD_MS) {
        slowTests.push([testId, avgDuration])
      }
    }

    if (slowTests.length > 0) {
      slowTests.sort((a, b) => b[1] - a[1])
      const topSlow = slowTests.slice(0, 5)

      insights.push(this._createInsight({
        insightType: InsightType.PATTERN,
        priority: InsightPriority.MEDIUM,
        category: InsightCategory.PERFORMANCE,
        title: 'Slow Test Pattern',
        description: `${slowTests.length} tests consistently exceed ${InsightEngine.SLOW_TEST_THRESHOLD_MS}ms`,
        affectedTests: topSlow.map(t => t[0]),
        evidence: {
          slowTestsCount: slowTests.length,
          slowest: Object.fromEntries(topSlow.map(t => [t[0], `${Math.round(t[1])}ms`]))
        },
        suggestions: [
          'Optimize slow selectors',
          'Reduce wait times where possible',
          'Consider parallel execution'
        ]
      }))
    }

    return insights
  }

  _analyzeFlakiness() {
    const insights = []
    const testEvents = this._groupEventsByTest()

    const flakyTests = []
    for (const [testId, events] of Object.entries(testEvents)) {
      if (events.length < this._minDataPoints) continue

      const sortedEvents = [...events].sort((a, b) => a.timestamp - b.timestamp)
      let transitions = 0

      for (let i = 1; i < sortedEvents.length; i++) {
        if (sortedEvents[i].eventType !== sortedEvents[i - 1].eventType) {
          if (['pass', 'fail'].includes(sortedEvents[i].eventType)) {
            transitions++
          }
        }
      }

      const flakyRate = transitions / sortedEvents.length
      if (flakyRate > InsightEngine.FLAKY_THRESHOLD) {
        flakyTests.push([testId, flakyRate])
      }
    }

    if (flakyTests.length > 0) {
      flakyTests.sort((a, b) => b[1] - a[1])

      insights.push(this._createInsight({
        insightType: InsightType.WARNING,
        priority: InsightPriority.HIGH,
        category: InsightCategory.RELIABILITY,
        title: 'Flaky Tests Detected',
        description: `${flakyTests.length} tests show inconsistent results`,
        affectedTests: flakyTests.map(t => t[0]),
        evidence: {
          flakyTestsCount: flakyTests.length,
          worstOffenders: Object.fromEntries(
            flakyTests.slice(0, 5).map(t => [t[0], `${(t[1] * 100).toFixed(1)}%`])
          )
        },
        suggestions: [
          'Add retry mechanisms for flaky tests',
          'Review async operations and race conditions',
          'Consider quarantining until fixed'
        ]
      }))
    }

    return insights
  }

  _detectDurationAnomalies() {
    const insights = []
    const testEvents = this._groupEventsByTest()

    for (const [testId, events] of Object.entries(testEvents)) {
      if (events.length < this._minDataPoints) continue

      const durations = events.map(e => e.durationMs)
      const mean = this._mean(durations)
      const stdev = this._stdev(durations)

      const recent = [...events].sort((a, b) => a.timestamp - b.timestamp).slice(-5)
      const outliers = recent.filter(e =>
        stdev > 0 && Math.abs(e.durationMs - mean) > 3 * stdev
      )

      if (outliers.length > 0) {
        insights.push(this._createInsight({
          insightType: InsightType.ANOMALY,
          priority: InsightPriority.MEDIUM,
          category: InsightCategory.PERFORMANCE,
          title: 'Duration Anomaly',
          description: `Unusual execution times detected for ${testId}`,
          affectedTests: [testId],
          evidence: {
            meanDurationMs: Math.round(mean * 100) / 100,
            stdDevMs: Math.round(stdev * 100) / 100,
            outlierCount: outliers.length,
            outlierDurations: outliers.map(o => Math.round(o.durationMs * 100) / 100)
          },
          suggestions: [
            'Check for resource contention',
            'Review network conditions',
            'Verify test environment stability'
          ]
        }))
      }
    }

    return insights
  }

  _detectFailureSpikes() {
    const insights = []

    // Group failures by hour
    const hourFailures = {}
    for (const event of this._events) {
      if (event.eventType === 'fail') {
        const hourKey = event.timestamp.toISOString().slice(0, 13) + ':00'
        hourFailures[hourKey] = (hourFailures[hourKey] || 0) + 1
      }
    }

    if (Object.keys(hourFailures).length < 3) return insights

    const values = Object.values(hourFailures)
    const avgFailures = this._mean(values)
    const recentHour = Object.keys(hourFailures).sort().pop()
    const recentFailures = hourFailures[recentHour] || 0

    if (avgFailures > 0 && recentFailures > avgFailures * 2) {
      insights.push(this._createInsight({
        insightType: InsightType.ANOMALY,
        priority: InsightPriority.HIGH,
        category: InsightCategory.RELIABILITY,
        title: 'Failure Spike Detected',
        description: `Failures spiked to ${recentFailures} (avg: ${avgFailures.toFixed(1)})`,
        affectedTests: [],
        evidence: {
          currentFailures: recentFailures,
          averageFailures: Math.round(avgFailures * 100) / 100,
          spikeFactor: Math.round((recentFailures / avgFailures) * 100) / 100
        },
        suggestions: [
          'Check for infrastructure issues',
          'Review recent deployments',
          'Verify test data availability'
        ]
      }))
    }

    return insights
  }

  _analyzeReliabilityTrends() {
    const insights = []

    if (this._events.length < this._minDataPoints) return insights

    const sortedEvents = [...this._events].sort((a, b) => a.timestamp - b.timestamp)
    const mid = Math.floor(sortedEvents.length / 2)
    const firstHalf = sortedEvents.slice(0, mid)
    const secondHalf = sortedEvents.slice(mid)

    const firstPassRate = firstHalf.filter(e => e.eventType === 'pass').length / firstHalf.length
    const secondPassRate = secondHalf.filter(e => e.eventType === 'pass').length / secondHalf.length

    const change = secondPassRate - firstPassRate

    if (Math.abs(change) > 0.1) {
      const isImproving = change > 0

      insights.push(this._createInsight({
        insightType: InsightType.TREND,
        priority: isImproving ? InsightPriority.MEDIUM : InsightPriority.HIGH,
        category: InsightCategory.RELIABILITY,
        title: `Reliability Trend ${isImproving ? 'Improving' : 'Declining'}`,
        description: `Pass rate changed from ${(firstPassRate * 100).toFixed(1)}% to ${(secondPassRate * 100).toFixed(1)}%`,
        affectedTests: [],
        evidence: {
          previousPassRate: Math.round(firstPassRate * 1000) / 1000,
          currentPassRate: Math.round(secondPassRate * 1000) / 1000,
          change: Math.round(change * 1000) / 1000
        },
        suggestions: [
          isImproving ? 'Continue current practices' : 'Investigate reliability issues',
          'Monitor trend closely'
        ]
      }))
    }

    return insights
  }

  _analyzePerformanceTrends() {
    const insights = []

    if (this._events.length < this._minDataPoints) return insights

    const sortedEvents = [...this._events].sort((a, b) => a.timestamp - b.timestamp)
    const mid = Math.floor(sortedEvents.length / 2)
    const firstHalf = sortedEvents.slice(0, mid)
    const secondHalf = sortedEvents.slice(mid)

    const firstAvg = this._mean(firstHalf.map(e => e.durationMs))
    const secondAvg = this._mean(secondHalf.map(e => e.durationMs))

    const pctChange = firstAvg > 0 ? (secondAvg - firstAvg) / firstAvg : 0

    if (Math.abs(pctChange) > InsightEngine.PERFORMANCE_DEGRADATION_PCT) {
      const isDegrading = pctChange > 0

      insights.push(this._createInsight({
        insightType: InsightType.TREND,
        priority: isDegrading ? InsightPriority.HIGH : InsightPriority.MEDIUM,
        category: InsightCategory.PERFORMANCE,
        title: `Performance Trend ${isDegrading ? 'Degrading' : 'Improving'}`,
        description: `Average duration changed by ${(pctChange * 100).toFixed(1)}% (${Math.round(firstAvg)}ms → ${Math.round(secondAvg)}ms)`,
        affectedTests: [],
        evidence: {
          previousAvgMs: Math.round(firstAvg * 100) / 100,
          currentAvgMs: Math.round(secondAvg * 100) / 100,
          pctChange: Math.round(pctChange * 10000) / 100
        },
        suggestions: [
          isDegrading ? 'Profile slow tests' : 'Document performance wins',
          'Review recent code changes affecting performance'
        ]
      }))
    }

    return insights
  }

  _identifyOptimizationOpportunities() {
    const insights = []
    const testEvents = this._groupEventsByTest()

    // Find tests that always pass (candidates for parallelization)
    const alwaysPass = []
    for (const [testId, events] of Object.entries(testEvents)) {
      if (events.length >= this._minDataPoints) {
        if (events.every(e => e.eventType === 'pass')) {
          const avgDuration = this._mean(events.map(e => e.durationMs))
          alwaysPass.push([testId, avgDuration])
        }
      }
    }

    if (alwaysPass.length >= 5) {
      const totalTime = alwaysPass.reduce((sum, t) => sum + t[1], 0)
      const maxTime = Math.max(...alwaysPass.map(t => t[1]))

      insights.push(this._createInsight({
        insightType: InsightType.OPPORTUNITY,
        priority: InsightPriority.LOW,
        category: InsightCategory.EFFICIENCY,
        title: 'Parallelization Opportunity',
        description: `${alwaysPass.length} stable tests could run in parallel (total: ${Math.round(totalTime)}ms)`,
        affectedTests: alwaysPass.slice(0, 10).map(t => t[0]),
        evidence: {
          stableTestsCount: alwaysPass.length,
          totalSequentialTimeMs: Math.round(totalTime * 100) / 100,
          potentialParallelTimeMs: Math.round(maxTime * 100) / 100
        },
        suggestions: [
          'Consider running stable tests in parallel',
          'Group tests by resource requirements'
        ]
      }))
    }

    return insights
  }

  /**
   * Get engine statistics
   */
  getStatistics() {
    const priorityCounts = {}
    for (const priority of Object.values(InsightPriority)) {
      priorityCounts[priority] = this._insights.filter(i => i.priority === priority).length
    }

    return {
      totalEvents: this._events.length,
      totalMetrics: this._metrics.length,
      totalInsights: this._insights.length,
      insightsByPriority: priorityCounts,
      uniqueTests: new Set(this._events.map(e => e.testId)).size
    }
  }

  /**
   * Format an insight for display
   */
  formatInsight(insight) {
    const priorityEmoji = {
      [InsightPriority.CRITICAL]: '🔴',
      [InsightPriority.HIGH]: '🟠',
      [InsightPriority.MEDIUM]: '🟡',
      [InsightPriority.LOW]: '🟢',
      [InsightPriority.INFO]: 'ℹ️'
    }

    const typeEmoji = {
      [InsightType.PATTERN]: '🔄',
      [InsightType.ANOMALY]: '⚠️',
      [InsightType.TREND]: '📈',
      [InsightType.OPPORTUNITY]: '💡',
      [InsightType.WARNING]: '🚨',
      [InsightType.ACHIEVEMENT]: '🏆'
    }

    const lines = [
      '='.repeat(60),
      `  ${priorityEmoji[insight.priority]} ${typeEmoji[insight.insightType]} ${insight.title}`,
      '='.repeat(60),
      '',
      `  ${insight.description}`,
      '',
      `  Category: ${insight.category}`,
      `  Priority: ${insight.priority}`,
      ''
    ]

    if (insight.affectedTests.length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  AFFECTED TESTS')
      lines.push('-'.repeat(60))
      for (const testId of insight.affectedTests.slice(0, 5)) {
        lines.push(`  • ${testId}`)
      }
      if (insight.affectedTests.length > 5) {
        lines.push(`  ... and ${insight.affectedTests.length - 5} more`)
      }
      lines.push('')
    }

    if (insight.suggestions.length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  SUGGESTIONS')
      lines.push('-'.repeat(60))
      for (const suggestion of insight.suggestions) {
        lines.push(`  → ${suggestion}`)
      }
      lines.push('')
    }

    lines.push('='.repeat(60))
    return lines.join('\n')
  }
}

/**
 * Quick helper to create an insight engine
 */
function createInsightEngine(options = {}) {
  return new InsightEngine(options)
}

module.exports = {
  InsightType,
  InsightPriority,
  InsightCategory,
  InsightEngine,
  createInsight,
  createTestEvent,
  createTestMetric,
  createInsightEngine
}
