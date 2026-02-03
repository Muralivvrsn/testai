/**
 * Yali Agent - Flakiness Detector
 * Ported from testai-agent/flakiness/detector.py
 *
 * Detect flaky tests through statistical analysis
 * of test execution history and patterns.
 */

/**
 * Patterns of flaky behavior
 */
const FlakinessPattern = {
  TIMING: 'timing',           // Timing-related failures
  ORDERING: 'ordering',       // Order-dependent failures
  RESOURCE: 'resource',       // Resource contention
  NETWORK: 'network',         // Network-related
  STATE: 'state',             // State leakage
  CONCURRENCY: 'concurrency', // Race conditions
  ENVIRONMENT: 'environment', // Environment differences
  DATA: 'data',               // Data-dependent
  UNKNOWN: 'unknown'
}

/**
 * Levels of flakiness severity
 */
const FlakinessLevel = {
  NONE: 'none',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
}

/**
 * Create a test execution record
 */
function createTestExecution(testId, testName, passed, durationMs, options = {}) {
  return {
    executionId: options.executionId || `EXEC-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    testId,
    testName,
    passed,
    durationMs,
    timestamp: options.timestamp || new Date(),
    errorMessage: options.errorMessage || null,
    environment: options.environment || 'default',
    metadata: options.metadata || {}
  }
}

/**
 * Create a flakiness report
 */
function createFlakinessReport(options) {
  return {
    reportId: options.reportId,
    testId: options.testId,
    testName: options.testName,
    flakinessScore: options.flakinessScore,
    flakinessLevel: options.flakinessLevel,
    totalRuns: options.totalRuns,
    passCount: options.passCount,
    failCount: options.failCount,
    patternsDetected: options.patternsDetected || [],
    confidence: options.confidence,
    timestamp: options.timestamp || new Date(),
    metadata: options.metadata || {}
  }
}

/**
 * Flakiness Detector class
 */
class FlakinessDetector {
  constructor(options = {}) {
    this._minRuns = options.minRuns || 5
    this._flakinessThreshold = options.flakinessThreshold || 0.1
    this._executions = new Map() // testId -> TestExecution[]
    this._reports = []
    this._executionCounter = 0
    this._reportCounter = 0
  }

  /**
   * Record a test execution
   */
  recordExecution(testId, testName, passed, durationMs, options = {}) {
    this._executionCounter++

    const execution = createTestExecution(testId, testName, passed, durationMs, {
      executionId: `EXEC-${String(this._executionCounter).padStart(6, '0')}`,
      errorMessage: options.errorMessage,
      environment: options.environment,
      metadata: options.metadata
    })

    if (!this._executions.has(testId)) {
      this._executions.set(testId, [])
    }
    this._executions.get(testId).push(execution)

    return execution
  }

  /**
   * Detect flakiness for a specific test
   */
  detect(testId) {
    const executions = this._executions.get(testId) || []

    if (executions.length < this._minRuns) {
      return null
    }

    this._reportCounter++
    const reportId = `FLAKE-${String(this._reportCounter).padStart(5, '0')}`

    // Calculate basic stats
    const totalRuns = executions.length
    const passCount = executions.filter(e => e.passed).length
    const failCount = totalRuns - passCount

    // Calculate flakiness score (0-1)
    // A truly flaky test has roughly 50% pass/fail ratio
    const passRate = passCount / totalRuns
    let flakinessScore = 1 - Math.abs(passRate - 0.5) * 2

    // If all pass or all fail, not flaky
    if (passCount === 0 || failCount === 0) {
      flakinessScore = 0.0
    }

    // Determine level
    let level
    if (flakinessScore >= 0.8) {
      level = FlakinessLevel.CRITICAL
    } else if (flakinessScore >= 0.6) {
      level = FlakinessLevel.HIGH
    } else if (flakinessScore >= 0.4) {
      level = FlakinessLevel.MEDIUM
    } else if (flakinessScore >= this._flakinessThreshold) {
      level = FlakinessLevel.LOW
    } else {
      level = FlakinessLevel.NONE
    }

    // Detect patterns
    const patterns = this._detectPatterns(executions)

    // Calculate confidence based on sample size
    const confidence = Math.min(1.0, Math.sqrt(totalRuns / 20))

    const testName = executions[0]?.testName || testId

    const report = createFlakinessReport({
      reportId,
      testId,
      testName,
      flakinessScore: Math.round(flakinessScore * 1000) / 1000,
      flakinessLevel: level,
      totalRuns,
      passCount,
      failCount,
      patternsDetected: patterns,
      confidence: Math.round(confidence * 100) / 100
    })

    this._reports.push(report)
    return report
  }

  _detectPatterns(executions) {
    const patterns = []

    if (executions.length < 3) {
      return [FlakinessPattern.UNKNOWN]
    }

    // Check timing pattern (high duration variance on failures)
    const durationsPass = executions.filter(e => e.passed).map(e => e.durationMs)
    const durationsFail = executions.filter(e => !e.passed).map(e => e.durationMs)

    if (durationsPass.length > 0 && durationsFail.length > 0) {
      const avgPass = durationsPass.reduce((a, b) => a + b, 0) / durationsPass.length
      const avgFail = durationsFail.reduce((a, b) => a + b, 0) / durationsFail.length

      if (Math.abs(avgFail - avgPass) > avgPass * 0.5) {
        patterns.push(FlakinessPattern.TIMING)
      }
    }

    // Check for ordering pattern (consecutive fails/passes)
    let streakChanges = 0
    let lastResult = executions[0].passed
    for (let i = 1; i < executions.length; i++) {
      if (executions[i].passed !== lastResult) {
        streakChanges++
        lastResult = executions[i].passed
      }
    }

    if (streakChanges > executions.length * 0.6) {
      patterns.push(FlakinessPattern.ORDERING)
    }

    // Check error messages for patterns
    const errorMessages = executions.filter(e => e.errorMessage).map(e => e.errorMessage)

    if (errorMessages.length > 0) {
      const errorText = errorMessages.join(' ').toLowerCase()

      if (errorText.includes('timeout') || errorText.includes('timed out')) {
        patterns.push(FlakinessPattern.TIMING)
      }

      if (errorText.includes('connection') || errorText.includes('network')) {
        patterns.push(FlakinessPattern.NETWORK)
      }

      if (errorText.includes('race') || errorText.includes('concurrent')) {
        patterns.push(FlakinessPattern.CONCURRENCY)
      }

      if (errorText.includes('resource') || errorText.includes('memory')) {
        patterns.push(FlakinessPattern.RESOURCE)
      }

      if (errorText.includes('state') || errorText.includes('stale')) {
        patterns.push(FlakinessPattern.STATE)
      }
    }

    // Check environment variance
    const envResults = new Map()
    for (const e of executions) {
      if (!envResults.has(e.environment)) {
        envResults.set(e.environment, [])
      }
      envResults.get(e.environment).push(e.passed)
    }

    if (envResults.size > 1) {
      const passRates = []
      for (const [env, results] of envResults) {
        if (results.length >= 2) {
          passRates.push(results.filter(r => r).length / results.length)
        }
      }

      if (passRates.length > 0 && Math.max(...passRates) - Math.min(...passRates) > 0.3) {
        patterns.push(FlakinessPattern.ENVIRONMENT)
      }
    }

    if (patterns.length === 0) {
      patterns.push(FlakinessPattern.UNKNOWN)
    }

    return [...new Set(patterns)]
  }

  /**
   * Detect flakiness for all recorded tests
   */
  detectAll() {
    const reports = []

    for (const testId of this._executions.keys()) {
      const report = this.detect(testId)
      if (report && report.flakinessLevel !== FlakinessLevel.NONE) {
        reports.push(report)
      }
    }

    return reports
  }

  /**
   * Get all flaky tests above a certain level
   */
  getFlakyTests(minLevel = FlakinessLevel.LOW) {
    const levels = Object.values(FlakinessLevel)
    const minIndex = levels.indexOf(minLevel)

    return this._reports.filter(r => levels.indexOf(r.flakinessLevel) >= minIndex)
  }

  /**
   * Get execution history for a test
   */
  getExecutions(testId, limit = 100) {
    const executions = this._executions.get(testId) || []
    return executions.slice(-limit)
  }

  /**
   * Get detector statistics
   */
  getStatistics() {
    let totalExecutions = 0
    for (const executions of this._executions.values()) {
      totalExecutions += executions.length
    }

    const levelCounts = {}
    for (const level of Object.values(FlakinessLevel)) {
      levelCounts[level] = 0
    }
    for (const report of this._reports) {
      levelCounts[report.flakinessLevel]++
    }

    const flakyTests = this._reports.filter(r => r.flakinessLevel !== FlakinessLevel.NONE).length

    return {
      totalTests: this._executions.size,
      totalExecutions,
      totalReports: this._reports.length,
      flakyTestsDetected: flakyTests,
      flakinessByLevel: levelCounts
    }
  }

  /**
   * Format a flakiness report for display
   */
  formatReport(report) {
    const levelIcons = {
      [FlakinessLevel.NONE]: '✅',
      [FlakinessLevel.LOW]: '🟡',
      [FlakinessLevel.MEDIUM]: '🟠',
      [FlakinessLevel.HIGH]: '🔴',
      [FlakinessLevel.CRITICAL]: '⛔'
    }

    const icon = levelIcons[report.flakinessLevel] || ''

    const lines = [
      '='.repeat(50),
      `  FLAKINESS REPORT: ${icon} ${report.flakinessLevel.toUpperCase()}`,
      '='.repeat(50),
      '',
      `  Test: ${report.testName}`,
      `  ID: ${report.testId}`,
      '',
      '-'.repeat(50),
      '  STATISTICS',
      '-'.repeat(50),
      '',
      `  Total Runs: ${report.totalRuns}`,
      `  Passed: ${report.passCount}`,
      `  Failed: ${report.failCount}`,
      `  Flakiness Score: ${(report.flakinessScore * 100).toFixed(1)}%`,
      `  Confidence: ${(report.confidence * 100).toFixed(0)}%`,
      ''
    ]

    if (report.patternsDetected.length > 0) {
      lines.push('-'.repeat(50))
      lines.push('  PATTERNS DETECTED')
      lines.push('-'.repeat(50))
      lines.push('')
      for (const pattern of report.patternsDetected) {
        lines.push(`  • ${pattern}`)
      }
      lines.push('')
    }

    lines.push('='.repeat(50))
    return lines.join('\n')
  }
}

/**
 * Quick helper to create a flakiness detector
 */
function createFlakinessDetector(options = {}) {
  return new FlakinessDetector(options)
}

module.exports = {
  FlakinessPattern,
  FlakinessLevel,
  FlakinessDetector,
  createTestExecution,
  createFlakinessReport,
  createFlakinessDetector
}
