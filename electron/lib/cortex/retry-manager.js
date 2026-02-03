/**
 * Yali Agent - Retry Manager
 * Ported from testai-agent/retry/
 *
 * Smart retry strategies, adaptive learning, and test quarantine
 * for resilient autonomous test execution.
 */

/**
 * Types of backoff algorithms
 */
const BackoffType = {
  FIXED: 'fixed',             // Fixed delay between retries
  LINEAR: 'linear',           // Linearly increasing delay
  EXPONENTIAL: 'exponential', // Exponentially increasing delay
  FIBONACCI: 'fibonacci',     // Fibonacci sequence delay
  JITTERED: 'jittered',       // Exponential with random jitter
  DECORRELATED: 'decorrelated' // Decorrelated jitter (AWS style)
}

/**
 * Retry decision types
 */
const RetryDecision = {
  RETRY: 'retry',           // Should retry
  SKIP: 'skip',             // Skip retry (not worth it)
  QUARANTINE: 'quarantine', // Move to quarantine
  ESCALATE: 'escalate'      // Escalate for review
}

/**
 * Reasons for quarantining a test
 */
const QuarantineReason = {
  CONSISTENTLY_FAILING: 'consistently_failing',
  EXTREMELY_FLAKY: 'extremely_flaky',
  ENVIRONMENT_DEPENDENT: 'environment_dependent',
  RESOURCE_INTENSIVE: 'resource_intensive',
  MANUAL_QUARANTINE: 'manual_quarantine',
  TIMEOUT_PRONE: 'timeout_prone',
  BLOCKING_CI: 'blocking_ci'
}

/**
 * Status of quarantined tests
 */
const QuarantineStatus = {
  ACTIVE: 'active',       // Currently quarantined
  MONITORING: 'monitoring', // Released but being watched
  RELEASED: 'released',   // Fully released
  PERMANENT: 'permanent'  // Permanently quarantined
}

// Fibonacci cache for performance
const fibCache = [1, 1]

function fibonacci(n) {
  while (fibCache.length <= n) {
    fibCache.push(fibCache[fibCache.length - 1] + fibCache[fibCache.length - 2])
  }
  return fibCache[n]
}

/**
 * Create a retry config
 */
function createRetryConfig(options = {}) {
  return {
    maxRetries: options.maxRetries || 3,
    backoffType: options.backoffType || BackoffType.EXPONENTIAL,
    initialDelayMs: options.initialDelayMs || 1000,
    maxDelayMs: options.maxDelayMs || 30000,
    jitterFactor: options.jitterFactor || 0.1, // 10% jitter
    retryOnErrors: options.retryOnErrors || null, // Specific errors to retry
    skipOnErrors: options.skipOnErrors || null    // Errors that shouldn't retry
  }
}

/**
 * Create a retry attempt record
 */
function createRetryAttempt(attemptNumber, delayBeforeMs = 0) {
  return {
    attemptNumber,
    startedAt: new Date(),
    endedAt: null,
    passed: false,
    error: null,
    durationMs: 0,
    delayBeforeMs
  }
}

/**
 * Create a retry result
 */
function createRetryResult(testId, finalStatus, attempts) {
  const successful = attempts.find(a => a.passed)
  return {
    testId,
    finalStatus, // passed, failed, exhausted
    totalAttempts: attempts.length,
    successfulAttempt: successful ? successful.attemptNumber : null,
    attempts,
    totalDurationMs: attempts.reduce((sum, a) => sum + a.durationMs, 0),
    totalDelayMs: attempts.reduce((sum, a) => sum + a.delayBeforeMs, 0),
    errorPattern: null
  }
}

/**
 * Retry Strategy class
 */
class RetryStrategy {
  constructor(config = null) {
    this.config = config || createRetryConfig()
    this._lastDelay = this.config.initialDelayMs
  }

  /**
   * Calculate delay before the given attempt
   */
  calculateDelay(attempt) {
    if (attempt <= 1) return 0 // No delay before first attempt

    let baseDelay = this._getBaseDelay(attempt)

    // Apply jitter if configured
    if (this.config.jitterFactor > 0) {
      const jitterRange = baseDelay * this.config.jitterFactor
      const jitter = (Math.random() * 2 - 1) * jitterRange
      baseDelay = Math.floor(baseDelay + jitter)
    }

    // Clamp to max delay
    const delay = Math.min(baseDelay, this.config.maxDelayMs)

    // Store for decorrelated jitter
    this._lastDelay = delay

    return Math.max(0, delay)
  }

  _getBaseDelay(attempt) {
    const initial = this.config.initialDelayMs
    const backoff = this.config.backoffType

    switch (backoff) {
      case BackoffType.FIXED:
        return initial

      case BackoffType.LINEAR:
        return initial * attempt

      case BackoffType.EXPONENTIAL:
        return initial * Math.pow(2, attempt - 1)

      case BackoffType.FIBONACCI:
        return initial * fibonacci(attempt)

      case BackoffType.JITTERED:
        // Full jitter: random between 0 and exponential delay
        const maxDelay = initial * Math.pow(2, attempt - 1)
        return Math.floor(Math.random() * maxDelay)

      case BackoffType.DECORRELATED:
        // Decorrelated jitter: random between initial and 3 * last_delay
        const min = initial
        const max = Math.min(this.config.maxDelayMs, this._lastDelay * 3)
        return Math.floor(Math.random() * (max - min + 1)) + min

      default:
        return initial
    }
  }

  /**
   * Determine if another retry should be attempted
   */
  shouldRetry(attempt, error = null) {
    // Check max retries
    if (attempt >= this.config.maxRetries) return false

    // Check error patterns
    if (error) {
      // Skip specific errors
      if (this.config.skipOnErrors) {
        for (const pattern of this.config.skipOnErrors) {
          if (error.toLowerCase().includes(pattern.toLowerCase())) {
            return false
          }
        }
      }

      // Only retry specific errors
      if (this.config.retryOnErrors) {
        for (const pattern of this.config.retryOnErrors) {
          if (error.toLowerCase().includes(pattern.toLowerCase())) {
            return true
          }
        }
        return false // Error didn't match retry patterns
      }
    }

    return true
  }

  /**
   * Execute a test with retry logic
   */
  async executeWithRetry(testId, testFn, errorFn = null) {
    const attempts = []
    let successfulAttempt = null
    const errorsSeen = []

    for (let attemptNum = 1; attemptNum <= this.config.maxRetries + 1; attemptNum++) {
      const delay = this.calculateDelay(attemptNum)

      // Wait for delay
      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay))
      }

      const attempt = createRetryAttempt(attemptNum, delay)

      try {
        const passed = await testFn()
        attempt.passed = passed
        attempt.endedAt = new Date()
        attempt.durationMs = attempt.endedAt - attempt.startedAt

        if (passed) {
          successfulAttempt = attemptNum
          attempts.push(attempt)
          break
        }

        // Get error if failed
        if (errorFn) {
          attempt.error = await errorFn()
          if (attempt.error) errorsSeen.push(attempt.error)
        }
      } catch (e) {
        attempt.error = e.message || String(e)
        attempt.endedAt = new Date()
        attempt.durationMs = attempt.endedAt - attempt.startedAt
        errorsSeen.push(attempt.error)
      }

      attempts.push(attempt)

      // Check if should retry
      if (!this.shouldRetry(attemptNum, attempt.error)) break
    }

    // Determine final status
    let finalStatus
    if (successfulAttempt) {
      finalStatus = 'passed'
    } else if (attempts.length >= this.config.maxRetries + 1) {
      finalStatus = 'exhausted'
    } else {
      finalStatus = 'failed'
    }

    const result = createRetryResult(testId, finalStatus, attempts)

    // Find common error pattern
    if (errorsSeen.length > 0) {
      result.errorPattern = this._findErrorPattern(errorsSeen)
    }

    return result
  }

  /**
   * Simulate retry execution for testing
   */
  async simulateRetries(testId, failureProbability = 0.5) {
    const testFn = () => Math.random() > failureProbability
    const errors = ['Element not found', 'Timeout exceeded', 'Connection refused', 'Assertion failed']
    const errorFn = () => errors[Math.floor(Math.random() * errors.length)]

    return this.executeWithRetry(testId, testFn, errorFn)
  }

  _findErrorPattern(errors) {
    if (!errors.length) return null

    const keywords = ['timeout', 'element', 'connection', 'assertion', 'network', 'not found', 'failed', 'refused']
    const errorTypes = {}

    for (const error of errors) {
      const errorLower = error.toLowerCase()
      for (const keyword of keywords) {
        if (errorLower.includes(keyword)) {
          errorTypes[keyword] = (errorTypes[keyword] || 0) + 1
        }
      }
    }

    if (Object.keys(errorTypes).length > 0) {
      return Object.entries(errorTypes).sort((a, b) => b[1] - a[1])[0][0]
    }

    return null
  }

  /**
   * Get the sequence of delays for visualization
   */
  getDelaySequence(maxAttempts = 5) {
    return Array.from({ length: maxAttempts }, (_, i) => this.calculateDelay(i + 1))
  }

  /**
   * Format retry result as readable text
   */
  formatResult(result) {
    const statusIcons = { passed: '✅', failed: '❌', exhausted: '⚠️' }
    const icon = statusIcons[result.finalStatus] || '⚪'

    const lines = [
      '='.repeat(50),
      `  ${icon} RETRY RESULT: ${result.testId}`,
      '='.repeat(50),
      '',
      `  Final Status: ${result.finalStatus.toUpperCase()}`,
      `  Total Attempts: ${result.totalAttempts}`
    ]

    if (result.successfulAttempt) {
      lines.push(`  Successful on Attempt: ${result.successfulAttempt}`)
    }

    lines.push(`  Total Duration: ${result.totalDurationMs}ms`)
    lines.push(`  Total Delay: ${result.totalDelayMs}ms`)
    lines.push('')

    if (result.errorPattern) {
      lines.push(`  Error Pattern: ${result.errorPattern}`)
      lines.push('')
    }

    lines.push('-'.repeat(50))
    lines.push('  ATTEMPTS')
    lines.push('-'.repeat(50))

    for (const attempt of result.attempts) {
      const attemptIcon = attempt.passed ? '✅' : '❌'
      lines.push(`  ${attemptIcon} Attempt ${attempt.attemptNumber}: ${attempt.durationMs}ms (delay: ${attempt.delayBeforeMs}ms)`)
      if (attempt.error) {
        lines.push(`     Error: ${attempt.error.slice(0, 50)}`)
      }
    }

    lines.push('')
    lines.push('='.repeat(50))
    return lines.join('\n')
  }
}

/**
 * Adaptive Retry Manager - learns from patterns
 */
class AdaptiveRetryManager {
  // Thresholds for decisions
  static QUARANTINE_THRESHOLD = 0.3
  static SKIP_RETRY_THRESHOLD = 0.1
  static ESCALATE_THRESHOLD = 5

  constructor(options = {}) {
    this.defaultMaxRetries = options.defaultMaxRetries || 3
    this.learningEnabled = options.learningEnabled !== false

    this._profiles = new Map() // testId -> TestRetryProfile
    this._recentResults = []
    this._maxRecentResults = 1000
  }

  /**
   * Get optimized retry strategy for a test
   */
  getStrategy(testId) {
    const profile = this._profiles.get(testId)

    let config
    if (profile && this.learningEnabled) {
      config = createRetryConfig({
        maxRetries: profile.optimalRetryCount,
        backoffType: profile.recommendedBackoff,
        initialDelayMs: this._calculateOptimalDelay(profile)
      })
    } else {
      config = createRetryConfig({ maxRetries: this.defaultMaxRetries })
    }

    return new RetryStrategy(config)
  }

  /**
   * Make an adaptive retry decision
   */
  decide(context) {
    // Check for quarantine condition
    if (context.historicalPassRate < AdaptiveRetryManager.QUARANTINE_THRESHOLD) {
      if (context.consecutiveFailures >= AdaptiveRetryManager.ESCALATE_THRESHOLD) {
        return RetryDecision.QUARANTINE
      }
    }

    // Check for escalation
    if (context.consecutiveFailures >= AdaptiveRetryManager.ESCALATE_THRESHOLD) {
      return RetryDecision.ESCALATE
    }

    // Check if retries are worth it
    if (context.avgRetrySuccessRate < AdaptiveRetryManager.SKIP_RETRY_THRESHOLD) {
      return RetryDecision.SKIP
    }

    // Check time budget
    if (context.runTimeBudgetRemainingMs !== null && context.runTimeBudgetRemainingMs !== undefined) {
      const estimatedRetryTime = this._estimateRetryTime(context)
      if (estimatedRetryTime > context.runTimeBudgetRemainingMs) {
        return RetryDecision.SKIP
      }
    }

    return RetryDecision.RETRY
  }

  /**
   * Record a retry result for learning
   */
  recordResult(result) {
    // Update profile
    let profile = this._profiles.get(result.testId)
    if (!profile) {
      profile = {
        testId: result.testId,
        totalRuns: 0,
        totalRetries: 0,
        retrySuccesses: 0,
        optimalRetryCount: 3,
        recommendedBackoff: BackoffType.EXPONENTIAL,
        errorPatterns: {},
        avgSuccessAttempt: 1.0,
        lastUpdated: new Date()
      }
      this._profiles.set(result.testId, profile)
    }

    profile.totalRuns++
    profile.totalRetries += result.totalAttempts - 1
    profile.lastUpdated = new Date()

    if (result.successfulAttempt && result.successfulAttempt > 1) {
      profile.retrySuccesses++
      // Update average success attempt
      profile.avgSuccessAttempt = (
        (profile.avgSuccessAttempt * (profile.retrySuccesses - 1) + result.successfulAttempt) /
        profile.retrySuccesses
      )
    }

    // Track error patterns
    if (result.errorPattern) {
      profile.errorPatterns[result.errorPattern] = (profile.errorPatterns[result.errorPattern] || 0) + 1
    }

    // Store recent result
    this._recentResults.push(result)
    if (this._recentResults.length > this._maxRecentResults) {
      this._recentResults.shift()
    }

    // Update optimal settings
    if (this.learningEnabled) {
      this._updateOptimalSettings(profile)
    }
  }

  /**
   * Get retry profile for a test
   */
  getProfile(testId) {
    return this._profiles.get(testId)
  }

  /**
   * Get retry success rate for a test
   */
  getRetrySuccessRate(testId) {
    const profile = this._profiles.get(testId)
    if (!profile || profile.totalRetries === 0) return 0.5 // Default assumption
    return profile.totalRuns > 0 ? profile.retrySuccesses / profile.totalRuns : 0
  }

  /**
   * Get recommended retry count for a test
   */
  getRecommendedRetries(testId) {
    const profile = this._profiles.get(testId)
    return profile ? profile.optimalRetryCount : this.defaultMaxRetries
  }

  _calculateOptimalDelay(profile) {
    // If test has high success on first retry, use shorter delays
    if (profile.avgSuccessAttempt < 1.5) return 500
    if (profile.avgSuccessAttempt < 2.5) return 1000
    return 2000
  }

  _estimateRetryTime(context) {
    const profile = this._profiles.get(context.testId)
    const maxRetries = profile ? profile.optimalRetryCount : this.defaultMaxRetries
    const remaining = maxRetries - context.currentAttempt

    // Estimate: avg test time * remaining retries + exponential backoff
    let estimated = context.durationMs * remaining
    for (let i = 0; i < remaining; i++) {
      estimated += 1000 * Math.pow(2, i)
    }
    return estimated
  }

  _updateOptimalSettings(profile) {
    // Adjust retry count based on success patterns
    if (profile.totalRuns >= 10) {
      const retrySuccessRate = profile.totalRuns > 0
        ? profile.retrySuccesses / profile.totalRuns
        : 0

      if (retrySuccessRate < 0.1) {
        profile.optimalRetryCount = 1
      } else if (retrySuccessRate < 0.3) {
        profile.optimalRetryCount = 2
      } else if (retrySuccessRate > 0.7) {
        profile.optimalRetryCount = 5
      } else {
        profile.optimalRetryCount = 3
      }

      // Adjust backoff based on success patterns
      if (profile.avgSuccessAttempt < 2) {
        profile.recommendedBackoff = BackoffType.FIXED
      } else if (profile.avgSuccessAttempt > 3) {
        profile.recommendedBackoff = BackoffType.EXPONENTIAL
      } else {
        profile.recommendedBackoff = BackoffType.LINEAR
      }
    }
  }

  /**
   * Get insights from retry patterns
   */
  getInsights() {
    if (this._profiles.size === 0) {
      return { message: 'No data collected yet' }
    }

    let totalRuns = 0
    let totalRetries = 0
    let totalSuccesses = 0
    const allErrors = {}

    for (const profile of this._profiles.values()) {
      totalRuns += profile.totalRuns
      totalRetries += profile.totalRetries
      totalSuccesses += profile.retrySuccesses

      for (const [error, count] of Object.entries(profile.errorPatterns)) {
        allErrors[error] = (allErrors[error] || 0) + count
      }
    }

    // Find most problematic tests
    const profiles = Array.from(this._profiles.values())
    const problematic = profiles
      .sort((a, b) => (b.totalRetries / Math.max(1, b.totalRuns)) - (a.totalRetries / Math.max(1, a.totalRuns)))
      .slice(0, 5)

    return {
      totalTestsTracked: this._profiles.size,
      totalRuns,
      totalRetries,
      retrySuccessRate: totalRuns > 0 ? totalSuccesses / totalRuns : 0,
      avgRetriesPerTest: totalRuns > 0 ? totalRetries / totalRuns : 0,
      mostProblematicTests: problematic.map(p => ({
        testId: p.testId,
        retryRate: p.totalRetries / Math.max(1, p.totalRuns)
      })),
      commonErrorPatterns: Object.fromEntries(
        Object.entries(allErrors).sort((a, b) => b[1] - a[1]).slice(0, 5)
      )
    }
  }

  /**
   * Format test profile as readable text
   */
  formatProfile(testId) {
    const profile = this._profiles.get(testId)
    if (!profile) return `No profile found for ${testId}`

    const lines = [
      '='.repeat(50),
      `  RETRY PROFILE: ${testId}`,
      '='.repeat(50),
      '',
      `  Total Runs: ${profile.totalRuns}`,
      `  Total Retries: ${profile.totalRetries}`,
      `  Retry Successes: ${profile.retrySuccesses}`,
      '',
      `  Optimal Retry Count: ${profile.optimalRetryCount}`,
      `  Recommended Backoff: ${profile.recommendedBackoff}`,
      `  Avg Success Attempt: ${profile.avgSuccessAttempt.toFixed(1)}`,
      ''
    ]

    if (Object.keys(profile.errorPatterns).length > 0) {
      lines.push('-'.repeat(50))
      lines.push('  ERROR PATTERNS')
      lines.push('-'.repeat(50))
      for (const [error, count] of Object.entries(profile.errorPatterns).sort((a, b) => b[1] - a[1])) {
        lines.push(`  • ${error}: ${count}`)
      }
    }

    lines.push('')
    lines.push('='.repeat(50))
    return lines.join('\n')
  }
}

/**
 * Quarantine Manager - isolates problematic tests
 */
class QuarantineManager {
  constructor(options = {}) {
    this.policy = {
      consecutiveFailuresThreshold: options.consecutiveFailuresThreshold || 5,
      flakinessRateThreshold: options.flakinessRateThreshold || 0.5,
      minRunsBeforeRelease: options.minRunsBeforeRelease || 10,
      monitoringPassRateThreshold: options.monitoringPassRateThreshold || 0.9,
      autoReleaseAfterDays: options.autoReleaseAfterDays || 7
    }

    this._quarantined = new Map()
    this._failureCounts = new Map()
    this._consecutiveFailures = new Map()
    this._runHistory = new Map()
  }

  /**
   * Quarantine a test
   */
  quarantine(testId, title, reason, options = {}) {
    const test = {
      testId,
      title,
      reason,
      status: QuarantineStatus.ACTIVE,
      quarantinedAt: new Date(),
      quarantinedBy: options.quarantinedBy || 'system',
      releaseConditions: options.releaseConditions || this._getDefaultConditions(reason),
      failureCount: this._failureCounts.get(testId) || 0,
      lastFailure: new Date(),
      notes: options.notes || '',
      monitoringStarted: null,
      monitoringRuns: 0,
      monitoringPasses: 0
    }

    this._quarantined.set(testId, test)
    return test
  }

  /**
   * Release a test from quarantine
   */
  release(testId, toMonitoring = true) {
    const test = this._quarantined.get(testId)
    if (!test) return null

    if (toMonitoring) {
      test.status = QuarantineStatus.MONITORING
      test.monitoringStarted = new Date()
      test.monitoringRuns = 0
      test.monitoringPasses = 0
    } else {
      test.status = QuarantineStatus.RELEASED
      this._failureCounts.delete(testId)
      this._consecutiveFailures.delete(testId)
      this._runHistory.delete(testId)
    }

    return test
  }

  /**
   * Record a test result and check quarantine status
   */
  recordResult(testId, passed, title = '') {
    // Update tracking
    if (passed) {
      this._consecutiveFailures.set(testId, 0)
    } else {
      this._failureCounts.set(testId, (this._failureCounts.get(testId) || 0) + 1)
      this._consecutiveFailures.set(testId, (this._consecutiveFailures.get(testId) || 0) + 1)
    }

    const history = this._runHistory.get(testId) || []
    history.push(passed)
    if (history.length > 100) history.shift()
    this._runHistory.set(testId, history)

    // Check if test is in monitoring
    const test = this._quarantined.get(testId)
    if (test && test.status === QuarantineStatus.MONITORING) {
      test.monitoringRuns++
      if (passed) test.monitoringPasses++

      if (this._shouldFullyRelease(test)) {
        test.status = QuarantineStatus.RELEASED
        return test
      }

      if (!passed && this._shouldRequarantine(test)) {
        test.status = QuarantineStatus.ACTIVE
        test.quarantinedAt = new Date()
        return test
      }

      return test
    }

    // Check if should auto-quarantine
    if (!test && this._shouldAutoQuarantine(testId)) {
      const reason = this._detectQuarantineReason(testId)
      return this.quarantine(testId, title || testId, reason)
    }

    return null
  }

  /**
   * Check if a test is currently quarantined
   */
  isQuarantined(testId) {
    const test = this._quarantined.get(testId)
    return test != null && test.status === QuarantineStatus.ACTIVE
  }

  /**
   * Check if a test is in monitoring status
   */
  isMonitoring(testId) {
    const test = this._quarantined.get(testId)
    return test != null && test.status === QuarantineStatus.MONITORING
  }

  /**
   * Get quarantined tests with optional filters
   */
  getQuarantinedTests(status = null, reason = null) {
    let tests = Array.from(this._quarantined.values())

    if (status) tests = tests.filter(t => t.status === status)
    if (reason) tests = tests.filter(t => t.reason === reason)

    return tests
  }

  /**
   * Get tests that might be ready for release
   */
  getReleaseCandidates() {
    const candidates = []

    for (const test of this._quarantined.values()) {
      if (test.status !== QuarantineStatus.ACTIVE) continue

      // Check auto-release time
      if (this.policy.autoReleaseAfterDays) {
        const age = (Date.now() - test.quarantinedAt.getTime()) / (1000 * 60 * 60 * 24)
        if (age >= this.policy.autoReleaseAfterDays) {
          candidates.push(test)
          continue
        }
      }

      // Check recent history
      const history = this._runHistory.get(test.testId) || []
      if (history.length >= this.policy.minRunsBeforeRelease) {
        const recent = history.slice(-this.policy.minRunsBeforeRelease)
        const passRate = recent.filter(Boolean).length / recent.length
        if (passRate >= this.policy.monitoringPassRateThreshold) {
          candidates.push(test)
        }
      }
    }

    return candidates
  }

  _shouldAutoQuarantine(testId) {
    // Check consecutive failures
    if ((this._consecutiveFailures.get(testId) || 0) >= this.policy.consecutiveFailuresThreshold) {
      return true
    }

    // Check flakiness rate
    const history = this._runHistory.get(testId) || []
    if (history.length >= 10) {
      const passRate = history.filter(Boolean).length / history.length
      if (passRate < (1 - this.policy.flakinessRateThreshold)) {
        return true
      }
    }

    return false
  }

  _shouldFullyRelease(test) {
    if (test.monitoringRuns < this.policy.minRunsBeforeRelease) return false
    const passRate = test.monitoringPasses / test.monitoringRuns
    return passRate >= this.policy.monitoringPassRateThreshold
  }

  _shouldRequarantine(test) {
    if (test.monitoringRuns < 3) return false
    const passRate = test.monitoringPasses / test.monitoringRuns
    return passRate < 0.5
  }

  _detectQuarantineReason(testId) {
    const history = this._runHistory.get(testId) || []
    if (!history.length) return QuarantineReason.CONSISTENTLY_FAILING

    const passRate = history.filter(Boolean).length / history.length

    if (passRate < 0.1) return QuarantineReason.CONSISTENTLY_FAILING
    if (passRate >= 0.3 && passRate <= 0.7) return QuarantineReason.EXTREMELY_FLAKY

    return QuarantineReason.CONSISTENTLY_FAILING
  }

  _getDefaultConditions(reason) {
    const conditions = {
      [QuarantineReason.CONSISTENTLY_FAILING]: [
        'Root cause identified and fixed',
        `Pass ${this.policy.minRunsBeforeRelease} consecutive runs`
      ],
      [QuarantineReason.EXTREMELY_FLAKY]: [
        'Flakiness root cause addressed',
        `Achieve ${Math.round(this.policy.monitoringPassRateThreshold * 100)}% pass rate over ${this.policy.minRunsBeforeRelease} runs`
      ],
      [QuarantineReason.ENVIRONMENT_DEPENDENT]: [
        'Environment dependencies documented',
        'Test can run reliably in CI'
      ],
      [QuarantineReason.RESOURCE_INTENSIVE]: [
        'Resource requirements reduced',
        'Or moved to nightly/weekly schedule'
      ],
      [QuarantineReason.TIMEOUT_PRONE]: [
        'Performance optimized',
        'Or timeout increased appropriately'
      ],
      [QuarantineReason.BLOCKING_CI]: [
        'Issue resolved',
        'CI pipeline stability confirmed'
      ]
    }

    return conditions[reason] || ['Manual review and approval']
  }

  /**
   * Get quarantine summary statistics
   */
  getSummary() {
    const active = Array.from(this._quarantined.values()).filter(t => t.status === QuarantineStatus.ACTIVE).length
    const monitoring = Array.from(this._quarantined.values()).filter(t => t.status === QuarantineStatus.MONITORING).length
    const released = Array.from(this._quarantined.values()).filter(t => t.status === QuarantineStatus.RELEASED).length

    const reasons = {}
    for (const test of this._quarantined.values()) {
      if (test.status === QuarantineStatus.ACTIVE) {
        reasons[test.reason] = (reasons[test.reason] || 0) + 1
      }
    }

    return {
      totalQuarantined: this._quarantined.size,
      active,
      monitoring,
      released,
      releaseCandidates: this.getReleaseCandidates().length,
      byReason: reasons
    }
  }

  /**
   * Format quarantine report as readable text
   */
  formatReport() {
    const summary = this.getSummary()

    const lines = [
      '='.repeat(60),
      '  QUARANTINE REPORT',
      '='.repeat(60),
      '',
      `  Active: ${summary.active}`,
      `  Monitoring: ${summary.monitoring}`,
      `  Released: ${summary.released}`,
      `  Release Candidates: ${summary.releaseCandidates}`,
      ''
    ]

    // By reason
    if (Object.keys(summary.byReason).length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  BY REASON')
      lines.push('-'.repeat(60))
      for (const [reason, count] of Object.entries(summary.byReason).sort()) {
        lines.push(`  • ${reason}: ${count}`)
      }
      lines.push('')
    }

    // Active quarantined tests
    const activeTests = this.getQuarantinedTests(QuarantineStatus.ACTIVE)
    if (activeTests.length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  ACTIVE QUARANTINE')
      lines.push('-'.repeat(60))
      for (const test of activeTests.sort((a, b) => a.quarantinedAt - b.quarantinedAt)) {
        const ageDays = Math.floor((Date.now() - test.quarantinedAt.getTime()) / (1000 * 60 * 60 * 24))
        lines.push(`\n  [${test.testId}] ${test.title}`)
        lines.push(`     Reason: ${test.reason}`)
        lines.push(`     Age: ${ageDays} days`)
        lines.push(`     Failures: ${test.failureCount}`)
      }
    }

    // Release candidates
    const candidates = this.getReleaseCandidates()
    if (candidates.length > 0) {
      lines.push('')
      lines.push('-'.repeat(60))
      lines.push('  RELEASE CANDIDATES')
      lines.push('-'.repeat(60))
      for (const test of candidates) {
        lines.push(`  • ${test.testId}: ${test.title}`)
      }
    }

    lines.push('')
    lines.push('='.repeat(60))
    return lines.join('\n')
  }
}

/**
 * Helper functions
 */
function createRetryStrategy(maxRetries = 3, backoffType = BackoffType.EXPONENTIAL, initialDelayMs = 1000) {
  const config = createRetryConfig({ maxRetries, backoffType, initialDelayMs })
  return new RetryStrategy(config)
}

function createAdaptiveRetryManager(defaultMaxRetries = 3, learningEnabled = true) {
  return new AdaptiveRetryManager({ defaultMaxRetries, learningEnabled })
}

function createQuarantineManager(policy = null) {
  return new QuarantineManager(policy || {})
}

module.exports = {
  // Backoff types
  BackoffType,
  RetryDecision,
  QuarantineReason,
  QuarantineStatus,

  // Retry Strategy
  RetryStrategy,
  createRetryStrategy,
  createRetryConfig,
  createRetryAttempt,
  createRetryResult,

  // Adaptive Retry Manager
  AdaptiveRetryManager,
  createAdaptiveRetryManager,

  // Quarantine Manager
  QuarantineManager,
  createQuarantineManager
}
