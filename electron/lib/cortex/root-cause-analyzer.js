/**
 * Yali Agent - Root Cause Analyzer
 * Ported from testai-agent/analysis/root_cause.py
 *
 * Analyzes test failures to identify root causes using
 * pattern recognition and historical data.
 * Think like a detective finding the real cause of failures.
 */

/**
 * Categories of test failures
 */
const FailureCategory = {
  ASSERTION: 'assertion',
  TIMEOUT: 'timeout',
  ELEMENT_NOT_FOUND: 'element_not_found',
  NETWORK: 'network',
  AUTHENTICATION: 'authentication',
  DATA_MISMATCH: 'data_mismatch',
  STATE_CORRUPTION: 'state_corruption',
  RACE_CONDITION: 'race_condition',
  RESOURCE_EXHAUSTION: 'resource_exhaustion',
  CONFIGURATION: 'configuration',
  DEPENDENCY: 'dependency',
  ENVIRONMENT: 'environment',
  UNKNOWN: 'unknown'
}

/**
 * Severity levels for failures
 */
const FailureSeverity = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
}

/**
 * Error patterns for classification
 */
const ERROR_PATTERNS = {
  [FailureCategory.ASSERTION]: [
    /assert(ion)?.*failed/i,
    /expected.*but (got|was|received)/i,
    /not equal/i,
    /should (be|have|equal|match)/i,
    /does not match/i
  ],
  [FailureCategory.TIMEOUT]: [
    /timeout/i,
    /timed? out/i,
    /exceeded.*time/i,
    /wait.*expired/i,
    /deadline/i
  ],
  [FailureCategory.ELEMENT_NOT_FOUND]: [
    /element.*not.*found/i,
    /no such element/i,
    /unable to locate/i,
    /selector.*not.*found/i,
    /cannot find.*element/i,
    /NoSuchElementException/i
  ],
  [FailureCategory.NETWORK]: [
    /connection.*refused/i,
    /connection.*reset/i,
    /network.*error/i,
    /ECONNREFUSED/i,
    /ERR_CONNECTION/i,
    /socket.*error/i,
    /dns.*failed/i
  ],
  [FailureCategory.AUTHENTICATION]: [
    /unauthorized/i,
    /authentication.*failed/i,
    /invalid.*token/i,
    /session.*expired/i,
    /access.*denied/i,
    /forbidden/i,
    /401/,
    /403/
  ],
  [FailureCategory.DATA_MISMATCH]: [
    /data.*mismatch/i,
    /unexpected.*value/i,
    /invalid.*data/i,
    /schema.*validation/i,
    /type.*error/i
  ],
  [FailureCategory.STATE_CORRUPTION]: [
    /state.*corrupt/i,
    /inconsistent.*state/i,
    /invalid.*state/i,
    /state.*transition/i
  ],
  [FailureCategory.RACE_CONDITION]: [
    /race.*condition/i,
    /concurrent/i,
    /deadlock/i,
    /stale.*element/i,
    /element.*stale/i,
    /element.*detached/i,
    /StaleElementReferenceException/i
  ],
  [FailureCategory.RESOURCE_EXHAUSTION]: [
    /out of memory/i,
    /memory.*exceeded/i,
    /resource.*exhausted/i,
    /too many.*connections/i,
    /quota.*exceeded/i
  ],
  [FailureCategory.CONFIGURATION]: [
    /config.*error/i,
    /missing.*config/i,
    /invalid.*setting/i,
    /environment.*variable/i
  ],
  [FailureCategory.DEPENDENCY]: [
    /dependency.*failed/i,
    /service.*unavailable/i,
    /upstream.*error/i,
    /external.*service/i
  ],
  [FailureCategory.ENVIRONMENT]: [
    /environment.*error/i,
    /platform.*specific/i,
    /os.*error/i,
    /permission.*denied/i
  ]
}

/**
 * Fix suggestions by category
 */
const FIX_SUGGESTIONS = {
  [FailureCategory.ASSERTION]: [
    'Verify expected values match current system state',
    'Check for recent data changes that may affect assertions',
    'Review test data setup for correctness',
    'Consider adding tolerance for floating-point comparisons'
  ],
  [FailureCategory.TIMEOUT]: [
    'Increase timeout value if legitimate slowness',
    'Add explicit waits for asynchronous operations',
    'Check for performance regression in the application',
    'Review network conditions and server load'
  ],
  [FailureCategory.ELEMENT_NOT_FOUND]: [
    'Verify selector is still valid after UI changes',
    'Add wait for element visibility before interaction',
    'Check if element is inside iframe or shadow DOM',
    'Review dynamic content loading timing'
  ],
  [FailureCategory.NETWORK]: [
    'Verify service is running and accessible',
    'Check network configuration and firewall rules',
    'Add retry logic for transient failures',
    'Review DNS resolution and connectivity'
  ],
  [FailureCategory.AUTHENTICATION]: [
    'Verify credentials are current and valid',
    'Check token expiration and refresh logic',
    'Review session management configuration',
    'Ensure proper headers are being sent'
  ],
  [FailureCategory.DATA_MISMATCH]: [
    'Verify test data matches expected schema',
    'Check for data type conversions',
    'Review API response format changes',
    'Validate data transformation logic'
  ],
  [FailureCategory.STATE_CORRUPTION]: [
    'Add test isolation to prevent shared state issues',
    'Review setup and teardown procedures',
    'Check for parallel test interference',
    'Implement proper state reset between tests'
  ],
  [FailureCategory.RACE_CONDITION]: [
    'Add proper synchronization mechanisms',
    'Use explicit waits for element stability',
    'Review parallel evaluation configuration',
    'Implement retry for stale element references'
  ],
  [FailureCategory.RESOURCE_EXHAUSTION]: [
    'Review memory usage and leaks',
    'Implement proper resource cleanup',
    'Reduce test parallelism if needed',
    'Monitor system resources during test runs'
  ],
  [FailureCategory.CONFIGURATION]: [
    'Verify configuration file exists and is valid',
    'Check environment variables are set',
    'Review default value handling',
    'Validate configuration against schema'
  ],
  [FailureCategory.DEPENDENCY]: [
    'Verify external services are available',
    'Implement service health checks',
    'Add retry logic for external calls',
    'Consider using mocks for reliability'
  ],
  [FailureCategory.ENVIRONMENT]: [
    'Check platform-specific requirements',
    'Verify file and directory permissions',
    'Review OS-specific path handling',
    'Ensure consistent environment setup'
  ]
}

/**
 * Severity mapping by category
 */
const SEVERITY_BY_CATEGORY = {
  [FailureCategory.AUTHENTICATION]: FailureSeverity.CRITICAL,
  [FailureCategory.STATE_CORRUPTION]: FailureSeverity.CRITICAL,
  [FailureCategory.RESOURCE_EXHAUSTION]: FailureSeverity.CRITICAL,
  [FailureCategory.NETWORK]: FailureSeverity.HIGH,
  [FailureCategory.DEPENDENCY]: FailureSeverity.HIGH,
  [FailureCategory.RACE_CONDITION]: FailureSeverity.HIGH,
  [FailureCategory.TIMEOUT]: FailureSeverity.MEDIUM,
  [FailureCategory.ELEMENT_NOT_FOUND]: FailureSeverity.MEDIUM,
  [FailureCategory.DATA_MISMATCH]: FailureSeverity.MEDIUM,
  [FailureCategory.ASSERTION]: FailureSeverity.LOW,
  [FailureCategory.CONFIGURATION]: FailureSeverity.LOW,
  [FailureCategory.ENVIRONMENT]: FailureSeverity.LOW,
  [FailureCategory.UNKNOWN]: FailureSeverity.LOW
}

/**
 * Category descriptions
 */
const CATEGORY_DESCRIPTIONS = {
  [FailureCategory.ASSERTION]: 'Test assertion failed - actual value doesn\'t match expected',
  [FailureCategory.TIMEOUT]: 'Operation exceeded time limit',
  [FailureCategory.ELEMENT_NOT_FOUND]: 'UI element could not be located on the page',
  [FailureCategory.NETWORK]: 'Network communication error occurred',
  [FailureCategory.AUTHENTICATION]: 'Authentication or authorization failure',
  [FailureCategory.DATA_MISMATCH]: 'Data validation or schema mismatch detected',
  [FailureCategory.STATE_CORRUPTION]: 'Application state is inconsistent or corrupted',
  [FailureCategory.RACE_CONDITION]: 'Timing-related issue or concurrent access problem',
  [FailureCategory.RESOURCE_EXHAUSTION]: 'System resources depleted',
  [FailureCategory.CONFIGURATION]: 'Configuration or settings error',
  [FailureCategory.DEPENDENCY]: 'External dependency or service failure',
  [FailureCategory.ENVIRONMENT]: 'Environment-specific issue detected',
  [FailureCategory.UNKNOWN]: 'Unable to classify failure - manual investigation needed'
}

/**
 * Create a root cause
 */
function createRootCause(testId, category, options = {}) {
  return {
    causeId: `RC_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    testId,
    category,
    severity: options.severity || SEVERITY_BY_CATEGORY[category] || FailureSeverity.MEDIUM,
    description: options.description || CATEGORY_DESCRIPTIONS[category],
    confidence: options.confidence || 0.7,
    evidence: options.evidence || [],
    suggestedFixes: options.suggestedFixes || FIX_SUGGESTIONS[category] || [],
    relatedTests: options.relatedTests || [],
    codeLocations: options.codeLocations || [],
    timestamp: Date.now()
  }
}

/**
 * Create a failure pattern
 */
function createFailurePattern(name, description, category, indicators) {
  return {
    patternId: `PAT_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    name,
    description,
    category,
    indicators,
    frequency: 0,
    lastSeen: null
  }
}

/**
 * Create a failure analysis result
 */
function createAnalysisResult(testId, errorMessage, options = {}) {
  return {
    testId,
    errorMessage,
    stackTrace: options.stackTrace || null,
    rootCauses: options.rootCauses || [],
    patternsMatched: options.patternsMatched || [],
    historicalOccurrences: options.historicalOccurrences || 0,
    similarFailures: options.similarFailures || [],
    recommendedPriority: options.recommendedPriority || 'medium',
    analyzedAt: Date.now()
  }
}

/**
 * Root Cause Analyzer class
 */
class RootCauseAnalyzer {
  constructor() {
    this.patterns = new Map()
    this.failureHistory = new Map()
  }

  /**
   * Analyze a test failure to identify root causes
   */
  analyze(testId, errorMessage, stackTrace = null, context = {}) {
    const categories = this._classifyError(errorMessage, stackTrace)
    const rootCauses = []

    for (const { category, confidence } of categories) {
      const cause = createRootCause(testId, category, {
        severity: SEVERITY_BY_CATEGORY[category],
        description: this._generateDescription(category, errorMessage),
        confidence,
        evidence: this._extractEvidence(errorMessage, stackTrace),
        suggestedFixes: FIX_SUGGESTIONS[category] || [],
        relatedTests: this._findRelatedTests(testId, category),
        codeLocations: this._extractCodeLocations(stackTrace)
      })
      rootCauses.push(cause)

      if (!this.failureHistory.has(testId)) {
        this.failureHistory.set(testId, [])
      }
      this.failureHistory.get(testId).push(cause)
    }

    const matchedPatterns = this._matchPatterns(errorMessage, stackTrace)
    const similar = this._findSimilarFailures(errorMessage, categories)
    const historyCount = (this.failureHistory.get(testId) || []).length

    return createAnalysisResult(testId, errorMessage, {
      stackTrace,
      rootCauses,
      patternsMatched: matchedPatterns,
      historicalOccurrences: historyCount,
      similarFailures: similar,
      recommendedPriority: this._recommendPriority(rootCauses)
    })
  }

  _classifyError(errorMessage, stackTrace) {
    const combined = errorMessage + (stackTrace || '')
    const matches = []

    for (const [category, patterns] of Object.entries(ERROR_PATTERNS)) {
      let matchCount = 0
      for (const pattern of patterns) {
        if (pattern.test(combined)) {
          matchCount++
        }
      }

      if (matchCount > 0) {
        const confidence = Math.min(0.95, 0.5 + (matchCount / patterns.length) * 0.45)
        matches.push({ category, confidence })
      }
    }

    matches.sort((a, b) => b.confidence - a.confidence)

    if (matches.length === 0) {
      matches.push({ category: FailureCategory.UNKNOWN, confidence: 0.3 })
    }

    return matches.slice(0, 3)
  }

  _generateDescription(category, errorMessage) {
    const baseDescription = CATEGORY_DESCRIPTIONS[category]
    const keyInfo = errorMessage.slice(0, 100)
    return `${baseDescription}. ${keyInfo}`
  }

  _extractEvidence(errorMessage, stackTrace) {
    const evidence = [`Error: ${errorMessage.slice(0, 200)}`]

    if (stackTrace) {
      const lines = stackTrace.split('\n')
      const relevant = lines
        .filter(line => line.trim() && !line.trim().startsWith('at '))
        .slice(0, 3)
      evidence.push(...relevant)
    }

    return evidence
  }

  _extractCodeLocations(stackTrace) {
    if (!stackTrace) return []

    const locations = []
    const patterns = [
      /at\s+.*\((.*?):(\d+)\)/g,
      /([\w./\\]+):(\d+)/g,
      /File "(.*?)", line (\d+)/g
    ]

    for (const pattern of patterns) {
      let match
      while ((match = pattern.exec(stackTrace)) !== null) {
        locations.push(`${match[1]}:${match[2]}`)
      }
    }

    return [...new Set(locations)].slice(0, 5)
  }

  _findRelatedTests(testId, category) {
    const related = []

    for (const [tid, causes] of this.failureHistory) {
      if (tid === testId) continue
      for (const cause of causes) {
        if (cause.category === category) {
          related.push(tid)
          break
        }
      }
    }

    return related.slice(0, 5)
  }

  _matchPatterns(errorMessage, stackTrace) {
    const matched = []
    const combined = (errorMessage + (stackTrace || '')).toLowerCase()

    for (const pattern of this.patterns.values()) {
      for (const indicator of pattern.indicators) {
        if (combined.includes(indicator.toLowerCase())) {
          pattern.frequency++
          pattern.lastSeen = Date.now()
          matched.push(pattern)
          break
        }
      }
    }

    return matched
  }

  _findSimilarFailures(errorMessage, categories) {
    const similar = []
    const primaryCategory = categories[0]?.category || FailureCategory.UNKNOWN

    for (const [testId, causes] of this.failureHistory) {
      for (const cause of causes) {
        if (cause.category === primaryCategory) {
          similar.push(testId)
          break
        }
      }
    }

    return [...new Set(similar)].slice(0, 10)
  }

  _recommendPriority(rootCauses) {
    if (!rootCauses.length) return 'low'

    const severities = rootCauses.map(c => c.severity)

    if (severities.includes(FailureSeverity.CRITICAL)) return 'critical'
    if (severities.includes(FailureSeverity.HIGH)) return 'high'
    if (severities.includes(FailureSeverity.MEDIUM)) return 'medium'
    return 'low'
  }

  registerPattern(name, description, category, indicators) {
    const pattern = createFailurePattern(name, description, category, indicators)
    this.patterns.set(pattern.patternId, pattern)
    return pattern
  }

  getFailureTrends(testId = null) {
    let history
    if (testId) {
      history = this.failureHistory.get(testId) || []
    } else {
      history = []
      for (const causes of this.failureHistory.values()) {
        history.push(...causes)
      }
    }

    if (!history.length) {
      return {
        totalFailures: 0,
        categoryDistribution: {},
        severityDistribution: {},
        topPatterns: []
      }
    }

    const categoryDist = {}
    for (const cause of history) {
      categoryDist[cause.category] = (categoryDist[cause.category] || 0) + 1
    }

    const severityDist = {}
    for (const cause of history) {
      severityDist[cause.severity] = (severityDist[cause.severity] || 0) + 1
    }

    const patternList = Array.from(this.patterns.values())
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 5)

    return {
      totalFailures: history.length,
      categoryDistribution: categoryDist,
      severityDistribution: severityDist,
      topPatterns: patternList.map(p => ({
        name: p.name,
        frequency: p.frequency
      }))
    }
  }

  formatAnalysis(analysis) {
    const lines = [
      '═'.repeat(60),
      '  ROOT CAUSE ANALYSIS',
      '═'.repeat(60),
      '',
      `  Test: ${analysis.testId}`,
      `  Priority: ${analysis.recommendedPriority.toUpperCase()}`,
      `  Historical Occurrences: ${analysis.historicalOccurrences}`,
      '',
      '─'.repeat(60),
      '  ERROR MESSAGE',
      '─'.repeat(60),
      `  ${analysis.errorMessage.slice(0, 200)}`,
      ''
    ]

    lines.push('─'.repeat(60), '  ROOT CAUSES', '─'.repeat(60))

    for (let i = 0; i < analysis.rootCauses.length; i++) {
      const cause = analysis.rootCauses[i]
      lines.push(
        '',
        `  ${i + 1}. ${cause.category.toUpperCase()} (Confidence: ${(cause.confidence * 100).toFixed(0)}%)`,
        `     Severity: ${cause.severity}`,
        `     ${cause.description}`
      )

      if (cause.evidence.length > 0) {
        lines.push('     Evidence:')
        for (const ev of cause.evidence.slice(0, 2)) {
          lines.push(`       - ${ev.slice(0, 80)}`)
        }
      }

      if (cause.codeLocations.length > 0) {
        lines.push('     Locations:')
        for (const loc of cause.codeLocations.slice(0, 2)) {
          lines.push(`       - ${loc}`)
        }
      }
    }

    if (analysis.rootCauses.length > 0) {
      lines.push('', '─'.repeat(60), '  SUGGESTED FIXES', '─'.repeat(60))
      const seenFixes = new Set()
      for (const cause of analysis.rootCauses) {
        for (const fix of cause.suggestedFixes.slice(0, 2)) {
          if (!seenFixes.has(fix)) {
            lines.push(`  - ${fix}`)
            seenFixes.add(fix)
          }
        }
      }
    }

    if (analysis.similarFailures.length > 0) {
      lines.push('', '─'.repeat(60), '  SIMILAR FAILURES', '─'.repeat(60))
      for (const test of analysis.similarFailures.slice(0, 5)) {
        lines.push(`  - ${test}`)
      }
    }

    lines.push('', '═'.repeat(60))
    return lines.join('\n')
  }

  clear() {
    this.patterns.clear()
    this.failureHistory.clear()
  }
}

function createRootCauseAnalyzer() {
  return new RootCauseAnalyzer()
}

function quickAnalyze(testId, errorMessage, stackTrace = null) {
  const analyzer = new RootCauseAnalyzer()
  return analyzer.analyze(testId, errorMessage, stackTrace)
}

module.exports = {
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
}
