/**
 * Yali Agent - Coverage Analyzer
 * Ported from testai-agent/cortex/coverage_analyzer.py
 *
 * Identifies gaps in test coverage by comparing existing tests
 * against required testing rules for each page type.
 */

/**
 * Gap severity levels
 */
const GapSeverity = {
  CRITICAL: 'critical',  // Must fix before release
  HIGH: 'high',          // Should fix before release
  MEDIUM: 'medium',      // Fix in next sprint
  LOW: 'low'             // Nice to have
}

/**
 * Coverage categories
 */
const CoverageCategory = {
  SECURITY: 'security',
  FUNCTIONAL: 'functional',
  VALIDATION: 'validation',
  EDGE_CASE: 'edge_case',
  PERFORMANCE: 'performance',
  ACCESSIBILITY: 'accessibility',
  ERROR_HANDLING: 'error_handling',
  INTEGRATION: 'integration',
  USABILITY: 'usability',
  DATA_INTEGRITY: 'data_integrity'
}

/**
 * Required testing rules by page type
 */
const REQUIRED_RULES = {
  login: {
    [CoverageCategory.SECURITY]: [
      { id: 'SEC-001', title: 'SQL Injection Prevention', severity: GapSeverity.CRITICAL },
      { id: 'SEC-002', title: 'XSS Prevention', severity: GapSeverity.CRITICAL },
      { id: 'SEC-003', title: 'Brute Force Protection', severity: GapSeverity.CRITICAL },
      { id: 'SEC-004', title: 'Session Fixation Prevention', severity: GapSeverity.HIGH },
      { id: 'SEC-005', title: 'CSRF Token Validation', severity: GapSeverity.CRITICAL },
      { id: 'SEC-006', title: 'Secure Cookie Flags', severity: GapSeverity.HIGH },
      { id: 'SEC-007', title: 'Password Not Logged', severity: GapSeverity.CRITICAL }
    ],
    [CoverageCategory.VALIDATION]: [
      { id: 'VAL-001', title: 'Email Format Validation', severity: GapSeverity.HIGH },
      { id: 'VAL-002', title: 'Password Complexity Check', severity: GapSeverity.HIGH },
      { id: 'VAL-003', title: 'Empty Field Handling', severity: GapSeverity.HIGH },
      { id: 'VAL-004', title: 'Max Length Validation', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.FUNCTIONAL]: [
      { id: 'FUN-001', title: 'Successful Login Flow', severity: GapSeverity.CRITICAL },
      { id: 'FUN-002', title: 'Invalid Credentials Message', severity: GapSeverity.HIGH },
      { id: 'FUN-003', title: 'Remember Me Functionality', severity: GapSeverity.MEDIUM },
      { id: 'FUN-004', title: 'Forgot Password Link', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.ERROR_HANDLING]: [
      { id: 'ERR-001', title: 'Network Error Handling', severity: GapSeverity.HIGH },
      { id: 'ERR-002', title: 'Server Error Display', severity: GapSeverity.HIGH },
      { id: 'ERR-003', title: 'Session Timeout Handling', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.ACCESSIBILITY]: [
      { id: 'ACC-001', title: 'Keyboard Navigation', severity: GapSeverity.HIGH },
      { id: 'ACC-002', title: 'Screen Reader Labels', severity: GapSeverity.HIGH },
      { id: 'ACC-003', title: 'Focus Indicators', severity: GapSeverity.MEDIUM }
    ]
  },
  signup: {
    [CoverageCategory.SECURITY]: [
      { id: 'SEC-001', title: 'SQL Injection Prevention', severity: GapSeverity.CRITICAL },
      { id: 'SEC-002', title: 'XSS Prevention', severity: GapSeverity.CRITICAL },
      { id: 'SEC-008', title: 'Email Verification Required', severity: GapSeverity.HIGH },
      { id: 'SEC-009', title: 'Captcha Implementation', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.VALIDATION]: [
      { id: 'VAL-001', title: 'Email Format Validation', severity: GapSeverity.HIGH },
      { id: 'VAL-002', title: 'Password Complexity Check', severity: GapSeverity.HIGH },
      { id: 'VAL-005', title: 'Password Confirmation Match', severity: GapSeverity.HIGH },
      { id: 'VAL-006', title: 'Username Availability Check', severity: GapSeverity.MEDIUM },
      { id: 'VAL-007', title: 'Terms Acceptance Required', severity: GapSeverity.HIGH }
    ],
    [CoverageCategory.FUNCTIONAL]: [
      { id: 'FUN-005', title: 'Successful Registration Flow', severity: GapSeverity.CRITICAL },
      { id: 'FUN-006', title: 'Duplicate Email Prevention', severity: GapSeverity.HIGH },
      { id: 'FUN-007', title: 'Welcome Email Sent', severity: GapSeverity.MEDIUM }
    ]
  },
  checkout: {
    [CoverageCategory.SECURITY]: [
      { id: 'SEC-010', title: 'PCI Compliance', severity: GapSeverity.CRITICAL },
      { id: 'SEC-011', title: 'Payment Data Encryption', severity: GapSeverity.CRITICAL },
      { id: 'SEC-012', title: 'Address Validation', severity: GapSeverity.HIGH },
      { id: 'SEC-005', title: 'CSRF Token Validation', severity: GapSeverity.CRITICAL }
    ],
    [CoverageCategory.VALIDATION]: [
      { id: 'VAL-008', title: 'Card Number Validation', severity: GapSeverity.CRITICAL },
      { id: 'VAL-009', title: 'Expiry Date Validation', severity: GapSeverity.CRITICAL },
      { id: 'VAL-010', title: 'CVV Validation', severity: GapSeverity.CRITICAL },
      { id: 'VAL-011', title: 'Billing Address Required', severity: GapSeverity.HIGH }
    ],
    [CoverageCategory.FUNCTIONAL]: [
      { id: 'FUN-008', title: 'Successful Payment Flow', severity: GapSeverity.CRITICAL },
      { id: 'FUN-009', title: 'Order Confirmation', severity: GapSeverity.CRITICAL },
      { id: 'FUN-010', title: 'Cart Persistence', severity: GapSeverity.HIGH },
      { id: 'FUN-011', title: 'Price Calculation', severity: GapSeverity.CRITICAL }
    ],
    [CoverageCategory.DATA_INTEGRITY]: [
      { id: 'DAT-001', title: 'Double Payment Prevention', severity: GapSeverity.CRITICAL },
      { id: 'DAT-002', title: 'Stock Validation', severity: GapSeverity.HIGH },
      { id: 'DAT-003', title: 'Order Record Created', severity: GapSeverity.CRITICAL }
    ]
  },
  search: {
    [CoverageCategory.SECURITY]: [
      { id: 'SEC-001', title: 'SQL Injection Prevention', severity: GapSeverity.CRITICAL },
      { id: 'SEC-002', title: 'XSS Prevention', severity: GapSeverity.CRITICAL }
    ],
    [CoverageCategory.FUNCTIONAL]: [
      { id: 'FUN-012', title: 'Search Results Display', severity: GapSeverity.HIGH },
      { id: 'FUN-013', title: 'No Results Handling', severity: GapSeverity.MEDIUM },
      { id: 'FUN-014', title: 'Pagination Works', severity: GapSeverity.MEDIUM },
      { id: 'FUN-015', title: 'Filters Work', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.PERFORMANCE]: [
      { id: 'PER-001', title: 'Search Response Time', severity: GapSeverity.HIGH },
      { id: 'PER-002', title: 'Large Result Set Handling', severity: GapSeverity.MEDIUM }
    ]
  },
  form: {
    [CoverageCategory.VALIDATION]: [
      { id: 'VAL-003', title: 'Empty Field Handling', severity: GapSeverity.HIGH },
      { id: 'VAL-004', title: 'Max Length Validation', severity: GapSeverity.MEDIUM },
      { id: 'VAL-012', title: 'Required Field Indicators', severity: GapSeverity.HIGH }
    ],
    [CoverageCategory.FUNCTIONAL]: [
      { id: 'FUN-016', title: 'Form Submission Success', severity: GapSeverity.HIGH },
      { id: 'FUN-017', title: 'Error Display', severity: GapSeverity.HIGH },
      { id: 'FUN-018', title: 'Data Persistence on Error', severity: GapSeverity.MEDIUM }
    ],
    [CoverageCategory.ACCESSIBILITY]: [
      { id: 'ACC-001', title: 'Keyboard Navigation', severity: GapSeverity.HIGH },
      { id: 'ACC-004', title: 'Error Announcements', severity: GapSeverity.MEDIUM }
    ]
  }
}

/**
 * Create a coverage gap object
 */
function createGap(ruleId, title, category, severity, description = '', recommendation = '') {
  return {
    ruleId,
    title,
    category,
    severity,
    description,
    recommendation,
    isAddressed: false
  }
}

/**
 * Create a coverage report
 */
function createCoverageReport(pageType, gaps, coveredRules, totalRules) {
  const coveragePercent = totalRules > 0
    ? Math.round((coveredRules / totalRules) * 100)
    : 0

  const gapsBySeverity = {
    [GapSeverity.CRITICAL]: gaps.filter(g => g.severity === GapSeverity.CRITICAL),
    [GapSeverity.HIGH]: gaps.filter(g => g.severity === GapSeverity.HIGH),
    [GapSeverity.MEDIUM]: gaps.filter(g => g.severity === GapSeverity.MEDIUM),
    [GapSeverity.LOW]: gaps.filter(g => g.severity === GapSeverity.LOW)
  }

  const gapsByCategory = {}
  for (const gap of gaps) {
    if (!gapsByCategory[gap.category]) {
      gapsByCategory[gap.category] = []
    }
    gapsByCategory[gap.category].push(gap)
  }

  return {
    pageType,
    coveragePercent,
    totalRules,
    coveredRules,
    gaps,
    gapsBySeverity,
    gapsByCategory,
    timestamp: new Date().toISOString(),

    get hasCriticalGaps() {
      return gapsBySeverity[GapSeverity.CRITICAL].length > 0
    },

    get isReadyForRelease() {
      return gapsBySeverity[GapSeverity.CRITICAL].length === 0 &&
             gapsBySeverity[GapSeverity.HIGH].length === 0
    },

    getSummary() {
      const lines = []
      lines.push(`Coverage Report: ${pageType}`)
      lines.push('='.repeat(40))
      lines.push(`Coverage: ${coveragePercent}% (${coveredRules}/${totalRules} rules)`)
      lines.push('')
      lines.push('Gaps by Severity:')
      lines.push(`  🔴 Critical: ${gapsBySeverity[GapSeverity.CRITICAL].length}`)
      lines.push(`  🟠 High: ${gapsBySeverity[GapSeverity.HIGH].length}`)
      lines.push(`  🟡 Medium: ${gapsBySeverity[GapSeverity.MEDIUM].length}`)
      lines.push(`  🟢 Low: ${gapsBySeverity[GapSeverity.LOW].length}`)
      lines.push('')
      lines.push(`Release Ready: ${this.isReadyForRelease ? 'Yes ✓' : 'No ✗'}`)
      return lines.join('\n')
    }
  }
}

/**
 * Coverage Analyzer class
 */
class CoverageAnalyzer {
  constructor() {
    this.registeredTests = new Map() // Map<pageType, Set<ruleId>>
  }

  /**
   * Register a test as covering specific rules
   */
  registerTest(pageType, ruleIds) {
    if (!this.registeredTests.has(pageType)) {
      this.registeredTests.set(pageType, new Set())
    }
    const covered = this.registeredTests.get(pageType)
    for (const ruleId of ruleIds) {
      covered.add(ruleId)
    }
  }

  /**
   * Register tests from test cases array
   */
  registerTestCases(pageType, testCases) {
    for (const test of testCases) {
      // Try to match test to rules based on keywords
      const matchedRules = this._matchTestToRules(test, pageType)
      this.registerTest(pageType, matchedRules)
    }
  }

  /**
   * Match a test case to coverage rules
   */
  _matchTestToRules(test, pageType) {
    const matchedRules = []
    const rules = REQUIRED_RULES[pageType] || {}

    const testText = [
      test.title || test.name || '',
      test.description || '',
      test.category || '',
      Array.isArray(test.steps) ? test.steps.join(' ') : ''
    ].join(' ').toLowerCase()

    // Check each category's rules
    for (const [category, categoryRules] of Object.entries(rules)) {
      for (const rule of categoryRules) {
        const ruleKeywords = rule.title.toLowerCase().split(/\s+/)
        const matches = ruleKeywords.filter(kw => testText.includes(kw))

        // If more than half the keywords match, consider it covered
        if (matches.length >= Math.ceil(ruleKeywords.length / 2)) {
          matchedRules.push(rule.id)
        }
      }
    }

    return matchedRules
  }

  /**
   * Analyze coverage for a page type
   */
  analyzeCoverage(pageType, existingTests = []) {
    // Register any provided tests
    if (existingTests.length > 0) {
      this.registerTestCases(pageType, existingTests)
    }

    const rules = REQUIRED_RULES[pageType] || REQUIRED_RULES.form // Default to form rules
    const covered = this.registeredTests.get(pageType) || new Set()

    const gaps = []
    let totalRules = 0

    // Check each category
    for (const [category, categoryRules] of Object.entries(rules)) {
      for (const rule of categoryRules) {
        totalRules++

        if (!covered.has(rule.id)) {
          // Generate recommendation based on category
          const recommendation = this._getRecommendation(rule, category, pageType)

          gaps.push(createGap(
            rule.id,
            rule.title,
            category,
            rule.severity,
            `Missing test coverage for: ${rule.title}`,
            recommendation
          ))
        }
      }
    }

    const coveredCount = totalRules - gaps.length

    return createCoverageReport(pageType, gaps, coveredCount, totalRules)
  }

  /**
   * Get recommendation for addressing a gap
   */
  _getRecommendation(rule, category, pageType) {
    const recommendations = {
      [CoverageCategory.SECURITY]: `Add security test for ${rule.title}. Use payloads from OWASP testing guide.`,
      [CoverageCategory.VALIDATION]: `Add input validation test for ${rule.title}. Test boundary values and invalid inputs.`,
      [CoverageCategory.FUNCTIONAL]: `Add functional test verifying ${rule.title} works as expected.`,
      [CoverageCategory.ERROR_HANDLING]: `Add error handling test for ${rule.title}. Simulate failure conditions.`,
      [CoverageCategory.ACCESSIBILITY]: `Add accessibility test for ${rule.title}. Use screen reader and keyboard only.`,
      [CoverageCategory.PERFORMANCE]: `Add performance test measuring ${rule.title}. Set acceptable thresholds.`,
      [CoverageCategory.DATA_INTEGRITY]: `Add data integrity test for ${rule.title}. Verify data consistency.`
    }

    return recommendations[category] || `Add test coverage for ${rule.title}.`
  }

  /**
   * Generate a detailed gap report
   */
  generateGapReport(pageType, existingTests = []) {
    const report = this.analyzeCoverage(pageType, existingTests)
    const lines = []

    lines.push('# Coverage Gap Report')
    lines.push(`**Page Type:** ${pageType}`)
    lines.push(`**Coverage:** ${report.coveragePercent}%`)
    lines.push(`**Generated:** ${report.timestamp}`)
    lines.push('')

    if (report.hasCriticalGaps) {
      lines.push('⚠️ **WARNING: Critical gaps detected!**')
      lines.push('')
    }

    // Critical gaps first
    if (report.gapsBySeverity[GapSeverity.CRITICAL].length > 0) {
      lines.push('## 🔴 Critical Gaps')
      for (const gap of report.gapsBySeverity[GapSeverity.CRITICAL]) {
        lines.push(`- **${gap.ruleId}**: ${gap.title}`)
        lines.push(`  - ${gap.description}`)
        lines.push(`  - *Recommendation:* ${gap.recommendation}`)
      }
      lines.push('')
    }

    // High gaps
    if (report.gapsBySeverity[GapSeverity.HIGH].length > 0) {
      lines.push('## 🟠 High Priority Gaps')
      for (const gap of report.gapsBySeverity[GapSeverity.HIGH]) {
        lines.push(`- **${gap.ruleId}**: ${gap.title}`)
        lines.push(`  - *Recommendation:* ${gap.recommendation}`)
      }
      lines.push('')
    }

    // Medium and low summarized
    const mediumLow = [
      ...report.gapsBySeverity[GapSeverity.MEDIUM],
      ...report.gapsBySeverity[GapSeverity.LOW]
    ]
    if (mediumLow.length > 0) {
      lines.push('## 🟡 Medium/Low Priority Gaps')
      for (const gap of mediumLow) {
        lines.push(`- ${gap.ruleId}: ${gap.title} (${gap.severity})`)
      }
    }

    return lines.join('\n')
  }

  /**
   * Get required rules for a page type
   */
  getRequiredRules(pageType) {
    return REQUIRED_RULES[pageType] || REQUIRED_RULES.form
  }

  /**
   * Clear registered tests
   */
  clear() {
    this.registeredTests.clear()
  }
}

/**
 * Quick coverage check
 */
function quickCoverageCheck(pageType, tests = []) {
  const analyzer = new CoverageAnalyzer()
  return analyzer.analyzeCoverage(pageType, tests)
}

module.exports = {
  GapSeverity,
  CoverageCategory,
  REQUIRED_RULES,
  CoverageAnalyzer,
  createGap,
  createCoverageReport,
  quickCoverageCheck
}
