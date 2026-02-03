/**
 * Yali Agent - Smart Test Prioritization
 * Ported from testai-agent/cortex/prioritizer.py
 *
 * Prioritizes test cases based on risk, not just arbitrary labels.
 *
 * Key factors:
 * 1. Security impact (highest weight)
 * 2. User impact (how many users affected)
 * 3. Business impact (revenue, reputation)
 * 4. Failure probability (based on complexity)
 * 5. Historical data (if available)
 *
 * Design: Thorough but pragmatic QA philosophy.
 */

/**
 * Factors that affect test priority
 */
const RiskFactor = {
  SECURITY: 'security',           // Security vulnerabilities
  DATA_LOSS: 'data_loss',         // Potential data loss
  REVENUE: 'revenue',             // Revenue impact
  USER_FRICTION: 'user_friction', // User experience
  COMPLIANCE: 'compliance',       // Legal/regulatory
  REPUTATION: 'reputation',       // Brand damage
  COMPLEXITY: 'complexity'        // Implementation complexity
}

/**
 * Test priority levels
 */
const Priority = {
  CRITICAL: 'critical',   // Must pass before release
  HIGH: 'high',           // Should pass before release
  MEDIUM: 'medium',       // Can release with known issue
  LOW: 'low'              // Nice to have
}

/**
 * Risk score weights
 */
const RISK_WEIGHTS = {
  security: 0.30,
  data_loss: 0.25,
  revenue: 0.15,
  user_impact: 0.15,
  compliance: 0.10,
  complexity: 0.05
}

/**
 * Keywords that indicate high security risk
 */
const SECURITY_KEYWORDS = [
  'injection', 'xss', 'csrf', 'sql', 'authentication', 'authorization',
  'password', 'token', 'session', 'cookie', 'bypass', 'privilege',
  'escalation', 'access control', 'encryption', 'certificate', 'tls',
  'ssl', 'api key', 'secret', 'credential', 'vulnerability', 'attack'
]

/**
 * Keywords that indicate data loss risk
 */
const DATA_LOSS_KEYWORDS = [
  'delete', 'remove', 'clear', 'reset', 'destroy', 'drop', 'truncate',
  'overwrite', 'modify', 'update', 'save', 'submit', 'commit', 'transfer',
  'payment', 'transaction', 'order', 'purchase'
]

/**
 * Keywords that indicate revenue impact
 */
const REVENUE_KEYWORDS = [
  'checkout', 'payment', 'cart', 'purchase', 'order', 'subscription',
  'billing', 'invoice', 'pricing', 'discount', 'coupon', 'refund',
  'transaction', 'credit', 'debit'
]

/**
 * Keywords that indicate user friction
 */
const USER_FRICTION_KEYWORDS = [
  'login', 'signup', 'register', 'onboarding', 'navigation', 'search',
  'filter', 'form', 'validation', 'error', 'message', 'notification',
  'loading', 'timeout', 'performance'
]

/**
 * Keywords that indicate compliance requirements
 */
const COMPLIANCE_KEYWORDS = [
  'gdpr', 'ccpa', 'hipaa', 'pci', 'privacy', 'consent', 'opt-in',
  'opt-out', 'unsubscribe', 'accessibility', 'wcag', 'ada', 'audit'
]

/**
 * Page type risk multipliers
 */
const PAGE_TYPE_RISK = {
  checkout: 1.3,     // High risk - money involved
  payment: 1.3,
  login: 1.2,        // Medium-high - security
  signup: 1.1,       // Medium - user acquisition
  profile: 1.0,      // Normal
  settings: 1.0,
  search: 0.9,       // Lower - read-only
  dashboard: 0.9,
  form: 1.0
}

/**
 * Create a risk assessment
 */
function createRiskAssessment(scores = {}) {
  const assessment = {
    securityScore: scores.security || 0,
    dataLossScore: scores.dataLoss || 0,
    revenueScore: scores.revenue || 0,
    userImpactScore: scores.userImpact || 0,
    complianceScore: scores.compliance || 0,
    complexityScore: scores.complexity || 0,

    get totalScore() {
      return (
        this.securityScore * RISK_WEIGHTS.security +
        this.dataLossScore * RISK_WEIGHTS.data_loss +
        this.revenueScore * RISK_WEIGHTS.revenue +
        this.userImpactScore * RISK_WEIGHTS.user_impact +
        this.complianceScore * RISK_WEIGHTS.compliance +
        this.complexityScore * RISK_WEIGHTS.complexity
      )
    },

    get priority() {
      const score = this.totalScore
      if (score >= 0.7) return Priority.CRITICAL
      if (score >= 0.5) return Priority.HIGH
      if (score >= 0.3) return Priority.MEDIUM
      return Priority.LOW
    },

    get reasoning() {
      const factors = []

      if (this.securityScore >= 0.7) factors.push('high security risk')
      if (this.dataLossScore >= 0.7) factors.push('potential data loss')
      if (this.revenueScore >= 0.7) factors.push('revenue impact')
      if (this.complianceScore >= 0.7) factors.push('compliance requirement')

      if (factors.length === 0) {
        if (this.totalScore >= 0.5) {
          factors.push('moderate combined risk')
        } else {
          factors.push('low overall risk')
        }
      }

      return `Priority: ${this.priority.toUpperCase()} due to ${factors.join(', ')}`
    }
  }

  return assessment
}

/**
 * Score text based on keyword matches
 */
function scoreKeywords(text, keywords) {
  const lowerText = text.toLowerCase()
  const matches = keywords.filter(kw => lowerText.includes(kw)).length
  // Diminishing returns for multiple matches
  return Math.min(1.0, matches * 0.3)
}

/**
 * Test Prioritizer class
 * Main class for prioritizing tests based on risk analysis
 */
class TestPrioritizer {
  constructor() {
    // Could be extended with historical data
  }

  /**
   * Prioritize a list of tests
   */
  prioritize(tests, pageType = null, context = null) {
    const prioritized = tests.map(test => {
      const risk = this._assessRisk(test, pageType)
      return {
        originalTest: test,
        riskAssessment: risk,
        computedPriority: risk.priority,
        executionOrder: 0
      }
    })

    // Sort by total risk score (descending)
    prioritized.sort((a, b) => b.riskAssessment.totalScore - a.riskAssessment.totalScore)

    // Assign execution order
    prioritized.forEach((test, i) => {
      test.executionOrder = i + 1
    })

    return prioritized
  }

  /**
   * Assess risk for a single test
   */
  _assessRisk(test, pageType = null) {
    // Get searchable text
    const title = (test.title || test.name || '').toLowerCase()
    const description = (test.description || '').toLowerCase()
    const category = (test.category || '').toLowerCase()
    const steps = Array.isArray(test.steps)
      ? test.steps.map(s => typeof s === 'string' ? s : s.action || '').join(' ').toLowerCase()
      : ''
    const allText = `${title} ${description} ${category} ${steps}`

    // Calculate individual scores
    let securityScore = scoreKeywords(allText, SECURITY_KEYWORDS)
    let dataLossScore = scoreKeywords(allText, DATA_LOSS_KEYWORDS)
    let revenueScore = scoreKeywords(allText, REVENUE_KEYWORDS)
    let userImpactScore = scoreKeywords(allText, USER_FRICTION_KEYWORDS)
    let complianceScore = scoreKeywords(allText, COMPLIANCE_KEYWORDS)

    // Category-based adjustments (strong boost for security category)
    if (category === 'security') {
      securityScore = Math.max(securityScore, 1.0)
      dataLossScore = Math.max(dataLossScore, 0.8)
      complianceScore = Math.max(complianceScore, 0.7)
    } else if (category === 'negative') {
      dataLossScore = Math.max(dataLossScore, 0.6)
      userImpactScore = Math.max(userImpactScore, 0.5)
    } else if (category === 'edge_case') {
      userImpactScore = Math.max(userImpactScore, 0.5)
    } else if (category === 'happy_path') {
      userImpactScore = Math.max(userImpactScore, 0.3)
    }

    // Complexity based on steps count
    const stepsCount = Array.isArray(test.steps) ? test.steps.length : 0
    const complexityScore = Math.min(1.0, stepsCount / 10)

    // Apply page type multiplier
    const multiplier = PAGE_TYPE_RISK[pageType] || 1.0
    securityScore = Math.min(1.0, securityScore * multiplier)
    dataLossScore = Math.min(1.0, dataLossScore * multiplier)
    revenueScore = Math.min(1.0, revenueScore * multiplier)

    return createRiskAssessment({
      security: securityScore,
      dataLoss: dataLossScore,
      revenue: revenueScore,
      userImpact: userImpactScore,
      compliance: complianceScore,
      complexity: complexityScore
    })
  }

  /**
   * Get tests in execution order
   */
  getExecutionOrder(prioritized, groupByPriority = true) {
    if (!groupByPriority) {
      return prioritized
    }

    // Group by priority
    const byPriority = {
      [Priority.CRITICAL]: [],
      [Priority.HIGH]: [],
      [Priority.MEDIUM]: [],
      [Priority.LOW]: []
    }

    for (const test of prioritized) {
      byPriority[test.computedPriority].push(test)
    }

    // Flatten in priority order
    const result = []
    let order = 1

    for (const priority of [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]) {
      for (const test of byPriority[priority]) {
        test.executionOrder = order
        result.push(test)
        order++
      }
    }

    return result
  }

  /**
   * Get a summary of prioritized tests
   */
  getSummary(prioritized) {
    const byPriority = {}
    for (const test of prioritized) {
      const priority = test.computedPriority
      byPriority[priority] = (byPriority[priority] || 0) + 1
    }

    const highRisk = prioritized.filter(t => t.riskAssessment.totalScore >= 0.7)

    return {
      totalTests: prioritized.length,
      byPriority,
      highRiskCount: highRisk.length,
      executionOrder: prioritized.slice(0, 10).map(t => ({
        order: t.executionOrder,
        title: t.originalTest.title || t.originalTest.name,
        priority: t.computedPriority,
        riskScore: Math.round(t.riskAssessment.totalScore * 100) / 100
      }))
    }
  }

  /**
   * Format prioritized tests for display
   */
  formatPrioritization(prioritized, showReasoning = true) {
    const lines = []
    lines.push('Test Execution Order (Risk-Based)')
    lines.push('='.repeat(40))
    lines.push('')

    let currentPriority = null
    const priorityIcons = {
      [Priority.CRITICAL]: '🔴',
      [Priority.HIGH]: '🟠',
      [Priority.MEDIUM]: '🟡',
      [Priority.LOW]: '🟢'
    }

    for (const test of prioritized) {
      // Priority header
      if (test.computedPriority !== currentPriority) {
        currentPriority = test.computedPriority
        const icon = priorityIcons[currentPriority]
        lines.push('')
        lines.push(`${icon} ${currentPriority.toUpperCase()}`)
        lines.push('-'.repeat(30))
      }

      // Test entry
      const title = test.originalTest.title || test.originalTest.name || 'Untitled'
      const score = test.riskAssessment.totalScore
      lines.push(`${String(test.executionOrder).padStart(2)}. ${title}`)
      lines.push(`    Risk: ${Math.round(score * 100)}%`)

      if (showReasoning) {
        lines.push(`    ${test.riskAssessment.reasoning}`)
      }
    }

    return lines.join('\n')
  }
}

/**
 * Quick function to prioritize tests
 */
function prioritizeTests(tests, pageType = null) {
  const prioritizer = new TestPrioritizer()
  const prioritized = prioritizer.prioritize(tests, pageType)

  // Update original tests with computed priority
  return prioritized.map(pt => ({
    ...pt.originalTest,
    priority: pt.computedPriority,
    riskScore: Math.round(pt.riskAssessment.totalScore * 100) / 100,
    executionOrder: pt.executionOrder
  }))
}

/**
 * Get only critical priority tests
 */
function getCriticalTests(tests, pageType = null) {
  const prioritizer = new TestPrioritizer()
  const prioritized = prioritizer.prioritize(tests, pageType)
  return prioritized
    .filter(pt => pt.computedPriority === Priority.CRITICAL)
    .map(pt => pt.originalTest)
}

module.exports = {
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
}
