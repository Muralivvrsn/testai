/**
 * Yali Agent - Risk Intelligence
 * Ported from testai-agent/cortex/risk_intelligence.py
 *
 * Intelligent test prioritization based on historical data,
 * business risk, and learned patterns.
 */

/**
 * Risk levels
 */
const RiskLevel = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  MINIMAL: 'minimal'
}

/**
 * Impact areas
 */
const ImpactArea = {
  REVENUE: 'revenue',
  SECURITY: 'security',
  DATA_INTEGRITY: 'data_integrity',
  USER_EXPERIENCE: 'user_experience',
  COMPLIANCE: 'compliance',
  REPUTATION: 'reputation'
}

/**
 * Risk weights by impact area
 */
const IMPACT_WEIGHTS = {
  [ImpactArea.SECURITY]: 1.0,
  [ImpactArea.DATA_INTEGRITY]: 0.9,
  [ImpactArea.REVENUE]: 0.85,
  [ImpactArea.COMPLIANCE]: 0.8,
  [ImpactArea.REPUTATION]: 0.7,
  [ImpactArea.USER_EXPERIENCE]: 0.6
}

/**
 * Page type base risk scores
 */
const PAGE_TYPE_RISK = {
  checkout: { base: 0.9, impacts: [ImpactArea.REVENUE, ImpactArea.SECURITY, ImpactArea.DATA_INTEGRITY] },
  payment: { base: 0.95, impacts: [ImpactArea.REVENUE, ImpactArea.SECURITY, ImpactArea.COMPLIANCE] },
  login: { base: 0.85, impacts: [ImpactArea.SECURITY, ImpactArea.DATA_INTEGRITY] },
  signup: { base: 0.75, impacts: [ImpactArea.SECURITY, ImpactArea.USER_EXPERIENCE] },
  profile: { base: 0.65, impacts: [ImpactArea.DATA_INTEGRITY, ImpactArea.USER_EXPERIENCE] },
  settings: { base: 0.6, impacts: [ImpactArea.DATA_INTEGRITY] },
  search: { base: 0.5, impacts: [ImpactArea.USER_EXPERIENCE] },
  dashboard: { base: 0.5, impacts: [ImpactArea.USER_EXPERIENCE] },
  form: { base: 0.55, impacts: [ImpactArea.DATA_INTEGRITY, ImpactArea.USER_EXPERIENCE] }
}

/**
 * Category risk multipliers
 */
const CATEGORY_RISK = {
  security: 1.5,
  authentication: 1.4,
  payment: 1.4,
  data_loss: 1.3,
  validation: 1.1,
  functional: 1.0,
  edge_case: 0.9,
  usability: 0.8,
  happy_path: 0.7
}

/**
 * Historical risk tracking
 */
class HistoricalRisk {
  constructor() {
    this.testHistory = new Map() // testId -> { runs, failures, lastRun }
    this.bugHistory = new Map()  // featureArea -> { count, severity }
    this.pageTypeHistory = new Map() // pageType -> { bugs, failures }
  }

  /**
   * Record a test execution result
   */
  recordTestResult(testId, passed, pageType = null) {
    if (!this.testHistory.has(testId)) {
      this.testHistory.set(testId, { runs: 0, failures: 0, lastRun: null })
    }

    const history = this.testHistory.get(testId)
    history.runs++
    if (!passed) history.failures++
    history.lastRun = Date.now()

    // Also track page type
    if (pageType) {
      if (!this.pageTypeHistory.has(pageType)) {
        this.pageTypeHistory.set(pageType, { bugs: 0, failures: 0 })
      }
      if (!passed) {
        this.pageTypeHistory.get(pageType).failures++
      }
    }
  }

  /**
   * Record a bug found
   */
  recordBug(featureArea, severity, pageType = null) {
    if (!this.bugHistory.has(featureArea)) {
      this.bugHistory.set(featureArea, { count: 0, totalSeverity: 0 })
    }

    const severityScore = { critical: 4, high: 3, medium: 2, low: 1 }[severity] || 1
    const history = this.bugHistory.get(featureArea)
    history.count++
    history.totalSeverity += severityScore

    if (pageType && this.pageTypeHistory.has(pageType)) {
      this.pageTypeHistory.get(pageType).bugs++
    }
  }

  /**
   * Get failure rate for a test
   */
  getFailureRate(testId) {
    const history = this.testHistory.get(testId)
    if (!history || history.runs === 0) return 0
    return history.failures / history.runs
  }

  /**
   * Get bug density for a feature area
   */
  getBugDensity(featureArea) {
    const history = this.bugHistory.get(featureArea)
    if (!history) return 0
    return history.count * (history.totalSeverity / history.count)
  }

  /**
   * Get risk multiplier based on history
   */
  getHistoricalMultiplier(testId, featureArea = null) {
    let multiplier = 1.0

    // Factor in test failure rate
    const failureRate = this.getFailureRate(testId)
    if (failureRate > 0.5) multiplier *= 1.5
    else if (failureRate > 0.2) multiplier *= 1.2
    else if (failureRate > 0) multiplier *= 1.1

    // Factor in bug density
    if (featureArea) {
      const bugDensity = this.getBugDensity(featureArea)
      if (bugDensity > 10) multiplier *= 1.4
      else if (bugDensity > 5) multiplier *= 1.2
      else if (bugDensity > 0) multiplier *= 1.1
    }

    return multiplier
  }
}

/**
 * Create a risk score
 */
function createRiskScore(score, level, impacts, explanations, recommendations = []) {
  return {
    score: Math.min(1.0, Math.max(0, score)),
    level,
    impacts,
    explanations,
    recommendations,

    toString() {
      return `Risk: ${this.level} (${Math.round(this.score * 100)}%)\n` +
             `Impacts: ${this.impacts.join(', ')}\n` +
             `Reasons: ${this.explanations.join('; ')}`
    }
  }
}

/**
 * Risk Intelligence class
 */
class RiskIntelligence {
  constructor() {
    this.history = new HistoricalRisk()
  }

  /**
   * Score a test case for risk-based prioritization
   */
  scoreTest(test, pageType = null) {
    const explanations = []
    const impacts = new Set()
    let baseScore = 0.5

    // 1. Page type risk
    const pageRisk = PAGE_TYPE_RISK[pageType] || PAGE_TYPE_RISK.form
    baseScore = pageRisk.base
    pageRisk.impacts.forEach(i => impacts.add(i))
    explanations.push(`Page type "${pageType}" has base risk ${Math.round(pageRisk.base * 100)}%`)

    // 2. Category risk
    const category = (test.category || '').toLowerCase()
    const categoryMultiplier = CATEGORY_RISK[category] || 1.0
    baseScore *= categoryMultiplier
    if (categoryMultiplier > 1) {
      explanations.push(`Category "${category}" increases risk by ${Math.round((categoryMultiplier - 1) * 100)}%`)
    }

    // 3. Keyword analysis
    const testText = [
      test.title || test.name || '',
      test.description || '',
      Array.isArray(test.steps) ? test.steps.join(' ') : ''
    ].join(' ').toLowerCase()

    // Security keywords
    const securityKeywords = ['injection', 'xss', 'csrf', 'authentication', 'password', 'token', 'session']
    const securityMatches = securityKeywords.filter(kw => testText.includes(kw))
    if (securityMatches.length > 0) {
      baseScore *= 1.3
      impacts.add(ImpactArea.SECURITY)
      explanations.push(`Security-related: ${securityMatches.join(', ')}`)
    }

    // Revenue keywords
    const revenueKeywords = ['payment', 'checkout', 'order', 'cart', 'purchase', 'transaction']
    const revenueMatches = revenueKeywords.filter(kw => testText.includes(kw))
    if (revenueMatches.length > 0) {
      baseScore *= 1.25
      impacts.add(ImpactArea.REVENUE)
      explanations.push(`Revenue-impacting: ${revenueMatches.join(', ')}`)
    }

    // Data keywords
    const dataKeywords = ['delete', 'update', 'save', 'modify', 'remove', 'create']
    const dataMatches = dataKeywords.filter(kw => testText.includes(kw))
    if (dataMatches.length > 0) {
      baseScore *= 1.15
      impacts.add(ImpactArea.DATA_INTEGRITY)
      explanations.push(`Data modification: ${dataMatches.join(', ')}`)
    }

    // 4. Historical risk
    const testId = test.id || test.title || 'unknown'
    const historicalMultiplier = this.history.getHistoricalMultiplier(testId, category)
    if (historicalMultiplier > 1) {
      baseScore *= historicalMultiplier
      explanations.push(`Historical failure patterns increase risk`)
    }

    // Determine level
    const finalScore = Math.min(1.0, baseScore)
    let level
    if (finalScore >= 0.85) level = RiskLevel.CRITICAL
    else if (finalScore >= 0.7) level = RiskLevel.HIGH
    else if (finalScore >= 0.5) level = RiskLevel.MEDIUM
    else if (finalScore >= 0.3) level = RiskLevel.LOW
    else level = RiskLevel.MINIMAL

    // Generate recommendations
    const recommendations = this._generateRecommendations(level, [...impacts], pageType)

    return createRiskScore(finalScore, level, [...impacts], explanations, recommendations)
  }

  /**
   * Generate recommendations based on risk
   */
  _generateRecommendations(level, impacts, pageType) {
    const recommendations = []

    if (level === RiskLevel.CRITICAL || level === RiskLevel.HIGH) {
      recommendations.push('Run this test in every build')
      recommendations.push('Include in smoke test suite')
    }

    if (impacts.includes(ImpactArea.SECURITY)) {
      recommendations.push('Consider additional security scanning')
      recommendations.push('Review OWASP guidelines for this feature')
    }

    if (impacts.includes(ImpactArea.REVENUE)) {
      recommendations.push('Add monitoring for this flow')
      recommendations.push('Consider A/B testing changes')
    }

    if (impacts.includes(ImpactArea.DATA_INTEGRITY)) {
      recommendations.push('Verify database rollback capability')
      recommendations.push('Add audit logging for this operation')
    }

    return recommendations
  }

  /**
   * Prioritize a list of tests by risk
   */
  prioritizeTests(tests, pageType = null) {
    const scored = tests.map(test => ({
      test,
      risk: this.scoreTest(test, pageType)
    }))

    // Sort by risk score descending
    scored.sort((a, b) => b.risk.score - a.risk.score)

    return scored.map((item, index) => ({
      ...item.test,
      riskScore: item.risk.score,
      riskLevel: item.risk.level,
      riskImpacts: item.risk.impacts,
      executionOrder: index + 1
    }))
  }

  /**
   * Record test result for learning
   */
  recordTestResult(testId, passed, pageType = null) {
    this.history.recordTestResult(testId, passed, pageType)
  }

  /**
   * Record bug for learning
   */
  recordBug(featureArea, severity, pageType = null) {
    this.history.recordBug(featureArea, severity, pageType)
  }

  /**
   * Get recommendations by page type
   */
  getRecommendations(pageType) {
    const pageRisk = PAGE_TYPE_RISK[pageType] || PAGE_TYPE_RISK.form
    const recommendations = []

    recommendations.push(`Focus on ${pageRisk.impacts.join(', ')} testing`)

    if (pageRisk.base >= 0.8) {
      recommendations.push('This is a high-risk page - prioritize security and edge case testing')
      recommendations.push('Consider exploratory testing sessions')
    }

    if (pageRisk.impacts.includes(ImpactArea.SECURITY)) {
      recommendations.push('Run security-focused tests first')
      recommendations.push('Check for common vulnerabilities (OWASP Top 10)')
    }

    if (pageRisk.impacts.includes(ImpactArea.REVENUE)) {
      recommendations.push('Verify all payment flows thoroughly')
      recommendations.push('Test error handling for payment failures')
    }

    return recommendations
  }

  /**
   * Get risk summary for a page type
   */
  getRiskSummary(pageType) {
    const pageRisk = PAGE_TYPE_RISK[pageType] || PAGE_TYPE_RISK.form
    const pageHistory = this.history.pageTypeHistory.get(pageType)

    return {
      pageType,
      baseRisk: pageRisk.base,
      impactAreas: pageRisk.impacts,
      historicalBugs: pageHistory?.bugs || 0,
      historicalFailures: pageHistory?.failures || 0,
      recommendations: this.getRecommendations(pageType)
    }
  }
}

/**
 * Quick risk score for a test
 */
function quickRiskScore(test, pageType = null) {
  const intelligence = new RiskIntelligence()
  return intelligence.scoreTest(test, pageType)
}

module.exports = {
  RiskLevel,
  ImpactArea,
  IMPACT_WEIGHTS,
  PAGE_TYPE_RISK,
  CATEGORY_RISK,
  RiskIntelligence,
  HistoricalRisk,
  createRiskScore,
  quickRiskScore
}
