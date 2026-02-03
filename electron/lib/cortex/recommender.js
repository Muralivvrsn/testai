/**
 * Yali Agent - Test Recommender
 * Ported from testai-agent/intelligence/recommender.py
 *
 * AI-powered recommendations for test improvements,
 * prioritization, and strategic testing decisions.
 */

/**
 * Recommendation types
 */
const RecommendationType = {
  PRIORITY: 'priority',
  OPTIMIZATION: 'optimization',
  COVERAGE: 'coverage',
  MAINTENANCE: 'maintenance',
  STRATEGY: 'strategy',
  RISK_MITIGATION: 'risk_mitigation'
}

/**
 * Recommendation impact levels
 */
const RecommendationImpact = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
}

/**
 * Recommendation effort levels
 */
const RecommendationEffort = {
  TRIVIAL: 'trivial',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  COMPLEX: 'complex'
}

/**
 * Create a test recommendation
 */
function createRecommendation(options) {
  return {
    recommendationId: options.recommendationId || `REC-${Date.now()}`,
    recommendationType: options.recommendationType,
    title: options.title,
    description: options.description,
    impact: options.impact,
    effort: options.effort,
    priorityScore: options.priorityScore || 0.5,
    affectedTests: options.affectedTests || [],
    actionItems: options.actionItems || [],
    expectedBenefits: options.expectedBenefits || [],
    createdAt: options.createdAt || new Date(),
    metadata: options.metadata || {}
  }
}

/**
 * Create a test profile
 */
function createTestProfile(testId, name, options = {}) {
  return {
    testId,
    name,
    durationMs: options.durationMs || 0,
    passRate: options.passRate ?? 1.0,
    flakyRate: options.flakyRate || 0.0,
    lastFailure: options.lastFailure || null,
    failureCount: options.failureCount || 0,
    coverageAreas: options.coverageAreas || new Set(),
    dependencies: options.dependencies || [],
    tags: options.tags || {}
  }
}

/**
 * Create a test suite profile
 */
function createSuiteProfile(suiteId, name, testProfiles, coverageScore = 0) {
  const totalDuration = testProfiles.reduce((sum, p) => sum + p.durationMs, 0)
  const avgPassRate = testProfiles.length > 0
    ? testProfiles.reduce((sum, p) => sum + p.passRate, 0) / testProfiles.length
    : 1.0

  return {
    suiteId,
    name,
    totalTests: testProfiles.length,
    totalDurationMs: totalDuration,
    avgPassRate,
    coverageScore,
    testProfiles
  }
}

/**
 * Test Recommender class
 */
class TestRecommender {
  // Priority weights
  static PRIORITY_WEIGHTS = {
    failure_rate: 0.25,
    flakiness: 0.20,
    impact: 0.20,
    recency: 0.15,
    duration: 0.10,
    coverage: 0.10
  }

  // Quick win thresholds
  static QUICK_WIN_EFFORT = new Set([RecommendationEffort.TRIVIAL, RecommendationEffort.LOW])
  static HIGH_IMPACT = new Set([RecommendationImpact.CRITICAL, RecommendationImpact.HIGH])

  constructor(options = {}) {
    this._maxRecommendations = options.maxRecommendations || 20
    this._testProfiles = new Map()
    this._suiteProfiles = new Map()
    this._recommendations = []
    this._recommendationCounter = 0
  }

  /**
   * Register a test for recommendation analysis
   */
  registerTest(testId, name, options = {}) {
    const profile = createTestProfile(testId, name, options)
    this._testProfiles.set(testId, profile)
    return profile
  }

  /**
   * Register a test suite
   */
  registerSuite(suiteId, name, testIds, coverageScore = 0) {
    const testProfiles = testIds
      .filter(tid => this._testProfiles.has(tid))
      .map(tid => this._testProfiles.get(tid))

    const suite = createSuiteProfile(suiteId, name, testProfiles, coverageScore)
    this._suiteProfiles.set(suiteId, suite)
    return suite
  }

  /**
   * Generate all recommendations
   */
  generateRecommendations(focusAreas = null) {
    let recommendations = []

    if (!focusAreas) {
      focusAreas = Object.values(RecommendationType)
    }

    if (focusAreas.includes(RecommendationType.PRIORITY)) {
      recommendations = recommendations.concat(this._generatePriorityRecommendations())
    }

    if (focusAreas.includes(RecommendationType.OPTIMIZATION)) {
      recommendations = recommendations.concat(this._generateOptimizationRecommendations())
    }

    if (focusAreas.includes(RecommendationType.COVERAGE)) {
      recommendations = recommendations.concat(this._generateCoverageRecommendations())
    }

    if (focusAreas.includes(RecommendationType.MAINTENANCE)) {
      recommendations = recommendations.concat(this._generateMaintenanceRecommendations())
    }

    if (focusAreas.includes(RecommendationType.RISK_MITIGATION)) {
      recommendations = recommendations.concat(this._generateRiskRecommendations())
    }

    // Sort by priority score
    recommendations.sort((a, b) => b.priorityScore - a.priorityScore)

    this._recommendations = recommendations.slice(0, this._maxRecommendations)
    return this._recommendations
  }

  /**
   * Get quick win recommendations (high impact, low effort)
   */
  getQuickWins() {
    return this._recommendations.filter(r =>
      TestRecommender.HIGH_IMPACT.has(r.impact) &&
      TestRecommender.QUICK_WIN_EFFORT.has(r.effort)
    )
  }

  /**
   * Get recommendations by type
   */
  getRecommendationsByType(recommendationType) {
    return this._recommendations.filter(r =>
      r.recommendationType === recommendationType
    )
  }

  /**
   * Get recommendations for a specific test
   */
  getRecommendationsForTest(testId) {
    return this._recommendations.filter(r =>
      r.affectedTests.includes(testId)
    )
  }

  /**
   * Prioritize tests for execution
   */
  prioritizeTests(testIds = null, timeBudgetMs = null) {
    if (!testIds) {
      testIds = Array.from(this._testProfiles.keys())
    }

    const scoredTests = []
    for (const testId of testIds) {
      const profile = this._testProfiles.get(testId)
      if (profile) {
        const score = this._calculatePriorityScore(profile)
        scoredTests.push([testId, score])
      }
    }

    // Sort by score (highest first)
    scoredTests.sort((a, b) => b[1] - a[1])

    // Apply time budget
    if (timeBudgetMs) {
      const selected = []
      let totalTime = 0
      for (const [testId, score] of scoredTests) {
        const profile = this._testProfiles.get(testId)
        if (profile && totalTime + profile.durationMs <= timeBudgetMs) {
          selected.push([testId, score])
          totalTime += profile.durationMs
        }
      }
      return selected
    }

    return scoredTests
  }

  _createRecommendation(options) {
    this._recommendationCounter++

    // Calculate priority score
    const impactScores = {
      [RecommendationImpact.CRITICAL]: 1.0,
      [RecommendationImpact.HIGH]: 0.75,
      [RecommendationImpact.MEDIUM]: 0.5,
      [RecommendationImpact.LOW]: 0.25
    }
    const effortScores = {
      [RecommendationEffort.TRIVIAL]: 1.0,
      [RecommendationEffort.LOW]: 0.8,
      [RecommendationEffort.MEDIUM]: 0.5,
      [RecommendationEffort.HIGH]: 0.3,
      [RecommendationEffort.COMPLEX]: 0.1
    }

    const priorityScore = (impactScores[options.impact] + effortScores[options.effort]) / 2

    return createRecommendation({
      recommendationId: `REC-${String(this._recommendationCounter).padStart(5, '0')}`,
      ...options,
      priorityScore
    })
  }

  _calculatePriorityScore(profile) {
    const scores = {}

    // Failure rate (higher failure = higher priority)
    scores.failure_rate = 1 - profile.passRate

    // Flakiness (higher = higher priority)
    scores.flakiness = Math.min(1.0, profile.flakyRate * 2)

    // Recency of failure (recent = higher priority)
    if (profile.lastFailure) {
      const daysSince = (Date.now() - profile.lastFailure.getTime()) / (1000 * 60 * 60 * 24)
      scores.recency = Math.max(0, 1 - daysSince / 30)
    } else {
      scores.recency = 0
    }

    // Duration (default)
    scores.duration = 0.5

    // Coverage (more coverage areas = higher priority)
    const coverageSize = profile.coverageAreas instanceof Set
      ? profile.coverageAreas.size
      : (Array.isArray(profile.coverageAreas) ? profile.coverageAreas.length : 0)
    scores.coverage = Math.min(1.0, coverageSize / 5)

    // Impact based on dependencies
    scores.impact = Math.min(1.0, profile.dependencies.length / 3)

    // Weighted sum
    let total = 0
    for (const [key, weight] of Object.entries(TestRecommender.PRIORITY_WEIGHTS)) {
      total += (scores[key] || 0) * weight
    }

    return Math.round(total * 1000) / 1000
  }

  _generatePriorityRecommendations() {
    const recommendations = []

    // Find tests that should run first
    const highPriority = []
    for (const [testId, profile] of this._testProfiles) {
      const score = this._calculatePriorityScore(profile)
      if (score > 0.6) {
        highPriority.push([testId, score])
      }
    }

    if (highPriority.length > 0) {
      highPriority.sort((a, b) => b[1] - a[1])
      const topTests = highPriority.slice(0, 5).map(t => t[0])

      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.PRIORITY,
        title: 'Prioritize Critical Tests',
        description: `${highPriority.length} tests identified as high priority for early execution`,
        impact: RecommendationImpact.HIGH,
        effort: RecommendationEffort.TRIVIAL,
        affectedTests: topTests,
        actionItems: [
          'Run high-priority tests first in CI/CD pipeline',
          'Set up fast feedback loop for critical tests'
        ],
        expectedBenefits: [
          'Faster feedback on critical functionality',
          'Earlier detection of regressions'
        ]
      }))
    }

    // Find tests with high failure impact
    const impactTests = []
    for (const [testId, profile] of this._testProfiles) {
      if (profile.dependencies.length >= 3 && profile.passRate < 0.95) {
        impactTests.push(testId)
      }
    }

    if (impactTests.length > 0) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.PRIORITY,
        title: 'Stabilize High-Impact Tests',
        description: `${impactTests.length} tests with many dependents need stabilization`,
        impact: RecommendationImpact.HIGH,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: impactTests.slice(0, 5),
        actionItems: [
          'Review and fix failing high-impact tests',
          'Add retry logic for transient failures'
        ],
        expectedBenefits: [
          'Reduced cascade failures',
          'More stable test runs'
        ]
      }))
    }

    return recommendations
  }

  _generateOptimizationRecommendations() {
    const recommendations = []

    // Find slow tests
    const slowThresholdMs = 5000
    const slowTests = []
    for (const [testId, profile] of this._testProfiles) {
      if (profile.durationMs > slowThresholdMs) {
        slowTests.push([testId, profile])
      }
    }

    if (slowTests.length > 0) {
      const totalTime = slowTests.reduce((sum, [, p]) => sum + p.durationMs, 0)
      const testIds = slowTests.slice(0, 5).map(([tid]) => tid)

      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.OPTIMIZATION,
        title: 'Optimize Slow Tests',
        description: `${slowTests.length} tests exceed ${slowThresholdMs}ms (total: ${(totalTime / 1000).toFixed(1)}s)`,
        impact: RecommendationImpact.MEDIUM,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: testIds,
        actionItems: [
          'Profile slow tests to identify bottlenecks',
          'Optimize selectors and waits',
          'Consider mocking slow external services'
        ],
        expectedBenefits: [
          'Faster test suite execution',
          'Quicker CI/CD feedback'
        ]
      }))
    }

    // Find parallelization opportunities
    const independentTests = []
    for (const [testId, profile] of this._testProfiles) {
      if (profile.dependencies.length === 0 && profile.passRate >= 0.95) {
        independentTests.push(testId)
      }
    }

    if (independentTests.length >= 5) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.OPTIMIZATION,
        title: 'Enable Test Parallelization',
        description: `${independentTests.length} independent tests can run in parallel`,
        impact: RecommendationImpact.HIGH,
        effort: RecommendationEffort.LOW,
        affectedTests: independentTests.slice(0, 10),
        actionItems: [
          'Configure test runner for parallel execution',
          "Ensure tests don't share mutable state"
        ],
        expectedBenefits: [
          'Significantly reduced total execution time',
          'Better resource utilization'
        ]
      }))
    }

    return recommendations
  }

  _generateCoverageRecommendations() {
    const recommendations = []

    // Find tests without coverage areas
    const uncoveredTests = []
    for (const [testId, profile] of this._testProfiles) {
      const coverageSize = profile.coverageAreas instanceof Set
        ? profile.coverageAreas.size
        : (Array.isArray(profile.coverageAreas) ? profile.coverageAreas.length : 0)
      if (coverageSize === 0) {
        uncoveredTests.push(testId)
      }
    }

    if (uncoveredTests.length > 0) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.COVERAGE,
        title: 'Define Coverage Areas',
        description: `${uncoveredTests.length} tests lack coverage area annotations`,
        impact: RecommendationImpact.MEDIUM,
        effort: RecommendationEffort.LOW,
        affectedTests: uncoveredTests.slice(0, 10),
        actionItems: [
          'Tag tests with feature/area coverage',
          'Map tests to requirements'
        ],
        expectedBenefits: [
          'Better visibility into test coverage',
          'Easier gap identification'
        ]
      }))
    }

    // Find areas with only one test
    const areaCounts = new Map()
    for (const profile of this._testProfiles.values()) {
      const areas = profile.coverageAreas instanceof Set
        ? profile.coverageAreas
        : new Set(profile.coverageAreas || [])
      for (const area of areas) {
        areaCounts.set(area, (areaCounts.get(area) || 0) + 1)
      }
    }

    const singleCoverage = Array.from(areaCounts.entries())
      .filter(([, count]) => count === 1)
      .map(([area]) => area)

    if (singleCoverage.length > 0) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.COVERAGE,
        title: 'Improve Coverage Depth',
        description: `${singleCoverage.length} areas have only single-test coverage`,
        impact: RecommendationImpact.MEDIUM,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: [],
        actionItems: [
          'Add additional tests for under-covered areas',
          'Consider edge cases and error scenarios'
        ],
        expectedBenefits: [
          'More robust coverage',
          'Reduced risk of missed regressions'
        ]
      }))
    }

    return recommendations
  }

  _generateMaintenanceRecommendations() {
    const recommendations = []

    // Find flaky tests
    const flakyTests = []
    for (const [testId, profile] of this._testProfiles) {
      if (profile.flakyRate > 0.1) {
        flakyTests.push([testId, profile])
      }
    }

    if (flakyTests.length > 0) {
      flakyTests.sort((a, b) => b[1].flakyRate - a[1].flakyRate)
      const testIds = flakyTests.slice(0, 5).map(([tid]) => tid)

      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.MAINTENANCE,
        title: 'Fix Flaky Tests',
        description: `${flakyTests.length} tests show flaky behavior`,
        impact: RecommendationImpact.HIGH,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: testIds,
        actionItems: [
          'Identify root cause of flakiness',
          'Add explicit waits for async operations',
          'Consider quarantining until fixed'
        ],
        expectedBenefits: [
          'More reliable test results',
          'Reduced false negatives',
          'Increased developer trust'
        ]
      }))
    }

    // Find tests with many failures
    const failingTests = []
    for (const [testId, profile] of this._testProfiles) {
      if (profile.failureCount > 5 && profile.passRate < 0.7) {
        failingTests.push([testId, profile])
      }
    }

    if (failingTests.length > 0) {
      const testIds = failingTests.slice(0, 5).map(([tid]) => tid)

      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.MAINTENANCE,
        title: 'Repair or Remove Failing Tests',
        description: `${failingTests.length} tests have persistent failures`,
        impact: RecommendationImpact.MEDIUM,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: testIds,
        actionItems: [
          'Investigate root cause of failures',
          'Update tests to match current behavior',
          'Consider removing obsolete tests'
        ],
        expectedBenefits: [
          'Cleaner test suite',
          'More meaningful results'
        ]
      }))
    }

    return recommendations
  }

  _generateRiskRecommendations() {
    const recommendations = []

    // Find tests with many dependents (single points of failure)
    const dependencyCounts = new Map()
    for (const profile of this._testProfiles.values()) {
      for (const dep of profile.dependencies) {
        dependencyCounts.set(dep, (dependencyCounts.get(dep) || 0) + 1)
      }
    }

    const criticalDeps = Array.from(dependencyCounts.entries())
      .filter(([, count]) => count >= 3)

    if (criticalDeps.length > 0) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.RISK_MITIGATION,
        title: 'Address Single Points of Failure',
        description: `${criticalDeps.length} tests are dependencies for multiple others`,
        impact: RecommendationImpact.HIGH,
        effort: RecommendationEffort.MEDIUM,
        affectedTests: criticalDeps.map(([dep]) => dep),
        actionItems: [
          'Ensure critical tests are highly stable',
          'Add redundant coverage for critical paths',
          'Implement fast failure detection'
        ],
        expectedBenefits: [
          'Reduced risk of mass failures',
          'More resilient test suite'
        ]
      }))
    }

    // Check for high dependency ratio
    const testsWithDeps = Array.from(this._testProfiles.values())
      .filter(p => p.dependencies.length > 0)

    if (testsWithDeps.length > this._testProfiles.size * 0.5) {
      recommendations.push(this._createRecommendation({
        recommendationType: RecommendationType.RISK_MITIGATION,
        title: 'Reduce Test Dependencies',
        description: 'Many tests have dependencies, increasing failure cascade risk',
        impact: RecommendationImpact.MEDIUM,
        effort: RecommendationEffort.HIGH,
        affectedTests: testsWithDeps.slice(0, 5).map(p => p.testId),
        actionItems: [
          'Review and reduce unnecessary dependencies',
          'Use mocks to isolate tests',
          'Consider independent test data setup'
        ],
        expectedBenefits: [
          'More isolated tests',
          'Easier debugging',
          'Reduced cascade failures'
        ]
      }))
    }

    return recommendations
  }

  /**
   * Get recommender statistics
   */
  getStatistics() {
    const typeCounts = {}
    for (const recType of Object.values(RecommendationType)) {
      typeCounts[recType] = this._recommendations.filter(r =>
        r.recommendationType === recType
      ).length
    }

    return {
      registeredTests: this._testProfiles.size,
      registeredSuites: this._suiteProfiles.size,
      totalRecommendations: this._recommendations.length,
      recommendationsByType: typeCounts,
      quickWins: this.getQuickWins().length
    }
  }

  /**
   * Format a recommendation for display
   */
  formatRecommendation(rec) {
    const impactEmoji = {
      [RecommendationImpact.CRITICAL]: '🔴',
      [RecommendationImpact.HIGH]: '🟠',
      [RecommendationImpact.MEDIUM]: '🟡',
      [RecommendationImpact.LOW]: '🟢'
    }

    const effortEmoji = {
      [RecommendationEffort.TRIVIAL]: '✨',
      [RecommendationEffort.LOW]: '🔧',
      [RecommendationEffort.MEDIUM]: '⚙️',
      [RecommendationEffort.HIGH]: '🏗️',
      [RecommendationEffort.COMPLEX]: '🔬'
    }

    const lines = [
      '='.repeat(60),
      `  ${impactEmoji[rec.impact]} RECOMMENDATION`,
      '='.repeat(60),
      '',
      `  ${rec.title}`,
      '',
      `  ${rec.description}`,
      '',
      `  Type: ${rec.recommendationType}`,
      `  Impact: ${rec.impact} ${impactEmoji[rec.impact]}`,
      `  Effort: ${rec.effort} ${effortEmoji[rec.effort]}`,
      `  Priority: ${Math.round(rec.priorityScore * 100)}%`,
      ''
    ]

    if (rec.actionItems.length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  ACTION ITEMS')
      lines.push('-'.repeat(60))
      for (const item of rec.actionItems) {
        lines.push(`  □ ${item}`)
      }
      lines.push('')
    }

    if (rec.expectedBenefits.length > 0) {
      lines.push('-'.repeat(60))
      lines.push('  EXPECTED BENEFITS')
      lines.push('-'.repeat(60))
      for (const benefit of rec.expectedBenefits) {
        lines.push(`  ✓ ${benefit}`)
      }
      lines.push('')
    }

    if (rec.affectedTests.length > 0) {
      lines.push('-'.repeat(60))
      lines.push(`  AFFECTED TESTS (${rec.affectedTests.length})`)
      lines.push('-'.repeat(60))
      for (const testId of rec.affectedTests.slice(0, 5)) {
        lines.push(`  • ${testId}`)
      }
      if (rec.affectedTests.length > 5) {
        lines.push(`  ... and ${rec.affectedTests.length - 5} more`)
      }
      lines.push('')
    }

    lines.push('='.repeat(60))
    return lines.join('\n')
  }
}

/**
 * Quick helper to create a recommender
 */
function createTestRecommender(options = {}) {
  return new TestRecommender(options)
}

module.exports = {
  RecommendationType,
  RecommendationImpact,
  RecommendationEffort,
  TestRecommender,
  createRecommendation,
  createTestProfile,
  createSuiteProfile,
  createTestRecommender
}
