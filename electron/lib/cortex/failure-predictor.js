/**
 * Yali Agent - Failure Predictor
 * Ported from testai-agent/intelligence/predictor.py
 *
 * AI-powered failure prediction that analyzes patterns,
 * code changes, and historical data to predict test failures
 * BEFORE they occur. Like a QA with intuition.
 */

/**
 * Types of failure predictions
 */
const PredictionType = {
  FLAKY_TEST: 'flaky_test',
  REGRESSION: 'regression',
  ENVIRONMENT_ISSUE: 'environment_issue',
  TIMING_ISSUE: 'timing_issue',
  DEPENDENCY_FAILURE: 'dependency_failure',
  CODE_CHANGE_IMPACT: 'code_change_impact',
  RESOURCE_EXHAUSTION: 'resource_exhaustion',
  SELECTOR_BREAKAGE: 'selector_breakage'
}

/**
 * Risk levels for predictions
 */
const RiskLevel = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  MINIMAL: 'minimal'
}

/**
 * Risk weights for different factors
 */
const RISK_WEIGHTS = {
  flakiness: 0.25,
  recentFailures: 0.20,
  codeChanges: 0.20,
  durationVariance: 0.10,
  environment: 0.10,
  dependencies: 0.10,
  age: 0.05
}

/**
 * Create a risk factor
 */
function createRiskFactor(name, description, weight, confidence, options = {}) {
  return {
    factorId: `RF_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    name,
    description,
    weight,
    confidence,
    evidence: options.evidence || [],
    mitigation: options.mitigation || ''
  }
}

/**
 * Create a failure prediction
 */
function createPrediction(testId, type, riskLevel, probability, options = {}) {
  return {
    predictionId: `PRED_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    testId,
    predictionType: type,
    riskLevel,
    probability,
    confidence: options.confidence || 0.7,
    riskFactors: options.riskFactors || [],
    predictedAt: Date.now(),
    validUntil: Date.now() + (options.horizonHours || 24) * 60 * 60 * 1000,
    description: options.description || '',
    recommendations: options.recommendations || []
  }
}

/**
 * Create test history record
 */
function createTestHistory(testId) {
  return {
    testId,
    totalRuns: 0,
    passCount: 0,
    failCount: 0,
    flakyCount: 0,
    avgDurationMs: 0,
    durationVariance: 0,
    lastFailure: null,
    recentResults: [], // Last N results, true=pass
    failurePatterns: {}
  }
}

/**
 * Failure Predictor class
 * Predicts test failures before they happen
 */
class FailurePredictor {
  constructor(options = {}) {
    this.historyWindow = options.historyWindow || 100
    this.predictionHorizonHours = options.predictionHorizonHours || 24
    this.flakyThreshold = 0.1 // 10% inconsistent = flaky

    this.testHistory = new Map()
    this.codeChanges = []
    this.predictions = new Map()
    this.environmentIssues = new Map()
  }

  /**
   * Record a test result for learning
   */
  recordResult(testId, passed, durationMs, failureType = null) {
    if (!this.testHistory.has(testId)) {
      this.testHistory.set(testId, createTestHistory(testId))
    }

    const history = this.testHistory.get(testId)
    history.totalRuns++

    if (passed) {
      history.passCount++
    } else {
      history.failCount++
      history.lastFailure = Date.now()
      if (failureType) {
        history.failurePatterns[failureType] = (history.failurePatterns[failureType] || 0) + 1
      }
    }

    // Update recent results
    history.recentResults.push(passed)
    if (history.recentResults.length > this.historyWindow) {
      history.recentResults.shift()
    }

    // Update average duration (Welford's algorithm)
    const n = history.totalRuns
    const oldAvg = history.avgDurationMs
    history.avgDurationMs = oldAvg + (durationMs - oldAvg) / n

    // Update variance
    if (n > 1) {
      history.durationVariance = ((n - 2) / (n - 1)) * history.durationVariance + Math.pow(durationMs - oldAvg, 2) / n
    }

    // Detect flakiness
    if (history.recentResults.length >= 10) {
      const recent = history.recentResults.slice(-10)
      let transitions = 0
      for (let i = 1; i < recent.length; i++) {
        if (recent[i] !== recent[i - 1]) transitions++
      }
      if (transitions >= 3) {
        history.flakyCount++
      }
    }
  }

  /**
   * Record a code change for impact analysis
   */
  recordCodeChange(filesChanged, linesAdded, linesRemoved, changeType = 'feature', affectedTests = []) {
    const change = {
      changeId: `CHG_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      filesChanged,
      linesAdded,
      linesRemoved,
      changeType,
      timestamp: Date.now(),
      affectedTests
    }

    this.codeChanges.push(change)

    // Keep only recent changes (30 days)
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000
    this.codeChanges = this.codeChanges.filter(c => c.timestamp > cutoff)

    return change
  }

  /**
   * Predict potential failure for a test
   */
  predictFailure(testId) {
    const history = this.testHistory.get(testId)
    const riskFactors = []
    let totalRisk = 0

    // Analyze flakiness
    const flakinessRisk = this._analyzeFlakinessRisk(testId, history)
    if (flakinessRisk) {
      riskFactors.push(flakinessRisk)
      totalRisk += flakinessRisk.weight * flakinessRisk.confidence
    }

    // Analyze recent failures
    const recentFailureRisk = this._analyzeRecentFailures(testId, history)
    if (recentFailureRisk) {
      riskFactors.push(recentFailureRisk)
      totalRisk += recentFailureRisk.weight * recentFailureRisk.confidence
    }

    // Analyze code change impact
    const codeChangeRisk = this._analyzeCodeChanges(testId)
    if (codeChangeRisk) {
      riskFactors.push(codeChangeRisk)
      totalRisk += codeChangeRisk.weight * codeChangeRisk.confidence
    }

    // Analyze duration variance
    const durationRisk = this._analyzeDurationVariance(testId, history)
    if (durationRisk) {
      riskFactors.push(durationRisk)
      totalRisk += durationRisk.weight * durationRisk.confidence
    }

    // Determine prediction type
    const predictionType = this._determinePredictionType(riskFactors)

    // Calculate probability and risk level
    const probability = Math.min(1.0, totalRisk)
    const confidence = this._calculateConfidence(history, riskFactors)
    const riskLevel = this._calculateRiskLevel(probability, confidence)

    // Generate recommendations
    const recommendations = this._generateRecommendations(riskFactors, predictionType)

    const prediction = createPrediction(testId, predictionType, riskLevel, probability, {
      confidence,
      riskFactors,
      horizonHours: this.predictionHorizonHours,
      description: this._generateDescription(predictionType, probability, riskFactors),
      recommendations
    })

    // Store prediction
    if (!this.predictions.has(testId)) {
      this.predictions.set(testId, [])
    }
    this.predictions.get(testId).push(prediction)

    return prediction
  }

  /**
   * Predict failures for multiple tests
   */
  predictBatch(testIds) {
    return testIds.map(testId => this.predictFailure(testId))
  }

  /**
   * Get tests with high failure probability
   */
  getHighRiskTests(threshold = 0.5) {
    const predictions = []

    for (const testId of this.testHistory.keys()) {
      const prediction = this.predictFailure(testId)
      if (prediction.probability >= threshold) {
        predictions.push(prediction)
      }
    }

    return predictions.sort((a, b) => b.probability - a.probability)
  }

  /**
   * Get health metrics for a test
   */
  getTestHealth(testId) {
    const history = this.testHistory.get(testId)

    if (!history) {
      return {
        testId,
        healthScore: 1.0,
        status: 'unknown',
        dataPoints: 0
      }
    }

    // Calculate health score
    const passRate = history.passCount / Math.max(1, history.totalRuns)
    const flakyRate = history.flakyCount / Math.max(1, history.totalRuns)
    const healthScore = passRate * (1 - flakyRate * 0.5)

    // Determine status
    let status = 'healthy'
    if (healthScore < 0.60) status = 'critical'
    else if (healthScore < 0.80) status = 'unstable'
    else if (healthScore < 0.95) status = 'stable'

    return {
      testId,
      healthScore: Math.round(healthScore * 1000) / 1000,
      status,
      passRate: Math.round(passRate * 1000) / 1000,
      flakyRate: Math.round(flakyRate * 1000) / 1000,
      totalRuns: history.totalRuns,
      recentTrend: this._calculateTrend(history.recentResults),
      avgDurationMs: Math.round(history.avgDurationMs * 100) / 100
    }
  }

  _analyzeFlakinessRisk(testId, history) {
    if (!history || history.totalRuns < 5) return null

    const flakyRate = history.flakyCount / history.totalRuns
    if (flakyRate < this.flakyThreshold) return null

    return createRiskFactor('Flakiness', `Test shows ${(flakyRate * 100).toFixed(1)}% flaky behavior`, RISK_WEIGHTS.flakiness, Math.min(1.0, flakyRate * 3), {
      evidence: [`Flaky runs: ${history.flakyCount}`, `Total runs: ${history.totalRuns}`],
      mitigation: 'Add retry logic or stabilize test conditions'
    })
  }

  _analyzeRecentFailures(testId, history) {
    if (!history || history.recentResults.length < 3) return null

    const recent = history.recentResults.slice(-10)
    const failCount = recent.filter(r => !r).length

    if (failCount === 0) return null

    const failRate = failCount / recent.length

    return createRiskFactor('Recent Failures', `${failCount} failures in last ${recent.length} runs`, RISK_WEIGHTS.recentFailures, failRate, {
      evidence: [
        `Recent fail rate: ${(failRate * 100).toFixed(1)}%`,
        `Pattern: ${recent.map(r => r ? '✓' : '✗').join('')}`
      ],
      mitigation: 'Investigate recent failure causes'
    })
  }

  _analyzeCodeChanges(testId) {
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
    const recentChanges = this.codeChanges.filter(c => c.timestamp > sevenDaysAgo)

    if (recentChanges.length === 0) return null

    const affectingChanges = recentChanges.filter(c => c.affectedTests.includes(testId))
    if (affectingChanges.length === 0) return null

    const totalImpact = affectingChanges.reduce((sum, c) => sum + c.linesAdded + c.linesRemoved, 0)

    return createRiskFactor('Code Changes', `${affectingChanges.length} recent changes affect this test`, RISK_WEIGHTS.codeChanges, Math.min(1.0, totalImpact / 100), {
      evidence: [`Changes: ${affectingChanges.length}`, `Lines modified: ${totalImpact}`],
      mitigation: 'Review test after code changes'
    })
  }

  _analyzeDurationVariance(testId, history) {
    if (!history || history.totalRuns < 5 || history.avgDurationMs === 0) return null

    const cv = Math.sqrt(history.durationVariance) / history.avgDurationMs

    if (cv < 0.3) return null

    return createRiskFactor('Timing Variance', `High execution time variance (CV=${cv.toFixed(2)})`, RISK_WEIGHTS.durationVariance, Math.min(1.0, cv), {
      evidence: [
        `Avg duration: ${Math.round(history.avgDurationMs)}ms`,
        `Std dev: ${Math.round(Math.sqrt(history.durationVariance))}ms`
      ],
      mitigation: 'Add explicit waits or reduce environment sensitivity'
    })
  }

  _determinePredictionType(riskFactors) {
    if (!riskFactors.length) return PredictionType.REGRESSION

    const topFactor = riskFactors.reduce((a, b) => a.weight * a.confidence > b.weight * b.confidence ? a : b)

    const typeMapping = {
      'Flakiness': PredictionType.FLAKY_TEST,
      'Recent Failures': PredictionType.REGRESSION,
      'Code Changes': PredictionType.CODE_CHANGE_IMPACT,
      'Timing Variance': PredictionType.TIMING_ISSUE
    }

    return typeMapping[topFactor.name] || PredictionType.REGRESSION
  }

  _calculateConfidence(history, riskFactors) {
    if (!history) return 0.3

    const dataConfidence = Math.min(1.0, history.totalRuns / 50)
    const factorConfidence = riskFactors.length ? riskFactors.reduce((sum, f) => sum + f.confidence, 0) / riskFactors.length : 0.5

    return (dataConfidence + factorConfidence) / 2
  }

  _calculateRiskLevel(probability, confidence) {
    const riskScore = probability * confidence

    if (riskScore >= 0.7) return RiskLevel.CRITICAL
    if (riskScore >= 0.5) return RiskLevel.HIGH
    if (riskScore >= 0.3) return RiskLevel.MEDIUM
    if (riskScore >= 0.1) return RiskLevel.LOW
    return RiskLevel.MINIMAL
  }

  _calculateTrend(recentResults) {
    if (recentResults.length < 5) return 'insufficient_data'

    const mid = Math.floor(recentResults.length / 2)
    const firstHalf = recentResults.slice(0, mid)
    const secondHalf = recentResults.slice(mid)

    const firstPassRate = firstHalf.filter(r => r).length / firstHalf.length
    const secondPassRate = secondHalf.filter(r => r).length / secondHalf.length

    const diff = secondPassRate - firstPassRate

    if (diff > 0.1) return 'improving'
    if (diff < -0.1) return 'degrading'
    return 'stable'
  }

  _generateRecommendations(riskFactors, predictionType) {
    const recommendations = riskFactors.filter(f => f.mitigation).map(f => f.mitigation)

    const typeRecs = {
      [PredictionType.FLAKY_TEST]: ['Consider adding retry mechanisms', 'Review async operations and waits'],
      [PredictionType.REGRESSION]: ['Check recent code changes', 'Verify test assertions are still valid'],
      [PredictionType.CODE_CHANGE_IMPACT]: ['Review code changes affecting this test', 'Update test to match new behavior if needed'],
      [PredictionType.TIMING_ISSUE]: ['Add explicit waits for dynamic content', 'Consider mocking slow operations']
    }

    for (const rec of (typeRecs[predictionType] || [])) {
      if (!recommendations.includes(rec)) {
        recommendations.push(rec)
      }
    }

    return recommendations.slice(0, 5)
  }

  _generateDescription(predictionType, probability, riskFactors) {
    const factorNames = riskFactors.map(f => f.name)

    if (!factorNames.length) {
      return `Low risk of ${predictionType} (${(probability * 100).toFixed(0)}% probability)`
    }

    return `Predicted ${predictionType} with ${(probability * 100).toFixed(0)}% probability. Contributing factors: ${factorNames.join(', ')}`
  }

  /**
   * Get predictor statistics
   */
  getStatistics() {
    let allPredictions = []
    for (const preds of this.predictions.values()) {
      allPredictions.push(...preds)
    }

    return {
      trackedTests: this.testHistory.size,
      totalPredictions: allPredictions.length,
      codeChangesTracked: this.codeChanges.length,
      environmentIssues: Array.from(this.environmentIssues.values()).reduce((a, b) => a + b, 0),
      avgProbability: allPredictions.length ? allPredictions.reduce((sum, p) => sum + p.probability, 0) / allPredictions.length : 0
    }
  }

  /**
   * Format prediction for display
   */
  formatPrediction(prediction) {
    const riskEmoji = {
      [RiskLevel.CRITICAL]: '🔴',
      [RiskLevel.HIGH]: '🟠',
      [RiskLevel.MEDIUM]: '🟡',
      [RiskLevel.LOW]: '🟢',
      [RiskLevel.MINIMAL]: '⚪'
    }

    const lines = [
      '═'.repeat(60),
      `  ${riskEmoji[prediction.riskLevel]} FAILURE PREDICTION`,
      '═'.repeat(60),
      '',
      `  Test: ${prediction.testId}`,
      `  Type: ${prediction.predictionType}`,
      `  Risk Level: ${prediction.riskLevel}`,
      `  Probability: ${(prediction.probability * 100).toFixed(1)}%`,
      `  Confidence: ${(prediction.confidence * 100).toFixed(1)}%`,
      '',
      '─'.repeat(60),
      '  RISK FACTORS',
      '─'.repeat(60),
      ''
    ]

    for (const factor of prediction.riskFactors) {
      lines.push(`  • ${factor.name} (weight: ${(factor.weight * 100).toFixed(0)}%)`)
      lines.push(`    ${factor.description}`)
    }

    if (prediction.recommendations.length) {
      lines.push('', '─'.repeat(60), '  RECOMMENDATIONS', '─'.repeat(60), '')
      for (const rec of prediction.recommendations) {
        lines.push(`  → ${rec}`)
      }
    }

    lines.push('', '═'.repeat(60))
    return lines.join('\n')
  }
}

/**
 * Create a failure predictor instance
 */
function createFailurePredictor(options = {}) {
  return new FailurePredictor(options)
}

module.exports = {
  PredictionType,
  RiskLevel,
  RISK_WEIGHTS,
  FailurePredictor,
  createFailurePredictor,
  createRiskFactor,
  createPrediction,
  createTestHistory
}
