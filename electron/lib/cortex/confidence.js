/**
 * Yali Agent - Confidence Scoring System
 * Ported from testai-agent/cortex/confidence.py
 *
 * Calculates how confident the agent should be about its decisions.
 * Humans show confidence naturally - so should we.
 *
 * Confidence Factors:
 * - Knowledge match quality (how relevant is our brain data?)
 * - Context completeness (do we have all the info?)
 * - Pattern recognition (have we seen this before?)
 * - Ambiguity level (how clear is the request?)
 */

/**
 * Human-readable confidence levels
 */
const ConfidenceLevel = {
  VERY_HIGH: 'very_high',    // 90%+ - Proceed without hesitation
  HIGH: 'high',              // 75-90% - Proceed with minor caveats
  MODERATE: 'moderate',      // 50-75% - Ask clarifying questions
  LOW: 'low',                // 25-50% - Need more info before proceeding
  VERY_LOW: 'very_low'       // <25% - Cannot proceed, need help
}

/**
 * Convert numeric score to confidence level
 */
function scoreToLevel(score) {
  if (score >= 0.90) return ConfidenceLevel.VERY_HIGH
  if (score >= 0.75) return ConfidenceLevel.HIGH
  if (score >= 0.50) return ConfidenceLevel.MODERATE
  if (score >= 0.25) return ConfidenceLevel.LOW
  return ConfidenceLevel.VERY_LOW
}

/**
 * Check if confidence level allows autonomous action
 */
function shouldProceed(level) {
  return level === ConfidenceLevel.VERY_HIGH || level === ConfidenceLevel.HIGH
}

/**
 * Check if we should ask clarifying questions
 */
function shouldClarify(level) {
  return level === ConfidenceLevel.MODERATE || level === ConfidenceLevel.LOW
}

/**
 * Factor weights for confidence calculation
 */
const FACTOR_WEIGHTS = {
  knowledge_relevance: 0.25,   // How relevant is our QA brain data?
  context_completeness: 0.20,  // Do we have all the info?
  pattern_match: 0.20,         // Have we seen this before?
  clarity: 0.15,               // How clear is the request?
  element_coverage: 0.10,      // Did we find expected elements?
  user_history: 0.10           // Past interactions help?
}

/**
 * Default confidence factors
 */
function createDefaultFactors() {
  return {
    knowledge_relevance: 0.0,
    context_completeness: 0.0,
    pattern_match: 0.0,
    clarity: 0.0,
    element_coverage: 0.0,
    user_history: 0.5  // Neutral default
  }
}

/**
 * Generate human-readable reasoning for confidence score
 */
function generateReasoning(factors, level) {
  const sortedFactors = Object.entries(factors).sort((a, b) => a[1] - b[1])
  const weakest = sortedFactors[0]
  const strongest = sortedFactors[sortedFactors.length - 1]

  const formatName = name => name.replace(/_/g, ' ')

  if (shouldProceed(level)) {
    return `Good confidence based on ${formatName(strongest[0])}.`
  } else if (level === ConfidenceLevel.MODERATE) {
    return `Moderate confidence. ${formatName(weakest[0]).charAt(0).toUpperCase() + formatName(weakest[0]).slice(1)} could be improved.`
  } else {
    return `Low confidence due to limited ${formatName(weakest[0])}.`
  }
}

/**
 * Generate suggestions for improving confidence
 */
function generateSuggestions(factors, level) {
  const suggestions = []

  if (shouldProceed(level)) {
    return suggestions
  }

  if (factors.knowledge_relevance < 0.5) {
    suggestions.push('More context about the feature would help')
  }

  if (factors.context_completeness < 0.5) {
    suggestions.push('Could you describe the expected behavior?')
  }

  if (factors.clarity < 0.5) {
    suggestions.push('The request is a bit ambiguous - any specifics?')
  }

  if (factors.element_coverage < 0.5) {
    suggestions.push('I found fewer elements than expected - is the page fully loaded?')
  }

  return suggestions.slice(0, 2) // Limit to 2 suggestions
}

/**
 * Confidence Scorer class
 * Main class for calculating confidence scores
 */
class ConfidenceScorer {
  constructor(defaultThreshold = 0.70) {
    this.threshold = defaultThreshold
  }

  /**
   * Calculate weighted confidence score from factors
   */
  calculate(factors) {
    // Weighted average
    let weightedSum = 0
    let totalWeight = 0

    for (const [key, weight] of Object.entries(FACTOR_WEIGHTS)) {
      weightedSum += (factors[key] || 0) * weight
      totalWeight += weight
    }

    const score = weightedSum / totalWeight
    const level = scoreToLevel(score)
    const reasoning = generateReasoning(factors, level)
    const suggestions = generateSuggestions(factors, level)

    return {
      score,
      level,
      factors: { ...factors },
      reasoning,
      suggestions,
      canProceed: shouldProceed(level),
      shouldClarify: shouldClarify(level)
    }
  }

  /**
   * Score confidence for page type classification
   */
  scoreClassification(pageType, foundElements = [], knowledgeMatchScore = 0.5, expectedElements = null) {
    // Expected elements for common page types
    const typeExpectations = {
      login: ['email', 'password', 'submit', 'login', 'sign in'],
      signup: ['email', 'password', 'confirm', 'register', 'sign up', 'name'],
      checkout: ['payment', 'card', 'address', 'shipping', 'total', 'order'],
      search: ['search', 'query', 'filter', 'results'],
      form: ['input', 'submit', 'field'],
      dashboard: ['menu', 'nav', 'overview', 'stats'],
      settings: ['save', 'update', 'profile', 'preferences']
    }

    const expected = expectedElements || typeExpectations[pageType.toLowerCase()] || []

    // Calculate element coverage
    let elementCoverage = 0.5
    if (expected.length > 0 && foundElements.length > 0) {
      const foundLower = foundElements.map(e => String(e).toLowerCase())
      const matches = expected.filter(exp =>
        foundLower.some(f => f.includes(exp))
      ).length
      elementCoverage = matches / expected.length
    }

    // Clarity based on how distinct the page type is
    const clarity = typeExpectations[pageType.toLowerCase()] ? 0.8 : 0.5

    const factors = {
      knowledge_relevance: knowledgeMatchScore,
      context_completeness: foundElements.length > 0 ? 0.7 : 0.3,
      pattern_match: elementCoverage,
      clarity: clarity,
      element_coverage: elementCoverage,
      user_history: 0.5
    }

    return this.calculate(factors)
  }

  /**
   * Score confidence for test generation
   */
  scoreGeneration(feature, contextAvailable = false, knowledgeChunks = 0, clarityIndicators = []) {
    // More knowledge chunks = higher relevance
    const knowledgeScore = Math.min(knowledgeChunks / 5, 1.0) // 5+ chunks = 100%

    // Context completeness
    const contextScore = contextAvailable ? 0.8 : 0.4

    // Clarity from indicators
    const clarityScore = clarityIndicators.length > 0
      ? Math.min(clarityIndicators.length / 5, 1.0)
      : 0.5

    const factors = {
      knowledge_relevance: knowledgeScore,
      context_completeness: contextScore,
      pattern_match: 0.6, // Default for generation
      clarity: clarityScore,
      element_coverage: contextAvailable ? 0.7 : 0.4,
      user_history: 0.5
    }

    return this.calculate(factors)
  }

  /**
   * Score confidence for security analysis
   */
  scoreSecurityAnalysis(pageType, hasAuthElements = false, hasInputElements = false, knowledgeMatch = 0.5) {
    // Security analysis needs good knowledge
    const knowledgeScore = knowledgeMatch

    // Auth pages have clearer security patterns
    const patternScore = hasAuthElements ? 0.8 : 0.5

    // Input elements create more attack surface
    const contextScore = hasInputElements ? 0.9 : 0.6

    // Security-sensitive page types
    const securityPages = ['login', 'signup', 'checkout', 'payment', 'settings']
    const clarity = securityPages.includes(pageType.toLowerCase()) ? 0.7 : 0.5

    const factors = {
      knowledge_relevance: knowledgeScore,
      context_completeness: contextScore,
      pattern_match: patternScore,
      clarity: clarity,
      element_coverage: 0.7,
      user_history: 0.5
    }

    return this.calculate(factors)
  }

  /**
   * Quick confidence check
   */
  quickScore(knowledgeScore, contextComplete, clarity = 0.7) {
    const factors = {
      knowledge_relevance: knowledgeScore,
      context_completeness: contextComplete ? 0.8 : 0.4,
      pattern_match: 0.6,
      clarity: clarity,
      element_coverage: 0.6,
      user_history: 0.5
    }
    return this.calculate(factors)
  }
}

/**
 * Quick confidence calculation helper
 */
function quickConfidence(knowledgeScore, contextComplete, clarity = 0.7) {
  const scorer = new ConfidenceScorer()
  return scorer.quickScore(knowledgeScore, contextComplete, clarity)
}

module.exports = {
  ConfidenceLevel,
  ConfidenceScorer,
  FACTOR_WEIGHTS,
  scoreToLevel,
  shouldProceed,
  shouldClarify,
  quickConfidence,
  createDefaultFactors,
  generateReasoning,
  generateSuggestions
}
