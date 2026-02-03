/**
 * Yali Agent - Selector Healer
 * Ported from testai-agent/healing/selector_healer.py
 *
 * Intelligent selector healing that automatically finds
 * alternative selectors when original selectors break.
 */

/**
 * Types of selectors
 */
const SelectorType = {
  CSS: 'css',
  XPATH: 'xpath',
  ID: 'id',
  CLASS: 'class',
  NAME: 'name',
  DATA_TESTID: 'data_testid',
  DATA_ATTR: 'data_attr',
  TEXT: 'text',
  ARIA_LABEL: 'aria_label',
  ROLE: 'role',
  LINK_TEXT: 'link_text',
  PARTIAL_LINK_TEXT: 'partial_link_text'
}

/**
 * Healing strategies
 */
const HealingStrategy = {
  ATTRIBUTE_FALLBACK: 'attribute_fallback', // Try other attributes
  STRUCTURAL: 'structural',                 // Use DOM structure
  SEMANTIC: 'semantic',                     // Use semantic attributes
  TEXT_BASED: 'text_based',                 // Use text content
  HYBRID: 'hybrid',                         // Combine multiple strategies
  ML_ASSISTED: 'ml_assisted'                // Machine learning suggestions
}

/**
 * Selector stability rankings (higher = more stable)
 */
const STABILITY_RANKINGS = {
  [SelectorType.DATA_TESTID]: 0.95,
  [SelectorType.ID]: 0.85,
  [SelectorType.DATA_ATTR]: 0.80,
  [SelectorType.ARIA_LABEL]: 0.75,
  [SelectorType.NAME]: 0.70,
  [SelectorType.ROLE]: 0.65,
  [SelectorType.TEXT]: 0.50,
  [SelectorType.CLASS]: 0.40,
  [SelectorType.CSS]: 0.35,
  [SelectorType.XPATH]: 0.30
}

/**
 * Create a selector candidate
 */
function createSelectorCandidate(selector, selectorType, confidence, strategy, options = {}) {
  return {
    selector,
    selectorType,
    confidence,
    strategy,
    stabilityScore: options.stabilityScore || STABILITY_RANKINGS[selectorType] || 0.5,
    specificityScore: options.specificityScore || 0.5,
    reasoning: options.reasoning || ''
  }
}

/**
 * Create a healing result
 */
function createHealingResult(options) {
  return {
    resultId: options.resultId,
    originalSelector: options.originalSelector,
    originalType: options.originalType,
    healedSelector: options.healedSelector,
    healedType: options.healedType,
    confidence: options.confidence,
    strategyUsed: options.strategyUsed,
    candidatesEvaluated: options.candidatesEvaluated,
    healingTimeMs: options.healingTimeMs,
    success: options.success,
    healedAt: options.healedAt || new Date(),
    metadata: options.metadata || {}
  }
}

/**
 * Selector Healer class
 */
class SelectorHealer {
  constructor(options = {}) {
    this.defaultStrategy = options.defaultStrategy || HealingStrategy.HYBRID
    this.minConfidence = options.minConfidence || 0.7

    this._snapshots = new Map()
    this._healingHistory = []
    this._resultCounter = 0
    this._successfulPatterns = []
  }

  /**
   * Capture a snapshot of an element for future healing
   */
  captureSnapshot(selectorId, elementInfo) {
    const snapshot = {
      tagName: elementInfo.tagName || elementInfo.tag || 'div',
      elementId: elementInfo.id || null,
      classes: elementInfo.classes || [],
      attributes: elementInfo.attributes || {},
      textContent: elementInfo.textContent || elementInfo.text || '',
      parentTag: elementInfo.parentTag || null,
      siblingIndex: elementInfo.siblingIndex || 0,
      xpath: elementInfo.xpath || '',
      timestamp: new Date()
    }

    this._snapshots.set(selectorId, snapshot)
    return snapshot
  }

  /**
   * Attempt to heal a broken selector
   */
  heal(originalSelector, originalType = SelectorType.CSS, currentDom = null, strategy = null) {
    const startTime = Date.now()
    this._resultCounter++
    const resultId = `HEAL-${String(this._resultCounter).padStart(5, '0')}`

    strategy = strategy || this.defaultStrategy

    // Generate candidates
    const candidates = this._generateCandidates(originalSelector, originalType, currentDom, strategy)

    // Rank and select best candidate
    if (candidates.length > 0) {
      candidates.sort((a, b) => b.confidence - a.confidence)
      const best = candidates[0]

      if (best.confidence >= this.minConfidence) {
        const healingTimeMs = Date.now() - startTime

        const result = createHealingResult({
          resultId,
          originalSelector,
          originalType,
          healedSelector: best.selector,
          healedType: best.selectorType,
          confidence: best.confidence,
          strategyUsed: best.strategy,
          candidatesEvaluated: candidates.length,
          healingTimeMs,
          success: true,
          metadata: {
            reasoning: best.reasoning,
            stabilityScore: best.stabilityScore
          }
        })

        this._healingHistory.push(result)
        this._learnFromSuccess(result)
        return result
      }
    }

    // Healing failed
    const healingTimeMs = Date.now() - startTime

    const result = createHealingResult({
      resultId,
      originalSelector,
      originalType,
      healedSelector: originalSelector,
      healedType: originalType,
      confidence: 0.0,
      strategyUsed: strategy,
      candidatesEvaluated: candidates.length,
      healingTimeMs,
      success: false,
      metadata: { reason: 'No suitable candidate found' }
    })

    this._healingHistory.push(result)
    return result
  }

  _generateCandidates(originalSelector, originalType, currentDom, strategy) {
    let candidates = []

    if (strategy === HealingStrategy.ATTRIBUTE_FALLBACK) {
      candidates = candidates.concat(this._attributeFallbackCandidates(originalSelector, currentDom))
    } else if (strategy === HealingStrategy.STRUCTURAL) {
      candidates = candidates.concat(this._structuralCandidates(originalSelector, currentDom))
    } else if (strategy === HealingStrategy.SEMANTIC) {
      candidates = candidates.concat(this._semanticCandidates(originalSelector, currentDom))
    } else if (strategy === HealingStrategy.TEXT_BASED) {
      candidates = candidates.concat(this._textBasedCandidates(originalSelector, currentDom))
    } else if (strategy === HealingStrategy.HYBRID) {
      // Try all strategies
      candidates = candidates.concat(this._attributeFallbackCandidates(originalSelector, currentDom))
      candidates = candidates.concat(this._structuralCandidates(originalSelector, currentDom))
      candidates = candidates.concat(this._semanticCandidates(originalSelector, currentDom))
      candidates = candidates.concat(this._textBasedCandidates(originalSelector, currentDom))
    }

    return candidates
  }

  _attributeFallbackCandidates(original, dom) {
    const candidates = []

    if (dom) {
      // Try data-testid
      if (dom.attributes && dom.attributes['data-testid']) {
        const testid = dom.attributes['data-testid']
        candidates.push(createSelectorCandidate(
          `[data-testid="${testid}"]`,
          SelectorType.DATA_TESTID,
          0.95,
          HealingStrategy.ATTRIBUTE_FALLBACK,
          { stabilityScore: 0.95, specificityScore: 0.90, reasoning: 'Using data-testid attribute (highly stable)' }
        ))
      }

      // Try ID
      if (dom.id) {
        candidates.push(createSelectorCandidate(
          `#${dom.id}`,
          SelectorType.ID,
          0.85,
          HealingStrategy.ATTRIBUTE_FALLBACK,
          { stabilityScore: 0.85, specificityScore: 0.95, reasoning: 'Using element ID' }
        ))
      }

      // Try name attribute
      if (dom.attributes && dom.attributes.name) {
        const name = dom.attributes.name
        candidates.push(createSelectorCandidate(
          `[name="${name}"]`,
          SelectorType.NAME,
          0.75,
          HealingStrategy.ATTRIBUTE_FALLBACK,
          { stabilityScore: 0.70, specificityScore: 0.80, reasoning: 'Using name attribute' }
        ))
      }

      // Try aria-label
      if (dom.attributes && dom.attributes['aria-label']) {
        const label = dom.attributes['aria-label']
        candidates.push(createSelectorCandidate(
          `[aria-label="${label}"]`,
          SelectorType.ARIA_LABEL,
          0.80,
          HealingStrategy.ATTRIBUTE_FALLBACK,
          { stabilityScore: 0.75, specificityScore: 0.85, reasoning: 'Using aria-label for accessibility' }
        ))
      }
    } else {
      // Simulated fallback when no DOM provided
      if (original.startsWith('#')) {
        const elementId = original.slice(1)
        candidates.push(createSelectorCandidate(
          `[data-testid="${elementId}"]`,
          SelectorType.DATA_TESTID,
          0.70,
          HealingStrategy.ATTRIBUTE_FALLBACK,
          { stabilityScore: 0.95, specificityScore: 0.80, reasoning: 'Converted ID to data-testid' }
        ))
      }
    }

    return candidates
  }

  _structuralCandidates(original, dom) {
    const candidates = []

    if (dom) {
      const tag = dom.tag || dom.tagName || 'div'
      const parent = dom.parentTag || dom.parent_tag || 'div'
      const index = dom.siblingIndex || dom.sibling_index || 0

      // Parent-child relationship
      candidates.push(createSelectorCandidate(
        `${parent} > ${tag}:nth-child(${index + 1})`,
        SelectorType.CSS,
        0.55,
        HealingStrategy.STRUCTURAL,
        { stabilityScore: 0.40, specificityScore: 0.70, reasoning: 'Using parent-child structural relationship' }
      ))

      // XPath based on structure
      const xpath = `//${parent}/${tag}[${index + 1}]`
      candidates.push(createSelectorCandidate(
        xpath,
        SelectorType.XPATH,
        0.50,
        HealingStrategy.STRUCTURAL,
        { stabilityScore: 0.35, specificityScore: 0.75, reasoning: 'Using XPath structural relationship' }
      ))
    }

    return candidates
  }

  _semanticCandidates(original, dom) {
    const candidates = []

    if (dom) {
      // Role-based selector
      if (dom.attributes && dom.attributes.role) {
        const role = dom.attributes.role
        candidates.push(createSelectorCandidate(
          `[role="${role}"]`,
          SelectorType.ROLE,
          0.70,
          HealingStrategy.SEMANTIC,
          { stabilityScore: 0.65, specificityScore: 0.60, reasoning: 'Using ARIA role for semantic selection' }
        ))
      }

      // Type-based for inputs
      const tag = (dom.tag || dom.tagName || '').toLowerCase()
      if (tag === 'input' && dom.attributes && dom.attributes.type) {
        const inputType = dom.attributes.type
        candidates.push(createSelectorCandidate(
          `input[type="${inputType}"]`,
          SelectorType.CSS,
          0.50,
          HealingStrategy.SEMANTIC,
          { stabilityScore: 0.45, specificityScore: 0.40, reasoning: 'Using input type for semantic selection' }
        ))
      }
    }

    return candidates
  }

  _textBasedCandidates(original, dom) {
    const candidates = []

    if (dom) {
      const text = (dom.textContent || dom.text_content || '').trim()

      if (text && text.length < 100) {
        // Exact text match
        candidates.push(createSelectorCandidate(
          `text="${text}"`,
          SelectorType.TEXT,
          0.65,
          HealingStrategy.TEXT_BASED,
          { stabilityScore: 0.50, specificityScore: 0.70, reasoning: 'Using exact text content match' }
        ))

        // Partial text match
        if (text.length > 10) {
          const partial = text.slice(0, 20)
          candidates.push(createSelectorCandidate(
            `//*[contains(text(), "${partial}")]`,
            SelectorType.XPATH,
            0.55,
            HealingStrategy.TEXT_BASED,
            { stabilityScore: 0.45, specificityScore: 0.55, reasoning: 'Using partial text content match' }
          ))
        }
      }
    }

    return candidates
  }

  _learnFromSuccess(result) {
    if (result.success) {
      this._successfulPatterns.push({
        originalType: result.originalType,
        healedType: result.healedType,
        strategy: result.strategyUsed,
        confidence: result.confidence,
        timestamp: result.healedAt.toISOString()
      })

      // Keep only recent patterns
      if (this._successfulPatterns.length > 1000) {
        this._successfulPatterns = this._successfulPatterns.slice(-500)
      }
    }
  }

  /**
   * Suggest stable selectors for an element
   */
  suggestStableSelectors(elementInfo) {
    const candidates = []

    // Prefer data-testid
    if (elementInfo.attributes && elementInfo.attributes['data-testid']) {
      const testid = elementInfo.attributes['data-testid']
      candidates.push(createSelectorCandidate(
        `[data-testid="${testid}"]`,
        SelectorType.DATA_TESTID,
        0.98,
        HealingStrategy.ATTRIBUTE_FALLBACK,
        { stabilityScore: 0.95, specificityScore: 0.90, reasoning: 'data-testid is the most stable selector strategy' }
      ))
    }

    // ID as second choice
    if (elementInfo.id) {
      candidates.push(createSelectorCandidate(
        `#${elementInfo.id}`,
        SelectorType.ID,
        0.90,
        HealingStrategy.ATTRIBUTE_FALLBACK,
        { stabilityScore: 0.85, specificityScore: 0.95, reasoning: 'ID selectors are highly specific and stable' }
      ))
    }

    // aria-label for accessibility
    if (elementInfo.attributes && elementInfo.attributes['aria-label']) {
      const label = elementInfo.attributes['aria-label']
      candidates.push(createSelectorCandidate(
        `[aria-label="${label}"]`,
        SelectorType.ARIA_LABEL,
        0.85,
        HealingStrategy.SEMANTIC,
        { stabilityScore: 0.75, specificityScore: 0.85, reasoning: 'aria-label provides semantic stability' }
      ))
    }

    return candidates.sort((a, b) => b.stabilityScore - a.stabilityScore)
  }

  /**
   * Get healing history
   */
  getHealingHistory(successOnly = false, limit = 100) {
    let results = this._healingHistory

    if (successOnly) {
      results = results.filter(r => r.success)
    }

    return results.slice(-limit)
  }

  /**
   * Get healing success rate
   */
  getSuccessRate() {
    if (this._healingHistory.length === 0) {
      return 0.0
    }

    const successful = this._healingHistory.filter(r => r.success).length
    return successful / this._healingHistory.length
  }

  /**
   * Get healer statistics
   */
  getStatistics() {
    const strategyCounts = {}
    const typeCounts = {}

    for (const result of this._healingHistory) {
      if (result.success) {
        const strategy = result.strategyUsed
        strategyCounts[strategy] = (strategyCounts[strategy] || 0) + 1

        const healedType = result.healedType
        typeCounts[healedType] = (typeCounts[healedType] || 0) + 1
      }
    }

    return {
      totalHealings: this._healingHistory.length,
      successfulHealings: this._healingHistory.filter(r => r.success).length,
      successRate: this.getSuccessRate(),
      snapshotsStored: this._snapshots.size,
      patternsLearned: this._successfulPatterns.length,
      strategyDistribution: strategyCounts,
      healedTypeDistribution: typeCounts
    }
  }

  /**
   * Format a healing result
   */
  formatResult(result) {
    const statusIcon = result.success ? '✅' : '❌'

    const lines = [
      '='.repeat(60),
      `  ${statusIcon} SELECTOR HEALING RESULT`,
      '='.repeat(60),
      '',
      `  Result ID: ${result.resultId}`,
      `  Success: ${result.success}`,
      `  Confidence: ${(result.confidence * 100).toFixed(0)}%`,
      '',
      `  Original: ${result.originalSelector}`,
      `  Original Type: ${result.originalType}`,
      '',
      `  Healed: ${result.healedSelector}`,
      `  Healed Type: ${result.healedType}`,
      '',
      `  Strategy: ${result.strategyUsed}`,
      `  Candidates Evaluated: ${result.candidatesEvaluated}`,
      `  Healing Time: ${result.healingTimeMs}ms`,
      '',
      '='.repeat(60)
    ]

    return lines.join('\n')
  }
}

/**
 * Quick helper to create a selector healer
 */
function createSelectorHealer(options = {}) {
  return new SelectorHealer(options)
}

module.exports = {
  SelectorType,
  HealingStrategy,
  STABILITY_RANKINGS,
  SelectorHealer,
  createSelectorCandidate,
  createHealingResult,
  createSelectorHealer
}
