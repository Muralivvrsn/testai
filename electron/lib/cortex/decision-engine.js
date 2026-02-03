/**
 * Yali Agent - Decision Engine
 * Ported from testai-agent/cortex/decision_engine.py
 *
 * The executive function of the agent.
 * Decides what to do next based on context, knowledge, and confidence.
 *
 * Decision Flow:
 * 1. Receive input (page content, user request, etc.)
 * 2. Query brain for relevant knowledge
 * 3. Calculate confidence
 * 4. Decide: act autonomously, ask questions, or escalate
 */

const { ConfidenceScorer, ConfidenceLevel, shouldProceed } = require('./confidence')

/**
 * Types of actions the agent can take
 */
const ActionType = {
  CLASSIFY_PAGE: 'classify_page',
  GENERATE_TESTS: 'generate_tests',
  ANALYZE_SECURITY: 'analyze_security',
  FIND_EDGE_CASES: 'find_edge_cases',
  ASK_CLARIFICATION: 'ask_clarification',
  EXECUTE_TEST: 'execute_test',
  REPORT_RESULTS: 'report_results',
  WAIT_FOR_USER: 'wait_for_user',
  NAVIGATE: 'navigate',
  CLICK: 'click',
  TYPE: 'type',
  SCROLL: 'scroll'
}

/**
 * Possible outcomes of a decision
 */
const DecisionOutcome = {
  PROCEED: 'proceed',       // Go ahead autonomously
  CLARIFY: 'clarify',       // Ask questions first
  ESCALATE: 'escalate',     // Need human help
  DEFER: 'defer',           // Save for later
  SKIP: 'skip'              // Not relevant
}

/**
 * Create a decision context
 */
function createDecisionContext(options = {}) {
  return {
    // What we're working with
    pageUrl: options.pageUrl || null,
    pageType: options.pageType || null,
    pageElements: options.pageElements || [],
    userRequest: options.userRequest || null,

    // What we know
    knowledgeChunks: options.knowledgeChunks || [],
    knowledgeConfidence: options.knowledgeConfidence || 0.5,

    // History
    previousActions: options.previousActions || [],
    clarificationsAsked: options.clarificationsAsked || 0,

    // Constraints
    maxClarifications: options.maxClarifications || 3,
    allowAutonomous: options.allowAutonomous !== false,

    // Helpers
    hasPageInfo() {
      return Boolean(this.pageUrl || this.pageElements.length > 0)
    },

    hasKnowledge() {
      return this.knowledgeChunks.length > 0
    },

    canAskMore() {
      return this.clarificationsAsked < this.maxClarifications
    }
  }
}

/**
 * Create a decision result
 */
function createDecision(action, outcome, confidence, reasoning, options = {}) {
  return {
    action,
    outcome,
    confidence,
    reasoning,
    nextSteps: options.nextSteps || [],
    clarificationQuestions: options.clarificationQuestions || [],
    payload: options.payload || {},

    // Helpers
    shouldProceed() {
      return this.outcome === DecisionOutcome.PROCEED
    },

    needsClarification() {
      return this.outcome === DecisionOutcome.CLARIFY ||
             this.outcome === DecisionOutcome.ESCALATE
    },

    toString() {
      return `Decision: ${this.action} -> ${this.outcome} (${this.confidence.level})\nReasoning: ${this.reasoning}`
    }
  }
}

/**
 * Decision Engine class
 * The brain's decision-making system
 */
class DecisionEngine {
  constructor(confidenceThreshold = 0.70) {
    this.confidenceThreshold = confidenceThreshold
    this.scorer = new ConfidenceScorer(confidenceThreshold)
  }

  /**
   * Make a decision based on context
   */
  async decide(context) {
    // First, determine what action type this is
    const actionType = this._determineActionType(context)

    // Calculate confidence based on context
    const confidence = this._calculateConfidence(context, actionType)

    // Decide outcome based on confidence and context
    const outcome = this._determineOutcome(confidence, context)

    // Generate reasoning
    const reasoning = this._generateReasoning(actionType, confidence, context)

    // Generate next steps or questions
    let nextSteps = []
    let questions = []

    if (outcome === DecisionOutcome.PROCEED) {
      nextSteps = this._generateNextSteps(actionType, context)
    } else if (outcome === DecisionOutcome.CLARIFY || outcome === DecisionOutcome.ESCALATE) {
      questions = this._generateQuestions(actionType, confidence, context)
    }

    return createDecision(actionType, outcome, confidence, reasoning, {
      nextSteps,
      clarificationQuestions: questions,
      payload: this._buildPayload(actionType, context)
    })
  }

  /**
   * Specialized decision for test generation strategy
   */
  async decideTestStrategy(context) {
    const hasPage = context.hasPageInfo()
    const hasKnowledge = context.hasKnowledge()

    if (!hasPage && !context.userRequest) {
      return createDecision(
        ActionType.WAIT_FOR_USER,
        DecisionOutcome.ESCALATE,
        this.scorer.scoreGeneration('', false, 0),
        'I need a page URL or feature description to generate tests.',
        { clarificationQuestions: ['What would you like me to test?'] }
      )
    }

    return this.decide(context)
  }

  /**
   * Determine the appropriate action type
   */
  _determineActionType(context) {
    const request = (context.userRequest || '').toLowerCase()

    // Check explicit requests
    if (/security|vulnerab/i.test(request)) {
      return ActionType.ANALYZE_SECURITY
    }
    if (/edge|boundary/i.test(request)) {
      return ActionType.FIND_EDGE_CASES
    }
    if (/test|generate/i.test(request)) {
      return ActionType.GENERATE_TESTS
    }
    if (/run|execute/i.test(request)) {
      return ActionType.EXECUTE_TEST
    }
    if (/click/i.test(request)) {
      return ActionType.CLICK
    }
    if (/type|enter|fill/i.test(request)) {
      return ActionType.TYPE
    }
    if (/scroll/i.test(request)) {
      return ActionType.SCROLL
    }
    if (/go to|navigate|load|open|visit/i.test(request)) {
      return ActionType.NAVIGATE
    }

    // Default based on what we have
    if (!context.pageType && context.hasPageInfo()) {
      return ActionType.CLASSIFY_PAGE
    }

    if (context.pageType) {
      return ActionType.GENERATE_TESTS
    }

    return ActionType.WAIT_FOR_USER
  }

  /**
   * Calculate confidence for the action
   */
  _calculateConfidence(context, actionType) {
    const elementTags = context.pageElements.map(e => e.tag || e.category || '')

    switch (actionType) {
      case ActionType.CLASSIFY_PAGE:
        return this.scorer.scoreClassification(
          context.pageType || 'unknown',
          elementTags,
          context.knowledgeConfidence
        )

      case ActionType.GENERATE_TESTS:
        return this.scorer.scoreGeneration(
          context.pageType || 'unknown',
          context.hasPageInfo(),
          context.knowledgeChunks.length
        )

      case ActionType.ANALYZE_SECURITY:
        const hasAuth = context.pageElements.some(e =>
          ['password', 'email', 'login'].includes(e.type)
        )
        const hasInputs = context.pageElements.some(e =>
          ['input', 'textarea'].includes(e.tag)
        )
        return this.scorer.scoreSecurityAnalysis(
          context.pageType || 'unknown',
          hasAuth,
          hasInputs,
          context.knowledgeConfidence
        )

      default:
        return this.scorer.scoreGeneration(
          'general',
          context.hasPageInfo(),
          context.knowledgeChunks.length
        )
    }
  }

  /**
   * Determine the outcome based on confidence and context
   */
  _determineOutcome(confidence, context) {
    // Check if we can proceed autonomously
    if (!context.allowAutonomous) {
      return DecisionOutcome.CLARIFY
    }

    // High confidence = proceed
    if (confidence.canProceed) {
      return DecisionOutcome.PROCEED
    }

    // Moderate confidence = clarify (if we can)
    if (confidence.level === ConfidenceLevel.MODERATE) {
      if (context.canAskMore()) {
        return DecisionOutcome.CLARIFY
      } else {
        // We've asked enough, just proceed with caveats
        return DecisionOutcome.PROCEED
      }
    }

    // Low confidence
    if (confidence.level === ConfidenceLevel.LOW) {
      if (context.canAskMore()) {
        return DecisionOutcome.CLARIFY
      } else {
        return DecisionOutcome.ESCALATE
      }
    }

    // Very low = escalate
    return DecisionOutcome.ESCALATE
  }

  /**
   * Generate human-readable reasoning
   */
  _generateReasoning(actionType, confidence, context) {
    const actionNames = {
      [ActionType.CLASSIFY_PAGE]: 'classify this page',
      [ActionType.GENERATE_TESTS]: 'generate tests',
      [ActionType.ANALYZE_SECURITY]: 'analyze security',
      [ActionType.FIND_EDGE_CASES]: 'find edge cases',
      [ActionType.EXECUTE_TEST]: 'execute tests',
      [ActionType.ASK_CLARIFICATION]: 'ask questions',
      [ActionType.WAIT_FOR_USER]: 'wait for input',
      [ActionType.REPORT_RESULTS]: 'report results',
      [ActionType.NAVIGATE]: 'navigate to the page',
      [ActionType.CLICK]: 'click the element',
      [ActionType.TYPE]: 'enter text',
      [ActionType.SCROLL]: 'scroll the page'
    }

    const actionName = actionNames[actionType] || 'proceed'

    if (confidence.canProceed) {
      return `I'm confident enough to ${actionName}. ${confidence.reasoning}`
    } else if (confidence.level === ConfidenceLevel.MODERATE) {
      return `I can ${actionName}, but a few clarifications would help. ${confidence.reasoning}`
    } else {
      return `I need more information before I can ${actionName}. ${confidence.reasoning}`
    }
  }

  /**
   * Generate next steps for proceeding
   */
  _generateNextSteps(actionType, context) {
    switch (actionType) {
      case ActionType.CLASSIFY_PAGE:
        return [
          'Identify page type based on elements',
          'Extract testable elements',
          'Prepare for test generation'
        ]

      case ActionType.GENERATE_TESTS:
        return [
          `Query brain for ${context.pageType || 'general'} testing rules`,
          'Generate tests for each category',
          'Prioritize by risk level'
        ]

      case ActionType.ANALYZE_SECURITY:
        return [
          'Check for common vulnerabilities',
          'Analyze input handling',
          'Review authentication flow'
        ]

      case ActionType.FIND_EDGE_CASES:
        return [
          'Identify boundary conditions',
          'Check error states',
          'Test unusual inputs'
        ]

      default:
        return []
    }
  }

  /**
   * Generate clarification questions
   */
  _generateQuestions(actionType, confidence, context) {
    const questions = []

    // Use confidence suggestions
    questions.push(...confidence.suggestions)

    // Action-specific questions
    if (actionType === ActionType.CLASSIFY_PAGE && !context.pageType) {
      questions.push('What type of page is this?')
    }

    if (actionType === ActionType.GENERATE_TESTS) {
      if (!context.pageType) {
        questions.push('What feature should I focus on?')
      }
      if (context.knowledgeChunks.length === 0) {
        questions.push('Any specific testing requirements I should know?')
      }
    }

    if (actionType === ActionType.ANALYZE_SECURITY) {
      questions.push('Are there any known security concerns?')
    }

    // Limit questions
    return questions.slice(0, 3)
  }

  /**
   * Build payload for the action
   */
  _buildPayload(actionType, context) {
    return {
      action: actionType,
      pageType: context.pageType,
      elementCount: context.pageElements.length,
      knowledgeChunks: context.knowledgeChunks.length,
      url: context.pageUrl
    }
  }
}

/**
 * Quick decision helper
 */
function quickDecide(pageType = null, elements = [], request = null) {
  const context = createDecisionContext({
    pageType,
    pageElements: elements,
    userRequest: request
  })

  const engine = new DecisionEngine()
  // Note: This is synchronous for quick decisions
  return engine.decide(context)
}

module.exports = {
  ActionType,
  DecisionOutcome,
  DecisionEngine,
  createDecisionContext,
  createDecision,
  quickDecide
}
