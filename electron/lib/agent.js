/**
 * Yali AI Agent - Full Cortex Integration
 * Citation-aware reasoning with comprehensive QA knowledge base
 *
 * Ported from testai-agent Python implementation to JavaScript
 * Includes: Confidence scoring, Decision engine, Risk prioritization, QA Brain
 */

const { AGENT_LIMITS } = require('./config')
const { isQuestion, extractKeywords, findMatchingElements, sleep, detectPageType } = require('./utils')
const { getPageState, formatElementsForAI } = require('./dom-extractor')
const { callDeepSeek, isApiConfigured } = require('./api')
const { executeAction, shouldStopAfterAction } = require('./actions')
const { getThinkingPhrase } = require('./personality')
const { BROWSER_AGENT_PERSONA, QA_AGENT_PERSONA, getPageTypeHint } = require('./prompts')
const { getKnowledgeForPageType, formatKnowledgeForPrompt, getEdgeCases: getKnowledgeEdgeCases } = require('./knowledge')

// NEW: Page structure extraction for curious brain
const {
  extractPageStructure,
  formatStructureForPrompt,
  detectPageTypeFromStructure,
  compareStructures
} = require('./page-structure-extractor')

// Import full Cortex system
const {
  // Confidence scoring
  ConfidenceScorer,
  ConfidenceLevel,
  quickConfidence,

  // Decision engine
  DecisionEngine,
  ActionType,
  DecisionOutcome,
  createDecisionContext,

  // Test prioritization
  TestPrioritizer,
  prioritizeTests,
  getCriticalTests,
  Priority,

  // QA Brain (comprehensive knowledge base)
  getForPageType,
  formatForPrompt,
  getEdgeCases,
  getTestsFromSections,
  searchByKeyword,

  // Reasoner
  ReasoningPhase,
  Reasoner,
  quickReason,

  // Unified Agent (The Brain) - NEW
  UnifiedAgent,
  createUnifiedAgent,
  AgentState,

  // Adaptive Learner - NEW
  AdaptiveLearner,
  createAdaptiveLearner,

  // Root Cause Analyzer - NEW
  RootCauseAnalyzer,
  createRootCauseAnalyzer,
  quickAnalyze,

  // Vulnerability Scanner - NEW
  VulnerabilityScanner,
  quickScan,

  // Coverage Analyzer - NEW
  CoverageAnalyzer,
  quickCoverageCheck,

  // Clarifier - Smart Questions
  Clarifier,
  clarifyForPage,
  clarifyFeature,

  // Response Styler - Human-like Responses
  Confidence,
  ResponseStyler,
  styledResponse,
  getPhrase,
  CELEBRATIONS,
  TRANSITIONS,

  // Insight Engine - Pattern Detection
  InsightEngine,
  createInsightEngine,
  InsightPriority,

  // Test Recommender - AI Recommendations
  TestRecommender,
  createTestRecommender,
  RecommendationType,
  RecommendationImpact,

  // Flakiness Detector - Detect Flaky Tests
  FlakinessDetector,
  createFlakinessDetector,
  FlakinessPattern,
  FlakinessLevel,

  // Selector Healer - Self-Healing Tests
  SelectorHealer,
  createSelectorHealer,
  HealingStrategy,

  // Edge Case Detector - Find What Humans Miss
  EdgeCaseDetector,
  detectEdgeCases,
  getEdgeCaseTests,
  EdgeCaseCategory,

  // Retry Manager - Smart Retries with Adaptive Learning
  BackoffType,
  RetryDecision,
  QuarantineReason,
  QuarantineStatus,
  RetryStrategy,
  createRetryStrategy,
  AdaptiveRetryManager,
  createAdaptiveRetryManager,
  QuarantineManager,
  createQuarantineManager,

  // Test Scheduler - Parallel Execution Across Browsers/Devices
  ScheduleType,
  ScheduleStatus,
  RecurrencePattern,
  TestScheduler,
  createTestScheduler,
  createBrowserTarget,
  createDeviceTarget,

  // Change Detector - Git Diff Analysis for Smart Test Selection
  ChangeType,
  ChangeDetector,
  createChangeDetector,
  createChangeSet,

  // QA Orchestrator - TODO-driven Exploration with Full Logging
  TaskPriority,
  TaskStatus,
  OrchestratorState,
  QAOrchestrator,
  createQAOrchestrator,
  createTask,
  createTaskStep
} = require('./cortex')

// Singleton instance of the Unified Agent Brain
let _unifiedAgentInstance = null

/**
 * Get or create the unified agent instance (singleton)
 */
function getUnifiedAgent() {
  if (!_unifiedAgentInstance) {
    _unifiedAgentInstance = createUnifiedAgent({
      enableLearning: true,
      onStateChange: (state) => {
        console.log('[UnifiedAgent] State changed to:', state)
      },
      onThinking: (thought) => {
        console.log('[UnifiedAgent] Thinking:', thought)
      }
    })
  }
  return _unifiedAgentInstance
}

// Singleton instance of the QA Orchestrator
let _orchestratorInstance = null

/**
 * Get or create the QA orchestrator instance (singleton)
 */
function getOrchestrator(options = {}) {
  if (!_orchestratorInstance) {
    _orchestratorInstance = createQAOrchestrator({
      enableLearning: true,
      logAIPrompts: true,
      ...options
    })
  }
  return _orchestratorInstance
}

/**
 * Start an exploration session with TODO-driven testing
 * This is the main entry point for autonomous exploration
 *
 * Enhanced with:
 * - Page structure extraction (curious brain)
 * - Recursive exploration across pages
 * - Predictive thinking before actions
 */
async function startExploration(browserView, viewBounds, request, sendMessage, options = {}) {
  const orchestrator = getOrchestrator({
    sendMessage,
    // Enable exploration mode for recursive page exploration
    explorationMode: options.explorationMode !== false,
    maxExplorationDepth: options.maxDepth || 3,
    enablePredictions: options.enablePredictions !== false,
    onTodoUpdate: (summary) => {
      sendMessage?.('todo', summary)
    },
    onProgress: (progress) => {
      sendMessage?.('progress', progress)
    },
    onDiscovery: (discovery) => {
      sendMessage?.('discovery', `Found: ${discovery.description}`)
    },
    onPrediction: (prediction) => {
      sendMessage?.('prediction', `Expecting: ${prediction.expected}`)
    },
    onNavigation: (navEvent) => {
      sendMessage?.('navigation', `Navigated to: ${navEvent.to} (depth ${navEvent.depth})`)
    }
  })

  // Enable exploration mode explicitly
  orchestrator.setExplorationMode(true)

  // Set up dependencies
  orchestrator.setDependencies({
    // Execute actions on the page
    executeAction: async (task, context) => {
      const pageState = await getPageState(browserView)
      return executeAction(
        browserView,
        viewBounds,
        {
          action: task.action,
          elementId: task.targetElement,
          value: task.testData,
          // Pass exploration mode to action executor
          explorationMode: orchestrator.config.explorationMode
        },
        pageState,
        request,
        sendMessage
      )
    },

    // Get current page state
    getPageState: async () => {
      return getPageState(browserView)
    },

    // NEW: Get page structure for curious brain
    getPageStructure: async () => {
      return extractPageStructure(browserView)
    },

    // Call AI for planning/analysis
    callAI: async (messages, options) => {
      return callDeepSeek(messages, options)
    }
  })

  // Get initial page state
  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  // NEW: Get page structure for better understanding
  let pageStructure = null
  try {
    pageStructure = await extractPageStructure(browserView)
    if (pageStructure.success) {
      sendMessage?.('thinking', `📖 Page structure: ${pageStructure.h1 || pageStructure.title}`)
      sendMessage?.('thinking', `   ${pageStructure.sections.length} sections, ${pageStructure.forms.length} forms, ${pageStructure.keyActions.length} key actions`)
    }
  } catch (e) {
    console.log('Could not extract page structure:', e.message)
  }

  // Send initial TODO message
  sendMessage?.('thinking', `Planning exploration for: "${request}"`)

  // Start session with enhanced context
  const session = await orchestrator.startSession(request, {
    pageType,
    url: pageState.url,
    elements: pageState.elements,
    // NEW: Include page structure in context
    pageStructure: pageStructure?.success ? {
      h1: pageStructure.h1,
      sections: pageStructure.sections,
      forms: pageStructure.forms,
      keyActions: pageStructure.keyActions,
      summary: pageStructure.summary
    } : null
  })

  // Send TODO list to user
  sendMessage?.('todo_list', orchestrator.formatTodoList())

  // Run the exploration loop
  sendMessage?.('thinking', 'Starting exploration loop...')
  const report = await orchestrator.runLoop({ pageState, pageStructure })

  // Send final report with enhanced stats
  sendMessage?.('report', report)

  // Get AI prompt history for debugging
  const aiHistory = orchestrator.getAIPromptHistory()

  return {
    success: true,
    sessionId: session.sessionId,
    report,
    aiPromptHistory: aiHistory,
    todoSummary: orchestrator.getTodoSummary(),
    deduplicationStats: orchestrator.getDeduplicationStats(),

    // NEW: Exploration-specific results
    siteMap: orchestrator.getSiteMap(),
    navigationHistory: orchestrator.getNavigationStack(),
    explorationDepth: orchestrator.getCurrentDepth(),
    predictions: report.predictions,

    // Methods to access history
    getFormattedAIHistory: () => orchestrator.formatAIPromptHistory(),
    exportHistory: () => orchestrator.exportHistory(),
    printSummary: () => orchestrator.printHistorySummary()
  }
}

/**
 * Get current TODO list from orchestrator
 */
function getTodoList() {
  const orchestrator = getOrchestrator()
  return {
    formatted: orchestrator.formatTodoList(),
    summary: orchestrator.getTodoSummary(),
    queue: orchestrator.getTaskQueue(),
    state: orchestrator.getState()
  }
}

/**
 * Get all history from orchestrator
 */
function getExplorationHistory() {
  const orchestrator = getOrchestrator()
  return orchestrator.getAllHistory()
}

/**
 * Get AI prompt history (what was sent to AI)
 */
function getAIPromptHistory() {
  const orchestrator = getOrchestrator()
  return {
    prompts: orchestrator.getAIPromptHistory(),
    formatted: orchestrator.formatAIPromptHistory()
  }
}

/**
 * Export exploration history to JSON
 */
function exportExplorationHistory() {
  const orchestrator = getOrchestrator()
  return orchestrator.exportHistory()
}

/**
 * Check if user's question is already answered by current page
 */
function checkIfAnswered(userMessage, pageState) {
  if (!isQuestion(userMessage)) {
    return { isQuestion: false, answered: false }
  }

  const keywords = extractKeywords(userMessage)
  const matching = findMatchingElements(pageState.elements, userMessage)

  const visibleText = (pageState.visibleText || '').toLowerCase()
  const textMatches = keywords.filter(kw => visibleText.includes(kw))

  const answered = matching.length > 0 || textMatches.length >= 2

  return {
    isQuestion: true,
    answered,
    matchingElements: matching,
    textMatches
  }
}

/**
 * Get relevant QA knowledge for page
 * Uses the comprehensive QA Brain from cortex
 */
function retrieveKnowledge(pageType, userMessage) {
  // Try cortex brain first (comprehensive)
  let sections = getForPageType(pageType)

  // Fallback to old knowledge if cortex returns empty
  if (!sections || sections.length === 0) {
    sections = getKnowledgeForPageType(pageType)
  }

  // Format for prompt
  const formatted = sections.length > 0
    ? formatForPrompt(sections)
    : formatKnowledgeForPrompt(sections)

  // Get page-specific hints
  const hint = getPageTypeHint(pageType)

  // Get tests from brain sections
  const tests = sections.length > 0
    ? getTestsFromSections(sections)
    : []

  return {
    sections,
    formatted,
    hint,
    tests,
    hasKnowledge: sections.length > 0,
    // Citation helper
    getCitations() {
      return sections.map(s => s.cite ? s.cite() : `Section ${s.id || 'unknown'} - ${s.title}`)
    }
  }
}

/**
 * Calculate confidence score using Cortex ConfidenceScorer
 * Provides weighted multi-factor confidence analysis
 */
function calculateConfidence(pageState, knowledge, actionHistory) {
  const scorer = new ConfidenceScorer()

  // Calculate context availability
  const contextAvailable = pageState.hasPage && pageState.elements.length > 0

  // Calculate success rate from history
  const successRate = actionHistory.length > 0
    ? actionHistory.filter(a => !a.result.startsWith('FAILED')).length / actionHistory.length
    : 1

  // Use cortex scorer for comprehensive confidence
  const result = scorer.scoreGeneration(
    pageState.url || 'unknown',
    contextAvailable,
    knowledge.sections ? knowledge.sections.length : 0,
    successRate > 0.7 ? ['consistent_success'] : []
  )

  // Add legacy fields for backward compatibility
  return {
    ...result,
    // Legacy fields
    level: result.level === ConfidenceLevel.VERY_HIGH || result.level === ConfidenceLevel.HIGH
      ? 'high'
      : result.level === ConfidenceLevel.MODERATE
        ? 'medium'
        : 'low',
    // New detailed fields
    factors: result.factors,
    suggestions: result.suggestions,
    reasoning: result.reasoning
  }
}

/**
 * Check if user wants autonomous exploration/analysis
 * This is now determined by AI, not hardcoded patterns
 * Keeping the function for backwards compatibility but it always returns false
 * The AI's decision prompt handles intent detection
 */
function isExplorationRequest(message) {
  // Let AI decide - no hardcoded patterns
  return false
}

/**
 * Extract testing intent from a message
 * Now returns a generic response - AI determines the actual intent
 */
function extractTestingIntent(message) {
  // Let AI decide the specific testing intent
  return { type: 'comprehensive', description: 'Testing' }
}

/**
 * Build decision prompt - SIMPLE and ACTION-ORIENTED
 */
function buildDecisionPrompt(userMessage, pageState, actionHistory, iteration, maxIterations, knowledge) {
  const elementsForAI = formatElementsForAI(pageState.elements, 50)

  // Build step-by-step journey showing what we've done so far
  let stepsText = ''
  if (actionHistory.length > 0) {
    stepsText = `\n📋 STEPS COMPLETED SO FAR:\n`
    actionHistory.forEach((a, i) => {
      const icon = a.action === 'click' ? '👆' : a.action === 'type' ? '⌨️' : a.action === 'scroll' ? '📜' : '▶️'
      const target = a.elementId ? ` "${a.elementText || a.elementId}"` : ''
      const value = a.value ? ` with "${a.value}"` : ''
      stepsText += `   Step ${i + 1}: ${icon} ${a.action}${target}${value} → ${a.result}\n`
    })
    stepsText += `\n⚠️ DO NOT repeat these actions! Move to the NEXT step.`
  }

  // Separate inputs for visibility - these are important!
  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const inputsText = inputs.length > 0
    ? `\n📝 INPUT FIELDS ON PAGE:\n${inputs.map(i => `   - ${i.id}: "${i.label || i.placeholder || i.name || 'input'}" (${i.type || 'text'})${i.value ? ` [has value: "${i.value}"]` : ' [empty]'}`).join('\n')}`
    : ''

  // Buttons/clickable elements
  const buttons = pageState.elements.filter(e => e.category === 'button')
  const buttonsText = buttons.length > 0
    ? `\n🔘 BUTTONS ON PAGE:\n${buttons.slice(0, 10).map(b => `   - ${b.id}: "${b.text || b.label || 'button'}"`).join('\n')}`
    : ''

  // Only include knowledge if user is asking about TESTING
  const isTestingRequest = /test|generate|qa|quality|check|validate|verify/i.test(userMessage)
  const knowledgeSection = isTestingRequest ? `\nQA KNOWLEDGE:\n${knowledge.formatted}` : ''

  return `USER'S GOAL: "${userMessage}"

CURRENT PAGE: ${pageState.url}
STEP: ${iteration} of ${maxIterations}
${stepsText}
${inputsText}
${buttonsText}
${knowledgeSection}

WHAT'S YOUR NEXT STEP? Return JSON:

To CLICK something:
{ "action": "click", "elementId": "testai-X" }

To TYPE text:
{ "action": "type", "elementId": "testai-X", "value": "text to type" }

To SCROLL:
{ "action": "scroll", "direction": "down" }

To PRESS ENTER (submit forms):
{ "action": "press_enter" }

When USER'S ENTIRE GOAL is COMPLETE:
{ "action": "task_complete", "summary": "what you accomplished" }

If you TRULY need info from user (password, captcha, etc.):
{ "action": "need_input", "question": "what you need" }

If element NOT FOUND or stuck:
{ "action": "cannot_proceed", "reason": "why" }

---
**CRITICAL RULES:**
1. ⚠️ NEVER click the same element twice! Check ALREADY CLICKED list above
2. If you clicked a button and a modal/form appeared, look for NEW elements (inputs, different buttons)
3. If there's an INPUT FIELD, TYPE in it before clicking submit buttons
4. KEEP GOING until the user's goal is achieved
5. If you see same elements after clicking, the page didn't change - try a DIFFERENT action
6. Progress forward - don't repeat the same action expecting different results

Return ONLY JSON for the NEXT action needed.`
}

/**
 * Detect if page requires authentication
 * Now returns minimal info - AI makes the decision about login handling
 */
function isLoginPage(pageState) {
  const inputs = pageState.elements.filter(e => e.category === 'text-input')

  // Just return basic field info, let AI decide what to do
  return {
    isLogin: false, // AI decides this
    hasPasswordField: inputs.some(e => e.type === 'password'),
    hasEmailField: inputs.some(e => e.type === 'email'),
    hasLoginButton: false, // AI decides this
    fields: inputs.map(i => ({
      type: i.type,
      label: i.label || i.placeholder || i.name,
      id: i.id
    }))
  }
}

/**
 * REAL QA Exploration - Think like a senior QA engineer
 *
 * SMART BEHAVIOR:
 * - Detects login pages and asks for credentials
 * - Provides conversational, helpful responses
 * - Actually helps the user accomplish their goal
 */
async function runRealExploration(browserView, viewBounds, pageState, sendMessage) {
  const { clickElement, typeInElement: simTypeInElement } = require('./input-simulator')

  // ═══════════════════════════════════════════════════════════════════
  // STATE TRACKING - Remember what we've done, don't repeat
  // AI decides about login pages through the main decision prompt
  // ═══════════════════════════════════════════════════════════════════
  const state = {
    startUrl: pageState.url,
    testedElements: new Set(),
    testedActions: new Set(),
    visitedUrls: new Set([pageState.url]),
    consoleErrors: [],
    networkErrors: [],
    issues: [],
    actions: [],
    actionCount: 0
  }

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 1: Quick page analysis (less verbose)
  // ═══════════════════════════════════════════════════════════════════
  const plan = createTestPlan(pageState, sendMessage)

  // Friendly start message
  sendMessage?.('action', `📍 **${pageState.title || pageState.url}**\nFound ${pageState.elements.length} elements (${plan.tests.length} testable)\n`)
  await sleep(500)

  // ═══════════════════════════════════════════════════════════════════
  // SET UP ERROR CAPTURING - Console and Network errors
  // ═══════════════════════════════════════════════════════════════════
  sendMessage?.('action', `\n🔧 **PHASE 2: SETUP**\n${'─'.repeat(40)}`)
  sendMessage?.('action', `📡 Setting up error monitoring...`)

  // Capture console errors
  const consoleHandler = (event, level, message, line, sourceId) => {
    if (level === 2 || level === 3) { // Warning or Error
      state.consoleErrors.push({
        level: level === 2 ? 'warning' : 'error',
        message: message.slice(0, 200),
        source: sourceId,
        timestamp: Date.now()
      })
    }
  }
  browserView.webContents.on('console-message', consoleHandler)

  // Capture failed network requests
  try {
    browserView.webContents.session.webRequest.onErrorOccurred((details) => {
      if (details.error !== 'net::ERR_ABORTED') {
        state.networkErrors.push({
          url: details.url.slice(0, 100),
          error: details.error,
          timestamp: Date.now()
        })
      }
    })
  } catch (e) {
    console.log('Could not set up network monitoring:', e.message)
  }

  sendMessage?.('action', `✅ Monitoring: Console errors, Network failures`)
  await sleep(500)

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 3: EXECUTION - Run each test with ReAct reasoning
  // ═══════════════════════════════════════════════════════════════════
  sendMessage?.('action', `\n🚀 **PHASE 3: EXECUTION**\n${'─'.repeat(40)}`)
  await sleep(500)

  // Inject visual cursor into the page
  const { injectVisualCursor, hideCursor } = require('./input-simulator')
  await injectVisualCursor(browserView)
  sendMessage?.('action', `🖱️ Visual cursor activated`)
  await sleep(300)

  // Track if we've navigated away from original page
  let hasNavigated = false

  for (let i = 0; i < plan.tests.length && i < 12 && !hasNavigated; i++) {
    const test = plan.tests[i]
    const element = test.element

    // ─── Check if we already did this action ───
    const actionKey = `${test.type}:${test.name}`.toLowerCase()
    if (state.testedActions.has(actionKey)) {
      sendMessage?.('action', `⏭️ Skipping (already tested): ${test.name}`)
      continue
    }

    // ═══════════════════════════════════════════════════════════════════
    // ReAct: THOUGHT - Reason about what we're about to do
    // ═══════════════════════════════════════════════════════════════════
    const thought = generateThought(test, state, plan, i)
    sendMessage?.('action', `\n💭 **Thought:** ${thought}`)

    // ─── Check current page state (might have changed) ───
    let currentState
    try {
      currentState = await getPageState(browserView)
    } catch (e) {
      // Before calling crash recovery, check if we navigated to a different page
      // If we're on a different URL, that's not a crash - just normal navigation
      let currentUrl = null
      try {
        currentUrl = await browserView.webContents.getURL()
      } catch (urlErr) {
        // Truly crashed
      }

      // If we're on a different URL than we started, this isn't a crash - we navigated
      if (currentUrl && currentUrl !== state.startUrl && currentUrl !== 'about:blank') {
        sendMessage?.('action', `📍 Now on different page: ${currentUrl}`)
        // We navigated - don't "recover" by going back to original page!
        // Just break out and let user see where they are
        state.visitedUrls.add(currentUrl)
        hasNavigated = true
        break
      }

      // Actual crash - page is blank or errored on same URL
      sendMessage?.('action', `💥 **Page Error Detected!** Attempting recovery...`)
      const recovered = await recoverFromCrash(browserView, state.startUrl, sendMessage)
      if (!recovered) {
        state.issues.push({ type: 'crash', message: 'Page crashed and could not recover' })
        break
      }
      currentState = await getPageState(browserView)
    }

    // ─── Check if element still exists ───
    const currentElement = currentState.elements.find(e => e.id === element.id)
    if (!currentElement) {
      // Element gone - page might have changed
      sendMessage?.('action', `⚠️ Element "${test.name}" no longer exists - page changed`)
      state.issues.push({ type: 'element_gone', element: test.name })
      continue
    }

    // ─── Execute the test ───
    sendMessage?.('action', `\n▶️ [${i + 1}/${Math.min(plan.tests.length, 12)}] ${test.description}`)

    const result = await executeTest(test, browserView, viewBounds, state, sendMessage)

    // Mark as tested
    state.testedActions.add(actionKey)
    state.testedElements.add(element.id)

    // ─── Handle navigation (went to different page) ───
    if (result.navigated) {
      state.visitedUrls.add(result.newUrl)
      sendMessage?.('action', `📍 Navigated to: ${result.newUrl}`)

      // ═══════════════════════════════════════════════════════════════════
      // STAY ON NEW PAGE - Don't go back!
      // A real QA explores where they land, not constantly going back.
      // The test plan was for the original page - we're now done with it.
      // ═══════════════════════════════════════════════════════════════════
      sendMessage?.('action', `\n🔍 **Now on new page - analyzing...**`)
      await sleep(2000) // Let page fully load

      try {
        // Get the new page state
        const newPageState = await getPageState(browserView)
        const newButtons = newPageState.elements.filter(e => e.category === 'button')
        const newInputs = newPageState.elements.filter(e => e.category === 'text-input')

        // Report what we found
        sendMessage?.('action', `📄 Page: ${newPageState.title || result.newUrl}`)
        sendMessage?.('action', `   Elements: ${newButtons.length} buttons, ${newInputs.length} inputs`)

        // Log key elements found
        const keyElements = newButtons.slice(0, 5).map(b => b.text || b.label).filter(Boolean)
        if (keyElements.length > 0) {
          sendMessage?.('action', `   Buttons: ${keyElements.join(', ')}`)
        }

        // Check for issues
        if (newPageState.elements.length === 0) {
          state.issues.push({ type: 'empty_page', url: result.newUrl })
          sendMessage?.('action', `⚠️ Warning: Page appears empty`)
        }

      } catch (e) {
        sendMessage?.('action', `⚠️ Could not analyze: ${e.message}`)
      }

      // STOP testing the old page's elements - they don't exist anymore
      // Break out of the loop since we're on a new page now
      sendMessage?.('action', `\n✅ Navigation complete. Original page test finished.`)
      sendMessage?.('action', `💡 Say "explore" again to test this new page.`)
      hasNavigated = true  // Ensure we exit the loop
      break
    }

    // ═══════════════════════════════════════════════════════════════════
    // ReAct: OBSERVATION - What happened after the action?
    // ═══════════════════════════════════════════════════════════════════
    const observations = []

    // Check for errors after action
    const recentConsoleErrors = state.consoleErrors.filter(e => Date.now() - e.timestamp < 5000)
    const recentNetErrors = state.networkErrors.filter(e => Date.now() - e.timestamp < 5000)

    if (result.success) {
      observations.push(`Action completed successfully.`)
    } else {
      observations.push(`Action failed: ${result.error || 'unknown reason'}.`)
    }

    if (result.navigated) {
      observations.push(`Page navigated to ${result.newUrl}.`)
    }

    if (recentConsoleErrors.length > 0) {
      observations.push(`⚠️ ${recentConsoleErrors.length} JavaScript error(s) detected.`)
      state.issues.push({
        type: 'console_error',
        action: test.description,
        errors: recentConsoleErrors.map(e => e.message)
      })
    }

    if (recentNetErrors.length > 0) {
      observations.push(`⚠️ ${recentNetErrors.length} network error(s) detected.`)
      state.issues.push({
        type: 'network_error',
        action: test.description,
        errors: recentNetErrors.map(e => `${e.error}: ${e.url}`)
      })
    }

    sendMessage?.('action', `👁️ **Observation:** ${observations.join(' ')}`)

    // Pause between tests (human-like pacing)
    await sleep(1500)
  }

  // Hide cursor when done
  await hideCursor(browserView)

  // Clean up listeners
  browserView.webContents.removeListener('console-message', consoleHandler)

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 4: REPORT - Generate detailed findings
  // ═══════════════════════════════════════════════════════════════════
  sendMessage?.('action', `\n📊 **PHASE 4: REPORT**\n${'─'.repeat(40)}`)
  await sleep(500)

  const report = generateDetailedReport(state, plan, pageState)

  sendMessage?.('action', report.summary)

  return {
    report: report.full,
    actionsTaken: state.actionCount,
    issues: state.issues,
    consoleErrors: state.consoleErrors,
    networkErrors: state.networkErrors,
    tested: state.testedElements.size
  }
}

/**
 * ReAct: Generate a thought/reasoning before each action
 * This makes the QA process transparent and logical
 */
function generateThought(test, state, plan, index) {
  const { name, type, priority, element } = test
  const tested = state.testedElements.size
  const remaining = plan.tests.length - index - 1

  // Build contextual reasoning
  const thoughts = []

  // Why this element?
  if (priority === 'HIGH') {
    thoughts.push(`"${name}" is a primary action - testing it first is critical.`)
  } else if (priority === 'LAST') {
    thoughts.push(`"${name}" ends the session, so I saved it for last.`)
  } else if (type === 'type') {
    thoughts.push(`I need to test if the "${name}" input accepts and validates data correctly.`)
  } else {
    thoughts.push(`Testing "${name}" to verify it responds correctly.`)
  }

  // Context awareness
  if (tested > 0) {
    thoughts.push(`Already tested ${tested} elements without major issues.`)
  }

  if (state.consoleErrors.length > 0) {
    thoughts.push(`⚠️ Noticed ${state.consoleErrors.length} console errors so far - watching for more.`)
  }

  if (remaining <= 3 && remaining > 0) {
    thoughts.push(`Almost done - ${remaining} more to test.`)
  }

  // What I expect
  if (type === 'click') {
    if (/nav|menu|tab|link/i.test(name)) {
      thoughts.push(`Expecting this might navigate to a different view.`)
    } else if (/submit|save|create/i.test(name)) {
      thoughts.push(`This is a form action - expecting validation or confirmation.`)
    }
  }

  return thoughts.join(' ')
}

/**
 * Create a smart test plan based on page analysis
 */
function createTestPlan(pageState, sendMessage) {
  const buttons = pageState.elements.filter(e => e.category === 'button')
  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const links = pageState.elements.filter(e => e.category === 'link')
  const dropdowns = pageState.elements.filter(e => e.category === 'dropdown')

  // Detect page type
  const url = pageState.url.toLowerCase()
  let pageType = 'general'
  let strategy = 'Systematic element testing'

  if (/login|signin|auth/.test(url)) {
    pageType = 'login'
    strategy = 'Test authentication flow, validation, error handling'
  } else if (/dashboard|home|main/.test(url)) {
    pageType = 'dashboard'
    strategy = 'Test navigation, widgets, data loading'
  } else if (/settings|config|preferences/.test(url)) {
    pageType = 'settings'
    strategy = 'Test form saves, validation, resets'
  } else if (/form|create|edit|new/.test(url)) {
    pageType = 'form'
    strategy = 'Test input validation, submission, required fields'
  } else if (inputs.length > 3) {
    pageType = 'form'
    strategy = 'Test all inputs and form submission'
  }

  // Build prioritized test list
  const tests = []
  const seen = new Set()

  // Helper to add unique tests
  const addTest = (type, element, priority, description) => {
    const name = element.text || element.label || element.placeholder || element.name || element.id
    const key = `${type}:${name}`.toLowerCase()
    if (seen.has(key) || !name || name.length < 2) return
    seen.add(key)

    tests.push({
      type,
      element,
      name,
      priority,
      description: description || `${type}: ${name}`
    })
  }

  // 1. HIGH PRIORITY - Main action buttons (not navigation)
  buttons.forEach(btn => {
    const text = (btn.text || btn.label || '').toLowerCase()

    // Skip dangerous/logout buttons
    if (/delete|remove|logout|sign.?out|cancel|close|exit/i.test(text)) return

    // Primary actions
    if (/submit|save|create|add|send|confirm|apply|update/i.test(text)) {
      addTest('click', btn, 'HIGH', `Click primary action: ${btn.text || btn.label}`)
    }
  })

  // 2. MEDIUM PRIORITY - Input fields
  inputs.forEach(input => {
    const label = input.label || input.placeholder || input.name
    if (label) {
      addTest('type', input, 'MEDIUM', `Test input: ${label}`)
    }
  })

  // 3. MEDIUM PRIORITY - Navigation/feature buttons
  buttons.forEach(btn => {
    const text = (btn.text || btn.label || '').toLowerCase()
    if (/delete|remove|logout|sign.?out|cancel|close|exit|submit|save|create|add|send|confirm|apply|update/i.test(text)) return
    addTest('click', btn, 'MEDIUM', `Click button: ${btn.text || btn.label}`)
  })

  // 4. LOW PRIORITY - Dropdowns
  dropdowns.forEach(dd => {
    addTest('click', dd, 'LOW', `Test dropdown: ${dd.label || dd.name || 'dropdown'}`)
  })

  // 5. LAST - Logout/Sign out (only one)
  const logoutBtn = buttons.find(b => /logout|sign.?out/i.test(b.text || b.label || ''))
  if (logoutBtn) {
    addTest('click', logoutBtn, 'LAST', `Logout: ${logoutBtn.text || logoutBtn.label}`)
  }

  return {
    pageType,
    strategy,
    tests,
    elementCounts: {
      buttons: buttons.length,
      inputs: inputs.length,
      links: links.length,
      dropdowns: dropdowns.length
    }
  }
}

/**
 * Execute a single test with proper error handling
 */
async function executeTest(test, browserView, viewBounds, state, sendMessage) {
  const { clickElement, typeInElement: simTypeInElement } = require('./input-simulator')

  const result = {
    success: false,
    navigated: false,
    newUrl: null,
    error: null
  }

  const beforeUrl = await browserView.webContents.getURL()

  try {
    if (test.type === 'click') {
      sendMessage?.('action', `👆 Clicking "${test.name}"...`)

      const clickResult = await clickElement(browserView, viewBounds, test.element.id)
      await sleep(1000)

      if (clickResult.success) {
        state.actionCount++
        state.actions.push({ type: 'click', name: test.name, success: true })
        sendMessage?.('action', `✅ Clicked: ${test.name}`)
        result.success = true

        // Check for navigation
        const afterUrl = await browserView.webContents.getURL()
        if (afterUrl !== beforeUrl) {
          result.navigated = true
          result.newUrl = afterUrl
        }
      } else {
        state.issues.push({ type: 'click_failed', element: test.name })
        sendMessage?.('action', `⚠️ Click had no effect: ${test.name}`)
      }
    } else if (test.type === 'type') {
      const testValue = getTestValueForInput(test.element)
      sendMessage?.('action', `⌨️ Typing "${testValue}" in ${test.name}...`)

      // Focus first
      await clickElement(browserView, viewBounds, test.element.id)
      await sleep(300)

      // Type
      await simTypeInElement(browserView, test.element.id, testValue)
      await sleep(500)

      state.actionCount++
      state.actions.push({ type: 'type', name: test.name, value: testValue, success: true })
      sendMessage?.('action', `✅ Typed in ${test.name}`)
      result.success = true
    }
  } catch (err) {
    result.error = err.message
    state.issues.push({ type: 'error', action: test.description, error: err.message })
    sendMessage?.('action', `❌ Error: ${err.message}`)
  }

  return result
}

/**
 * Recover from page crash
 */
async function recoverFromCrash(browserView, startUrl, sendMessage) {
  try {
    sendMessage?.('action', `🔄 Attempting to reload page...`)
    await browserView.webContents.loadURL(startUrl)
    await sleep(3000)

    const newUrl = await browserView.webContents.getURL()
    if (newUrl && newUrl !== 'about:blank') {
      sendMessage?.('action', `✅ Recovered! Back on ${newUrl}`)
      return true
    }
  } catch (e) {
    sendMessage?.('action', `❌ Could not recover: ${e.message}`)
  }
  return false
}

/**
 * Generate a conversational, user-friendly summary
 * Not a boring technical report - talk like a helpful colleague
 */
function generateDetailedReport(state, plan, pageState) {
  const { issues, consoleErrors, networkErrors, testedElements } = state
  const totalIssues = issues.length + consoleErrors.length + networkErrors.length

  // Start with a friendly summary
  let summary = ''

  if (totalIssues === 0) {
    // All good!
    summary = `✅ **Looking good!**\n\n`
    summary += `I tested ${testedElements.size} elements on this page and everything seems to be working correctly.\n\n`
    summary += `**What I checked:**\n`
    summary += `• Clicked ${state.actionCount} interactive elements\n`
    summary += `• Monitored for JavaScript errors\n`
    summary += `• Watched network requests\n\n`
    summary += `No issues found! Would you like me to:\n`
    summary += `• Test with specific data?\n`
    summary += `• Check accessibility?\n`
    summary += `• Run security tests?`
  } else {
    // Found issues
    summary = `⚠️ **Found ${totalIssues} thing${totalIssues > 1 ? 's' : ''} to look at**\n\n`

    if (consoleErrors.length > 0) {
      summary += `**JavaScript Errors (${consoleErrors.length}):**\n`
      consoleErrors.slice(0, 2).forEach(err => {
        const shortMsg = err.message.length > 60 ? err.message.slice(0, 60) + '...' : err.message
        summary += `• ${shortMsg}\n`
      })
      if (consoleErrors.length > 2) {
        summary += `• ... and ${consoleErrors.length - 2} more\n`
      }
      summary += `\n`
    }

    if (networkErrors.length > 0) {
      summary += `**Network Issues (${networkErrors.length}):**\n`
      networkErrors.slice(0, 2).forEach(err => {
        summary += `• Failed to load: ${err.url.split('/').pop() || err.url}\n`
      })
      summary += `\n`
    }

    if (issues.length > 0) {
      summary += `**Other Issues:**\n`
      issues.slice(0, 3).forEach(issue => {
        summary += `• ${issue.element || issue.action || issue.message || 'Unknown issue'}\n`
      })
      summary += `\n`
    }

    summary += `Would you like me to investigate any of these further?`
  }

  return {
    summary,
    full: summary
  }
}

/**
 * Get appropriate test value for an input field
 */
function getTestValueForInput(input) {
  const type = input.type || 'text'
  const name = (input.name || input.label || '').toLowerCase()

  if (type === 'email' || name.includes('email')) return 'test@example.com'
  if (type === 'password' || name.includes('password')) return 'TestPass123!'
  if (type === 'tel' || name.includes('phone')) return '555-1234'
  if (type === 'number' || name.includes('amount') || name.includes('price')) return '100'
  if (name.includes('name')) return 'Test User'
  if (name.includes('search')) return 'test search'
  if (name.includes('url') || name.includes('website')) return 'https://example.com'

  return 'Test value'
}

/**
 * Generate exploration report
 */
function generateExplorationReport(pageState, actions, issues, totalTested) {
  let report = `## 🔍 Exploration Report: ${pageState.title || pageState.url}\n\n`

  report += `### Summary\n`
  report += `- **Page:** ${pageState.url}\n`
  report += `- **Elements found:** ${pageState.elements.length}\n`
  report += `- **Actions performed:** ${actions.length}\n`
  report += `- **Issues found:** ${issues.length}\n\n`

  if (actions.length > 0) {
    report += `### Actions Performed\n`
    actions.slice(0, 10).forEach(a => {
      report += `- ${a.action === 'click' ? '🖱️ Clicked' : '⌨️ Typed'}: ${a.element}${a.value ? ` ("${a.value}")` : ''}\n`
    })
    if (actions.length > 10) report += `- ... and ${actions.length - 10} more\n`
    report += '\n'
  }

  if (issues.length > 0) {
    report += `### Issues Found\n`
    issues.forEach(issue => {
      report += `${issue}\n`
    })
    report += '\n'
  } else {
    report += `### ✅ No Critical Issues Found\n\n`
  }

  report += `### Recommendations\n`
  report += `- Test form submissions with invalid data\n`
  report += `- Check error handling and validation messages\n`
  report += `- Verify all navigation paths work correctly\n`

  return report
}

/**
 * Autonomous page analysis - like a curious QA engineer
 */
async function analyzePageAutonomously(browserView, sendMessage) {
  sendMessage?.('thinking', '🔍 Exploring the page like a QA engineer...')

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  // Categorize all elements
  const buttons = pageState.elements.filter(e => e.category === 'button')
  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const links = pageState.elements.filter(e => e.category === 'link')
  const dropdowns = pageState.elements.filter(e => e.category === 'dropdown')

  // Check for potential issues
  const issues = []

  // Check for inputs without labels
  const unlabeledInputs = inputs.filter(i => !i.label && !i.placeholder)
  if (unlabeledInputs.length > 0) {
    issues.push(`⚠️ ${unlabeledInputs.length} input field(s) without labels (accessibility issue)`)
  }

  // Check for buttons without text
  const emptyButtons = buttons.filter(b => !b.text && !b.label)
  if (emptyButtons.length > 0) {
    issues.push(`⚠️ ${emptyButtons.length} button(s) without text (accessibility issue)`)
  }

  // Check for links without href or text
  const badLinks = links.filter(l => !l.href || !l.text)
  if (badLinks.length > 0) {
    issues.push(`⚠️ ${badLinks.length} link(s) missing href or text`)
  }

  // Build detailed analysis
  const analysis = {
    url: pageState.url,
    title: pageState.title,
    pageType,
    elements: {
      total: pageState.elements.length,
      buttons: buttons.length,
      inputs: inputs.length,
      links: links.length,
      dropdowns: dropdowns.length
    },
    keyButtons: buttons.slice(0, 8).map(b => b.text || b.label).filter(Boolean),
    keyInputs: inputs.slice(0, 5).map(i => i.label || i.placeholder || i.name).filter(Boolean),
    keyLinks: links.slice(0, 8).map(l => l.text).filter(Boolean),
    issues,
    hasAuth: pageState.elements.some(e => e.type === 'password' || /login|sign|auth/i.test(e.text || '')),
    hasForms: inputs.length > 0,
    hasNavigation: links.length > 5
  }

  return analysis
}

/**
 * Main agent loop with citation-aware reasoning
 */
async function runAgentLoop(browserView, viewBounds, userMessage, sendMessage) {
  if (!isApiConfigured()) {
    return {
      success: false,
      error: 'API key not configured. Please add your DeepSeek API key in Settings.'
    }
  }

  // Check if this is a navigation request - extract URL
  const urlMatch = userMessage.match(/https?:\/\/[^\s]+|[\w.-]+\.(com|org|net|io|dev|co|app)[^\s]*/i)
  const navigateMatch = userMessage.match(/(?:go to|load|open|navigate to|visit)\s+(.+)/i)

  console.log('Agent - URL match:', urlMatch?.[0])
  console.log('Agent - Navigate match:', navigateMatch?.[1])

  // If no browser but user wants to navigate, we need the browser to be created first
  if (!browserView) {
    return {
      success: false,
      error: 'Browser not ready. Please try again.'
    }
  }

  const actionHistory = []
  const thinkingSteps = []
  let iteration = 0
  let finalResponse = ''

  try {
    // Phase 1: Understanding
    thinkingSteps.push(`💭 ${ReasoningPhase.UNDERSTANDING}: Parsing request...`)
    sendMessage?.('thinking', getThinkingPhrase('receiving'))

    while (iteration < AGENT_LIMITS.maxIterations) {
    iteration++

    // Phase 2: Get fresh DOM state
    thinkingSteps.push(`💭 ${ReasoningPhase.RETRIEVING}: Getting current page state...`)
    sendMessage?.('thinking', `Step ${iteration}: ${getThinkingPhrase('analyzing')}`)

    const pageState = await getPageState(browserView)
    console.log('Page state - hasPage:', pageState.hasPage, 'url:', pageState.url)

    // If no page loaded, check if user wants to navigate
    if (!pageState.hasPage) {
      // Extract URL from message
      const urlMatch = userMessage.match(/https?:\/\/[^\s]+|[\w.-]+\.(com|org|net|io|dev|co|app)[^\s]*/i)
      const navigateMatch = userMessage.match(/(?:go to|load|open|navigate to|visit)\s+(.+)/i)

      let targetUrl = urlMatch?.[0] || navigateMatch?.[1]?.trim()

      if (targetUrl) {
        // User wants to navigate - do it!
        console.log('Navigating to:', targetUrl)
        sendMessage?.('action', `Navigating to ${targetUrl}...`)

        // Normalize URL
        if (!/^https?:\/\//i.test(targetUrl)) {
          const isLocal = targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1')
          targetUrl = (isLocal ? 'http://' : 'https://') + targetUrl
        }

        try {
          await browserView.webContents.loadURL(targetUrl)
          await sleep(2500) // Wait for page to load

          // Page loaded - DON'T STOP HERE!
          // Continue the agent loop - it will see the new page and keep working
          sendMessage?.('action', `✓ Loaded page, continuing...`)

          // Continue to next iteration of the while loop
          // The loop will get fresh page state and decide what to do next
          continue
        } catch (navErr) {
          return {
            success: false,
            error: `Failed to load ${targetUrl}: ${navErr.message}`,
            thinking: thinkingSteps.join('\n')
          }
        }
      }

      // No URL found and no page loaded - this shouldn't happen if !pageState.hasPage
      return {
        success: false,
        error: 'No page loaded. Navigate to a page first or tell me a URL to visit.',
        thinking: thinkingSteps.join('\n')
      }
    }

    // Log what we found on the page
    console.log('=== PAGE ANALYSIS ===')
    console.log('URL:', pageState.url)
    console.log('Elements found:', pageState.elements.length)

    // Categorize elements
    const buttons = pageState.elements.filter(e => e.category === 'button')
    const inputs = pageState.elements.filter(e => e.category === 'text-input')
    const links = pageState.elements.filter(e => e.category === 'link')

    console.log('- Buttons:', buttons.length, buttons.slice(0, 3).map(b => b.text || b.label).join(', '))
    console.log('- Inputs:', inputs.length, inputs.slice(0, 3).map(i => i.label || i.placeholder || i.name).join(', '))
    console.log('- Links:', links.length)

    // Send element info to UI
    sendMessage?.('thinking', `📋 Found ${pageState.elements.length} elements (${buttons.length} buttons, ${inputs.length} inputs)`)

    // AI decides what to do - no hardcoded exploration checks
    // The decision prompt handles all intent detection

    // Phase 3: Retrieve knowledge
    const pageType = detectPageType(pageState.url, pageState.elements)
    const knowledge = retrieveKnowledge(pageType, userMessage)
    thinkingSteps.push(`💭 ${ReasoningPhase.RETRIEVING}: Found ${knowledge.sections.length} knowledge sections for ${pageType}`)

    // Calculate confidence
    const confidence = calculateConfidence(pageState, knowledge, actionHistory)
    thinkingSteps.push(`💭 Confidence: ${confidence.level} (${Math.round(confidence.score * 100)}%)`)

    // Check if answer is already visible (for questions)
    const answerCheck = checkIfAnswered(userMessage, pageState)
    if (answerCheck.isQuestion && answerCheck.answered && iteration === 1) {
      const elements = answerCheck.matchingElements.slice(0, 5)
      thinkingSteps.push(`💭 Answer found on first look!`)
      return {
        success: true,
        response: `I can see what you're looking for!\n\n**Found on page:**\n${elements.map(e => `• ${e.text || e.label}`).join('\n')}`,
        actionsTaken: 0,
        thinking: thinkingSteps.join('\n'),
        confidence
      }
    }

    // Phase 4: Planning - Ask AI what to do
    thinkingSteps.push(`💭 ${ReasoningPhase.PLANNING}: Determining next action...`)

    const prompt = buildDecisionPrompt(
      userMessage,
      pageState,
      actionHistory,
      iteration,
      AGENT_LIMITS.maxIterations,
      knowledge
    )

    let decision
    try {
      console.log('=== ASKING AI FOR DECISION ===')
      console.log('Iteration:', iteration)
      console.log('Action history:', actionHistory.map(a => `${a.action}:${a.elementId}`).join(', ') || 'none')
      console.log('Inputs on page:', pageState.elements.filter(e => e.category === 'text-input').map(e => e.label || e.placeholder || e.id).join(', ') || 'none')
      console.log('Elements sent to AI:', pageState.elements.slice(0, 5).map(e => ({
        id: e.id,
        text: (e.text || e.label || '').slice(0, 30),
        category: e.category
      })))

      const response = await callDeepSeek([
        { role: 'system', content: BROWSER_AGENT_PERSONA + '\n\nReturn only valid JSON.' },
        { role: 'user', content: prompt }
      ], { jsonMode: true, maxTokens: 400, temperature: 0.1 })

      decision = JSON.parse(response.content)
      console.log('=== AI DECISION ===')
      console.log('Action:', decision.action)
      console.log('Element ID:', decision.elementId)
      console.log('Reason:', decision.reason)

      thinkingSteps.push(`💭 Decision: ${decision.action} ${decision.elementId || decision.url || ''}`)
      sendMessage?.('thinking', `🤔 Decided to: ${decision.action} ${decision.elementId ? `on ${decision.elementId}` : ''}`)
    } catch (e) {
      console.error('AI decision error:', e)
      decision = { action: 'cannot_proceed', reason: 'Failed to determine action: ' + e.message }
    }

    // Phase 5: Executing
    thinkingSteps.push(`💭 ${ReasoningPhase.EXECUTING}: ${decision.action}...`)

    const result = await executeAction(
      browserView,
      viewBounds,
      decision,
      pageState,
      userMessage,
      sendMessage
    )

    // Record in history with element details
    const targetElement = decision.elementId
      ? pageState.elements.find(e => e.id === decision.elementId)
      : null

    actionHistory.push({
      action: decision.action,
      result: result.success ? '✓ Success' : `✗ ${result.message}`,
      elementId: decision.elementId,
      elementText: targetElement?.text || targetElement?.label || targetElement?.placeholder || '',
      value: decision.value || ''
    })

    // Phase 6: Validating
    thinkingSteps.push(`💭 ${ReasoningPhase.VALIDATING}: ${result.success ? 'Success' : 'Failed'}`)

    // Check if we should stop
    if (shouldStopAfterAction(result)) {
      // ACTION COMPLETED - Now observe the result and respond naturally
      thinkingSteps.push(`💭 Action completed. Observing result...`)

      // Get fresh page state AFTER the action
      const newPageState = await getPageState(browserView)
      const newElements = formatElementsForAI(newPageState.elements, 20)

      // Ask AI to respond naturally based on what happened
      const responsePrompt = `You just completed ALL actions for the user's request.

USER'S ORIGINAL REQUEST: "${userMessage}"
FINAL ACTION: ${result.message}

NEW PAGE STATE:
- URL: ${newPageState.url}
- Title: ${newPageState.title || 'Unknown'}
- Key elements visible: ${newElements.slice(0, 10).map(e => e.text).filter(Boolean).join(', ')}

Respond naturally to the user. Tell them:
1. What you accomplished (the complete task, not just the last action)
2. What the current state is

IMPORTANT:
- Do NOT ask "what would you like me to do next" or similar
- Do NOT offer to help with something else
- Just report what you did and the result
- If you needed to stop for a specific reason (need password, captcha, etc.), explain that

Keep it brief (1-2 sentences). Be factual.`

      try {
        const naturalResponse = await callDeepSeek([
          { role: 'system', content: 'You are Yali, a friendly QA assistant. Respond naturally and conversationally.' },
          { role: 'user', content: responsePrompt }
        ], { maxTokens: 200, temperature: 0.5 })

        finalResponse = naturalResponse.content
      } catch (e) {
        // Fallback to basic message if AI fails
        finalResponse = result.message
      }

      break
    }

    // Wait for DOM to settle if changed
    if (result.domChanged) {
      await sleep(AGENT_LIMITS.domSettleTime)
    }

    // Check for repeated failures
    const recentFailures = actionHistory.slice(-3).filter(a => a.result.includes('✗'))
    if (recentFailures.length >= 3) {
      finalResponse = 'I seem to be stuck with failures. Could you clarify what you need?'
      break
    }

    // Check for stuck in scroll loop (no elements found)
    const recentScrolls = actionHistory.slice(-4).filter(a => a.action === 'scroll')
    if (recentScrolls.length >= 4) {
      finalResponse = `I've scrolled multiple times but the page doesn't seem to have more content. The page at ${pageState.url} might still be loading or has no interactive elements.`
      break
    }

    // Check for page with no elements (SPA still loading)
    if (pageState.elements.length === 0) {
      sendMessage?.('thinking', '⏳ Page seems empty, waiting for it to load...')
      await sleep(2000) // Wait longer for SPA

      // Re-check
      const retryState = await getPageState(browserView)
      if (retryState.elements.length === 0) {
        finalResponse = `The page at ${pageState.url} appears to be empty or still loading. You may need to refresh or check if the page loaded correctly.`
        break
      }
    }
  }

    // Summarize if we hit max iterations
    if (!finalResponse) {
      finalResponse = `Completed ${iteration} steps. ${actionHistory.filter(a => !a.result.startsWith('FAILED')).length} successful actions.`
    }

    return {
      success: true,
      response: finalResponse,
      actionsTaken: actionHistory.length,
      history: actionHistory,
      thinking: thinkingSteps.join('\n')
    }
  } catch (err) {
    console.error('Agent loop error:', err)
    return {
      success: false,
      error: `Agent error: ${err.message || String(err)}`,
      thinking: thinkingSteps.join('\n')
    }
  }
}

/**
 * Generate tests for current page using Cortex Reasoner
 * Uses citation-aware reasoning and risk-based prioritization
 */
async function generateTestsForPage(browserView, pageType) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) {
    return { success: false, error: 'No page loaded' }
  }

  const knowledge = retrieveKnowledge(pageType, 'generate tests')
  const elements = formatElementsForAI(pageState.elements, 50)

  // Create a reasoner with LLM callback
  const reasoner = new Reasoner({
    callLLM: async (messages, options) => {
      return await callDeepSeek(messages, options)
    }
  })

  try {
    // Use cortex reasoner for citation-aware test generation
    const reasoningResult = await reasoner.reasonAboutFeature(
      `${pageType} page testing`,
      'Generate comprehensive tests',
      pageType,
      pageState.elements
    )

    // If reasoner produced good output, use it
    if (reasoningResult.isConfident && reasoningResult.output) {
      // Also generate structured JSON tests
      const prompt = `${QA_AGENT_PERSONA}

Generate comprehensive test cases for this page.

PAGE INFO:
- URL: ${pageState.url}
- Title: ${pageState.title}
- Type: ${pageType}

ELEMENTS:
${JSON.stringify(elements, null, 2)}

${knowledge.formatted}

Generate 5-7 specific, actionable test cases. For each:
1. Test ID (TC_001, TC_002, etc.)
2. Name
3. Category (happy_path, edge_case, security, negative)
4. Priority (P0, P1, P2, P3)
5. Steps with specific test data
6. Expected result

Use REAL test data, not placeholders.

Return JSON:
{
  "testCases": [
    {
      "id": "TC_001",
      "name": "test name",
      "category": "category",
      "priority": "P0",
      "steps": [{ "action": "click/type/etc", "target": "element", "value": "data" }],
      "expectedResult": "what should happen"
    }
  ]
}`

      const response = await callDeepSeek([
        { role: 'system', content: 'Generate specific, actionable test cases. Return only valid JSON.' },
        { role: 'user', content: prompt }
      ], { jsonMode: true, maxTokens: 2000, temperature: 0.3 })

      const tests = JSON.parse(response.content)
      const testCases = tests.testCases || []

      // Prioritize tests using cortex prioritizer
      const prioritizedTests = prioritizeTests(testCases, pageType)

      return {
        success: true,
        tests: prioritizedTests,
        knowledge: knowledge.sections.map(s => s.title),
        citations: reasoningResult.citations,
        confidence: reasoningResult.confidence,
        thinking: reasoningResult.thinking
      }
    }

    // Fallback: get tests directly from brain
    const brainTests = knowledge.tests || []
    const prioritized = prioritizeTests(brainTests, pageType)

    return {
      success: true,
      tests: prioritized,
      knowledge: knowledge.sections.map(s => s.title),
      citations: knowledge.getCitations ? knowledge.getCitations() : [],
      fromBrain: true
    }
  } catch (e) {
    return { success: false, error: e.message }
  }
}

/**
 * Analyze security for current page using Cortex Reasoner
 * Uses comprehensive security knowledge from QA Brain
 */
async function analyzeSecurityForPage(browserView, pageType) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) {
    return { success: false, error: 'No page loaded' }
  }

  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const hasAuthElements = inputs.some(e => e.type === 'password' || e.type === 'email')

  // Get security edge cases from cortex brain
  const edgeCases = {
    email: getEdgeCases('email'),
    password: getEdgeCases('password'),
    text: getEdgeCases('text')
  }

  // Create a reasoner with LLM callback
  const reasoner = new Reasoner({
    callLLM: async (messages, options) => {
      return await callDeepSeek(messages, options)
    }
  })

  try {
    // Use cortex reasoner for security analysis
    const securityResult = await reasoner.analyzeSecurity(
      `${pageType} page`,
      pageType,
      pageState.elements
    )

    // Also get structured vulnerabilities via JSON
    const prompt = `You are a security-focused QA expert. Analyze this page for vulnerabilities.

PAGE INFO:
- URL: ${pageState.url}
- Type: ${pageType}
- Has auth elements: ${hasAuthElements}

INPUT FIELDS:
${inputs.map(e => `- ${e.label || e.name || e.id}: type=${e.type}`).join('\n')}

SECURITY TEST CASES TO TRY:
${JSON.stringify(edgeCases, null, 2)}

Identify:
1. Potential SQL injection points
2. XSS vulnerabilities
3. Authentication weaknesses
4. Input validation gaps

Return JSON:
{
  "vulnerabilities": [
    {
      "id": "VULN_001",
      "type": "xss|sql_injection|auth|validation",
      "severity": "critical|high|medium|low",
      "title": "vulnerability name",
      "description": "what's wrong",
      "testCase": "how to test it",
      "recommendation": "how to fix"
    }
  ]
}`

    const response = await callDeepSeek([
      { role: 'system', content: 'Identify security vulnerabilities. Return only valid JSON.' },
      { role: 'user', content: prompt }
    ], { jsonMode: true, maxTokens: 1500, temperature: 0.2 })

    const analysis = JSON.parse(response.content)

    // Prioritize vulnerabilities by severity
    const vulnerabilities = (analysis.vulnerabilities || []).sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
    })

    return {
      success: true,
      vulnerabilities,
      hasAuthElements,
      // Include cortex analysis
      analysis: securityResult.output,
      citations: securityResult.citations,
      confidence: securityResult.confidence,
      thinking: securityResult.thinking
    }
  } catch (e) {
    return { success: false, error: e.message }
  }
}

/**
 * Quick answer check - for simple questions
 */
async function quickAnswerCheck(browserView, userMessage) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) return null

  const check = checkIfAnswered(userMessage, pageState)
  if (check.isQuestion && check.answered) {
    return {
      found: true,
      elements: check.matchingElements.slice(0, 5)
    }
  }

  return null
}

/**
 * Find edge cases for a feature using Cortex Reasoner
 */
async function findEdgeCasesForPage(browserView, pageType) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) {
    return { success: false, error: 'No page loaded' }
  }

  // Create a reasoner with LLM callback
  const reasoner = new Reasoner({
    callLLM: async (messages, options) => {
      return await callDeepSeek(messages, options)
    }
  })

  try {
    const edgeCaseResult = await reasoner.findEdgeCases(
      `${pageType} page`,
      pageType
    )

    // Also get edge cases from brain for specific field types
    const inputs = pageState.elements.filter(e => e.category === 'text-input')
    const fieldEdgeCases = {}

    for (const input of inputs.slice(0, 10)) {
      const fieldType = input.type || 'text'
      if (!fieldEdgeCases[fieldType]) {
        fieldEdgeCases[fieldType] = getEdgeCases(fieldType)
      }
    }

    return {
      success: true,
      edgeCases: edgeCaseResult.output,
      fieldEdgeCases,
      citations: edgeCaseResult.citations,
      confidence: edgeCaseResult.confidence,
      thinking: edgeCaseResult.thinking
    }
  } catch (e) {
    return { success: false, error: e.message }
  }
}

/**
 * Get critical tests for immediate execution
 */
async function getCriticalTestsForPage(browserView, pageType) {
  const result = await generateTestsForPage(browserView, pageType)
  if (!result.success) return result

  const criticalTests = getCriticalTests(result.tests, pageType)

  return {
    success: true,
    tests: criticalTests,
    totalTests: result.tests.length,
    criticalCount: criticalTests.length
  }
}

module.exports = {
  // Main agent functions
  runAgentLoop,
  generateTestsForPage,
  analyzeSecurityForPage,
  quickAnswerCheck,
  checkIfAnswered,
  findEdgeCasesForPage,
  getCriticalTestsForPage,

  // Unified Agent (The Brain) - AUTONOMOUS AGENT
  getUnifiedAgent,
  UnifiedAgent,
  createUnifiedAgent,
  AgentState,

  // Adaptive Learning
  AdaptiveLearner,
  createAdaptiveLearner,

  // Root Cause Analysis
  RootCauseAnalyzer,
  createRootCauseAnalyzer,
  quickAnalyze,

  // Security Analysis
  VulnerabilityScanner,
  quickScan,

  // Coverage Analysis
  CoverageAnalyzer,
  quickCoverageCheck,

  // Reasoning phases
  ReasoningPhase,

  // Cortex exports for external use
  ConfidenceScorer,
  ConfidenceLevel,
  DecisionEngine,
  ActionType,
  DecisionOutcome,
  TestPrioritizer,
  Priority,
  Reasoner,
  prioritizeTests,
  getCriticalTests,
  getEdgeCases,
  quickConfidence,
  quickReason,

  // Smart Questions & Human-like Responses
  Clarifier,
  clarifyForPage,
  clarifyFeature,
  Confidence,
  ResponseStyler,
  styledResponse,
  getPhrase,
  CELEBRATIONS,
  TRANSITIONS,

  // Pattern Detection & Insights
  InsightEngine,
  createInsightEngine,
  InsightPriority,

  // AI Recommendations
  TestRecommender,
  createTestRecommender,
  RecommendationType,
  RecommendationImpact,

  // Flakiness Detection - Find Unreliable Tests
  FlakinessDetector,
  createFlakinessDetector,
  FlakinessPattern,
  FlakinessLevel,

  // Self-Healing Selectors - Auto-fix Broken Tests
  SelectorHealer,
  createSelectorHealer,
  HealingStrategy,

  // Edge Case Detection - Find What Humans Miss
  EdgeCaseDetector,
  detectEdgeCases,
  getEdgeCaseTests,
  EdgeCaseCategory,

  // Retry Manager - Smart Retries with Adaptive Learning
  BackoffType,
  RetryDecision,
  QuarantineReason,
  QuarantineStatus,
  RetryStrategy,
  createRetryStrategy,
  AdaptiveRetryManager,
  createAdaptiveRetryManager,
  QuarantineManager,
  createQuarantineManager,

  // Test Scheduler - Parallel Execution Across Browsers/Devices
  ScheduleType,
  ScheduleStatus,
  RecurrencePattern,
  TestScheduler,
  createTestScheduler,
  createBrowserTarget,
  createDeviceTarget,

  // Change Detector - Git Diff Analysis for Smart Test Selection
  ChangeType,
  ChangeDetector,
  createChangeDetector,
  createChangeSet,

  // QA Orchestrator - TODO-driven Exploration
  QAOrchestrator,
  createQAOrchestrator,
  getOrchestrator,
  TaskPriority,
  TaskStatus,
  OrchestratorState,

  // Exploration Functions
  startExploration,
  getTodoList,
  getExplorationHistory,
  getAIPromptHistory,
  exportExplorationHistory,

  // NEW: Page Structure Extraction
  extractPageStructure,
  formatStructureForPrompt,
  detectPageTypeFromStructure,
  compareStructures
}
