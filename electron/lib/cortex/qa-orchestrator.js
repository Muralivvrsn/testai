/**
 * Yali Agent - QA Orchestrator
 *
 * The main workflow controller that ties everything together.
 * Implements a TODO-driven exploration loop like a human QA engineer.
 *
 * Features:
 * - Task queue with priorities
 * - Full action/observation history
 * - AI prompt logging (see exactly what goes to AI)
 * - Discovery tracking
 * - Performance metrics
 * - State machine for exploration loop
 */

const { getForPageType, getEdgeCases, formatForPrompt } = require('./qa-brain')
const { detectEdgeCases } = require('./edge-case-detector')
const { createRetryStrategy, BackoffType } = require('./retry-manager')
const { createSelectorHealer } = require('./selector-healer')
const { createFlakinessDetector } = require('./flakiness-detector')
const { createInsightEngine } = require('./insight-engine')

/**
 * Task priorities (lower number = higher priority)
 */
const TaskPriority = {
  CRITICAL: 1,    // Security, data loss risks
  HIGH: 2,        // Core functionality
  MEDIUM: 3,      // Standard tests
  LOW: 4,         // Nice to have
  DISCOVERY: 5    // Found during exploration
}

/**
 * Task status
 */
const TaskStatus = {
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  FAILED: 'failed',
  SKIPPED: 'skipped',
  BLOCKED: 'blocked'
}

/**
 * Orchestrator states
 */
const OrchestratorState = {
  IDLE: 'idle',
  PLANNING: 'planning',
  EXECUTING: 'executing',
  OBSERVING: 'observing',
  DISCOVERING: 'discovering',
  LEARNING: 'learning',
  REPORTING: 'reporting',
  PAUSED: 'paused',
  COMPLETED: 'completed'
}

/**
 * Action types for history
 */
const ActionType = {
  CLICK: 'click',
  TYPE: 'type',
  SCROLL: 'scroll',
  NAVIGATE: 'navigate',
  WAIT: 'wait',
  ASSERT: 'assert',
  SCREENSHOT: 'screenshot',
  HOVER: 'hover',
  SELECT: 'select',
  CLEAR: 'clear'
}

/**
 * Create a task object
 */
function createTask(id, options = {}) {
  return {
    id,
    title: options.title || `Task ${id}`,
    description: options.description || '',
    type: options.type || 'test',           // test, explore, verify, edge_case
    priority: options.priority || TaskPriority.MEDIUM,
    status: TaskStatus.PENDING,

    // What to do
    targetElement: options.targetElement || null,
    action: options.action || null,
    testData: options.testData || null,
    expectedResult: options.expectedResult || null,

    // Sub-steps for this task (each task can have multiple actions)
    steps: options.steps || [],
    currentStepIndex: 0,

    // Execution tracking
    attempts: 0,
    maxAttempts: options.maxAttempts || 3,

    // Timing
    createdAt: Date.now(),
    startedAt: null,
    completedAt: null,
    durationMs: 0,

    // Results
    actualResult: null,
    error: null,
    observations: [],
    discoveries: [],
    stepResults: [],                        // Results for each step

    // Metadata
    source: options.source || 'manual',     // manual, brain, discovery, edge_case
    parentTaskId: options.parentTaskId || null,
    tags: options.tags || [],

    // For deduplication
    uniqueKey: options.uniqueKey || null    // Used to prevent duplicates
  }
}

/**
 * Create a task step (sub-action within a task)
 */
function createTaskStep(stepNumber, options = {}) {
  return {
    stepNumber,
    action: options.action || 'click',
    target: options.target || null,
    value: options.value || null,
    description: options.description || '',
    expectedResult: options.expectedResult || null,
    status: TaskStatus.PENDING,
    actualResult: null,
    error: null,
    durationMs: 0
  }
}

/**
 * Create an action record
 */
function createActionRecord(taskId, actionType, target, options = {}) {
  return {
    id: `ACT-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    taskId,
    actionType,
    target,                                  // Element ID or selector
    value: options.value || null,            // For type actions
    timestamp: Date.now(),

    // Before state
    beforeState: {
      url: options.beforeUrl || null,
      elementCount: options.beforeElementCount || 0,
      screenshot: options.beforeScreenshot || null
    },

    // After state
    afterState: {
      url: options.afterUrl || null,
      elementCount: options.afterElementCount || 0,
      screenshot: options.afterScreenshot || null,
      domChanged: options.domChanged || false,
      urlChanged: options.urlChanged || false,
      newElements: options.newElements || []
    },

    // Result
    success: options.success !== false,
    error: options.error || null,
    durationMs: options.durationMs || 0
  }
}

/**
 * Create an observation record
 */
function createObservation(taskId, actionId, options = {}) {
  return {
    id: `OBS-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    taskId,
    actionId,
    timestamp: Date.now(),

    // What was observed
    type: options.type || 'state_change',    // state_change, error, success, unexpected
    description: options.description || '',

    // Details
    expectedBehavior: options.expectedBehavior || null,
    actualBehavior: options.actualBehavior || null,
    matchesExpected: options.matchesExpected !== false,

    // Evidence
    screenshot: options.screenshot || null,
    consoleErrors: options.consoleErrors || [],
    networkRequests: options.networkRequests || [],

    // Classification
    severity: options.severity || 'info',    // info, warning, error, critical
    category: options.category || 'general', // ui, data, performance, security

    // AI interpretation
    aiAnalysis: options.aiAnalysis || null
  }
}

/**
 * Create a discovery record
 */
function createDiscovery(taskId, options = {}) {
  return {
    id: `DISC-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    taskId,
    timestamp: Date.now(),

    // What was discovered
    type: options.type || 'element',         // element, page, feature, bug, edge_case
    description: options.description || '',

    // Details
    element: options.element || null,        // For element discoveries
    url: options.url || null,                // For page discoveries
    feature: options.feature || null,        // For feature discoveries

    // Should we create a task for this?
    shouldCreateTask: options.shouldCreateTask !== false,
    createdTaskId: null,

    // Importance
    priority: options.priority || TaskPriority.DISCOVERY,
    confidence: options.confidence || 0.7
  }
}

/**
 * Create an AI prompt log entry
 */
function createAIPromptLog(purpose, messages, response, options = {}) {
  return {
    id: `PROMPT-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    timestamp: Date.now(),

    // Purpose
    purpose,                                 // plan, decide, analyze, observe, etc.
    taskId: options.taskId || null,

    // The actual prompt
    messages: messages.map(m => ({
      role: m.role,
      content: typeof m.content === 'string'
        ? m.content.slice(0, 10000)          // Truncate for storage
        : JSON.stringify(m.content).slice(0, 10000)
    })),

    // Token counts (estimated)
    inputTokens: options.inputTokens || messages.reduce((sum, m) =>
      sum + (m.content?.length || 0) / 4, 0),

    // Response
    response: {
      content: typeof response === 'string'
        ? response.slice(0, 10000)
        : JSON.stringify(response).slice(0, 10000),
      success: options.success !== false,
      error: options.error || null
    },
    outputTokens: options.outputTokens || (response?.length || 0) / 4,

    // Timing
    durationMs: options.durationMs || 0,

    // Model info
    model: options.model || 'unknown',
    temperature: options.temperature || 0
  }
}

/**
 * QA Orchestrator - The main workflow controller
 */
class QAOrchestrator {
  constructor(options = {}) {
    // Configuration
    this.config = {
      maxTasks: options.maxTasks || 100,
      maxRetries: options.maxRetries || 3,
      pauseBetweenTasks: options.pauseBetweenTasks || 500,
      screenshotOnAction: options.screenshotOnAction || false,
      stopOnCriticalError: options.stopOnCriticalError || true,
      enableLearning: options.enableLearning !== false,
      logAIPrompts: options.logAIPrompts !== false,
      // NEW: Recursive exploration settings
      maxExplorationDepth: options.maxExplorationDepth || 3,
      enablePredictions: options.enablePredictions !== false,
      explorationMode: options.explorationMode || false,
      ...options
    }

    // State
    this._state = OrchestratorState.IDLE
    this._currentTaskId = null
    this._taskCounter = 0
    this._sessionId = `SESSION-${Date.now()}`

    // Task queue (priority queue)
    this._taskQueue = []
    this._completedTasks = []
    this._failedTasks = []

    // History logs
    this._actionHistory = []
    this._observationLog = []
    this._discoveryLog = []
    this._aiPromptLog = []
    this._predictionLog = []  // NEW: Track predictions vs outcomes

    // Performance metrics
    this._metrics = {
      startTime: null,
      endTime: null,
      totalTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      skippedTasks: 0,
      totalActions: 0,
      totalObservations: 0,
      totalDiscoveries: 0,
      totalAIPrompts: 0,
      totalAIDurationMs: 0,
      totalExecutionMs: 0,
      // NEW: Exploration metrics
      maxDepthReached: 0,
      pagesExplored: 0,
      predictionsCorrect: 0,
      predictionsWrong: 0
    }

    // Sub-components
    this._retryStrategy = createRetryStrategy(3, BackoffType.EXPONENTIAL, 500)
    this._selectorHealer = createSelectorHealer()
    this._flakinessDetector = createFlakinessDetector()
    this._insightEngine = createInsightEngine()

    // DEDUPLICATION - Track what we've already done
    this._completedActions = new Set()      // "click:element-id", "type:input-name:value"
    this._visitedUrls = new Set()           // URLs we've already explored
    this._testedElements = new Set()        // Element IDs we've interacted with
    this._usedTestData = new Map()          // element -> [values tested]
    this._taskUniqueKeys = new Set()        // Unique keys for task deduplication

    // NEW: Navigation and depth tracking for recursive exploration
    this._navigationStack = []              // Stack of { url, pageStructure, timestamp }
    this._siteMap = {}                      // url -> { title, structure, testedElements, depth }
    this._currentDepth = 0                  // Current exploration depth
    this._startUrl = null                   // Original starting URL

    // NEW: Page structure extractor (injected)
    this._getPageStructure = options.getPageStructure || null

    // Callbacks
    this._callbacks = {
      onStateChange: options.onStateChange || null,
      onTaskStart: options.onTaskStart || null,
      onTaskComplete: options.onTaskComplete || null,
      onDiscovery: options.onDiscovery || null,
      onObservation: options.onObservation || null,
      onAIPrompt: options.onAIPrompt || null,
      onProgress: options.onProgress || null,
      onTodoUpdate: options.onTodoUpdate || null,    // Called when TODO list changes
      sendMessage: options.sendMessage || null,       // For sending messages to UI
      onPrediction: options.onPrediction || null,    // NEW: Called when making predictions
      onNavigation: options.onNavigation || null     // NEW: Called when navigating to new page
    }

    // External dependencies (injected)
    this._executeAction = options.executeAction || null
    this._getPageState = options.getPageState || null
    this._callAI = options.callAI || null
  }

  /**
   * Set external dependencies
   */
  setDependencies(deps) {
    if (deps.executeAction) this._executeAction = deps.executeAction
    if (deps.getPageState) this._getPageState = deps.getPageState
    if (deps.callAI) this._callAI = deps.callAI
    if (deps.getPageStructure) this._getPageStructure = deps.getPageStructure
  }

  /**
   * Enable exploration mode (don't stop on clicks)
   */
  setExplorationMode(enabled) {
    this.config.explorationMode = enabled
  }

  /**
   * Get current exploration depth
   */
  getCurrentDepth() {
    return this._currentDepth
  }

  /**
   * Get the site map built during exploration
   */
  getSiteMap() {
    return { ...this._siteMap }
  }

  /**
   * Get navigation history
   */
  getNavigationStack() {
    return [...this._navigationStack]
  }

  /**
   * Start a new QA session
   */
  async startSession(request, context = {}) {
    this._sessionId = `SESSION-${Date.now()}`
    this._metrics.startTime = Date.now()
    this._state = OrchestratorState.PLANNING
    this._emit('onStateChange', this._state)

    console.log(`\n${'='.repeat(60)}`)
    console.log(`  QA ORCHESTRATOR - SESSION: ${this._sessionId}`)
    console.log(`${'='.repeat(60)}`)
    console.log(`  Request: "${request}"`)
    console.log(`${'='.repeat(60)}\n`)

    // 1. PLAN - Create initial TODO list
    const tasks = await this._planTasks(request, context)

    console.log(`\n📋 INITIAL TODO LIST (${tasks.length} tasks):`)
    tasks.forEach((t, i) => {
      console.log(`  ${i + 1}. [P${t.priority}] ${t.title}`)
    })
    console.log('')

    // 2. Add tasks to queue
    for (const task of tasks) {
      this._addTask(task)
    }

    return {
      sessionId: this._sessionId,
      initialTasks: tasks.length,
      tasks: tasks.map(t => ({ id: t.id, title: t.title, priority: t.priority }))
    }
  }

  /**
   * Run the exploration loop until all tasks complete
   */
  async runLoop(context = {}) {
    console.log(`\n🔄 STARTING EXPLORATION LOOP`)
    console.log(`${'─'.repeat(60)}\n`)

    // Show initial TODO list
    console.log(this.formatTodoList())
    this._emit('onTodoUpdate', this.getTodoSummary())

    while (this._taskQueue.length > 0 && this._state !== OrchestratorState.PAUSED) {
      // Get next task
      const task = this._getNextTask()
      if (!task) break

      // Skip if duplicate (final check)
      if (this._isDuplicateTask(task)) {
        console.log(`   ⏭️  Skipping duplicate: ${task.title}`)
        this._metrics.skippedTasks++
        continue
      }

      this._currentTaskId = task.id
      this._state = OrchestratorState.EXECUTING
      this._emit('onStateChange', this._state)

      console.log(`\n▶️  EXECUTING: ${task.title}`)
      console.log(`   Task ID: ${task.id}`)
      console.log(`   Priority: ${this._getPriorityIcon(task.priority)} ${this._getPriorityName(task.priority)}`)
      if (task.steps.length > 0) {
        console.log(`   Steps: ${task.steps.length}`)
      }

      // Show current TODO state
      this._emit('onTodoUpdate', this.getTodoSummary())

      // Execute the task
      const result = await this._executeTask(task, context)

      // Skip observation/discovery if action was skipped (already done)
      if (!result.skipped) {
        // Observe the result
        this._state = OrchestratorState.OBSERVING
        await this._observeResult(task, result, context)

        // Check for discoveries
        this._state = OrchestratorState.DISCOVERING
        await this._checkForDiscoveries(task, result, context)

        // Learn from the result
        if (this.config.enableLearning) {
          this._state = OrchestratorState.LEARNING
          this._learnFromResult(task, result)
        }
      }

      // Mark task complete
      this._completeTask(task, result)

      // Progress update
      const summary = this.getTodoSummary()
      this._emit('onProgress', {
        ...summary,
        currentTask: task.title
      })
      this._emit('onTodoUpdate', summary)

      // Show updated TODO list periodically
      if (this._completedTasks.length % 5 === 0) {
        console.log(this.formatTodoList())
      }

      // Pause between tasks
      if (this.config.pauseBetweenTasks > 0) {
        await this._sleep(this.config.pauseBetweenTasks)
      }

      // Check for critical errors
      if (result.criticalError && this.config.stopOnCriticalError) {
        console.log(`\n⛔ CRITICAL ERROR - Stopping loop`)
        break
      }
    }

    // Generate final report
    this._state = OrchestratorState.REPORTING
    const report = this._generateReport()

    this._state = OrchestratorState.COMPLETED
    this._metrics.endTime = Date.now()
    this._metrics.totalExecutionMs = this._metrics.endTime - this._metrics.startTime

    console.log(`\n${'='.repeat(60)}`)
    console.log(`  SESSION COMPLETE`)
    console.log(`${'='.repeat(60)}`)
    console.log(`  Duration: ${this._metrics.totalExecutionMs}ms`)
    console.log(`  Tasks Completed: ${this._completedTasks.length}`)
    console.log(`  Tasks Failed: ${this._failedTasks.length}`)
    console.log(`  Discoveries: ${this._discoveryLog.length}`)
    console.log(`  AI Prompts: ${this._aiPromptLog.length}`)
    console.log(`${'='.repeat(60)}\n`)

    return report
  }

  /**
   * Plan initial tasks based on request
   */
  async _planTasks(request, context = {}) {
    const tasks = []
    const pageType = context.pageType || this._detectPageType(request)

    console.log(`\n🧠 PLANNING TASKS for: "${request}"`)
    console.log(`   Detected page type: ${pageType}`)

    // Get knowledge from QA Brain
    const knowledge = getForPageType(pageType)
    console.log(`   Found ${knowledge.length} knowledge sections`)

    // Get edge cases
    const edgeCases = detectEdgeCases(pageType, context.elements || [])
    console.log(`   Found ${edgeCases.edgeCases?.length || 0} edge cases`)

    // Ask AI to plan if available
    if (this._callAI) {
      const aiTasks = await this._askAIForPlan(request, pageType, knowledge, edgeCases, context)
      tasks.push(...aiTasks)
    } else {
      // Fallback: Generate tasks from knowledge base
      const knowledgeTasks = this._generateTasksFromKnowledge(knowledge, pageType)
      tasks.push(...knowledgeTasks)

      // Add edge case tasks
      const edgeCaseTasks = this._generateEdgeCaseTasks(edgeCases)
      tasks.push(...edgeCaseTasks)
    }

    return tasks
  }

  /**
   * Ask AI to create a test plan
   */
  async _askAIForPlan(request, pageType, knowledge, edgeCases, context) {
    const startTime = Date.now()

    const systemPrompt = `You are an expert QA engineer creating a test plan.
You think systematically and never miss edge cases.
You prioritize tests by risk (security > data loss > core functionality > UX).

Return a JSON array of tasks, each with:
- title: Short description (what to test)
- description: Detailed steps
- type: "test" | "explore" | "verify" | "edge_case"
- priority: 1 (critical) to 5 (low)
- action: The action to perform (click, type, etc.)
- targetElement: Description of element to interact with
- testData: Any test data to use
- expectedResult: What should happen`

    const userPrompt = `Create a comprehensive test plan for: "${request}"

Page Type: ${pageType}

Available Knowledge:
${formatForPrompt(knowledge.slice(0, 5))}

Edge Cases to Consider:
${JSON.stringify(edgeCases.edgeCases?.slice(0, 10) || [], null, 2)}

Current Page Elements:
${JSON.stringify(context.elements?.slice(0, 20) || [], null, 2)}

Generate 5-15 prioritized test tasks. Include:
1. Happy path tests (core functionality)
2. Negative tests (invalid inputs, errors)
3. Edge cases (boundaries, special characters)
4. Security tests (if applicable)

Return ONLY valid JSON array.`

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ]

    try {
      const response = await this._callAI(messages, {
        jsonMode: true,
        maxTokens: 2000,
        temperature: 0.3
      })

      const durationMs = Date.now() - startTime

      // Log the AI prompt
      this._logAIPrompt('plan', messages, response.content, {
        durationMs,
        success: true
      })

      // Parse response
      const parsed = JSON.parse(response.content)
      const taskArray = Array.isArray(parsed) ? parsed : parsed.tasks || []

      // Convert to task objects
      return taskArray.map((t, i) => createTask(
        `TASK-${++this._taskCounter}`,
        {
          title: t.title || `Task ${i + 1}`,
          description: t.description || '',
          type: t.type || 'test',
          priority: t.priority || TaskPriority.MEDIUM,
          action: t.action,
          targetElement: t.targetElement,
          testData: t.testData,
          expectedResult: t.expectedResult,
          source: 'ai_plan',
          tags: [pageType]
        }
      ))
    } catch (error) {
      console.error('AI planning failed:', error.message)

      // Log failed prompt
      this._logAIPrompt('plan', messages, null, {
        durationMs: Date.now() - startTime,
        success: false,
        error: error.message
      })

      return []
    }
  }

  /**
   * Generate tasks from knowledge base
   */
  _generateTasksFromKnowledge(knowledge, pageType) {
    const tasks = []

    for (const section of knowledge.slice(0, 10)) {
      if (section.tests) {
        for (const test of section.tests.slice(0, 5)) {
          tasks.push(createTask(
            `TASK-${++this._taskCounter}`,
            {
              title: test.name || test.title || 'Knowledge test',
              description: test.description || '',
              type: 'test',
              priority: test.priority === 'P0' ? TaskPriority.CRITICAL
                      : test.priority === 'P1' ? TaskPriority.HIGH
                      : TaskPriority.MEDIUM,
              expectedResult: test.expectedResult,
              source: 'brain',
              tags: [pageType, section.id || 'knowledge']
            }
          ))
        }
      }
    }

    return tasks
  }

  /**
   * Generate tasks from edge cases
   */
  _generateEdgeCaseTasks(edgeCases) {
    const tasks = []

    for (const ec of (edgeCases.edgeCases || []).slice(0, 10)) {
      tasks.push(createTask(
        `TASK-${++this._taskCounter}`,
        {
          title: `Edge case: ${ec.name || ec.description || 'Unknown'}`,
          description: ec.description || '',
          type: 'edge_case',
          priority: ec.severity === 'critical' ? TaskPriority.CRITICAL
                  : ec.severity === 'high' ? TaskPriority.HIGH
                  : TaskPriority.LOW,
          testData: ec.testData || ec.value,
          expectedResult: ec.expectedResult,
          source: 'edge_case',
          tags: ['edge_case', ec.category || 'unknown']
        }
      ))
    }

    return tasks
  }

  /**
   * Execute a single task (handles multi-step tasks)
   */
  async _executeTask(task, context = {}) {
    task.status = TaskStatus.IN_PROGRESS
    task.startedAt = Date.now()
    task.attempts++

    this._emit('onTaskStart', task)

    // Check if this action was already done (deduplication)
    if (task.action && task.targetElement) {
      if (this._hasAlreadyDone(task.action, task.targetElement, task.testData)) {
        console.log(`   ⏭️  Already done: ${task.action} on ${task.targetElement}`)
        return {
          success: true,
          skipped: true,
          message: 'Action already performed previously'
        }
      }
    }

    // Get current page state
    let pageState = null
    if (this._getPageState) {
      pageState = await this._getPageState()

      // Track URL and set start URL on first action
      if (pageState?.url) {
        if (!this._startUrl) {
          this._startUrl = pageState.url
          await this._pushNavigation(pageState)
        }
        if (!this._hasVisitedUrl(pageState.url)) {
          this._markUrlVisited(pageState.url)
        }
      }
    }

    // If task has steps, execute each step
    if (task.steps && task.steps.length > 0) {
      return await this._executeTaskWithSteps(task, context, pageState)
    }

    // If we have a single action to perform
    if (task.action && this._executeAction) {
      // PREDICTIVE THINKING: Predict outcome before executing
      const prediction = await this._predictOutcome(task, pageState)

      const result = await this._executeSingleAction(task, context, pageState)

      // Get page state after action for prediction analysis
      let afterState = null
      if (this._getPageState) {
        afterState = await this._getPageState()
      }

      // Analyze prediction accuracy
      if (prediction) {
        const predictionAnalysis = this._analyzePrediction(prediction, result, afterState, pageState)
        result.predictionAnalysis = predictionAnalysis
      }

      // Handle navigation if URL changed (in exploration mode)
      if (result.actionRecord?.afterState?.urlChanged && this.config.explorationMode) {
        const navResult = await this._handleNavigation(
          result.actionRecord.afterState.url,
          pageState?.url,
          task
        )
        result.navigationHandled = navResult
      }

      // Mark as done for deduplication
      if (result.success) {
        this._markAsDone(task.action, task.targetElement, task.testData)
      }

      return result
    }

    // No action to perform - just observation task
    return {
      success: true,
      message: 'Observation task - no action required',
      pageState
    }
  }

  /**
   * Execute a task with multiple steps
   */
  async _executeTaskWithSteps(task, context, pageState) {
    const stepResults = []

    for (let i = task.currentStepIndex; i < task.steps.length; i++) {
      const step = task.steps[i]
      task.currentStepIndex = i

      console.log(`      Step ${i + 1}/${task.steps.length}: ${step.description || step.action}`)

      // Check if step was already done
      if (this._hasAlreadyDone(step.action, step.target, step.value)) {
        console.log(`      ⏭️  Step already done, skipping`)
        step.status = TaskStatus.COMPLETED
        step.actualResult = 'Skipped - already done'
        stepResults.push({ success: true, skipped: true })
        continue
      }

      step.status = TaskStatus.IN_PROGRESS
      const stepStartTime = Date.now()

      try {
        // Create a mini-task for this step
        const stepTask = {
          ...task,
          action: step.action,
          targetElement: step.target,
          testData: step.value,
          expectedResult: step.expectedResult
        }

        const result = await this._executeSingleAction(stepTask, context, pageState)

        step.status = result.success ? TaskStatus.COMPLETED : TaskStatus.FAILED
        step.actualResult = result.message
        step.error = result.error
        step.durationMs = Date.now() - stepStartTime

        stepResults.push(result)

        // Mark step as done
        if (result.success) {
          this._markAsDone(step.action, step.target, step.value)
        }

        // Update page state for next step
        if (this._getPageState) {
          pageState = await this._getPageState()
        }

        // Stop on failure if critical
        if (!result.success && task.priority === TaskPriority.CRITICAL) {
          break
        }

      } catch (error) {
        step.status = TaskStatus.FAILED
        step.error = error.message
        step.durationMs = Date.now() - stepStartTime
        stepResults.push({ success: false, error: error.message })
        break
      }
    }

    task.stepResults = stepResults
    const allSuccess = stepResults.every(r => r.success)
    const anySuccess = stepResults.some(r => r.success && !r.skipped)

    return {
      success: allSuccess,
      partialSuccess: anySuccess && !allSuccess,
      stepResults,
      message: allSuccess
        ? `All ${task.steps.length} steps completed`
        : `${stepResults.filter(r => r.success).length}/${task.steps.length} steps completed`,
      pageState
    }
  }

  /**
   * Execute a single action
   */
  async _executeSingleAction(task, context, pageState) {
    // Create action record
    const actionRecord = createActionRecord(
      task.id,
      task.action,
      task.targetElement,
      {
        beforeUrl: pageState?.url,
        beforeElementCount: pageState?.elements?.length || 0,
        value: task.testData
      }
    )

    const actionStartTime = Date.now()

    try {
      // Execute the action
      const result = await this._executeAction(task, context)

      // Get page state after
      const afterState = this._getPageState ? await this._getPageState() : null

      // Find new elements
      let newElements = []
      if (afterState?.elements && pageState?.elements) {
        const beforeIds = new Set(pageState.elements.map(e => e.id))
        newElements = afterState.elements.filter(e => !beforeIds.has(e.id))
      }

      actionRecord.afterState = {
        url: afterState?.url,
        elementCount: afterState?.elements?.length || 0,
        domChanged: afterState?.url !== pageState?.url ||
                   afterState?.elements?.length !== pageState?.elements?.length,
        urlChanged: afterState?.url !== pageState?.url,
        newElements: newElements.slice(0, 10) // Limit for storage
      }
      actionRecord.success = result.success !== false
      actionRecord.error = result.error || null
      actionRecord.durationMs = Date.now() - actionStartTime

      // Log action
      this._actionHistory.push(actionRecord)
      this._metrics.totalActions++

      // Mark new URL as visited
      if (afterState?.url && afterState.url !== pageState?.url) {
        this._markUrlVisited(afterState.url)
      }

      return {
        success: result.success !== false,
        actionRecord,
        pageState: afterState,
        message: result.message,
        data: result.data
      }
    } catch (error) {
      actionRecord.success = false
      actionRecord.error = error.message
      actionRecord.durationMs = Date.now() - actionStartTime

      this._actionHistory.push(actionRecord)
      this._metrics.totalActions++

      // Try to heal selector if element not found
      if (error.message?.includes('not found') || error.message?.includes('selector')) {
        const healed = this._selectorHealer.heal(
          task.targetElement,
          'css',
          pageState
        )
        if (healed.success) {
          console.log(`   🔧 Healed selector: ${task.targetElement} → ${healed.healedSelector}`)
          task.targetElement = healed.healedSelector
          // Could retry here
        }
      }

      return {
        success: false,
        error: error.message,
        actionRecord
      }
    }
  }

  /**
   * Observe and record the result
   */
  async _observeResult(task, result, context) {
    const observation = createObservation(
      task.id,
      result.actionRecord?.id,
      {
        type: result.success ? 'success' : 'error',
        description: result.message || (result.success ? 'Action completed' : 'Action failed'),
        expectedBehavior: task.expectedResult,
        actualBehavior: result.message,
        matchesExpected: result.success && (!task.expectedResult ||
          result.message?.includes(task.expectedResult)),
        severity: result.success ? 'info' : 'error',
        consoleErrors: context.consoleErrors || []
      }
    )

    // Ask AI to analyze if significant
    if (this._callAI && (!result.success || result.actionRecord?.afterState?.domChanged)) {
      observation.aiAnalysis = await this._askAIToAnalyze(task, result)
    }

    this._observationLog.push(observation)
    this._metrics.totalObservations++
    task.observations.push(observation.id)

    this._emit('onObservation', observation)

    // Print observation
    const icon = observation.matchesExpected ? '✅' : '⚠️'
    console.log(`   ${icon} Observation: ${observation.description}`)
    if (observation.aiAnalysis) {
      console.log(`   🤖 AI Analysis: ${observation.aiAnalysis.slice(0, 100)}...`)
    }
  }

  /**
   * Ask AI to analyze result
   */
  async _askAIToAnalyze(task, result) {
    const startTime = Date.now()

    const messages = [
      {
        role: 'system',
        content: 'You are a QA expert analyzing test results. Be concise.'
      },
      {
        role: 'user',
        content: `Analyze this test result:

Task: ${task.title}
Expected: ${task.expectedResult || 'Not specified'}
Actual: ${result.message || 'Unknown'}
Success: ${result.success}
${result.error ? `Error: ${result.error}` : ''}
${result.actionRecord?.afterState?.urlChanged ? 'URL changed after action' : ''}
${result.actionRecord?.afterState?.domChanged ? 'DOM changed after action' : ''}

In 1-2 sentences: What happened? Is this expected? Any concerns?`
      }
    ]

    try {
      const response = await this._callAI(messages, {
        maxTokens: 200,
        temperature: 0.3
      })

      this._logAIPrompt('analyze', messages, response.content, {
        taskId: task.id,
        durationMs: Date.now() - startTime,
        success: true
      })

      return response.content
    } catch (error) {
      this._logAIPrompt('analyze', messages, null, {
        taskId: task.id,
        durationMs: Date.now() - startTime,
        success: false,
        error: error.message
      })
      return null
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // PREDICTIVE THINKING - Anticipate outcomes before actions
  // ─────────────────────────────────────────────────────────────────

  /**
   * Predict what will happen before executing an action
   * This makes the AI's reasoning transparent and helps catch unexpected behavior
   */
  async _predictOutcome(task, pageState) {
    if (!this.config.enablePredictions) {
      return null
    }

    const prediction = {
      id: `PRED-${Date.now()}`,
      taskId: task.id,
      timestamp: Date.now(),
      action: task.action,
      target: task.targetElement,
      expected: null,
      type: 'unknown',
      confidence: 0.5
    }

    // Find the target element
    const element = pageState?.elements?.find(e =>
      e.id === task.targetElement ||
      e.text === task.targetElement ||
      e.label === task.targetElement
    )

    const elementText = element?.text || element?.label || task.targetElement || 'unknown element'
    const elementTag = element?.tag || 'element'
    const elementHref = element?.href

    // Predict based on action type and element characteristics
    if (task.action === 'click') {
      // Navigation predictions
      if (elementHref && elementHref !== '#' && !elementHref.startsWith('javascript:')) {
        prediction.type = 'navigation'
        prediction.expected = `Will navigate to ${elementHref}`
        prediction.confidence = 0.9
      }
      // Button text analysis
      else if (/submit|save|create|confirm|send|apply/i.test(elementText)) {
        prediction.type = 'form_submit'
        prediction.expected = `Will submit form and show success/error message`
        prediction.confidence = 0.8
      }
      else if (/login|sign.?in/i.test(elementText)) {
        prediction.type = 'navigation'
        prediction.expected = `Will attempt login and navigate to dashboard/home`
        prediction.confidence = 0.8
      }
      else if (/sign.?up|register/i.test(elementText)) {
        prediction.type = 'navigation'
        prediction.expected = `Will create account and navigate to welcome/dashboard`
        prediction.confidence = 0.7
      }
      else if (/cancel|close|dismiss|x/i.test(elementText)) {
        prediction.type = 'close'
        prediction.expected = `Will close modal/dialog or navigate back`
        prediction.confidence = 0.8
      }
      else if (/menu|dropdown|expand|more|show/i.test(elementText)) {
        prediction.type = 'expand'
        prediction.expected = `Will expand to show more options/content`
        prediction.confidence = 0.7
      }
      else if (/toggle|switch/i.test(elementText)) {
        prediction.type = 'toggle'
        prediction.expected = `Will toggle this option on/off`
        prediction.confidence = 0.8
      }
      else if (elementTag === 'a' || element?.category === 'link') {
        prediction.type = 'navigation'
        prediction.expected = `Will navigate to a different page`
        prediction.confidence = 0.7
      }
      else {
        // Generic button
        prediction.type = 'action'
        prediction.expected = `Will trigger an action (may show modal, update page, or navigate)`
        prediction.confidence = 0.5
      }
    }
    else if (task.action === 'type') {
      prediction.type = 'input'
      prediction.expected = `Will enter "${task.testData}" into the field`
      prediction.confidence = 0.9
    }
    else if (task.action === 'scroll') {
      prediction.type = 'scroll'
      prediction.expected = `Will scroll ${task.direction || 'down'} to reveal more content`
      prediction.confidence = 0.95
    }

    // Log prediction
    this._predictionLog.push(prediction)

    // Emit prediction event
    this._emit('onPrediction', prediction)

    // Send message to UI
    const msg = this._callbacks.sendMessage
    if (msg) {
      msg('prediction', `Prediction: ${prediction.expected}`)
    }

    console.log(`   Prediction: ${prediction.expected} (${Math.round(prediction.confidence * 100)}% confident)`)

    return prediction
  }

  /**
   * Analyze prediction accuracy after action completes
   */
  _analyzePrediction(prediction, result, afterState, beforeState) {
    if (!prediction) return null

    const analysis = {
      predictionId: prediction.id,
      wasCorrect: false,
      actualOutcome: null,
      surprise: null,
      surpriseLevel: 'none' // none, minor, major
    }

    // Determine actual outcome
    const urlChanged = afterState?.url !== beforeState?.url
    const domChanged = result?.domChanged || false

    if (urlChanged) {
      analysis.actualOutcome = `Navigated to ${afterState.url}`
    } else if (domChanged) {
      analysis.actualOutcome = `Page content changed (DOM updated)`
    } else if (result?.success) {
      analysis.actualOutcome = `Action completed without visible change`
    } else {
      analysis.actualOutcome = `Action failed: ${result?.error || 'unknown error'}`
    }

    // Compare with prediction
    if (prediction.type === 'navigation') {
      analysis.wasCorrect = urlChanged
      if (!urlChanged) {
        analysis.surprise = `Expected navigation but stayed on same page`
        analysis.surpriseLevel = 'major'
      }
    }
    else if (prediction.type === 'form_submit') {
      // Form submit could navigate or update DOM
      analysis.wasCorrect = urlChanged || domChanged
      if (!urlChanged && !domChanged && result?.success) {
        analysis.surprise = `Form submitted but no visible feedback`
        analysis.surpriseLevel = 'minor'
      }
    }
    else if (prediction.type === 'expand' || prediction.type === 'toggle') {
      analysis.wasCorrect = domChanged && !urlChanged
      if (urlChanged) {
        analysis.surprise = `Expected in-page update but navigated instead`
        analysis.surpriseLevel = 'major'
      }
    }
    else if (prediction.type === 'close') {
      analysis.wasCorrect = domChanged || urlChanged
    }
    else {
      // Generic action - consider it correct if something happened
      analysis.wasCorrect = result?.success
    }

    // Update metrics
    if (analysis.wasCorrect) {
      this._metrics.predictionsCorrect++
    } else {
      this._metrics.predictionsWrong++
    }

    // Log surprise as discovery if significant
    if (analysis.surpriseLevel === 'major') {
      const discovery = createDiscovery(prediction.taskId, {
        type: 'unexpected_behavior',
        description: analysis.surprise,
        priority: TaskPriority.HIGH
      })
      this._discoveryLog.push(discovery)
      this._metrics.totalDiscoveries++
      this._emit('onDiscovery', discovery)

      console.log(`   UNEXPECTED: ${analysis.surprise}`)
    }

    // Send message to UI
    const msg = this._callbacks.sendMessage
    if (msg) {
      if (analysis.wasCorrect) {
        msg('observation', `Result matched prediction`)
      } else if (analysis.surprise) {
        msg('observation', `Unexpected: ${analysis.surprise}`)
      }
    }

    return analysis
  }

  // ─────────────────────────────────────────────────────────────────
  // NAVIGATION TRACKING - Track where we've been
  // ─────────────────────────────────────────────────────────────────

  /**
   * Push current page to navigation stack
   */
  async _pushNavigation(pageState) {
    const entry = {
      url: pageState?.url,
      title: pageState?.title,
      timestamp: Date.now(),
      depth: this._currentDepth,
      structure: null
    }

    // Get page structure if extractor is available
    if (this._getPageStructure) {
      try {
        entry.structure = await this._getPageStructure()
      } catch (e) {
        console.log('Could not get page structure:', e.message)
      }
    }

    this._navigationStack.push(entry)

    // Update site map
    if (pageState?.url) {
      const normalizedUrl = this._normalizeUrl(pageState.url)
      if (!this._siteMap[normalizedUrl]) {
        this._siteMap[normalizedUrl] = {
          title: pageState.title,
          structure: entry.structure,
          testedElements: new Set(),
          depth: this._currentDepth,
          visitedAt: Date.now()
        }
        this._metrics.pagesExplored++
      }
    }
  }

  /**
   * Handle navigation to a new page during exploration
   */
  async _handleNavigation(newUrl, previousUrl, task) {
    // Update depth
    this._currentDepth++
    if (this._currentDepth > this._metrics.maxDepthReached) {
      this._metrics.maxDepthReached = this._currentDepth
    }

    // Check depth limit
    if (this._currentDepth > this.config.maxExplorationDepth) {
      console.log(`   Reached max depth (${this.config.maxExplorationDepth}), not exploring deeper`)
      return { shouldContinue: false, reason: 'max_depth_reached' }
    }

    // Check if external link
    try {
      const newOrigin = new URL(newUrl).origin
      const startOrigin = this._startUrl ? new URL(this._startUrl).origin : null
      if (startOrigin && newOrigin !== startOrigin) {
        console.log(`   External link detected, skipping`)
        return { shouldContinue: false, reason: 'external_link' }
      }
    } catch (e) {
      // Invalid URL, skip
      return { shouldContinue: false, reason: 'invalid_url' }
    }

    // Get fresh page state
    let newPageState = null
    if (this._getPageState) {
      newPageState = await this._getPageState()
    }

    // Push to navigation stack
    await this._pushNavigation(newPageState)

    // Emit navigation event
    this._emit('onNavigation', {
      from: previousUrl,
      to: newUrl,
      depth: this._currentDepth,
      pageState: newPageState
    })

    // Send message to UI
    const msg = this._callbacks.sendMessage
    if (msg) {
      msg('navigation', `Now on page: ${newPageState?.title || newUrl} (depth ${this._currentDepth})`)
    }

    return { shouldContinue: true, pageState: newPageState }
  }

  /**
   * Check for new discoveries
   */
  async _checkForDiscoveries(task, result, context) {
    // Check for new elements
    if (result.actionRecord?.afterState?.newElements?.length > 0) {
      for (const element of result.actionRecord.afterState.newElements.slice(0, 5)) {
        // Skip if we've already interacted with this element
        if (this._testedElements.has(element.id)) {
          continue
        }

        const discovery = createDiscovery(task.id, {
          type: 'element',
          description: `New element found: ${element.text || element.id || element.tag}`,
          element,
          shouldCreateTask: this._shouldCreateTaskForElement(element),
          priority: TaskPriority.DISCOVERY
        })

        this._discoveryLog.push(discovery)
        this._metrics.totalDiscoveries++

        // Create new task for discovery (with deduplication)
        if (discovery.shouldCreateTask && this._taskQueue.length < this.config.maxTasks) {
          const uniqueKey = `explore:${element.id || element.selector}`

          // Skip if we already have a task for this
          if (this._taskUniqueKeys.has(uniqueKey)) {
            continue
          }

          const newTask = createTask(
            `TASK-${++this._taskCounter}`,
            {
              title: `Explore: ${element.text || element.id || element.tag}`,
              description: `Discovered during: ${task.title}`,
              type: 'explore',
              priority: TaskPriority.DISCOVERY,
              targetElement: element.id || element.selector,
              action: element.category === 'button' ? 'click' : 'explore',
              source: 'discovery',
              parentTaskId: task.id,
              uniqueKey
            }
          )

          if (this._addTaskIfNew(newTask)) {
            discovery.createdTaskId = newTask.id
            console.log(`   🔍 DISCOVERY: New task added - ${newTask.title}`)
          }
        }

        this._emit('onDiscovery', discovery)
      }
    }

    // Check for URL change (new page)
    if (result.actionRecord?.afterState?.urlChanged) {
      const newUrl = result.actionRecord.afterState.url

      // Skip if we've already visited this URL
      if (this._hasVisitedUrl(newUrl)) {
        console.log(`   ⏭️  Already visited: ${newUrl}`)
        return
      }

      // Check depth limit
      const taskDepth = this._getTaskDepth(task)
      if (taskDepth >= this.config.maxExplorationDepth) {
        console.log(`   ⏭️  At max depth (${this.config.maxExplorationDepth}), not exploring: ${newUrl}`)
        return
      }

      // Check if external link
      try {
        const newOrigin = new URL(newUrl).origin
        const startOrigin = this._startUrl ? new URL(this._startUrl).origin : null
        if (startOrigin && newOrigin !== startOrigin) {
          console.log(`   ⏭️  External link, not exploring: ${newUrl}`)
          return
        }
      } catch (e) {
        // Invalid URL
        return
      }

      const discovery = createDiscovery(task.id, {
        type: 'page',
        description: `Navigated to new page: ${newUrl}`,
        url: newUrl,
        shouldCreateTask: this.config.explorationMode,
        priority: TaskPriority.HIGH
      })

      this._discoveryLog.push(discovery)
      this._metrics.totalDiscoveries++

      // Create task to explore new page (with deduplication)
      // In exploration mode, we want to continue exploring
      if (this.config.explorationMode && this._taskQueue.length < this.config.maxTasks) {
        const uniqueKey = `explore-page:${this._normalizeUrl(newUrl)}`

        if (!this._taskUniqueKeys.has(uniqueKey)) {
          // Get page structure for the new page if available
          let pageTitle = newUrl
          if (this._getPageState) {
            try {
              const newPageState = await this._getPageState()
              pageTitle = newPageState?.title || newUrl
            } catch (e) {
              // Use URL as fallback
            }
          }

          const newTask = createTask(
            `TASK-${++this._taskCounter}`,
            {
              title: `Explore: ${pageTitle}`,
              description: `Discovered during: ${task.title}\nURL: ${newUrl}\nDepth: ${taskDepth + 1}`,
              type: 'explore',
              priority: TaskPriority.HIGH,
              source: 'discovery',
              parentTaskId: task.id,
              uniqueKey,
              // Store depth in task metadata
              tags: [`depth:${taskDepth + 1}`]
            }
          )

          if (this._addTaskIfNew(newTask)) {
            discovery.createdTaskId = newTask.id
            console.log(`   Discovered new page: ${pageTitle} (depth ${taskDepth + 1})`)
          }
        }
      }

      this._emit('onDiscovery', discovery)
    }
  }

  /**
   * Get the depth of a task based on parent chain
   */
  _getTaskDepth(task) {
    let depth = 0
    let current = task

    while (current?.parentTaskId && depth < 20) { // Safety limit
      // Find parent task
      const parent = this._findTaskById(current.parentTaskId)
      if (!parent) break
      current = parent
      depth++
    }

    // Also check depth tag if present
    const depthTag = task.tags?.find(t => t.startsWith('depth:'))
    if (depthTag) {
      const tagDepth = parseInt(depthTag.split(':')[1])
      if (!isNaN(tagDepth)) {
        return Math.max(depth, tagDepth)
      }
    }

    return depth
  }

  /**
   * Learn from task result
   */
  _learnFromResult(task, result) {
    // Record in flakiness detector
    this._flakinessDetector.recordExecution(
      task.id,
      task.title,
      result.success,
      result.actionRecord?.durationMs || 0,
      { errorMessage: result.error }
    )

    // Record in insight engine
    this._insightEngine.recordEvent(
      task.id,
      result.success ? 'pass' : 'fail',
      result.actionRecord?.durationMs || 0,
      result.error,
      { taskType: task.type }
    )
  }

  /**
   * Complete a task
   */
  _completeTask(task, result) {
    task.completedAt = Date.now()
    task.durationMs = task.completedAt - task.startedAt
    task.status = result.success ? TaskStatus.COMPLETED : TaskStatus.FAILED
    task.actualResult = result.message
    task.error = result.error

    if (result.success) {
      this._completedTasks.push(task)
      this._metrics.completedTasks++
      console.log(`   ✅ Task completed in ${task.durationMs}ms`)
    } else {
      // Check if should retry
      if (task.attempts < task.maxAttempts) {
        task.status = TaskStatus.PENDING
        this._addTask(task) // Re-add to queue
        console.log(`   🔄 Task failed, will retry (attempt ${task.attempts}/${task.maxAttempts})`)
      } else {
        this._failedTasks.push(task)
        this._metrics.failedTasks++
        console.log(`   ❌ Task failed after ${task.attempts} attempts: ${result.error}`)
      }
    }

    this._emit('onTaskComplete', task)
  }

  /**
   * Add task to queue (maintaining priority order)
   */
  _addTask(task) {
    // Insert in priority order
    const idx = this._taskQueue.findIndex(t => t.priority > task.priority)
    if (idx === -1) {
      this._taskQueue.push(task)
    } else {
      this._taskQueue.splice(idx, 0, task)
    }
    this._metrics.totalTasks++
  }

  /**
   * Get next task from queue
   */
  _getNextTask() {
    return this._taskQueue.shift()
  }

  /**
   * Log an AI prompt
   */
  _logAIPrompt(purpose, messages, response, options = {}) {
    const logEntry = createAIPromptLog(purpose, messages, response, options)
    this._aiPromptLog.push(logEntry)
    this._metrics.totalAIPrompts++
    this._metrics.totalAIDurationMs += options.durationMs || 0

    this._emit('onAIPrompt', logEntry)
  }

  /**
   * Generate final report
   */
  _generateReport() {
    return {
      sessionId: this._sessionId,

      // Summary
      summary: {
        totalTasks: this._metrics.totalTasks,
        completed: this._completedTasks.length,
        failed: this._failedTasks.length,
        skipped: this._metrics.skippedTasks,
        discoveries: this._discoveryLog.length,
        duration: this._metrics.totalExecutionMs
      },

      // Task details
      completedTasks: this._completedTasks.map(t => ({
        id: t.id,
        title: t.title,
        duration: t.durationMs,
        result: t.actualResult
      })),

      failedTasks: this._failedTasks.map(t => ({
        id: t.id,
        title: t.title,
        error: t.error,
        attempts: t.attempts
      })),

      // Discoveries
      discoveries: this._discoveryLog.map(d => ({
        id: d.id,
        type: d.type,
        description: d.description,
        createdTaskId: d.createdTaskId
      })),

      // Observations
      observations: this._observationLog.map(o => ({
        id: o.id,
        type: o.type,
        description: o.description,
        severity: o.severity,
        matchesExpected: o.matchesExpected
      })),

      // AI usage
      aiUsage: {
        totalPrompts: this._metrics.totalAIPrompts,
        totalDuration: this._metrics.totalAIDurationMs,
        avgDuration: this._metrics.totalAIPrompts > 0
          ? this._metrics.totalAIDurationMs / this._metrics.totalAIPrompts
          : 0
      },

      // Exploration stats (NEW)
      exploration: {
        pagesExplored: this._metrics.pagesExplored,
        maxDepthReached: this._metrics.maxDepthReached,
        visitedUrls: Array.from(this._visitedUrls),
        siteMap: Object.keys(this._siteMap).map(url => ({
          url,
          title: this._siteMap[url].title,
          depth: this._siteMap[url].depth,
          testedElements: this._siteMap[url].testedElements?.size || 0
        }))
      },

      // Prediction accuracy (NEW)
      predictions: {
        total: this._metrics.predictionsCorrect + this._metrics.predictionsWrong,
        correct: this._metrics.predictionsCorrect,
        wrong: this._metrics.predictionsWrong,
        accuracy: (this._metrics.predictionsCorrect + this._metrics.predictionsWrong) > 0
          ? this._metrics.predictionsCorrect / (this._metrics.predictionsCorrect + this._metrics.predictionsWrong)
          : null,
        surprises: this._predictionLog.filter(p =>
          this._discoveryLog.some(d =>
            d.type === 'unexpected_behavior' && d.taskId === p.taskId
          )
        ).length
      },

      // Insights from learning
      insights: this._insightEngine.generateInsights()
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // HISTORY ACCESS METHODS (for user to see what's happening)
  // ─────────────────────────────────────────────────────────────────

  /**
   * Get all AI prompts that were sent
   */
  getAIPromptHistory() {
    return this._aiPromptLog
  }

  /**
   * Get AI prompt history as formatted string
   */
  formatAIPromptHistory() {
    const lines = [
      '═'.repeat(80),
      '  AI PROMPT HISTORY',
      '═'.repeat(80),
      ''
    ]

    for (const prompt of this._aiPromptLog) {
      lines.push(`┌${'─'.repeat(78)}┐`)
      lines.push(`│ PROMPT: ${prompt.id}`)
      lines.push(`│ Purpose: ${prompt.purpose}`)
      lines.push(`│ Time: ${new Date(prompt.timestamp).toISOString()}`)
      lines.push(`│ Duration: ${prompt.durationMs}ms`)
      lines.push(`│ Success: ${prompt.response.success}`)
      lines.push(`├${'─'.repeat(78)}┤`)
      lines.push(`│ MESSAGES:`)

      for (const msg of prompt.messages) {
        lines.push(`│   [${msg.role}]:`)
        const contentLines = msg.content.split('\n').slice(0, 20)
        for (const line of contentLines) {
          lines.push(`│     ${line.slice(0, 74)}`)
        }
        if (msg.content.split('\n').length > 20) {
          lines.push(`│     ... (truncated)`)
        }
      }

      lines.push(`├${'─'.repeat(78)}┤`)
      lines.push(`│ RESPONSE:`)
      const respLines = (prompt.response.content || 'null').split('\n').slice(0, 10)
      for (const line of respLines) {
        lines.push(`│   ${line.slice(0, 74)}`)
      }
      if ((prompt.response.content || '').split('\n').length > 10) {
        lines.push(`│   ... (truncated)`)
      }

      lines.push(`└${'─'.repeat(78)}┘`)
      lines.push('')
    }

    return lines.join('\n')
  }

  /**
   * Get action history
   */
  getActionHistory() {
    return this._actionHistory
  }

  /**
   * Get observation log
   */
  getObservationLog() {
    return this._observationLog
  }

  /**
   * Get discovery log
   */
  getDiscoveryLog() {
    return this._discoveryLog
  }

  /**
   * Get all history combined
   */
  getAllHistory() {
    return {
      sessionId: this._sessionId,
      aiPrompts: this._aiPromptLog,
      actions: this._actionHistory,
      observations: this._observationLog,
      discoveries: this._discoveryLog,
      completedTasks: this._completedTasks,
      failedTasks: this._failedTasks,
      metrics: this._metrics
    }
  }

  /**
   * Save history to file (returns content, actual save done by caller)
   */
  exportHistory() {
    return JSON.stringify(this.getAllHistory(), null, 2)
  }

  /**
   * Print history summary to console
   */
  printHistorySummary() {
    console.log('\n' + '═'.repeat(60))
    console.log('  SESSION HISTORY SUMMARY')
    console.log('═'.repeat(60))
    console.log(`  Session: ${this._sessionId}`)
    console.log(`  Duration: ${this._metrics.totalExecutionMs}ms`)
    console.log('')
    console.log('  TASKS:')
    console.log(`    Total: ${this._metrics.totalTasks}`)
    console.log(`    Completed: ${this._completedTasks.length}`)
    console.log(`    Failed: ${this._failedTasks.length}`)
    console.log('')
    console.log('  AI PROMPTS:')
    console.log(`    Total: ${this._aiPromptLog.length}`)
    console.log(`    Total Duration: ${this._metrics.totalAIDurationMs}ms`)
    console.log('')
    console.log('  ACTIONS:')
    console.log(`    Total: ${this._actionHistory.length}`)
    console.log(`    Success: ${this._actionHistory.filter(a => a.success).length}`)
    console.log(`    Failed: ${this._actionHistory.filter(a => !a.success).length}`)
    console.log('')
    console.log('  DISCOVERIES:')
    console.log(`    Total: ${this._discoveryLog.length}`)
    console.log(`    Elements: ${this._discoveryLog.filter(d => d.type === 'element').length}`)
    console.log(`    Pages: ${this._discoveryLog.filter(d => d.type === 'page').length}`)
    console.log('═'.repeat(60) + '\n')
  }

  // ─────────────────────────────────────────────────────────────────
  // UTILITY METHODS
  // ─────────────────────────────────────────────────────────────────

  _detectPageType(text) {
    const lower = text.toLowerCase()
    if (/login|sign.?in/.test(lower)) return 'login'
    if (/sign.?up|register/.test(lower)) return 'signup'
    if (/checkout|cart|payment/.test(lower)) return 'checkout'
    if (/search/.test(lower)) return 'search'
    if (/profile|account|settings/.test(lower)) return 'settings'
    if (/dashboard/.test(lower)) return 'dashboard'
    return 'general'
  }

  _shouldCreateTaskForElement(element) {
    // Create tasks for buttons, links, forms
    return ['button', 'link', 'form', 'input'].includes(element.category) ||
           element.tag === 'button' ||
           element.tag === 'a'
  }

  _emit(event, data) {
    if (this._callbacks[event]) {
      try {
        this._callbacks[event](data)
      } catch (e) {
        // Ignore callback errors
      }
    }
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  // ─────────────────────────────────────────────────────────────────
  // TODO LIST DISPLAY (for user visibility)
  // ─────────────────────────────────────────────────────────────────

  /**
   * Format TODO list for display to user
   */
  formatTodoList() {
    const lines = []

    lines.push('')
    lines.push('╔' + '═'.repeat(70) + '╗')
    lines.push('║' + '  📋 TODO LIST'.padEnd(70) + '║')
    lines.push('╠' + '═'.repeat(70) + '╣')

    // Show current task
    if (this._currentTaskId) {
      const current = this._findTaskById(this._currentTaskId)
      if (current) {
        lines.push('║' + `  ▶️  IN PROGRESS: ${current.title}`.padEnd(70).slice(0, 70) + '║')
        if (current.steps.length > 0) {
          lines.push('║' + `      Step ${current.currentStepIndex + 1}/${current.steps.length}: ${current.steps[current.currentStepIndex]?.description || 'Executing...'}`.padEnd(70).slice(0, 70) + '║')
        }
        lines.push('╠' + '─'.repeat(70) + '╣')
      }
    }

    // Show pending tasks
    const pending = this._taskQueue.filter(t => t.status === TaskStatus.PENDING)
    if (pending.length > 0) {
      lines.push('║' + '  📝 PENDING:'.padEnd(70) + '║')
      for (let i = 0; i < Math.min(pending.length, 10); i++) {
        const task = pending[i]
        const priority = this._getPriorityIcon(task.priority)
        const stepInfo = task.steps.length > 0 ? ` (${task.steps.length} steps)` : ''
        lines.push('║' + `     ${priority} ${task.title}${stepInfo}`.padEnd(70).slice(0, 70) + '║')
      }
      if (pending.length > 10) {
        lines.push('║' + `     ... and ${pending.length - 10} more tasks`.padEnd(70) + '║')
      }
    }

    // Show completed tasks
    if (this._completedTasks.length > 0) {
      lines.push('╠' + '─'.repeat(70) + '╣')
      lines.push('║' + '  ✅ COMPLETED:'.padEnd(70) + '║')
      const recentCompleted = this._completedTasks.slice(-5)
      for (const task of recentCompleted) {
        lines.push('║' + `     ✓ ${task.title} (${task.durationMs}ms)`.padEnd(70).slice(0, 70) + '║')
      }
      if (this._completedTasks.length > 5) {
        lines.push('║' + `     ... and ${this._completedTasks.length - 5} more completed`.padEnd(70) + '║')
      }
    }

    // Show failed tasks
    if (this._failedTasks.length > 0) {
      lines.push('╠' + '─'.repeat(70) + '╣')
      lines.push('║' + '  ❌ FAILED:'.padEnd(70) + '║')
      for (const task of this._failedTasks.slice(-3)) {
        lines.push('║' + `     ✗ ${task.title}: ${(task.error || 'Unknown error').slice(0, 40)}`.padEnd(70).slice(0, 70) + '║')
      }
    }

    // Summary
    lines.push('╠' + '═'.repeat(70) + '╣')
    lines.push('║' + `  Total: ${this._metrics.totalTasks} | Pending: ${pending.length} | Done: ${this._completedTasks.length} | Failed: ${this._failedTasks.length}`.padEnd(70).slice(0, 70) + '║')
    lines.push('╚' + '═'.repeat(70) + '╝')
    lines.push('')

    return lines.join('\n')
  }

  /**
   * Get compact TODO summary for inline display
   */
  getTodoSummary() {
    const pending = this._taskQueue.filter(t => t.status === TaskStatus.PENDING).length
    const current = this._currentTaskId ? this._findTaskById(this._currentTaskId) : null

    return {
      current: current ? current.title : null,
      currentStep: current && current.steps.length > 0
        ? `${current.currentStepIndex + 1}/${current.steps.length}`
        : null,
      pending,
      completed: this._completedTasks.length,
      failed: this._failedTasks.length,
      total: this._metrics.totalTasks,
      progress: this._metrics.totalTasks > 0
        ? Math.round((this._completedTasks.length / this._metrics.totalTasks) * 100)
        : 0
    }
  }

  /**
   * Get detailed task info for display
   */
  getTaskDetails(taskId) {
    const task = this._findTaskById(taskId)
    if (!task) return null

    return {
      id: task.id,
      title: task.title,
      description: task.description,
      type: task.type,
      priority: task.priority,
      priorityName: this._getPriorityName(task.priority),
      status: task.status,
      steps: task.steps.map((s, i) => ({
        number: i + 1,
        action: s.action,
        target: s.target,
        description: s.description,
        status: s.status,
        isCurrent: i === task.currentStepIndex
      })),
      observations: task.observations.length,
      discoveries: task.discoveries.length,
      attempts: task.attempts,
      duration: task.durationMs
    }
  }

  _getPriorityIcon(priority) {
    switch (priority) {
      case TaskPriority.CRITICAL: return '🔴'
      case TaskPriority.HIGH: return '🟠'
      case TaskPriority.MEDIUM: return '🟡'
      case TaskPriority.LOW: return '🟢'
      case TaskPriority.DISCOVERY: return '🔵'
      default: return '⚪'
    }
  }

  _getPriorityName(priority) {
    switch (priority) {
      case TaskPriority.CRITICAL: return 'CRITICAL'
      case TaskPriority.HIGH: return 'HIGH'
      case TaskPriority.MEDIUM: return 'MEDIUM'
      case TaskPriority.LOW: return 'LOW'
      case TaskPriority.DISCOVERY: return 'DISCOVERY'
      default: return 'UNKNOWN'
    }
  }

  _findTaskById(taskId) {
    // Check queue
    let task = this._taskQueue.find(t => t.id === taskId)
    if (task) return task

    // Check completed
    task = this._completedTasks.find(t => t.id === taskId)
    if (task) return task

    // Check failed
    task = this._failedTasks.find(t => t.id === taskId)
    return task
  }

  // ─────────────────────────────────────────────────────────────────
  // DEDUPLICATION (prevent repeating actions)
  // ─────────────────────────────────────────────────────────────────

  /**
   * Check if an action has already been performed
   */
  _hasAlreadyDone(action, target, value = null) {
    const key = value
      ? `${action}:${target}:${value}`
      : `${action}:${target}`
    return this._completedActions.has(key)
  }

  /**
   * Mark an action as completed
   */
  _markAsDone(action, target, value = null) {
    const key = value
      ? `${action}:${target}:${value}`
      : `${action}:${target}`
    this._completedActions.add(key)

    if (target) {
      this._testedElements.add(target)
    }

    if (value && target) {
      if (!this._usedTestData.has(target)) {
        this._usedTestData.set(target, [])
      }
      this._usedTestData.get(target).push(value)
    }
  }

  /**
   * Check if URL has been visited
   */
  _hasVisitedUrl(url) {
    // Normalize URL for comparison
    const normalized = this._normalizeUrl(url)
    return this._visitedUrls.has(normalized)
  }

  /**
   * Mark URL as visited
   */
  _markUrlVisited(url) {
    const normalized = this._normalizeUrl(url)
    this._visitedUrls.add(normalized)
  }

  _normalizeUrl(url) {
    try {
      const u = new URL(url)
      return `${u.origin}${u.pathname}`.toLowerCase()
    } catch {
      return url.toLowerCase()
    }
  }

  /**
   * Check if a task is a duplicate
   */
  _isDuplicateTask(task) {
    // Check by unique key
    if (task.uniqueKey && this._taskUniqueKeys.has(task.uniqueKey)) {
      return true
    }

    // Check by action + target
    if (task.action && task.targetElement) {
      if (this._hasAlreadyDone(task.action, task.targetElement, task.testData)) {
        return true
      }
    }

    // Check by title (fuzzy match)
    const titleLower = task.title.toLowerCase()
    for (const completed of this._completedTasks) {
      if (completed.title.toLowerCase() === titleLower) {
        return true
      }
    }

    return false
  }

  /**
   * Add task only if not duplicate
   */
  _addTaskIfNew(task) {
    if (this._isDuplicateTask(task)) {
      console.log(`   ⏭️  Skipping duplicate: ${task.title}`)
      this._metrics.skippedTasks++
      return false
    }

    // Mark unique key
    if (task.uniqueKey) {
      this._taskUniqueKeys.add(task.uniqueKey)
    }

    this._addTask(task)
    return true
  }

  /**
   * Get deduplication stats
   */
  getDeduplicationStats() {
    return {
      completedActions: this._completedActions.size,
      visitedUrls: this._visitedUrls.size,
      testedElements: this._testedElements.size,
      uniqueTestDataEntries: Array.from(this._usedTestData.values()).reduce((sum, arr) => sum + arr.length, 0),
      skippedDuplicates: this._metrics.skippedTasks
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // STATE MANAGEMENT
  // ─────────────────────────────────────────────────────────────────

  pause() {
    this._state = OrchestratorState.PAUSED
  }

  resume() {
    if (this._state === OrchestratorState.PAUSED) {
      this._state = OrchestratorState.EXECUTING
    }
  }

  getState() {
    return this._state
  }

  getTaskQueue() {
    return this._taskQueue
  }

  getMetrics() {
    return { ...this._metrics }
  }
}

/**
 * Create an orchestrator instance
 */
function createQAOrchestrator(options = {}) {
  return new QAOrchestrator(options)
}

module.exports = {
  // Enums
  TaskPriority,
  TaskStatus,
  OrchestratorState,
  ActionType,

  // Factory functions
  createTask,
  createTaskStep,
  createActionRecord,
  createObservation,
  createDiscovery,
  createAIPromptLog,

  // Main class
  QAOrchestrator,
  createQAOrchestrator
}
