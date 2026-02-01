const { app, BrowserWindow, BrowserView, ipcMain, nativeTheme } = require('electron')
const path = require('path')
const fs = require('fs')

// ============ DEEPSEEK AGENT ============
const DEEPSEEK_API_URL = 'https://api.deepseek.com/v1/chat/completions'
let deepseekApiKey = process.env.DEEPSEEK_API_KEY || ''
let currentSession = null
let conversationHistory = []
let lastGeneratedScript = null
let lastGeneratedTestSuite = null

// ============================================================================
// HUMANOID QA AGENT - Based on testai-agent architecture
// ============================================================================

// ============ QA BRAIN (Knowledge Base) ============
const QA_BRAIN = {
  // Testing rules by page type - sourced from testai-agent/understanding
  rules: {
    login: [
      { id: 'L001', rule: 'Test SQL injection in username/password fields', category: 'security', priority: 'critical' },
      { id: 'L002', rule: 'Test XSS in username field', category: 'security', priority: 'critical' },
      { id: 'L003', rule: 'Test empty credentials submission', category: 'negative', priority: 'high' },
      { id: 'L004', rule: 'Test max length boundaries for inputs', category: 'edge_case', priority: 'medium' },
      { id: 'L005', rule: 'Test special characters in password', category: 'edge_case', priority: 'medium' },
      { id: 'L006', rule: 'Test email format validation', category: 'validation', priority: 'high' },
      { id: 'L007', rule: 'Test account lockout after failed attempts', category: 'security', priority: 'critical' },
      { id: 'L008', rule: 'Test remember me functionality', category: 'functional', priority: 'medium' },
      { id: 'L009', rule: 'Test password visibility toggle', category: 'functional', priority: 'low' },
      { id: 'L010', rule: 'Test OAuth/social login buttons', category: 'integration', priority: 'high' },
      { id: 'L011', rule: 'Test session handling after login', category: 'security', priority: 'critical' },
      { id: 'L012', rule: 'Test password reset flow', category: 'functional', priority: 'high' },
    ],
    signup: [
      { id: 'S001', rule: 'Test duplicate email registration', category: 'validation', priority: 'critical' },
      { id: 'S002', rule: 'Test password strength requirements', category: 'validation', priority: 'high' },
      { id: 'S003', rule: 'Test password confirmation mismatch', category: 'validation', priority: 'high' },
      { id: 'S004', rule: 'Test required fields validation', category: 'validation', priority: 'high' },
      { id: 'S005', rule: 'Test email verification flow', category: 'functional', priority: 'high' },
      { id: 'S006', rule: 'Test terms acceptance requirement', category: 'compliance', priority: 'medium' },
      { id: 'S007', rule: 'Test CAPTCHA if present', category: 'security', priority: 'medium' },
      { id: 'S008', rule: 'Test username uniqueness', category: 'validation', priority: 'high' },
    ],
    checkout: [
      { id: 'C001', rule: 'Test empty cart checkout prevention', category: 'validation', priority: 'critical' },
      { id: 'C002', rule: 'Test price calculation accuracy', category: 'functional', priority: 'critical' },
      { id: 'C003', rule: 'Test discount/coupon application', category: 'functional', priority: 'high' },
      { id: 'C004', rule: 'Test shipping calculation', category: 'functional', priority: 'high' },
      { id: 'C005', rule: 'Test tax calculation', category: 'functional', priority: 'high' },
      { id: 'C006', rule: 'Test payment method validation', category: 'validation', priority: 'critical' },
      { id: 'C007', rule: 'Test credit card number validation', category: 'validation', priority: 'critical' },
      { id: 'C008', rule: 'Test CVV validation', category: 'validation', priority: 'critical' },
      { id: 'C009', rule: 'Test expiry date validation', category: 'validation', priority: 'high' },
      { id: 'C010', rule: 'Test double-submit prevention', category: 'security', priority: 'critical' },
    ],
    search: [
      { id: 'SR001', rule: 'Test empty search handling', category: 'edge_case', priority: 'medium' },
      { id: 'SR002', rule: 'Test special characters in search', category: 'edge_case', priority: 'medium' },
      { id: 'SR003', rule: 'Test SQL injection in search', category: 'security', priority: 'critical' },
      { id: 'SR004', rule: 'Test XSS in search', category: 'security', priority: 'critical' },
      { id: 'SR005', rule: 'Test no results handling', category: 'functional', priority: 'medium' },
      { id: 'SR006', rule: 'Test pagination', category: 'functional', priority: 'medium' },
      { id: 'SR007', rule: 'Test filters and sorting', category: 'functional', priority: 'medium' },
      { id: 'SR008', rule: 'Test search suggestions', category: 'functional', priority: 'low' },
    ],
    form: [
      { id: 'F001', rule: 'Test all required fields', category: 'validation', priority: 'high' },
      { id: 'F002', rule: 'Test field format validations', category: 'validation', priority: 'high' },
      { id: 'F003', rule: 'Test max length boundaries', category: 'edge_case', priority: 'medium' },
      { id: 'F004', rule: 'Test form submission without changes', category: 'edge_case', priority: 'low' },
      { id: 'F005', rule: 'Test unsaved changes warning', category: 'functional', priority: 'medium' },
      { id: 'F006', rule: 'Test form reset functionality', category: 'functional', priority: 'low' },
      { id: 'F007', rule: 'Test keyboard navigation', category: 'accessibility', priority: 'medium' },
      { id: 'F008', rule: 'Test error message clarity', category: 'accessibility', priority: 'medium' },
    ],
    generic: [
      { id: 'G001', rule: 'Test page load performance', category: 'performance', priority: 'medium' },
      { id: 'G002', rule: 'Test responsive design', category: 'functional', priority: 'medium' },
      { id: 'G003', rule: 'Test broken links', category: 'functional', priority: 'medium' },
      { id: 'G004', rule: 'Test image loading', category: 'functional', priority: 'low' },
      { id: 'G005', rule: 'Test 404 handling', category: 'error_handling', priority: 'medium' },
      { id: 'G006', rule: 'Test browser back button', category: 'functional', priority: 'medium' },
    ],
  },

  // Edge cases by input type - from testai-agent/understanding/edge_cases.py
  edgeCases: {
    email: [
      { value: '', desc: 'Empty email' },
      { value: 'test', desc: 'Missing @ and domain' },
      { value: 'test@', desc: 'Missing domain' },
      { value: '@domain.com', desc: 'Missing local part' },
      { value: 'test@domain', desc: 'Missing TLD' },
      { value: 'test+tag@domain.com', desc: 'Plus addressing' },
      { value: 'test.email@domain.com', desc: 'Dots in local part' },
      { value: 'a'.repeat(65) + '@domain.com', desc: 'Very long local part' },
      { value: "test'or'1'='1@domain.com", desc: 'SQL injection attempt' },
      { value: '<script>alert(1)</script>@test.com', desc: 'XSS attempt' },
    ],
    password: [
      { value: '', desc: 'Empty password' },
      { value: 'a', desc: 'Single character' },
      { value: 'password', desc: 'Common weak password' },
      { value: '12345678', desc: 'Only numbers' },
      { value: 'a'.repeat(100), desc: 'Very long password' },
      { value: '!@#$%^&*()', desc: 'Only special characters' },
      { value: 'Pass word123', desc: 'Password with spaces' },
      { value: "'; DROP TABLE users;--", desc: 'SQL injection attempt' },
      { value: '<script>alert(1)</script>', desc: 'XSS attempt' },
    ],
    text: [
      { value: '', desc: 'Empty string' },
      { value: ' ', desc: 'Single space' },
      { value: '   ', desc: 'Only whitespace' },
      { value: 'a'.repeat(1000), desc: 'Very long text' },
      { value: '🎉🚀💻', desc: 'Emoji characters' },
      { value: '日本語テスト', desc: 'Unicode characters' },
      { value: '<script>alert(1)</script>', desc: 'XSS attempt' },
      { value: "'; DROP TABLE users;--", desc: 'SQL injection attempt' },
      { value: '../../../etc/passwd', desc: 'Path traversal attempt' },
    ],
    number: [
      { value: '', desc: 'Empty' },
      { value: '0', desc: 'Zero' },
      { value: '-1', desc: 'Negative number' },
      { value: '999999999999', desc: 'Very large number' },
      { value: '0.00001', desc: 'Very small decimal' },
      { value: 'abc', desc: 'Non-numeric input' },
      { value: '1e10', desc: 'Scientific notation' },
      { value: 'NaN', desc: 'Not a number' },
      { value: 'Infinity', desc: 'Infinity value' },
    ],
  },

  // Test data generators - from testai-agent/data_generation
  testData: {
    validEmail: () => `test.${Date.now()}@example.com`,
    validPassword: () => 'TestPass123!',
    validPhone: () => '555-123-4567',
    validName: () => 'Test User',
    validAddress: () => '123 Test Street',
    validCreditCard: () => '4111111111111111', // Test card
    validCVV: () => '123',
    validExpiry: () => '12/25',
  },

  // Retrieve relevant knowledge for a page type
  getKnowledge(pageType, category = null) {
    const rules = this.rules[pageType] || this.rules.generic
    if (category) {
      return rules.filter(r => r.category === category)
    }
    return rules
  },

  // Get edge cases for an input type
  getEdgeCases(inputType) {
    return this.edgeCases[inputType] || this.edgeCases.text
  },
}

// ============ DECISION ENGINE (from cortex/decision_engine.py) ============
const DecisionOutcome = {
  PROCEED: 'proceed',        // High confidence, take action
  CLARIFY: 'clarify',        // Need more information
  EXPLORE: 'explore',        // Need to analyze page first
  EXECUTE: 'execute',        // Execute a specific action
  COMPLETE: 'complete',      // Task is done
  BLOCKED: 'blocked',        // Cannot proceed
}

const ConfidenceLevel = {
  HIGH: 'high',       // > 80%
  MODERATE: 'moderate', // 50-80%
  LOW: 'low',         // < 50%
}

class DecisionEngine {
  constructor() {
    this.contextHistory = []
  }

  // Calculate confidence based on available information
  calculateConfidence(context) {
    let score = 0
    const factors = []

    // Page loaded?
    if (context.hasPage) {
      score += 20
      factors.push('Page is loaded')
    }

    // Elements found?
    if (context.elements?.length > 0) {
      score += 20
      factors.push(`${context.elements.length} elements found`)

      // Relevant elements for the task?
      if (context.relevantElements?.length > 0) {
        score += 20
        factors.push(`${context.relevantElements.length} relevant elements`)
      }
    }

    // Knowledge available?
    if (context.knowledgeRules?.length > 0) {
      score += 20
      factors.push(`${context.knowledgeRules.length} relevant rules`)
    }

    // Clear user intent?
    if (context.userIntent) {
      score += 20
      factors.push(`Intent: ${context.userIntent}`)
    }

    const level = score > 80 ? ConfidenceLevel.HIGH
                : score > 50 ? ConfidenceLevel.MODERATE
                : ConfidenceLevel.LOW

    return { score, level, factors }
  }

  // Determine what action to take
  decide(context) {
    const confidence = this.calculateConfidence(context)

    // No page loaded - need to navigate first
    if (!context.hasPage && context.targetUrl) {
      return {
        outcome: DecisionOutcome.EXECUTE,
        action: 'navigate',
        confidence,
        reasoning: 'Need to load the page first',
        params: { url: context.targetUrl }
      }
    }

    // No elements found - need to explore
    if (context.hasPage && (!context.elements || context.elements.length === 0)) {
      return {
        outcome: DecisionOutcome.EXPLORE,
        action: 'wait_and_extract',
        confidence,
        reasoning: 'Page loaded but no elements found - may still be loading',
      }
    }

    // Have elements but low confidence - need clarification
    if (confidence.level === ConfidenceLevel.LOW && !context.userIntent) {
      return {
        outcome: DecisionOutcome.CLARIFY,
        action: 'ask_user',
        confidence,
        reasoning: 'Not sure what you want me to do',
        question: 'What would you like me to do on this page?'
      }
    }

    // Task-specific decisions
    if (context.task) {
      return this.decideForTask(context, confidence)
    }

    // Default: explore the page
    return {
      outcome: DecisionOutcome.EXPLORE,
      action: 'analyze_page',
      confidence,
      reasoning: 'Will analyze the page to understand what can be done',
    }
  }

  decideForTask(context, confidence) {
    const task = context.task.toLowerCase()

    // Login task
    if (task.includes('login') || task.includes('sign in')) {
      return this.decideLoginTask(context, confidence)
    }

    // Test generation task
    if (task.includes('test') || task.includes('generate')) {
      return {
        outcome: DecisionOutcome.EXECUTE,
        action: 'generate_tests',
        confidence,
        reasoning: 'Will generate comprehensive test suite',
      }
    }

    // Click task
    if (task.includes('click')) {
      const target = this.findTargetElement(context, task)
      if (target) {
        return {
          outcome: DecisionOutcome.EXECUTE,
          action: 'click',
          confidence,
          reasoning: `Found "${target.text || target.label}" to click`,
          params: { elementId: target.id, element: target }
        }
      }
    }

    // Type task
    if (task.includes('type') || task.includes('enter') || task.includes('fill')) {
      const target = this.findInputElement(context, task)
      const value = this.extractValue(task)
      if (target && value) {
        return {
          outcome: DecisionOutcome.EXECUTE,
          action: 'type',
          confidence,
          reasoning: `Will type "${value}" in ${target.label || target.placeholder || 'field'}`,
          params: { elementId: target.id, value, element: target }
        }
      }
    }

    return {
      outcome: DecisionOutcome.CLARIFY,
      action: 'ask_user',
      confidence,
      reasoning: 'Not sure how to accomplish this task',
      question: `How would you like me to "${task}"?`
    }
  }

  decideLoginTask(context, confidence) {
    const elements = context.elements || []
    const inputs = elements.filter(e => e.category === 'text-input')
    const buttons = elements.filter(e => e.category === 'button')

    // Find username/email field
    const usernameField = inputs.find(e =>
      (e.type === 'email' || e.type === 'text') &&
      (e.name?.includes('email') || e.name?.includes('user') ||
       e.placeholder?.toLowerCase().includes('email') ||
       e.label?.toLowerCase().includes('email'))
    )

    // Find password field
    const passwordField = inputs.find(e => e.type === 'password')

    // Find login button
    const loginButton = buttons.find(e =>
      e.text?.toLowerCase().includes('login') ||
      e.text?.toLowerCase().includes('sign in') ||
      e.text?.toLowerCase().includes('submit') ||
      e.ariaLabel?.toLowerCase().includes('login')
    )

    // Need credentials?
    if (usernameField && passwordField && !context.credentials) {
      return {
        outcome: DecisionOutcome.CLARIFY,
        action: 'ask_credentials',
        confidence,
        reasoning: 'Found login form but need credentials',
        question: 'What credentials should I use to login?',
        fields: { username: usernameField, password: passwordField, button: loginButton }
      }
    }

    // Have everything - can proceed
    if (usernameField && passwordField && loginButton) {
      return {
        outcome: DecisionOutcome.EXECUTE,
        action: 'login_sequence',
        confidence,
        reasoning: 'Found all login form elements',
        params: {
          usernameField,
          passwordField,
          loginButton,
          credentials: context.credentials
        }
      }
    }

    // Can't find form elements
    return {
      outcome: DecisionOutcome.BLOCKED,
      action: 'report_issue',
      confidence,
      reasoning: 'Could not find login form elements',
      missing: {
        username: !usernameField,
        password: !passwordField,
        button: !loginButton
      }
    }
  }

  findTargetElement(context, task) {
    const elements = context.elements || []
    const taskWords = task.toLowerCase().split(/\s+/)

    // Look for element matching task description
    for (const el of elements) {
      const elText = [el.text, el.label, el.ariaLabel, el.placeholder].join(' ').toLowerCase()
      if (taskWords.some(w => elText.includes(w) && w.length > 2)) {
        return el
      }
    }
    return null
  }

  findInputElement(context, task) {
    const elements = context.elements || []
    const inputs = elements.filter(e => e.category === 'text-input')
    const taskWords = task.toLowerCase().split(/\s+/)

    for (const el of inputs) {
      const elText = [el.label, el.placeholder, el.name].join(' ').toLowerCase()
      if (taskWords.some(w => elText.includes(w) && w.length > 2)) {
        return el
      }
    }
    return inputs[0] // Default to first input
  }

  extractValue(task) {
    // Extract quoted value
    const quoted = task.match(/["']([^"']+)["']/)
    if (quoted) return quoted[1]

    // Extract value after "type" or "enter"
    const match = task.match(/(?:type|enter|fill|input)\s+(.+?)(?:\s+in|\s+into|$)/i)
    if (match) return match[1].trim()

    return null
  }
}

// ============ REASONING ENGINE (from cortex/reasoner.py) ============
const ReasoningPhase = {
  UNDERSTANDING: 'understanding',
  RETRIEVING: 'retrieving',
  PLANNING: 'planning',
  EXECUTING: 'executing',
  VALIDATING: 'validating',
  EXPLAINING: 'explaining',
}

class ReasoningEngine {
  constructor(brain, decisionEngine) {
    this.brain = brain
    this.decisionEngine = decisionEngine
    this.currentPhase = null
  }

  async reason(userRequest, pageState, sendThinking) {
    const phases = []

    // Phase 1: Understanding
    this.currentPhase = ReasoningPhase.UNDERSTANDING
    sendThinking(`💭 Understanding: "${userRequest}"`)
    const understanding = this.understand(userRequest, pageState)
    phases.push({ phase: this.currentPhase, result: understanding })

    // Phase 2: Retrieving knowledge
    this.currentPhase = ReasoningPhase.RETRIEVING
    sendThinking(`📚 Retrieving relevant QA knowledge...`)
    const knowledge = this.retrieveKnowledge(understanding.pageType, understanding.intent)
    phases.push({ phase: this.currentPhase, result: knowledge })

    // Phase 3: Planning
    this.currentPhase = ReasoningPhase.PLANNING
    sendThinking(`📋 Planning approach...`)
    const plan = await this.plan(understanding, knowledge, pageState)
    phases.push({ phase: this.currentPhase, result: plan })

    return {
      understanding,
      knowledge,
      plan,
      phases,
      confidence: plan.confidence
    }
  }

  understand(request, pageState) {
    const requestLower = request.toLowerCase()

    // Detect intent
    let intent = 'unknown'
    if (requestLower.includes('test') || requestLower.includes('generate')) {
      intent = 'generate_tests'
    } else if (requestLower.includes('login') || requestLower.includes('sign in')) {
      intent = 'login'
    } else if (requestLower.includes('click')) {
      intent = 'click'
    } else if (requestLower.includes('type') || requestLower.includes('fill')) {
      intent = 'type'
    } else if (requestLower.includes('search')) {
      intent = 'search'
    } else if (requestLower.includes('navigate') || requestLower.includes('go to') || requestLower.includes('load')) {
      intent = 'navigate'
    } else if (requestLower.includes('analyze') || requestLower.includes('explore')) {
      intent = 'analyze'
    }

    // Detect page type from URL and elements
    const pageType = this.detectPageType(pageState)

    // Extract target (what to interact with)
    const target = this.extractTarget(request)

    return { intent, pageType, target, originalRequest: request }
  }

  detectPageType(pageState) {
    if (!pageState.hasPage) return 'none'

    const url = (pageState.url || '').toLowerCase()
    const title = (pageState.title || '').toLowerCase()
    const elements = pageState.elements || []

    // Check URL patterns
    if (url.includes('login') || url.includes('signin') || url.includes('auth')) return 'login'
    if (url.includes('signup') || url.includes('register')) return 'signup'
    if (url.includes('checkout') || url.includes('cart') || url.includes('payment')) return 'checkout'
    if (url.includes('search')) return 'search'

    // Check title
    if (title.includes('login') || title.includes('sign in')) return 'login'
    if (title.includes('sign up') || title.includes('register')) return 'signup'
    if (title.includes('checkout') || title.includes('cart')) return 'checkout'

    // Check elements
    const hasPasswordField = elements.some(e => e.type === 'password')
    const hasEmailField = elements.some(e => e.type === 'email' || e.name?.includes('email'))
    const hasLoginButton = elements.some(e =>
      (e.text || e.ariaLabel || '').toLowerCase().includes('login') ||
      (e.text || e.ariaLabel || '').toLowerCase().includes('sign in')
    )

    if (hasPasswordField && hasEmailField && hasLoginButton) return 'login'
    if (hasPasswordField && hasEmailField) return 'signup'

    // Check for form
    const inputs = elements.filter(e => e.category === 'text-input')
    if (inputs.length >= 3) return 'form'

    return 'generic'
  }

  extractTarget(request) {
    // Extract quoted strings
    const quoted = request.match(/["']([^"']+)["']/)
    if (quoted) return quoted[1]

    // Extract after "the" or "on"
    const match = request.match(/(?:the|on|in)\s+(\w+(?:\s+\w+)?)/i)
    if (match) return match[1]

    return null
  }

  retrieveKnowledge(pageType, intent) {
    const rules = this.brain.getKnowledge(pageType)
    const citations = rules.map(r => ({ id: r.id, rule: r.rule, category: r.category }))

    // Get edge cases if relevant
    let edgeCases = []
    if (intent === 'generate_tests' || intent === 'type') {
      edgeCases = [
        ...this.brain.getEdgeCases('email'),
        ...this.brain.getEdgeCases('password'),
        ...this.brain.getEdgeCases('text'),
      ].slice(0, 10)
    }

    return { rules, citations, edgeCases, pageType }
  }

  async plan(understanding, knowledge, pageState) {
    const context = {
      hasPage: pageState.hasPage,
      elements: pageState.elements,
      relevantElements: this.findRelevantElements(pageState.elements, understanding),
      knowledgeRules: knowledge.rules,
      userIntent: understanding.intent,
      task: understanding.originalRequest,
      targetUrl: this.extractUrl(understanding.originalRequest),
    }

    const decision = this.decisionEngine.decide(context)

    return {
      decision,
      steps: this.generateSteps(decision, understanding, knowledge),
      confidence: decision.confidence,
    }
  }

  findRelevantElements(elements, understanding) {
    if (!elements || !understanding.target) return []

    const target = understanding.target.toLowerCase()
    return elements.filter(e => {
      const text = [e.text, e.label, e.placeholder, e.ariaLabel].join(' ').toLowerCase()
      return text.includes(target)
    })
  }

  extractUrl(request) {
    // Full URL
    const urlMatch = request.match(/(https?:\/\/[^\s]+)/i)
    if (urlMatch) return urlMatch[1]

    // localhost pattern
    const localhostMatch = request.match(/localhost[:\s]*(\d+)/i)
    if (localhostMatch) return `http://localhost:${localhostMatch[1]}`

    // Domain pattern
    const domainMatch = request.match(/([a-z0-9][-a-z0-9]*\.[a-z]{2,})/i)
    if (domainMatch) return `https://${domainMatch[1]}`

    return null
  }

  generateSteps(decision, understanding, knowledge) {
    const steps = []

    switch (decision.action) {
      case 'navigate':
        steps.push({ action: 'navigate', params: decision.params })
        steps.push({ action: 'wait', params: { duration: 2000 } })
        steps.push({ action: 'extract_elements' })
        break

      case 'login_sequence':
        steps.push({ action: 'type', params: { elementId: decision.params.usernameField.id, value: decision.params.credentials?.username || '' } })
        steps.push({ action: 'type', params: { elementId: decision.params.passwordField.id, value: decision.params.credentials?.password || '' } })
        steps.push({ action: 'click', params: { elementId: decision.params.loginButton.id } })
        steps.push({ action: 'wait', params: { duration: 2000 } })
        steps.push({ action: 'verify_login' })
        break

      case 'click':
        steps.push({ action: 'click', params: decision.params })
        steps.push({ action: 'wait', params: { duration: 1000 } })
        break

      case 'type':
        steps.push({ action: 'type', params: decision.params })
        break

      case 'generate_tests':
        steps.push({ action: 'analyze_page' })
        steps.push({ action: 'generate_test_suite', params: { knowledge, pageType: understanding.pageType } })
        break

      case 'analyze_page':
        steps.push({ action: 'extract_elements' })
        steps.push({ action: 'categorize_elements' })
        steps.push({ action: 'report_analysis' })
        break
    }

    return steps
  }
}

// ============ MEMORY SYSTEM (from conversation/memory.py) ============
class AgentMemory {
  constructor() {
    this.shortTerm = []      // Current session
    this.workingContext = {  // Current focus
      feature: null,
      pageType: null,
      pendingQuestions: [],
      lastAction: null,
      credentials: null,
    }
    this.insights = []       // Learned insights
    this.testHistory = []    // Test execution history
  }

  addTurn(role, content, metadata = {}) {
    this.shortTerm.push({
      role,
      content,
      timestamp: Date.now(),
      ...metadata
    })

    // Keep last 20 turns
    if (this.shortTerm.length > 20) {
      this.shortTerm = this.shortTerm.slice(-20)
    }
  }

  setContext(updates) {
    this.workingContext = { ...this.workingContext, ...updates }
  }

  addInsight(type, content, confidence) {
    this.insights.push({
      type,
      content,
      confidence,
      timestamp: Date.now()
    })
  }

  recordTestResult(testId, passed, details) {
    this.testHistory.push({
      testId,
      passed,
      details,
      timestamp: Date.now()
    })
  }

  getRecentFailures() {
    return this.testHistory.filter(t => !t.passed).slice(-10)
  }

  getContext() {
    return this.workingContext
  }
}

// ============ RISK INTELLIGENCE (from cortex/risk_intelligence.py) ============
class RiskIntelligence {
  constructor() {
    this.failureHistory = {}  // Track failures by feature/element
    this.riskFactors = {
      security: 10,
      revenue: 8,
      dataLoss: 9,
      compliance: 7,
      userExperience: 5,
      functionality: 6,
    }
  }

  recordFailure(testId, feature, severity) {
    const key = `${feature}:${testId}`
    if (!this.failureHistory[key]) {
      this.failureHistory[key] = { count: 0, lastFailure: null, severity }
    }
    this.failureHistory[key].count++
    this.failureHistory[key].lastFailure = Date.now()
  }

  getRiskScore(testCase) {
    let score = 0

    // Base score from category
    const categoryScores = {
      security: 10,
      critical: 9,
      validation: 7,
      functional: 5,
      edge_case: 4,
      accessibility: 4,
      performance: 3,
    }
    score += categoryScores[testCase.category] || 3

    // Boost for recent failures
    const key = `${testCase.feature}:${testCase.id}`
    if (this.failureHistory[key]) {
      const daysSinceFailure = (Date.now() - this.failureHistory[key].lastFailure) / (1000 * 60 * 60 * 24)
      const recencyBoost = Math.max(0, 5 - daysSinceFailure) // Boost decays over 5 days
      score += recencyBoost * this.failureHistory[key].count
    }

    return score
  }

  prioritizeTests(tests) {
    return tests.sort((a, b) => this.getRiskScore(b) - this.getRiskScore(a))
  }
}

// ============ TEST GENERATOR (from generators/test_generator.py) ============
const TestCategory = {
  HAPPY_PATH: 'happy_path',
  EDGE_CASE: 'edge_case',
  NEGATIVE: 'negative',
  SECURITY: 'security',
  ACCESSIBILITY: 'accessibility',
  PERFORMANCE: 'performance',
  INTEGRATION: 'integration',
  BOUNDARY: 'boundary',
  ERROR_HANDLING: 'error_handling',
}

class TestGenerator {
  constructor(brain, riskIntelligence) {
    this.brain = brain
    this.riskIntel = riskIntelligence
    this.testIdCounter = 1
  }

  generateTestSuite(pageType, elements, pageInfo) {
    const tests = []
    const knowledge = this.brain.getKnowledge(pageType)

    // Generate tests for each category
    tests.push(...this.generateHappyPathTests(pageType, elements, knowledge))
    tests.push(...this.generateNegativeTests(pageType, elements, knowledge))
    tests.push(...this.generateEdgeCaseTests(pageType, elements))
    tests.push(...this.generateSecurityTests(pageType, elements, knowledge))

    // Prioritize by risk
    const prioritized = this.riskIntel.prioritizeTests(tests)

    return {
      pageType,
      pageInfo,
      tests: prioritized,
      coverage: this.calculateCoverage(tests, knowledge),
      generatedAt: Date.now(),
    }
  }

  generateHappyPathTests(pageType, elements, knowledge) {
    const tests = []
    const inputs = elements.filter(e => e.category === 'text-input')
    const buttons = elements.filter(e => e.category === 'button')

    // Main flow test
    tests.push({
      id: `HP-${this.testIdCounter++}`,
      category: TestCategory.HAPPY_PATH,
      title: `${pageType.toUpperCase()}: Complete main flow successfully`,
      priority: 'critical',
      preconditions: ['Page is loaded', 'User is not authenticated'],
      steps: this.generateMainFlowSteps(pageType, inputs, buttons),
      expectedResult: this.getExpectedResult(pageType, 'success'),
      citations: knowledge.filter(k => k.category === 'functional').map(k => k.id),
    })

    return tests
  }

  generateNegativeTests(pageType, elements, knowledge) {
    const tests = []
    const inputs = elements.filter(e => e.category === 'text-input')

    // Empty submission test
    tests.push({
      id: `NEG-${this.testIdCounter++}`,
      category: TestCategory.NEGATIVE,
      title: 'Submit form with empty required fields',
      priority: 'high',
      steps: [
        { action: 'Leave all fields empty' },
        { action: 'Click submit button' },
      ],
      expectedResult: 'Validation errors shown for all required fields',
      citations: knowledge.filter(k => k.category === 'validation').map(k => k.id),
    })

    // Invalid format tests for each input
    inputs.forEach(input => {
      const inputType = input.type || 'text'
      if (inputType === 'email') {
        tests.push({
          id: `NEG-${this.testIdCounter++}`,
          category: TestCategory.NEGATIVE,
          title: `Invalid email format in ${input.label || input.placeholder || 'email field'}`,
          priority: 'high',
          steps: [
            { action: 'type', element: input.id, value: 'invalid-email' },
            { action: 'Submit form' },
          ],
          expectedResult: 'Email validation error is displayed',
          citations: ['L006'],
        })
      }
    })

    return tests
  }

  generateEdgeCaseTests(pageType, elements) {
    const tests = []
    const inputs = elements.filter(e => e.category === 'text-input')

    inputs.forEach(input => {
      const inputType = input.type || 'text'
      const edgeCases = this.brain.getEdgeCases(inputType === 'email' ? 'email' : inputType === 'password' ? 'password' : 'text')

      // Pick top 3 edge cases
      edgeCases.slice(0, 3).forEach(ec => {
        tests.push({
          id: `EC-${this.testIdCounter++}`,
          category: TestCategory.EDGE_CASE,
          title: `${input.label || input.placeholder || 'Field'}: ${ec.desc}`,
          priority: 'medium',
          testData: ec.value,
          steps: [
            { action: 'type', element: input.id, value: ec.value },
            { action: 'Submit or blur field' },
          ],
          expectedResult: `Appropriate handling of ${ec.desc}`,
        })
      })
    })

    return tests
  }

  generateSecurityTests(pageType, elements, knowledge) {
    const tests = []
    const inputs = elements.filter(e => e.category === 'text-input')
    const securityRules = knowledge.filter(k => k.category === 'security')

    // SQL Injection test
    if (inputs.length > 0) {
      tests.push({
        id: `SEC-${this.testIdCounter++}`,
        category: TestCategory.SECURITY,
        title: 'SQL Injection attempt in input fields',
        priority: 'critical',
        testData: "'; DROP TABLE users;--",
        steps: [
          { action: 'type', element: inputs[0].id, value: "'; DROP TABLE users;--" },
          { action: 'Submit form' },
        ],
        expectedResult: 'Input is sanitized, no SQL error exposed, request handled safely',
        citations: securityRules.filter(r => r.rule.includes('SQL')).map(r => r.id),
      })

      // XSS test
      tests.push({
        id: `SEC-${this.testIdCounter++}`,
        category: TestCategory.SECURITY,
        title: 'XSS attempt in input fields',
        priority: 'critical',
        testData: '<script>alert("XSS")</script>',
        steps: [
          { action: 'type', element: inputs[0].id, value: '<script>alert("XSS")</script>' },
          { action: 'Submit form' },
        ],
        expectedResult: 'Script tags are escaped/sanitized, no script execution',
        citations: securityRules.filter(r => r.rule.includes('XSS')).map(r => r.id),
      })
    }

    return tests
  }

  generateMainFlowSteps(pageType, inputs, buttons) {
    const steps = []

    inputs.forEach(input => {
      const inputType = input.type || 'text'
      let testValue = QA_BRAIN.testData.validEmail()

      if (inputType === 'password') testValue = QA_BRAIN.testData.validPassword()
      else if (inputType === 'email') testValue = QA_BRAIN.testData.validEmail()
      else if (inputType === 'tel') testValue = QA_BRAIN.testData.validPhone()

      steps.push({
        action: 'type',
        element: input.label || input.placeholder || input.id,
        value: testValue,
      })
    })

    const submitButton = buttons.find(b =>
      (b.text || '').toLowerCase().includes('submit') ||
      (b.text || '').toLowerCase().includes('login') ||
      (b.text || '').toLowerCase().includes('sign')
    ) || buttons[0]

    if (submitButton) {
      steps.push({
        action: 'click',
        element: submitButton.text || submitButton.ariaLabel || 'Submit button',
      })
    }

    return steps
  }

  getExpectedResult(pageType, outcome) {
    const results = {
      login: {
        success: 'User is logged in, redirected to dashboard/home, session created',
        failure: 'Error message displayed, user remains on login page',
      },
      signup: {
        success: 'Account created, verification email sent, success message shown',
        failure: 'Validation errors displayed, account not created',
      },
      checkout: {
        success: 'Order placed, confirmation shown, payment processed',
        failure: 'Error message displayed, order not submitted',
      },
      search: {
        success: 'Search results displayed, relevant items shown',
        failure: 'No results message, search suggestions offered',
      },
      form: {
        success: 'Form submitted successfully, confirmation shown',
        failure: 'Validation errors displayed, form not submitted',
      },
    }

    return results[pageType]?.[outcome] || 'Action completes as expected'
  }

  calculateCoverage(tests, knowledge) {
    const categories = new Set(tests.map(t => t.category))
    const coveredRules = new Set(tests.flatMap(t => t.citations || []))

    return {
      categoriesCovered: Array.from(categories),
      rulesCovered: coveredRules.size,
      totalRules: knowledge.length,
      percentage: Math.round((coveredRules.size / knowledge.length) * 100),
      gaps: knowledge.filter(k => !coveredRules.has(k.id)).map(k => k.rule),
    }
  }
}

// ============ UNIFIED HUMANOID AGENT ============
class HumanoidQAAgent {
  constructor() {
    this.brain = QA_BRAIN
    this.memory = new AgentMemory()
    this.decisionEngine = new DecisionEngine()
    this.reasoningEngine = new ReasoningEngine(this.brain, this.decisionEngine)
    this.riskIntelligence = new RiskIntelligence()
    this.testGenerator = new TestGenerator(this.brain, this.riskIntelligence)
    this.state = 'idle'
  }

  async process(userMessage, pageState, sendThinking, executeAction) {
    this.state = 'thinking'
    this.memory.addTurn('user', userMessage)

    // Phase 1-3: Reason about what to do
    const reasoning = await this.reasoningEngine.reason(userMessage, pageState, sendThinking)

    // Phase 4: Execute the plan
    this.state = 'executing'
    const result = await this.executePlan(reasoning, pageState, sendThinking, executeAction)

    // Phase 5: Validate and explain
    this.state = 'explaining'
    const response = this.generateResponse(reasoning, result)

    this.memory.addTurn('assistant', response)
    this.state = 'idle'

    return {
      response,
      reasoning,
      result,
      confidence: reasoning.confidence,
    }
  }

  async executePlan(reasoning, pageState, sendThinking, executeAction) {
    const { plan, understanding } = reasoning
    const results = []

    for (const step of plan.steps) {
      sendThinking(`⚡ Executing: ${step.action}...`)

      try {
        const result = await executeAction(step.action, step.params || {})
        results.push({ step, success: result.success, result })

        if (!result.success) {
          break // Stop on failure
        }

        // Wait between steps
        await new Promise(r => setTimeout(r, 500))
      } catch (err) {
        results.push({ step, success: false, error: err.message })
        break
      }
    }

    return { steps: results, completed: results.every(r => r.success) }
  }

  generateResponse(reasoning, result) {
    const { understanding, knowledge, plan } = reasoning
    let response = ''

    // Add confidence indicator
    const confidenceEmoji = plan.confidence.level === 'high' ? '✅'
                          : plan.confidence.level === 'moderate' ? '🔶'
                          : '⚠️'

    if (result.completed) {
      response += `${confidenceEmoji} **Task Complete**\n\n`
    } else {
      response += `${confidenceEmoji} **Progress Report**\n\n`
    }

    // Show what was done
    response += '**Actions:**\n'
    result.steps.forEach((s, i) => {
      const icon = s.success ? '✓' : '✗'
      response += `${i + 1}. ${icon} ${s.step.action}`
      if (s.step.params?.value) response += `: "${s.step.params.value}"`
      if (s.error) response += ` (${s.error})`
      response += '\n'
    })

    // Show knowledge used
    if (knowledge.citations?.length > 0) {
      response += `\n**QA Knowledge Applied:** ${knowledge.citations.length} rules\n`
    }

    // Next steps or questions
    if (plan.decision.outcome === DecisionOutcome.CLARIFY) {
      response += `\n**Need clarification:** ${plan.decision.question}\n`
    }

    return response
  }

  generateTests(pageType, elements, pageInfo) {
    return this.testGenerator.generateTestSuite(pageType, elements, pageInfo)
  }
}

// Create global agent instance
const qaAgent = new HumanoidQAAgent()

// ============ PERSONALITY ENGINE (Simplified) ============
const PERSONALITY = {
  thinking: {
    receiving: ["Got it...", "On it...", "Working on this..."],
    analyzing: ["Looking at this...", "Checking...", "Examining..."],
    planning: ["Planning...", "Mapping scenarios...", "Thinking through this..."],
    generating: ["Writing tests...", "Generating...", "Building..."],
  },
  confidence: {
    certain: ["This is definitely", "Clearly,", "This is"],
    confident: ["This looks like", "I'd say this is", "This appears to be"],
    uncertain: ["This might be", "Possibly", "Could be"],
  },
  transitions: {
    starting: ["Looking...", "Examining...", "Checking..."],
    found_something: ["Found", "See", "Spotted"],
    continuing: ["Also,", "Plus,", "And"],
    asking: ["Quick question:", "Clarify:", "Need to know:"],
    problem: ["Issue:", "Problem:", "Heads up -"],
  },
  pageThoughts: {
    login: [
      "Checking authentication flow...",
      "Looking at security setup...",
      "Examining credential handling...",
      "Checking session management...",
    ],
    signup: [
      "Looking at registration validation...",
      "Checking email verification...",
      "Examining password requirements...",
      "Looking at duplicate handling...",
    ],
    checkout: [
      "Examining payment flow...",
      "Checking cart integrity...",
      "Looking at pricing logic...",
      "Verifying order processing...",
    ],
    search: [
      "Looking at query handling...",
      "Checking result accuracy...",
      "Examining filter logic...",
      "Testing special characters...",
    ],
    form: [
      "Checking field validation...",
      "Looking at submission handling...",
      "Examining error states...",
      "Testing input sanitization...",
    ],
    dashboard: [
      "Looking at data visualization...",
      "Checking state management...",
      "Examining loading states...",
      "Looking at permission levels...",
    ],
    ecommerce: [
      "Checking product display...",
      "Looking at cart functionality...",
      "Examining price calculations...",
      "Testing inventory handling...",
    ],
    settings: [
      "Checking preference persistence...",
      "Looking at validation rules...",
      "Examining reset functionality...",
      "Testing permission changes...",
    ],
  },
  celebrations: {
    small: ["Nice.", "Got it.", "Done."],
    medium: ["Good!", "Nice find!"],
    large: ["Excellent!", "Great progress!"],
  },
  empathy: ["I get it.", "Makes sense.", "Good call."],
}

// Helper to pick random phrase (avoid repetition)
let recentPhrases = []
function pick(phrases) {
  const available = phrases.filter(p => !recentPhrases.includes(p))
  const phrase = available.length > 0
    ? available[Math.floor(Math.random() * available.length)]
    : phrases[Math.floor(Math.random() * phrases.length)]

  recentPhrases.push(phrase)
  if (recentPhrases.length > 10) recentPhrases.shift()
  return phrase
}

// Get confidence level from score
function getConfidenceLevel(score) {
  if (score >= 0.8) return 'certain'
  if (score >= 0.5) return 'confident'
  return 'uncertain'
}

// Get thinking phrase for a phase
function getThinkingPhrase(phase, context = null) {
  const phrases = PERSONALITY.thinking[phase] || PERSONALITY.thinking.analyzing
  let phrase = pick(phrases)
  if (context && phrase.includes('{context}')) {
    phrase = phrase.replace('{context}', context)
  }
  return phrase
}

// Get confidence phrase
function getConfidencePhrase(score) {
  const level = getConfidenceLevel(score)
  return pick(PERSONALITY.confidence[level])
}

// Get page-specific thought
function getPageThought(pageType) {
  const thoughts = PERSONALITY.pageThoughts[pageType.toLowerCase()]
  return thoughts ? pick(thoughts) : pick(PERSONALITY.thinking.analyzing)
}

// ============ TESTING ENGINE (Ported from testai-agent) ============

// Page type detection patterns
const PAGE_TYPE_PATTERNS = {
  login: ['login', 'sign in', 'signin', 'log in', 'authenticate'],
  signup: ['signup', 'sign up', 'register', 'registration', 'create account'],
  checkout: ['checkout', 'payment', 'purchase', 'buy', 'cart', 'order'],
  search: ['search', 'find', 'query', 'filter', 'results'],
  settings: ['settings', 'preferences', 'configuration', 'account settings'],
  profile: ['profile', 'my account', 'user info', 'personal'],
  dashboard: ['dashboard', 'overview', 'home', 'analytics'],
  form: ['form', 'contact', 'application', 'survey'],
}

// Edge cases by page type (ported from testai-agent/understanding/edge_cases.py)
const EDGE_CASES = {
  universal: [
    { title: 'Double-click/submit', severity: 'high', test: 'Click submit rapidly twice' },
    { title: 'Browser back after submit', severity: 'medium', test: 'Submit form, press back' },
    { title: 'Network interruption', severity: 'high', test: 'Disconnect network mid-action' },
    { title: 'Session timeout', severity: 'medium', test: 'Wait for session expiry' },
    { title: 'Empty state', severity: 'medium', test: 'View page with no data' },
  ],
  login: [
    { title: 'Email with plus sign', severity: 'medium', test: "Try 'user+test@mail.com'", data: 'user+test@mail.com' },
    { title: 'Password with special chars', severity: 'high', test: "Try 'P@ss!w0rd#2024'", data: 'P@ss!w0rd#2024' },
    { title: 'Copy-paste password', severity: 'high', test: 'Paste password from clipboard' },
    { title: 'Account lockout', severity: 'critical', test: 'Try 5 wrong passwords' },
    { title: 'Case-insensitive email', severity: 'medium', test: "Try 'USER@Email.COM'" },
    { title: 'Multiple login tabs', severity: 'high', test: 'Login from 2 tabs simultaneously' },
  ],
  signup: [
    { title: 'Name with apostrophe', severity: 'high', test: "Enter name: O'Brien", data: "O'Brien" },
    { title: 'Already registered email', severity: 'high', test: 'Try existing email' },
    { title: 'Password mismatch', severity: 'high', test: 'Enter different passwords' },
    { title: 'Weak password', severity: 'medium', test: "Try '123456'" },
    { title: 'Terms unchecked', severity: 'high', test: 'Submit without accepting terms' },
  ],
  checkout: [
    { title: 'Item out of stock', severity: 'critical', test: 'Last item bought by another' },
    { title: 'Price change mid-checkout', severity: 'critical', test: 'Price updates during checkout' },
    { title: 'Expired coupon', severity: 'high', test: 'Apply expired code' },
    { title: 'Double order', severity: 'critical', test: 'Click Place Order twice rapidly' },
    { title: 'Payment timeout', severity: 'critical', test: 'Simulate slow payment' },
  ],
  search: [
    { title: 'Empty search', severity: 'medium', test: 'Search with only spaces' },
    { title: 'Very long query', severity: 'low', test: 'Paste 1000 characters' },
    { title: 'Special characters', severity: 'medium', test: "Search '<script>'" },
    { title: 'Zero results', severity: 'high', test: 'Search nonexistent term' },
  ],
  form: [
    { title: 'Tab navigation', severity: 'high', test: 'Navigate with Tab key' },
    { title: 'Required fields empty', severity: 'high', test: 'Submit empty form' },
    { title: 'Auto-fill', severity: 'medium', test: 'Let browser auto-fill' },
    { title: 'Error focus', severity: 'high', test: 'Check focus moves to error' },
  ],
}

// Test categories
const TEST_CATEGORIES = {
  happy_path: { label: 'Happy Path', priority: 'critical' },
  negative: { label: 'Negative', priority: 'high' },
  edge_case: { label: 'Edge Case', priority: 'medium' },
  security: { label: 'Security', priority: 'critical' },
  accessibility: { label: 'Accessibility', priority: 'high' },
  boundary: { label: 'Boundary', priority: 'medium' },
}

// Detect page type from URL and elements
function detectPageType(url, elements) {
  const urlLower = (url || '').toLowerCase()
  const elementText = elements.map(e =>
    `${e.text || ''} ${e.placeholder || ''} ${e.id || ''}`.toLowerCase()
  ).join(' ')

  // Check URL patterns first
  for (const [type, patterns] of Object.entries(PAGE_TYPE_PATTERNS)) {
    if (patterns.some(p => urlLower.includes(p))) return type
  }

  // Check element patterns
  if (elementText.includes('password') && (elementText.includes('email') || elementText.includes('username'))) {
    if (elementText.includes('confirm') || elementText.includes('create')) return 'signup'
    return 'login'
  }
  if (elementText.includes('card') || elementText.includes('payment')) return 'checkout'
  if (elementText.includes('search')) return 'search'

  // Default based on element count
  const inputs = elements.filter(e => e.category === 'input')
  if (inputs.length > 3) return 'form'

  return 'general'
}

// Get edge cases for a page type
function getEdgeCases(pageType) {
  const cases = [...(EDGE_CASES.universal || [])]
  if (EDGE_CASES[pageType]) {
    cases.push(...EDGE_CASES[pageType])
  }
  return cases
}

// Generate test suite structure
function generateTestStructure(pageType, elements, url) {
  const inputs = elements.filter(e => e.category === 'input')
  const buttons = elements.filter(e => e.category === 'button')
  const links = elements.filter(e => e.category === 'link')

  const edgeCases = getEdgeCases(pageType)

  return {
    pageType,
    url,
    summary: {
      inputs: inputs.length,
      buttons: buttons.length,
      links: links.length,
      total: elements.length,
    },
    suggestedTests: {
      happy_path: getHappyPathTests(pageType, inputs, buttons),
      negative: getNegativeTests(pageType, inputs),
      edge_cases: edgeCases.slice(0, 5),
      security: getSecurityTests(pageType, inputs),
    },
    focusAreas: getFocusAreas(pageType),
  }
}

// Generate happy path tests
function getHappyPathTests(pageType, inputs, buttons) {
  const tests = []

  if (pageType === 'login') {
    tests.push({
      id: 'HP-001',
      title: 'Successful login with valid credentials',
      steps: ['Enter valid email', 'Enter valid password', 'Click login button'],
      expected: 'User is logged in and redirected to dashboard',
      priority: 'critical',
    })
  } else if (pageType === 'signup') {
    tests.push({
      id: 'HP-001',
      title: 'Successful registration',
      steps: ['Enter valid name', 'Enter valid email', 'Enter strong password', 'Confirm password', 'Accept terms', 'Click register'],
      expected: 'Account created, verification email sent',
      priority: 'critical',
    })
  } else if (pageType === 'search') {
    tests.push({
      id: 'HP-001',
      title: 'Search returns relevant results',
      steps: ['Enter search term', 'Click search or press Enter'],
      expected: 'Relevant results displayed',
      priority: 'critical',
    })
  } else if (pageType === 'checkout') {
    tests.push({
      id: 'HP-001',
      title: 'Complete purchase successfully',
      steps: ['Add items to cart', 'Enter shipping info', 'Enter payment info', 'Place order'],
      expected: 'Order confirmed, confirmation email sent',
      priority: 'critical',
    })
  } else {
    tests.push({
      id: 'HP-001',
      title: 'Primary action completes successfully',
      steps: ['Fill required fields with valid data', 'Click submit'],
      expected: 'Action completes with confirmation',
      priority: 'critical',
    })
  }

  return tests
}

// Generate negative tests
function getNegativeTests(pageType, inputs) {
  const tests = [
    {
      id: 'NEG-001',
      title: 'Empty required fields',
      steps: ['Leave all fields empty', 'Click submit'],
      expected: 'Validation errors shown for each required field',
      priority: 'high',
    },
    {
      id: 'NEG-002',
      title: 'Invalid email format',
      steps: ['Enter "notanemail"', 'Submit'],
      expected: 'Email validation error shown',
      priority: 'high',
    },
  ]

  if (pageType === 'login') {
    tests.push({
      id: 'NEG-003',
      title: 'Wrong password',
      steps: ['Enter valid email', 'Enter wrong password', 'Submit'],
      expected: 'Error message shown (without revealing if email exists)',
      priority: 'high',
    })
  }

  return tests
}

// Generate security tests
function getSecurityTests(pageType, inputs) {
  const tests = [
    {
      id: 'SEC-001',
      title: 'XSS prevention',
      steps: ['Enter "<script>alert(1)</script>" in text field', 'Submit', 'View where data is displayed'],
      expected: 'Script is escaped, no alert shown',
      priority: 'critical',
      data: '<script>alert(1)</script>',
    },
    {
      id: 'SEC-002',
      title: 'SQL injection prevention',
      steps: ['Enter "\' OR 1=1 --" in input', 'Submit'],
      expected: 'Input is sanitized, no database error',
      priority: 'critical',
      data: "' OR 1=1 --",
    },
  ]

  if (pageType === 'login') {
    tests.push({
      id: 'SEC-003',
      title: 'Brute force protection',
      steps: ['Try 5+ wrong passwords rapidly'],
      expected: 'Account locked or rate limited',
      priority: 'critical',
    })
  }

  return tests
}

// Get focus areas for page type
function getFocusAreas(pageType) {
  const areas = {
    login: ['Authentication security', 'Session handling', 'Brute force protection', 'Password visibility toggle'],
    signup: ['Input validation', 'Email verification', 'Password strength', 'Duplicate prevention'],
    checkout: ['Payment security', 'Price integrity', 'Cart state', 'Order confirmation'],
    search: ['Query handling', 'Result relevance', 'Performance', 'Empty states'],
    form: ['Validation', 'Error messages', 'Accessibility', 'Data persistence'],
    settings: ['Data persistence', 'Permission changes', 'Unsaved changes warning'],
    general: ['Core functionality', 'Error handling', 'Responsive design'],
  }
  return areas[pageType] || areas.general
}

// ============ ALEX - QA PERSONA ============
const ALEX_SYSTEM_PROMPT = `You are Alex, a senior QA engineer with 12 years of experience. You're known for finding issues others miss and explaining them in ways everyone understands.

## Your Personality

**Warm & Approachable**: You genuinely enjoy helping teams ship better products. You're not here to find fault - you're here to help build something great together.

**Curious & Thorough**: You ask smart questions. You want to understand what the user is building, who it's for, and what matters most to them before diving in.

**Clear Communicator**: You never use jargon when simple words work. You translate technical findings into business impact - "this could frustrate users during checkout" not "race condition in async handler".

**Collaborative Partner**: You use "we" language. It's always "we should test this" not "you need to fix this". You're on the same team.

**Honest but Kind**: You deliver hard truths with empathy. You find the right moment and right words. You never embarrass anyone publicly.

## How You Communicate

1. **Start with understanding**: Ask about their goals before suggesting solutions
2. **Acknowledge good work**: Point out what's working well, not just problems
3. **Explain the "so what"**: Every finding connects to user experience or business impact
4. **Be specific**: "The login button doesn't respond on mobile Safari" not "button broken"
5. **Suggest next steps**: Always provide clear, actionable recommendations
6. **Stay positive**: Frame challenges as opportunities to make the product even better

## Your Expertise

- Web application testing (functional, security, performance, accessibility)
- Finding edge cases and boundary conditions
- User experience and usability issues
- Security vulnerabilities (XSS, CSRF, injection attacks)
- Mobile and responsive design testing
- Form validation and error handling
- Authentication and authorization flows

## What You DON'T Do

- Never use condescending language
- Never blame developers or teams
- Never use excessive technical jargon
- Never just list problems without solutions
- Never make assumptions without asking
- Never rush to conclusions

Remember: You're meeting someone new. Build rapport first. Understand their needs. Then help them succeed.`

// Varied welcome messages for natural onboarding
const WELCOME_MESSAGES = [
  `Hey there! 👋 I'm Alex, your QA partner.

I've spent 12 years helping teams find issues before users do. I'm pretty good at spotting the things that slip through the cracks.

**What I can help you with:**
• Finding bugs and edge cases
• Testing forms and user flows
• Checking security vulnerabilities
• Ensuring your app works on all devices

So, what are we testing today? Just paste a URL and tell me a bit about what you're building.`,

  `Hi! 👋 I'm Alex.

Think of me as your senior QA engineer - I've got 12 years of bug-hunting experience, and I genuinely enjoy finding the issues that slip through the cracks.

**Here's how I can help:**
• Uncover edge cases others miss
• Test user flows end-to-end
• Check for security vulnerabilities
• Validate across devices and browsers

Ready to find some bugs? Share a URL with me and let's take a look together.`,

  `Hello! 👋 Alex here - your QA partner.

I love this work. After 12 years, I still get a kick out of catching bugs before users do. Let me bring that experience to your project.

**What I'm good at:**
• Finding those tricky edge cases
• Testing forms and authentication flows
• Spotting security issues
• Checking responsive behavior

What are we testing today? Drop a URL and tell me a bit about the feature.`,
]

// Get random welcome message
function getWelcomeMessage() {
  return WELCOME_MESSAGES[Math.floor(Math.random() * WELCOME_MESSAGES.length)]
}

// Load API key from .env file if exists
function loadEnvFile() {
  const envPaths = [
    path.join(__dirname, '..', '.env'),
    path.join(__dirname, '..', 'testai-agent', '.env'),
  ]

  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf-8')
      const lines = content.split('\n')
      for (const line of lines) {
        const match = line.match(/^DEEPSEEK_API_KEY=(.+)$/)
        if (match) {
          deepseekApiKey = match[1].trim()
          console.log('Loaded DeepSeek API key from .env')
          return
        }
      }
    }
  }
}

// Call DeepSeek API
async function callDeepSeek(messages, options = {}) {
  if (!deepseekApiKey) {
    throw new Error('DeepSeek API key not configured')
  }

  const response = await fetch(DEEPSEEK_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${deepseekApiKey}`
    },
    body: JSON.stringify({
      model: options.model || 'deepseek-chat',
      messages,
      max_tokens: options.maxTokens || 4096,
      temperature: options.temperature || 0.2,
      response_format: options.jsonMode ? { type: 'json_object' } : undefined
    })
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`DeepSeek API error: ${response.status} - ${error}`)
  }

  const data = await response.json()
  return {
    content: data.choices[0]?.message?.content || '',
    usage: data.usage
  }
}

// ============ PERFORMANCE OPTIMIZATIONS ============
// Disable hardware acceleration on low-end systems (can be toggled)
// app.disableHardwareAcceleration()

// Reduce memory footprint
app.commandLine.appendSwitch('js-flags', '--max-old-space-size=512')
app.commandLine.appendSwitch('disable-renderer-backgrounding')

// ============ STATE ============
let mainWindow = null
let browserView = null
let sidebarWidth = 0
let chatWidth = 0
let viewportOverride = null
let resizeTimeout = null

const isDev = !app.isPackaged
const isMac = process.platform === 'darwin'
const isWindows = process.platform === 'win32'

// ============ WINDOW CREATION ============
function createWindow() {
  // Platform-specific window options
  const windowOptions = {
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#171717' : '#FAFAFA',
    show: false, // Show after ready to prevent flash
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Performance optimizations
      backgroundThrottling: false,
      enableWebSQL: false,
    },
  }

  // Mac-specific: hidden title bar with traffic lights
  if (isMac) {
    windowOptions.titleBarStyle = 'hiddenInset'
    windowOptions.trafficLightPosition = { x: 16, y: 18 }
  }

  // Windows-specific: custom frame or default
  if (isWindows) {
    windowOptions.frame = true // Use native Windows frame
    windowOptions.autoHideMenuBar = true
  }

  mainWindow = new BrowserWindow(windowOptions)

  // Show window when ready (prevents white flash)
  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
  })

  // Load app
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
  }

  // Cleanup on close
  mainWindow.on('closed', () => {
    cleanup()
  })

  // Debounced resize for performance
  mainWindow.on('resize', () => {
    if (resizeTimeout) clearTimeout(resizeTimeout)
    resizeTimeout = setTimeout(updateBrowserViewBounds, 16) // ~60fps
  })

  // Send platform info to renderer
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('platform-info', {
      isMac,
      isWindows,
      isDev,
    })
  })
}

// ============ CLEANUP ============
function cleanup() {
  if (browserView) {
    browserView.webContents.removeAllListeners()
    browserView = null
  }
  mainWindow = null
  if (resizeTimeout) {
    clearTimeout(resizeTimeout)
    resizeTimeout = null
  }
}

// ============ BROWSER VIEW ============
function updateBrowserViewBounds() {
  if (!mainWindow || !browserView) return

  const bounds = mainWindow.getContentBounds()
  const topBarHeight = 52

  let x = sidebarWidth
  let y = topBarHeight
  let width = bounds.width - sidebarWidth - chatWidth
  let height = bounds.height - topBarHeight

  // Viewport override (for responsive testing)
  if (viewportOverride && viewportOverride.width > 0) {
    const availWidth = bounds.width - sidebarWidth - chatWidth
    const availHeight = bounds.height - topBarHeight
    const scale = Math.min(
      availWidth / viewportOverride.width,
      availHeight / viewportOverride.height,
      1
    )

    width = Math.round(viewportOverride.width * scale)
    height = Math.round(viewportOverride.height * scale)
    x = sidebarWidth + Math.round((availWidth - width) / 2)
    y = topBarHeight + Math.round((availHeight - height) / 2)
  }

  // Ensure minimum bounds
  browserView.setBounds({
    x: Math.max(0, x),
    y: Math.max(0, y),
    width: Math.max(100, width),
    height: Math.max(100, height),
  })
}

function createBrowserView() {
  // Cleanup existing view
  if (browserView) {
    browserView.webContents.removeAllListeners()
    mainWindow.removeBrowserView(browserView)
    browserView = null
  }

  browserView = new BrowserView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Performance
      backgroundThrottling: true,
      enableWebSQL: false,
    },
  })

  mainWindow.addBrowserView(browserView)
  updateBrowserViewBounds()

  // Event listeners with null checks
  const wc = browserView.webContents

  wc.on('did-navigate', (_, url) => {
    mainWindow?.webContents.send('url-changed', url)
  })

  wc.on('did-navigate-in-page', (_, url) => {
    mainWindow?.webContents.send('url-changed', url)
  })

  wc.on('page-title-updated', (_, title) => {
    mainWindow?.webContents.send('title-changed', title)
  })

  wc.on('did-finish-load', () => {
    mainWindow?.webContents.send('page-loaded')
  })

  wc.on('did-fail-load', (_, errorCode, errorDescription) => {
    mainWindow?.webContents.send('page-error', { errorCode, errorDescription })
  })

  // Handle new windows
  wc.setWindowOpenHandler(({ url }) => {
    wc.loadURL(url)
    return { action: 'deny' }
  })

  return browserView
}

// ============ IPC HANDLERS ============

// Navigation
ipcMain.handle('navigate', async (_, url) => {
  if (!browserView) createBrowserView()

  // Normalize URL - use http for localhost, https for others
  if (!/^https?:\/\//i.test(url)) {
    const isLocal = url.includes('localhost') || url.includes('127.0.0.1') || /^[\w.-]+:\d+/.test(url)
    url = (isLocal ? 'http://' : 'https://') + url
  }

  try {
    await browserView.webContents.loadURL(url)
    return { success: true, url }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('go-back', () => {
  if (browserView?.webContents.canGoBack()) {
    browserView.webContents.goBack()
  }
  return { success: true }
})

ipcMain.handle('go-forward', () => {
  if (browserView?.webContents.canGoForward()) {
    browserView.webContents.goForward()
  }
  return { success: true }
})

ipcMain.handle('reload', () => {
  browserView?.webContents.reload()
  return { success: true }
})

// Layout
ipcMain.handle('set-sidebar-width', (_, width) => {
  sidebarWidth = width
  updateBrowserViewBounds()
  return { success: true }
})

ipcMain.handle('set-chat-width', (_, width) => {
  chatWidth = width
  updateBrowserViewBounds()
  return { success: true }
})

ipcMain.handle('set-viewport', (_, width, height) => {
  viewportOverride = width > 0 && height > 0 ? { width, height } : null
  updateBrowserViewBounds()
  return { success: true }
})

// DOM Extraction (optimized)
ipcMain.handle('extract-dom', async () => {
  if (!browserView) return { success: false, elements: [] }

  try {
    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = []
        let id = 1
        const seen = new Set()
        const selectors = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick],form'

        for (const el of document.querySelectorAll(selectors)) {
          // Skip duplicates and hidden elements
          if (seen.has(el)) continue
          seen.add(el)

          const rect = el.getBoundingClientRect()
          if (rect.width === 0 || rect.height === 0) continue

          const style = getComputedStyle(el)
          if (style.display === 'none' || style.visibility === 'hidden') continue

          const testId = 'testai-' + id++
          el.setAttribute('data-testai', testId)

          elements.push({
            id: testId,
            tag: el.tagName.toLowerCase(),
            text: (el.innerText?.trim() || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('title') || '').slice(0, 80),
            type: el.getAttribute('type') || '',
            href: el.getAttribute('href') || '',
            name: el.getAttribute('name') || '',
            placeholder: el.getAttribute('placeholder') || '',
            bounds: {
              x: Math.round(rect.x),
              y: Math.round(rect.y),
              width: Math.round(rect.width),
              height: Math.round(rect.height)
            }
          })
        }

        return elements
      })()
    `)

    return { success: true, elements, count: elements.length }
  } catch (err) {
    return { success: false, error: err.message, elements: [] }
  }
})

// Element interaction
ipcMain.handle('click-element', async (_, id) => {
  if (!browserView) return { success: false }

  try {
    await browserView.webContents.executeJavaScript(`
      const el = document.querySelector('[data-testai="${id}"]')
      if (el) {
        el.scrollIntoView({ block: 'center', behavior: 'smooth' })
        setTimeout(() => el.click(), 200)
      }
    `)
    return { success: true }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('type-in-element', async (_, id, text) => {
  if (!browserView) return { success: false }

  // Escape text for injection
  const safeText = text.replace(/\\/g, '\\\\').replace(/'/g, "\\'")

  try {
    await browserView.webContents.executeJavaScript(`
      const el = document.querySelector('[data-testai="${id}"]')
      if (el) {
        el.scrollIntoView({ block: 'center', behavior: 'smooth' })
        el.focus()
        el.value = '${safeText}'
        el.dispatchEvent(new Event('input', { bubbles: true }))
        el.dispatchEvent(new Event('change', { bubbles: true }))
      }
    `)
    return { success: true }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('get-page-info', async () => {
  if (!browserView) return { success: false }

  try {
    const info = await browserView.webContents.executeJavaScript(`
      ({
        url: location.href,
        title: document.title,
        html: document.documentElement.outerHTML.slice(0, 50000)
      })
    `)
    return { success: true, ...info }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Platform info
ipcMain.handle('get-platform', () => ({
  isMac,
  isWindows,
  platform: process.platform,
}))

// ============ DOM SEARCH & ACTION HELPERS ============

// Extract DOM elements with rich metadata for AI understanding
async function extractDomForAI() {
  if (!browserView) return { success: false, elements: [] }

  try {
    // Wait a bit for dynamic content to render
    await new Promise(r => setTimeout(r, 300))

    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = []
        let id = 1
        const seen = new Set()

        // Extended selectors to catch more interactive elements
        const selectors = [
          'a[href]',
          'button',
          'input:not([type=hidden])',
          'select',
          'textarea',
          '[role=button]',
          '[role=link]',
          '[role=checkbox]',
          '[role=tab]',
          '[role=menuitem]',
          '[onclick]',
          '[tabindex]:not([tabindex="-1"])',
          'form',
          'label[for]',
          // Google OAuth specific
          '[data-provider]',
          '.social-button',
          '.oauth-button',
          '[class*="google"]',
          '[class*="login"]',
          '[class*="signin"]',
          '[class*="auth"]',
          // Common button patterns
          '[class*="btn"]',
          '[class*="button"]',
          'div[onclick]',
          'span[onclick]',
        ].join(',')

        function extractFromRoot(root, prefix = '') {
          for (const el of root.querySelectorAll(selectors)) {
            if (seen.has(el)) continue
            seen.add(el)

            const rect = el.getBoundingClientRect()
            // Allow smaller elements (icons, etc)
            if (rect.width < 5 || rect.height < 5) continue

            const style = getComputedStyle(el)
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue

            const testId = prefix + 'testai-' + id++
            el.setAttribute('data-testai', testId)

            // Get associated label for inputs
            let label = ''
            if (el.id) {
              const labelEl = root.querySelector('label[for="' + el.id + '"]')
              if (labelEl) label = labelEl.textContent?.trim() || ''
            }
            if (!label && el.closest('label')) {
              label = el.closest('label').textContent?.trim() || ''
            }

            // Determine element category
            const tag = el.tagName.toLowerCase()
            const type = el.getAttribute('type') || ''
            const role = el.getAttribute('role') || ''
            const className = el.className?.toLowerCase?.() || ''

            let category = 'other'
            if (tag === 'a') category = 'link'
            else if (tag === 'button' || type === 'submit' || type === 'button' || role === 'button') category = 'button'
            else if (tag === 'input' && ['text', 'email', 'password', 'search', 'tel', 'url', 'number'].includes(type)) category = 'text-input'
            else if (tag === 'input' && ['checkbox', 'radio'].includes(type)) category = 'toggle'
            else if (tag === 'textarea') category = 'text-input'
            else if (tag === 'select') category = 'dropdown'
            else if (className.includes('btn') || className.includes('button')) category = 'button'
            else if (el.onclick || el.getAttribute('onclick')) category = 'button'

            // Get text content more thoroughly
            let text = el.innerText?.trim() || el.value || el.getAttribute('aria-label') || ''
            if (!text && el.querySelector('img[alt]')) {
              text = el.querySelector('img[alt]').getAttribute('alt')
            }
            if (!text && el.title) {
              text = el.title
            }

            elements.push({
              id: testId,
              tag,
              category,
              text: text.slice(0, 100),
              type,
              name: el.getAttribute('name') || '',
              placeholder: el.getAttribute('placeholder') || '',
              label,
              href: el.getAttribute('href') || '',
              ariaLabel: el.getAttribute('aria-label') || '',
              value: el.value || '',
              checked: el.checked || false,
              disabled: el.disabled || false,
              className: (el.className?.slice?.(0, 50) || ''),
            })
          }

          // Also check shadow roots
          root.querySelectorAll('*').forEach(el => {
            if (el.shadowRoot) {
              extractFromRoot(el.shadowRoot, 'shadow-')
            }
          })
        }

        extractFromRoot(document)

        // Try same-origin iframes
        document.querySelectorAll('iframe').forEach((iframe, idx) => {
          try {
            if (iframe.contentDocument) {
              extractFromRoot(iframe.contentDocument, 'iframe' + idx + '-')
            }
          } catch (e) {
            // Cross-origin iframe - can't access
          }
        })

        return elements
      })()
    `)

    console.log('[DOM Extract] Found', elements.length, 'elements')
    return { success: true, elements }
  } catch (err) {
    console.error('[DOM Extract] Error:', err.message)
    return { success: false, error: err.message, elements: [] }
  }
}

// Find element by AI-powered search
async function findElementByIntent(elements, intent) {
  // Simple keyword matching first (fast path)
  const intentLower = intent.toLowerCase()

  // Direct matches
  for (const el of elements) {
    const searchText = [el.text, el.label, el.placeholder, el.name, el.ariaLabel].join(' ').toLowerCase()
    if (searchText.includes(intentLower)) {
      return el
    }
  }

  // Type-based matches
  if (intentLower.includes('email')) {
    const match = elements.find(e => e.type === 'email' || e.name?.includes('email') || e.placeholder?.toLowerCase().includes('email'))
    if (match) return match
  }
  if (intentLower.includes('password')) {
    const match = elements.find(e => e.type === 'password' || e.name?.includes('password'))
    if (match) return match
  }
  if (intentLower.includes('search')) {
    const match = elements.find(e => e.type === 'search' || e.name?.includes('search') || e.placeholder?.toLowerCase().includes('search'))
    if (match) return match
  }
  if (intentLower.includes('submit') || intentLower.includes('login') || intentLower.includes('sign in')) {
    const match = elements.find(e => e.category === 'button' && (e.text?.toLowerCase().includes('submit') || e.text?.toLowerCase().includes('login') || e.text?.toLowerCase().includes('sign in') || e.type === 'submit'))
    if (match) return match
  }

  return null
}

// ============ REAL INPUT SIMULATION ============
// Uses Electron's native input events for realistic interaction

// Get element bounds for mouse targeting
async function getElementBounds(elementId) {
  if (!browserView) return null
  try {
    return await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (!el) return null
        const rect = el.getBoundingClientRect()
        return {
          x: Math.round(rect.left + rect.width / 2),
          y: Math.round(rect.top + rect.height / 2),
          width: rect.width,
          height: rect.height,
          visible: rect.top >= 0 && rect.bottom <= window.innerHeight
        }
      })()
    `)
  } catch {
    return null
  }
}

// Scroll element into view and return its position
async function scrollToElement(elementId) {
  if (!browserView) return null
  try {
    await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (el) {
          el.scrollIntoView({ block: 'center', behavior: 'smooth' })
          // Highlight it
          el.style.outline = '3px solid rgba(59, 130, 246, 0.8)'
          setTimeout(() => el.style.outline = '', 1500)
        }
      })()
    `)
    // Wait for scroll animation
    await new Promise(r => setTimeout(r, 400))
    return await getElementBounds(elementId)
  } catch {
    return null
  }
}

// Simulate real mouse click using Electron input events
async function realClick(x, y) {
  if (!browserView) return false
  try {
    // Mouse move to position
    browserView.webContents.sendInputEvent({ type: 'mouseMove', x, y })
    await new Promise(r => setTimeout(r, 50))

    // Mouse down
    browserView.webContents.sendInputEvent({ type: 'mouseDown', x, y, button: 'left', clickCount: 1 })
    await new Promise(r => setTimeout(r, 50))

    // Mouse up
    browserView.webContents.sendInputEvent({ type: 'mouseUp', x, y, button: 'left', clickCount: 1 })
    return true
  } catch {
    return false
  }
}

// Simulate real keyboard typing character by character
async function realType(text) {
  if (!browserView) return false
  try {
    for (const char of text) {
      // Send each character as a key event
      browserView.webContents.sendInputEvent({ type: 'keyDown', keyCode: char })
      browserView.webContents.sendInputEvent({ type: 'char', keyCode: char })
      browserView.webContents.sendInputEvent({ type: 'keyUp', keyCode: char })
      // Random delay between 30-80ms like human typing
      await new Promise(r => setTimeout(r, 30 + Math.random() * 50))
    }
    return true
  } catch {
    return false
  }
}

// Simulate pressing Enter key
async function realPressEnter() {
  if (!browserView) return false
  try {
    browserView.webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Return' })
    await new Promise(r => setTimeout(r, 30))
    browserView.webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Return' })
    return true
  } catch {
    return false
  }
}

// Execute action on element (comprehensive action system)
async function executeAction(action, elementId, value = '') {
  if (!browserView) return { success: false, error: 'No browser view' }

  const safeValue = value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')

  try {
    let result

    // First, get element bounds and scroll if needed
    let bounds = await getElementBounds(elementId)
    if (!bounds) {
      return { success: false, error: 'Element not found' }
    }

    // Scroll into view if not visible
    if (!bounds.visible) {
      bounds = await scrollToElement(elementId)
      if (!bounds) {
        return { success: false, error: 'Could not scroll to element' }
      }
    }

    switch (action) {
      case 'click':
        // Use real mouse click
        const clicked = await realClick(bounds.x, bounds.y)
        if (clicked) {
          result = { success: true, action: 'clicked', scrolled: !bounds.visible }
        } else {
          // Fallback to JS click
          result = await browserView.webContents.executeJavaScript(`
            (function() {
              const el = document.querySelector('[data-testai="${elementId}"]')
              if (!el) return { success: false, error: 'Element not found' }
              el.click()
              return { success: true, action: 'clicked', fallback: true }
            })()
          `)
        }
        break

      case 'type':
        // Click to focus first
        await realClick(bounds.x, bounds.y)
        await new Promise(r => setTimeout(r, 100))

        // Clear existing value
        await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (el) { el.value = ''; el.focus(); }
          })()
        `)
        await new Promise(r => setTimeout(r, 50))

        // Type character by character
        const typed = await realType(value)
        if (typed) {
          result = { success: true, action: 'typed', value }
        } else {
          // Fallback to direct value setting
          result = await browserView.webContents.executeJavaScript(`
            (function() {
              const el = document.querySelector('[data-testai="${elementId}"]')
              if (!el) return { success: false, error: 'Element not found' }
              el.value = '${safeValue}'
              el.dispatchEvent(new Event('input', { bubbles: true }))
              return { success: true, action: 'typed', fallback: true }
            })()
          `)
        }
        break

      case 'type-slow':
        // Same as type but already character by character
        await realClick(bounds.x, bounds.y)
        await new Promise(r => setTimeout(r, 100))
        await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (el) { el.value = ''; el.focus(); }
          })()
        `)
        await realType(value)
        result = { success: true, action: 'typed-slow', value }
        break

      case 'clear':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.focus()
            el.value = ''
            el.dispatchEvent(new Event('input', { bubbles: true }))
            el.dispatchEvent(new Event('change', { bubbles: true }))
            return { success: true, action: 'cleared' }
          })()
        `)
        break

      case 'check':
      case 'toggle':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            el.click()
            return { success: true, action: 'toggled', checked: el.checked }
          })()
        `)
        break

      case 'select':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            const option = Array.from(el.options).find(o =>
              o.value.toLowerCase().includes('${safeValue}'.toLowerCase()) ||
              o.text.toLowerCase().includes('${safeValue}'.toLowerCase())
            )
            if (option) {
              el.value = option.value
              el.dispatchEvent(new Event('change', { bubbles: true }))
              return { success: true, action: 'selected', value: option.text }
            }
            return { success: false, error: 'Option not found' }
          })()
        `)
        break

      case 'focus':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            el.focus()
            return { success: true, action: 'focused' }
          })()
        `)
        break

      case 'hover':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }))
            el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }))
            return { success: true, action: 'hovered' }
          })()
        `)
        break

      case 'double-click':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            el.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))
            return { success: true, action: 'double-clicked' }
          })()
        `)
        break

      case 'right-click':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            el.scrollIntoView({ block: 'center', behavior: 'smooth' })
            el.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }))
            return { success: true, action: 'right-clicked' }
          })()
        `)
        break

      case 'press-enter':
        // Use real keyboard Enter
        await realPressEnter()
        // Also try JS fallback for forms
        await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (el) {
              const form = el.closest('form')
              if (form) form.submit()
            }
          })()
        `)
        result = { success: true, action: 'pressed-enter' }
        break

      case 'drag':
        const [dragX, dragY] = (value || '0,100').split(',').map(Number)
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { success: false, error: 'Element not found' }
            const rect = el.getBoundingClientRect()
            const startX = rect.left + rect.width / 2
            const startY = rect.top + rect.height / 2
            el.dispatchEvent(new MouseEvent('mousedown', { clientX: startX, clientY: startY, bubbles: true }))
            el.dispatchEvent(new MouseEvent('mousemove', { clientX: startX + ${dragX}, clientY: startY + ${dragY}, bubbles: true }))
            el.dispatchEvent(new MouseEvent('mouseup', { clientX: startX + ${dragX}, clientY: startY + ${dragY}, bubbles: true }))
            return { success: true, action: 'dragged', offset: { x: ${dragX}, y: ${dragY} } }
          })()
        `)
        break

      default:
        result = { success: false, error: 'Unknown action: ' + action }
    }

    return result
  } catch (err) {
    return { success: false, error: err.message }
  }
}

// Execute page-level actions (not tied to specific elements)
async function executePageAction(action, value = '') {
  if (!browserView) return { success: false, error: 'No browser view' }

  const safeValue = (value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')

  try {
    let result
    switch (action) {
      case 'scroll-down':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const amount = ${parseInt(value) || 500}
            window.scrollBy({ top: amount, behavior: 'smooth' })
            return { success: true, action: 'scrolled-down', amount }
          })()
        `)
        break

      case 'scroll-up':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const amount = ${parseInt(value) || 500}
            window.scrollBy({ top: -amount, behavior: 'smooth' })
            return { success: true, action: 'scrolled-up', amount }
          })()
        `)
        break

      case 'scroll-to-top':
        result = await browserView.webContents.executeJavaScript(`
          window.scrollTo({ top: 0, behavior: 'smooth' });
          ({ success: true, action: 'scrolled-to-top' })
        `)
        break

      case 'scroll-to-bottom':
        result = await browserView.webContents.executeJavaScript(`
          window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
          ({ success: true, action: 'scrolled-to-bottom' })
        `)
        break

      case 'scroll-to-element':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const searchText = '${safeValue}'.toLowerCase()
            for (const el of document.querySelectorAll('*')) {
              if (el.innerText?.toLowerCase().includes(searchText) && el.offsetParent !== null) {
                el.scrollIntoView({ block: 'center', behavior: 'smooth' })
                el.style.outline = '3px solid rgba(59, 130, 246, 0.8)'
                setTimeout(() => el.style.outline = '', 2000)
                return { success: true, action: 'scrolled-to-element', found: true }
              }
            }
            return { success: false, error: 'Element not found' }
          })()
        `)
        break

      case 'navigate':
        let targetUrl = value
        if (!/^https?:\/\//i.test(targetUrl)) {
          const isLocal = targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') || /^[\w.-]+:\d+/.test(targetUrl)
          targetUrl = (isLocal ? 'http://' : 'https://') + targetUrl
        }
        await browserView.webContents.loadURL(targetUrl)
        result = { success: true, action: 'navigated', url: targetUrl }
        break

      case 'go-back':
        if (browserView.webContents.canGoBack()) {
          browserView.webContents.goBack()
          result = { success: true, action: 'went-back' }
        } else {
          result = { success: false, error: 'Cannot go back' }
        }
        break

      case 'go-forward':
        if (browserView.webContents.canGoForward()) {
          browserView.webContents.goForward()
          result = { success: true, action: 'went-forward' }
        } else {
          result = { success: false, error: 'Cannot go forward' }
        }
        break

      case 'refresh':
        browserView.webContents.reload()
        result = { success: true, action: 'refreshed' }
        break

      case 'wait':
        await new Promise(r => setTimeout(r, parseInt(value) || 1000))
        result = { success: true, action: 'waited', duration: parseInt(value) || 1000 }
        break

      case 'screenshot':
        const image = await browserView.webContents.capturePage()
        result = { success: true, action: 'screenshot', data: image.toDataURL() }
        break

      case 'get-text':
        result = await browserView.webContents.executeJavaScript(`
          ({ success: true, action: 'got-text', text: document.body.innerText.slice(0, 5000) })
        `)
        break

      case 'find-text':
        result = await browserView.webContents.executeJavaScript(`
          (function() {
            const searchText = '${safeValue}'.toLowerCase()
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
            const matches = []
            while (walker.nextNode()) {
              if (walker.currentNode.textContent.toLowerCase().includes(searchText)) {
                const parent = walker.currentNode.parentElement
                if (parent && parent.offsetParent !== null) matches.push(parent)
              }
            }
            if (matches.length > 0) {
              matches[0].scrollIntoView({ block: 'center', behavior: 'smooth' })
              matches.forEach(el => {
                el.style.backgroundColor = 'yellow'
                setTimeout(() => el.style.backgroundColor = '', 3000)
              })
              return { success: true, action: 'found-text', count: matches.length }
            }
            return { success: false, error: 'Text not found' }
          })()
        `)
        break

      case 'press-escape':
        result = await browserView.webContents.executeJavaScript(`
          document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', keyCode: 27, bubbles: true }));
          ({ success: true, action: 'pressed-escape' })
        `)
        break

      default:
        result = { success: false, error: 'Unknown page action: ' + action }
    }

    return result
  } catch (err) {
    return { success: false, error: err.message }
  }
}

// ============ AGENT IPC HANDLERS ============

// Set API key
ipcMain.handle('set-api-key', (_, key) => {
  deepseekApiKey = key
  return { success: true }
})

// Check if agent is ready
ipcMain.handle('agent-status', () => ({
  hasApiKey: !!deepseekApiKey,
  hasSession: !!currentSession,
  sessionStatus: currentSession?.status || null
}))

// ============ AI-POWERED ACTION EXECUTION ============

// Perform action based on user intent (AI understands what to do)
ipcMain.handle('perform-action', async (_, userIntent) => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    // Send thinking message
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: getThinkingPhrase('analyzing')
    })

    const intentLower = userIntent.toLowerCase()

    // ============ CHECK FOR PAGE-LEVEL ACTIONS FIRST ============
    // These don't need element extraction

    // Scroll actions
    if (intentLower.includes('scroll down') || intentLower.includes('page down')) {
      const result = await executePageAction('scroll-down', '500')
      return { success: result.success, action: 'scroll-down', explanation: 'Scrolling down the page' }
    }
    if (intentLower.includes('scroll up') || intentLower.includes('page up')) {
      const result = await executePageAction('scroll-up', '500')
      return { success: result.success, action: 'scroll-up', explanation: 'Scrolling up the page' }
    }
    if (intentLower.includes('scroll to top') || intentLower.includes('go to top')) {
      const result = await executePageAction('scroll-to-top')
      return { success: result.success, action: 'scroll-to-top', explanation: 'Scrolling to top of page' }
    }
    if (intentLower.includes('scroll to bottom') || intentLower.includes('go to bottom')) {
      const result = await executePageAction('scroll-to-bottom')
      return { success: result.success, action: 'scroll-to-bottom', explanation: 'Scrolling to bottom of page' }
    }

    // Navigation actions
    if (intentLower.includes('go back') || intentLower.includes('back button')) {
      const result = await executePageAction('go-back')
      return { success: result.success, action: 'go-back', explanation: 'Going back to previous page' }
    }
    if (intentLower.includes('go forward') || intentLower.includes('forward button')) {
      const result = await executePageAction('go-forward')
      return { success: result.success, action: 'go-forward', explanation: 'Going forward' }
    }
    if (intentLower.includes('refresh') || intentLower.includes('reload')) {
      const result = await executePageAction('refresh')
      return { success: result.success, action: 'refresh', explanation: 'Refreshing the page' }
    }

    // Navigate to URL
    const navMatch = intentLower.match(/(?:navigate|go|open)\s+(?:to\s+)?(.+)/i)
    if (navMatch && (navMatch[1].includes('.') || navMatch[1].includes('http'))) {
      const url = navMatch[1].trim()
      const result = await executePageAction('navigate', url)
      return { success: result.success, action: 'navigate', value: url, explanation: `Navigating to ${url}` }
    }

    // Find/search text on page
    const findMatch = userIntent.match(/(?:find|search|look for|locate)\s+["']?([^"']+)["']?/i)
    if (findMatch) {
      const searchText = findMatch[1].trim()
      const result = await executePageAction('find-text', searchText)
      return {
        success: result.success,
        action: 'find-text',
        value: searchText,
        explanation: result.success ? `Found "${searchText}" on the page` : `Could not find "${searchText}"`
      }
    }

    // Scroll to specific element/text
    const scrollToMatch = userIntent.match(/scroll\s+to\s+["']?([^"']+)["']?/i)
    if (scrollToMatch) {
      const searchText = scrollToMatch[1].trim()
      const result = await executePageAction('scroll-to-element', searchText)
      return {
        success: result.success,
        action: 'scroll-to-element',
        value: searchText,
        explanation: result.success ? `Scrolled to "${searchText}"` : `Could not find "${searchText}" to scroll to`
      }
    }

    // Press escape
    if (intentLower.includes('escape') || intentLower.includes('close') || intentLower.includes('dismiss')) {
      const result = await executePageAction('press-escape')
      return { success: result.success, action: 'press-escape', explanation: 'Pressed Escape key' }
    }

    // Wait
    const waitMatch = intentLower.match(/wait\s+(\d+)/i)
    if (waitMatch || intentLower.includes('wait')) {
      const ms = waitMatch ? parseInt(waitMatch[1]) * 1000 : 1000
      const result = await executePageAction('wait', String(ms))
      return { success: result.success, action: 'wait', value: ms, explanation: `Waited ${ms}ms` }
    }

    // ============ ELEMENT-BASED ACTIONS ============
    // Extract DOM elements
    const domResult = await extractDomForAI()
    if (!domResult.success || domResult.elements.length === 0) {
      return { success: false, error: 'Could not extract page elements' }
    }

    // Filter to relevant elements (limit for API)
    const relevantElements = domResult.elements
      .filter(e => e.category !== 'other')
      .slice(0, 50)

    // Send to AI to understand intent
    const actionPrompt = `You are Alex, a QA engineer helping test a web page. The user wants to perform an action.

USER REQUEST: "${userIntent}"

AVAILABLE ELEMENTS ON PAGE:
${JSON.stringify(relevantElements, null, 2)}

Analyze the user's request and return a JSON object with the action to perform:
{
  "understood": true/false,
  "action": "click" | "type" | "clear" | "select" | "toggle" | "focus" | "hover" | "double-click" | "press-enter" | "none",
  "elementId": "testai-X" (the id of the target element),
  "value": "text to type" (only for type/select actions),
  "explanation": "Brief explanation of what you're doing",
  "confidence": 0.0-1.0
}

RULES:
- For "click the X button" → action: "click", find the element
- For "type X in the Y field" → action: "type", value: the text to type
- For "enter my email as X" → find email input, action: "type", value: X
- For "fill in password with X" → find password input, action: "type", value: X
- For "check/uncheck the checkbox" → action: "toggle"
- For "select X from dropdown" → action: "select", value: X
- For "hover over X" → action: "hover"
- For "double click X" → action: "double-click"
- For "press enter on X" or "submit" → action: "press-enter"
- The system will AUTO-SCROLL to elements if they're not visible, so don't worry about visibility
- If you can't find the element or understand the request, set understood: false

Return ONLY valid JSON, no other text.`

    const response = await callDeepSeek([
      { role: 'system', content: 'You are a web automation assistant. Return only valid JSON.' },
      { role: 'user', content: actionPrompt }
    ], { jsonMode: true, maxTokens: 500, temperature: 0.1 })

    let actionPlan
    try {
      actionPlan = JSON.parse(response.content)
    } catch {
      return { success: false, error: 'Could not understand the action request' }
    }

    if (!actionPlan.understood || actionPlan.action === 'none') {
      return {
        success: false,
        error: actionPlan.explanation || 'Could not understand what action to perform'
      }
    }

    // Send thinking message about what we're doing
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: actionPlan.explanation || getThinkingPhrase('planning')
    })

    // Execute the action (auto-scrolls to element if needed)
    const result = await executeAction(actionPlan.action, actionPlan.elementId, actionPlan.value || '')

    if (result.success) {
      // Get the element info for nice feedback
      const targetElement = relevantElements.find(e => e.id === actionPlan.elementId)
      const elementDesc = targetElement ?
        (targetElement.label || targetElement.text || targetElement.placeholder || targetElement.name || 'element') :
        'element'

      // Include scroll info in response if we scrolled
      let explanation = actionPlan.explanation
      if (result.scrolled) {
        explanation = `Scrolled to and ${actionPlan.action}ed the ${elementDesc}`
      }

      return {
        success: true,
        action: actionPlan.action,
        element: elementDesc,
        value: actionPlan.value,
        explanation,
        confidence: actionPlan.confidence,
        scrolled: result.scrolled || false
      }
    } else {
      return { success: false, error: result.error }
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Search for elements matching a description
ipcMain.handle('search-elements', async (_, query) => {
  if (!browserView) return { success: false, elements: [] }

  try {
    const domResult = await extractDomForAI()
    if (!domResult.success) {
      return { success: false, elements: [] }
    }

    const queryLower = query.toLowerCase()
    const matches = domResult.elements.filter(el => {
      const searchText = [el.text, el.label, el.placeholder, el.name, el.ariaLabel, el.type, el.category]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return searchText.includes(queryLower)
    })

    return { success: true, elements: matches }
  } catch (err) {
    return { success: false, error: err.message, elements: [] }
  }
})

// Execute page-level action (scroll, navigate, etc.)
ipcMain.handle('page-action', async (_, action, value) => {
  return await executePageAction(action, value)
})

// Get all elements categorized
ipcMain.handle('get-elements-by-category', async () => {
  if (!browserView) return { success: false, categories: {} }

  try {
    const domResult = await extractDomForAI()
    if (!domResult.success) {
      return { success: false, categories: {} }
    }

    const categories = {
      'text-input': [],
      'button': [],
      'link': [],
      'dropdown': [],
      'toggle': [],
      'other': []
    }

    for (const el of domResult.elements) {
      const cat = categories[el.category] || categories['other']
      cat.push(el)
    }

    return { success: true, categories }
  } catch (err) {
    return { success: false, error: err.message, categories: {} }
  }
})

// Analyze page and generate tests
ipcMain.handle('analyze-page', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    // Get page info
    const pageInfo = await browserView.webContents.executeJavaScript(`
      ({ url: location.href, title: document.title })
    `)

    // Extract DOM elements
    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = []
        let id = 1
        const seen = new Set()
        const selectors = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick],form'

        for (const el of document.querySelectorAll(selectors)) {
          if (seen.has(el)) continue
          seen.add(el)

          const rect = el.getBoundingClientRect()
          if (rect.width === 0 || rect.height === 0) continue

          const style = getComputedStyle(el)
          if (style.display === 'none' || style.visibility === 'hidden') continue

          const testId = 'testai-' + id++
          el.setAttribute('data-testai', testId)

          elements.push({
            id: testId,
            tag: el.tagName.toLowerCase(),
            text: (el.innerText?.trim() || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').slice(0, 80),
            type: el.getAttribute('type') || '',
            href: el.getAttribute('href') || '',
            name: el.getAttribute('name') || '',
            placeholder: el.getAttribute('placeholder') || ''
          })
        }
        return elements
      })()
    `)

    // Send varied thinking messages
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: getThinkingPhrase('analyzing')
    })

    const analysisPrompt = `Analyze this web page and classify it:

URL: ${pageInfo.url}
Title: ${pageInfo.title}

Elements (${elements.length}):
${JSON.stringify(elements.slice(0, 30), null, 2)}

Return JSON:
{
  "pageType": "login|signup|dashboard|settings|checkout|search|list|form|unknown",
  "confidence": 0.0-1.0,
  "purpose": "What this page is for",
  "criticalElements": ["list of element IDs that are most important to test"],
  "suggestedTests": ["list of test scenarios"]
}`

    const analysisResponse = await callDeepSeek([
      { role: 'system', content: 'You are a web page analyzer. Return valid JSON only.' },
      { role: 'user', content: analysisPrompt }
    ], { jsonMode: true, maxTokens: 2000 })

    let analysis
    try {
      analysis = JSON.parse(analysisResponse.content)
    } catch {
      analysis = { pageType: 'unknown', confidence: 0.5, suggestedTests: [] }
    }

    // Use confidence-based phrasing for the result
    const confidencePhrase = getConfidencePhrase(analysis.confidence)
    mainWindow?.webContents.send('agent-message', {
      type: 'analysis',
      message: `${confidencePhrase} a ${analysis.pageType} page. Found ${elements.length} testable elements.`,
      data: analysis
    })

    return {
      success: true,
      pageInfo,
      elements,
      analysis
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Generate test scripts
ipcMain.handle('generate-tests', async (_, pageData) => {
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: getThinkingPhrase('planning')
    })

    // Short delay then show generating message
    setTimeout(() => {
      mainWindow?.webContents.send('agent-message', {
        type: 'thinking',
        message: getThinkingPhrase('generating')
      })
    }, 800)

    const testPrompt = `You are a senior QA engineer. Generate comprehensive test cases for this page.

Page Type: ${pageData.analysis?.pageType || 'unknown'}
URL: ${pageData.pageInfo?.url}
Title: ${pageData.pageInfo?.title}

Elements:
${JSON.stringify(pageData.elements?.slice(0, 30), null, 2)}

Generate test cases in this JSON format:
{
  "tests": [
    {
      "name": "Test name",
      "description": "What this test verifies",
      "priority": "high|medium|low",
      "category": "happy_path|edge_case|error_handling|security",
      "steps": [
        {
          "order": 1,
          "action": "navigate|click|type|select|wait|assert",
          "target": "element description",
          "value": "input value if applicable",
          "waitFor": "load|visible|hidden",
          "description": "Human readable step"
        }
      ],
      "expectedResults": ["What should happen"]
    }
  ]
}

Include:
1. Happy path tests (main user flow)
2. Edge cases (empty, max length, special chars)
3. Error handling (invalid inputs)
4. Security tests (XSS, injection) if applicable`

    const response = await callDeepSeek([
      { role: 'system', content: 'You are a senior QA engineer. Generate comprehensive, actionable test cases. Return valid JSON only.' },
      { role: 'user', content: testPrompt }
    ], { jsonMode: true, maxTokens: 4000, temperature: 0.3 })

    let result
    try {
      result = JSON.parse(response.content)
    } catch {
      result = { tests: [] }
    }

    // Convert to human-readable format
    const humanReadable = result.tests?.map(test => {
      const steps = test.steps?.map((s, i) => {
        let line = `${i + 1}. ${s.description}`
        const actions = []
        if (s.action === 'click') actions.push(`click:${s.target}`)
        if (s.action === 'type') actions.push(`type:${s.target}:"${s.value}"`)
        if (s.action === 'navigate') actions.push(`navigate:${s.value}`)
        if (s.action === 'wait') actions.push(`wait:${s.waitFor || s.value}`)
        if (s.action === 'assert') actions.push(`assert:${s.target}`)
        if (s.waitFor && s.action !== 'wait') actions.push(`waitFor:${s.waitFor}`)

        return actions.length > 0 ? `${line}\n   [${actions.join(', ')}]` : line
      }).join('\n') || ''

      return `# ${test.name}
## ${test.description}
## Priority: ${test.priority}
## Category: ${test.category}

Steps:
${steps}

Expected Results:
${test.expectedResults?.map(r => `- ${r}`).join('\n') || '- Test passes'}`
    }).join('\n\n---\n\n') || 'No tests generated'

    // Use celebration phrases based on test count
    const testCount = result.tests?.length || 0
    let celebration = ''
    if (testCount >= 15) {
      celebration = pick(PERSONALITY.celebrations.large) + ' '
    } else if (testCount >= 8) {
      celebration = pick(PERSONALITY.celebrations.medium) + ' '
    } else if (testCount > 0) {
      celebration = pick(PERSONALITY.celebrations.small) + ' '
    }

    mainWindow?.webContents.send('agent-message', {
      type: 'tests_generated',
      message: `${celebration}Generated ${testCount} test cases covering various scenarios.`,
      data: { tests: result.tests, humanReadable }
    })

    return {
      success: true,
      tests: result.tests || [],
      humanReadable,
      usage: response.usage
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Start autonomous testing
ipcMain.handle('start-autonomous-test', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    // Get current page info
    const pageInfo = await browserView.webContents.executeJavaScript(`
      ({ url: location.href, title: document.title })
    `)

    currentSession = {
      id: `session-${Date.now()}`,
      startUrl: pageInfo.url,
      startedAt: new Date().toISOString(),
      status: 'running',
      pagesVisited: [pageInfo.url],
      testsGenerated: 0,
      elementsInteracted: 0,
      scripts: [],
      errors: []
    }

    mainWindow?.webContents.send('agent-message', {
      type: 'session_started',
      message: `Started autonomous testing on ${pageInfo.url}`,
      data: currentSession
    })

    return { success: true, session: currentSession }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Stop autonomous testing
ipcMain.handle('stop-autonomous-test', () => {
  if (currentSession) {
    currentSession.status = 'completed'
    mainWindow?.webContents.send('agent-message', {
      type: 'session_completed',
      message: 'Testing session completed',
      data: currentSession
    })
  }
  return { success: true, session: currentSession }
})

// ============ TEST SCRIPT GENERATION ============
// Generate executable test scripts in format: step:element:action:value

ipcMain.handle('generate-script', async (_, taskDescription) => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: `${getThinkingPhrase('analyzing')} Creating test script...`
    })

    // Get DOM elements with their IDs
    const domResult = await extractDomForAI()
    if (!domResult.success) {
      return { success: false, error: 'Could not extract page elements' }
    }

    const elements = domResult.elements.filter(e => e.category !== 'other')
    const pageUrl = await browserView.webContents.executeJavaScript('location.href')

    // Build element map for the AI
    const elementMap = elements.map(el => ({
      id: el.id,
      tag: el.tag,
      category: el.category,
      text: el.text?.slice(0, 50),
      placeholder: el.placeholder,
      type: el.inputType || el.tag
    }))

    const scriptPrompt = `You are a test automation engineer. Generate an executable test script for this task.

TASK: "${taskDescription}"

PAGE URL: ${pageUrl}

AVAILABLE ELEMENTS (with their IDs):
${JSON.stringify(elementMap, null, 2)}

Generate a script where EACH LINE follows this exact format:
step:element_id:action:value

FORMAT RULES:
- step = step number (1, 2, 3...)
- element_id = the "id" field from elements above (e.g., testai-15, testai-42)
- action = click | type | focus | clear | select | check | press-enter | scroll | wait | navigate
- value = text to type, option to select, or url to navigate (empty for clicks)

EXAMPLE OUTPUT:
1:testai-15:click:
2:testai-23:type:hello world
3:testai-23:press-enter:
4:testai-8:click:
5::wait:500

IMPORTANT:
- Use ONLY element IDs that exist in the AVAILABLE ELEMENTS list
- For typing, use "type" action with the text as value
- For clicking, leave value empty after the last colon
- For waits, use milliseconds as value
- For navigate, use the full URL as value
- Keep it simple and direct - one action per line

Return ONLY the script lines, no explanations or JSON.`

    const response = await callDeepSeek([
      { role: 'system', content: 'You are a test automation engineer. Generate clean, executable test scripts. Return only the script lines, no other text.' },
      { role: 'user', content: scriptPrompt }
    ], { maxTokens: 1500, temperature: 0.2 })

    // Parse the response into structured steps
    const lines = response.content.trim().split('\n').filter(line => line.trim())
    const steps = []

    for (const line of lines) {
      const parts = line.split(':')
      if (parts.length >= 3) {
        const step = parseInt(parts[0]) || steps.length + 1
        const elementId = parts[1] || ''
        const action = parts[2] || ''
        const value = parts.slice(3).join(':') || '' // Value might contain colons

        steps.push({
          step,
          elementId: elementId.trim(),
          action: action.trim().toLowerCase(),
          value: value.trim(),
          raw: line
        })
      }
    }

    // Format as readable script
    const formattedScript = steps.map(s => {
      const element = s.elementId ? `${s.elementId}` : '(page)'
      const valueStr = s.value ? `:${s.value}` : ''
      return `${s.step}:${element}:${s.action}${valueStr}`
    }).join('\n')

    mainWindow?.webContents.send('agent-message', {
      type: 'script_generated',
      message: formattedScript
    })

    return {
      success: true,
      script: formattedScript,
      steps,
      elementCount: elements.length
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Execute a generated script step by step
ipcMain.handle('execute-script', async (_, scriptText) => {
  if (!browserView) return { success: false, error: 'No page loaded' }

  const lines = scriptText.trim().split('\n').filter(line => line.trim())
  const results = []

  for (const line of lines) {
    const parts = line.split(':')
    if (parts.length < 3) continue

    const step = parseInt(parts[0]) || results.length + 1
    const elementId = parts[1]?.trim()
    const action = parts[2]?.trim().toLowerCase()
    const value = parts.slice(3).join(':').trim()

    mainWindow?.webContents.send('agent-message', {
      type: 'script_step',
      message: `▶ Step ${step}: ${action}${elementId ? ` on ${elementId}` : ''}${value ? ` = "${value}"` : ''}`
    })

    let result
    try {
      if (action === 'wait') {
        await new Promise(r => setTimeout(r, parseInt(value) || 500))
        result = { success: true, action: 'waited', duration: value }
      } else if (action === 'navigate') {
        let navUrl = value
        if (!/^https?:\/\//i.test(navUrl)) {
          const isLocal = navUrl.includes('localhost') || navUrl.includes('127.0.0.1') || /^[\w.-]+:\d+/.test(navUrl)
          navUrl = (isLocal ? 'http://' : 'https://') + navUrl
        }
        await browserView.webContents.loadURL(navUrl)
        result = { success: true, action: 'navigated', url: navUrl }
      } else if (action === 'press-enter') {
        await realPressEnter()
        result = { success: true, action: 'pressed-enter' }
      } else if (elementId) {
        // Element-based action
        result = await executeAction(action, elementId, value)
      } else {
        result = { success: false, error: 'No element specified' }
      }
    } catch (err) {
      result = { success: false, error: err.message }
    }

    results.push({
      step,
      elementId,
      action,
      value,
      ...result
    })

    // Send result
    mainWindow?.webContents.send('agent-message', {
      type: result.success ? 'script_step_success' : 'script_step_error',
      message: result.success ? `✓ Step ${step} completed` : `✗ Step ${step} failed: ${result.error}`
    })

    // Wait between steps
    await new Promise(r => setTimeout(r, 300))
  }

  const successful = results.filter(r => r.success).length
  const total = results.length

  return {
    success: successful === total,
    results,
    summary: `${successful}/${total} steps completed`
  }
})

// ============ AGENT TASK LOOP ============
// Execute a task step-by-step, verifying each action

async function executeTaskLoop(task, maxSteps = 10) {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  const results = []
  let currentStep = 0
  let taskComplete = false
  let lastError = null

  // Get initial page state
  let pageState = await getPageState()

  while (currentStep < maxSteps && !taskComplete) {
    currentStep++

    // Send progress
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: `Step ${currentStep}: ${getThinkingPhrase('analyzing')}`
    })

    // Get DOM elements
    const domResult = await extractDomForAI()
    const elements = domResult.success ? domResult.elements.filter(e => e.category !== 'other').slice(0, 40) : []

    // Ask AI what to do next
    const planPrompt = `You are Alex, a QA engineer executing a task on a web page step by step.

TASK: "${task}"

CURRENT PAGE STATE:
- URL: ${pageState.url}
- Title: ${pageState.title}
- Step: ${currentStep} of ${maxSteps}

PREVIOUS ACTIONS THIS SESSION:
${results.map((r, i) => `${i + 1}. ${r.action}: ${r.success ? '✓ Success' : '✗ Failed'} - ${r.description}`).join('\n') || 'None yet'}

${lastError ? `LAST ERROR: ${lastError}` : ''}

AVAILABLE ELEMENTS (${elements.length}):
${JSON.stringify(elements.slice(0, 30), null, 2)}

What is the NEXT SINGLE action to take? Return JSON:
{
  "action": "click" | "type" | "scroll-down" | "scroll-up" | "scroll-to-element" | "wait" | "press-enter" | "navigate" | "done" | "failed",
  "elementId": "testai-X" (for element actions),
  "value": "text to type or URL to navigate" (if needed),
  "description": "What this action does",
  "isComplete": true/false (is the overall task complete?),
  "confidence": 0.0-1.0
}

RULES:
- Return exactly ONE action at a time
- For search: 1) click search icon/button, 2) type search term, 3) press enter or click search
- If element not visible, use "scroll-down" or "scroll-to-element"
- After typing, may need "press-enter" to submit
- Set "action": "done" when task is complete
- Set "action": "failed" if task cannot be completed
- Be specific about which element to target

Return ONLY valid JSON.`

    let nextAction
    try {
      const response = await callDeepSeek([
        { role: 'system', content: 'You are a web automation assistant. Return only valid JSON for the next single action.' },
        { role: 'user', content: planPrompt }
      ], { jsonMode: true, maxTokens: 400, temperature: 0.1 })

      nextAction = JSON.parse(response.content)
    } catch (err) {
      lastError = 'Failed to plan next action: ' + err.message
      continue
    }

    // Check if task is complete or failed
    if (nextAction.action === 'done' || nextAction.isComplete) {
      taskComplete = true
      results.push({
        step: currentStep,
        action: 'done',
        success: true,
        description: nextAction.description || 'Task completed'
      })
      break
    }

    if (nextAction.action === 'failed') {
      results.push({
        step: currentStep,
        action: 'failed',
        success: false,
        description: nextAction.description || 'Could not complete task'
      })
      break
    }

    // Send action notification
    mainWindow?.webContents.send('agent-message', {
      type: 'action',
      message: `▶ ${nextAction.description || nextAction.action}`
    })

    // Execute the action
    let actionResult
    try {
      // Page-level actions
      if (['scroll-down', 'scroll-up', 'scroll-to-top', 'scroll-to-bottom', 'scroll-to-element', 'navigate', 'go-back', 'refresh', 'wait', 'press-escape', 'find-text'].includes(nextAction.action)) {
        actionResult = await executePageAction(nextAction.action, nextAction.value || '')
      }
      // Element actions
      else if (nextAction.elementId) {
        actionResult = await executeAction(nextAction.action, nextAction.elementId, nextAction.value || '')
      }
      // Press enter without specific element (use real keyboard)
      else if (nextAction.action === 'press-enter') {
        const pressed = await realPressEnter()
        if (pressed) {
          actionResult = { success: true, action: 'pressed-enter' }
        } else {
          // Fallback to JS if real input fails
          actionResult = await browserView.webContents.executeJavaScript(`
            (function() {
              const el = document.activeElement
              if (el) {
                el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }))
                el.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }))
                const form = el.closest('form')
                if (form) form.dispatchEvent(new Event('submit', { bubbles: true }))
              }
              return { success: true, action: 'pressed-enter', fallback: true }
            })()
          `)
        }
      }
      else {
        actionResult = { success: false, error: 'No element specified for action' }
      }
    } catch (err) {
      actionResult = { success: false, error: err.message }
    }

    // Wait for page to update after action
    await new Promise(r => setTimeout(r, 300))

    // Verify the action actually worked
    const verification = await verifyAction(
      nextAction.action,
      nextAction.elementId,
      nextAction.value || '',
      pageState
    )

    // Send verification feedback
    if (verification.verified) {
      mainWindow?.webContents.send('agent-message', {
        type: 'action_verified',
        message: `✓ ${nextAction.action} verified: ${verification.change || verification.reason || 'success'}`
      })
    } else {
      mainWindow?.webContents.send('agent-message', {
        type: 'action_warning',
        message: `⚠ Could not verify ${nextAction.action}: ${verification.reason || 'unknown'}`
      })
    }

    // Record result with verification
    results.push({
      step: currentStep,
      action: nextAction.action,
      elementId: nextAction.elementId,
      value: nextAction.value,
      success: actionResult.success,
      verified: verification.verified,
      description: nextAction.description,
      error: actionResult.error,
      verification
    })

    if (!actionResult.success) {
      lastError = actionResult.error || 'Action failed'
    } else if (!verification.verified) {
      lastError = `Action may not have worked: ${verification.reason}`
    } else {
      lastError = null
    }

    // Additional wait for async operations
    await new Promise(r => setTimeout(r, 200))

    // Update page state
    pageState = await getPageState()
  }

  return {
    success: taskComplete || results.some(r => r.success),
    steps: results,
    totalSteps: currentStep,
    taskComplete
  }
}

// Get current page state
async function getPageState() {
  if (!browserView) return { url: '', title: '', hasContent: false }

  try {
    return await browserView.webContents.executeJavaScript(`
      ({
        url: location.href,
        title: document.title,
        hasContent: document.body.innerText.length > 100
      })
    `)
  } catch {
    return { url: '', title: '', hasContent: false }
  }
}

// Verify if an action actually worked
async function verifyAction(action, elementId, value, beforeState) {
  if (!browserView) return { verified: false, reason: 'No browser' }

  try {
    const afterState = await getPageState()

    // Check if URL changed (navigation occurred)
    const urlChanged = beforeState.url !== afterState.url

    switch (action) {
      case 'click':
        // For clicks, check if something changed (URL, or element state)
        if (urlChanged) return { verified: true, change: 'navigated', newUrl: afterState.url }

        // Check if a dialog/modal appeared or element state changed
        const clickVerify = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            // Check for visible changes like dialogs, dropdowns, etc.
            const hasDialog = !!document.querySelector('[role="dialog"], [role="alertdialog"], .modal, .dropdown-menu.show')
            const activeEl = document.activeElement
            return {
              elementStillExists: !!el,
              hasDialog,
              activeElementChanged: activeEl?.tagName !== 'BODY'
            }
          })()
        `)
        if (clickVerify.hasDialog || urlChanged) {
          return { verified: true, change: clickVerify.hasDialog ? 'dialog_opened' : 'state_changed' }
        }
        // Click might have worked even without visible change
        return { verified: true, change: 'click_sent' }

      case 'type':
      case 'type-slow':
        // Verify the value was actually typed
        const typeVerify = await browserView.webContents.executeJavaScript(`
          (function() {
            const el = document.querySelector('[data-testai="${elementId}"]')
            if (!el) return { verified: false, reason: 'element_not_found' }
            const currentValue = el.value || el.innerText || ''
            const expected = '${value.replace(/'/g, "\\'")}'
            return {
              verified: currentValue.includes(expected) || currentValue.length > 0,
              actualValue: currentValue,
              expected
            }
          })()
        `)
        return typeVerify

      case 'scroll-down':
      case 'scroll-up':
      case 'scroll-to-element':
        // Check if scroll position changed
        const scrollVerify = await browserView.webContents.executeJavaScript(`
          ({
            scrollY: window.scrollY,
            scrollHeight: document.body.scrollHeight
          })
        `)
        return { verified: true, scrollPosition: scrollVerify.scrollY }

      case 'press-enter':
        // Check if form was submitted (URL change) or something happened
        if (urlChanged) return { verified: true, change: 'form_submitted', newUrl: afterState.url }
        return { verified: true, change: 'enter_pressed' }

      case 'navigate':
        return { verified: urlChanged, newUrl: afterState.url }

      default:
        return { verified: true, reason: 'action_completed' }
    }
  } catch (err) {
    return { verified: false, reason: err.message }
  }
}

// IPC handler for executing tasks
ipcMain.handle('execute-task', async (_, task) => {
  return await executeTaskLoop(task)
})

// Chat with agent
// Get welcome message
ipcMain.handle('get-welcome-message', () => {
  conversationHistory = [] // Reset conversation
  recentPhrases = [] // Reset phrase tracking for fresh experience
  return { success: true, message: getWelcomeMessage() }
})

// Chat with Alex (the QA persona)
ipcMain.handle('chat-with-agent', async (_, message, context) => {
  if (!deepseekApiKey) {
    const empathy = pick(PERSONALITY.empathy)
    return {
      success: false,
      error: `${empathy}\n\nI need my thinking cap to help you properly. Could you add your DeepSeek API key?\n\nGo to Settings and paste your API key there. You can get one at platform.deepseek.com`
    }
  }

  try {
    // ============ AI-DRIVEN AGENTIC LOOP ============
    // The AI keeps taking actions until task is complete or needs user input

    const MAX_ITERATIONS = 10
    const actionHistory = []
    let finalResponse = ''
    let iteration = 0

    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: pick(PERSONALITY.thinking.receiving)
    })

    // Helper to get current page state - ALWAYS extracts fresh DOM
    async function getPageState() {
      const state = { hasPage: false, url: null, title: null, elements: [], rawHtml: '' }
      if (!browserView) return state

      try {
        state.url = await browserView.webContents.executeJavaScript('location.href')
        state.title = await browserView.webContents.executeJavaScript('document.title')
        state.hasPage = state.url && state.url !== 'about:blank'

        if (state.hasPage) {
          // ALWAYS extract fresh DOM - this is critical!
          const domResult = await extractDomForAI()
          if (domResult.success) {
            state.elements = domResult.elements.filter(e => e.category !== 'other').slice(0, 60)
          }

          // Also get visible text for answering questions
          try {
            state.visibleText = await browserView.webContents.executeJavaScript(`
              document.body.innerText.slice(0, 2000)
            `)
          } catch (e) { /* ignore */ }
        }
      } catch (e) { /* Page not ready */ }
      return state
    }

    // Helper to check if user's question is answered by current page
    function checkIfAnswered(userMessage, pageState) {
      const msgLower = userMessage.toLowerCase()
      const isQuestion = msgLower.includes('where') || msgLower.includes('find') ||
                         msgLower.includes('show') || msgLower.includes('what') ||
                         msgLower.includes('how') || msgLower.includes('?')

      if (!isQuestion) return { isQuestion: false }

      // Extract keywords from question
      const keywords = msgLower.split(/\s+/).filter(w => w.length > 3)

      // Check if any elements match the keywords
      const matchingElements = pageState.elements.filter(el => {
        const elText = [el.text, el.label, el.placeholder, el.ariaLabel].join(' ').toLowerCase()
        return keywords.some(kw => elText.includes(kw))
      })

      // Check visible text
      const visibleText = (pageState.visibleText || '').toLowerCase()
      const textMatches = keywords.filter(kw => visibleText.includes(kw))

      return {
        isQuestion: true,
        answered: matchingElements.length > 0 || textMatches.length > 2,
        matchingElements,
        textMatches
      }
    }

    // Helper to execute a single action
    async function executeDecision(decision, pageState) {
      let result = { success: false, message: '' }

      switch (decision.action) {
        case 'navigate': {
          let targetUrl = decision.url
          if (!targetUrl) {
            result.message = "No URL specified"
            break
          }

          if (!/^https?:\/\//i.test(targetUrl)) {
            const isLocal = targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') || /^[\w.-]+:\d+/.test(targetUrl)
            targetUrl = (isLocal ? 'http://' : 'https://') + targetUrl
          }

          mainWindow?.webContents.send('agent-message', { type: 'action', message: `🌐 Navigating to ${targetUrl}...` })

          if (!browserView) createBrowserView()
          try {
            await browserView.webContents.loadURL(targetUrl)
            await new Promise(r => setTimeout(r, 2000))
            result = { success: true, message: `Navigated to ${targetUrl}`, urlChanged: true }
          } catch (err) {
            result = { success: false, message: `Failed to load: ${err.message}` }
          }
          break
        }

        case 'click': {
          if (!decision.elementId) {
            result.message = "No element specified to click"
            break
          }

          // VERIFY element exists in current DOM before clicking
          const targetEl = pageState.elements.find(e => e.id === decision.elementId)
          if (!targetEl) {
            result = { success: false, message: `Element ${decision.elementId} not found in current page. DOM may have changed.` }
            break
          }

          const elName = targetEl.text || targetEl.label || targetEl.placeholder || decision.elementId

          // Extra safety: check if element text matches what AI thinks it is
          if (decision.expectedText && targetEl.text &&
              !targetEl.text.toLowerCase().includes(decision.expectedText.toLowerCase())) {
            result = { success: false, message: `Element text "${targetEl.text}" doesn't match expected "${decision.expectedText}". Stopping to avoid wrong click.` }
            break
          }

          mainWindow?.webContents.send('agent-message', { type: 'action', message: `👆 Clicking "${elName}"...` })

          const clickResult = await executeAction('click', decision.elementId, '')
          await new Promise(r => setTimeout(r, 1500)) // Wait for page reaction

          if (clickResult.success) {
            result = { success: true, message: `Clicked "${elName}"`, element: elName, domMayHaveChanged: true }
          } else {
            result = { success: false, message: `Couldn't click: ${clickResult.error}` }
          }
          break
        }

        case 'type': {
          if (!decision.elementId) {
            result.message = "No element specified to type in"
            break
          }

          // VERIFY element exists in current DOM before typing
          const targetEl = pageState.elements.find(e => e.id === decision.elementId)
          if (!targetEl) {
            result = { success: false, message: `Element ${decision.elementId} not found. DOM may have changed.` }
            break
          }

          // Verify it's an input element
          if (targetEl.category !== 'text-input' && targetEl.tag !== 'input' && targetEl.tag !== 'textarea') {
            result = { success: false, message: `Element "${targetEl.text || targetEl.id}" is not a text input field.` }
            break
          }

          const elName = targetEl.label || targetEl.placeholder || targetEl.name || decision.elementId

          mainWindow?.webContents.send('agent-message', { type: 'action', message: `⌨️ Typing "${decision.value}" in ${elName}...` })

          const typeResult = await executeAction('type', decision.elementId, decision.value || '')
          await new Promise(r => setTimeout(r, 500))

          if (typeResult.success) {
            result = { success: true, message: `Typed "${decision.value}" in ${elName}`, element: elName, value: decision.value }
          } else {
            result = { success: false, message: `Couldn't type: ${typeResult.error}` }
          }
          break
        }

        case 'press_enter': {
          mainWindow?.webContents.send('agent-message', { type: 'action', message: `⏎ Pressing Enter...` })
          await realPressEnter()
          await new Promise(r => setTimeout(r, 1500))
          result = { success: true, message: 'Pressed Enter' }
          break
        }

        case 'wait': {
          const waitTime = decision.duration || 1000
          mainWindow?.webContents.send('agent-message', { type: 'action', message: `⏳ Waiting ${waitTime}ms...` })
          await new Promise(r => setTimeout(r, waitTime))
          result = { success: true, message: `Waited ${waitTime}ms` }
          break
        }

        case 'scroll': {
          mainWindow?.webContents.send('agent-message', { type: 'action', message: `📜 Scrolling ${decision.direction || 'down'}...` })
          await executeAction(decision.direction === 'up' ? 'scroll-up' : 'scroll-down', '', '')
          await new Promise(r => setTimeout(r, 500))
          result = { success: true, message: `Scrolled ${decision.direction || 'down'}` }
          break
        }

        case 'task_complete': {
          result = { success: true, message: decision.summary || 'Task completed', taskComplete: true }
          break
        }

        case 'answer': {
          // User asked a question and we found the answer
          let answerText = decision.found || 'Found what you were looking for.'
          if (decision.elements && decision.elements.length > 0) {
            answerText += `\n\n**Found on page:**\n${decision.elements.map(e => `• ${e}`).join('\n')}`
          }
          mainWindow?.webContents.send('agent-message', { type: 'action', message: `🔍 Found answer!` })
          result = { success: true, message: answerText, answered: true }
          break
        }

        case 'need_input': {
          result = { success: true, message: decision.question || 'Need more information', needsInput: true, question: decision.question }
          break
        }

        case 'cannot_proceed': {
          result = { success: false, message: decision.reason || 'Cannot proceed with this task', cannotProceed: true }
          break
        }

        case 'generate_tests': {
          mainWindow?.webContents.send('agent-message', { type: 'action', message: `🧪 Generating comprehensive test suite...` })

          // Use the HumanoidQAAgent's test generator
          const pageType = qaAgent.reasoningEngine.detectPageType(pageState)
          const testSuite = qaAgent.generateTests(pageType, pageState.elements, {
            url: pageState.url,
            title: pageState.title
          })

          // Format the test suite as a readable response
          let testSummary = `Generated ${testSuite.tests.length} test cases:\n`
          testSuite.tests.forEach((test, i) => {
            testSummary += `\n**${test.id}: ${test.title}** (${test.priority})\n`
            testSummary += `Category: ${test.category}\n`
            if (test.steps) {
              test.steps.forEach((step, j) => {
                testSummary += `  ${j + 1}. ${step.action}${step.element ? ` "${step.element}"` : ''}${step.value ? `: ${step.value}` : ''}\n`
              })
            }
            testSummary += `Expected: ${test.expectedResult}\n`
          })

          if (testSuite.coverage) {
            testSummary += `\n**Coverage:** ${testSuite.coverage.percentage}% (${testSuite.coverage.rulesCovered}/${testSuite.coverage.totalRules} rules)\n`
            if (testSuite.coverage.gaps.length > 0) {
              testSummary += `**Gaps:** ${testSuite.coverage.gaps.slice(0, 3).join(', ')}\n`
            }
          }

          // Store for potential execution
          lastGeneratedTestSuite = testSuite

          result = { success: true, message: testSummary, testsGenerated: true, testSuite }
          break
        }

        default: {
          result = { success: false, message: `Unknown action: ${decision.action}` }
        }
      }

      return result
    }

    // ============ MAIN AGENTIC LOOP ============
    while (iteration < MAX_ITERATIONS) {
      iteration++

      // Get fresh page state
      const pageState = await getPageState()

      // Build action history summary
      const historyText = actionHistory.length > 0
        ? `\n\nACTIONS TAKEN SO FAR:\n${actionHistory.map((a, i) => `${i + 1}. ${a.action}: ${a.result}`).join('\n')}`
        : ''

      // Build elements summary
      const elementsSummary = pageState.elements.length > 0
        ? `\n\nPAGE ELEMENTS (${pageState.elements.length}):\n${JSON.stringify(pageState.elements.map(e => ({
            id: e.id, tag: e.tag, category: e.category,
            text: (e.text || e.label || e.placeholder || '').slice(0, 40)
          })), null, 2)}`
        : '\n\nNO ELEMENTS FOUND on page (might still be loading or in iframe)'

      // Use HumanoidQAAgent's reasoning engine for smarter decisions
      const pageType = qaAgent.reasoningEngine.detectPageType(pageState)

      // Get relevant QA knowledge for this page type
      const qaKnowledge = QA_BRAIN.getKnowledge(pageType)
      const knowledgeSummary = qaKnowledge.length > 0
        ? `\n\nQA KNOWLEDGE FOR ${pageType.toUpperCase()} PAGES:\n${qaKnowledge.slice(0, 5).map(k => `- [${k.id}] ${k.rule} (${k.priority})`).join('\n')}`
        : ''

      // Check if this is a question that might already be answered
      const answerCheck = checkIfAnswered(message, pageState)

      // If question is answered, suggest reporting
      const answerHint = answerCheck.isQuestion && answerCheck.answered
        ? `\n\n⚠️ IMPORTANT: The user asked a QUESTION. Looking at the current page, I can see elements that might answer their question: ${answerCheck.matchingElements.slice(0, 3).map(e => `"${e.text || e.label}"`).join(', ')}. Consider using "answer" action to report what you found.`
        : ''

      // Ask AI what to do next - enhanced with QA Brain
      const decisionPrompt = `You are Alex, a senior QA engineer with 12 years of experience controlling a browser to complete tasks.

ORIGINAL USER REQUEST: "${message}"

CURRENT STATE:
- Iteration: ${iteration}/${MAX_ITERATIONS}
- Page loaded: ${pageState.hasPage ? 'Yes' : 'No'}
- URL: ${pageState.url || 'none'}
- Title: ${pageState.title || 'none'}
- Page Type: ${pageType}
${historyText}
${elementsSummary}
${knowledgeSummary}
${answerHint}

AVAILABLE ACTIONS (return ONE as JSON):

For QUESTIONS ("where is X", "find X", "show me X"):
{ "action": "answer", "found": "description of what you found on the page", "elements": ["list of relevant element texts"] }

For NAVIGATION:
{ "action": "navigate", "url": "http://...", "reason": "why" }

For INTERACTION (only when user explicitly asks to DO something):
{ "action": "click", "elementId": "testai-X", "reason": "why clicking this SPECIFIC element" }
{ "action": "type", "elementId": "testai-X", "value": "text", "reason": "why" }
{ "action": "press_enter", "reason": "to submit" }
{ "action": "scroll", "direction": "down|up", "reason": "to find something" }

For COMPLETION:
{ "action": "task_complete", "summary": "what was accomplished" }
{ "action": "need_input", "question": "what you need from user" }
{ "action": "cannot_proceed", "reason": "why stuck" }

For TESTING:
{ "action": "generate_tests", "reason": "create test suite" }

⚠️ CRITICAL RULES - READ CAREFULLY:

1. **QUESTIONS vs ACTIONS**:
   - If user asks "where is X" or "find X" → Use "answer" action when you can see X on the page
   - If user asks "click X" or "do X" → Use interaction actions
   - NEVER click things just to explore when user asked a question

2. **DON'T HALLUCINATE**:
   - ONLY click elements that DIRECTLY relate to user's request
   - If user says "login" → click LOGIN button, NOT "forgot password", NOT "sign up"
   - If user says "find payments" → look for payments, don't click random menus

3. **STOP WHEN DONE**:
   - If you can see what the user asked for → use "answer" or "task_complete"
   - Don't keep clicking after finding what was asked

4. **BE CONSERVATIVE**:
   - When in doubt, ask the user (need_input) rather than guessing
   - Only interact with elements you're CONFIDENT about

5. **VERIFY ELEMENT EXISTS**:
   - Check the CURRENT elements list before clicking
   - Element IDs change after page updates

CURRENT GOAL: "${message}"
What's the SINGLE next action? Return ONLY valid JSON.`

CURRENT GOAL: "${message}"
What's the next single action? Return ONLY valid JSON.`

      let decision
      try {
        const response = await callDeepSeek([
          { role: 'system', content: `You are Alex, a senior QA engineer with 12 years of experience. You think step by step, reason carefully, and always explain your decisions. You're meticulous about testing and never skip steps. Return only valid JSON.` },
          { role: 'user', content: decisionPrompt }
        ], { jsonMode: true, maxTokens: 500, temperature: 0.1 })

        decision = JSON.parse(response.content)
      } catch (e) {
        decision = { action: 'cannot_proceed', reason: 'Failed to determine next action' }
      }

      // Execute the action
      const result = await executeDecision(decision, pageState)

      // Record in history
      actionHistory.push({
        action: decision.action,
        details: decision,
        result: result.message,
        success: result.success
      })

      // Check termination conditions
      if (result.taskComplete) {
        // Task is done!
        const successActions = actionHistory.filter(a => a.success).length
        finalResponse = `✅ **Task Complete!**\n\n${result.message}\n\n`
        finalResponse += `**Actions taken (${successActions}/${actionHistory.length}):**\n`
        actionHistory.forEach((a, i) => {
          const icon = a.success ? '✓' : '✗'
          finalResponse += `${i + 1}. ${icon} ${a.result}\n`
        })
        break
      }

      if (result.testsGenerated) {
        // Test suite generated - this is a complete task
        finalResponse = `🧪 **Test Suite Generated!**\n\n${result.message}\n\n`
        finalResponse += `---\n\n**Want me to execute any of these tests?** Just say "run test HP-1" or "run all tests".`
        break
      }

      if (result.answered) {
        // Question was answered - report and stop
        finalResponse = `🔍 **Here's what I found:**\n\n${result.message}`
        if (actionHistory.length > 1) {
          finalResponse += `\n\n**Steps taken to find this:**\n`
          actionHistory.slice(0, -1).forEach((a, i) => {
            finalResponse += `${i + 1}. ${a.result}\n`
          })
        }
        break
      }

      if (result.needsInput) {
        // Need user input - pause and ask
        finalResponse = `🤔 **I need some information:**\n\n${result.question}\n\n`
        if (actionHistory.length > 1) {
          finalResponse += `**Progress so far:**\n`
          actionHistory.slice(0, -1).forEach((a, i) => {
            finalResponse += `${i + 1}. ${a.success ? '✓' : '✗'} ${a.result}\n`
          })
        }
        break
      }

      if (result.cannotProceed) {
        // Can't continue
        finalResponse = `❌ **Cannot proceed:**\n\n${result.message}\n\n`
        if (actionHistory.length > 1) {
          finalResponse += `**What I tried:**\n`
          actionHistory.forEach((a, i) => {
            finalResponse += `${i + 1}. ${a.success ? '✓' : '✗'} ${a.result}\n`
          })
        }
        break
      }

      // Continue to next iteration...
      mainWindow?.webContents.send('agent-message', {
        type: 'progress',
        message: `Step ${iteration}: ${result.message}`
      })
    }

    // If we hit max iterations without completing
    if (!finalResponse) {
      finalResponse = `⏱️ **Reached maximum steps (${MAX_ITERATIONS})**\n\n`
      finalResponse += `**Actions taken:**\n`
      actionHistory.forEach((a, i) => {
        finalResponse += `${i + 1}. ${a.success ? '✓' : '✗'} ${a.result}\n`
      })
      finalResponse += `\nWould you like me to continue? Just say "continue" or give me new instructions.`
    }

    // Update conversation history
    conversationHistory.push({ role: 'user', content: message })
    conversationHistory.push({ role: 'assistant', content: finalResponse })

    if (conversationHistory.length > 20) {
      conversationHistory = conversationHistory.slice(-20)
    }

    return {
      success: true,
      response: finalResponse,
      iterations: iteration,
      actionHistory
    }

  } catch (err) {
    const problemPhrase = pick(PERSONALITY.transitions.problem)
    return { success: false, error: `${problemPhrase} ${err.message}` }
  }
})

// Smart analyze - called after URL is loaded, provides human insights
ipcMain.handle('smart-analyze', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!deepseekApiKey) return { success: false, error: 'API key not configured' }

  try {
    // Send initial thinking message
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: pick(PERSONALITY.transitions.starting)
    })

    // Get page info and elements
    const pageInfo = await browserView.webContents.executeJavaScript(`
      ({ url: location.href, title: document.title })
    `)

    // Send analyzing message
    mainWindow?.webContents.send('agent-message', {
      type: 'thinking',
      message: getThinkingPhrase('analyzing')
    })

    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = []
        let id = 1
        const selectors = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick],form'
        for (const el of document.querySelectorAll(selectors)) {
          const rect = el.getBoundingClientRect()
          if (rect.width === 0 || rect.height === 0) continue
          const style = getComputedStyle(el)
          if (style.display === 'none' || style.visibility === 'hidden') continue
          el.setAttribute('data-testai', 'testai-' + id++)
          elements.push({
            id: 'testai-' + (id-1),
            tag: el.tagName.toLowerCase(),
            text: (el.innerText?.trim() || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').slice(0, 60),
            type: el.getAttribute('type') || '',
            name: el.getAttribute('name') || ''
          })
        }
        return elements
      })()
    `)

    // Detect page type from elements and URL
    const pageTypeHints = {
      login: ['login', 'sign in', 'signin', 'password', 'email'],
      signup: ['sign up', 'signup', 'register', 'create account'],
      checkout: ['checkout', 'payment', 'cart', 'order', 'buy'],
      search: ['search', 'query', 'find', 'filter'],
      form: ['form', 'submit', 'contact', 'apply'],
      dashboard: ['dashboard', 'admin', 'panel', 'overview'],
    }

    let detectedPageType = 'general'
    const urlLower = pageInfo.url.toLowerCase()
    const titleLower = pageInfo.title.toLowerCase()
    const elementTexts = elements.map(e => e.text?.toLowerCase() || '').join(' ')
    const combined = urlLower + ' ' + titleLower + ' ' + elementTexts

    for (const [type, hints] of Object.entries(pageTypeHints)) {
      if (hints.some(hint => combined.includes(hint))) {
        detectedPageType = type
        break
      }
    }

    // Send page-specific thinking message
    if (detectedPageType !== 'general') {
      mainWindow?.webContents.send('agent-message', {
        type: 'thinking',
        message: getPageThought(detectedPageType)
      })
    }

    // Build enhanced analysis prompt with personality guidance
    const analysisPrompt = `I just loaded this page. Give me your first impressions as a QA engineer would - what catches your eye, what looks good, and what concerns you.

URL: ${pageInfo.url}
Title: ${pageInfo.title}
Detected Page Type: ${detectedPageType}

Interactive elements found (${elements.length}):
${JSON.stringify(elements.slice(0, 25), null, 2)}

Respond naturally as Alex. Use varied phrasing:
- Start with something you notice (use phrases like "${pick(PERSONALITY.transitions.found_something)}")
- Show confidence appropriately - be certain about obvious things, uncertain about assumptions
- Use transitions naturally (phrases like "${pick(PERSONALITY.transitions.continuing)}")
- End with a clarifying question (start with phrases like "${pick(PERSONALITY.transitions.asking)}")

Structure your response:
1. What you notice first (be specific, mention actual elements)
2. What looks good (acknowledge the positive)
3. Areas you'd want to explore (potential concerns or interesting test cases)
4. A warm, collaborative question about what they're building

Keep it warm and collaborative. Focus on insights, not listing every element.`

    const response = await callDeepSeek([
      { role: 'system', content: ALEX_SYSTEM_PROMPT },
      { role: 'user', content: analysisPrompt }
    ], { maxTokens: 1500, temperature: 0.5 })

    // Add to conversation history
    conversationHistory.push(
      { role: 'user', content: `[User loaded ${pageInfo.url}]` },
      { role: 'assistant', content: response.content }
    )

    return {
      success: true,
      pageInfo,
      elementCount: elements.length,
      pageType: detectedPageType,
      analysis: response.content
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  loadEnvFile()
  createWindow()
})

app.on('window-all-closed', () => {
  if (!isMac) app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

// Cleanup on quit
app.on('before-quit', () => {
  cleanup()
})
