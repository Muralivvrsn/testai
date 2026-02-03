/**
 * Yali Agent - Feature Analyzer
 * Ported from testai-agent/understanding/feature_analyzer.py
 *
 * Understands user requests and extracts testing intent.
 * Thinks like a human QA: "What are they really trying to test?"
 *
 * Key Capabilities:
 * - Extract feature name from natural language
 * - Identify page type from description or elements
 * - Suggest testing focus based on feature type
 * - Detect ambiguity and ask smart clarifying questions
 */

/**
 * User intent types
 */
const UserIntent = {
  GENERATE_TESTS: 'generate_tests',
  ANALYZE_PAGE: 'analyze_page',
  SECURITY_CHECK: 'security_check',
  ACCESSIBILITY_CHECK: 'accessibility',
  REGRESSION_TESTS: 'regression',
  SMOKE_TESTS: 'smoke',
  EXPLORATORY: 'exploratory',
  UNKNOWN: 'unknown'
}

/**
 * Keywords that indicate intent
 */
const INTENT_KEYWORDS = {
  [UserIntent.GENERATE_TESTS]: ['test', 'tests', 'testing', 'generate', 'create', 'write'],
  [UserIntent.ANALYZE_PAGE]: ['analyze', 'check', 'review', 'look at', 'examine'],
  [UserIntent.SECURITY_CHECK]: ['security', 'secure', 'vulnerability', 'xss', 'injection', 'penetration', 'pentest'],
  [UserIntent.ACCESSIBILITY_CHECK]: ['accessibility', 'a11y', 'screen reader', 'wcag', 'aria'],
  [UserIntent.REGRESSION_TESTS]: ['regression', 'after change', 'verify still works'],
  [UserIntent.SMOKE_TESTS]: ['smoke', 'quick', 'basic', 'sanity'],
  [UserIntent.EXPLORATORY]: ['explore', 'find bugs', 'break it', 'edge cases']
}

/**
 * Page type detection patterns
 */
const PAGE_TYPE_PATTERNS = {
  login: ['login', 'sign in', 'signin', 'log in', 'authenticate'],
  signup: ['signup', 'sign up', 'register', 'registration', 'create account'],
  checkout: ['checkout', 'payment', 'purchase', 'buy', 'cart', 'order'],
  search: ['search', 'find', 'query', 'filter', 'results'],
  settings: ['settings', 'preferences', 'configuration', 'account settings'],
  profile: ['profile', 'my account', 'user info', 'personal'],
  dashboard: ['dashboard', 'overview', 'home', 'main page'],
  form: ['form', 'input', 'submit', 'application'],
  list: ['list', 'table', 'grid', 'items', 'products'],
  detail: ['detail', 'view', 'item page', 'product page']
}

/**
 * Focus area suggestions based on page type
 */
const FOCUS_SUGGESTIONS = {
  login: ['authentication', 'session handling', 'brute force', 'password security'],
  signup: ['validation', 'email verification', 'password strength', 'duplicate accounts'],
  checkout: ['payment security', 'cart integrity', 'price accuracy', 'address validation'],
  search: ['query handling', 'result accuracy', 'performance', 'special characters'],
  settings: ['data persistence', 'permission changes', 'notification preferences'],
  profile: ['data privacy', 'image upload', 'field validation'],
  form: ['validation', 'required fields', 'error messages', 'data sanitization']
}

/**
 * Create a feature context
 */
function createFeatureContext(featureName, options = {}) {
  return {
    featureName,
    pageType: options.pageType || null,
    url: options.url || null,
    intent: options.intent || UserIntent.GENERATE_TESTS,
    focusAreas: options.focusAreas || [],
    elements: options.elements || [],
    elementSummary: options.elementSummary || {},
    constraints: options.constraints || [],
    ambiguities: options.ambiguities || [],
    clarificationNeeded: options.clarificationNeeded || false,
    confidence: options.confidence || 0.5,

    toString() {
      const parts = [`Feature: ${this.featureName}`]
      if (this.pageType) parts.push(`Page type: ${this.pageType}`)
      parts.push(`Intent: ${this.intent}`)
      if (this.focusAreas.length) parts.push(`Focus: ${this.focusAreas.join(', ')}`)
      if (this.ambiguities.length) parts.push(`Unclear: ${this.ambiguities.join(', ')}`)
      return parts.join(' | ')
    },

    toDict() {
      return {
        featureName: this.featureName,
        pageType: this.pageType,
        url: this.url,
        intent: this.intent,
        focusAreas: this.focusAreas,
        elementCount: this.elements.length,
        elementSummary: this.elementSummary,
        constraints: this.constraints,
        ambiguities: this.ambiguities,
        clarificationNeeded: this.clarificationNeeded,
        confidence: this.confidence
      }
    }
  }
}

/**
 * Feature Analyzer class
 * Understands user requests and extracts testing intent
 */
class FeatureAnalyzer {
  constructor() {
    // Nothing to initialize
  }

  /**
   * Analyze a natural language request
   */
  fromRequest(request) {
    const requestLower = request.toLowerCase()

    // Extract intent
    const intent = this._detectIntent(requestLower)

    // Extract feature name
    const featureName = this._extractFeatureName(request)

    // Detect page type
    const pageType = this._detectPageType(requestLower)

    // Extract URL if present
    const url = this._extractUrl(request)

    // Detect focus areas
    const focusAreas = this._detectFocusAreas(requestLower, pageType)

    // Detect constraints
    const constraints = this._detectConstraints(requestLower)

    // Calculate confidence and ambiguities
    const ambiguities = []
    let confidence = 0.7

    if (!featureName || featureName === 'Unknown Feature') {
      ambiguities.push('feature name unclear')
      confidence -= 0.2
    }

    if (!pageType) {
      ambiguities.push('page type not identified')
      confidence -= 0.1
    }

    if (intent === UserIntent.UNKNOWN) {
      ambiguities.push('intent unclear')
      confidence -= 0.2
    }

    return createFeatureContext(featureName, {
      pageType,
      url,
      intent,
      focusAreas,
      constraints,
      ambiguities,
      clarificationNeeded: ambiguities.length > 0,
      confidence: Math.max(confidence, 0.1)
    })
  }

  /**
   * Analyze a page from its elements
   */
  fromElements(elements, url = null, title = null) {
    // Summarize elements
    const elementSummary = {}
    const elementTexts = []

    for (const el of elements) {
      const elType = el.elementType || el.type || el.tag || 'unknown'
      elementSummary[elType] = (elementSummary[elType] || 0) + 1

      // Collect text for analysis
      for (const field of ['name', 'id', 'text', 'placeholder', 'aria-label']) {
        if (el[field]) {
          elementTexts.push(el[field].toLowerCase())
        }
      }
    }

    const combinedText = elementTexts.join(' ')

    // Detect page type from elements
    let pageType = this._detectPageTypeFromElements(elementSummary, combinedText)

    // Also check URL
    if (!pageType && url) {
      pageType = this._detectPageType(url.toLowerCase())
    }

    // Generate feature name
    let featureName
    if (title) {
      featureName = title
    } else if (pageType) {
      featureName = `${pageType.charAt(0).toUpperCase() + pageType.slice(1)} Page`
    } else {
      featureName = 'Web Page'
    }

    // Detect focus areas
    const focusAreas = this._detectFocusFromElements(elementSummary, combinedText)

    // Calculate confidence
    let confidence = 0.6
    const ambiguities = []

    if (!pageType) {
      ambiguities.push('page type unclear from elements')
      confidence -= 0.1
    }

    if (elements.length < 3) {
      ambiguities.push('very few elements detected')
      confidence -= 0.1
    }

    return createFeatureContext(featureName, {
      pageType,
      url,
      intent: UserIntent.GENERATE_TESTS,
      focusAreas,
      elements,
      elementSummary,
      ambiguities,
      clarificationNeeded: ambiguities.length > 0,
      confidence: Math.max(confidence, 0.1)
    })
  }

  /**
   * Generate smart clarification questions
   */
  getClarificationQuestions(context) {
    const questions = []

    // If feature name is unclear
    if (context.ambiguities.includes('feature name unclear')) {
      questions.push({
        question: 'What feature or page would you like me to test?',
        type: 'open',
        priority: 'high',
        examples: ['User login', 'Checkout flow', 'Search functionality']
      })
    }

    // If page type is unclear
    if (context.ambiguities.includes('page type not identified')) {
      questions.push({
        question: 'What type of page is this?',
        type: 'choice',
        priority: 'high',
        options: ['Login', 'Signup', 'Checkout', 'Search', 'Form', 'Other']
      })
    }

    // If intent is unclear
    if (context.ambiguities.includes('intent unclear')) {
      questions.push({
        question: 'What kind of testing would you like me to focus on?',
        type: 'choice',
        priority: 'medium',
        options: [
          'Comprehensive tests (all categories)',
          'Security focused',
          'Quick smoke tests',
          'Accessibility check'
        ]
      })
    }

    // Suggest focus areas if page type is known but no focus specified
    if (context.pageType && !context.focusAreas.length) {
      const suggested = FOCUS_SUGGESTIONS[context.pageType] || []
      if (suggested.length) {
        questions.push({
          question: `Any specific areas to focus on for this ${context.pageType} page?`,
          type: 'multi-choice',
          priority: 'low',
          options: suggested.slice(0, 4),
          default: 'All of the above'
        })
      }
    }

    return questions
  }

  _detectIntent(text) {
    for (const [intent, keywords] of Object.entries(INTENT_KEYWORDS)) {
      if (keywords.some(kw => text.includes(kw))) {
        return intent
      }
    }
    return UserIntent.UNKNOWN
  }

  _extractFeatureName(text) {
    const patterns = [
      /test(?:ing)?\s+(?:the\s+)?([a-z][a-z\s]+?)(?:\s+page|\s+feature|\s+flow|\s+for|\.|$)/i,
      /(?:for|check|analyze)\s+(?:the\s+)?([a-z][a-z\s]+?)(?:\s+page|\s+feature|\s+flow|\.|$)/i,
      /([a-z]+)\s+(?:page|feature|form|flow)/i
    ]

    const textLower = text.toLowerCase()

    for (const pattern of patterns) {
      const match = textLower.match(pattern)
      if (match) {
        let name = match[1].trim()
        // Clean up common words
        name = name.replace(/\b(the|a|an|some|any)\b/g, '').trim()
        if (name && name.length > 2) {
          return name.charAt(0).toUpperCase() + name.slice(1)
        }
      }
    }

    // Check for page type keywords as fallback
    for (const pageType of Object.keys(PAGE_TYPE_PATTERNS)) {
      if (textLower.includes(pageType)) {
        return `${pageType.charAt(0).toUpperCase() + pageType.slice(1)} Feature`
      }
    }

    return 'Unknown Feature'
  }

  _detectPageType(text) {
    for (const [pageType, patterns] of Object.entries(PAGE_TYPE_PATTERNS)) {
      if (patterns.some(p => text.includes(p))) {
        return pageType
      }
    }
    return null
  }

  _detectPageTypeFromElements(elementSummary, text) {
    // Login page indicators
    if (text.includes('password') && (text.includes('email') || text.includes('username'))) {
      if (text.includes('confirm') || text.includes('verify')) {
        return 'signup'
      }
      return 'login'
    }

    // Checkout indicators
    if (text.includes('card') || text.includes('payment') || text.includes('cvv')) {
      return 'checkout'
    }

    // Search indicators
    if (text.includes('search')) {
      return 'search'
    }

    // Form with many inputs
    const inputCount = elementSummary.input || 0
    if (inputCount > 5) {
      return 'form'
    }

    return null
  }

  _detectFocusAreas(text, pageType) {
    const focus = []

    // Explicit focus keywords
    const focusKeywords = {
      'security': ['security', 'secure', 'xss', 'injection', 'vulnerability'],
      'accessibility': ['accessibility', 'a11y', 'screen reader', 'wcag'],
      'performance': ['performance', 'speed', 'load time', 'fast'],
      'validation': ['validation', 'validate', 'verify', 'check'],
      'edge cases': ['edge case', 'corner case', 'unusual', 'extreme'],
      'error handling': ['error', 'fail', 'invalid', 'wrong']
    }

    for (const [area, keywords] of Object.entries(focusKeywords)) {
      if (keywords.some(kw => text.includes(kw))) {
        focus.push(area)
      }
    }

    // Add page-type specific focus if no explicit focus
    if (!focus.length && pageType) {
      const suggested = FOCUS_SUGGESTIONS[pageType] || []
      focus.push(...suggested.slice(0, 2))
    }

    return focus
  }

  _detectFocusFromElements(elementSummary, text) {
    const focus = []

    // Password fields suggest security focus
    if (text.includes('password')) {
      focus.push('authentication security')
    }

    // Many inputs suggest validation focus
    const inputCount = elementSummary.input || 0
    if (inputCount > 3) {
      focus.push('input validation')
    }

    // File upload suggests upload security
    if (text.includes('file') || text.includes('upload')) {
      focus.push('file upload security')
    }

    // Payment-related
    if (text.includes('card') || text.includes('payment')) {
      focus.push('payment security')
    }

    return focus
  }

  _detectConstraints(text) {
    const constraints = []

    const constraintPatterns = [
      [/no\s+(api|backend|server)\s+tests?/i, 'no api tests'],
      [/only\s+(ui|frontend|visual)/i, 'frontend only'],
      [/(mobile|responsive)/i, 'include mobile'],
      [/skip\s+(security|a11y|accessibility)/i, 'skip security'],
      [/quick|fast|brief/i, 'brief tests']
    ]

    for (const [pattern, constraint] of constraintPatterns) {
      if (pattern.test(text)) {
        constraints.push(constraint)
      }
    }

    return constraints
  }

  _extractUrl(text) {
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/
    const match = text.match(urlPattern)
    return match ? match[0] : null
  }
}

/**
 * Quick helper to analyze a request
 */
function analyzeRequest(request) {
  const analyzer = new FeatureAnalyzer()
  return analyzer.fromRequest(request)
}

/**
 * Quick helper to analyze page elements
 */
function analyzePage(elements, url = null) {
  const analyzer = new FeatureAnalyzer()
  return analyzer.fromElements(elements, url)
}

module.exports = {
  UserIntent,
  INTENT_KEYWORDS,
  PAGE_TYPE_PATTERNS,
  FOCUS_SUGGESTIONS,
  FeatureAnalyzer,
  createFeatureContext,
  analyzeRequest,
  analyzePage
}
