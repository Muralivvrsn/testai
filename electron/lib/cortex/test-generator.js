/**
 * Yali Agent - Test Generator
 * Ported from testai-agent/generators/test_generator.py
 *
 * Core test generation engine combining brain knowledge + LLM intelligence.
 */

const { getForPageType, getEdgeCases, getTestsFromSections } = require('./qa-brain')
const { prioritizeTests, Priority } = require('./prioritizer')

/**
 * Test categories
 */
const TestCategory = {
  HAPPY_PATH: 'happy_path',
  NEGATIVE: 'negative',
  EDGE_CASE: 'edge_case',
  SECURITY: 'security',
  VALIDATION: 'validation',
  BOUNDARY: 'boundary',
  ERROR_HANDLING: 'error_handling',
  ACCESSIBILITY: 'accessibility',
  PERFORMANCE: 'performance',
  INTEGRATION: 'integration'
}

/**
 * Test priority
 */
const TestPriority = {
  CRITICAL: 'P0',
  HIGH: 'P1',
  MEDIUM: 'P2',
  LOW: 'P3'
}

/**
 * Create a test case
 */
function createTestCase(options) {
  return {
    id: options.id || `TC_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    title: options.title || options.name || 'Untitled Test',
    name: options.name || options.title || 'Untitled Test',
    description: options.description || '',
    category: options.category || TestCategory.FUNCTIONAL,
    priority: options.priority || TestPriority.MEDIUM,
    preconditions: options.preconditions || [],
    steps: options.steps || [],
    expectedResult: options.expectedResult || options.expected || '',
    testData: options.testData || {},
    tags: options.tags || [],
    source: options.source || null,

    toJSON() {
      return {
        id: this.id,
        title: this.title,
        category: this.category,
        priority: this.priority,
        steps: this.steps,
        expectedResult: this.expectedResult,
        testData: this.testData
      }
    }
  }
}

/**
 * Create a test suite
 */
function createTestSuite(name, tests = [], metadata = {}) {
  return {
    name,
    tests,
    metadata,
    createdAt: new Date().toISOString(),

    get count() {
      return this.tests.length
    },

    getByCategory(category) {
      return this.tests.filter(t => t.category === category)
    },

    getByPriority(priority) {
      return this.tests.filter(t => t.priority === priority)
    },

    getSummary() {
      const byCat = {}
      const byPri = {}

      for (const t of this.tests) {
        byCat[t.category] = (byCat[t.category] || 0) + 1
        byPri[t.priority] = (byPri[t.priority] || 0) + 1
      }

      return {
        total: this.tests.length,
        byCategory: byCat,
        byPriority: byPri
      }
    }
  }
}

/**
 * Template tests for fallback generation
 */
const TEST_TEMPLATES = {
  login: [
    {
      title: 'Valid Login with Correct Credentials',
      category: TestCategory.HAPPY_PATH,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'navigate', target: 'login page' },
        { action: 'type', target: 'email field', value: 'yali.test@example.com' },
        { action: 'type', target: 'password field', value: 'ValidP@ss123' },
        { action: 'click', target: 'login button' }
      ],
      expectedResult: 'User is logged in and redirected to dashboard',
      source: 'Template: Login Happy Path'
    },
    {
      title: 'Invalid Email Format Rejected',
      category: TestCategory.VALIDATION,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'email field', value: 'invalid-email' },
        { action: 'click', target: 'login button' }
      ],
      expectedResult: 'Error message displays: "Please enter a valid email address"',
      source: 'Template: Login Validation'
    },
    {
      title: 'SQL Injection Prevention',
      category: TestCategory.SECURITY,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'type', target: 'email field', value: "' OR '1'='1" },
        { action: 'type', target: 'password field', value: "' OR '1'='1" },
        { action: 'click', target: 'login button' }
      ],
      expectedResult: 'Login fails with generic error. No SQL error exposed. No bypass.',
      source: 'Template: Login Security'
    },
    {
      title: 'XSS Prevention in Error Message',
      category: TestCategory.SECURITY,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'type', target: 'email field', value: '<script>alert("XSS")</script>' },
        { action: 'click', target: 'login button' }
      ],
      expectedResult: 'Script is escaped/sanitized. No alert popup. Safe error display.',
      source: 'Template: Login Security'
    },
    {
      title: 'Account Lockout After Failed Attempts',
      category: TestCategory.SECURITY,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'email field', value: 'test@example.com' },
        { action: 'type', target: 'password field', value: 'wrong1' },
        { action: 'click', target: 'login button' },
        { action: 'repeat', times: 5, note: 'Repeat failed login 5 times' }
      ],
      expectedResult: 'Account locked or CAPTCHA triggered after 5 failures',
      source: 'Template: Login Security'
    },
    {
      title: 'Empty Form Submission',
      category: TestCategory.NEGATIVE,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'click', target: 'login button', note: 'Without entering any data' }
      ],
      expectedResult: 'Validation errors shown for required fields',
      source: 'Template: Login Negative'
    }
  ],

  signup: [
    {
      title: 'Successful Registration',
      category: TestCategory.HAPPY_PATH,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'type', target: 'email field', value: 'newuser@example.com' },
        { action: 'type', target: 'password field', value: 'StrongP@ss123!' },
        { action: 'type', target: 'confirm password', value: 'StrongP@ss123!' },
        { action: 'click', target: 'register button' }
      ],
      expectedResult: 'Account created. Verification email sent.',
      source: 'Template: Signup Happy Path'
    },
    {
      title: 'Duplicate Email Prevention',
      category: TestCategory.NEGATIVE,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'email field', value: 'existing@example.com' },
        { action: 'complete form' },
        { action: 'click', target: 'register button' }
      ],
      expectedResult: 'Error: Email already registered. Offer login/reset link.',
      source: 'Template: Signup Negative'
    },
    {
      title: 'Weak Password Rejected',
      category: TestCategory.SECURITY,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'password field', value: '123456' }
      ],
      expectedResult: 'Password rejected as too weak. Requirements shown.',
      source: 'Template: Signup Security'
    }
  ],

  checkout: [
    {
      title: 'Successful Purchase Flow',
      category: TestCategory.HAPPY_PATH,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'verify', target: 'cart items displayed' },
        { action: 'type', target: 'card number', value: '4111111111111111' },
        { action: 'type', target: 'expiry', value: '12/28' },
        { action: 'type', target: 'cvv', value: '123' },
        { action: 'click', target: 'place order button' }
      ],
      expectedResult: 'Order placed. Confirmation number displayed. Email sent.',
      source: 'Template: Checkout Happy Path'
    },
    {
      title: 'Invalid Card Rejection',
      category: TestCategory.NEGATIVE,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'card number', value: '1234567890123456' }
      ],
      expectedResult: 'Card number invalid error displayed',
      source: 'Template: Checkout Validation'
    },
    {
      title: 'Price Tampering Prevention',
      category: TestCategory.SECURITY,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'intercept', target: 'checkout request' },
        { action: 'modify', target: 'price field', value: '0.01' },
        { action: 'submit', target: 'modified request' }
      ],
      expectedResult: 'Server validates price. Tampered request rejected.',
      source: 'Template: Checkout Security'
    }
  ],

  form: [
    {
      title: 'Form Submission with Valid Data',
      category: TestCategory.HAPPY_PATH,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'fill', target: 'all required fields' },
        { action: 'click', target: 'submit button' }
      ],
      expectedResult: 'Form submitted successfully. Confirmation shown.',
      source: 'Template: Form Happy Path'
    },
    {
      title: 'Required Field Validation',
      category: TestCategory.VALIDATION,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'leave', target: 'required fields empty' },
        { action: 'click', target: 'submit button' }
      ],
      expectedResult: 'Validation errors shown for each required field',
      source: 'Template: Form Validation'
    },
    {
      title: 'Maximum Length Boundary',
      category: TestCategory.BOUNDARY,
      priority: TestPriority.MEDIUM,
      steps: [
        { action: 'type', target: 'text field', value: 'a'.repeat(256) }
      ],
      expectedResult: 'Input truncated or error shown at boundary',
      source: 'Template: Form Boundary'
    }
  ],

  search: [
    {
      title: 'Basic Search Returns Results',
      category: TestCategory.HAPPY_PATH,
      priority: TestPriority.HIGH,
      steps: [
        { action: 'type', target: 'search field', value: 'test query' },
        { action: 'click', target: 'search button' }
      ],
      expectedResult: 'Relevant results displayed',
      source: 'Template: Search Happy Path'
    },
    {
      title: 'No Results Handling',
      category: TestCategory.EDGE_CASE,
      priority: TestPriority.MEDIUM,
      steps: [
        { action: 'type', target: 'search field', value: 'xyznonexistent123' }
      ],
      expectedResult: 'Friendly "No results found" message with suggestions',
      source: 'Template: Search Edge Case'
    },
    {
      title: 'SQL Injection in Search',
      category: TestCategory.SECURITY,
      priority: TestPriority.CRITICAL,
      steps: [
        { action: 'type', target: 'search field', value: "'; DROP TABLE products;--" }
      ],
      expectedResult: 'Query sanitized. No SQL error. Normal results or empty.',
      source: 'Template: Search Security'
    }
  ]
}

/**
 * Test Generator class
 */
class TestGenerator {
  constructor(options = {}) {
    this.callLLM = options.callLLM || null
    this.includeEdgeCases = options.includeEdgeCases !== false
    this.maxTests = options.maxTests || 10
  }

  /**
   * Generate tests for a page type
   */
  async generate(pageType, elements = [], userRequest = null) {
    const tests = []
    const sources = []

    // 1. Get knowledge from brain
    const brainSections = getForPageType(pageType)
    const brainTests = getTestsFromSections(brainSections)
    sources.push(...brainSections.map(s => s.cite ? s.cite() : s.title))

    // Convert brain tests to test cases
    for (const bt of brainTests.slice(0, 5)) {
      tests.push(createTestCase({
        title: bt.description,
        category: this._inferCategory(bt.description),
        priority: this._convertPriority(bt.priority),
        steps: [{ action: 'test', description: bt.description }],
        expectedResult: 'Requirement met as specified',
        source: bt.source
      }))
    }

    // 2. Get template tests
    const templates = TEST_TEMPLATES[pageType] || TEST_TEMPLATES.form
    for (const t of templates) {
      tests.push(createTestCase(t))
    }

    // 3. Add edge cases
    if (this.includeEdgeCases) {
      const edgeCases = this._generateEdgeCaseTests(pageType, elements)
      tests.push(...edgeCases)
    }

    // 4. If LLM available, enhance with generated tests
    if (this.callLLM && userRequest) {
      try {
        const llmTests = await this._generateWithLLM(pageType, elements, userRequest, brainSections)
        tests.push(...llmTests)
      } catch (e) {
        console.warn('LLM test generation failed:', e.message)
      }
    }

    // 5. Deduplicate and prioritize
    const uniqueTests = this._deduplicateTests(tests)
    const prioritized = prioritizeTests(uniqueTests, pageType)

    // Limit to max
    const finalTests = prioritized.slice(0, this.maxTests)

    return createTestSuite(`${pageType} Test Suite`, finalTests, {
      pageType,
      sources,
      generatedAt: new Date().toISOString()
    })
  }

  /**
   * Generate edge case tests based on elements
   */
  _generateEdgeCaseTests(pageType, elements) {
    const tests = []

    const inputs = elements.filter(e => e.category === 'text-input' || e.tag === 'input')

    for (const input of inputs.slice(0, 3)) {
      const fieldType = input.type || 'text'
      const fieldName = input.label || input.name || input.placeholder || 'field'
      const edgeCases = getEdgeCases(fieldType)

      // Add one edge case test per input
      if (edgeCases.length > 0) {
        tests.push(createTestCase({
          title: `Edge Case: ${fieldName} with ${fieldType} boundary`,
          category: TestCategory.EDGE_CASE,
          priority: TestPriority.MEDIUM,
          steps: [
            { action: 'type', target: fieldName, value: edgeCases[0] },
            { action: 'verify', target: 'validation behavior' }
          ],
          expectedResult: 'Field handles edge case gracefully',
          testData: { edgeCases: edgeCases.slice(0, 5) },
          source: 'Generated from element analysis'
        }))
      }
    }

    return tests
  }

  /**
   * Generate tests using LLM
   */
  async _generateWithLLM(pageType, elements, userRequest, brainSections) {
    const prompt = this._buildLLMPrompt(pageType, elements, userRequest, brainSections)

    const response = await this.callLLM([
      {
        role: 'system',
        content: `You are Yali, an expert QA engineer. Generate specific, actionable test cases.
Return ONLY valid JSON array of test cases. No explanations.`
      },
      { role: 'user', content: prompt }
    ], { maxTokens: 1500, temperature: 0.4 })

    // Parse response
    try {
      const content = response.content.trim()
      // Try to extract JSON array
      const jsonMatch = content.match(/\[[\s\S]*\]/)
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0])
        return parsed.map(t => createTestCase({
          ...t,
          source: 'LLM Generated'
        }))
      }
    } catch (e) {
      console.warn('Failed to parse LLM response:', e.message)
    }

    return []
  }

  /**
   * Build prompt for LLM
   */
  _buildLLMPrompt(pageType, elements, userRequest, brainSections) {
    const elementList = elements.slice(0, 15).map(e =>
      `- ${e.category || e.tag}: ${e.label || e.text || e.name || 'unnamed'}`
    ).join('\n')

    const brainKnowledge = brainSections.slice(0, 3).map(s =>
      `${s.title}: ${s.content.slice(0, 200)}...`
    ).join('\n\n')

    return `Generate 5 test cases for ${pageType} page.

USER REQUEST: ${userRequest || 'Comprehensive testing'}

PAGE ELEMENTS:
${elementList}

QA KNOWLEDGE:
${brainKnowledge}

Return JSON array:
[
  {
    "title": "Test name",
    "category": "security|validation|happy_path|edge_case|negative",
    "priority": "P0|P1|P2|P3",
    "steps": [{"action": "click/type/verify", "target": "element", "value": "data"}],
    "expectedResult": "What should happen"
  }
]

Use REAL test data (emails, passwords, etc.). Focus on security and edge cases.`
  }

  /**
   * Deduplicate tests by title similarity
   */
  _deduplicateTests(tests) {
    const seen = new Set()
    const unique = []

    for (const test of tests) {
      const key = test.title.toLowerCase().replace(/[^a-z0-9]/g, '')
      if (!seen.has(key)) {
        seen.add(key)
        unique.push(test)
      }
    }

    return unique
  }

  /**
   * Infer category from description
   */
  _inferCategory(description) {
    const desc = description.toLowerCase()
    if (/security|injection|xss|csrf|auth/i.test(desc)) return TestCategory.SECURITY
    if (/valid/i.test(desc)) return TestCategory.VALIDATION
    if (/edge|boundary|limit/i.test(desc)) return TestCategory.EDGE_CASE
    if (/error|fail|invalid/i.test(desc)) return TestCategory.NEGATIVE
    if (/access|keyboard|screen reader/i.test(desc)) return TestCategory.ACCESSIBILITY
    return TestCategory.HAPPY_PATH
  }

  /**
   * Convert priority string to enum
   */
  _convertPriority(priority) {
    const map = {
      critical: TestPriority.CRITICAL,
      high: TestPriority.HIGH,
      medium: TestPriority.MEDIUM,
      low: TestPriority.LOW
    }
    return map[priority?.toLowerCase()] || TestPriority.MEDIUM
  }
}

/**
 * Quick test generation
 */
async function quickGenerate(pageType, elements = [], callLLM = null) {
  const generator = new TestGenerator({ callLLM })
  return generator.generate(pageType, elements)
}

module.exports = {
  TestCategory,
  TestPriority,
  TestGenerator,
  TEST_TEMPLATES,
  createTestCase,
  createTestSuite,
  quickGenerate
}
