/**
 * QA Knowledge Base
 * ~180 lines
 */

const RULES = {
  login: [
    { id: 'login-001', rule: 'Verify successful login redirects properly', priority: 'critical' },
    { id: 'login-002', rule: 'Test invalid credentials show appropriate error', priority: 'critical' },
    { id: 'login-003', rule: 'Check empty field validation', priority: 'high' },
    { id: 'login-004', rule: 'Verify password field masks input', priority: 'high' },
    { id: 'login-005', rule: 'Test forgot password link works', priority: 'medium' }
  ],
  signup: [
    { id: 'signup-001', rule: 'All required fields must be validated', priority: 'critical' },
    { id: 'signup-002', rule: 'Email format validation', priority: 'critical' },
    { id: 'signup-003', rule: 'Password strength requirements shown', priority: 'high' },
    { id: 'signup-004', rule: 'Terms and conditions checkbox required', priority: 'high' }
  ],
  checkout: [
    { id: 'checkout-001', rule: 'Card number validation (format, length)', priority: 'critical' },
    { id: 'checkout-002', rule: 'Expiry date validation', priority: 'critical' },
    { id: 'checkout-003', rule: 'CVV field masks input', priority: 'high' },
    { id: 'checkout-004', rule: 'Order total calculated correctly', priority: 'critical' },
    { id: 'checkout-005', rule: 'Billing address validation', priority: 'high' }
  ],
  search: [
    { id: 'search-001', rule: 'Empty search shows appropriate message', priority: 'high' },
    { id: 'search-002', rule: 'Results display correctly', priority: 'critical' },
    { id: 'search-003', rule: 'No results shows helpful message', priority: 'medium' },
    { id: 'search-004', rule: 'Special characters handled safely', priority: 'high' }
  ],
  form: [
    { id: 'form-001', rule: 'Required fields marked and validated', priority: 'critical' },
    { id: 'form-002', rule: 'Submit button disabled until valid', priority: 'medium' },
    { id: 'form-003', rule: 'Success confirmation shown', priority: 'high' },
    { id: 'form-004', rule: 'Error messages clear and helpful', priority: 'high' }
  ],
  general: [
    { id: 'gen-001', rule: 'Page loads without errors', priority: 'critical' },
    { id: 'gen-002', rule: 'Navigation works correctly', priority: 'high' },
    { id: 'gen-003', rule: 'Responsive on different screen sizes', priority: 'medium' },
    { id: 'gen-004', rule: 'No console errors', priority: 'medium' }
  ]
}

const EDGE_CASES = {
  text_input: [
    { type: 'empty', value: '', description: 'Empty input' },
    { type: 'whitespace', value: '   ', description: 'Only whitespace' },
    { type: 'long', value: 'a'.repeat(500), description: 'Very long text' },
    { type: 'special', value: '<script>alert(1)</script>', description: 'XSS attempt' },
    { type: 'unicode', value: '测试 🎉 émojis', description: 'Unicode characters' },
    { type: 'sql', value: "'; DROP TABLE users;--", description: 'SQL injection' }
  ],
  email: [
    { type: 'invalid', value: 'notanemail', description: 'Missing @' },
    { type: 'nodomain', value: 'test@', description: 'No domain' },
    { type: 'spaces', value: 'test @email.com', description: 'Contains space' }
  ],
  password: [
    { type: 'short', value: '123', description: 'Too short' },
    { type: 'nospecial', value: 'password123', description: 'No special chars' },
    { type: 'common', value: 'password', description: 'Common password' }
  ],
  number: [
    { type: 'negative', value: '-1', description: 'Negative number' },
    { type: 'decimal', value: '1.5', description: 'Decimal' },
    { type: 'text', value: 'abc', description: 'Non-numeric' },
    { type: 'large', value: '99999999999', description: 'Very large number' }
  ]
}

/**
 * Get QA rules for page type
 */
function getKnowledge(pageType) {
  return RULES[pageType] || RULES.general
}

/**
 * Get edge cases for input type
 */
function getEdgeCases(inputType) {
  return EDGE_CASES[inputType] || EDGE_CASES.text_input
}

/**
 * Generate test cases for page
 */
function generateTests(pageType, elements) {
  const rules = getKnowledge(pageType)
  const tests = []

  // Generate tests from rules
  rules.forEach(rule => {
    tests.push({
      id: rule.id,
      title: rule.rule,
      priority: rule.priority,
      category: 'functional',
      steps: [],
      expectedResult: 'Verify ' + rule.rule.toLowerCase()
    })
  })

  // Add edge case tests for inputs
  const inputs = elements.filter(e => e.category === 'text-input')
  inputs.slice(0, 3).forEach(input => {
    const edgeCases = getEdgeCases(input.type || 'text_input')
    edgeCases.slice(0, 3).forEach(edge => {
      tests.push({
        id: `edge-${input.id}-${edge.type}`,
        title: `${input.label || input.name || 'Input'}: ${edge.description}`,
        priority: 'medium',
        category: 'edge',
        steps: [
          { action: 'type', element: input.id, value: edge.value }
        ],
        expectedResult: 'Handles edge case gracefully'
      })
    })
  })

  return {
    pageType,
    tests,
    coverage: {
      percentage: Math.min(100, tests.length * 10),
      rulesCovered: rules.length,
      totalRules: rules.length
    }
  }
}

/**
 * Get focus areas for testing
 */
function getFocusAreas(pageType) {
  const areas = {
    login: ['Authentication flow', 'Error handling', 'Security'],
    signup: ['Validation', 'User feedback', 'Required fields'],
    checkout: ['Payment validation', 'Order calculation', 'Error states'],
    search: ['Results display', 'Empty states', 'Input handling'],
    form: ['Validation', 'Submission', 'Error messages']
  }
  return areas[pageType] || ['General functionality', 'User experience']
}

module.exports = {
  RULES,
  EDGE_CASES,
  getKnowledge,
  getEdgeCases,
  generateTests,
  getFocusAreas
}
