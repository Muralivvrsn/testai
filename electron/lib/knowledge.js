/**
 * QA Knowledge Base - Ported from testai-agent/QA_BRAIN.md
 * Structured knowledge with citation support
 * ~400 lines
 */

/**
 * Knowledge sections with IDs for citation
 */
const KNOWLEDGE = {
  // Section 1: Input Validation
  'input-validation': {
    id: '1',
    title: 'Input Validation',
    rules: [
      'Validate on client AND server (client for UX, server for security)',
      'Use allowlists over denylists where possible',
      'Sanitize output, not just input',
      'Fail securely - reject invalid input by default'
    ]
  },

  'text-validation': {
    id: '1.1',
    title: 'Text Field Validation',
    tests: [
      { name: 'Empty input submission', priority: 'high' },
      { name: 'Maximum length boundary (exact limit, limit+1)', priority: 'high' },
      { name: 'Minimum length boundary (exact limit, limit-1)', priority: 'medium' },
      { name: 'Special characters: < > " \' & / \\ | ; : @ # $ % ^ * ( ) { } [ ]', priority: 'high' },
      { name: 'Unicode: emojis, RTL text, zero-width characters', priority: 'medium' },
      { name: 'SQL injection: \' OR \'1\'=\'1, "; DROP TABLE--', priority: 'critical' },
      { name: 'XSS: <script>alert(1)</script>', priority: 'critical' },
      { name: 'Whitespace: leading/trailing spaces, tabs, newlines', priority: 'medium' },
      { name: 'Very long input (10,000+ characters)', priority: 'medium' }
    ]
  },

  'numeric-validation': {
    id: '1.2',
    title: 'Numeric Input Validation',
    tests: [
      { name: 'Zero value', priority: 'high' },
      { name: 'Negative numbers', priority: 'high' },
      { name: 'Decimal precision limits', priority: 'medium' },
      { name: 'Integer overflow: MAX_INT + 1', priority: 'medium' },
      { name: 'Non-numeric input in numeric fields', priority: 'high' },
      { name: 'Currency formats: $100, 100.00', priority: 'medium' }
    ]
  },

  // Section 2: Security Testing
  'sql-injection': {
    id: '2.1',
    title: 'SQL Injection',
    attackVectors: [
      "Classic: ' OR '1'='1' --",
      "Union-based: ' UNION SELECT username, password FROM users --",
      "Blind Boolean: ' AND 1=1 -- vs ' AND 1=2 --",
      "Time-based: '; WAITFOR DELAY '0:0:5' --"
    ],
    testPoints: [
      'All form inputs',
      'URL parameters',
      'HTTP headers (User-Agent, Referer, Cookie)',
      'JSON/XML body parameters',
      'Search functionality'
    ]
  },

  'xss': {
    id: '2.2',
    title: 'Cross-Site Scripting (XSS)',
    types: ['Reflected XSS', 'Stored XSS', 'DOM-based XSS'],
    payloads: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "javascript:alert('XSS')"
    ]
  },

  'authentication': {
    id: '2.4',
    title: 'Authentication Testing',
    tests: [
      { name: 'Brute force protection (account lockout)', priority: 'critical' },
      { name: 'Password complexity requirements', priority: 'high' },
      { name: 'Password reset flow vulnerabilities', priority: 'high' },
      { name: 'Session timeout', priority: 'high' },
      { name: 'Concurrent session handling', priority: 'medium' },
      { name: 'Username enumeration via timing', priority: 'high' }
    ]
  },

  'authorization': {
    id: '2.5',
    title: 'Authorization Testing',
    tests: [
      { name: 'Horizontal privilege escalation', priority: 'critical' },
      { name: 'Vertical privilege escalation', priority: 'critical' },
      { name: 'IDOR (Insecure Direct Object Reference)', priority: 'critical' },
      { name: 'Missing function-level access control', priority: 'high' },
      { name: 'API endpoint authorization', priority: 'high' }
    ]
  },

  // Section 3: Functional Testing
  'form-submission': {
    id: '3.1',
    title: 'Form Submission',
    tests: [
      { name: 'Successful submission with valid data', priority: 'critical' },
      { name: 'Error handling with invalid data', priority: 'high' },
      { name: 'Form persistence after validation error', priority: 'medium' },
      { name: 'Double-click submission prevention', priority: 'high' },
      { name: 'Back button behavior after submission', priority: 'medium' },
      { name: 'Required field validation', priority: 'high' }
    ]
  },

  'search': {
    id: '3.3',
    title: 'Search Functionality',
    tests: [
      { name: 'Exact match search', priority: 'high' },
      { name: 'Partial match search', priority: 'high' },
      { name: 'Case insensitivity', priority: 'medium' },
      { name: 'Special character handling', priority: 'high' },
      { name: 'No results messaging', priority: 'medium' },
      { name: 'Pagination of results', priority: 'medium' }
    ]
  },

  // Section 4: Accessibility
  'accessibility': {
    id: '4.3',
    title: 'Accessibility (WCAG 2.1)',
    tests: [
      { name: 'Keyboard navigation (Tab order)', priority: 'high' },
      { name: 'Screen reader compatibility', priority: 'high' },
      { name: 'Alt text for images', priority: 'high' },
      { name: 'Form labels and ARIA attributes', priority: 'high' },
      { name: 'Color contrast (4.5:1 for text)', priority: 'medium' },
      { name: 'Focus indicators', priority: 'high' }
    ]
  },

  // Section 7: Login Page
  'login-email': {
    id: '7.1',
    title: 'Login Email Validation',
    tests: [
      { name: 'Valid email formats', priority: 'high' },
      { name: 'Invalid emails: user@, @domain.com', priority: 'high' },
      { name: 'Case insensitivity', priority: 'medium' },
      { name: 'Maximum length (254 chars)', priority: 'medium' },
      { name: 'SQL injection in email field', priority: 'critical' },
      { name: 'XSS in email field', priority: 'critical' }
    ]
  },

  'login-password': {
    id: '7.2',
    title: 'Login Password Validation',
    tests: [
      { name: 'Minimum length requirement', priority: 'high' },
      { name: 'Maximum length (some limit to 72/128)', priority: 'medium' },
      { name: 'Complexity requirements', priority: 'high' },
      { name: 'Common password rejection', priority: 'high' },
      { name: 'Password visibility toggle', priority: 'medium' }
    ]
  },

  'login-flow': {
    id: '7.3',
    title: 'Login Flow',
    tests: [
      { name: 'Successful login redirect', priority: 'critical' },
      { name: 'Failed login messaging', priority: 'high' },
      { name: 'Account lockout after failed attempts', priority: 'critical' },
      { name: 'Remember me functionality', priority: 'medium' },
      { name: 'Session creation security', priority: 'high' }
    ]
  },

  // Section 8: Checkout/Payment
  'checkout-cart': {
    id: '8.1',
    title: 'Cart Functionality',
    tests: [
      { name: 'Add to cart', priority: 'critical' },
      { name: 'Update quantity', priority: 'high' },
      { name: 'Remove item', priority: 'high' },
      { name: 'Cart persistence', priority: 'high' },
      { name: 'Stock validation', priority: 'critical' },
      { name: 'Price updates', priority: 'critical' }
    ]
  },

  'checkout-payment': {
    id: '8.2',
    title: 'Payment Processing',
    tests: [
      { name: 'Valid card acceptance', priority: 'critical' },
      { name: 'Invalid card rejection', priority: 'critical' },
      { name: 'Expired card handling', priority: 'high' },
      { name: 'Insufficient funds', priority: 'high' },
      { name: 'Double payment prevention', priority: 'critical' },
      { name: 'Refund flow', priority: 'high' }
    ]
  }
}

/**
 * Edge cases by input type
 */
const EDGE_CASES = {
  email: [
    { value: '', description: 'Empty email' },
    { value: 'test', description: 'Missing @ and domain' },
    { value: 'test@', description: 'Missing domain' },
    { value: '@domain.com', description: 'Missing local part' },
    { value: 'test@domain', description: 'Missing TLD' },
    { value: "test'or'1'='1@domain.com", description: 'SQL injection attempt' },
    { value: '<script>alert(1)</script>@test.com', description: 'XSS attempt' }
  ],
  password: [
    { value: '', description: 'Empty password' },
    { value: 'a', description: 'Single character' },
    { value: 'password', description: 'Common weak password' },
    { value: 'a'.repeat(100), description: 'Very long password' },
    { value: "'; DROP TABLE users;--", description: 'SQL injection attempt' }
  ],
  text: [
    { value: '', description: 'Empty string' },
    { value: '   ', description: 'Only whitespace' },
    { value: 'a'.repeat(1000), description: 'Very long text' },
    { value: '🎉🚀💻', description: 'Emoji characters' },
    { value: '日本語テスト', description: 'Unicode characters' },
    { value: '<script>alert(1)</script>', description: 'XSS attempt' },
    { value: '../../../etc/passwd', description: 'Path traversal attempt' }
  ],
  number: [
    { value: '', description: 'Empty' },
    { value: '0', description: 'Zero' },
    { value: '-1', description: 'Negative number' },
    { value: '999999999999', description: 'Very large number' },
    { value: 'abc', description: 'Non-numeric input' },
    { value: 'NaN', description: 'Not a number' }
  ]
}

/**
 * Test data generators
 */
const TEST_DATA = {
  validEmail: () => `test.${Date.now()}@example.com`,
  validPassword: () => 'TestPass123!',
  validPhone: () => '555-123-4567',
  validName: () => 'Test User',
  validCreditCard: () => '4111111111111111',
  validCVV: () => '123',
  validExpiry: () => '12/25'
}

/**
 * Get knowledge for a specific section
 */
function getKnowledge(sectionId) {
  return KNOWLEDGE[sectionId] || null
}

/**
 * Get all knowledge for a page type
 */
function getKnowledgeForPageType(pageType) {
  const mapping = {
    login: ['login-email', 'login-password', 'login-flow', 'sql-injection', 'xss'],
    signup: ['text-validation', 'authentication', 'form-submission'],
    checkout: ['checkout-cart', 'checkout-payment', 'numeric-validation'],
    search: ['search', 'text-validation', 'xss'],
    form: ['form-submission', 'text-validation', 'accessibility'],
    dashboard: ['authorization', 'authentication'],
    settings: ['form-submission', 'authentication']
  }

  const sections = mapping[pageType] || ['text-validation', 'form-submission']
  return sections.map(id => KNOWLEDGE[id]).filter(Boolean)
}

/**
 * Get edge cases for input type
 */
function getEdgeCases(inputType) {
  return EDGE_CASES[inputType] || EDGE_CASES.text
}

/**
 * Generate test data
 */
function generateTestData(type) {
  const generator = TEST_DATA[type]
  return generator ? generator() : ''
}

/**
 * Format knowledge for AI prompt
 */
function formatKnowledgeForPrompt(sections) {
  let output = 'QA KNOWLEDGE BASE:\n\n'

  sections.forEach(section => {
    output += `[Section ${section.id}] ${section.title}\n`

    if (section.tests) {
      section.tests.forEach(test => {
        output += `- ${test.name} (${test.priority})\n`
      })
    }

    if (section.rules) {
      section.rules.forEach(rule => {
        output += `- ${rule}\n`
      })
    }

    output += '\n'
  })

  return output
}

module.exports = {
  KNOWLEDGE,
  EDGE_CASES,
  TEST_DATA,
  getKnowledge,
  getKnowledgeForPageType,
  getEdgeCases,
  generateTestData,
  formatKnowledgeForPrompt
}
