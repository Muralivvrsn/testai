/**
 * Yali Agent - Edge Case Detection
 * Ported from testai-agent/understanding/edge_cases.py
 *
 * Automatically identifies edge cases that humans often miss.
 * This is where we beat human QA - pattern recognition at scale.
 *
 * Edge Case Categories:
 * 1. Boundary conditions (min/max values)
 * 2. State transitions (empty → filled, logged out → in)
 * 3. Timing issues (race conditions, timeouts)
 * 4. Data edge cases (unicode, special chars, injection)
 * 5. User behavior patterns (multi-tab, back button)
 * 6. Integration points (third-party failures, API timeouts)
 */

/**
 * Categories of edge cases
 */
const EdgeCaseCategory = {
  BOUNDARY: 'boundary',           // Min/max values, limits
  STATE: 'state',                 // State transitions
  TIMING: 'timing',               // Race conditions, timeouts
  DATA: 'data',                   // Special characters, injection
  BEHAVIOR: 'behavior',           // User behavior patterns
  INTEGRATION: 'integration',     // External dependencies
  SECURITY: 'security',           // Security-specific edge cases
  ACCESSIBILITY: 'accessibility'  // A11y edge cases
}

/**
 * Create an edge case
 */
function createEdgeCase(title, description, category, severity, testSuggestion, testData = null) {
  return {
    title,
    description,
    category,
    severity,
    testSuggestion,
    testData
  }
}

/**
 * Create an edge case analysis result
 */
function createEdgeCaseAnalysis(feature, pageType, edgeCases = [], coverageScore = 0) {
  return {
    feature,
    pageType,
    edgeCases,
    coverageScore,

    criticalCount() {
      return this.edgeCases.filter(ec => ec.severity === 'critical').length
    },

    byCategory() {
      const result = {}
      for (const ec of this.edgeCases) {
        if (!result[ec.category]) {
          result[ec.category] = []
        }
        result[ec.category].push(ec)
      }
      return result
    }
  }
}

/**
 * Universal edge cases that apply to almost any feature
 */
const UNIVERSAL_EDGE_CASES = [
  createEdgeCase(
    'Empty state handling',
    "What happens when there's no data?",
    EdgeCaseCategory.STATE,
    'medium',
    'Navigate to the feature with no prior data and verify graceful empty state'
  ),
  createEdgeCase(
    'Double-click/double-submit',
    'Rapidly clicking buttons can cause duplicate submissions',
    EdgeCaseCategory.BEHAVIOR,
    'high',
    'Click the primary action button multiple times rapidly'
  ),
  createEdgeCase(
    'Browser back button after submission',
    'Using back after form submit can cause re-submission issues',
    EdgeCaseCategory.BEHAVIOR,
    'medium',
    'Complete an action, press browser back, observe behavior'
  ),
  createEdgeCase(
    'Session timeout during interaction',
    'What if the session expires while user is filling a form?',
    EdgeCaseCategory.TIMING,
    'medium',
    'Start an action, wait for session to expire, try to complete'
  ),
  createEdgeCase(
    'Network interruption',
    'What if network drops mid-request?',
    EdgeCaseCategory.INTEGRATION,
    'high',
    'Use DevTools to simulate offline mode during submission'
  ),
  createEdgeCase(
    'Slow network response',
    'UI should handle slow responses gracefully',
    EdgeCaseCategory.TIMING,
    'medium',
    'Throttle network to slow 3G and observe loading states'
  )
]

/**
 * Page-type specific edge case patterns
 */
const PAGE_EDGE_CASES = {
  login: [
    createEdgeCase('Email with plus sign (aliases)', 'Email aliases like user+test@mail.com should work', EdgeCaseCategory.DATA, 'medium', "Login with 'user+alias@company.com'", { email: 'user+alias@company.com' }),
    createEdgeCase('Password with special characters', 'Passwords with !@#$%^&*() should be accepted', EdgeCaseCategory.DATA, 'high', "Create account with password 'P@ss!w0rd#2024'", { password: 'P@ss!w0rd#2024' }),
    createEdgeCase('Unicode in password', 'Emoji and international chars in password', EdgeCaseCategory.DATA, 'medium', "Test password with emoji: 'Secure🔐Pass日本語'", { password: 'Secure🔐Pass日本語' }),
    createEdgeCase('Copy-paste password', 'Users should be able to paste passwords (for password managers)', EdgeCaseCategory.BEHAVIOR, 'high', 'Copy password to clipboard and paste into field'),
    createEdgeCase('Remember me on public computer', "'Remember me' warning for shared computers", EdgeCaseCategory.SECURITY, 'medium', "Check if 'remember me' shows security warning"),
    createEdgeCase('Multiple login tabs', 'Logging in from multiple tabs simultaneously', EdgeCaseCategory.STATE, 'high', 'Open login in 2 tabs, login in one, observe other'),
    createEdgeCase('Account lockout timing', 'Account lockout after N failed attempts', EdgeCaseCategory.SECURITY, 'critical', 'Try 5 wrong passwords, then try correct one'),
    createEdgeCase('Case sensitivity in email', 'Email should be case-insensitive', EdgeCaseCategory.DATA, 'medium', "Login with 'USER@Email.COM' for account 'user@email.com'")
  ],

  signup: [
    createEdgeCase('Very long name', 'Names can be 100+ characters in some cultures', EdgeCaseCategory.BOUNDARY, 'low', 'Enter 100-character name', { name: 'A'.repeat(100) }),
    createEdgeCase('Name with special characters', "O'Brien, José, Müller should all work", EdgeCaseCategory.DATA, 'high', "Register with name: O'Brien-Müller", { name: "O'Brien-Müller" }),
    createEdgeCase('Already registered email', 'Clear error for duplicate email', EdgeCaseCategory.STATE, 'high', 'Try to register with existing email'),
    createEdgeCase('Password confirmation mismatch', "Passwords don't match should show clear error", EdgeCaseCategory.DATA, 'high', 'Enter different passwords in password and confirm fields'),
    createEdgeCase('Terms checkbox required', 'Submitting without accepting terms', EdgeCaseCategory.STATE, 'high', 'Fill all fields but leave terms unchecked, submit'),
    createEdgeCase('Email verification timeout', 'What if user clicks verification link after it expires?', EdgeCaseCategory.TIMING, 'medium', 'Wait for verification link to expire, then click it'),
    createEdgeCase('Weak password feedback', 'Real-time password strength indicator', EdgeCaseCategory.DATA, 'medium', "Enter '123456' and verify strength indicator shows weak")
  ],

  checkout: [
    createEdgeCase('Item goes out of stock during checkout', 'Cart item becomes unavailable mid-checkout', EdgeCaseCategory.STATE, 'critical', 'Start checkout, have another user buy last item, complete checkout'),
    createEdgeCase('Price change during checkout', 'Price updates while user is checking out', EdgeCaseCategory.STATE, 'critical', 'Start checkout, change price in admin, complete checkout'),
    createEdgeCase('Coupon code expired', 'Using an expired coupon code', EdgeCaseCategory.TIMING, 'high', "Apply coupon 'EXPIRED2023' and verify error message", { coupon: 'EXPIRED2023' }),
    createEdgeCase('Coupon already used (single-use)', 'Trying to use a single-use coupon twice', EdgeCaseCategory.STATE, 'high', 'Apply same single-use coupon on second order'),
    createEdgeCase('Payment timeout', 'Payment processor takes too long', EdgeCaseCategory.TIMING, 'critical', "Simulate slow payment response, verify UI doesn't freeze"),
    createEdgeCase('Double order submission', "Clicking 'Place Order' twice quickly", EdgeCaseCategory.BEHAVIOR, 'critical', 'Click Place Order rapidly, verify only one order created'),
    createEdgeCase('International address format', 'Addresses outside US have different formats', EdgeCaseCategory.DATA, 'medium', "Enter UK address with postcode: 'SW1A 1AA'", { address: '10 Downing Street, London, SW1A 1AA, UK' }),
    createEdgeCase('Tax calculation changes', 'Shipping address change affects tax', EdgeCaseCategory.STATE, 'high', 'Enter CA address, change to OR (no sales tax), verify tax updates')
  ],

  search: [
    createEdgeCase('Search with only spaces', 'Searching for just whitespace', EdgeCaseCategory.DATA, 'medium', "Enter '     ' and submit search", { query: '     ' }),
    createEdgeCase('Very long search query', 'Search with 1000+ characters', EdgeCaseCategory.BOUNDARY, 'low', 'Paste a 1000-character string into search', { query: 'a'.repeat(1000) }),
    createEdgeCase('Search with quotes', 'Exact phrase search with quotes', EdgeCaseCategory.DATA, 'medium', "Search for '\"exact phrase\"' with quotes"),
    createEdgeCase('Search with boolean operators', 'Using AND, OR, NOT in search', EdgeCaseCategory.DATA, 'low', "Search for 'blue AND shoes NOT sneakers'"),
    createEdgeCase('Rapid search queries', 'Typing fast with autocomplete', EdgeCaseCategory.TIMING, 'medium', 'Type quickly and verify debouncing works'),
    createEdgeCase('Search result pagination edge', 'Exactly at page boundary (10, 20, etc.)', EdgeCaseCategory.BOUNDARY, 'low', 'Search for something with exactly 20 results, verify pagination'),
    createEdgeCase('Zero results state', 'No results should show helpful message', EdgeCaseCategory.STATE, 'high', "Search for 'xyznonexistent123'")
  ],

  settings: [
    createEdgeCase('Unsaved changes warning', 'Navigating away with unsaved changes', EdgeCaseCategory.BEHAVIOR, 'high', "Make changes, don't save, click away, verify warning"),
    createEdgeCase('Concurrent settings changes', 'Same user changing settings in two tabs', EdgeCaseCategory.STATE, 'medium', 'Open settings in 2 tabs, make different changes, save both'),
    createEdgeCase('Change email to existing email', "Changing email to one that's already registered", EdgeCaseCategory.STATE, 'high', "Try to change email to another user's email"),
    createEdgeCase('Password change without current password', 'Security: must verify identity before password change', EdgeCaseCategory.SECURITY, 'critical', 'Try to change password without entering current password'),
    createEdgeCase('Delete account data retention', 'What data is kept after account deletion?', EdgeCaseCategory.SECURITY, 'high', 'Delete account, check if any data remains accessible')
  ],

  profile: [
    createEdgeCase('Profile picture with transparency', 'PNG with transparent background', EdgeCaseCategory.DATA, 'low', 'Upload PNG with alpha channel, verify display'),
    createEdgeCase('Profile picture with EXIF rotation', 'Photo rotated via EXIF metadata', EdgeCaseCategory.DATA, 'medium', 'Upload phone photo, verify correct orientation'),
    createEdgeCase('Empty bio allowed', 'Bio should be optional', EdgeCaseCategory.STATE, 'low', 'Clear bio completely and save'),
    createEdgeCase('Links in bio', 'URLs in bio should be handled safely', EdgeCaseCategory.SECURITY, 'high', "Enter 'javascript:alert(1)' as website URL", { bio_link: 'javascript:alert(1)' }),
    createEdgeCase('Profile URL with special characters', 'Username with dashes, underscores in URL', EdgeCaseCategory.DATA, 'medium', "Create user 'test-user_123' and verify profile URL works")
  ],

  form: [
    createEdgeCase('Tab order for accessibility', 'Tab key should navigate form logically', EdgeCaseCategory.ACCESSIBILITY, 'high', 'Press Tab repeatedly, verify logical order'),
    createEdgeCase('Form auto-fill', 'Browser auto-fill should work correctly', EdgeCaseCategory.BEHAVIOR, 'medium', 'Let browser auto-fill form, verify all fields populate'),
    createEdgeCase('Required field indicator', 'Required fields should be clearly marked', EdgeCaseCategory.ACCESSIBILITY, 'high', "Verify * or 'required' label on mandatory fields"),
    createEdgeCase('Error focus management', 'On error, focus should move to first error field', EdgeCaseCategory.ACCESSIBILITY, 'high', 'Submit with errors, verify focus moves to error field'),
    createEdgeCase('Paste into all fields', 'Pasting should work in all text fields', EdgeCaseCategory.BEHAVIOR, 'medium', 'Try pasting text into each field')
  ],

  dashboard: [
    createEdgeCase('Widget load failure', 'One widget fails, others should still work', EdgeCaseCategory.INTEGRATION, 'high', "Block one widget's API call, verify others load"),
    createEdgeCase('Stale data indicator', 'Show when data was last updated', EdgeCaseCategory.STATE, 'low', "Check for 'last updated' timestamp on widgets"),
    createEdgeCase('Dashboard on mobile', 'Dashboard should be usable on small screens', EdgeCaseCategory.ACCESSIBILITY, 'medium', 'View dashboard at 375px width'),
    createEdgeCase('Real-time updates', 'Data should refresh without manual action', EdgeCaseCategory.STATE, 'medium', 'Wait for auto-refresh interval, verify data updates')
  ]
}

/**
 * Input field patterns and their edge cases
 */
const INPUT_PATTERNS = {
  email: [
    ['Plus sign in email', 'user+test@company.com'],
    ['Very long email', 'a'.repeat(64) + '@company.com'],
    ['Subdomain email', 'user@mail.company.co.uk'],
    ['Numbers in local part', 'user123@company.com']
  ],
  password: [
    ['All special characters', '!@#$%^&*()_+-='],
    ['Unicode characters', 'Пароль日本語🔐'],
    ['255 characters', 'a'.repeat(255)],
    ['Space in password', 'pass word 123']
  ],
  phone: [
    ['International format', '+44 20 7946 0958'],
    ['With extension', '555-123-4567 ext. 890'],
    ['Letters (vanity)', '1-800-FLOWERS']
  ],
  name: [
    ['Apostrophe', "O'Brien"],
    ['Hyphen', 'Mary-Jane'],
    ['Unicode', 'José García-Müller'],
    ['Single character', 'X']
  ],
  url: [
    ['With port', 'http://localhost:3000'],
    ['IP address', 'http://192.168.1.1'],
    ['Unicode domain', 'http://münchen.de'],
    ['Query string', 'https://site.com?foo=bar&baz=qux']
  ],
  number: [
    ['Negative', '-1'],
    ['Zero', '0'],
    ['Decimal', '3.14159'],
    ['Scientific notation', '1e10'],
    ['Leading zeros', '007']
  ]
}

/**
 * Edge Case Detector class
 */
class EdgeCaseDetector {
  constructor() {
    // Store references to constants
    this.universalEdgeCases = UNIVERSAL_EDGE_CASES
    this.pageEdgeCases = PAGE_EDGE_CASES
    this.inputPatterns = INPUT_PATTERNS
  }

  /**
   * Get edge cases for a specific page type
   */
  analyzePageType(pageType) {
    const edgeCases = [...this.universalEdgeCases] // Start with universal

    // Add page-specific
    const pageSpecific = this.pageEdgeCases[pageType.toLowerCase()] || []
    edgeCases.push(...pageSpecific)

    // Calculate coverage score
    const totalPatterns = this.universalEdgeCases.length + (this.pageEdgeCases[pageType.toLowerCase()]?.length || 0)
    const coverage = edgeCases.length / Math.max(totalPatterns, 1)

    return createEdgeCaseAnalysis(
      `${pageType.charAt(0).toUpperCase() + pageType.slice(1)} page`,
      pageType,
      edgeCases,
      coverage
    )
  }

  /**
   * Analyze elements to detect relevant edge cases
   */
  analyzeElements(elements, pageType = null) {
    const edgeCases = [...this.universalEdgeCases]
    const detectedInputTypes = new Set()

    // Analyze each element
    for (const el of elements) {
      const elType = (el.type || el.elementType || '').toLowerCase()
      const elName = (el.name || el.id || '').toLowerCase()
      const placeholder = (el.placeholder || '').toLowerCase()

      // Detect input types
      if (['email', 'password', 'tel', 'url', 'number'].includes(elType)) {
        detectedInputTypes.add(elType === 'tel' ? 'phone' : elType)
      } else if (elName.includes('email') || placeholder.includes('email')) {
        detectedInputTypes.add('email')
      } else if (elName.includes('password') || placeholder.includes('password')) {
        detectedInputTypes.add('password')
      } else if (elName.includes('phone') || placeholder.includes('phone') || elName.includes('tel')) {
        detectedInputTypes.add('phone')
      } else if (elName.includes('name') || placeholder.includes('name')) {
        detectedInputTypes.add('name')
      } else if (elName.includes('url') || elName.includes('website')) {
        detectedInputTypes.add('url')
      }
    }

    // Add edge cases for detected input types
    for (const inputType of detectedInputTypes) {
      const patterns = this.inputPatterns[inputType] || []
      for (const [title, testValue] of patterns) {
        edgeCases.push(createEdgeCase(
          `${inputType.charAt(0).toUpperCase() + inputType.slice(1)} field: ${title}`,
          `Test ${inputType} field with: ${testValue.slice(0, 50)}...`,
          EdgeCaseCategory.DATA,
          'medium',
          `Enter '${testValue}' in ${inputType} field`,
          { [inputType]: testValue }
        ))
      }
    }

    // Add page-specific if known
    if (pageType) {
      const pageSpecific = this.pageEdgeCases[pageType.toLowerCase()] || []
      edgeCases.push(...pageSpecific)
    }

    return createEdgeCaseAnalysis(
      'Analyzed page',
      pageType,
      edgeCases,
      Math.min(1.0, edgeCases.length / 20)
    )
  }

  /**
   * Get only critical edge cases
   */
  getCriticalEdgeCases(pageType = null) {
    let analysis
    if (pageType) {
      analysis = this.analyzePageType(pageType)
    } else {
      // Return critical cases from all page types
      const allCases = []
      for (const cases of Object.values(this.pageEdgeCases)) {
        allCases.push(...cases)
      }
      allCases.push(...this.universalEdgeCases)
      analysis = createEdgeCaseAnalysis('All', null, allCases)
    }

    return analysis.edgeCases.filter(ec => ec.severity === 'critical')
  }

  /**
   * Get edge cases for specific input types
   */
  getInputEdgeCases(inputType) {
    const patterns = this.inputPatterns[inputType] || []
    return patterns.map(([title, testValue]) => createEdgeCase(
      title,
      `Test with: ${testValue}`,
      EdgeCaseCategory.DATA,
      'medium',
      `Enter '${testValue}'`,
      { [inputType]: testValue }
    ))
  }
}

/**
 * Quick helper to detect edge cases for a page type
 */
function detectEdgeCases(pageType) {
  const detector = new EdgeCaseDetector()
  return detector.analyzePageType(pageType)
}

/**
 * Convert detected edge cases to test case format
 */
function getEdgeCaseTests(pageType) {
  const detector = new EdgeCaseDetector()
  const analysis = detector.analyzePageType(pageType)

  return analysis.edgeCases.map((ec, i) => ({
    id: `EC-${String(i + 1).padStart(3, '0')}`,
    title: ec.title,
    description: ec.description,
    category: ec.category,
    priority: ec.severity,
    steps: [ec.testSuggestion],
    expectedResult: 'System handles edge case gracefully',
    testData: ec.testData || {}
  }))
}

module.exports = {
  EdgeCaseCategory,
  UNIVERSAL_EDGE_CASES,
  PAGE_EDGE_CASES,
  INPUT_PATTERNS,
  EdgeCaseDetector,
  createEdgeCase,
  createEdgeCaseAnalysis,
  detectEdgeCases,
  getEdgeCaseTests
}
