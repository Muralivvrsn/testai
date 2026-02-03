/**
 * Yali Agent - QA Consultant Personality
 * Ported from testai-agent/personality/qa_consultant.py
 *
 * Behaves like a professional senior QA consultant.
 * Asks the right questions, shares insights, makes recommendations.
 */

/**
 * Consultant mood states
 */
const ConsultantMood = {
  PROFESSIONAL: 'professional',
  CURIOUS: 'curious',
  CONCERNED: 'concerned',
  CONFIDENT: 'confident',
  THOUGHTFUL: 'thoughtful'
}

/**
 * Question priority
 */
const QuestionPriority = {
  CRITICAL: 'critical',
  IMPORTANT: 'important',
  OPTIONAL: 'optional'
}

/**
 * Pre-defined clarifying questions by page type
 */
const CLARIFYING_QUESTIONS = {
  login: [
    {
      question: 'Is there a password reset flow I should test?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Password reset is often a security weak point',
      options: ['Yes, test it', 'No, skip it', 'Not sure']
    },
    {
      question: 'Are there social login options (Google, Facebook, etc.)?',
      priority: QuestionPriority.IMPORTANT,
      context: 'OAuth flows need specific testing',
      options: ['Yes', 'No', 'Some providers']
    },
    {
      question: 'Is there multi-factor authentication?',
      priority: QuestionPriority.IMPORTANT,
      context: 'MFA adds complexity to auth flows',
      options: ['Yes, test MFA', 'No MFA', 'Optional MFA']
    },
    {
      question: 'What happens after too many failed login attempts?',
      priority: QuestionPriority.CRITICAL,
      context: 'Brute force protection is essential',
      options: ['Account locks', 'CAPTCHA shows', 'Nothing special', 'Not sure']
    }
  ],

  signup: [
    {
      question: 'Is email verification required before account activation?',
      priority: QuestionPriority.CRITICAL,
      context: 'Unverified accounts are a security risk',
      options: ['Yes, required', 'No, immediate access', 'Optional']
    },
    {
      question: 'What are the password requirements?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Need to test boundary cases',
      options: ['Show me the rules', 'Standard rules', 'No specific rules']
    },
    {
      question: 'Are there any terms/privacy agreements to accept?',
      priority: QuestionPriority.IMPORTANT,
      context: 'GDPR/compliance requirements',
      options: ['Yes, mandatory', 'Optional', 'None']
    }
  ],

  checkout: [
    {
      question: 'What payment methods are supported?',
      priority: QuestionPriority.CRITICAL,
      context: 'Each payment method needs testing',
      options: ['Credit cards only', 'Multiple methods', 'Show me options']
    },
    {
      question: 'Is there guest checkout or is login required?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Different flows to test',
      options: ['Guest allowed', 'Login required', 'Both options']
    },
    {
      question: 'Are there discount codes or promotions to test?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Coupon logic is often buggy',
      options: ['Yes, test coupons', 'No coupons', 'Not sure']
    },
    {
      question: 'Does the checkout involve shipping calculations?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Shipping logic adds complexity',
      options: ['Yes, physical products', 'Digital only', 'Both']
    }
  ],

  form: [
    {
      question: 'What happens to the form data after submission?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Need to verify data handling',
      options: ['Sent via email', 'Stored in database', 'API call', 'Not sure']
    },
    {
      question: 'Are there any conditional fields that show/hide?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Dynamic forms need extra testing',
      options: ['Yes, conditional logic', 'No, all fields visible', 'Not sure']
    },
    {
      question: 'Is there file upload functionality?',
      priority: QuestionPriority.IMPORTANT,
      context: 'File uploads are security-sensitive',
      options: ['Yes, test uploads', 'No uploads', 'Optional uploads']
    }
  ],

  search: [
    {
      question: 'Are there filters or faceted search options?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Filter combinations need testing',
      options: ['Yes, multiple filters', 'Basic filters', 'No filters']
    },
    {
      question: 'Is there autocomplete/suggestions?',
      priority: QuestionPriority.OPTIONAL,
      context: 'Autocomplete UX testing',
      options: ['Yes', 'No', 'Not sure']
    }
  ],

  general: [
    {
      question: 'What browsers need to be supported?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Cross-browser testing scope',
      options: ['All major browsers', 'Chrome only', 'Specific list']
    },
    {
      question: 'Is mobile responsiveness important?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Mobile testing requirements',
      options: ['Yes, mobile-first', 'Desktop priority', 'Both equal']
    },
    {
      question: 'Are there accessibility requirements (WCAG)?',
      priority: QuestionPriority.IMPORTANT,
      context: 'Accessibility compliance',
      options: ['WCAG 2.1 AA', 'Basic accessibility', 'Not required']
    }
  ]
}

/**
 * Greetings based on context
 */
const GREETINGS = {
  new_session: [
    "Hey! I'm Yali, your QA consultant. What are we testing today?",
    "Hi there! Ready to find some bugs. What's on the testing agenda?",
    "Hello! Let's make sure this works perfectly. What are we looking at?",
    "Yali here, ready to help! Tell me about what you want to test."
  ],
  returning: [
    "Welcome back! Ready to continue testing?",
    "Good to see you again! What shall we test next?",
    "Back for more testing? Let's dive in!"
  ],
  page_loaded: [
    "I see you've loaded a page. Want me to analyze it?",
    "New page detected! Should I take a look at what needs testing?",
    "Page loaded. I can scan for testable elements if you'd like."
  ]
}

/**
 * Thinking phrases by phase
 */
const THINKING_PHRASES = {
  analyzing: [
    "Let me analyze this page structure...",
    "Examining the elements here...",
    "Looking at what we've got...",
    "Scanning for testable components..."
  ],
  planning: [
    "Thinking about the best approach...",
    "Planning our testing strategy...",
    "Considering what needs coverage...",
    "Mapping out the test scenarios..."
  ],
  generating: [
    "Creating test cases...",
    "Generating specific tests...",
    "Building out the test suite...",
    "Crafting targeted scenarios..."
  ],
  security: [
    "Checking for security concerns...",
    "Looking at potential vulnerabilities...",
    "Analyzing attack surfaces...",
    "Reviewing security posture..."
  ]
}

/**
 * Create a clarifying question
 */
function createClarifyingQuestion(question, priority, context, options = []) {
  return {
    question,
    priority,
    context,
    options,
    answered: false,
    answer: null
  }
}

/**
 * Create a consultant thought
 */
function createThought(content, mood = ConsultantMood.PROFESSIONAL, confidence = 0.8) {
  return {
    content,
    mood,
    confidence,
    timestamp: Date.now()
  }
}

/**
 * Create a recommendation
 */
function createRecommendation(title, description, priority, actionItems = []) {
  return {
    title,
    description,
    priority,
    actionItems,
    timestamp: Date.now()
  }
}

/**
 * QA Consultant Personality class
 */
class QAConsultantPersonality {
  constructor() {
    this.currentMood = ConsultantMood.PROFESSIONAL
    this.answeredQuestions = new Map()
    this.insights = []
  }

  /**
   * Get greeting based on context
   */
  greet(context = 'new_session') {
    const greetings = GREETINGS[context] || GREETINGS.new_session
    return greetings[Math.floor(Math.random() * greetings.length)]
  }

  /**
   * Get thinking phrase for phase
   */
  getThinkingPhrase(phase) {
    const phrases = THINKING_PHRASES[phase] || THINKING_PHRASES.analyzing
    return phrases[Math.floor(Math.random() * phrases.length)]
  }

  /**
   * Get clarifying questions for page type
   */
  getClarifyingQuestions(pageType, limit = 3) {
    const questions = CLARIFYING_QUESTIONS[pageType] || CLARIFYING_QUESTIONS.general

    // Filter out already answered
    const unanswered = questions.filter(q =>
      !this.answeredQuestions.has(q.question)
    )

    // Sort by priority
    const priorityOrder = {
      [QuestionPriority.CRITICAL]: 0,
      [QuestionPriority.IMPORTANT]: 1,
      [QuestionPriority.OPTIONAL]: 2
    }

    unanswered.sort((a, b) =>
      priorityOrder[a.priority] - priorityOrder[b.priority]
    )

    return unanswered.slice(0, limit).map(q =>
      createClarifyingQuestion(q.question, q.priority, q.context, q.options)
    )
  }

  /**
   * Record an answer to a question
   */
  recordAnswer(question, answer) {
    this.answeredQuestions.set(question, {
      answer,
      timestamp: Date.now()
    })
  }

  /**
   * Share thoughts during analysis
   */
  shareThoughts(pageType, elements, findings) {
    const thoughts = []

    // Element-based thoughts
    const inputs = elements.filter(e => e.category === 'text-input' || e.tag === 'input')
    const buttons = elements.filter(e => e.category === 'button')
    const forms = elements.filter(e => e.tag === 'form')

    if (inputs.length > 5) {
      thoughts.push(createThought(
        `I see ${inputs.length} input fields here. That's a lot of validation to test.`,
        ConsultantMood.THOUGHTFUL,
        0.9
      ))
    }

    if (forms.length > 1) {
      thoughts.push(createThought(
        `Multiple forms detected. I'll need to test each submission flow separately.`,
        ConsultantMood.CURIOUS,
        0.85
      ))
    }

    // Security-focused thoughts
    const passwordFields = inputs.filter(e => e.type === 'password')
    if (passwordFields.length > 0) {
      thoughts.push(createThought(
        `Password field detected. Security testing will be critical here.`,
        ConsultantMood.CONCERNED,
        0.95
      ))
    }

    // Page-type specific
    if (pageType === 'checkout') {
      thoughts.push(createThought(
        `Checkout page - this is high risk. Payment flows need thorough testing.`,
        ConsultantMood.CONCERNED,
        0.95
      ))
    }

    if (pageType === 'login') {
      thoughts.push(createThought(
        `Login page is the front door. Security here protects everything else.`,
        ConsultantMood.PROFESSIONAL,
        0.9
      ))
    }

    // Add findings-based thoughts
    if (findings && findings.vulnerabilities && findings.vulnerabilities.length > 0) {
      const criticalCount = findings.vulnerabilities.filter(v => v.severity === 'critical').length
      if (criticalCount > 0) {
        thoughts.push(createThought(
          `Found ${criticalCount} critical security concern(s). We should address these first.`,
          ConsultantMood.CONCERNED,
          0.95
        ))
      }
    }

    return thoughts
  }

  /**
   * Make recommendations based on analysis
   */
  makeRecommendations(pageType, coverageReport, securityFindings) {
    const recommendations = []

    // Coverage-based recommendations
    if (coverageReport && coverageReport.hasCriticalGaps) {
      recommendations.push(createRecommendation(
        'Address Critical Coverage Gaps',
        'There are critical testing gaps that should be addressed before release.',
        QuestionPriority.CRITICAL,
        coverageReport.gapsBySeverity?.critical?.slice(0, 3).map(g => g.title) || []
      ))
    }

    // Security-based recommendations
    if (securityFindings && securityFindings.riskScore > 50) {
      recommendations.push(createRecommendation(
        'Security Testing Required',
        `Security risk score is ${securityFindings.riskScore}/100. Additional security testing recommended.`,
        QuestionPriority.CRITICAL,
        ['Run security-focused tests', 'Review OWASP Top 10', 'Consider penetration testing']
      ))
    }

    // Page-type specific recommendations
    const pageRecommendations = {
      login: [
        createRecommendation(
          'Test Authentication Security',
          'Login pages require comprehensive security testing.',
          QuestionPriority.CRITICAL,
          ['Test brute force protection', 'Verify session handling', 'Check for credential exposure']
        )
      ],
      checkout: [
        createRecommendation(
          'Payment Flow Testing',
          'Checkout requires end-to-end payment testing.',
          QuestionPriority.CRITICAL,
          ['Test with valid test cards', 'Verify error handling', 'Check for double-charge prevention']
        )
      ],
      signup: [
        createRecommendation(
          'Registration Security',
          'New user registration needs security validation.',
          QuestionPriority.IMPORTANT,
          ['Test email verification', 'Verify password requirements', 'Check duplicate prevention']
        )
      ]
    }

    if (pageRecommendations[pageType]) {
      recommendations.push(...pageRecommendations[pageType])
    }

    // General recommendations
    recommendations.push(createRecommendation(
      'Cross-Browser Testing',
      'Verify functionality across major browsers.',
      QuestionPriority.IMPORTANT,
      ['Chrome', 'Firefox', 'Safari', 'Edge']
    ))

    return recommendations
  }

  /**
   * Format questions for display
   */
  formatQuestionsDialog(questions) {
    const lines = []
    lines.push("Before I generate tests, a few quick questions:\n")

    questions.forEach((q, i) => {
      const priorityIcon = {
        [QuestionPriority.CRITICAL]: '🔴',
        [QuestionPriority.IMPORTANT]: '🟡',
        [QuestionPriority.OPTIONAL]: '🟢'
      }[q.priority] || '❓'

      lines.push(`${priorityIcon} **${i + 1}. ${q.question}**`)
      if (q.context) {
        lines.push(`   _${q.context}_`)
      }
      if (q.options.length > 0) {
        lines.push(`   Options: ${q.options.join(' | ')}`)
      }
      lines.push('')
    })

    return lines.join('\n')
  }

  /**
   * Format recommendations for display
   */
  formatRecommendations(recommendations) {
    const lines = []
    lines.push("## My Recommendations\n")

    recommendations.forEach((rec, i) => {
      const priorityIcon = {
        [QuestionPriority.CRITICAL]: '🔴',
        [QuestionPriority.IMPORTANT]: '🟡',
        [QuestionPriority.OPTIONAL]: '🟢'
      }[rec.priority] || '📝'

      lines.push(`### ${priorityIcon} ${rec.title}`)
      lines.push(rec.description)
      if (rec.actionItems.length > 0) {
        lines.push('**Action Items:**')
        rec.actionItems.forEach(item => lines.push(`- ${item}`))
      }
      lines.push('')
    })

    return lines.join('\n')
  }

  /**
   * Get current mood
   */
  getMood() {
    return this.currentMood
  }

  /**
   * Set mood based on findings
   */
  updateMood(findings) {
    if (findings.criticalIssues > 0) {
      this.currentMood = ConsultantMood.CONCERNED
    } else if (findings.coverage > 80) {
      this.currentMood = ConsultantMood.CONFIDENT
    } else if (findings.unknowns > 0) {
      this.currentMood = ConsultantMood.CURIOUS
    } else {
      this.currentMood = ConsultantMood.PROFESSIONAL
    }
  }
}

module.exports = {
  ConsultantMood,
  QuestionPriority,
  CLARIFYING_QUESTIONS,
  GREETINGS,
  THINKING_PHRASES,
  QAConsultantPersonality,
  createClarifyingQuestion,
  createThought,
  createRecommendation
}
