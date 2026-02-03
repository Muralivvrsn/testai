/**
 * Yali Agent - Clarification System
 * Ported from testai-agent/personality/clarifier.py
 *
 * Asks smart questions like humans do.
 * Good QA engineers don't assume - they clarify.
 *
 * Design Philosophy:
 * - Ask before assuming
 * - Group related questions
 * - Offer sensible defaults
 * - Don't overwhelm with questions
 */

/**
 * Question priority levels
 */
const QuestionPriority = {
  CRITICAL: 'critical',   // Can't proceed without answer
  IMPORTANT: 'important', // Significantly affects outcome
  OPTIONAL: 'optional'    // Nice to know, has default
}

/**
 * Create a clarification question
 */
function createClarificationQuestion(question, priority, options = {}) {
  const q = {
    question,
    priority,
    default: options.default || null,
    options: options.options || [],
    context: options.context || null,
    category: options.category || 'general',

    toString() {
      let str = this.question
      if (this.options.length > 0) {
        str += ` (${this.options.join(' / ')})`
      }
      if (this.default) {
        str += ` [default: ${this.default}]`
      }
      return str
    }
  }
  return q
}

/**
 * Create a bundle of related questions
 */
function createClarificationBundle(title, questions, requiredBeforeProceed = false) {
  return {
    title,
    questions,
    requiredBeforeProceed,

    getCritical() {
      return this.questions.filter(q => q.priority === QuestionPriority.CRITICAL)
    },

    summarize() {
      const critical = this.questions.filter(q => q.priority === QuestionPriority.CRITICAL).length
      const important = this.questions.filter(q => q.priority === QuestionPriority.IMPORTANT).length

      const parts = []
      if (critical > 0) parts.push(`${critical} critical`)
      if (important > 0) parts.push(`${important} important`)

      return `${this.title}: ${parts.join(', ')} questions`
    }
  }
}

/**
 * Clarifier class - generates smart clarification questions
 */
class Clarifier {
  constructor(maxQuestions = 5) {
    this.maxQuestions = maxQuestions
  }

  /**
   * Generate questions for a detected page type
   */
  forPageType(pageType, foundElements = null, url = null) {
    let questions = []
    const pageTypeLower = pageType.toLowerCase()

    switch (pageTypeLower) {
      case 'login':
        questions = this._loginQuestions(foundElements)
        break
      case 'signup':
        questions = this._signupQuestions(foundElements)
        break
      case 'checkout':
        questions = this._checkoutQuestions(foundElements)
        break
      case 'search':
        questions = this._searchQuestions(foundElements)
        break
      case 'form':
        questions = this._formQuestions(foundElements)
        break
      case 'settings':
        questions = this._settingsQuestions(foundElements)
        break
      case 'profile':
        questions = this._profileQuestions(foundElements)
        break
      case 'dashboard':
        questions = this._dashboardQuestions(foundElements)
        break
      case 'list':
      case 'table':
        questions = this._listQuestions(foundElements)
        break
      default:
        questions = this._genericQuestions(pageType, foundElements)
    }

    questions = questions.slice(0, this.maxQuestions)
    const hasCritical = questions.some(q => q.priority === QuestionPriority.CRITICAL)

    return createClarificationBundle(
      `Questions about ${pageType} page`,
      questions,
      hasCritical
    )
  }

  /**
   * Generate questions when feature intent is unclear
   */
  forAmbiguousFeature(featureDescription, detectedTypes = null) {
    const questions = [
      createClarificationQuestion(
        `What should '${featureDescription}' accomplish?`,
        QuestionPriority.CRITICAL,
        { category: 'intent' }
      ),
      createClarificationQuestion(
        'Who are the primary users of this feature?',
        QuestionPriority.IMPORTANT,
        { options: ['End users', 'Admin users', 'Both'], default: 'End users', category: 'audience' }
      ),
      createClarificationQuestion(
        'Are there any specific business rules I should know?',
        QuestionPriority.OPTIONAL,
        { category: 'rules' }
      )
    ]

    if (detectedTypes && detectedTypes.length > 0) {
      questions.push(createClarificationQuestion(
        `I detected these element types: ${detectedTypes.join(', ')}. Is this complete?`,
        QuestionPriority.IMPORTANT,
        { options: ['Yes', "No, there's more"], category: 'completeness' }
      ))
    }

    return createClarificationBundle(
      `Clarifying: ${featureDescription}`,
      questions.slice(0, this.maxQuestions),
      true
    )
  }

  /**
   * Ask about testing priorities
   */
  forTestFocus(feature, suggestedCategories) {
    const questions = [
      createClarificationQuestion(
        'Which testing areas should I prioritize?',
        QuestionPriority.IMPORTANT,
        { options: suggestedCategories.slice(0, 4), category: 'priority' }
      ),
      createClarificationQuestion(
        "Any specific edge cases you're worried about?",
        QuestionPriority.OPTIONAL,
        { category: 'edge_cases' }
      ),
      createClarificationQuestion(
        'Should I include accessibility testing?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes', 'No', 'Basic only'], default: 'Basic only', category: 'accessibility' }
      )
    ]

    return createClarificationBundle(
      `Testing focus for ${feature}`,
      questions,
      false
    )
  }

  /**
   * Generate a single question for missing information
   */
  forMissingInfo(whatIsMissing, context = null) {
    return createClarificationQuestion(
      `I need to know: ${whatIsMissing}`,
      QuestionPriority.CRITICAL,
      { context, category: 'missing_info' }
    )
  }

  // =========================================================================
  // Page-specific question generators
  // =========================================================================

  _loginQuestions(elements) {
    const questions = []

    const hasSocial = elements && elements.some(e =>
      e.toLowerCase().includes('google') ||
      e.toLowerCase().includes('facebook') ||
      e.toLowerCase().includes('oauth')
    )
    const has2fa = elements && elements.some(e =>
      e.toLowerCase().includes('2fa') ||
      e.toLowerCase().includes('otp') ||
      e.toLowerCase().includes('code')
    )

    if (!hasSocial) {
      questions.push(createClarificationQuestion(
        'Does this login support social sign-in (Google, Facebook, etc.)?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes', 'No'], category: 'auth_method' }
      ))
    }

    if (!has2fa) {
      questions.push(createClarificationQuestion(
        'Is two-factor authentication (2FA) enabled?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes', 'No', 'Optional'], category: 'security' }
      ))
    }

    questions.push(createClarificationQuestion(
      "What's the lockout policy after failed attempts?",
      QuestionPriority.OPTIONAL,
      { options: ['3 attempts', '5 attempts', 'No lockout', 'Unknown'], default: 'Unknown', category: 'security' }
    ))

    return questions
  }

  _signupQuestions(elements) {
    return [
      createClarificationQuestion(
        'What fields are required for registration?',
        QuestionPriority.IMPORTANT,
        { category: 'requirements' }
      ),
      createClarificationQuestion(
        'Are there password complexity requirements?',
        QuestionPriority.IMPORTANT,
        { options: ['Strong (8+ chars, symbols)', 'Medium (6+ chars)', 'Weak (any)', 'Unknown'], category: 'validation' }
      ),
      createClarificationQuestion(
        'Is email verification required?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes', 'No'], default: 'Yes', category: 'flow' }
      )
    ]
  }

  _checkoutQuestions(elements) {
    return [
      createClarificationQuestion(
        'What payment methods should I test?',
        QuestionPriority.CRITICAL,
        { options: ['Credit card', 'PayPal', 'Apple Pay', 'All'], category: 'payment' }
      ),
      createClarificationQuestion(
        'Should I test guest checkout (no account)?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes', 'No', 'If available'], default: 'If available', category: 'flow' }
      ),
      createClarificationQuestion(
        'Are there promo codes to test?',
        QuestionPriority.OPTIONAL,
        { category: 'discounts' }
      )
    ]
  }

  _searchQuestions(elements) {
    return [
      createClarificationQuestion(
        'What type of content is being searched?',
        QuestionPriority.IMPORTANT,
        { options: ['Products', 'Articles', 'Users', 'Mixed'], category: 'content' }
      ),
      createClarificationQuestion(
        'Are there filters or faceted search?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes', 'No'], category: 'features' }
      )
    ]
  }

  _formQuestions(elements) {
    return [
      createClarificationQuestion(
        'What is the purpose of this form?',
        QuestionPriority.CRITICAL,
        { category: 'intent' }
      ),
      createClarificationQuestion(
        'Which fields are required vs optional?',
        QuestionPriority.IMPORTANT,
        { category: 'validation' }
      )
    ]
  }

  _settingsQuestions(elements) {
    return [
      createClarificationQuestion(
        'What settings can users change here?',
        QuestionPriority.IMPORTANT,
        { options: ['Profile info', 'Password/Security', 'Notifications', 'All of the above'], default: 'All of the above', category: 'scope' }
      ),
      createClarificationQuestion(
        'Can users delete their account from this page?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes', 'No', 'Not sure'], category: 'danger_zone' }
      ),
      createClarificationQuestion(
        'Are there any settings that require re-authentication?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes, password change', 'Yes, email change', 'No'], category: 'security' }
      )
    ]
  }

  _profileQuestions(elements) {
    return [
      createClarificationQuestion(
        'Can users upload a profile picture?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes', 'No'], category: 'features' }
      ),
      createClarificationQuestion(
        'Is any profile information public to other users?',
        QuestionPriority.IMPORTANT,
        { options: ['Yes, some fields', 'No, all private', 'User can choose'], category: 'privacy' }
      ),
      createClarificationQuestion(
        'Are there character limits on fields like bio or name?',
        QuestionPriority.OPTIONAL,
        { category: 'validation' }
      )
    ]
  }

  _dashboardQuestions(elements) {
    return [
      createClarificationQuestion(
        'What widgets or sections appear on this dashboard?',
        QuestionPriority.IMPORTANT,
        { category: 'layout' }
      ),
      createClarificationQuestion(
        'Does the dashboard data refresh automatically?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes, real-time', 'Yes, every few minutes', 'No, manual only'], category: 'behavior' }
      ),
      createClarificationQuestion(
        'Can users customize which widgets they see?',
        QuestionPriority.OPTIONAL,
        { options: ['Yes', 'No'], category: 'personalization' }
      )
    ]
  }

  _listQuestions(elements) {
    return [
      createClarificationQuestion(
        'What items does this list display?',
        QuestionPriority.IMPORTANT,
        { options: ['Products', 'Users', 'Orders', 'Custom data'], category: 'content' }
      ),
      createClarificationQuestion(
        'Does it support sorting and filtering?',
        QuestionPriority.IMPORTANT,
        { options: ['Both', 'Sorting only', 'Filtering only', 'Neither'], category: 'features' }
      ),
      createClarificationQuestion(
        'How many items per page (pagination)?',
        QuestionPriority.OPTIONAL,
        { options: ['10', '25', '50', 'Infinite scroll', 'Unknown'], default: 'Unknown', category: 'pagination' }
      )
    ]
  }

  _genericQuestions(pageType, elements) {
    return [
      createClarificationQuestion(
        `Help me understand - what does this ${pageType} page do?`,
        QuestionPriority.IMPORTANT,
        { category: 'intent' }
      ),
      createClarificationQuestion(
        "What's the main thing users do on this page?",
        QuestionPriority.IMPORTANT,
        { category: 'actions' }
      ),
      createClarificationQuestion(
        "Anything you're particularly worried about with this feature?",
        QuestionPriority.OPTIONAL,
        { category: 'focus' }
      )
    ]
  }
}

/**
 * Quick helper to get clarification questions for a page
 */
function clarifyForPage(pageType, elements = null) {
  const clarifier = new Clarifier()
  return clarifier.forPageType(pageType, elements)
}

/**
 * Quick helper to clarify ambiguous feature
 */
function clarifyFeature(featureDescription) {
  const clarifier = new Clarifier()
  return clarifier.forAmbiguousFeature(featureDescription)
}

module.exports = {
  QuestionPriority,
  Clarifier,
  createClarificationQuestion,
  createClarificationBundle,
  clarifyForPage,
  clarifyFeature
}
