/**
 * Yali Agent - Response Tone & Style
 * Ported from testai-agent/personality/tone.py
 *
 * Makes responses feel human and conversational.
 * Follows European design principles: minimal, warm, purposeful.
 *
 * Key Principles:
 * 1. Don't dump information - reveal progressively
 * 2. Show confidence levels naturally
 * 3. Be conversational, not robotic
 * 4. Every word has purpose
 */

/**
 * Confidence levels
 */
const Confidence = {
  CERTAIN: 'certain',       // 95%+ sure
  CONFIDENT: 'confident',   // 80-95% sure
  LIKELY: 'likely',         // 60-80% sure
  UNCERTAIN: 'uncertain',   // 40-60% sure
  GUESSING: 'guessing'      // <40% sure
}

/**
 * Get numeric score for confidence
 */
function getConfidenceScore(confidence) {
  const scores = {
    [Confidence.CERTAIN]: 0.97,
    [Confidence.CONFIDENT]: 0.87,
    [Confidence.LIKELY]: 0.70,
    [Confidence.UNCERTAIN]: 0.50,
    [Confidence.GUESSING]: 0.30
  }
  return scores[confidence] || 0.5
}

/**
 * Human-like phrases for different confidence levels
 */
const CONFIDENCE_PHRASES = {
  [Confidence.CERTAIN]: [
    'This is definitely',
    'I can confirm this is',
    'Clearly, this is',
    'No doubt about it, this is',
    "100% sure this is",
    'This is unmistakably'
  ],
  [Confidence.CONFIDENT]: [
    "I'm pretty sure this is",
    'This looks like',
    "I'd say this is",
    'Based on what I see, this is',
    "I'm confident this is",
    'This has all the hallmarks of'
  ],
  [Confidence.LIKELY]: [
    'This appears to be',
    'This seems like',
    'Most likely, this is',
    "I'd lean towards this being",
    'This has the characteristics of',
    'If I had to bet, this is'
  ],
  [Confidence.UNCERTAIN]: [
    'I think this might be',
    'This could be',
    'If I had to guess, this is',
    "I'm not entirely sure, but this looks like",
    'My best guess is this is',
    'This resembles'
  ],
  [Confidence.GUESSING]: [
    "I'm not sure, but maybe",
    'This is a bit unclear, perhaps',
    'Hard to tell, but possibly',
    "I'd need more context, but maybe",
    "Honestly, I'm guessing here - could be",
    'This is tricky to identify, but perhaps'
  ]
}

/**
 * Transition phrases for natural flow
 */
const TRANSITIONS = {
  starting: [
    'Let me take a look...',
    'Looking at this...',
    'Examining the page...',
    'Alright, analyzing this...',
    'Let me see what we have here...',
    'Checking this out...',
    'Taking a closer look...',
    'One moment while I analyze this...'
  ],
  found_something: [
    'I found',
    'I noticed',
    'I spotted',
    'I detected',
    'I identified',
    'I see',
    "There's",
    'I picked up on'
  ],
  continuing: [
    'Also,',
    'Additionally,',
    'I also see',
    'Beyond that,',
    'Furthermore,',
    'On top of that,',
    "And there's more -",
    'Worth noting,'
  ],
  concluding: [
    'So overall,',
    'In summary,',
    'To wrap up,',
    'Bottom line:',
    'All things considered,',
    'Taking everything together,',
    'The gist is:',
    "Here's the takeaway:"
  ],
  asking: [
    'Quick question:',
    'Just to clarify:',
    'I want to make sure:',
    'Before I continue,',
    'One thing I need to know:',
    'Help me understand:',
    'Can you tell me:',
    "I'm curious about:"
  ],
  thinking: [
    'Let me think about this...',
    'Hmm, interesting...',
    'Processing this...',
    'Working through this...',
    'Bear with me...',
    'This needs some thought...',
    'Analyzing the patterns...',
    'Running through scenarios...'
  ],
  success: [
    'Done!',
    'All set.',
    'Finished.',
    'Complete.',
    'Got it.',
    "That's done.",
    'Wrapped up.',
    'Good to go.'
  ],
  problem: [
    'Hmm, ran into something...',
    'Small hiccup here...',
    'Found an issue...',
    "Something's not right...",
    'Let me flag this...',
    'This needs attention...',
    'Spotted a problem...',
    'Heads up -'
  ]
}

/**
 * Greetings
 */
const GREETINGS = [
  'Hey! What are we testing today?',
  'Hi there! Ready to find some bugs.',
  "Hello! Let's make sure this feature works perfectly.",
  'Hey! What would you like me to test?',
  "Hi! I'm ready to dig into whatever you've got.",
  'Hello! Point me at something to test.',
  "Hey there! What's on the testing agenda?",
  "Hi! Let's catch some bugs before users do."
]

/**
 * Celebration phrases for achievements
 */
const CELEBRATIONS = {
  small: ['Nice.', 'Got it.', 'Good find.', 'Noted.', 'Check.', 'Solid.'],
  medium: ['Nice find!', 'Good catch!', "That's useful.", 'This is helpful.', 'Getting somewhere.', 'Making progress.'],
  large: ['Excellent!', 'This is great!', 'Really good progress!', "We're onto something.", 'This is valuable stuff.', 'Strong work here.'],
  critical_find: ['This is a big one!', 'Critical find here!', 'Glad we caught this!', "This could've been bad.", 'Major catch!', 'This was hiding in plain sight!']
}

/**
 * Softening phrases for uncertainty
 */
const SOFTENERS = [
  'I could be wrong, but',
  'Take this with a grain of salt,',
  "My confidence isn't super high here, but",
  "I'd want to verify this, but",
  'This is preliminary, but',
  'Initial thoughts:'
]

/**
 * Empathy phrases
 */
const EMPATHY_PHRASES = [
  "I understand that's frustrating.",
  "That's annoying, I get it.",
  'Yeah, this is tricky.',
  'Totally understand the concern.',
  "Makes sense you'd want to catch this.",
  'Good instinct to test this.'
]

/**
 * Importance phrases
 */
const IMPORTANCE_PHRASES = {
  critical: [
    'This is critical because',
    'This matters a lot because',
    'You definitely want to test this because',
    'This could break things badly -',
    'High stakes here -'
  ],
  security: [
    'Security-wise, this is important because',
    'From a security perspective,',
    'This could be a vulnerability because',
    'Bad actors could exploit this -'
  ],
  ux: [
    'Users will notice this because',
    'This affects user experience -',
    'From a UX standpoint,',
    'Users might get confused here because'
  ],
  edge_case: [
    'Edge case alert:',
    'This catches the corner case where',
    'Not obvious, but this matters when',
    'Easy to miss, but'
  ]
}

/**
 * Create a styled response object
 */
function createStyledResponse(mainContent, confidence, options = {}) {
  return {
    mainContent,
    confidence,
    suggestions: options.suggestions || [],
    questions: options.questions || [],
    metadata: options.metadata || {},

    toString() {
      const parts = [this.mainContent]

      if (this.suggestions.length > 0) {
        parts.push('\n\nSuggestions:')
        for (const s of this.suggestions) {
          parts.push(`  → ${s}`)
        }
      }

      if (this.questions.length > 0) {
        parts.push('\n\nQuestions:')
        for (const q of this.questions) {
          parts.push(`  ? ${q}`)
        }
      }

      return parts.join('\n')
    }
  }
}

/**
 * Response Styler class
 */
class ResponseStyler {
  constructor(verbose = false) {
    this.verbose = verbose
  }

  _pick(phrases) {
    return phrases[Math.floor(Math.random() * phrases.length)]
  }

  _confidencePrefix(confidence) {
    return this._pick(CONFIDENCE_PHRASES[confidence] || CONFIDENCE_PHRASES[Confidence.CONFIDENT])
  }

  /**
   * Style a page classification result
   */
  classifyPage(pageType, confidence, elementsFound = 0, hints = null) {
    const prefix = this._confidencePrefix(confidence)
    let main = `${prefix} a ${pageType} page.`

    if (elementsFound > 0) {
      main += ` Found ${elementsFound} testable elements.`
    }

    const suggestions = hints ? hints.slice(0, 3) : []
    const questions = []

    if (getConfidenceScore(confidence) < 0.7) {
      questions.push(`Can you confirm this is a ${pageType} page?`)
    }

    return createStyledResponse(main, confidence, {
      suggestions,
      questions,
      metadata: { pageType, elements: elementsFound }
    })
  }

  /**
   * Style a test generation result
   */
  testsGenerated(count, categories, criticalCount = 0) {
    let main
    let confidence

    if (count === 0) {
      main = "I couldn't generate any tests. Let me know more about what you're testing."
      confidence = Confidence.UNCERTAIN
    } else if (count < 5) {
      main = `Generated ${count} test cases. Might need more context for comprehensive coverage.`
      confidence = Confidence.LIKELY
    } else {
      main = `Generated ${count} test cases across ${categories.length} categories.`
      confidence = Confidence.CONFIDENT
    }

    if (criticalCount > 0) {
      main += ` Found ${criticalCount} critical edge cases!`
    }

    const catList = categories.length > 0 ? categories.join(', ') : 'general'
    const suggestions = [`Categories covered: ${catList}`]
    const questions = count < 10 ? ['Want me to dig deeper into any specific area?'] : []

    return createStyledResponse(main, confidence, {
      suggestions,
      questions,
      metadata: { count, categories, critical: criticalCount }
    })
  }

  /**
   * Style a security analysis result
   */
  securityAnalysis(vulnerabilities, severityHigh = 0, severityMedium = 0, severityLow = 0) {
    let main
    let confidence

    if (vulnerabilities === 0) {
      main = 'No obvious security issues found. The page follows good practices.'
      confidence = Confidence.CONFIDENT
    } else if (severityHigh > 0) {
      main = `⚠️ Found ${severityHigh} high-severity security concerns that need attention.`
      confidence = Confidence.CERTAIN
    } else {
      main = `Found ${vulnerabilities} potential security items to review.`
      confidence = Confidence.CONFIDENT
    }

    const suggestions = []
    if (severityHigh > 0) suggestions.push('Address high-severity issues first')
    if (severityMedium > 0) suggestions.push(`Review ${severityMedium} medium-priority items`)

    return createStyledResponse(main, confidence, {
      suggestions,
      questions: [],
      metadata: { total: vulnerabilities, high: severityHigh, medium: severityMedium, low: severityLow }
    })
  }

  /**
   * Style edge case detection results
   */
  edgeCases(cases, feature) {
    const count = cases.length
    let main
    let confidence

    if (count === 0) {
      main = `No unusual edge cases for ${feature}. Standard testing should suffice.`
      confidence = Confidence.LIKELY
    } else if (count > 10) {
      main = `Found ${count} edge cases for ${feature}. Some interesting scenarios here!`
      confidence = Confidence.CONFIDENT
    } else {
      main = `Identified ${count} edge cases to test for ${feature}.`
      confidence = Confidence.CONFIDENT
    }

    const suggestions = []
    for (const caseItem of cases.slice(0, 3)) {
      if (typeof caseItem === 'object' && caseItem.description) {
        suggestions.push(caseItem.description.slice(0, 80))
      } else if (typeof caseItem === 'string') {
        suggestions.push(caseItem.slice(0, 80))
      }
    }

    return createStyledResponse(main, confidence, {
      suggestions,
      questions: count > 5 ? ['Want me to prioritize these by risk level?'] : [],
      metadata: { count, feature }
    })
  }

  /**
   * Quick progress message
   */
  progressUpdate(currentStep, totalSteps, completedSteps) {
    const progress = totalSteps > 0 ? completedSteps / totalSteps : 0
    const filled = Math.floor(progress * 10)
    const bar = '█'.repeat(filled) + '░'.repeat(10 - filled)
    return `${bar} ${currentStep} (${completedSteps}/${totalSteps})`
  }

  /**
   * Style an error message
   */
  errorMessage(error, recoverable = true) {
    let main
    let confidence

    if (recoverable) {
      main = `Hit a small snag: ${error}. Let me try a different approach.`
      confidence = Confidence.UNCERTAIN
    } else {
      main = `Ran into an issue: ${error}. Need your help to continue.`
      confidence = Confidence.GUESSING
    }

    return createStyledResponse(main, confidence, {
      suggestions: recoverable ? ['Try refreshing the page', 'Check if the element still exists'] : [],
      questions: recoverable ? ['Should I skip this and continue?'] : [],
      metadata: { error, recoverable }
    })
  }

  /**
   * Get a random greeting
   */
  getGreeting() {
    return this._pick(GREETINGS)
  }

  /**
   * Get a transition phrase
   */
  getTransition(type) {
    return this._pick(TRANSITIONS[type] || TRANSITIONS.continuing)
  }

  /**
   * Get a celebration phrase
   */
  getCelebration(size = 'medium') {
    return this._pick(CELEBRATIONS[size] || CELEBRATIONS.medium)
  }

  /**
   * Get an empathy phrase
   */
  getEmpathy() {
    return this._pick(EMPATHY_PHRASES)
  }

  /**
   * Get an importance phrase
   */
  getImportance(type = 'critical') {
    return this._pick(IMPORTANCE_PHRASES[type] || IMPORTANCE_PHRASES.critical)
  }
}

/**
 * Quick helper to create styled response
 */
function styledResponse(content, confidence = Confidence.CONFIDENT, options = {}) {
  return createStyledResponse(content, confidence, options)
}

/**
 * Quick helper to get random phrase
 */
function getPhrase(type, category = null) {
  const styler = new ResponseStyler()

  switch (type) {
    case 'greeting':
      return styler.getGreeting()
    case 'transition':
      return styler.getTransition(category || 'continuing')
    case 'celebration':
      return styler.getCelebration(category || 'medium')
    case 'empathy':
      return styler.getEmpathy()
    case 'importance':
      return styler.getImportance(category || 'critical')
    default:
      return styler.getTransition('thinking')
  }
}

module.exports = {
  Confidence,
  getConfidenceScore,
  CONFIDENCE_PHRASES,
  TRANSITIONS,
  GREETINGS,
  CELEBRATIONS,
  SOFTENERS,
  EMPATHY_PHRASES,
  IMPORTANCE_PHRASES,
  ResponseStyler,
  createStyledResponse,
  styledResponse,
  getPhrase
}
