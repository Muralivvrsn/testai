/**
 * Yali Agent - Thinking Aloud System
 * Ported from testai-agent/personality/thinker.py
 *
 * Makes the agent's reasoning visible to users.
 * Good QA engineers explain their thinking - it builds trust.
 *
 * Design Philosophy:
 * - Show work, but don't overwhelm
 * - Vary the phrasing to feel natural
 * - Connect thinking to actions
 * - Express uncertainty when appropriate
 */

/**
 * Phases of the thinking process
 */
const ThinkingPhase = {
  RECEIVING: 'receiving',
  ANALYZING: 'analyzing',
  DETECTING: 'detecting',
  PLANNING: 'planning',
  GENERATING: 'generating',
  REVIEWING: 'reviewing',
  UNCERTAIN: 'uncertain',
  FOUND_ISSUE: 'found_issue',
  COMPLETED: 'completed'
}

/**
 * Thought patterns for each phase
 */
const PATTERNS = {
  [ThinkingPhase.RECEIVING]: [
    "Got it. Let me think about this...",
    "Okay, processing that...",
    "Understood. Give me a moment...",
    "Alright, let me work on this...",
    "Hmm, interesting request..."
  ],

  [ThinkingPhase.ANALYZING]: [
    "Looking at what we have here...",
    "Examining the structure...",
    "Checking the elements...",
    "Taking a closer look...",
    "Analyzing the page layout...",
    "Seeing what we're working with...",
    "Mapping out the feature..."
  ],

  [ThinkingPhase.DETECTING]: [
    "I'm seeing a pattern here...",
    "This looks like {context}...",
    "The structure suggests {context}...",
    "Based on what I see, this appears to be {context}...",
    "Detecting {context} characteristics...",
    "This has the hallmarks of {context}..."
  ],

  [ThinkingPhase.PLANNING]: [
    "Thinking through the scenarios...",
    "Planning what to test...",
    "Mapping out the edge cases...",
    "Figuring out the critical paths...",
    "Considering what could go wrong...",
    "Identifying the risk areas...",
    "Prioritizing the test cases..."
  ],

  [ThinkingPhase.GENERATING]: [
    "Writing up the tests...",
    "Generating test cases...",
    "Creating the test suite...",
    "Putting together the scenarios...",
    "Building the test plan...",
    "Crafting the test cases..."
  ],

  [ThinkingPhase.REVIEWING]: [
    "Let me double-check this...",
    "Reviewing what I've got...",
    "Making sure I haven't missed anything...",
    "Verifying the coverage...",
    "Checking my work..."
  ],

  [ThinkingPhase.UNCERTAIN]: [
    "I'm not 100% sure about this...",
    "This is a bit unclear...",
    "I might be missing something here...",
    "My confidence isn't super high on this one...",
    "I'd want to verify this...",
    "This needs a closer look..."
  ],

  [ThinkingPhase.FOUND_ISSUE]: [
    "Wait, this is interesting...",
    "Hmm, found something...",
    "This could be a problem...",
    "Let me flag this...",
    "This needs attention...",
    "Spotted something worth noting..."
  ],

  [ThinkingPhase.COMPLETED]: [
    "Done with that.",
    "Finished.",
    "All set.",
    "That's wrapped up.",
    "Complete."
  ]
}

/**
 * Context-specific patterns for different page types
 */
const PAGE_SPECIFIC_THOUGHTS = {
  login: [
    "Checking authentication flow...",
    "Looking at the security setup...",
    "Examining credential handling...",
    "Checking for session management..."
  ],
  signup: [
    "Looking at registration validation...",
    "Checking email verification flow...",
    "Examining password requirements...",
    "Looking at duplicate handling..."
  ],
  checkout: [
    "Examining payment flow...",
    "Checking cart integrity...",
    "Looking at pricing logic...",
    "Verifying order processing..."
  ],
  search: [
    "Looking at query handling...",
    "Checking result accuracy...",
    "Examining filter logic...",
    "Testing special characters..."
  ],
  form: [
    "Checking field validation...",
    "Looking at submission handling...",
    "Examining error states...",
    "Testing input sanitization..."
  ]
}

/**
 * Confidence modifiers
 */
const CONFIDENT_PREFIXES = [
  "I can see that",
  "Clearly,",
  "It's evident that",
  "I'm confident that"
]

const UNCERTAIN_PREFIXES = [
  "I think",
  "It seems like",
  "Possibly",
  "It appears that",
  "My guess is"
]

/**
 * Delay values for each phase (in milliseconds)
 */
const PHASE_DELAYS = {
  [ThinkingPhase.RECEIVING]: 300,
  [ThinkingPhase.ANALYZING]: 500,
  [ThinkingPhase.DETECTING]: 300,
  [ThinkingPhase.PLANNING]: 500,
  [ThinkingPhase.GENERATING]: 600,
  [ThinkingPhase.REVIEWING]: 400,
  [ThinkingPhase.UNCERTAIN]: 300,
  [ThinkingPhase.FOUND_ISSUE]: 400,
  [ThinkingPhase.COMPLETED]: 200
}

/**
 * Create a thought object
 */
function createThought(text, phase, confidence = 1.0, delay = 300) {
  return {
    text,
    phase,
    confidence,
    delay,
    timestamp: Date.now()
  }
}

/**
 * Thinker class
 * Generates human-like thinking-aloud text
 */
class Thinker {
  constructor(verbose = true) {
    this.verbose = verbose
    this.recentThoughts = []
    this.maxRecent = 5 // Track recent to avoid repetition
  }

  /**
   * Generate a thought for a specific phase
   */
  think(phase, context = null, confidence = 1.0) {
    const patterns = PATTERNS[phase] || PATTERNS[ThinkingPhase.ANALYZING]

    // Filter out recently used patterns
    let available = patterns.filter(p => !this.recentThoughts.includes(p))
    if (!available.length) {
      available = patterns
      this.recentThoughts = []
    }

    let text = available[Math.floor(Math.random() * available.length)]

    // Handle context substitution
    if (context && text.includes('{context}')) {
      text = text.replace('{context}', context)
    }

    // Add confidence modifier for uncertain thoughts
    if (confidence < 0.5 && phase !== ThinkingPhase.UNCERTAIN) {
      const prefix = UNCERTAIN_PREFIXES[Math.floor(Math.random() * UNCERTAIN_PREFIXES.length)]
      text = `${prefix} ${text.toLowerCase()}`
    }

    // Track recent
    this.recentThoughts.push(text)
    if (this.recentThoughts.length > this.maxRecent) {
      this.recentThoughts.shift()
    }

    const delay = PHASE_DELAYS[phase] || 300

    return createThought(text, phase, confidence, delay)
  }

  /**
   * Generate a sequence of thoughts for analyzing a page
   */
  analyzeSequence(pageType = null, includePlanning = true) {
    const thoughts = []

    // Start with analysis
    thoughts.push(this.think(ThinkingPhase.ANALYZING))

    // Add page-specific thought if available
    if (pageType && PAGE_SPECIFIC_THOUGHTS[pageType.toLowerCase()]) {
      const specific = PAGE_SPECIFIC_THOUGHTS[pageType.toLowerCase()]
      const text = specific[Math.floor(Math.random() * specific.length)]
      thoughts.push(createThought(text, ThinkingPhase.ANALYZING, 1.0, 400))
    }

    // Detection
    if (pageType) {
      thoughts.push(this.think(ThinkingPhase.DETECTING, pageType))
    }

    // Planning
    if (includePlanning) {
      thoughts.push(this.think(ThinkingPhase.PLANNING))
    }

    return thoughts
  }

  /**
   * Generate a sequence of thoughts for test generation
   */
  generateSequence() {
    return [
      this.think(ThinkingPhase.PLANNING),
      this.think(ThinkingPhase.GENERATING),
      this.think(ThinkingPhase.REVIEWING)
    ]
  }

  /**
   * Express uncertainty about something
   */
  uncertaintyThought(about) {
    const text = `I'm not entirely sure about ${about}...`
    return createThought(text, ThinkingPhase.UNCERTAIN, 0.5, 300)
  }

  /**
   * Express finding something interesting
   */
  discoveryThought(what) {
    const prefixes = ['Wait,', 'Interesting -', 'Hmm,', 'Oh,', 'Found something:']
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)]
    const text = `${prefix} ${what}`
    return createThought(text, ThinkingPhase.FOUND_ISSUE, 0.9, 400)
  }

  /**
   * Get a random thinking phrase for a phase (string only)
   */
  getPhrase(phase, context = null) {
    return this.think(phase, context).text
  }

  /**
   * Get page-specific thought
   */
  getPageThought(pageType) {
    const thoughts = PAGE_SPECIFIC_THOUGHTS[pageType?.toLowerCase()]
    if (!thoughts) return null
    return thoughts[Math.floor(Math.random() * thoughts.length)]
  }
}

/**
 * Quick helper to generate a thought
 */
function think(phase, context = null) {
  const thinker = new Thinker()
  const phaseEnum = Object.values(ThinkingPhase).includes(phase) ? phase : ThinkingPhase.ANALYZING
  return thinker.think(phaseEnum, context).text
}

/**
 * Quick helper to generate a thinking sequence
 */
function thinkSequence(pageType = null) {
  const thinker = new Thinker()
  return thinker.analyzeSequence(pageType).map(t => t.text)
}

/**
 * Get random phrase for a phase
 */
function getThinkingPhrase(phase) {
  const patterns = PATTERNS[phase] || PATTERNS[ThinkingPhase.ANALYZING]
  return patterns[Math.floor(Math.random() * patterns.length)]
}

module.exports = {
  ThinkingPhase,
  PATTERNS,
  PAGE_SPECIFIC_THOUGHTS,
  CONFIDENT_PREFIXES,
  UNCERTAIN_PREFIXES,
  PHASE_DELAYS,
  Thinker,
  createThought,
  think,
  thinkSequence,
  getThinkingPhrase
}
