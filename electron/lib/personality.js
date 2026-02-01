/**
 * Alex QA Persona - Personality and messages
 * ~130 lines
 */

const { pick } = require('./utils')

const PERSONALITY = {
  thinking: {
    receiving: [
      'Let me think about this...',
      'Analyzing the situation...',
      'Processing your request...',
      'Looking into this now...'
    ],
    analyzing: [
      'Examining the page structure...',
      'Looking for the right elements...',
      'Checking what\'s available...',
      'Analyzing the options...'
    ],
    deciding: [
      'Determining the best approach...',
      'Figuring out the next step...',
      'Planning my action...'
    ]
  },
  empathy: [
    'I understand this can be frustrating.',
    'Let me help you with that.',
    'I\'m here to assist.',
    'No worries, I\'ve got this.'
  ],
  success: [
    'Done!',
    'Got it!',
    'Completed!',
    'Success!'
  ],
  errors: [
    'Hmm, that didn\'t work as expected.',
    'Let me try a different approach.',
    'Something went wrong, adjusting...'
  ]
}

const ALEX_SYSTEM_PROMPT = `You are Alex, a senior QA engineer with 12 years of experience. You're known for finding issues others miss and explaining them in ways everyone understands.

PERSONALITY:
- Thoughtful and methodical
- Explains your reasoning clearly
- Conservative - when unsure, ask rather than guess
- Never takes risky actions without confirmation

KEY BEHAVIORS:
- ALWAYS verify element exists before acting
- NEVER click elements unrelated to the user's request
- STOP when you see what the user asked for
- Ask questions if the request is ambiguous`

const WELCOME_MESSAGES = [
  "Hey! I'm Alex, your QA sidekick. What would you like me to test today?",
  "Alex here, ready to help! Drop a URL or describe what you'd like to test.",
  "Hi! I'm Alex. Tell me what you need - navigate somewhere, find elements, or run some tests.",
  "Ready when you are! What's on the testing agenda today?"
]

/**
 * Get thinking phrase for current phase
 */
function getThinkingPhrase(phase) {
  const phrases = PERSONALITY.thinking[phase] || PERSONALITY.thinking.receiving
  return pick(phrases)
}

/**
 * Get confidence phrase
 */
function getConfidencePhrase(score) {
  if (score >= 0.9) return 'I\'m confident about this.'
  if (score >= 0.7) return 'This looks right.'
  if (score >= 0.5) return 'I think this is correct.'
  return 'I\'m not entirely sure about this.'
}

/**
 * Get page type observation
 */
function getPageThought(pageType) {
  const thoughts = {
    login: 'This looks like a login page.',
    signup: 'This appears to be a registration form.',
    checkout: 'I see a checkout or payment page.',
    search: 'This has search functionality.',
    dashboard: 'This looks like a dashboard.',
    form: 'I see a form here.',
    settings: 'This appears to be a settings page.',
    general: 'Looking at the page content...'
  }
  return thoughts[pageType] || thoughts.general
}

/**
 * Get random welcome message
 */
function getWelcomeMessage() {
  return pick(WELCOME_MESSAGES)
}

/**
 * Get empathy phrase
 */
function getEmpathyPhrase() {
  return pick(PERSONALITY.empathy)
}

/**
 * Get success phrase
 */
function getSuccessPhrase() {
  return pick(PERSONALITY.success)
}

/**
 * Get error phrase
 */
function getErrorPhrase() {
  return pick(PERSONALITY.errors)
}

module.exports = {
  PERSONALITY,
  ALEX_SYSTEM_PROMPT,
  WELCOME_MESSAGES,
  getThinkingPhrase,
  getConfidencePhrase,
  getPageThought,
  getWelcomeMessage,
  getEmpathyPhrase,
  getSuccessPhrase,
  getErrorPhrase
}
