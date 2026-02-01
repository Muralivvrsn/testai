/**
 * Configuration and constants
 * ~60 lines
 */

const DEEPSEEK_API_URL = 'https://api.deepseek.com/v1/chat/completions'

const PAGE_TYPE_PATTERNS = {
  login: /login|signin|sign-in|log-in|auth/i,
  signup: /signup|sign-up|register|create.*account/i,
  checkout: /checkout|cart|payment|billing/i,
  search: /search|find|browse/i,
  form: /form|contact|submit|apply/i,
  dashboard: /dashboard|admin|portal|account/i,
  settings: /settings|preferences|config/i,
  profile: /profile|user|account/i
}

const TEST_CATEGORIES = {
  critical: { priority: 1, label: 'Critical Path' },
  functional: { priority: 2, label: 'Functional' },
  edge: { priority: 3, label: 'Edge Cases' },
  security: { priority: 4, label: 'Security' },
  accessibility: { priority: 5, label: 'Accessibility' }
}

const AGENT_LIMITS = {
  maxIterations: 10,
  maxElements: 60,
  waitAfterClick: 1500,
  waitAfterType: 500,
  waitAfterNavigation: 2000,
  domSettleTime: 300
}

const ACTION_TYPES = {
  navigation: ['navigate', 'go-back', 'refresh'],
  interaction: ['click', 'type', 'press_enter'],
  scroll: ['scroll', 'scroll-down', 'scroll-up'],
  completion: ['task_complete', 'answer', 'cannot_proceed', 'need_input'],
  testing: ['generate_tests']
}

module.exports = {
  DEEPSEEK_API_URL,
  PAGE_TYPE_PATTERNS,
  TEST_CATEGORIES,
  AGENT_LIMITS,
  ACTION_TYPES
}
