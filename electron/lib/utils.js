/**
 * Shared utility functions
 * ~120 lines
 */

const { PAGE_TYPE_PATTERNS } = require('./config')

/**
 * Pick random item from array
 */
function pick(arr) {
  if (!arr || arr.length === 0) return ''
  return arr[Math.floor(Math.random() * arr.length)]
}

/**
 * Detect page type from URL and elements
 */
function detectPageType(url = '', elements = []) {
  const urlLower = url.toLowerCase()

  for (const [type, pattern] of Object.entries(PAGE_TYPE_PATTERNS)) {
    if (pattern.test(urlLower)) return type
  }

  // Check elements for hints
  const elemTexts = elements
    .map(e => [e.text, e.label, e.placeholder].join(' '))
    .join(' ')
    .toLowerCase()

  if (/password|email.*password|login/i.test(elemTexts)) return 'login'
  if (/credit.*card|payment|billing/i.test(elemTexts)) return 'checkout'
  if (/search/i.test(elemTexts)) return 'search'

  return 'general'
}

/**
 * Get confidence level label
 */
function getConfidenceLevel(score) {
  if (score >= 0.9) return 'high'
  if (score >= 0.7) return 'medium'
  if (score >= 0.5) return 'low'
  return 'very-low'
}

/**
 * Check if user message is a question
 */
function isQuestion(message) {
  const lower = message.toLowerCase()
  return /^(where|what|how|when|why|which|find|show|is there|are there|can i|do you)/i.test(lower) ||
         lower.includes('?')
}

/**
 * Extract keywords from message
 */
function extractKeywords(message) {
  return message
    .toLowerCase()
    .split(/\s+/)
    .filter(w => w.length > 3)
    .filter(w => !['where', 'what', 'show', 'find', 'the', 'that', 'this', 'with', 'from'].includes(w))
}

/**
 * Check if element matches keywords
 */
function elementMatchesKeywords(element, keywords) {
  const text = [
    element.text,
    element.label,
    element.placeholder,
    element.ariaLabel,
    element.name
  ].filter(Boolean).join(' ').toLowerCase()

  return keywords.some(kw => text.includes(kw))
}

/**
 * Find matching elements for a search query
 */
function findMatchingElements(elements, query) {
  const keywords = extractKeywords(query)
  return elements.filter(el => elementMatchesKeywords(el, keywords))
}

/**
 * Validate element exists in current DOM
 */
function validateElement(elementId, elements) {
  return elements.find(e => e.id === elementId)
}

/**
 * Check if action matches user intent
 */
function actionMatchesIntent(action, elementText, userMessage) {
  const msgLower = userMessage.toLowerCase()
  const elLower = (elementText || '').toLowerCase()

  // Dangerous mismatches
  if (msgLower.includes('login') && elLower.includes('forgot')) return false
  if (msgLower.includes('login') && elLower.includes('reset')) return false
  if (msgLower.includes('login') && elLower.includes('sign up')) return false
  if (msgLower.includes('payment') && elLower.includes('cancel')) return false

  return true
}

/**
 * Sleep utility
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Truncate text for display
 */
function truncate(text, maxLen = 40) {
  if (!text) return ''
  return text.length > maxLen ? text.slice(0, maxLen) + '...' : text
}

module.exports = {
  pick,
  detectPageType,
  getConfidenceLevel,
  isQuestion,
  extractKeywords,
  elementMatchesKeywords,
  findMatchingElements,
  validateElement,
  actionMatchesIntent,
  sleep,
  truncate
}
