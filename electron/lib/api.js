/**
 * DeepSeek API wrapper
 * ~80 lines
 */

const { DEEPSEEK_API_URL } = require('./config')

let apiKey = null

/**
 * Set API key
 */
function setApiKey(key) {
  apiKey = key
}

/**
 * Get API key
 */
function getApiKey() {
  return apiKey
}

/**
 * Check if API is configured
 */
function isApiConfigured() {
  return !!apiKey
}

/**
 * Call DeepSeek API
 */
async function callDeepSeek(messages, options = {}) {
  if (!apiKey) {
    throw new Error('API key not configured')
  }

  const {
    jsonMode = false,
    maxTokens = 500,
    temperature = 0.1,
    model = 'deepseek-chat'
  } = options

  const requestBody = {
    model,
    messages,
    max_tokens: maxTokens,
    temperature
  }

  if (jsonMode) {
    requestBody.response_format = { type: 'json_object' }
  }

  let response
  try {
    response = await fetch(DEEPSEEK_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(requestBody)
    })
  } catch (fetchError) {
    throw new Error(`Network error: ${fetchError.message}`)
  }

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'Unknown error')
    throw new Error(`API error ${response.status}: ${errorText.slice(0, 100)}`)
  }

  let data
  try {
    data = await response.json()
  } catch (jsonError) {
    throw new Error('Failed to parse API response')
  }

  if (!data.choices?.[0]?.message?.content) {
    throw new Error('Invalid API response: no content')
  }

  return {
    content: data.choices[0].message.content,
    usage: data.usage
  }
}

module.exports = {
  setApiKey,
  getApiKey,
  isApiConfigured,
  callDeepSeek
}
