/**
 * Action execution module
 * ~200 lines
 */

const { AGENT_LIMITS } = require('./config')
const { sleep, validateElement, actionMatchesIntent } = require('./utils')
const { clickElement, typeInElement, scrollPage, realPressEnter } = require('./input-simulator')

/**
 * Execute a single action with validation
 */
async function executeAction(browserView, viewBounds, action, pageState, userMessage, sendMessage) {
  const result = { success: false, message: '', domChanged: false }

  // Safety check for browserView
  if (!browserView && !['task_complete', 'answer', 'need_input', 'cannot_proceed'].includes(action.action)) {
    result.message = 'No browser available'
    return result
  }

  // Validate element exists BEFORE acting
  if (action.elementId && !['navigate', 'scroll', 'press_enter', 'wait', 'task_complete', 'answer', 'need_input', 'cannot_proceed'].includes(action.action)) {
    const element = validateElement(action.elementId, pageState.elements)
    if (!element) {
      result.message = `Element ${action.elementId} not found in current DOM. Page may have changed.`
      sendMessage?.('action_error', `Element not found - refreshing DOM`)
      return result
    }

    // Check if action matches user intent (prevent hallucination)
    const elText = element.text || element.label || ''
    if (!actionMatchesIntent(action.action, elText, userMessage)) {
      result.message = `Blocked: "${elText}" doesn't match request "${userMessage}". Avoiding wrong action.`
      sendMessage?.('action_blocked', `Blocked potential wrong action on "${elText}"`)
      return result
    }
  }

  switch (action.action) {
    case 'navigate': {
      let url = action.url
      if (!url) {
        result.message = 'No URL specified'
        break
      }

      if (!/^https?:\/\//i.test(url)) {
        const isLocal = url.includes('localhost') || url.includes('127.0.0.1')
        url = (isLocal ? 'http://' : 'https://') + url
      }

      sendMessage?.('action', `Navigating to ${url}...`)

      try {
        await browserView.webContents.loadURL(url)
        await sleep(AGENT_LIMITS.waitAfterNavigation)
        result.success = true
        result.message = `Navigated to ${url}`
        result.domChanged = true
      } catch (err) {
        result.message = `Failed to load: ${err.message}`
      }
      break
    }

    case 'click': {
      console.log('=== CLICK ACTION ===')
      console.log('Element ID:', action.elementId)

      if (!action.elementId) {
        result.message = 'No element specified to click'
        break
      }

      const element = validateElement(action.elementId, pageState.elements)
      console.log('Element found:', element ? `${element.text || element.label} (${element.tag})` : 'NOT FOUND')

      if (!element) {
        result.message = `Element ${action.elementId} not found`
        break
      }

      const elName = element?.text || element?.label || action.elementId

      sendMessage?.('action', `👆 Clicking "${elName}"...`)

      const clickResult = await clickElement(browserView, viewBounds, action.elementId)
      console.log('Click result:', clickResult)
      await sleep(AGENT_LIMITS.waitAfterClick)

      if (clickResult.success) {
        result.success = true
        result.domChanged = clickResult.urlChanged || false
        result.taskComplete = true  // ALWAYS stop after a successful click - let user see result

        if (clickResult.urlChanged) {
          result.message = `✓ Clicked "${elName}" and navigated to ${clickResult.newUrl}`
          sendMessage?.('action', `✓ Clicked "${elName}" → ${clickResult.newUrl}`)
        } else {
          // Click "worked" but page didn't change - might be popup, modal, or in-page update
          result.message = `✓ Clicked "${elName}"`
          sendMessage?.('action', `✓ Clicked "${elName}"`)
        }
      } else {
        result.message = clickResult.error
        sendMessage?.('action', `✗ Failed to click: ${clickResult.error}`)
      }
      break
    }

    case 'type': {
      if (!action.elementId) {
        result.message = 'No element specified to type in'
        break
      }

      const element = validateElement(action.elementId, pageState.elements)
      if (element?.category !== 'text-input' && element?.tag !== 'input' && element?.tag !== 'textarea') {
        result.message = `Element "${element?.text || action.elementId}" is not a text input`
        break
      }

      const elName = element?.label || element?.placeholder || action.elementId

      sendMessage?.('action', `Typing "${action.value}" in ${elName}...`)

      const typeResult = await typeInElement(browserView, viewBounds, action.elementId, action.value || '')
      await sleep(AGENT_LIMITS.waitAfterType)

      if (typeResult.success) {
        result.success = true
        result.message = `Typed "${action.value}" in ${elName}`
      } else {
        result.message = typeResult.error
      }
      break
    }

    case 'press_enter': {
      sendMessage?.('action', 'Pressing Enter...')
      await realPressEnter(browserView)
      await sleep(AGENT_LIMITS.waitAfterClick)
      result.success = true
      result.message = 'Pressed Enter'
      result.domChanged = true
      break
    }

    case 'scroll': {
      const direction = action.direction || 'down'
      sendMessage?.('action', `Scrolling ${direction}...`)
      await scrollPage(browserView, direction)
      await sleep(AGENT_LIMITS.domSettleTime)
      result.success = true
      result.message = `Scrolled ${direction}`
      break
    }

    case 'wait': {
      const waitTime = action.duration || 1000
      sendMessage?.('action', `Waiting ${waitTime}ms...`)
      await sleep(waitTime)
      result.success = true
      result.message = `Waited ${waitTime}ms`
      break
    }

    case 'task_complete': {
      result.success = true
      result.message = action.summary || 'Task completed'
      result.taskComplete = true
      break
    }

    case 'answer': {
      result.success = true
      result.message = action.found || 'Found what you were looking for'
      result.answered = true
      if (action.elements?.length) {
        result.message += '\n\n**Found on page:**\n' + action.elements.map(e => `• ${e}`).join('\n')
      }
      sendMessage?.('action', 'Found answer!')
      break
    }

    case 'need_input': {
      result.success = true
      result.message = action.question || 'Need more information'
      result.needsInput = true
      break
    }

    case 'cannot_proceed': {
      result.success = false
      result.message = action.reason || 'Cannot proceed with this task'
      result.cannotProceed = true
      break
    }

    default: {
      result.message = `Unknown action: ${action.action}`
    }
  }

  return result
}

/**
 * Check if action result indicates we should stop
 */
function shouldStopAfterAction(result) {
  return result.taskComplete || result.answered || result.needsInput || result.cannotProceed
}

module.exports = {
  executeAction,
  shouldStopAfterAction
}
