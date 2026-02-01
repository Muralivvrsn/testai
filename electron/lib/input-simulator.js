/**
 * Real input simulation (keyboard, mouse)
 * ~180 lines
 */

const { sleep } = require('./utils')

/**
 * Get element bounds for clicking
 */
async function getElementBounds(browserView, elementId) {
  if (!browserView) return null

  try {
    return await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (!el) return null
        const rect = el.getBoundingClientRect()
        return {
          x: Math.round(rect.x + rect.width / 2),
          y: Math.round(rect.y + rect.height / 2),
          width: Math.round(rect.width),
          height: Math.round(rect.height)
        }
      })()
    `)
  } catch {
    return null
  }
}

/**
 * Scroll element into view
 */
async function scrollToElement(browserView, elementId) {
  if (!browserView) return false

  try {
    return await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (!el) return false
        el.scrollIntoView({ behavior: 'smooth', block: 'center' })
        return true
      })()
    `)
  } catch {
    return false
  }
}

/**
 * Perform real mouse click
 */
async function realClick(browserView, viewBounds, x, y) {
  if (!browserView) return false

  try {
    // Calculate absolute position
    const absX = Math.round(viewBounds.x + x)
    const absY = Math.round(viewBounds.y + y)

    // Send mouse events
    browserView.webContents.sendInputEvent({ type: 'mouseDown', x: absX, y: absY, button: 'left', clickCount: 1 })
    await sleep(50)
    browserView.webContents.sendInputEvent({ type: 'mouseUp', x: absX, y: absY, button: 'left', clickCount: 1 })

    return true
  } catch {
    return false
  }
}

/**
 * Type text using keyboard events
 */
async function realType(browserView, text) {
  if (!browserView || !text) return false

  try {
    for (const char of text) {
      browserView.webContents.sendInputEvent({ type: 'keyDown', keyCode: char })
      browserView.webContents.sendInputEvent({ type: 'char', keyCode: char })
      browserView.webContents.sendInputEvent({ type: 'keyUp', keyCode: char })
      await sleep(20) // Small delay between characters
    }
    return true
  } catch {
    return false
  }
}

/**
 * Press Enter key
 */
async function realPressEnter(browserView) {
  if (!browserView) return false

  try {
    browserView.webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Return' })
    browserView.webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Return' })
    return true
  } catch {
    return false
  }
}

/**
 * Click on element by ID - using REAL mouse events (required for OAuth buttons)
 */
async function clickElement(browserView, viewBounds, elementId) {
  if (!browserView) return { success: false, error: 'No browser' }

  try {
    // Get URL before click to detect navigation
    const urlBefore = await browserView.webContents.executeJavaScript('location.href')

    // First, scroll element into view and get its position
    const elementInfo = await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (!el) return null

        // Scroll into view
        el.scrollIntoView({ behavior: 'instant', block: 'center' })

        // Wait a frame for scroll to complete
        return new Promise(resolve => {
          requestAnimationFrame(() => {
            const rect = el.getBoundingClientRect()
            resolve({
              x: Math.round(rect.x + rect.width / 2),
              y: Math.round(rect.y + rect.height / 2),
              width: Math.round(rect.width),
              height: Math.round(rect.height),
              text: (el.innerText || el.textContent || '').slice(0, 50),
              tag: el.tagName,
              visible: rect.width > 0 && rect.height > 0
            })
          })
        })
      })()
    `)

    if (!elementInfo) {
      return { success: false, error: 'Element not found on page' }
    }

    if (!elementInfo.visible) {
      return { success: false, error: 'Element is not visible' }
    }

    console.log('=== REAL CLICK ===')
    console.log('Element:', elementInfo.text, `(${elementInfo.tag})`)
    console.log('Element position in page:', elementInfo.x, elementInfo.y)
    console.log('View bounds:', viewBounds)

    // Calculate absolute screen position
    // The element position is relative to the viewport
    // viewBounds.x/y is where the BrowserView starts on screen
    const absX = Math.round(viewBounds.x + elementInfo.x)
    const absY = Math.round(viewBounds.y + elementInfo.y)

    console.log('Clicking at absolute position:', absX, absY)

    // Send REAL mouse events (these are trusted events!)
    browserView.webContents.sendInputEvent({
      type: 'mouseDown',
      x: elementInfo.x,  // Use viewport-relative coords for sendInputEvent
      y: elementInfo.y,
      button: 'left',
      clickCount: 1
    })

    await sleep(50)

    browserView.webContents.sendInputEvent({
      type: 'mouseUp',
      x: elementInfo.x,
      y: elementInfo.y,
      button: 'left',
      clickCount: 1
    })

    console.log('Real mouse events sent!')

    // Wait for potential navigation/popup
    await sleep(800)

    // Check if URL changed
    const urlAfter = await browserView.webContents.executeJavaScript('location.href')
    const urlChanged = urlBefore !== urlAfter

    console.log('Click complete - URL changed:', urlChanged)
    if (urlChanged) {
      console.log('  From:', urlBefore)
      console.log('  To:', urlAfter)
    }

    return {
      success: true,
      action: 'clicked',
      elementId,
      elementText: elementInfo.text,
      urlChanged,
      newUrl: urlChanged ? urlAfter : null
    }
  } catch (error) {
    console.error('Click error:', error)
    return { success: false, error: error.message }
  }
}

/**
 * Type in element by ID
 */
async function typeInElement(browserView, viewBounds, elementId, text) {
  if (!browserView) return { success: false, error: 'No browser' }

  try {
    // Focus element and clear existing value
    await browserView.webContents.executeJavaScript(`
      (function() {
        const el = document.querySelector('[data-testai="${elementId}"]')
        if (el) {
          el.focus()
          el.value = ''
          el.dispatchEvent(new Event('focus', { bubbles: true }))
        }
      })()
    `)

    await sleep(50)

    // Type using real keyboard events
    const typed = await realType(browserView, text)

    if (!typed) {
      // Fallback to setting value directly
      await browserView.webContents.executeJavaScript(`
        (function() {
          const el = document.querySelector('[data-testai="${elementId}"]')
          if (el) {
            el.value = ${JSON.stringify(text)}
            el.dispatchEvent(new Event('input', { bubbles: true }))
            el.dispatchEvent(new Event('change', { bubbles: true }))
          }
        })()
      `)
    }

    return { success: true, action: 'typed', elementId, value: text }
  } catch (error) {
    return { success: false, error: error.message }
  }
}

/**
 * Scroll page
 */
async function scrollPage(browserView, direction = 'down') {
  if (!browserView) return { success: false, error: 'No browser' }

  try {
    const amount = direction === 'up' ? -400 : 400
    await browserView.webContents.executeJavaScript(`
      window.scrollBy({ top: ${amount}, behavior: 'smooth' })
    `)
    return { success: true, action: 'scrolled', direction }
  } catch (error) {
    return { success: false, error: error.message }
  }
}

module.exports = {
  getElementBounds,
  scrollToElement,
  realClick,
  realType,
  realPressEnter,
  clickElement,
  typeInElement,
  scrollPage
}
