/**
 * Real input simulation (keyboard, mouse)
 * With visual cursor for QA testing
 */

const { sleep } = require('./utils')

/**
 * Inject visual cursor into the page (call once per page)
 */
async function injectVisualCursor(browserView) {
  if (!browserView) return false

  try {
    await browserView.webContents.executeJavaScript(`
      (function() {
        // Remove existing cursor if any
        const existing = document.getElementById('testai-cursor')
        if (existing) existing.remove()

        // Create cursor using DOM methods (safe)
        const cursor = document.createElement('div')
        cursor.id = 'testai-cursor'

        // Create SVG cursor shape
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
        svg.setAttribute('width', '24')
        svg.setAttribute('height', '24')
        svg.setAttribute('viewBox', '0 0 24 24')
        svg.setAttribute('fill', 'none')

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
        path.setAttribute('d', 'M5.5 3.5L18 12L12 13L9 19.5L5.5 3.5Z')
        path.setAttribute('fill', '#6366f1')
        path.setAttribute('stroke', '#fff')
        path.setAttribute('stroke-width', '1.5')
        svg.appendChild(path)
        cursor.appendChild(svg)

        cursor.style.cssText = 'position:fixed;top:0;left:0;width:24px;height:24px;pointer-events:none;z-index:999999;transition:transform 0.4s cubic-bezier(0.4,0,0.2,1);filter:drop-shadow(0 2px 4px rgba(0,0,0,0.3));display:none;'
        document.body.appendChild(cursor)

        // Create highlight ring
        const ring = document.createElement('div')
        ring.id = 'testai-ring'
        ring.style.cssText = 'position:fixed;width:40px;height:40px;border:3px solid #6366f1;border-radius:50%;pointer-events:none;z-index:999998;opacity:0;transform:translate(-50%,-50%) scale(0.5);transition:all 0.3s ease;'
        document.body.appendChild(ring)

        window.__testaiCursor = cursor
        window.__testaiRing = ring
        return true
      })()
    `)
    return true
  } catch (e) {
    console.log('Could not inject cursor:', e.message)
    return false
  }
}

/**
 * Move visual cursor to position with animation
 */
async function moveCursorTo(browserView, x, y, click = false) {
  if (!browserView) return

  try {
    await browserView.webContents.executeJavaScript(`
      (function() {
        const cursor = window.__testaiCursor || document.getElementById('testai-cursor')
        const ring = window.__testaiRing || document.getElementById('testai-ring')
        if (!cursor) return

        cursor.style.display = 'block'
        cursor.style.transform = 'translate(${x}px, ${y}px)'

        if (${click}) {
          // Show click effect
          setTimeout(() => {
            if (ring) {
              ring.style.left = '${x}px'
              ring.style.top = '${y}px'
              ring.style.opacity = '1'
              ring.style.transform = 'translate(-50%, -50%) scale(1)'

              setTimeout(() => {
                ring.style.opacity = '0'
                ring.style.transform = 'translate(-50%, -50%) scale(1.5)'
              }, 200)
            }
          }, 400)
        }
      })()
    `)
  } catch (e) {
    // Ignore cursor errors
  }
}

/**
 * Hide the visual cursor
 */
async function hideCursor(browserView) {
  if (!browserView) return

  try {
    await browserView.webContents.executeJavaScript(`
      (function() {
        const cursor = document.getElementById('testai-cursor')
        if (cursor) cursor.style.display = 'none'
      })()
    `)
  } catch (e) {
    // Ignore
  }
}

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

    // ─── VISUAL CURSOR: Move to element before clicking ───
    await moveCursorTo(browserView, elementInfo.x, elementInfo.y, true)
    await sleep(500) // Let user see the cursor move

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
  scrollPage,
  // Visual cursor functions
  injectVisualCursor,
  moveCursorTo,
  hideCursor
}
