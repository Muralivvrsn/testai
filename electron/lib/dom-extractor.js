/**
 * DOM Extraction for AI
 * ~250 lines
 */

const { truncate } = require('./utils')

/**
 * Extract DOM elements from browser view for AI consumption
 * @param {BrowserView} browserView - Electron BrowserView instance
 */
async function extractDomForAI(browserView) {
  if (!browserView) {
    return { success: false, elements: [], error: 'No browser view' }
  }

  try {
    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const results = []
        let idCounter = 0

        // Remove previous testai markers
        document.querySelectorAll('[data-testai]').forEach(el => {
          el.removeAttribute('data-testai')
        })

        // Get element visibility
        function isVisible(el) {
          const rect = el.getBoundingClientRect()
          const style = getComputedStyle(el)
          return rect.width > 0 &&
                 rect.height > 0 &&
                 style.visibility !== 'hidden' &&
                 style.display !== 'none' &&
                 style.opacity !== '0'
        }

        // Get element's human-readable text
        function getText(el) {
          return (el.innerText || el.textContent || '').trim().slice(0, 100)
        }

        // Categorize element
        function categorize(el) {
          const tag = el.tagName.toLowerCase()
          const type = (el.type || '').toLowerCase()
          const role = el.getAttribute('role')

          if (tag === 'button' || role === 'button' || type === 'submit') return 'button'
          if (tag === 'a') return 'link'
          if (tag === 'input') {
            if (['text', 'email', 'password', 'search', 'tel', 'url', 'number'].includes(type)) return 'text-input'
            if (['checkbox', 'radio'].includes(type)) return 'checkbox'
            if (type === 'file') return 'file-input'
            return 'input'
          }
          if (tag === 'textarea') return 'text-input'
          if (tag === 'select') return 'dropdown'
          if (['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag)) return 'heading'
          if (tag === 'img') return 'image'
          if (tag === 'nav') return 'navigation'
          if (el.onclick || el.getAttribute('onclick')) return 'clickable'
          if (role) return role
          return 'other'
        }

        // Interactive elements to extract
        const selectors = [
          'button', 'a[href]', 'input', 'textarea', 'select',
          '[role="button"]', '[role="link"]', '[role="tab"]',
          '[role="menuitem"]', '[role="checkbox"]', '[role="radio"]',
          '[onclick]', '[data-action]', '[tabindex="0"]',
          // OAuth/social login buttons often use these patterns
          '[class*="google"]', '[class*="login"]', '[class*="signin"]',
          '[class*="auth"]', '[class*="social"]', '[class*="btn"]',
          '[id*="google"]', '[id*="login"]', '[id*="signin"]'
        ]

        const seen = new Set()

        selectors.forEach(selector => {
          try {
            document.querySelectorAll(selector).forEach(el => {
              if (seen.has(el) || !isVisible(el)) return
              seen.add(el)

              const id = 'testai-' + (idCounter++)
              el.setAttribute('data-testai', id)

              const rect = el.getBoundingClientRect()
              const category = categorize(el)

              results.push({
                id,
                tag: el.tagName.toLowerCase(),
                type: el.type || null,
                category,
                text: getText(el),
                label: el.getAttribute('aria-label') ||
                       document.querySelector('label[for="' + el.id + '"]')?.textContent?.trim() || null,
                placeholder: el.placeholder || null,
                name: el.name || null,
                href: el.href || null,
                value: el.value || null,
                disabled: el.disabled || false,
                rect: {
                  x: Math.round(rect.x),
                  y: Math.round(rect.y),
                  width: Math.round(rect.width),
                  height: Math.round(rect.height)
                }
              })
            })
          } catch (e) {}
        })

        // Also find divs/spans that look clickable (cursor: pointer)
        // Many OAuth buttons are styled divs without proper semantic markup
        document.querySelectorAll('div, span').forEach(el => {
          if (seen.has(el) || !isVisible(el)) return
          const style = getComputedStyle(el)
          const text = getText(el)
          // Include if it looks clickable and has meaningful text
          if (style.cursor === 'pointer' && text.length > 0 && text.length < 50) {
            seen.add(el)
            const id = 'testai-' + (idCounter++)
            el.setAttribute('data-testai', id)
            const rect = el.getBoundingClientRect()
            results.push({
              id,
              tag: el.tagName.toLowerCase(),
              type: null,
              category: 'button',
              text,
              label: el.getAttribute('aria-label') || null,
              placeholder: null,
              name: null,
              href: null,
              value: null,
              disabled: false,
              rect: {
                x: Math.round(rect.x),
                y: Math.round(rect.y),
                width: Math.round(rect.width),
                height: Math.round(rect.height)
              }
            })
          }
        })

        return results
      })()
    `)

    // Filter out non-interactive elements and limit count
    const interactive = elements.filter(e => e.category !== 'other')

    return {
      success: true,
      elements: interactive,
      total: elements.length,
      interactive: interactive.length
    }
  } catch (error) {
    return { success: false, elements: [], error: error.message }
  }
}

/**
 * Get current page state
 */
async function getPageState(browserView) {
  if (!browserView) {
    return { hasPage: false, url: null, title: null, elements: [], visibleText: '' }
  }

  try {
    const [url, title] = await Promise.all([
      browserView.webContents.executeJavaScript('location.href'),
      browserView.webContents.executeJavaScript('document.title')
    ])

    const hasPage = url && url !== 'about:blank'

    if (!hasPage) {
      return { hasPage: false, url, title, elements: [], visibleText: '' }
    }

    // Extract fresh DOM - CRITICAL for accurate actions
    const domResult = await extractDomForAI(browserView)
    const elements = domResult.success ? domResult.elements : []

    // Get visible text for context
    let visibleText = ''
    try {
      visibleText = await browserView.webContents.executeJavaScript(`
        document.body.innerText.slice(0, 3000)
      `)
    } catch (e) {}

    return {
      hasPage: true,
      url,
      title,
      elements,
      visibleText
    }
  } catch (error) {
    return { hasPage: false, url: null, title: null, elements: [], visibleText: '', error: error.message }
  }
}

/**
 * Find element by intent (text matching)
 */
function findElementByIntent(elements, intent) {
  const intentLower = intent.toLowerCase()

  // Exact match first
  const exact = elements.find(e => {
    const text = (e.text || e.label || e.placeholder || '').toLowerCase()
    return text === intentLower
  })
  if (exact) return { element: exact, confidence: 1.0 }

  // Contains match
  const contains = elements.find(e => {
    const text = (e.text || e.label || e.placeholder || '').toLowerCase()
    return text.includes(intentLower) || intentLower.includes(text)
  })
  if (contains) return { element: contains, confidence: 0.8 }

  // Word overlap
  const intentWords = intentLower.split(/\s+/)
  let bestMatch = null
  let bestScore = 0

  for (const el of elements) {
    const text = (el.text || el.label || el.placeholder || '').toLowerCase()
    const elWords = text.split(/\s+/)
    const overlap = intentWords.filter(w => elWords.some(ew => ew.includes(w) || w.includes(ew))).length
    const score = overlap / intentWords.length

    if (score > bestScore) {
      bestScore = score
      bestMatch = el
    }
  }

  if (bestMatch && bestScore > 0.3) {
    return { element: bestMatch, confidence: bestScore }
  }

  return { element: null, confidence: 0 }
}

/**
 * Format elements for AI prompt
 */
function formatElementsForAI(elements, limit = 40) {
  return elements.slice(0, limit).map(e => ({
    id: e.id,
    tag: e.tag,
    category: e.category,
    text: truncate(e.text || e.label || e.placeholder || '', 50)
  }))
}

module.exports = {
  extractDomForAI,
  getPageState,
  findElementByIntent,
  formatElementsForAI
}
