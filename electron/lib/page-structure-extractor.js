/**
 * Page Structure Extractor
 *
 * Extracts semantic page structure for AI understanding.
 * Unlike dom-extractor.js (which focuses on interactive elements),
 * this module extracts the hierarchical meaning of a page:
 * - Heading structure (H1 > H2 > H3)
 * - Landmark regions (nav, main, aside, header, footer)
 * - Form groupings
 * - Navigation menus
 * - Human-readable page summary
 */

/**
 * Extract hierarchical page structure from a browser view
 * @param {BrowserView} browserView - Electron BrowserView instance
 * @returns {Promise<PageStructure>}
 */
async function extractPageStructure(browserView) {
  if (!browserView) {
    return createEmptyStructure('No browser view')
  }

  try {
    const structure = await browserView.webContents.executeJavaScript(`
      (function() {
        // ═══════════════════════════════════════════════════════════════
        // HELPERS
        // ═══════════════════════════════════════════════════════════════

        function isVisible(el) {
          const rect = el.getBoundingClientRect()
          const style = getComputedStyle(el)
          return rect.width > 0 &&
                 rect.height > 0 &&
                 style.visibility !== 'hidden' &&
                 style.display !== 'none'
        }

        function getText(el, maxLen = 100) {
          return (el.innerText || el.textContent || '').trim().slice(0, maxLen)
        }

        function getRegionName(el) {
          const tag = el.tagName.toLowerCase()
          const role = el.getAttribute('role')
          const ariaLabel = el.getAttribute('aria-label')
          const id = el.id
          const className = el.className

          // Try aria-label first
          if (ariaLabel) return ariaLabel

          // Common patterns in id/class
          const patterns = {
            'nav': 'navigation',
            'header': 'header',
            'footer': 'footer',
            'sidebar': 'sidebar',
            'main': 'main content',
            'content': 'content',
            'menu': 'menu',
            'search': 'search',
            'login': 'login',
            'auth': 'authentication',
            'form': 'form',
            'modal': 'modal',
            'dialog': 'dialog',
            'banner': 'banner',
            'hero': 'hero section',
            'card': 'card',
            'list': 'list'
          }

          const combined = (id + ' ' + className).toLowerCase()
          for (const [pattern, name] of Object.entries(patterns)) {
            if (combined.includes(pattern)) return name
          }

          return tag
        }

        // ═══════════════════════════════════════════════════════════════
        // EXTRACT HEADINGS
        // ═══════════════════════════════════════════════════════════════

        const headings = []
        document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(h => {
          if (!isVisible(h)) return
          const level = parseInt(h.tagName[1])
          const text = getText(h, 80)
          if (text) {
            // Find which section this heading belongs to
            let section = 'main'
            let parent = h.parentElement
            while (parent && parent !== document.body) {
              const tag = parent.tagName.toLowerCase()
              if (['nav', 'header', 'footer', 'aside', 'main', 'section', 'article'].includes(tag)) {
                section = getRegionName(parent)
                break
              }
              parent = parent.parentElement
            }

            headings.push({ level, text, section })
          }
        })

        // ═══════════════════════════════════════════════════════════════
        // EXTRACT LANDMARK REGIONS
        // ═══════════════════════════════════════════════════════════════

        const sections = []
        const landmarkSelectors = [
          'nav', 'header', 'footer', 'main', 'aside',
          '[role="navigation"]', '[role="banner"]', '[role="main"]',
          '[role="complementary"]', '[role="contentinfo"]', '[role="search"]'
        ]

        const seenElements = new Set()
        landmarkSelectors.forEach(selector => {
          document.querySelectorAll(selector).forEach(el => {
            if (seenElements.has(el) || !isVisible(el)) return
            seenElements.add(el)

            const rect = el.getBoundingClientRect()
            const name = getRegionName(el)

            // Count interactive elements in this region
            const buttons = el.querySelectorAll('button, [role="button"], input[type="submit"]').length
            const links = el.querySelectorAll('a[href]').length
            const inputs = el.querySelectorAll('input, textarea, select').length
            const totalElements = buttons + links + inputs

            // Determine purpose based on content
            let purpose = 'unknown'
            if (name.includes('nav') || links > 3) purpose = 'site navigation'
            else if (name.includes('header') || name.includes('banner')) purpose = 'page header'
            else if (name.includes('footer')) purpose = 'page footer'
            else if (name.includes('sidebar') || name.includes('aside')) purpose = 'secondary content'
            else if (name.includes('main') || name.includes('content')) purpose = 'primary content'
            else if (name.includes('search')) purpose = 'search functionality'
            else if (name.includes('login') || name.includes('auth')) purpose = 'authentication'
            else if (inputs > 2) purpose = 'form area'
            else if (buttons > 2) purpose = 'action area'

            sections.push({
              name,
              tag: el.tagName.toLowerCase(),
              elements: totalElements,
              purpose,
              rect: {
                x: Math.round(rect.x),
                y: Math.round(rect.y),
                width: Math.round(rect.width),
                height: Math.round(rect.height)
              }
            })
          })
        })

        // ═══════════════════════════════════════════════════════════════
        // EXTRACT FORM GROUPS
        // ═══════════════════════════════════════════════════════════════

        const forms = []
        document.querySelectorAll('form').forEach(form => {
          if (!isVisible(form)) return

          const formName = form.getAttribute('name') ||
                          form.getAttribute('aria-label') ||
                          form.id ||
                          'unnamed form'

          const fields = []
          form.querySelectorAll('input, textarea, select').forEach(input => {
            if (!isVisible(input)) return
            const fieldName = input.name ||
                             input.id ||
                             input.placeholder ||
                             input.getAttribute('aria-label')
            if (fieldName) {
              fields.push({
                name: fieldName,
                type: input.type || input.tagName.toLowerCase(),
                required: input.required || false
              })
            }
          })

          // Find submit button
          const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])')
          const submitText = submitBtn ? getText(submitBtn, 30) : null

          forms.push({
            name: formName,
            fields,
            submitButton: submitText,
            action: form.action || null,
            method: form.method || 'get'
          })
        })

        // ═══════════════════════════════════════════════════════════════
        // EXTRACT NAVIGATION MENUS
        // ═══════════════════════════════════════════════════════════════

        const menus = []
        document.querySelectorAll('nav, [role="navigation"], [role="menu"], ul.menu, ul.nav').forEach(nav => {
          if (!isVisible(nav)) return

          const menuName = nav.getAttribute('aria-label') ||
                          nav.id ||
                          getRegionName(nav)

          const items = []
          nav.querySelectorAll('a, button, [role="menuitem"]').forEach(item => {
            const text = getText(item, 40)
            if (text && text.length > 1) {
              items.push({
                text,
                href: item.href || null,
                isCurrent: item.classList.contains('active') ||
                           item.getAttribute('aria-current') === 'page'
              })
            }
          })

          if (items.length > 0) {
            menus.push({
              name: menuName,
              items: items.slice(0, 15), // Limit items
              itemCount: items.length
            })
          }
        })

        // ═══════════════════════════════════════════════════════════════
        // EXTRACT KEY ACTIONS (Primary buttons)
        // ═══════════════════════════════════════════════════════════════

        const keyActions = []
        const primaryPatterns = /submit|save|create|add|send|confirm|apply|update|login|sign|register|buy|checkout|continue|next|done/i
        const dangerPatterns = /delete|remove|cancel|logout|sign.?out|exit/i

        document.querySelectorAll('button, [role="button"], input[type="submit"], a.btn, a.button').forEach(btn => {
          if (!isVisible(btn)) return
          const text = getText(btn, 40)
          if (!text || text.length < 2) return

          let actionType = 'secondary'
          if (primaryPatterns.test(text)) actionType = 'primary'
          else if (dangerPatterns.test(text)) actionType = 'danger'

          // Only track primary and danger actions
          if (actionType !== 'secondary') {
            keyActions.push({
              text,
              type: actionType,
              tag: btn.tagName.toLowerCase()
            })
          }
        })

        // ═══════════════════════════════════════════════════════════════
        // GENERATE HUMAN-READABLE SUMMARY
        // ═══════════════════════════════════════════════════════════════

        const title = document.title || 'Untitled Page'
        const h1 = document.querySelector('h1')?.innerText?.trim() || null

        let summary = ''

        // Page identity
        if (h1) {
          summary += 'This is a "' + h1 + '" page'
        } else {
          summary += 'This page (' + title + ')'
        }

        // Section summary
        if (sections.length > 0) {
          const sectionNames = sections.map(s => s.name).filter((v, i, a) => a.indexOf(v) === i)
          summary += ' with ' + sectionNames.length + ' main sections'
        }

        summary += '.\\n\\n'

        // Key sections
        if (sections.length > 0) {
          summary += 'Page structure:\\n'
          sections.forEach(s => {
            summary += '- ' + s.name.charAt(0).toUpperCase() + s.name.slice(1)
            if (s.elements > 0) {
              summary += ' (' + s.elements + ' interactive elements)'
            }
            if (s.purpose !== 'unknown') {
              summary += ' - ' + s.purpose
            }
            summary += '\\n'
          })
          summary += '\\n'
        }

        // Forms
        if (forms.length > 0) {
          summary += 'Forms on page:\\n'
          forms.forEach(f => {
            summary += '- ' + f.name + ' with ' + f.fields.length + ' fields'
            if (f.submitButton) {
              summary += ' ("' + f.submitButton + '" button)'
            }
            summary += '\\n'
          })
          summary += '\\n'
        }

        // Key actions
        if (keyActions.length > 0) {
          const primary = keyActions.filter(a => a.type === 'primary')
          const danger = keyActions.filter(a => a.type === 'danger')

          summary += 'Key actions available:\\n'
          primary.forEach(a => {
            summary += '- "' + a.text + '" (primary action)\\n'
          })
          danger.forEach(a => {
            summary += '- "' + a.text + '" (destructive action)\\n'
          })
        }

        // Navigation
        if (menus.length > 0) {
          const totalNavItems = menus.reduce((sum, m) => sum + m.itemCount, 0)
          summary += '\\nNavigation: ' + totalNavItems + ' links across ' + menus.length + ' menu(s)'

          const mainMenu = menus[0]
          if (mainMenu && mainMenu.items.length > 0) {
            summary += '\\nMain menu items: ' + mainMenu.items.slice(0, 5).map(i => '"' + i.text + '"').join(', ')
            if (mainMenu.items.length > 5) {
              summary += ', and ' + (mainMenu.items.length - 5) + ' more'
            }
          }
        }

        return {
          title,
          h1,
          headings,
          sections,
          forms,
          menus,
          keyActions,
          summary
        }
      })()
    `)

    return {
      success: true,
      ...structure
    }
  } catch (error) {
    return createEmptyStructure(error.message)
  }
}

/**
 * Create empty structure object
 */
function createEmptyStructure(error = null) {
  return {
    success: false,
    error,
    title: null,
    h1: null,
    headings: [],
    sections: [],
    forms: [],
    menus: [],
    keyActions: [],
    summary: 'Unable to analyze page structure.'
  }
}

/**
 * Get a concise page context for AI prompts
 * @param {PageStructure} structure - Result from extractPageStructure
 * @returns {string} - Formatted context string
 */
function formatStructureForPrompt(structure) {
  if (!structure.success) {
    return 'Page structure unavailable.'
  }

  let context = `PAGE: ${structure.title || 'Unknown'}\n`

  if (structure.h1) {
    context += `HEADING: ${structure.h1}\n`
  }

  if (structure.sections.length > 0) {
    context += `\nSTRUCTURE:\n`
    structure.sections.forEach(s => {
      context += `- ${s.name}: ${s.purpose} (${s.elements} elements)\n`
    })
  }

  if (structure.forms.length > 0) {
    context += `\nFORMS:\n`
    structure.forms.forEach(f => {
      const fields = f.fields.map(fd => fd.name).join(', ')
      context += `- ${f.name}: [${fields}] → ${f.submitButton || 'submit'}\n`
    })
  }

  if (structure.keyActions.length > 0) {
    const primary = structure.keyActions.filter(a => a.type === 'primary').map(a => a.text)
    const danger = structure.keyActions.filter(a => a.type === 'danger').map(a => a.text)

    context += `\nACTIONS:\n`
    if (primary.length) context += `- Primary: ${primary.join(', ')}\n`
    if (danger.length) context += `- Danger: ${danger.join(', ')}\n`
  }

  return context
}

/**
 * Detect the page type from structure
 * @param {PageStructure} structure
 * @returns {string} - Page type identifier
 */
function detectPageTypeFromStructure(structure) {
  if (!structure.success) return 'unknown'

  const { h1, title, forms, keyActions, summary } = structure
  const combinedText = `${h1 || ''} ${title || ''} ${summary || ''}`.toLowerCase()

  // Check for login/auth
  if (/login|sign.?in|authenticate/i.test(combinedText)) return 'login'
  if (/sign.?up|register|create.?account/i.test(combinedText)) return 'signup'

  // Check forms for auth indicators
  const hasPasswordField = forms.some(f => f.fields.some(fd => fd.type === 'password'))
  const hasEmailField = forms.some(f => f.fields.some(fd => fd.type === 'email' || fd.name?.includes('email')))
  if (hasPasswordField && hasEmailField) return 'login'

  // Check for other page types
  if (/dashboard|overview|home/i.test(combinedText)) return 'dashboard'
  if (/settings|preferences|configuration/i.test(combinedText)) return 'settings'
  if (/checkout|payment|cart/i.test(combinedText)) return 'checkout'
  if (/search|results/i.test(combinedText)) return 'search'
  if (/profile|account/i.test(combinedText)) return 'profile'

  // Check by form count
  if (forms.length > 0 && forms[0].fields.length > 3) return 'form'

  return 'general'
}

/**
 * Compare two page structures to detect meaningful changes
 * @param {PageStructure} before
 * @param {PageStructure} after
 * @returns {object} - Change summary
 */
function compareStructures(before, after) {
  const changes = {
    titleChanged: before.title !== after.title,
    h1Changed: before.h1 !== after.h1,
    sectionsChanged: before.sections.length !== after.sections.length,
    formsChanged: before.forms.length !== after.forms.length,
    newSections: [],
    removedSections: [],
    isSignificant: false
  }

  // Find new sections
  const beforeNames = new Set(before.sections.map(s => s.name))
  const afterNames = new Set(after.sections.map(s => s.name))

  changes.newSections = after.sections.filter(s => !beforeNames.has(s.name)).map(s => s.name)
  changes.removedSections = before.sections.filter(s => !afterNames.has(s.name)).map(s => s.name)

  // Determine if change is significant
  changes.isSignificant = changes.titleChanged ||
                          changes.h1Changed ||
                          changes.newSections.length > 0 ||
                          changes.formsChanged

  return changes
}

module.exports = {
  extractPageStructure,
  formatStructureForPrompt,
  detectPageTypeFromStructure,
  compareStructures,
  createEmptyStructure
}
