/**
 * Yalitest Main Process
 * Clean modular architecture with auto-update
 */

const { app, BrowserWindow, BrowserView, ipcMain, nativeTheme } = require('electron')
const path = require('path')
const fs = require('fs')

// Auto-updater for automatic updates
let autoUpdater = null
if (app.isPackaged) {
  try {
    autoUpdater = require('electron-updater').autoUpdater
    autoUpdater.autoDownload = true
    autoUpdater.autoInstallOnAppQuit = true
  } catch (e) {
    console.log('Auto-updater not available:', e.message)
  }
}

// Import modules
const { setApiKey, getApiKey, isApiConfigured } = require('./lib/api')
const { extractDomForAI, getPageState, formatElementsForAI } = require('./lib/dom-extractor')
const { clickElement, typeInElement, scrollPage, realPressEnter } = require('./lib/input-simulator')
const { runAgentLoop, generateTestsForPage, analyzeSecurityForPage } = require('./lib/agent')
const { generateTests, getKnowledge, getFocusAreas } = require('./lib/qa-brain')
const { getWelcomeMessage, getEmpathyPhrase } = require('./lib/personality')
const { detectPageType, sleep } = require('./lib/utils')
const { AGENT_LIMITS } = require('./lib/config')
const { getKnowledgeForPageType, formatKnowledgeForPrompt } = require('./lib/knowledge')

// ============ STATE ============
let mainWindow = null
let browserView = null
let sidebarWidth = 0  // Start with sidebar closed
let chatWidth = 0     // Start with chat closed
let viewportOverride = null
let resizeTimeout = null

// Conversation memory
let conversationHistory = []
let actionHistory = []

function addToHistory(role, content) {
  conversationHistory.push({ role, content, timestamp: Date.now() })
  // Keep last 20 messages for context
  if (conversationHistory.length > 20) {
    conversationHistory = conversationHistory.slice(-20)
  }
}

function addAction(action, result) {
  actionHistory.push({ action, result, timestamp: Date.now() })
  // Keep last 10 actions
  if (actionHistory.length > 10) {
    actionHistory = actionHistory.slice(-10)
  }
}

const isDev = !app.isPackaged
const isMac = process.platform === 'darwin'
const isWindows = process.platform === 'win32'

// Load API key from env
loadEnvFile()

function loadEnvFile() {
  try {
    const envPath = path.join(__dirname, '..', '.env')
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf-8')
      const match = content.match(/DEEPSEEK_API_KEY=(.+)/)
      if (match) setApiKey(match[1].trim())
    }
  } catch (e) {}

  // Also check process.env
  if (process.env.DEEPSEEK_API_KEY) {
    setApiKey(process.env.DEEPSEEK_API_KEY)
  }
}

// ============ WINDOW CREATION ============
function createWindow() {
  const windowOptions = {
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#171717' : '#FAFAFA',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      backgroundThrottling: false
    }
  }

  if (isMac) {
    windowOptions.titleBarStyle = 'hiddenInset'
    windowOptions.trafficLightPosition = { x: 16, y: 18 }
  }

  if (isWindows) {
    windowOptions.frame = true
    windowOptions.autoHideMenuBar = true
  }

  mainWindow = new BrowserWindow(windowOptions)

  mainWindow.once('ready-to-show', () => mainWindow.show())

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
  }

  mainWindow.on('closed', cleanup)
  mainWindow.on('resize', () => {
    if (resizeTimeout) clearTimeout(resizeTimeout)
    resizeTimeout = setTimeout(updateBrowserViewBounds, 16)
  })

  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('platform-info', { isMac, isWindows, isDev })
  })
}

function cleanup() {
  if (browserView) {
    browserView.webContents.removeAllListeners()
    browserView = null
  }
  mainWindow = null
  if (resizeTimeout) clearTimeout(resizeTimeout)
}

// ============ BROWSER VIEW ============
function updateBrowserViewBounds() {
  if (!mainWindow || !browserView) return

  const bounds = mainWindow.getContentBounds()
  const topBarHeight = 56  // Match React's top-[56px]

  let x = sidebarWidth
  let y = topBarHeight
  let width = bounds.width - sidebarWidth - chatWidth
  let height = bounds.height - topBarHeight

  if (viewportOverride?.width > 0) {
    const availWidth = bounds.width - sidebarWidth - chatWidth
    const availHeight = bounds.height - topBarHeight
    const scale = Math.min(availWidth / viewportOverride.width, availHeight / viewportOverride.height, 1)

    width = Math.round(viewportOverride.width * scale)
    height = Math.round(viewportOverride.height * scale)
    x = sidebarWidth + Math.round((availWidth - width) / 2)
    y = topBarHeight + Math.round((availHeight - height) / 2)
  }

  browserView.setBounds({
    x: Math.max(0, x),
    y: Math.max(0, y),
    width: Math.max(100, width),
    height: Math.max(100, height)
  })
}

function getViewBounds() {
  if (!browserView) return { x: 0, y: 0, width: 0, height: 0 }
  return browserView.getBounds()
}

function createBrowserView() {
  if (browserView) {
    browserView.webContents.removeAllListeners()
    mainWindow.removeBrowserView(browserView)
    browserView = null
  }

  browserView = new BrowserView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      backgroundThrottling: true
    }
  })

  mainWindow.addBrowserView(browserView)
  updateBrowserViewBounds()

  const wc = browserView.webContents

  wc.on('did-navigate', (_, url) => mainWindow?.webContents.send('url-changed', url))
  wc.on('did-navigate-in-page', (_, url) => mainWindow?.webContents.send('url-changed', url))
  wc.on('page-title-updated', (_, title) => mainWindow?.webContents.send('title-changed', title))
  wc.on('did-finish-load', () => mainWindow?.webContents.send('page-loaded'))
  wc.on('did-fail-load', (_, errorCode, errorDescription) => {
    mainWindow?.webContents.send('page-error', { errorCode, errorDescription })
  })

  wc.setWindowOpenHandler(({ url }) => {
    wc.loadURL(url)
    return { action: 'deny' }
  })

  return browserView
}

// ============ HELPER: Send message to UI ============
function sendMessage(type, message) {
  mainWindow?.webContents.send('agent-message', { type, message })
}

// ============ IPC HANDLERS ============

// Navigation
ipcMain.handle('navigate', async (_, url) => {
  if (!browserView) createBrowserView()

  if (!/^https?:\/\//i.test(url)) {
    const isLocal = url.includes('localhost') || url.includes('127.0.0.1')
    url = (isLocal ? 'http://' : 'https://') + url
  }

  try {
    await browserView.webContents.loadURL(url)
    return { success: true, url }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('go-back', () => {
  if (browserView?.webContents.canGoBack()) {
    browserView.webContents.goBack()
    return { success: true }
  }
  return { success: false }
})

ipcMain.handle('go-forward', () => {
  if (browserView?.webContents.canGoForward()) {
    browserView.webContents.goForward()
    return { success: true }
  }
  return { success: false }
})

ipcMain.handle('reload', () => {
  browserView?.webContents.reload()
  return { success: true }
})

// Layout
ipcMain.handle('set-sidebar-width', (_, width) => {
  sidebarWidth = width
  updateBrowserViewBounds()
})

ipcMain.handle('set-chat-width', (_, width) => {
  chatWidth = width
  updateBrowserViewBounds()
})

ipcMain.handle('set-viewport', (_, width, height) => {
  viewportOverride = width && height ? { width, height } : null
  updateBrowserViewBounds()
})

// DOM extraction
ipcMain.handle('extract-dom', async () => {
  if (!browserView) return { success: false, elements: [] }
  return await extractDomForAI(browserView)
})

// Element actions
ipcMain.handle('click-element', async (_, id) => {
  if (!browserView) return { success: false, error: 'No browser' }
  return await clickElement(browserView, getViewBounds(), id)
})

ipcMain.handle('type-in-element', async (_, id, text) => {
  if (!browserView) return { success: false, error: 'No browser' }
  return await typeInElement(browserView, getViewBounds(), id, text)
})

// Page info
ipcMain.handle('get-page-info', async () => {
  if (!browserView) return { url: '', title: '', hasPage: false }
  return await getPageState(browserView)
})

ipcMain.handle('get-platform', () => ({ isMac, isWindows, isDev }))

// API key management
ipcMain.handle('set-api-key', (_, key) => {
  setApiKey(key)
  return { success: true }
})

ipcMain.handle('agent-status', () => ({
  hasApiKey: isApiConfigured(),
  hasPage: !!browserView
}))

// Welcome message
ipcMain.handle('get-welcome-message', () => {
  return { message: getWelcomeMessage() }
})

// ============ MAIN CHAT HANDLER (AI-DRIVEN WITH MEMORY) ============
ipcMain.handle('chat-with-agent', async (_, message, context) => {
  console.log('=== CHAT WITH AGENT ===')
  console.log('Message:', message)

  // Add user message to history
  addToHistory('user', message)

  // Check API key first
  if (!isApiConfigured()) {
    return {
      success: false,
      error: `${getEmpathyPhrase()}\n\nI need my API key to help you. Add your DeepSeek API key in Settings.`
    }
  }

  try {
    const { callDeepSeek } = require('./lib/api')

    // Get current page state
    let pageInfo = 'No page currently loaded.'
    let pageUrl = null
    if (browserView) {
      try {
        pageUrl = await browserView.webContents.executeJavaScript('location.href')
        const title = await browserView.webContents.executeJavaScript('document.title')
        if (pageUrl && pageUrl !== 'about:blank') {
          pageInfo = `Current page: "${title}" at ${pageUrl}`
        }
      } catch (e) {}
    }

    // Build conversation context - include more history for better context
    const recentChat = conversationHistory.slice(-10).map(m => `${m.role}: ${m.content}`).join('\n')
    const recentActions = actionHistory.slice(-8).map(a => `- ${a.action}: ${a.result}`).join('\n')

    // Ask AI what to do with FULL context
    const decisionPrompt = `You are Yali, a proactive QA engineer. You DO things, you don't ask unnecessary questions.

CONVERSATION HISTORY:
${recentChat || 'No previous messages'}

RECENT ACTIONS TAKEN:
${recentActions || 'None yet'}

CURRENT STATE:
- ${pageInfo}

USER'S NEW MESSAGE: "${message}"

Decide what to do. Return JSON:

For greetings/casual chat only:
{ "type": "chat", "response": "brief friendly response" }

For "TEST [URL]" requests (user wants to test a website):
{ "type": "test_url", "url": "full URL" }

For navigation ONLY (user just wants to visit/open a page, no testing):
{ "type": "navigate", "url": "full URL" }

For EXPLORATION requests on current page (explore, test everything, check the site, find issues):
{ "type": "explore", "scope": "full" }

For LOGIN with credentials (user provides email/username AND password):
{ "type": "login", "email": "the email/username", "password": "the password" }

For specific actions (click X, type Y, find Z):
{ "type": "action" }

For situations where you TRULY cannot proceed:
{ "type": "clarify", "response": "ask ONLY what's blocking you" }

CRITICAL RULES:
- "can you test [URL]" = type "test_url" - NAVIGATE AND START TESTING
- "test the [site]" = type "test_url" - NAVIGATE AND START TESTING
- "test this website" on current page = type "explore"
- "explore/audit/review" = type "explore" - START IMMEDIATELY
- "go to [URL]" or "open [URL]" WITHOUT test/check/explore = type "navigate"
- If user provides BOTH email/username AND password = type "login" - extract and use them
- If message contains URL + email + "let me know if you need password" = type "test_url", work until you need password
- NEVER ask "what do you want me to check" - a QA tests EVERYTHING
- NEVER stop after one action - CONTINUE until the user's goal is FULLY satisfied
- Be a DOER, not an asker - KEEP WORKING until done`

    // ALL DECISIONS MADE BY AI - No hardcoded pattern matching
    console.log('Asking AI for decision...')
    const response = await callDeepSeek([
      { role: 'system', content: 'You are Yali, a friendly QA assistant. Return only valid JSON.' },
      { role: 'user', content: decisionPrompt }
    ], { jsonMode: true, maxTokens: 300, temperature: 0.3 })

    // Parse AI response with error handling
    let decision
    try {
      decision = JSON.parse(response.content)
    } catch (parseError) {
      console.error('JSON parse error:', parseError.message)
      console.log('Raw response:', response.content?.slice(0, 200))

      // Try to extract action type from malformed response
      if (/action|click|type|navigate/i.test(response.content)) {
        decision = { type: 'action' }
      } else {
        // Fallback: treat as chat
        decision = {
          type: 'chat',
          response: "I understood your request. Let me help you with that."
        }
      }
    }
    console.log('AI decision:', decision.type)

    // Handle based on AI decision
    switch (decision.type) {
      case 'chat': {
        addToHistory('assistant', decision.response)
        return { success: true, response: decision.response }
      }

      case 'clarify': {
        addToHistory('assistant', decision.response)
        return { success: true, response: decision.response }
      }

      case 'navigate': {
        if (!browserView) createBrowserView()

        let url = decision.url
        if (!/^https?:\/\//i.test(url)) {
          const isLocal = url.includes('localhost') || url.includes('127.0.0.1')
          url = (isLocal ? 'http://' : 'https://') + url
        }

        // Send "doing" message
        sendMessage?.('action', `🌐 Loading ${url}...`)

        try {
          await browserView.webContents.loadURL(url)
          await sleep(2500)

          // Get page title after load
          let title = url
          try {
            title = await browserView.webContents.executeJavaScript('document.title') || url
          } catch (e) {}

          // Record action
          addAction(`Navigate to ${url}`, 'success')
          sendMessage?.('action', `✓ Loaded ${title}`)

          // Check if user wanted MORE actions after navigation
          // (e.g., "load page X and then click Y")
          const hasMoreActions = /and then|then|after that|also|click|login|sign|find|type|fill/i.test(message)

          if (hasMoreActions) {
            console.log('User wants more actions after navigation, continuing...')
            // Continue to agent loop for remaining actions
            const result = await runAgentLoop(browserView, getViewBounds(), message, sendMessage)

            if (result.history) {
              result.history.forEach(h => addAction(h.action, h.result))
            }

            const fullResponse = `I've loaded **${title}** and ${result.response || 'completed the actions.'}`
            addToHistory('assistant', fullResponse)
            return { success: result.success, response: fullResponse }
          }

          // Just navigation, no more actions
          const doneResponse = `I've loaded **${title}**. What would you like me to do on this page?`
          addToHistory('assistant', doneResponse)
          return { success: true, response: doneResponse }

        } catch (err) {
          addAction(`Navigate to ${url}`, `failed: ${err.message}`)
          const errorResponse = `I couldn't load that page: ${err.message}`
          addToHistory('assistant', errorResponse)
          return { success: false, error: errorResponse }
        }
      }

      case 'test_url': {
        // User wants to TEST a URL - navigate AND start testing automatically
        if (!browserView) createBrowserView()

        let url = decision.url
        if (!/^https?:\/\//i.test(url)) {
          const isLocal = url.includes('localhost') || url.includes('127.0.0.1')
          url = (isLocal ? 'http://' : 'https://') + url
        }

        sendMessage?.('action', `🌐 Loading ${url}...`)

        try {
          await browserView.webContents.loadURL(url)
          await sleep(2500)

          // Get page title
          let title = url
          try {
            title = await browserView.webContents.executeJavaScript('document.title') || url
          } catch (e) {}

          addAction(`Navigate to ${url}`, 'success')
          sendMessage?.('action', `✓ Loaded **${title}**`)

          // Run agent with the USER'S ORIGINAL MESSAGE - it contains important context like email/password
          const result = await runAgentLoop(
            browserView,
            getViewBounds(),
            message,  // Pass the ORIGINAL user message, not a generic one!
            sendMessage
          )

          // Check if we need credentials (landed on login page)
          if (result.needsCredentials) {
            const credResponse = result.response || result.report
            addToHistory('assistant', credResponse)
            return {
              success: true,
              response: credResponse,
              needsCredentials: true,
              actionsTaken: 1
            }
          }

          if (result.history) {
            result.history.forEach(h => addAction(h.action, h.result))
          }

          const fullResponse = result.response || `Testing complete! ${result.actionsTaken || 0} actions performed.`
          addToHistory('assistant', fullResponse)
          return {
            success: result.success,
            response: fullResponse,
            actionsTaken: (result.actionsTaken || 0) + 1
          }

        } catch (err) {
          addAction(`Test ${url}`, `failed: ${err.message}`)
          const errorResponse = `I couldn't load that page: ${err.message}`
          addToHistory('assistant', errorResponse)
          return { success: false, error: errorResponse }
        }
      }

      case 'explore': {
        // Full exploration mode - like a real QA engineer
        if (!browserView) {
          const response = "I need a page to explore first. Which website should I test?"
          addToHistory('assistant', response)
          return { success: true, response }
        }

        // Get current URL
        let currentUrl = 'unknown'
        try {
          currentUrl = await browserView.webContents.executeJavaScript('location.href')
        } catch (e) {}

        // Start exploration with a clear acknowledgment
        const startMsg = `🔍 **Starting full exploration of ${currentUrl}**\n\nI'll systematically test:\n• All buttons and clickable elements\n• Form inputs and validation\n• Navigation and links\n• Edge cases and error states\n\nLet's go!`
        sendMessage?.('action', startMsg)

        // Run the full agent loop with the USER'S ORIGINAL MESSAGE
        const result = await runAgentLoop(browserView, getViewBounds(), message, sendMessage)

        // Record actions taken
        if (result.history) {
          result.history.forEach(h => addAction(h.action, h.result))
        }

        const fullResponse = result.response || `Exploration complete! ${result.actionsTaken || 0} actions performed.`
        addToHistory('assistant', fullResponse)
        return {
          success: result.success,
          response: fullResponse,
          actionsTaken: result.actionsTaken || 0
        }
      }

      case 'login': {
        // AI detected user providing login credentials
        if (!browserView) {
          const response = "I need a page to login to. Which website should I navigate to first?"
          addToHistory('assistant', response)
          return { success: true, response }
        }

        const email = decision.email
        const password = decision.password

        if (!email || !password) {
          const response = "I need both email/username and password to login. What are they?"
          addToHistory('assistant', response)
          return { success: true, response }
        }

        sendMessage?.('action', `🔐 Logging in with ${email}...`)

        // Run the login action through the agent
        const loginResult = await runAgentLoop(
          browserView,
          getViewBounds(),
          `Login with email/username "${email}" and password "${password}". Type the email in the email/username field, type the password in the password field, then click the login/submit button.`,
          sendMessage
        )

        if (loginResult.history) {
          loginResult.history.forEach(h => addAction(h.action, h.result))
        }

        addToHistory('assistant', loginResult.response || loginResult.error)
        return {
          success: loginResult.success,
          response: loginResult.response || loginResult.error,
          actionsTaken: loginResult.actionsTaken || 0
        }
      }

      case 'action': {
        if (!browserView) {
          const response = "I need a page to work with. Which website should I navigate to?"
          addToHistory('assistant', response)
          return { success: true, response }
        }

        // Run the full agent loop
        const result = await runAgentLoop(browserView, getViewBounds(), message, sendMessage)

        // Record actions taken
        if (result.history) {
          result.history.forEach(h => addAction(h.action, h.result))
        }

        addToHistory('assistant', result.response || result.error)
        return {
          success: result.success,
          response: result.response || result.error,
          actionsTaken: result.actionsTaken || 0
        }
      }

      default: {
        const response = decision.response || "I'm not sure what you mean. Could you tell me more?"
        addToHistory('assistant', response)
        return { success: true, response }
      }
    }
  } catch (err) {
    console.error('Agent error:', err.stack || err)
    return { success: false, error: `Error: ${err.message || String(err)}` }
  }
})

// ============ PAGE ANALYSIS ============
ipcMain.handle('analyze-page', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)
  const focusAreas = getFocusAreas(pageType)

  // Get knowledge from full knowledge base
  const knowledgeSections = getKnowledgeForPageType(pageType)
  const knowledge = getKnowledge(pageType)

  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const buttons = pageState.elements.filter(e => e.category === 'button')
  const links = pageState.elements.filter(e => e.category === 'link')

  return {
    success: true,
    analysis: {
      pageType,
      url: pageState.url,
      title: pageState.title,
      stats: {
        totalElements: pageState.elements.length,
        inputs: inputs.length,
        buttons: buttons.length,
        links: links.length
      },
      focusAreas,
      suggestedTests: knowledge.slice(0, 5),
      knowledgeSections: knowledgeSections.map(s => ({ id: s.id, title: s.title }))
    }
  }
})

// ============ TEST GENERATION (AI-powered with knowledge base) ============
ipcMain.handle('generate-tests', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  // Use AI-powered test generation with full knowledge base
  if (isApiConfigured()) {
    const aiResult = await generateTestsForPage(browserView, pageType)
    if (aiResult.success) {
      return {
        success: true,
        tests: aiResult.tests,
        knowledge: aiResult.knowledge,
        source: 'ai'
      }
    }
  }

  // Fallback to static generation
  const testSuite = generateTests(pageType, pageState.elements)
  return {
    success: true,
    tests: testSuite.tests,
    coverage: testSuite.coverage,
    source: 'static'
  }
})

// ============ SECURITY ANALYSIS (AI-powered) ============
ipcMain.handle('analyze-security', async () => {
  if (!browserView) return { success: false, error: 'No page loaded' }
  if (!isApiConfigured()) return { success: false, error: 'API key required for security analysis' }

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  const result = await analyzeSecurityForPage(browserView, pageType)
  return result
})

// ============ ELEMENT SEARCH ============
ipcMain.handle('search-elements', async (_, query) => {
  if (!browserView) return { success: false, elements: [] }

  const pageState = await getPageState(browserView)
  const queryLower = query.toLowerCase()

  const matching = pageState.elements.filter(el => {
    const text = [el.text, el.label, el.placeholder, el.name].join(' ').toLowerCase()
    return text.includes(queryLower)
  })

  return { success: true, elements: matching }
})

// ============ ELEMENT CATEGORIES ============
ipcMain.handle('get-elements-by-category', async () => {
  if (!browserView) return { success: false, categories: {} }

  const pageState = await getPageState(browserView)
  const categories = {}

  pageState.elements.forEach(el => {
    const cat = el.category || 'other'
    if (!categories[cat]) categories[cat] = []
    categories[cat].push(el)
  })

  return { success: true, categories }
})

// ============ PAGE ACTIONS ============
ipcMain.handle('page-action', async (_, action, value) => {
  if (!browserView) return { success: false, error: 'No browser' }

  switch (action) {
    case 'scroll-down':
      return await scrollPage(browserView, 'down')
    case 'scroll-up':
      return await scrollPage(browserView, 'up')
    case 'press-enter':
      await realPressEnter(browserView)
      return { success: true }
    default:
      return { success: false, error: `Unknown action: ${action}` }
  }
})

// ============ SMART ANALYZE (Quick page summary) ============
ipcMain.handle('smart-analyze', async () => {
  if (!browserView) {
    return { success: false, error: 'No page loaded' }
  }

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  const summary = {
    type: pageType,
    url: pageState.url,
    elements: {
      inputs: pageState.elements.filter(e => e.category === 'text-input').length,
      buttons: pageState.elements.filter(e => e.category === 'button').length,
      links: pageState.elements.filter(e => e.category === 'link').length,
      total: pageState.elements.length
    },
    testable: pageState.elements.filter(e => ['text-input', 'button', 'dropdown'].includes(e.category))
  }

  return { success: true, summary }
})

// ============ QA ORCHESTRATOR ============
let orchestrator = null

ipcMain.handle('get-todo-list', () => {
  if (!orchestrator) {
    return { success: false, error: 'No orchestrator session active' }
  }

  const summary = orchestrator.getTodoSummary()
  const currentTaskId = orchestrator._currentTaskId
  const currentTask = currentTaskId ? orchestrator.getTaskDetails(currentTaskId) : null

  // Get task lists
  const pendingTasks = orchestrator._taskQueue
    .filter(t => t.status === 'pending')
    .slice(0, 10)
    .map(t => ({
      id: t.id,
      title: t.title,
      priority: t.priority,
      status: t.status,
      steps: t.steps?.map((s, i) => ({
        stepNumber: i,
        action: s.action,
        description: s.description,
        status: s.status
      }))
    }))

  const completedTasks = orchestrator._completedTasks
    .slice(-5)
    .map(t => ({
      id: t.id,
      title: t.title,
      priority: t.priority,
      status: t.status,
      durationMs: t.durationMs
    }))

  const failedTasks = orchestrator._failedTasks
    .slice(-5)
    .map(t => ({
      id: t.id,
      title: t.title,
      priority: t.priority,
      status: t.status,
      error: t.error
    }))

  return {
    success: true,
    data: {
      summary,
      currentTask,
      pendingTasks,
      completedTasks,
      failedTasks
    }
  }
})

ipcMain.handle('get-ai-prompt-history', () => {
  if (!orchestrator) {
    return { success: false, error: 'No orchestrator session active' }
  }

  return {
    success: true,
    history: orchestrator.getAIPromptHistory(),
    formatted: orchestrator.formatAIPromptHistory()
  }
})

ipcMain.handle('start-exploration', async (_, request) => {
  try {
    const { startExploration, getOrchestrator } = require('./lib/agent')

    // Create or get orchestrator
    orchestrator = getOrchestrator({
      onTodoUpdate: (summary) => {
        // Send TODO update to renderer
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('todo-update', summary)
        }
      },
      onProgress: (progress) => {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('agent-message', {
            type: 'progress',
            message: progress.message || 'Exploring...',
            data: progress
          })
        }
      }
    })

    // Send message helper
    const sendMessage = (msg) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('agent-message', msg)
      }
    }

    // Start exploration
    const result = await startExploration(browserView, viewBounds, request, sendMessage)

    return { success: true, result }
  } catch (error) {
    return { success: false, error: error.message }
  }
})

ipcMain.handle('stop-exploration', () => {
  if (orchestrator) {
    orchestrator.pause()
    return { success: true }
  }
  return { success: false, error: 'No exploration running' }
})

// ============ AUTO-UPDATE ============
function setupAutoUpdater() {
  if (!autoUpdater) return

  autoUpdater.on('checking-for-update', () => {
    console.log('Checking for updates...')
  })

  autoUpdater.on('update-available', (info) => {
    console.log('Update available:', info.version)
    mainWindow?.webContents.send('update-available', info.version)
  })

  autoUpdater.on('update-downloaded', (info) => {
    console.log('Update downloaded:', info.version)
    mainWindow?.webContents.send('update-downloaded', info.version)
  })

  autoUpdater.on('error', (err) => {
    console.log('Auto-update error:', err.message)
  })

  // Check for updates every 4 hours
  setInterval(() => {
    autoUpdater.checkForUpdates().catch(() => {})
  }, 4 * 60 * 60 * 1000)

  // Check immediately on startup
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch(() => {})
  }, 5000)
}

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  createWindow()
  setupAutoUpdater()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
