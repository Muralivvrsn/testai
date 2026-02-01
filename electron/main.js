/**
 * TestAI Main Process
 * Clean modular architecture - ~450 lines
 */

const { app, BrowserWindow, BrowserView, ipcMain, nativeTheme } = require('electron')
const path = require('path')
const fs = require('fs')

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
let sidebarWidth = 220
let chatWidth = 380
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
  const topBarHeight = 52

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

    // Build conversation context
    const recentChat = conversationHistory.slice(-6).map(m => `${m.role}: ${m.content}`).join('\n')
    const recentActions = actionHistory.slice(-5).map(a => `- ${a.action}: ${a.result}`).join('\n')

    // Ask AI what to do with FULL context
    const decisionPrompt = `You are Alex, a friendly QA engineer assistant.

CONVERSATION HISTORY:
${recentChat || 'No previous messages'}

RECENT ACTIONS TAKEN:
${recentActions || 'None yet'}

CURRENT STATE:
- ${pageInfo}

USER'S NEW MESSAGE: "${message}"

Decide what to do. Return JSON:

For greetings/chat:
{ "type": "chat", "response": "your friendly response" }

For navigation (user mentions a URL or website):
{ "type": "navigate", "url": "full URL to load", "message": "brief acknowledgment" }

For page actions (find, click, type, etc.):
{ "type": "action" }

For unclear requests:
{ "type": "clarify", "response": "ask what they need" }

RULES:
- Be conversational and natural
- Use past tense for completed actions ("I've loaded" not "I'll load")
- Reference conversation history when relevant
- If they just say "load the page" without a URL, ask which page`

    console.log('Asking AI for decision...')
    const response = await callDeepSeek([
      { role: 'system', content: 'You are Alex, a friendly QA assistant. Return only valid JSON.' },
      { role: 'user', content: decisionPrompt }
    ], { jsonMode: true, maxTokens: 300, temperature: 0.3 })

    const decision = JSON.parse(response.content)
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

      case 'action': {
        if (!browserView) {
          const response = "I'd be happy to help! Which website should I navigate to first?"
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

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  createWindow()

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
