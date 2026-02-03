import { useState, useCallback, useEffect, useRef, useMemo } from 'react'
import type { DomElement, Message, ViewportType } from '../lib/types'

// ============ API TYPE DECLARATIONS ============
interface AgentMessage {
  type: 'thinking' | 'analysis' | 'tests_generated' | 'session_started' | 'session_completed' |
        'action' | 'action_verified' | 'action_warning' | 'script_generated' | 'script_step' |
        'script_step_success' | 'script_step_error'
  message: string
  data?: any
}

interface PageAnalysis {
  pageType: string
  confidence: number
  purpose?: string
  criticalElements?: string[]
  suggestedTests?: string[]
}

interface GeneratedTest {
  name: string
  description: string
  priority: string
  category: string
  steps: any[]
  expectedResults: string[]
}

declare global {
  interface Window {
    api?: {
      // Navigation
      navigate: (url: string) => Promise<{ success: boolean; url?: string; error?: string }>
      goBack: () => Promise<{ success: boolean }>
      goForward: () => Promise<{ success: boolean }>
      reload: () => Promise<{ success: boolean }>
      // Layout
      setSidebarWidth: (width: number) => Promise<{ success: boolean }>
      setChatWidth: (width: number) => Promise<{ success: boolean }>
      setViewport: (width: number, height: number) => Promise<{ success: boolean }>
      // DOM
      extractDom: () => Promise<{ success: boolean; elements: DomElement[]; count?: number }>
      clickElement: (id: string) => Promise<{ success: boolean }>
      typeInElement: (id: string, text: string) => Promise<{ success: boolean }>
      getPageInfo: () => Promise<{ success: boolean; url?: string; title?: string; html?: string }>
      getPlatform: () => Promise<{ isMac: boolean; isWindows: boolean; platform: string }>
      // Events
      onUrlChanged: (callback: (url: string) => void) => () => void
      onTitleChanged: (callback: (title: string) => void) => () => void
      onPageLoaded: (callback: () => void) => () => void
      onPageError: (callback: (error: { errorCode: number; errorDescription: string }) => void) => () => void
      onPlatformInfo: (callback: (info: { isMac: boolean; isWindows: boolean }) => void) => () => void
      onAgentMessage: (callback: (msg: AgentMessage) => void) => () => void
      onTodoUpdate: (callback: (data: any) => void) => () => void
      removeAllListeners: (channel?: string) => void
      // Agent API
      setApiKey: (key: string) => Promise<{ success: boolean }>
      getAgentStatus: () => Promise<{ hasApiKey: boolean; hasSession: boolean; sessionStatus: string | null }>
      analyzePage: () => Promise<{ success: boolean; pageInfo?: any; elements?: any[]; analysis?: PageAnalysis; error?: string }>
      generateTests: (pageData: any) => Promise<{ success: boolean; tests?: GeneratedTest[]; humanReadable?: string; error?: string }>
      startAutonomousTest: () => Promise<{ success: boolean; session?: any; error?: string }>
      stopAutonomousTest: () => Promise<{ success: boolean; session?: any }>
      chatWithAgent: (message: string, context?: any) => Promise<{
        success: boolean
        response?: string
        details?: string
        type?: 'text' | 'script' | 'action' | 'error' | 'success'
        detectedUrl?: string
        shouldLoadUrl?: boolean
        actionPerformed?: {
          action: string
          element: string
          value?: string
          confidence: number
        }
        error?: string
      }>
      getWelcomeMessage: () => Promise<{ success: boolean; message: string }>
      smartAnalyze: () => Promise<{ success: boolean; pageInfo?: any; elementCount?: number; pageType?: string; analysis?: string; error?: string }>
      // Action APIs
      performAction: (intent: string) => Promise<{
        success: boolean
        action?: string
        element?: string
        value?: string | number
        explanation?: string
        confidence?: number
        scrolled?: boolean
        error?: string
      }>
      pageAction: (action: string, value?: string) => Promise<{
        success: boolean
        action?: string
        amount?: number
        url?: string
        count?: number
        text?: string
        data?: string
        error?: string
      }>
      executeTask: (task: string) => Promise<{
        success: boolean
        steps: Array<{
          step: number
          action: string
          elementId?: string
          value?: string
          success: boolean
          description?: string
          error?: string
        }>
        totalSteps: number
        taskComplete: boolean
      }>
      searchElements: (query: string) => Promise<{ success: boolean; elements: any[]; error?: string }>
      getElementsByCategory: () => Promise<{ success: boolean; categories: Record<string, any[]>; error?: string }>
      // Script APIs
      generateScript: (taskDescription: string) => Promise<{
        success: boolean
        script?: string
        steps?: Array<{
          step: number
          elementId: string
          action: string
          value: string
        }>
        error?: string
      }>
      executeScript: (scriptText: string) => Promise<{
        success: boolean
        results?: Array<{
          step: number
          elementId: string
          action: string
          value: string
          success: boolean
          error?: string
        }>
        summary?: string
      }>
      // Orchestrator API
      getTodoList: () => Promise<{ success: boolean; data?: any; error?: string }>
      getAIPromptHistory: () => Promise<{ success: boolean; history?: any[]; formatted?: string; error?: string }>
      startExploration: (request: string) => Promise<{ success: boolean; result?: any; error?: string }>
      stopExploration: () => Promise<{ success: boolean; error?: string }>
    }
  }
}

// ============ ANIMATION HELPER ============
function animateValue(
  from: number,
  to: number,
  onUpdate: (value: number) => void,
  duration: number = 200
) {
  const startTime = performance.now()
  let animationFrame: number

  function easeOutCubic(t: number): number {
    return 1 - Math.pow(1 - t, 3)
  }

  function update() {
    const elapsed = performance.now() - startTime
    const progress = Math.min(elapsed / duration, 1)
    const eased = easeOutCubic(progress)
    const value = from + (to - from) * eased

    onUpdate(Math.round(value))

    if (progress < 1) {
      animationFrame = requestAnimationFrame(update)
    }
  }

  animationFrame = requestAnimationFrame(update)

  // Return cancel function
  return () => cancelAnimationFrame(animationFrame)
}

// ============ MAIN STORE HOOK ============
export function useAppStore() {
  // Platform state
  const [platform, setPlatform] = useState<{ isMac: boolean; isWindows: boolean }>({
    isMac: false,
    isWindows: false,
  })

  // UI State
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [chatOpen, setChatOpen] = useState(false)
  const [viewport, setViewport] = useState<ViewportType>('desktop')

  // Animation refs
  const currentSidebarWidth = useRef(0)
  const currentChatWidth = useRef(0)
  const cancelAnimation = useRef<(() => void) | null>(null)

  // Browser State
  const [url, setUrl] = useState('')
  const [pageTitle, setPageTitle] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [hasPage, setHasPage] = useState(false)
  const [pageError, setPageError] = useState<string | null>(null)

  // DOM State
  const [elements, setElements] = useState<DomElement[]>([])
  const [isExtracting, setIsExtracting] = useState(false)
  const [selectedElement, setSelectedElement] = useState<string | null>(null)

  // Chat State
  const [messages, setMessages] = useState<Message[]>([])
  const [isThinking, setIsThinking] = useState(false)
  const [hasWelcomed, setHasWelcomed] = useState(false)

  // TODO/Orchestrator State
  const [todoData, setTodoData] = useState<any>(null)
  const [isExploring, setIsExploring] = useState(false)

  // ============ PLATFORM DETECTION ============
  useEffect(() => {
    window.api?.getPlatform?.().then(setPlatform)
  }, [])

  // ============ SIDEBAR TOGGLE ============
  const toggleSidebar = useCallback(() => {
    const newState = !sidebarOpen
    setSidebarOpen(newState)

    // Cancel any ongoing animation
    if (cancelAnimation.current) cancelAnimation.current()

    // Sync with Electron BrowserView
    const targetWidth = newState ? 300 : 0
    cancelAnimation.current = animateValue(
      currentSidebarWidth.current,
      targetWidth,
      (value) => {
        currentSidebarWidth.current = value
        window.api?.setSidebarWidth(value)
      },
      250
    )
  }, [sidebarOpen])

  // ============ CHAT TOGGLE ============
  const toggleChat = useCallback(async () => {
    const newState = !chatOpen
    setChatOpen(newState)

    // Cancel any ongoing animation
    if (cancelAnimation.current) cancelAnimation.current()

    // Sync with Electron BrowserView
    const targetWidth = newState ? 380 : 0
    cancelAnimation.current = animateValue(
      currentChatWidth.current,
      targetWidth,
      (value) => {
        currentChatWidth.current = value
        window.api?.setChatWidth(value)
      },
      250
    )

    // Show welcome message when opening chat for the first time
    if (newState && !hasWelcomed) {
      setHasWelcomed(true)
      const result = await window.api?.getWelcomeMessage()
      if (result?.success && result.message) {
        setMessages([{
          id: 'welcome',
          content: result.message,
          role: 'assistant',
          timestamp: new Date(),
        }])
      }
    }
  }, [chatOpen, hasWelcomed])

  // ============ VIEWPORT ============
  const changeViewport = useCallback((type: ViewportType) => {
    setViewport(type)
    const sizes: Record<ViewportType, [number, number]> = {
      desktop: [0, 0],
      laptop: [1366, 768],
      tablet: [768, 1024],
      mobile: [375, 812],
    }
    const [w, h] = sizes[type]
    window.api?.setViewport(w, h)
  }, [])

  // ============ NAVIGATION ============
  const navigate = useCallback(async (targetUrl: string) => {
    if (!targetUrl.trim()) return
    setIsLoading(true)
    setHasPage(true)
    setPageError(null)

    const result = await window.api?.navigate(targetUrl)
    if (result?.success && result.url) {
      setUrl(result.url)
    } else if (result?.error) {
      setPageError(result.error)
    }
    setIsLoading(false)
  }, [])

  const goBack = useCallback(() => window.api?.goBack(), [])
  const goForward = useCallback(() => window.api?.goForward(), [])
  const reload = useCallback(() => {
    setIsLoading(true)
    window.api?.reload()
  }, [])

  // ============ DOM EXTRACTION ============
  const extractDom = useCallback(async () => {
    setIsExtracting(true)
    const result = await window.api?.extractDom()
    if (result?.success) {
      setElements(result.elements)
    }
    setIsExtracting(false)
  }, [])

  // ============ CHAT WITH AGENT (ALEX PERSONA) ============
  const sendMessage = useCallback(async (content: string) => {
    const userMessage: Message = {
      id: Date.now().toString(),
      content,
      role: 'user',
      timestamp: new Date(),
    }
    setMessages(prev => [...prev, userMessage])
    setIsThinking(true)

    try {
      // Call the agent
      const result = await window.api?.chatWithAgent(content, {
        url,
        title: pageTitle,
        elementCount: elements.length
      })

      if (!result?.success) {
        // Handle errors gracefully
        setMessages(prev => [...prev, {
          id: (Date.now() + 1).toString(),
          content: result?.error || 'Something went wrong. Let me try that again.',
          role: 'assistant',
          timestamp: new Date(),
        }])
        setIsThinking(false)
        return
      }

      // AI-driven response - actions already executed in backend
      // Just show the response and update state based on action taken
      if (result.actionTaken === 'navigate' && result.actionResult?.success) {
        // Navigation happened in backend - update frontend state
        setHasPage(true)
        setPageError(null)
        if (result.actionResult.url) {
          setUrl(result.actionResult.url)
        }
        // Refresh elements after navigation
        const domResult = await window.api?.extractDom()
        if (domResult?.elements) {
          setElements(domResult.elements)
        }
      }

      // Show AI response
      const responseContent = result.response || 'Let me think about that...'

      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        content: responseContent,
        role: 'assistant',
        timestamp: new Date(),
      }])
    } catch (error: any) {
      const errorPhrases = [
        `Oops, something went wrong: ${error.message}\n\nLet's try that again.`,
        `Hmm, hit a small snag: ${error.message}\n\nMind trying once more?`,
        `Something unexpected happened: ${error.message}\n\nLet me know if it persists.`,
        `Ran into an issue: ${error.message}\n\nWant to give it another shot?`,
      ]
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        content: errorPhrases[Math.floor(Math.random() * errorPhrases.length)],
        role: 'assistant',
        timestamp: new Date(),
      }])
    }

    setIsThinking(false)
  }, [url, pageTitle, elements.length])

  const startTest = useCallback(async () => {
    // Use varied starting phrases
    const startPhrases = [
      `Alright, let me dig into ${url || 'this page'}...`,
      `Starting my analysis of ${url || 'the page'}...`,
      `Let me take a thorough look at ${url || 'this'}...`,
      `Examining ${url || 'the page'} now...`,
      `Got it, running tests on ${url || 'this page'}...`,
    ]

    setMessages(prev => [...prev, {
      id: Date.now().toString(),
      content: startPhrases[Math.floor(Math.random() * startPhrases.length)],
      role: 'assistant',
      timestamp: new Date(),
    }])
    setIsThinking(true)

    try {
      // Analyze the page
      const analysisResult = await window.api?.analyzePage()

      if (!analysisResult?.success) {
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          content: `Failed to analyze page: ${analysisResult?.error || 'Unknown error'}. Make sure you have set your DeepSeek API key.`,
          role: 'assistant',
          timestamp: new Date(),
        }])
        setIsThinking(false)
        return
      }

      // Update elements from analysis
      if (analysisResult.elements) {
        setElements(analysisResult.elements)
      }

      // Show analysis result
      const analysis = analysisResult.analysis
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        content: `**Page Analysis Complete**\n\n` +
          `- **Type:** ${analysis?.pageType || 'unknown'}\n` +
          `- **Confidence:** ${Math.round((analysis?.confidence || 0) * 100)}%\n` +
          `- **Elements Found:** ${analysisResult.elements?.length || 0}\n\n` +
          `Suggested tests:\n${analysis?.suggestedTests?.map((t: string) => `- ${t}`).join('\n') || 'None'}`,
        role: 'assistant',
        timestamp: new Date(),
      }])

      // Generate test cases
      const testsResult = await window.api?.generateTests(analysisResult)

      if (testsResult?.success && testsResult.tests) {
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          content: `**Generated ${testsResult.tests.length} Test Cases**\n\n` +
            `Here are the human-readable test scripts:\n\n\`\`\`\n${testsResult.humanReadable?.slice(0, 2000) || 'No tests generated'}\n\`\`\``,
          role: 'assistant',
          timestamp: new Date(),
        }])
      } else {
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          content: `Failed to generate tests: ${testsResult?.error || 'Unknown error'}`,
          role: 'assistant',
          timestamp: new Date(),
        }])
      }
    } catch (error: any) {
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        content: `Error: ${error.message}`,
        role: 'assistant',
        timestamp: new Date(),
      }])
    }

    setIsThinking(false)
  }, [url])

  // ============ ORCHESTRATOR METHODS ============
  const startExploration = useCallback(async (request: string) => {
    setIsExploring(true)

    // Add exploring message
    setMessages(prev => [...prev, {
      id: Date.now().toString(),
      content: `Starting exploration: "${request}"`,
      role: 'assistant',
      timestamp: new Date(),
    }])

    try {
      // Fetch initial TODO list
      const todoResult = await (window.api as any)?.getTodoList?.()
      if (todoResult?.success) {
        setTodoData(todoResult.data)
      }

      // Start exploration
      const result = await (window.api as any)?.startExploration?.(request)

      if (result?.success) {
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          content: `Exploration complete! ${result.result?.summary || ''}`,
          role: 'assistant',
          timestamp: new Date(),
        }])
      } else {
        setMessages(prev => [...prev, {
          id: Date.now().toString(),
          content: `Exploration failed: ${result?.error || 'Unknown error'}`,
          role: 'assistant',
          timestamp: new Date(),
          type: 'error'
        }])
      }
    } catch (error: any) {
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        content: `Error: ${error.message}`,
        role: 'assistant',
        timestamp: new Date(),
        type: 'error'
      }])
    }

    setIsExploring(false)
  }, [])

  const stopExploration = useCallback(async () => {
    await (window.api as any)?.stopExploration?.()
    setIsExploring(false)
  }, [])

  const refreshTodoList = useCallback(async () => {
    const result = await (window.api as any)?.getTodoList?.()
    if (result?.success) {
      setTodoData(result.data)
    }
  }, [])

  // ============ EVENT LISTENERS ============
  useEffect(() => {
    const cleanups: (() => void)[] = []

    // URL changes
    const urlCleanup = window.api?.onUrlChanged?.((newUrl) => {
      setUrl(newUrl)
      setHasPage(true)
      setPageError(null)
    })
    if (urlCleanup) cleanups.push(urlCleanup)

    // Title changes
    const titleCleanup = window.api?.onTitleChanged?.((title) => {
      setPageTitle(title)
    })
    if (titleCleanup) cleanups.push(titleCleanup)

    // Page loaded
    const loadCleanup = window.api?.onPageLoaded?.(() => {
      setIsLoading(false)
    })
    if (loadCleanup) cleanups.push(loadCleanup)

    // Page errors
    const errorCleanup = window.api?.onPageError?.((error) => {
      setPageError(error.errorDescription)
      setIsLoading(false)
    })
    if (errorCleanup) cleanups.push(errorCleanup)

    // Agent messages
    const agentCleanup = window.api?.onAgentMessage?.((msg) => {
      if (msg.type === 'thinking') {
        // Could show a thinking indicator
        console.log('Agent thinking:', msg.message)
      } else if (msg.type === 'analysis' || msg.type === 'tests_generated') {
        // These are handled in the callback, but we could also show them here
        console.log('Agent:', msg.message)
      }
    })
    if (agentCleanup) cleanups.push(agentCleanup)

    // TODO updates from orchestrator
    const todoCleanup = window.api?.onTodoUpdate?.((data: any) => {
      setTodoData(data)
    })
    if (todoCleanup) cleanups.push(todoCleanup)

    // Cleanup on unmount
    return () => {
      cleanups.forEach(cleanup => cleanup())
      if (cancelAnimation.current) cancelAnimation.current()
    }
  }, [])

  // ============ MEMOIZED RETURN ============
  return useMemo(() => ({
    // Platform
    platform,

    // UI State
    sidebarOpen,
    chatOpen,
    viewport,
    toggleSidebar,
    toggleChat,
    changeViewport,

    // Browser State
    url,
    setUrl,
    pageTitle,
    isLoading,
    hasPage,
    pageError,
    navigate,
    goBack,
    goForward,
    reload,

    // DOM State
    elements,
    isExtracting,
    selectedElement,
    setSelectedElement,
    extractDom,

    // Chat State
    messages,
    isThinking,
    sendMessage,
    startTest,

    // Orchestrator State
    todoData,
    isExploring,
    startExploration,
    stopExploration,
    refreshTodoList,
  }), [
    platform,
    sidebarOpen,
    chatOpen,
    viewport,
    toggleSidebar,
    toggleChat,
    changeViewport,
    url,
    pageTitle,
    isLoading,
    hasPage,
    pageError,
    navigate,
    goBack,
    goForward,
    reload,
    elements,
    isExtracting,
    selectedElement,
    extractDom,
    messages,
    isThinking,
    sendMessage,
    startTest,
    todoData,
    isExploring,
    startExploration,
    stopExploration,
    refreshTodoList,
  ])
}
