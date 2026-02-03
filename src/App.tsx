import { useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertCircle } from 'lucide-react'
import { Toolbar } from './components/Toolbar'
import { Sidebar } from './components/Sidebar'
import { ChatPanel } from './components/ChatPanel'
import { TodoPanel } from './components/TodoPanel'
import { WelcomeModal } from './components/WelcomeModal'
import { useAppStore } from './hooks/useStore'

const WELCOME_KEY = 'testai-welcome-complete'

// Panel widths - single source of truth
const SIDEBAR_WIDTH = 300
const CHAT_WIDTH = 380
const TOOLBAR_HEIGHT = 56

export default function App() {
  const [showWelcome, setShowWelcome] = useState<boolean | null>(null)
  const [chatDocked, setChatDocked] = useState(true) // Always docked to side

  const {
    platform,
    sidebarOpen,
    chatOpen,
    viewport,
    toggleSidebar,
    toggleChat,
    changeViewport,
    url,
    setUrl,
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
    setSelectedElement,
    extractDom,
    messages,
    isThinking,
    sendMessage,
    startTest,
    todoData,
    isExploring,
  } = useAppStore()

  // Check welcome state
  useEffect(() => {
    const hasCompleted = localStorage.getItem(WELCOME_KEY)
    setShowWelcome(!hasCompleted)
  }, [])

  const handleWelcomeClose = () => {
    localStorage.setItem(WELCOME_KEY, 'true')
    setShowWelcome(false)
  }

  // Chat is always docked to the side - no centered modal mode
  // Keep chatDocked always true for consistent side panel behavior

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (showWelcome) return
      const isMeta = platform.isMac ? e.metaKey : e.ctrlKey

      if (isMeta && e.key === 'l') {
        e.preventDefault()
        const urlInput = document.querySelector('input[type="text"]') as HTMLInputElement
        urlInput?.focus()
        urlInput?.select()
      }
      if (isMeta && e.key === 'e') {
        e.preventDefault()
        toggleSidebar()
      }
      if (isMeta && e.key === 'j') {
        e.preventDefault()
        toggleChat()
      }
      if (isMeta && e.key === 'r') {
        e.preventDefault()
        reload()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [toggleSidebar, toggleChat, reload, platform.isMac, showWelcome])

  // Apple-like spring animation
  const appleSpring = useMemo(() => ({
    type: 'spring' as const,
    stiffness: 300,
    damping: 30,
    mass: 0.8,
  }), [])

  const modKey = platform.isMac ? '⌘' : 'Ctrl+'

  // Calculate layout positions
  const TODO_WIDTH = 280
  const sidebarLeft = sidebarOpen ? 0 : -SIDEBAR_WIDTH
  const chatRight = (chatOpen && chatDocked) ? 0 : -CHAT_WIDTH
  const mainLeft = sidebarOpen ? SIDEBAR_WIDTH : 0
  const todoVisible = !!(todoData || isExploring)
  const mainRight = ((chatOpen && chatDocked) ? CHAT_WIDTH : 0) + (todoVisible ? TODO_WIDTH : 0)

  if (showWelcome === null) {
    return (
      <div className="h-screen bg-[#f8f9f6] dark:bg-[#0a0b0a] flex items-center justify-center">
        <motion.div
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
          className="flex items-center justify-center"
        >
          <img
            src="/images/logo.svg"
            alt="Yalitest"
            className="h-10 w-auto max-w-[160px] object-contain dark:invert dark:brightness-200"
          />
        </motion.div>
      </div>
    )
  }

  return (
    <div className="h-screen bg-[#f8f9f6] dark:bg-[#0a0b0a] overflow-hidden select-none">
      {/* Welcome Modal */}
      <AnimatePresence>
        {showWelcome && <WelcomeModal onClose={handleWelcomeClose} />}
      </AnimatePresence>

      {/* Main App Container */}
      <motion.div
        initial={false}
        animate={{ opacity: showWelcome ? 0 : 1 }}
        className={showWelcome ? 'pointer-events-none' : ''}
      >
        {/* Background - calm, subtle */}
        <div className="fixed inset-0 pointer-events-none">
          <div
            className="absolute inset-0 opacity-[0.02] dark:opacity-[0.015]"
            style={{
              backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
              backgroundSize: '40px 40px',
            }}
          />
          <div className="absolute inset-0 bg-gradient-to-br from-[#4A5D6A]/[0.02] via-transparent to-[#4A5D6A]/[0.01]" />
        </div>

        {/* ===== TOOLBAR (Fixed at top) ===== */}
        <Toolbar
          url={url}
          onUrlChange={setUrl}
          onNavigate={navigate}
          onBack={goBack}
          onForward={goForward}
          onReload={reload}
          viewport={viewport}
          onViewportChange={changeViewport}
          sidebarOpen={sidebarOpen}
          onToggleSidebar={toggleSidebar}
          chatOpen={chatOpen}
          onToggleChat={toggleChat}
          isLoading={isLoading}
          isMac={platform.isMac}
          modKey={modKey}
        />

        {/* ===== LEFT SIDEBAR (Slides in/out) ===== */}
        <motion.div
          className="fixed top-[56px] bottom-0 w-[300px] z-40"
          initial={false}
          animate={{ x: sidebarLeft }}
          transition={appleSpring}
          style={{ left: 0 }}
        >
          <Sidebar
            open={true}
            elements={elements}
            isExtracting={isExtracting}
            onExtract={extractDom}
            selectedElement={selectedElement}
            onSelectElement={setSelectedElement}
          />
        </motion.div>

        {/* ===== MAIN CONTENT (Resizes with panels) ===== */}
        <motion.main
          className="fixed top-[56px] bottom-0 overflow-hidden"
          initial={false}
          animate={{
            left: mainLeft,
            right: mainRight,
          }}
          transition={appleSpring}
        >
          <AnimatePresence mode="wait">
            {/* Empty state - no page loaded */}
            {!hasPage && !pageError && (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full flex items-center justify-center"
              >
                {!chatOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-center max-w-lg px-8"
                  >
                    {/* Large, prominent logo */}
                    <motion.div
                      className="mb-10 flex items-center justify-center"
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.1, duration: 0.5 }}
                    >
                      <img
                        src="/images/logo.svg"
                        alt="Yalitest"
                        className="h-16 w-auto max-w-[280px] object-contain dark:invert dark:brightness-200"
                      />
                    </motion.div>

                    {/* Tagline */}
                    <motion.h2
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.2 }}
                      className="font-display text-2xl font-semibold text-[#2a3a42] dark:text-white/90 mb-4"
                    >
                      Quality assurance, simplified.
                    </motion.h2>
                    <motion.p
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.3 }}
                      className="text-lg text-[#4A5D6A] dark:text-white/50 mb-10 leading-relaxed"
                    >
                      Paste a URL above or open the assistant to begin testing.
                    </motion.p>

                    {/* CTA Button */}
                    <motion.button
                      onClick={toggleChat}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.4 }}
                      className="inline-flex items-center gap-3 px-8 py-4 bg-[#4A5D6A] hover:bg-[#3a4d5a] text-white text-lg font-medium rounded-2xl shadow-xl shadow-[#4A5D6A]/20 transition-all duration-200"
                      whileHover={{ scale: 1.02, y: -2 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <span>Open Assistant</span>
                      <kbd className="px-2.5 py-1 bg-white/20 rounded-lg text-sm">{modKey}J</kbd>
                    </motion.button>
                  </motion.div>
                )}

                {chatOpen && chatDocked && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-center px-8"
                  >
                    {/* Logo when chat is open */}
                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="mb-6 flex items-center justify-center"
                    >
                      <img
                        src="/images/logo.svg"
                        alt="Yalitest"
                        className="h-12 w-auto max-w-[200px] object-contain dark:invert dark:brightness-200 opacity-60"
                      />
                    </motion.div>
                    <p className="text-base text-[#4A5D6A] dark:text-white/50">
                      Enter a URL to begin testing
                    </p>
                  </motion.div>
                )}
              </motion.div>
            )}

            {/* Error state */}
            {pageError && (
              <motion.div
                key="error"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
                className="h-full flex items-center justify-center"
              >
                <div className="text-center px-8 max-w-md">
                  <motion.div
                    className="w-24 h-24 mx-auto mb-6 bg-red-50 dark:bg-red-500/10 rounded-3xl flex items-center justify-center border border-red-200/50 dark:border-red-500/20"
                    initial={{ rotate: -10 }}
                    animate={{ rotate: 0 }}
                  >
                    <AlertCircle className="w-12 h-12 text-red-500" strokeWidth={1.5} />
                  </motion.div>
                  <h3 className="font-display text-xl font-semibold text-neutral-900 dark:text-white mb-2">
                    Unable to load page
                  </h3>
                  <p className="text-sm text-neutral-500 dark:text-white/50">{pageError}</p>
                </div>
              </motion.div>
            )}

            {/* Loading state */}
            {hasPage && isLoading && !pageError && (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full flex items-center justify-center"
              >
                <div className="flex flex-col items-center gap-5">
                  <div className="relative">
                    <motion.div
                      className="w-12 h-12 rounded-xl border-2 border-[#4A5D6A]/20 border-t-[#4A5D6A]"
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                    />
                  </div>
                  <p className="text-sm text-[#4A5D6A] dark:text-white/50">Loading...</p>
                </div>
              </motion.div>
            )}

            {/* Page loaded - transparent area for BrowserView */}
            {hasPage && !isLoading && !pageError && (
              <motion.div
                key="loaded"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="h-full"
              />
            )}
          </AnimatePresence>
        </motion.main>

        {/* ===== TODO PANEL (Shows when exploring) ===== */}
        <AnimatePresence>
          {(todoData || isExploring) && (
            <motion.div
              initial={{ opacity: 0, x: 280 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 280 }}
              transition={appleSpring}
              className="fixed top-[56px] bottom-0 w-[280px] z-30"
              style={{ right: (chatOpen && chatDocked) ? CHAT_WIDTH : 0 }}
            >
              <TodoPanel
                data={todoData}
                isRunning={isExploring}
              />
            </motion.div>
          )}
        </AnimatePresence>

        {/* ===== RIGHT CHAT PANEL (Slides in/out or centered) ===== */}
        <ChatPanel
          open={chatOpen}
          messages={messages}
          isThinking={isThinking}
          onSendMessage={sendMessage}
          onStartTest={startTest}
          isDocked={chatDocked}
          onDock={() => setChatDocked(true)}
        />
      </motion.div>
    </div>
  )
}
