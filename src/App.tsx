import { useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, AlertCircle } from 'lucide-react'
import { Toolbar } from './components/Toolbar'
import { Sidebar } from './components/Sidebar'
import { ChatPanel } from './components/ChatPanel'
import { useAppStore } from './hooks/useStore'

export default function App() {
  const {
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
  } = useAppStore()

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Use Cmd on Mac, Ctrl on Windows
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

      // Refresh shortcut
      if (isMeta && e.key === 'r') {
        e.preventDefault()
        reload()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [toggleSidebar, toggleChat, reload, platform.isMac])

  // Smooth layout transition config (optimized)
  const layoutTransition = useMemo(() => ({
    type: 'spring' as const,
    stiffness: 400,
    damping: 40,
    mass: 1,
  }), [])

  // Shortcut key display (⌘ for Mac, Ctrl for Windows)
  const modKey = platform.isMac ? '⌘' : 'Ctrl+'

  return (
    <div className="h-screen bg-neutral-50 overflow-hidden select-none">
      {/* Toolbar */}
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

      {/* Sidebar */}
      <Sidebar
        open={sidebarOpen}
        elements={elements}
        isExtracting={isExtracting}
        onExtract={extractDom}
        selectedElement={selectedElement}
        onSelectElement={setSelectedElement}
      />

      {/* Main Content Area - Animated */}
      <motion.main
        className="fixed top-[52px] bottom-0 will-change-transform"
        animate={{
          left: sidebarOpen ? 280 : 0,
          right: chatOpen ? 360 : 0,
        }}
        transition={layoutTransition}
      >
        {/* Placeholder when no page loaded */}
        <AnimatePresence mode="wait">
          {!hasPage && !pageError && (
            <motion.div
              key="placeholder"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="h-full flex flex-col items-center justify-center"
            >
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.3, delay: 0.1 }}
                className="flex flex-col items-center"
              >
                <div className="w-16 h-16 bg-neutral-100 rounded-2xl flex items-center justify-center mb-4">
                  <Globe className="w-8 h-8 text-neutral-300" strokeWidth={1.5} />
                </div>
                <p className="text-sm text-neutral-400">Enter a URL to start testing</p>
                <p className="text-xs text-neutral-300 mt-2">{modKey}L to focus URL bar</p>
              </motion.div>
            </motion.div>
          )}

          {/* Error state */}
          {pageError && (
            <motion.div
              key="error"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="h-full flex flex-col items-center justify-center"
            >
              <div className="flex flex-col items-center text-center px-8 max-w-md">
                <div className="w-16 h-16 bg-red-50 rounded-2xl flex items-center justify-center mb-4">
                  <AlertCircle className="w-8 h-8 text-red-400" strokeWidth={1.5} />
                </div>
                <p className="text-sm text-neutral-600 font-medium mb-2">Failed to load page</p>
                <p className="text-xs text-neutral-400">{pageError}</p>
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
              <motion.div
                className="w-8 h-8 border-2 border-neutral-200 border-t-neutral-900 rounded-full"
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </motion.main>

      {/* Chat Panel */}
      <ChatPanel
        open={chatOpen}
        messages={messages}
        isThinking={isThinking}
        onSendMessage={sendMessage}
        onStartTest={startTest}
      />
    </div>
  )
}
