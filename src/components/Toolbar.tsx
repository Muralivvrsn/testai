import { useState, useEffect, KeyboardEvent, memo } from 'react'
import { motion } from 'framer-motion'
import {
  PanelLeft,
  ChevronLeft,
  ChevronRight,
  RotateCw,
  Monitor,
  Laptop,
  Tablet,
  Smartphone,
  MessageCircle,
} from 'lucide-react'
import { cn } from '../lib/cn'
import type { ViewportType } from '../lib/types'

interface ToolbarProps {
  url: string
  onUrlChange: (url: string) => void
  onNavigate: (url: string) => void
  onBack: () => void
  onForward: () => void
  onReload: () => void
  viewport: ViewportType
  onViewportChange: (viewport: ViewportType) => void
  sidebarOpen: boolean
  onToggleSidebar: () => void
  chatOpen: boolean
  onToggleChat: () => void
  isLoading: boolean
  isMac?: boolean
  modKey?: string
}

// Memoized smooth spring config
const smoothSpring = {
  type: 'spring' as const,
  stiffness: 400,
  damping: 30,
}

const viewports: { type: ViewportType; icon: typeof Monitor; label: string }[] = [
  { type: 'desktop', icon: Monitor, label: 'Desktop' },
  { type: 'laptop', icon: Laptop, label: 'Laptop' },
  { type: 'tablet', icon: Tablet, label: 'Tablet' },
  { type: 'mobile', icon: Smartphone, label: 'Mobile' },
]

export const Toolbar = memo(function Toolbar({
  url,
  onNavigate,
  onBack,
  onForward,
  onReload,
  viewport,
  onViewportChange,
  sidebarOpen,
  onToggleSidebar,
  chatOpen,
  onToggleChat,
  isLoading,
  isMac = true,
  modKey = '⌘',
}: ToolbarProps) {
  const [inputValue, setInputValue] = useState(url)

  // Sync input value with url prop
  useEffect(() => {
    setInputValue(url)
  }, [url])

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      onNavigate(inputValue)
    }
  }

  // Platform-specific left padding (for Mac traffic lights or Windows margin)
  const leftPadding = isMac ? 80 : 16

  return (
    <header
      className="drag-region fixed top-0 left-0 right-0 h-[52px] bg-white border-b border-neutral-200 flex items-center px-3 gap-2 z-50"
      style={{ paddingLeft: leftPadding }}
    >
      {/* Sidebar Toggle */}
      <IconButton
        icon={PanelLeft}
        onClick={onToggleSidebar}
        active={sidebarOpen}
        tooltip={`Elements (${modKey}E)`}
      />

      <Divider />

      {/* Navigation */}
      <div className="no-drag flex items-center gap-0.5">
        <IconButton icon={ChevronLeft} onClick={onBack} tooltip="Back" />
        <IconButton icon={ChevronRight} onClick={onForward} tooltip="Forward" />
        <IconButton
          icon={RotateCw}
          onClick={onReload}
          tooltip={`Reload (${modKey}R)`}
          isLoading={isLoading}
        />
      </div>

      <Divider />

      {/* URL Bar */}
      <div className="no-drag flex-1 max-w-xl relative">
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={(e) => e.target.select()}
          placeholder="Enter URL to start testing..."
          spellCheck={false}
          autoComplete="off"
          className="w-full h-9 px-4 pr-12 bg-neutral-100 border border-neutral-200 rounded-lg text-sm text-neutral-900 placeholder:text-neutral-400 outline-none transition-all duration-200 hover:border-neutral-300 focus:bg-white focus:border-neutral-900 focus:ring-2 focus:ring-neutral-900/5"
        />
        <kbd className="absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 bg-neutral-200/50 border border-neutral-200 rounded text-[10px] font-mono text-neutral-400">
          {modKey}L
        </kbd>
      </div>

      <Divider />

      {/* Viewport Switcher */}
      <div className="no-drag flex items-center bg-neutral-100 rounded-lg p-1 gap-0.5 relative">
        {/* Animated background indicator */}
        <motion.div
          className="absolute h-7 bg-white rounded-md shadow-sm"
          initial={false}
          animate={{
            x: viewports.findIndex(v => v.type === viewport) * 32 + 2,
            width: 28,
          }}
          transition={smoothSpring}
        />

        {viewports.map(({ type, icon: Icon, label }) => (
          <motion.button
            key={type}
            onClick={() => onViewportChange(type)}
            className={cn(
              'relative z-10 w-8 h-8 flex items-center justify-center rounded-md transition-colors duration-200',
              viewport === type
                ? 'text-neutral-900'
                : 'text-neutral-500 hover:text-neutral-700'
            )}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            title={label}
          >
            <Icon className="w-4 h-4" />
          </motion.button>
        ))}
      </div>

      <div className="flex-1" />

      {/* Chat Toggle */}
      <IconButton
        icon={MessageCircle}
        onClick={onToggleChat}
        active={chatOpen}
        tooltip={`AI Assistant (${modKey}J)`}
      />
    </header>
  )
})

// Memoized Icon Button Component
const IconButton = memo(function IconButton({
  icon: Icon,
  onClick,
  active = false,
  tooltip,
  isLoading = false,
}: {
  icon: typeof Monitor
  onClick: () => void
  active?: boolean
  tooltip?: string
  isLoading?: boolean
}) {
  return (
    <motion.button
      onClick={onClick}
      className={cn(
        'no-drag w-8 h-8 flex items-center justify-center rounded-md transition-colors duration-200',
        active
          ? 'bg-neutral-900/5 text-neutral-900'
          : 'text-neutral-500 hover:text-neutral-700 hover:bg-neutral-100'
      )}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      title={tooltip}
    >
      <motion.div
        animate={isLoading ? { rotate: 360 } : { rotate: 0 }}
        transition={isLoading ? { duration: 1, repeat: Infinity, ease: 'linear' } : { duration: 0.2 }}
      >
        <Icon className="w-4 h-4" strokeWidth={1.75} />
      </motion.div>
    </motion.button>
  )
})

const Divider = memo(function Divider() {
  return <div className="w-px h-5 bg-neutral-200 mx-1" />
})
