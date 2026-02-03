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
  Search,
} from 'lucide-react'
import { cn } from '@/lib/cn'
import { Button } from './ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'
import type { ViewportType } from '@/lib/types'

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

// Smooth spring config
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
  const [isFocused, setIsFocused] = useState(false)

  useEffect(() => {
    setInputValue(url)
  }, [url])

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      onNavigate(inputValue)
    }
  }

  const leftPadding = isMac ? 80 : 16

  return (
    <TooltipProvider delayDuration={300}>
      <header
        className="drag-region fixed top-0 left-0 right-0 h-[56px] bg-white/90 dark:bg-[#111113]/90 backdrop-blur-2xl border-b border-[#4A5D6A]/10 dark:border-white/[0.06] flex items-center px-3 gap-3 z-50"
        style={{ paddingLeft: leftPadding }}
      >
        {/* Logo + Sidebar Toggle */}
        <div className="no-drag flex items-center gap-2.5">
          {/* Yalitest Logo */}
          <img
            src="/images/logo.svg"
            alt="Yalitest"
            className="h-7 dark:invert dark:brightness-200"
          />

          {/* Sidebar Toggle */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onToggleSidebar}
                className={cn(
                  'no-drag h-8 w-8',
                  sidebarOpen && 'bg-[#4A5D6A]/10 dark:bg-white/[0.08] text-[#2a3a42] dark:text-white'
                )}
              >
                <PanelLeft className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Elements ({modKey}E)</TooltipContent>
          </Tooltip>
        </div>

        {/* Divider */}
        <div className="h-6 w-px bg-[#4A5D6A]/10 dark:bg-white/[0.08]" />

        {/* Navigation */}
        <div className="no-drag flex items-center gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon-sm" onClick={onBack} className="h-8 w-8">
                <ChevronLeft className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Back</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon-sm" onClick={onForward} className="h-8 w-8">
                <ChevronRight className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Forward</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon-sm" onClick={onReload} className="h-8 w-8">
                <motion.div
                  animate={isLoading ? { rotate: 360 } : { rotate: 0 }}
                  transition={isLoading ? { duration: 1, repeat: Infinity, ease: 'linear' } : { duration: 0.2 }}
                >
                  <RotateCw className="h-4 w-4" />
                </motion.div>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="bottom">Reload ({modKey}R)</TooltipContent>
          </Tooltip>
        </div>

        {/* URL Bar - Calm, professional design */}
        <div className="no-drag flex-1 max-w-2xl relative">
          <motion.div
            className={cn(
              'relative flex items-center h-10 rounded-xl transition-all duration-200',
              'bg-[#f8f9f6] dark:bg-white/[0.04]',
              'border border-transparent',
              isFocused
                ? 'bg-white dark:bg-[#161618] border-[#4A5D6A]/30 dark:border-[#4A5D6A]/30 shadow-sm'
                : 'hover:bg-white dark:hover:bg-white/[0.06]'
            )}
          >
            {/* Search icon */}
            <div className="pl-3.5 pr-1 flex items-center">
              <Search className={cn(
                'w-4 h-4 transition-colors duration-200',
                isFocused ? 'text-[#4A5D6A]' : 'text-[#4A5D6A]/40 dark:text-white/30'
              )} />
            </div>

            {/* Input */}
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={(e) => {
                setIsFocused(true)
                e.target.select()
              }}
              onBlur={() => setIsFocused(false)}
              placeholder="Enter URL to start testing..."
              spellCheck={false}
              autoComplete="off"
              className={cn(
                'flex-1 h-full bg-transparent px-2 text-sm font-medium',
                'text-[#2a3a42] dark:text-white',
                'placeholder:text-[#4A5D6A]/40 dark:placeholder:text-white/30',
                'outline-none'
              )}
            />

            {/* Keyboard shortcut */}
            <div className="pr-3 flex items-center">
              <kbd className={cn(
                'px-2 py-0.5 rounded-md text-[11px] font-mono font-medium transition-colors duration-200',
                isFocused
                  ? 'bg-[#4A5D6A]/10 dark:bg-[#4A5D6A]/20 text-[#4A5D6A] dark:text-white/60'
                  : 'bg-[#4A5D6A]/5 dark:bg-white/[0.06] text-[#4A5D6A]/50 dark:text-white/40'
              )}>
                {modKey}L
              </kbd>
            </div>
          </motion.div>
        </div>

        {/* Divider */}
        <div className="h-6 w-px bg-[#4A5D6A]/10 dark:bg-white/[0.08]" />

        {/* Viewport Switcher */}
        <div className="no-drag flex items-center bg-[#f8f9f6] dark:bg-white/[0.04] rounded-xl p-1 gap-0.5 relative">
          {/* Animated background indicator */}
          <motion.div
            className="absolute h-8 bg-white dark:bg-white/[0.1] rounded-lg shadow-sm"
            initial={false}
            animate={{
              x: viewports.findIndex(v => v.type === viewport) * 34 + 2,
              width: 30,
            }}
            transition={smoothSpring}
          />

          {viewports.map(({ type, icon: Icon, label }) => (
            <Tooltip key={type}>
              <TooltipTrigger asChild>
                <motion.button
                  onClick={() => onViewportChange(type)}
                  className={cn(
                    'relative z-10 w-[34px] h-8 flex items-center justify-center rounded-lg transition-colors duration-200',
                    viewport === type
                      ? 'text-[#2a3a42] dark:text-white'
                      : 'text-[#4A5D6A]/50 dark:text-white/40 hover:text-[#4A5D6A] dark:hover:text-white/60'
                  )}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Icon className="w-4 h-4" />
                </motion.button>
              </TooltipTrigger>
              <TooltipContent side="bottom">{label}</TooltipContent>
            </Tooltip>
          ))}
        </div>

        <div className="flex-1" />

        {/* Chat Toggle - Calm, professional */}
        <Tooltip>
          <TooltipTrigger asChild>
            <motion.button
              onClick={onToggleChat}
              className={cn(
                'no-drag relative flex items-center gap-2 h-9 px-4 rounded-xl font-medium text-sm transition-all duration-200',
                chatOpen
                  ? 'bg-[#4A5D6A] text-white'
                  : 'bg-[#f8f9f6] dark:bg-white/[0.04] text-[#4A5D6A] dark:text-white/70 hover:bg-[#4A5D6A]/10 dark:hover:bg-white/[0.08]'
              )}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <MessageCircle className="w-4 h-4" />
              <span className="hidden sm:inline">Assistant</span>
              {!chatOpen && (
                <kbd className="hidden sm:inline px-1.5 py-0.5 bg-[#4A5D6A]/10 dark:bg-white/[0.1] rounded text-[10px] font-mono text-[#4A5D6A]/60 dark:text-white/50">
                  {modKey}J
                </kbd>
              )}
            </motion.button>
          </TooltipTrigger>
          <TooltipContent side="bottom">AI Assistant ({modKey}J)</TooltipContent>
        </Tooltip>
      </header>
    </TooltipProvider>
  )
})
