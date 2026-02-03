import { useState, useRef, useEffect, KeyboardEvent, memo, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Send, User2, ChevronRight, ArrowRight, Shield, Bug, Accessibility, Search } from 'lucide-react'
import { cn } from '@/lib/cn'
import { ScrollArea } from './ui/scroll-area'
import type { Message } from '@/lib/types'

// Parse message content into sections for accordion display
function parseMessageSections(content: string): { intro: string; sections: { title: string; content: string }[] } {
  const lines = content.split('\n')
  const sections: { title: string; content: string }[] = []
  let intro = ''
  let currentSection: { title: string; lines: string[] } | null = null

  for (const line of lines) {
    const sectionMatch = line.match(/^\*\*([^*]+)\*\*:?$/) || line.match(/^([A-Z][^:]{5,50}):$/)

    if (sectionMatch) {
      if (currentSection) {
        sections.push({ title: currentSection.title, content: currentSection.lines.join('\n').trim() })
      }
      currentSection = { title: sectionMatch[1].trim(), lines: [] }
    } else if (currentSection) {
      currentSection.lines.push(line)
    } else {
      intro += line + '\n'
    }
  }

  if (currentSection && currentSection.lines.length > 0) {
    sections.push({ title: currentSection.title, content: currentSection.lines.join('\n').trim() })
  }

  return { intro: intro.trim(), sections }
}

interface ChatPanelProps {
  open: boolean
  messages: Message[]
  isThinking: boolean
  onSendMessage: (content: string) => void
  onStartTest: () => void
  isDocked: boolean
  onDock: () => void
}

// Simple markdown-like formatting
function formatMessage(content: string): JSX.Element {
  const parts = content.split(/(\*\*[^*]+\*\*)/g)

  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**')) {
          return <strong key={i} className="font-semibold text-neutral-900 dark:text-white">{part.slice(2, -2)}</strong>
        }
        return part.split('\n').map((line, j) => (
          <span key={`${i}-${j}`}>
            {j > 0 && <br />}
            {line}
          </span>
        ))
      })}
    </>
  )
}

// Apple-like spring animation
const appleSpring = {
  type: 'spring' as const,
  stiffness: 400,
  damping: 40,
  mass: 0.8,
}

export const ChatPanel = memo(function ChatPanel({
  open,
  messages,
  isThinking,
  onSendMessage,
  isDocked,
  onDock,
}: ChatPanelProps) {
  const [input, setInput] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, isThinking])

  const handleSend = () => {
    if (input.trim()) {
      if (!isDocked) {
        onDock()
      }
      onSendMessage(input)
      setInput('')
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  // Quick action prompts - streamlined for efficiency
  const quickActions = [
    { label: 'Full scan', icon: Search, prompt: 'Run a comprehensive test on this page', color: 'slate' },
    { label: 'Security audit', icon: Shield, prompt: 'Check for security vulnerabilities', color: 'slate' },
    { label: 'Accessibility', icon: Accessibility, prompt: 'Check accessibility compliance', color: 'slate' },
  ]

  const handleQuickAction = (prompt: string) => {
    if (!isDocked) {
      onDock()
    }
    onSendMessage(prompt)
  }

  return (
    <AnimatePresence mode="wait">
      {open && (
        <>
          {/* Backdrop for centered mode */}
          {!isDocked && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 top-[56px] bg-black/20 dark:bg-black/40 backdrop-blur-md z-30"
              onClick={onDock}
            />
          )}

          <motion.aside
            initial={isDocked ? { x: 400, opacity: 0 } : { y: 30, opacity: 0, scale: 0.96 }}
            animate={{ x: 0, y: 0, opacity: 1, scale: 1 }}
            exit={isDocked ? { x: 400, opacity: 0 } : { y: 30, opacity: 0, scale: 0.96 }}
            transition={appleSpring}
            className={cn(
              'flex flex-col z-40 will-change-transform',
              isDocked
                ? 'fixed top-[56px] right-0 bottom-0 w-[400px] bg-white/90 dark:bg-[#1a1a1c]/90 backdrop-blur-2xl border-l border-neutral-200/50 dark:border-white/[0.08]'
                : 'fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[520px] max-h-[640px] bg-white dark:bg-[#1a1a1c] rounded-[28px] shadow-2xl shadow-black/20 dark:shadow-black/50 border border-neutral-200/50 dark:border-white/[0.08]'
            )}
            layout
          >
            {/* Header - calm, professional */}
            <div className={cn(
              'flex items-center justify-between border-b border-[#4A5D6A]/10 dark:border-white/[0.06]',
              isDocked ? 'px-5 py-4' : 'px-6 py-5'
            )}>
              <div className="flex items-center gap-3">
                <img
                  src="/images/logo.svg"
                  alt="Yalitest"
                  className={cn(
                    'w-auto object-contain dark:invert dark:brightness-200',
                    isDocked ? 'h-6 max-w-[100px]' : 'h-7 max-w-[120px]'
                  )}
                />
              </div>

              {/* Status - minimal */}
              <div className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded-full',
                isThinking
                  ? 'bg-[#4A5D6A]/10 dark:bg-white/10'
                  : 'bg-emerald-500/10'
              )}>
                <motion.div
                  animate={isThinking ? { opacity: [0.4, 1, 0.4] } : {}}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                  className={cn(
                    'w-1.5 h-1.5 rounded-full',
                    isThinking ? 'bg-[#4A5D6A] dark:bg-white/60' : 'bg-emerald-500'
                  )}
                />
                <span className={cn(
                  'text-xs font-medium',
                  isThinking
                    ? 'text-[#4A5D6A] dark:text-white/60'
                    : 'text-emerald-600 dark:text-emerald-400'
                )}>
                  {isThinking ? 'Working...' : 'Ready'}
                </span>
              </div>
            </div>

            {/* Messages / Welcome */}
            <ScrollArea className="flex-1">
              <div className={cn(isDocked ? 'p-5' : 'p-7')}>
                <AnimatePresence mode="wait">
                  {messages.length === 0 && !isDocked ? (
                    <CenteredWelcome
                      quickActions={quickActions}
                      onQuickAction={handleQuickAction}
                    />
                  ) : messages.length === 0 ? (
                    <DockedWelcome key="docked-welcome" />
                  ) : (
                    <motion.div
                      key="messages"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="space-y-5"
                    >
                      {messages.map((message, index) => (
                        <MessageBubble key={message.id} message={message} index={index} />
                      ))}
                      {isThinking && <ThinkingIndicator />}
                      <div ref={messagesEndRef} />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </ScrollArea>

            {/* Input - clean, minimal */}
            <div className={cn(
              'bg-[#f8f9f6]/80 dark:bg-black/20 border-t border-[#4A5D6A]/5 dark:border-white/[0.06]',
              isDocked ? 'px-4 py-3' : 'px-5 py-4'
            )}>
              <div className={cn(
                'flex items-center gap-2 rounded-xl transition-colors duration-150',
                'bg-white dark:bg-[#1a1a1c]',
                'border border-[#4A5D6A]/10 dark:border-white/[0.08]',
                'focus-within:border-[#4A5D6A]/30 dark:focus-within:border-white/20',
                isDocked ? 'pl-3 pr-2 py-2' : 'pl-4 pr-2 py-2.5'
              )}>
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value)
                    // Auto-resize for smooth typing
                    e.target.style.height = 'auto'
                    e.target.style.height = Math.min(e.target.scrollHeight, 80) + 'px'
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder="Enter a URL or describe your test..."
                  rows={1}
                  className={cn(
                    'flex-1 bg-transparent text-[#2a3a42] dark:text-white resize-none',
                    'placeholder:text-[#4A5D6A]/40 dark:placeholder:text-white/30',
                    'outline-none border-none focus:outline-none focus:ring-0 appearance-none',
                    'text-sm min-h-[22px] max-h-[80px] py-0.5',
                    'will-change-[height]' // GPU acceleration for smooth resize
                  )}
                />

                {/* Send button */}
                <motion.button
                  onClick={handleSend}
                  disabled={!input.trim() || isThinking}
                  whileTap={{ scale: input.trim() ? 0.95 : 1 }}
                  className={cn(
                    'shrink-0 rounded-lg flex items-center justify-center transition-all duration-200',
                    'bg-[#4A5D6A] text-white',
                    input.trim() && !isThinking
                      ? 'opacity-100 hover:bg-[#3a4d5a]'
                      : 'opacity-30 cursor-not-allowed',
                    'w-8 h-8'
                  )}
                >
                  <Send className="w-4 h-4" />
                </motion.button>
              </div>

              <p className={cn(
                'text-[#4A5D6A]/40 dark:text-white/30 mt-2 text-center text-[11px]'
              )}>
                Press <kbd className="px-1 py-0.5 bg-[#4A5D6A]/5 dark:bg-white/5 rounded text-[10px] font-mono">Enter</kbd> to send
              </p>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
})

// Color map for quick actions - unified calm palette
const actionColors = {
  slate: {
    bg: 'bg-[#4A5D6A]/5 dark:bg-white/[0.04]',
    icon: 'text-[#4A5D6A] dark:text-white/60',
    hover: 'hover:bg-[#4A5D6A]/10 dark:hover:bg-white/[0.08] hover:border-[#4A5D6A]/20 dark:hover:border-white/[0.1]',
  },
}

// Centered welcome state - calm, efficient, gets to the point
const CenteredWelcome = memo(function CenteredWelcome({
  quickActions,
  onQuickAction,
}: {
  quickActions: { label: string; icon: typeof Bug; prompt: string; color: string }[]
  onQuickAction: (prompt: string) => void
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex flex-col py-4"
    >
      {/* Simple greeting - no avatar, less visual noise */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, ...appleSpring }}
        className="mb-8"
      >
        <h3 className="text-lg font-medium text-[#2a3a42] dark:text-white/90 mb-2">
          What would you like to test?
        </h3>
        <p className="text-sm text-[#4A5D6A] dark:text-white/50">
          Enter a URL or choose a quick action to get started.
        </p>
      </motion.div>

      {/* Quick actions - streamlined */}
      <div className="flex flex-col gap-2">
        {quickActions.map((action, i) => {
          const colors = actionColors[action.color as keyof typeof actionColors] || actionColors.slate
          return (
            <motion.button
              key={action.label}
              onClick={() => onQuickAction(action.prompt)}
              className={cn(
                'group flex items-center gap-3 px-4 py-3 bg-white dark:bg-white/[0.02] border border-[#4A5D6A]/10 dark:border-white/[0.06] rounded-xl transition-all duration-200 text-left',
                colors.hover
              )}
              whileHover={{ x: 4 }}
              whileTap={{ scale: 0.98 }}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.15 + i * 0.05, ...appleSpring }}
            >
              <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center', colors.bg)}>
                <action.icon className={cn('w-4 h-4', colors.icon)} />
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-sm font-medium text-[#2a3a42] dark:text-white/80 block">{action.label}</span>
              </div>
              <ArrowRight className="w-4 h-4 text-[#4A5D6A]/30 dark:text-white/20 group-hover:text-[#4A5D6A] dark:group-hover:text-white/60 transition-colors" />
            </motion.button>
          )
        })}
      </div>
    </motion.div>
  )
})

// Docked welcome state - minimal, gets out of the way
const DockedWelcome = memo(function DockedWelcome() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="h-full flex flex-col items-center justify-center text-center px-6 py-12"
    >
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={appleSpring}
        className="w-14 h-14 bg-[#4A5D6A]/5 dark:bg-white/[0.04] rounded-2xl flex items-center justify-center mb-5"
      >
        <Search className="w-6 h-6 text-[#4A5D6A] dark:text-white/40" />
      </motion.div>
      <motion.h3
        initial={{ y: 10, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.1, ...appleSpring }}
        className="font-display text-base font-medium text-[#2a3a42] dark:text-white/90 mb-2"
      >
        Ready to test
      </motion.h3>
      <motion.p
        initial={{ y: 10, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.15, ...appleSpring }}
        className="text-sm text-[#4A5D6A] dark:text-white/50 leading-relaxed max-w-[240px]"
      >
        Enter a URL or describe what you'd like to test.
      </motion.p>
    </motion.div>
  )
})

// Accordion Section Component
const AccordionSection = memo(function AccordionSection({
  title,
  content,
  defaultOpen = false
}: {
  title: string;
  content: string;
  defaultOpen?: boolean
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border-t border-neutral-200/50 dark:border-white/[0.06] first:border-t-0">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center gap-2.5 py-3 text-left hover:bg-neutral-100/50 dark:hover:bg-white/[0.02] transition-colors rounded-lg px-1 -mx-1"
      >
        <motion.div
          animate={{ rotate: isOpen ? 90 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronRight className="w-4 h-4 text-neutral-400 dark:text-neutral-500" />
        </motion.div>
        <span className="text-sm font-semibold text-neutral-800 dark:text-white">{title}</span>
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="pl-6 pb-3 text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed whitespace-pre-wrap">
              {formatMessage(content)}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
})

const MessageBubble = memo(function MessageBubble({ message, index }: { message: Message; index: number }) {
  const isUser = message.role === 'user'

  const parsed = useMemo(() => {
    if (isUser || message.content.length < 200) return null
    const result = parseMessageSections(message.content)
    return result.sections.length > 0 ? result : null
  }, [message.content, isUser])

  return (
    <motion.div
      initial={{ y: 15, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{
        ...appleSpring,
        delay: Math.min(index * 0.03, 0.2),
      }}
      className={cn('flex gap-3', isUser ? 'justify-end' : 'justify-start')}
    >
      {/* Avatar for assistant - minimal */}
      {!isUser && (
        <div className="w-8 h-8 rounded-lg bg-[#4A5D6A]/10 dark:bg-white/[0.06] flex items-center justify-center shrink-0">
          <span className="text-sm font-medium text-[#4A5D6A] dark:text-white/60">Y</span>
        </div>
      )}

      <div className="max-w-[80%] flex flex-col">
        {parsed ? (
          <div className="bg-[#f8f9f6] dark:bg-white/[0.04] rounded-2xl rounded-tl-lg overflow-hidden border border-[#4A5D6A]/5 dark:border-white/[0.06]">
            {parsed.intro && (
              <div className="px-4 py-3 text-sm text-[#2a3a42] dark:text-white/90 leading-relaxed">
                {formatMessage(parsed.intro)}
              </div>
            )}
            <div className="px-4 pb-3">
              {parsed.sections.map((section, i) => (
                <AccordionSection
                  key={i}
                  title={section.title}
                  content={section.content}
                  defaultOpen={i === 0}
                />
              ))}
            </div>
          </div>
        ) : (
          <div
            className={cn(
              'px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap',
              isUser
                ? 'bg-[#4A5D6A] text-white rounded-2xl rounded-br-lg'
                : 'bg-[#f8f9f6] dark:bg-white/[0.04] text-[#2a3a42] dark:text-white/90 rounded-2xl rounded-tl-lg border border-[#4A5D6A]/5 dark:border-white/[0.06]'
            )}
          >
            {isUser ? message.content : formatMessage(message.content)}
          </div>
        )}
      </div>

      {/* Avatar for user - minimal */}
      {isUser && (
        <div className="w-8 h-8 rounded-lg bg-[#4A5D6A] flex items-center justify-center shrink-0">
          <User2 className="w-4 h-4 text-white" />
        </div>
      )}
    </motion.div>
  )
})

const ThinkingIndicator = memo(function ThinkingIndicator() {
  return (
    <motion.div
      initial={{ y: 15, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={appleSpring}
      className="flex gap-3 justify-start"
    >
      <div className="w-8 h-8 rounded-lg bg-[#4A5D6A]/10 dark:bg-white/[0.06] flex items-center justify-center shrink-0">
        <span className="text-sm font-medium text-[#4A5D6A] dark:text-white/60">Y</span>
      </div>

      <div className="px-4 py-3 bg-[#f8f9f6] dark:bg-white/[0.04] rounded-2xl rounded-tl-lg border border-[#4A5D6A]/5 dark:border-white/[0.06]">
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {[0, 1, 2].map((i) => (
              <motion.div
                key={i}
                className="w-1.5 h-1.5 bg-[#4A5D6A] dark:bg-white/40 rounded-full"
                animate={{
                  opacity: [0.3, 1, 0.3],
                }}
                transition={{
                  duration: 1,
                  repeat: Infinity,
                  delay: i * 0.2,
                  ease: 'easeInOut',
                }}
              />
            ))}
          </div>
          <span className="text-sm text-[#4A5D6A] dark:text-white/50">Analyzing...</span>
        </div>
      </div>
    </motion.div>
  )
})
