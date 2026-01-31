import { useState, useRef, useEffect, KeyboardEvent, memo, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Send, User2, Bot, ChevronRight } from 'lucide-react'
import { cn } from '../lib/cn'
import type { Message } from '../lib/types'

// Parse message content into sections for accordion display
function parseMessageSections(content: string): { intro: string; sections: { title: string; content: string }[] } {
  const lines = content.split('\n')
  const sections: { title: string; content: string }[] = []
  let intro = ''
  let currentSection: { title: string; lines: string[] } | null = null

  for (const line of lines) {
    // Detect section headers (bold text with colon, or ** markers)
    const sectionMatch = line.match(/^\*\*([^*]+)\*\*:?$/) || line.match(/^([A-Z][^:]{5,50}):$/)

    if (sectionMatch) {
      // Save previous section
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

  // Save last section
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
}

// Simple markdown-like formatting
function formatMessage(content: string): JSX.Element {
  // Split by bold markers
  const parts = content.split(/(\*\*[^*]+\*\*)/g)

  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**')) {
          return <strong key={i} className="font-semibold">{part.slice(2, -2)}</strong>
        }
        // Handle newlines
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

// Smooth spring config - same across all components
const smoothSpring = {
  type: 'spring' as const,
  stiffness: 400,
  damping: 40,
  mass: 1,
}

export const ChatPanel = memo(function ChatPanel({
  open,
  messages,
  isThinking,
  onSendMessage,
  onStartTest,
}: ChatPanelProps) {
  const [input, setInput] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, isThinking])

  const handleSend = () => {
    if (input.trim()) {
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

  return (
    <AnimatePresence mode="wait">
      {open && (
        <motion.aside
          initial={{ x: 360, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 360, opacity: 0 }}
          transition={smoothSpring}
          className="fixed top-[52px] right-0 bottom-0 w-[360px] bg-white border-l border-neutral-200 flex flex-col z-40 will-change-transform contain-layout"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-100">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-neutral-800 to-neutral-600 rounded-full flex items-center justify-center">
                <Bot className="w-4 h-4 text-white" />
              </div>
              <div>
                <span className="text-sm font-semibold text-neutral-900 block">Alex</span>
                <span className="text-xs text-neutral-500">Senior QA Engineer</span>
              </div>
            </div>
            <motion.div
              animate={{
                backgroundColor: isThinking ? 'rgb(254 243 199)' : 'rgb(220 252 231)',
              }}
              transition={{ duration: 0.3 }}
              className="flex items-center gap-2 px-2.5 py-1 rounded-full"
            >
              <motion.span
                animate={{
                  backgroundColor: isThinking ? 'rgb(245 158 11)' : 'rgb(34 197 94)',
                  scale: isThinking ? [1, 1.2, 1] : 1,
                }}
                transition={{
                  backgroundColor: { duration: 0.3 },
                  scale: { repeat: isThinking ? Infinity : 0, duration: 1 },
                }}
                className="w-1.5 h-1.5 rounded-full"
              />
              <span className="text-xs text-neutral-600">
                {isThinking ? 'Thinking...' : 'Online'}
              </span>
            </motion.div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4">
            <AnimatePresence mode="wait">
              {messages.length === 0 ? (
                <WelcomeState key="welcome" />
              ) : (
                <motion.div
                  key="messages"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="space-y-3"
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

          {/* Input */}
          <motion.div
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.1 }}
            className="p-4 border-t border-neutral-100"
          >
            {/* Chat Input */}
            <div className="flex items-end gap-2 p-3 bg-neutral-50 rounded-xl border border-neutral-200 transition-all duration-200 focus-within:border-neutral-400 focus-within:bg-white focus-within:shadow-sm">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Paste a URL or ask Alex anything..."
                rows={1}
                className="flex-1 bg-transparent text-sm text-neutral-900 placeholder:text-neutral-400 outline-none resize-none min-h-[24px] max-h-[100px]"
              />
              <motion.button
                onClick={handleSend}
                disabled={!input.trim() || isThinking}
                className="w-9 h-9 bg-neutral-900 text-white rounded-lg flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed hover:bg-neutral-800"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.9 }}
              >
                <Send className="w-4 h-4" />
              </motion.button>
            </div>
            <p className="text-[10px] text-neutral-400 mt-2 text-center">
              Press Enter to send • Shift+Enter for new line
            </p>
          </motion.div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
})

const WelcomeState = memo(function WelcomeState() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="h-full flex flex-col items-center justify-center text-center px-6"
    >
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 400, damping: 25, delay: 0.1 }}
        className="w-16 h-16 bg-gradient-to-br from-neutral-800 to-neutral-600 rounded-2xl flex items-center justify-center mb-4"
      >
        <Bot className="w-8 h-8 text-white" />
      </motion.div>
      <motion.h3
        initial={{ y: 15, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 400, damping: 30, delay: 0.15 }}
        className="text-base font-semibold text-neutral-900 mb-2"
      >
        Meet Alex
      </motion.h3>
      <motion.p
        initial={{ y: 15, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 400, damping: 30, delay: 0.2 }}
        className="text-sm text-neutral-500 leading-relaxed"
      >
        Your senior QA engineer with 12 years of experience finding bugs others miss.
      </motion.p>
      <motion.div
        initial={{ y: 15, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 400, damping: 30, delay: 0.3 }}
        className="mt-4"
      >
        <div className="flex gap-1">
          {[0, 1, 2].map((i) => (
            <motion.div
              key={i}
              className="w-2 h-2 bg-neutral-300 rounded-full"
              animate={{ opacity: [0.3, 1, 0.3] }}
              transition={{
                duration: 1,
                repeat: Infinity,
                delay: i * 0.2,
              }}
            />
          ))}
        </div>
      </motion.div>
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
    <div className="border-t border-neutral-200 first:border-t-0">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center gap-2 py-2 text-left hover:bg-neutral-50 transition-colors"
      >
        <motion.div
          animate={{ rotate: isOpen ? 90 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronRight className="w-3.5 h-3.5 text-neutral-400" />
        </motion.div>
        <span className="text-xs font-semibold text-neutral-700">{title}</span>
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
            <div className="pl-5 pb-2 text-xs text-neutral-600 whitespace-pre-wrap">
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

  // Parse sections for accordion (only for longer assistant messages)
  const parsed = useMemo(() => {
    if (isUser || message.content.length < 200) return null
    const result = parseMessageSections(message.content)
    // Only use accordion if we have sections
    return result.sections.length > 0 ? result : null
  }, [message.content, isUser])

  return (
    <motion.div
      initial={{ y: 15, opacity: 0, scale: 0.95 }}
      animate={{ y: 0, opacity: 1, scale: 1 }}
      transition={{
        type: 'spring',
        stiffness: 400,
        damping: 30,
        delay: Math.min(index * 0.03, 0.3),
      }}
      className={cn('flex gap-2', isUser ? 'justify-end' : 'justify-start')}
    >
      {/* Avatar for assistant */}
      {!isUser && (
        <div className="w-7 h-7 bg-gradient-to-br from-neutral-700 to-neutral-500 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
          <Bot className="w-3.5 h-3.5 text-white" />
        </div>
      )}

      <div className="max-w-[85%] flex flex-col">
        {parsed ? (
          // Accordion layout for sectioned content
          <div className="bg-neutral-100 rounded-2xl rounded-bl-md overflow-hidden">
            {/* Intro text */}
            {parsed.intro && (
              <div className="px-3 py-2 text-sm text-neutral-800 leading-relaxed">
                {formatMessage(parsed.intro)}
              </div>
            )}
            {/* Accordion sections */}
            <div className="px-3 pb-2">
              {parsed.sections.map((section, i) => (
                <AccordionSection
                  key={i}
                  title={section.title}
                  content={section.content}
                  defaultOpen={i === 0} // First section open by default
                />
              ))}
            </div>
          </div>
        ) : (
          // Simple message bubble
          <div
            className={cn(
              'px-3 py-2 rounded-2xl text-sm leading-relaxed whitespace-pre-wrap',
              isUser
                ? 'bg-neutral-900 text-white rounded-br-md'
                : 'bg-neutral-100 text-neutral-800 rounded-bl-md'
            )}
          >
            {isUser ? message.content : formatMessage(message.content)}
          </div>
        )}
      </div>

      {/* Avatar for user */}
      {isUser && (
        <div className="w-7 h-7 bg-blue-500 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
          <User2 className="w-3.5 h-3.5 text-white" />
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
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      className="flex gap-2 justify-start"
    >
      {/* Avatar */}
      <div className="w-7 h-7 bg-gradient-to-br from-neutral-700 to-neutral-500 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
        <Bot className="w-3.5 h-3.5 text-white" />
      </div>

      <div className="px-4 py-3 bg-neutral-100 rounded-2xl rounded-bl-md">
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {[0, 1, 2].map((i) => (
              <motion.div
                key={i}
                className="w-2 h-2 bg-neutral-400 rounded-full"
                animate={{
                  y: [0, -5, 0],
                  opacity: [0.4, 1, 0.4],
                }}
                transition={{
                  duration: 0.6,
                  repeat: Infinity,
                  delay: i * 0.1,
                  ease: 'easeInOut',
                }}
              />
            ))}
          </div>
          <span className="text-xs text-neutral-500">Alex is thinking...</span>
        </div>
      </div>
    </motion.div>
  )
})
