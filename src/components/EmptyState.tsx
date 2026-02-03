import { motion } from 'framer-motion'
import { useState, useEffect } from 'react'

interface EmptyStateProps {
  modKey: string
}

const spring = {
  type: 'spring' as const,
  stiffness: 300,
  damping: 30,
}

// Animated scanning lines
function ScanLines() {
  return (
    <div className="absolute inset-0 overflow-hidden rounded-2xl">
      {[...Array(3)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"
          initial={{ top: '-10%' }}
          animate={{ top: '110%' }}
          transition={{
            duration: 2,
            repeat: Infinity,
            delay: i * 0.6,
            ease: 'linear',
          }}
        />
      ))}
    </div>
  )
}

// Floating element that represents a detected issue
function FloatingBadge({
  children,
  className,
  delay
}: {
  children: React.ReactNode
  className: string
  delay: number
}) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, scale: 0.8, y: 10 }}
      animate={{
        opacity: 1,
        scale: 1,
        y: [0, -5, 0],
      }}
      transition={{
        opacity: { delay, duration: 0.3 },
        scale: { delay, duration: 0.3 },
        y: { delay: delay + 0.3, duration: 3, repeat: Infinity, ease: 'easeInOut' },
      }}
    >
      {children}
    </motion.div>
  )
}

export function EmptyState({ modKey }: EmptyStateProps) {
  const [dots, setDots] = useState('')

  useEffect(() => {
    const interval = setInterval(() => {
      setDots(d => d.length >= 3 ? '' : d + '.')
    }, 500)
    return () => clearInterval(interval)
  }, [])

  return (
    <motion.div
      key="placeholder"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="h-full flex flex-col items-center justify-center relative"
    >
      {/* Central visual */}
      <motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ ...spring, delay: 0.1 }}
        className="relative mb-10"
      >
        {/* Main browser mockup */}
        <div className="relative">
          {/* Glow effect */}
          <div className="absolute -inset-8 bg-gradient-to-br from-indigo-500/10 via-purple-500/10 to-indigo-500/10 rounded-[40px] blur-2xl opacity-60 dark:opacity-40" />

          {/* Browser window */}
          <motion.div
            className="relative w-[280px] h-[180px] bg-white dark:bg-[#111113] rounded-2xl border border-neutral-200/80 dark:border-white/[0.08] shadow-2xl shadow-neutral-200/50 dark:shadow-black/50 overflow-hidden"
            animate={{ y: [0, -4, 0] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          >
            {/* Browser header */}
            <div className="h-8 bg-neutral-50 dark:bg-[#0d0d0f] border-b border-neutral-200/80 dark:border-white/[0.06] flex items-center px-3 gap-2">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              </div>
              <div className="flex-1 mx-3">
                <div className="h-5 bg-neutral-200/80 dark:bg-white/[0.06] rounded-md flex items-center justify-center">
                  <span className="text-[10px] text-neutral-400 dark:text-white/30 font-mono">
                    https://
                  </span>
                </div>
              </div>
            </div>

            {/* Content area with scan effect */}
            <div className="relative h-[calc(100%-2rem)] p-4">
              <ScanLines />

              {/* Placeholder content lines */}
              <div className="space-y-3 relative z-10">
                <div className="h-3 bg-neutral-100 dark:bg-white/[0.04] rounded-full w-3/4" />
                <div className="h-3 bg-neutral-100 dark:bg-white/[0.04] rounded-full w-full" />
                <div className="h-3 bg-neutral-100 dark:bg-white/[0.04] rounded-full w-2/3" />
                <div className="flex gap-2 mt-4">
                  <div className="h-8 bg-neutral-100 dark:bg-white/[0.04] rounded-lg flex-1" />
                  <div className="h-8 bg-neutral-100 dark:bg-white/[0.04] rounded-lg w-20" />
                </div>
              </div>
            </div>
          </motion.div>

          {/* Floating badges around the browser */}
          <FloatingBadge
            className="absolute -top-4 -right-12"
            delay={0.5}
          >
            <div className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-[#161618] border border-neutral-200/80 dark:border-white/[0.08] rounded-xl shadow-lg">
              <div className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-xs font-medium text-neutral-700 dark:text-white/70">Security</span>
            </div>
          </FloatingBadge>

          <FloatingBadge
            className="absolute -bottom-2 -right-8"
            delay={0.7}
          >
            <div className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-[#161618] border border-neutral-200/80 dark:border-white/[0.08] rounded-xl shadow-lg">
              <div className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-xs font-medium text-neutral-700 dark:text-white/70">A11y</span>
            </div>
          </FloatingBadge>

          <FloatingBadge
            className="absolute top-8 -left-14"
            delay={0.9}
          >
            <div className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-[#161618] border border-neutral-200/80 dark:border-white/[0.08] rounded-xl shadow-lg">
              <div className="w-2 h-2 rounded-full bg-indigo-500" />
              <span className="text-xs font-medium text-neutral-700 dark:text-white/70">UI/UX</span>
            </div>
          </FloatingBadge>
        </div>
      </motion.div>

      {/* Text content */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ...spring, delay: 0.3 }}
        className="text-center max-w-sm"
      >
        <h2 className="font-display text-2xl font-bold text-neutral-900 dark:text-white mb-3">
          Ready to test
        </h2>
        <p className="text-neutral-500 dark:text-white/50 mb-6 leading-relaxed">
          Paste any URL above to scan for bugs, accessibility issues, and security vulnerabilities.
        </p>

        {/* Keyboard shortcut hint */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="inline-flex items-center gap-3 px-5 py-3 bg-neutral-100/80 dark:bg-white/[0.03] border border-neutral-200/60 dark:border-white/[0.06] rounded-2xl"
        >
          <kbd className="px-3 py-1.5 bg-white dark:bg-white/[0.08] border border-neutral-200/80 dark:border-white/[0.08] rounded-lg text-sm font-mono font-medium text-neutral-700 dark:text-white/70 shadow-sm">
            {modKey}L
          </kbd>
          <span className="text-sm text-neutral-500 dark:text-white/40">
            to focus URL bar
          </span>
        </motion.div>
      </motion.div>

      {/* Subtle bottom gradient */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-[#fafafa] dark:from-[#0a0a0b] to-transparent pointer-events-none" />
    </motion.div>
  )
}
