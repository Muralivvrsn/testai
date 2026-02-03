import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ArrowRight, CheckCircle2 } from 'lucide-react'
import { Button } from './ui/button'

interface WelcomeModalProps {
  onClose: () => void
}

const spring = {
  type: 'spring' as const,
  stiffness: 300,
  damping: 30,
}

// Single-page welcome - no multi-step wizard
// Professional, calm, gets out of the way quickly
export function WelcomeModal({ onClose }: WelcomeModalProps) {
  const [isReady, setIsReady] = useState(false)

  useEffect(() => {
    // Small delay for entrance animation
    const timer = setTimeout(() => setIsReady(true), 100)
    return () => clearTimeout(timer)
  }, [])

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }, [onClose])

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  const capabilities = [
    'Deep security analysis',
    'Accessibility compliance',
    'Performance insights',
    'Edge case detection',
  ]

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-[#f8f9f6] dark:bg-[#0a0b0a]"
    >
      {/* Subtle ambient gradient */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/3 left-1/3 w-[600px] h-[600px] bg-[#4A5D6A]/[0.03] rounded-full blur-[150px]" />
        <div className="absolute bottom-1/3 right-1/3 w-[400px] h-[400px] bg-[#4A5D6A]/[0.02] rounded-full blur-[120px]" />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-lg w-full px-8">
        <AnimatePresence>
          {isReady && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={spring}
              className="text-center"
            >
              {/* Logo */}
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ ...spring, delay: 0.1 }}
                className="mb-10"
              >
                <img
                  src="/images/logo.svg"
                  alt="Yalitest"
                  className="h-12 mx-auto dark:invert dark:brightness-200"
                />
              </motion.div>

              {/* Headline - calm, professional */}
              <motion.h1
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring, delay: 0.15 }}
                className="font-display text-3xl font-semibold text-[#2a3a42] dark:text-white/90 mb-4 tracking-tight"
              >
                Quality assurance, simplified.
              </motion.h1>

              {/* Subhead - value-focused */}
              <motion.p
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring, delay: 0.2 }}
                className="text-lg text-[#4A5D6A] dark:text-white/50 mb-10 leading-relaxed max-w-md mx-auto"
              >
                Paste a URL. Get comprehensive test results. Ship with confidence.
              </motion.p>

              {/* Capabilities - quick scan */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring, delay: 0.25 }}
                className="flex flex-wrap justify-center gap-3 mb-12"
              >
                {capabilities.map((cap, i) => (
                  <motion.div
                    key={cap}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ ...spring, delay: 0.3 + i * 0.05 }}
                    className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-white/[0.04] border border-[#4A5D6A]/10 dark:border-white/[0.06] rounded-full"
                  >
                    <CheckCircle2 className="w-4 h-4 text-[#4A5D6A] dark:text-white/40" />
                    <span className="text-sm text-[#4A5D6A] dark:text-white/60">{cap}</span>
                  </motion.div>
                ))}
              </motion.div>

              {/* CTA - single action, gets out of the way */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ ...spring, delay: 0.5 }}
              >
                <Button
                  onClick={onClose}
                  size="lg"
                  className="group gap-3 px-8 h-14 bg-[#4A5D6A] hover:bg-[#3a4d5a] text-white text-base font-medium rounded-2xl transition-all duration-200 hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-[#4A5D6A]/20"
                >
                  Get started
                  <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-0.5" />
                </Button>
              </motion.div>

              {/* Keyboard hint */}
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.7 }}
                className="mt-6 text-sm text-[#4A5D6A]/50 dark:text-white/30"
              >
                Press <kbd className="px-2 py-0.5 bg-[#4A5D6A]/5 dark:bg-white/5 rounded text-xs font-mono">Enter</kbd> to continue
              </motion.p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
