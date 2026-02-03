import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, MessageCircle, Sparkles, Check, ArrowRight, Zap, Shield, Bug } from 'lucide-react'
import { cn } from '@/lib/cn'
import { Button } from './ui/button'

interface OnboardingProps {
  onComplete: () => void
}

const TOTAL_STEPS = 4

// Smooth spring for all animations
const spring = {
  type: 'spring' as const,
  stiffness: 400,
  damping: 35,
}

// Stagger children animation
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.2 },
  },
}

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: spring,
  },
}

export function Onboarding({ onComplete }: OnboardingProps) {
  const [step, setStep] = useState(0)

  const nextStep = useCallback(() => {
    if (step < TOTAL_STEPS - 1) {
      setStep(step + 1)
    } else {
      onComplete()
    }
  }, [step, onComplete])

  // Keyboard navigation (Enter/Space to continue)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        nextStep()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [nextStep])

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-background"
    >
      {/* Gradient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-violet-500/5 via-background to-purple-500/5" />

      {/* Subtle grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.02]"
        style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
          backgroundSize: '40px 40px',
        }}
      />

      {/* Glowing orbs */}
      <motion.div
        className="absolute top-1/4 left-1/4 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl"
        animate={{
          scale: [1, 1.2, 1],
          opacity: [0.3, 0.5, 0.3],
        }}
        transition={{
          duration: 8,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
      <motion.div
        className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"
        animate={{
          scale: [1.2, 1, 1.2],
          opacity: [0.5, 0.3, 0.5],
        }}
        transition={{
          duration: 8,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />

      {/* Content */}
      <div className="relative z-10 w-full max-w-lg px-8">
        <AnimatePresence mode="wait">
          {step === 0 && <WelcomeStep key="welcome" onNext={nextStep} />}
          {step === 1 && <MeetAlexStep key="alex" onNext={nextStep} />}
          {step === 2 && <HowItWorksStep key="how" onNext={nextStep} />}
          {step === 3 && <ReadyStep key="ready" onNext={nextStep} />}
        </AnimatePresence>

        {/* Progress dots */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="flex justify-center gap-2 mt-8"
        >
          {Array.from({ length: TOTAL_STEPS }).map((_, i) => (
            <motion.div
              key={i}
              className={cn(
                'h-2 rounded-full transition-all duration-300',
                i === step
                  ? 'bg-foreground w-6'
                  : i < step
                  ? 'bg-foreground/50 w-2'
                  : 'bg-foreground/20 w-2'
              )}
            />
          ))}
        </motion.div>
      </div>
    </motion.div>
  )
}

// Step 1: Welcome
function WelcomeStep({ onNext }: { onNext: () => void }) {
  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="flex flex-col items-center text-center"
    >
      {/* Logo */}
      <motion.div
        variants={itemVariants}
        className="relative mb-8"
      >
        <motion.div
          className="w-24 h-24 bg-gradient-to-br from-violet-500 to-purple-600 rounded-3xl flex items-center justify-center shadow-soft-lg"
          animate={{
            boxShadow: [
              '0 8px 32px -8px rgba(139, 92, 246, 0.3)',
              '0 8px 48px -8px rgba(139, 92, 246, 0.5)',
              '0 8px 32px -8px rgba(139, 92, 246, 0.3)',
            ],
          }}
          transition={{ duration: 3, repeat: Infinity }}
        >
          <Zap className="w-12 h-12 text-white" strokeWidth={1.5} />
        </motion.div>

        {/* Floating particles */}
        {[...Array(3)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-2 h-2 bg-violet-400 rounded-full"
            style={{
              top: `${20 + i * 25}%`,
              left: i % 2 === 0 ? '-20%' : '120%',
            }}
            animate={{
              y: [0, -10, 0],
              opacity: [0.5, 1, 0.5],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              delay: i * 0.3,
            }}
          />
        ))}
      </motion.div>

      {/* Title */}
      <motion.h1
        variants={itemVariants}
        className="text-3xl font-bold text-foreground mb-3"
      >
        Welcome to TestAI
      </motion.h1>

      {/* Subtitle */}
      <motion.p
        variants={itemVariants}
        className="text-lg text-muted-foreground mb-8 max-w-sm"
      >
        AI-powered web testing that thinks like a senior QA engineer
      </motion.p>

      {/* CTA */}
      <motion.div variants={itemVariants}>
        <Button
          onClick={onNext}
          size="lg"
          className="gap-2 px-8 bg-gradient-to-r from-violet-500 to-purple-600 hover:from-violet-600 hover:to-purple-700 shadow-soft-lg"
        >
          Get Started
          <ArrowRight className="w-4 h-4" />
        </Button>
      </motion.div>
    </motion.div>
  )
}

// Step 2: Meet Alex
function MeetAlexStep({ onNext }: { onNext: () => void }) {
  const features = [
    { icon: Bug, text: 'Finds bugs others miss' },
    { icon: Shield, text: 'Spots security issues' },
    { icon: Sparkles, text: 'Generates test cases' },
  ]

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="flex flex-col items-center text-center"
    >
      {/* Alex Avatar */}
      <motion.div
        variants={itemVariants}
        className="relative mb-6"
      >
        <motion.div
          className="w-20 h-20 bg-gradient-to-br from-violet-500 to-purple-600 rounded-full flex items-center justify-center shadow-soft-lg"
          animate={{ scale: [1, 1.05, 1] }}
          transition={{ duration: 3, repeat: Infinity }}
        >
          <Sparkles className="w-10 h-10 text-white" />
        </motion.div>

        {/* Status indicator */}
        <motion.div
          className="absolute -bottom-1 -right-1 w-6 h-6 bg-emerald-500 rounded-full border-4 border-background flex items-center justify-center"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.5, type: 'spring', stiffness: 500 }}
        >
          <Check className="w-3 h-3 text-white" />
        </motion.div>
      </motion.div>

      {/* Title */}
      <motion.h2
        variants={itemVariants}
        className="text-2xl font-bold text-foreground mb-1"
      >
        Meet Alex
      </motion.h2>

      <motion.p
        variants={itemVariants}
        className="text-muted-foreground mb-8"
      >
        Your AI QA Engineer
      </motion.p>

      {/* Features */}
      <motion.div
        variants={itemVariants}
        className="space-y-3 mb-8 w-full max-w-xs"
      >
        {features.map((feature, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 + i * 0.1, ...spring }}
            className="flex items-center gap-3 p-3 bg-secondary/50 rounded-xl border border-border/50"
          >
            <div className="w-10 h-10 bg-violet-500/10 rounded-lg flex items-center justify-center">
              <feature.icon className="w-5 h-5 text-violet-500" />
            </div>
            <span className="text-sm font-medium text-foreground">{feature.text}</span>
          </motion.div>
        ))}
      </motion.div>

      {/* CTA */}
      <motion.div variants={itemVariants}>
        <Button onClick={onNext} size="lg" className="gap-2 px-8">
          Continue
          <ArrowRight className="w-4 h-4" />
        </Button>
      </motion.div>
    </motion.div>
  )
}

// Step 3: How It Works
function HowItWorksStep({ onNext }: { onNext: () => void }) {
  const steps = [
    { icon: Globe, title: 'Enter URL', desc: 'Paste any website' },
    { icon: MessageCircle, title: 'Chat', desc: 'Tell Alex what to test' },
    { icon: Sparkles, title: 'Results', desc: 'Get instant insights' },
  ]

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="flex flex-col items-center text-center"
    >
      {/* Title */}
      <motion.h2
        variants={itemVariants}
        className="text-2xl font-bold text-foreground mb-2"
      >
        How It Works
      </motion.h2>

      <motion.p
        variants={itemVariants}
        className="text-muted-foreground mb-10"
      >
        Three simple steps to better testing
      </motion.p>

      {/* Steps */}
      <motion.div
        variants={itemVariants}
        className="flex items-start justify-center gap-4 mb-10 w-full"
      >
        {steps.map((s, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 + i * 0.15, ...spring }}
            className="flex flex-col items-center flex-1"
          >
            {/* Icon */}
            <motion.div
              className="relative mb-4"
              whileHover={{ scale: 1.1 }}
            >
              <div className="w-16 h-16 bg-gradient-to-br from-violet-500/20 to-purple-500/20 rounded-2xl flex items-center justify-center border border-violet-500/20">
                <s.icon className="w-7 h-7 text-violet-500" />
              </div>

              {/* Step number */}
              <div className="absolute -top-2 -right-2 w-6 h-6 bg-foreground text-background rounded-full flex items-center justify-center text-xs font-bold">
                {i + 1}
              </div>
            </motion.div>

            {/* Text */}
            <h3 className="text-sm font-semibold text-foreground mb-1">{s.title}</h3>
            <p className="text-xs text-muted-foreground">{s.desc}</p>

            {/* Connector line */}
            {i < steps.length - 1 && (
              <motion.div
                className="absolute top-8 left-1/2 w-full h-px bg-gradient-to-r from-transparent via-border to-transparent"
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                transition={{ delay: 0.6, duration: 0.5 }}
                style={{ transform: 'translateX(50%)' }}
              />
            )}
          </motion.div>
        ))}
      </motion.div>

      {/* CTA */}
      <motion.div variants={itemVariants}>
        <Button onClick={onNext} size="lg" className="gap-2 px-8">
          Continue
          <ArrowRight className="w-4 h-4" />
        </Button>
      </motion.div>
    </motion.div>
  )
}

// Step 4: Ready
function ReadyStep({ onNext }: { onNext: () => void }) {
  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="flex flex-col items-center text-center"
    >
      {/* Celebration animation */}
      <motion.div
        variants={itemVariants}
        className="relative mb-8"
      >
        {/* Main checkmark */}
        <motion.div
          className="w-24 h-24 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-full flex items-center justify-center shadow-soft-lg"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 300, damping: 20, delay: 0.2 }}
        >
          <motion.div
            initial={{ scale: 0, rotate: -45 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{ delay: 0.4, type: 'spring', stiffness: 400 }}
          >
            <Check className="w-12 h-12 text-white" strokeWidth={3} />
          </motion.div>
        </motion.div>

        {/* Sparkles around */}
        {[...Array(6)].map((_, i) => {
          const angle = (i / 6) * Math.PI * 2
          const radius = 60
          return (
            <motion.div
              key={i}
              className="absolute w-3 h-3"
              style={{
                top: '50%',
                left: '50%',
              }}
              initial={{ scale: 0, x: 0, y: 0 }}
              animate={{
                scale: [0, 1, 0],
                x: Math.cos(angle) * radius,
                y: Math.sin(angle) * radius,
              }}
              transition={{
                delay: 0.5 + i * 0.05,
                duration: 0.6,
              }}
            >
              <Sparkles className="w-3 h-3 text-amber-400" />
            </motion.div>
          )
        })}
      </motion.div>

      {/* Title */}
      <motion.h2
        variants={itemVariants}
        className="text-2xl font-bold text-foreground mb-2"
      >
        You're all set!
      </motion.h2>

      <motion.p
        variants={itemVariants}
        className="text-muted-foreground mb-8 max-w-xs"
      >
        Start by entering a URL in the toolbar above, then chat with Alex
      </motion.p>

      {/* Keyboard hint */}
      <motion.div
        variants={itemVariants}
        className="flex items-center gap-2 mb-8 text-sm text-muted-foreground"
      >
        <kbd className="px-2 py-1 bg-secondary rounded border border-border text-xs font-mono">⌘L</kbd>
        <span>to focus URL bar</span>
      </motion.div>

      {/* CTA */}
      <motion.div variants={itemVariants}>
        <Button
          onClick={onNext}
          size="lg"
          className="gap-2 px-8 bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 shadow-soft-lg"
        >
          Start Testing
          <Sparkles className="w-4 h-4" />
        </Button>
      </motion.div>
    </motion.div>
  )
}
