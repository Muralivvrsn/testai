import { memo, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CheckCircle2,
  Circle,
  AlertCircle,
  Clock,
  Loader2,
  ListTodo,
} from 'lucide-react'
import { cn } from '@/lib/cn'
import { ScrollArea } from './ui/scroll-area'
import type { TodoListData, TodoTask, TaskPriority } from '@/lib/types'

interface TodoPanelProps {
  data: TodoListData | null
  isRunning: boolean
  className?: string
}

// Priority colors and icons
const PRIORITY_CONFIG: Record<TaskPriority, { color: string; bg: string; label: string }> = {
  1: { color: 'text-red-500', bg: 'bg-red-500/10', label: 'CRITICAL' },
  2: { color: 'text-orange-500', bg: 'bg-orange-500/10', label: 'HIGH' },
  3: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', label: 'MEDIUM' },
  4: { color: 'text-green-500', bg: 'bg-green-500/10', label: 'LOW' },
  5: { color: 'text-blue-500', bg: 'bg-blue-500/10', label: 'DISCOVERY' },
}

// Status icons
function StatusIcon({ status, className }: { status: string; className?: string }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className={cn('w-4 h-4 text-emerald-500', className)} />
    case 'in_progress':
      return <Loader2 className={cn('w-4 h-4 text-[#4A5D6A] animate-spin', className)} />
    case 'failed':
      return <AlertCircle className={cn('w-4 h-4 text-red-500', className)} />
    case 'blocked':
      return <Clock className={cn('w-4 h-4 text-amber-500', className)} />
    default:
      return <Circle className={cn('w-4 h-4 text-[#4A5D6A]/40 dark:text-neutral-600', className)} />
  }
}

// Task item component
const TaskItem = memo(function TaskItem({ task, isActive }: { task: TodoTask; isActive?: boolean }) {
  const priority = PRIORITY_CONFIG[task.priority] || PRIORITY_CONFIG[3]

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 10 }}
      className={cn(
        'group flex items-start gap-3 p-3 rounded-xl transition-colors',
        isActive
          ? 'bg-[#4A5D6A]/10 dark:bg-[#4A5D6A]/5 border border-[#4A5D6A]/20'
          : 'hover:bg-[#4A5D6A]/5 dark:hover:bg-white/[0.02]'
      )}
    >
      <StatusIcon status={task.status} className="mt-0.5 shrink-0" />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={cn(
            'text-sm font-medium truncate',
            task.status === 'completed'
              ? 'text-[#4A5D6A]/50 dark:text-neutral-400 line-through'
              : 'text-[#2a3a42] dark:text-white'
          )}>
            {task.title}
          </span>
          {isActive && (
            <span className="shrink-0 text-[10px] font-semibold text-[#4A5D6A] bg-[#4A5D6A]/10 px-1.5 py-0.5 rounded-full">
              ACTIVE
            </span>
          )}
        </div>

        {/* Steps progress */}
        {task.steps && task.steps.length > 0 && (
          <div className="mt-1.5 flex items-center gap-2">
            <div className="flex gap-0.5">
              {task.steps.map((step, i) => (
                <div
                  key={i}
                  className={cn(
                    'w-1.5 h-1.5 rounded-full transition-colors',
                    step.status === 'completed' ? 'bg-emerald-500' :
                    step.status === 'in_progress' ? 'bg-[#4A5D6A] animate-pulse' :
                    step.status === 'failed' ? 'bg-red-500' :
                    'bg-[#4A5D6A]/20 dark:bg-neutral-700'
                  )}
                />
              ))}
            </div>
            <span className="text-[10px] text-[#4A5D6A]/60">
              {task.currentStepIndex !== undefined
                ? `Step ${task.currentStepIndex + 1}/${task.steps.length}`
                : `${task.steps.length} steps`}
            </span>
          </div>
        )}

        {/* Error message */}
        {task.error && (
          <p className="mt-1 text-xs text-red-500 truncate">{task.error}</p>
        )}

        {/* Duration */}
        {task.durationMs && task.status === 'completed' && (
          <span className="text-[10px] text-[#4A5D6A]/50">{task.durationMs}ms</span>
        )}
      </div>

      {/* Priority badge */}
      <span className={cn(
        'shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded-md',
        priority.bg,
        priority.color
      )}>
        {priority.label}
      </span>
    </motion.div>
  )
})

// Progress ring component
function ProgressRing({ progress, size = 48 }: { progress: number; size?: number }) {
  const strokeWidth = 3
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (progress / 100) * circumference

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-[#4A5D6A]/10 dark:text-neutral-800"
        />
        {/* Progress circle */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#4A5D6A"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          style={{
            strokeDasharray: circumference,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xs font-bold text-[#2a3a42] dark:text-white">
          {Math.round(progress)}%
        </span>
      </div>
    </div>
  )
}

export const TodoPanel = memo(function TodoPanel({ data, isRunning, className }: TodoPanelProps) {
  const summary = data?.summary

  // Calculate stats
  const stats = useMemo(() => {
    if (!summary) return null
    return {
      total: summary.total,
      done: summary.completed,
      failed: summary.failed,
      pending: summary.pending,
      progress: summary.progress,
    }
  }, [summary])

  if (!data && !isRunning) {
    return null
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className={cn(
        'flex flex-col h-full bg-white/90 dark:bg-neutral-900/80 backdrop-blur-xl',
        'border-l border-[#4A5D6A]/10 dark:border-white/[0.06]',
        className
      )}
    >
      {/* Header */}
      <div className="shrink-0 p-4 border-b border-[#4A5D6A]/10 dark:border-white/[0.06]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#4A5D6A] flex items-center justify-center">
              <ListTodo className="w-4 h-4 text-white" />
            </div>
            <div>
              <h3 className="font-display font-semibold text-sm text-[#2a3a42] dark:text-white">
                Test Queue
              </h3>
              {isRunning && (
                <p className="text-[10px] text-[#4A5D6A] font-medium flex items-center gap-1">
                  <motion.span
                    animate={{ opacity: [0.4, 1, 0.4] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    className="w-1.5 h-1.5 rounded-full bg-[#4A5D6A]"
                  />
                  Running...
                </p>
              )}
            </div>
          </div>

          {stats && <ProgressRing progress={stats.progress} />}
        </div>

        {/* Quick stats */}
        {stats && (
          <div className="mt-4 grid grid-cols-4 gap-2">
            {[
              { label: 'Total', value: stats.total, color: 'text-[#4A5D6A] dark:text-neutral-400' },
              { label: 'Done', value: stats.done, color: 'text-emerald-500' },
              { label: 'Pending', value: stats.pending, color: 'text-[#4A5D6A]' },
              { label: 'Failed', value: stats.failed, color: 'text-red-500' },
            ].map(stat => (
              <div key={stat.label} className="text-center">
                <p className={cn('text-lg font-bold', stat.color)}>{stat.value}</p>
                <p className="text-[9px] text-[#4A5D6A]/60 uppercase tracking-wide">{stat.label}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Task list */}
      <ScrollArea className="flex-1">
        <div className="p-3 space-y-1">
          {/* Current task */}
          {data?.currentTask && (
            <div className="mb-3">
              <p className="text-[10px] font-semibold text-[#4A5D6A] uppercase tracking-wider mb-2 px-1">
                Current Task
              </p>
              <TaskItem task={data.currentTask} isActive />
            </div>
          )}

          {/* Pending tasks */}
          {data?.pendingTasks && data.pendingTasks.length > 0 && (
            <div className="mb-3">
              <p className="text-[10px] font-semibold text-[#4A5D6A]/60 dark:text-neutral-400 uppercase tracking-wider mb-2 px-1">
                Pending ({data.pendingTasks.length})
              </p>
              <AnimatePresence mode="popLayout">
                {data.pendingTasks.slice(0, 5).map(task => (
                  <TaskItem key={task.id} task={task} />
                ))}
              </AnimatePresence>
              {data.pendingTasks.length > 5 && (
                <p className="text-xs text-[#4A5D6A]/40 text-center mt-2">
                  +{data.pendingTasks.length - 5} more
                </p>
              )}
            </div>
          )}

          {/* Completed tasks */}
          {data?.completedTasks && data.completedTasks.length > 0 && (
            <div className="mb-3">
              <p className="text-[10px] font-semibold text-emerald-500 uppercase tracking-wider mb-2 px-1">
                Completed ({data.completedTasks.length})
              </p>
              <AnimatePresence mode="popLayout">
                {data.completedTasks.slice(-3).map(task => (
                  <TaskItem key={task.id} task={task} />
                ))}
              </AnimatePresence>
            </div>
          )}

          {/* Failed tasks */}
          {data?.failedTasks && data.failedTasks.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-red-500 uppercase tracking-wider mb-2 px-1">
                Failed ({data.failedTasks.length})
              </p>
              <AnimatePresence mode="popLayout">
                {data.failedTasks.map(task => (
                  <TaskItem key={task.id} task={task} />
                ))}
              </AnimatePresence>
            </div>
          )}

          {/* Empty state */}
          {!data?.currentTask &&
           (!data?.pendingTasks || data.pendingTasks.length === 0) &&
           (!data?.completedTasks || data.completedTasks.length === 0) && (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-12 h-12 rounded-xl bg-[#4A5D6A]/5 dark:bg-white/[0.04] flex items-center justify-center mb-3">
                <ListTodo className="w-6 h-6 text-[#4A5D6A]/40" />
              </div>
              <p className="text-sm text-[#4A5D6A] dark:text-neutral-400">
                {isRunning ? 'Generating test plan...' : 'No tasks yet'}
              </p>
              <p className="text-xs text-[#4A5D6A]/50 mt-1">
                {isRunning ? 'AI is analyzing the page' : 'Start a test to see tasks here'}
              </p>
            </div>
          )}
        </div>
      </ScrollArea>
    </motion.div>
  )
})
