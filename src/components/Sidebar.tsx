import { useState, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RefreshCw, ChevronRight, Link, Square, Type, Box } from 'lucide-react'
import { cn } from '../lib/cn'
import type { DomElement } from '../lib/types'

interface SidebarProps {
  open: boolean
  elements: DomElement[]
  isExtracting: boolean
  onExtract: () => void
  selectedElement: string | null
  onSelectElement: (id: string | null) => void
}

// Smooth spring config - same as App.tsx
const smoothSpring = {
  type: 'spring' as const,
  stiffness: 400,
  damping: 40,
  mass: 1,
}

export const Sidebar = memo(function Sidebar({
  open,
  elements,
  isExtracting,
  onExtract,
  selectedElement,
  onSelectElement,
}: SidebarProps) {
  // Group elements by type
  const groups = {
    links: elements.filter(e => e.tag === 'a'),
    buttons: elements.filter(e => e.tag === 'button' || e.type === 'submit'),
    inputs: elements.filter(e => ['input', 'textarea', 'select'].includes(e.tag) && e.type !== 'submit'),
    other: elements.filter(e => !['a', 'button', 'input', 'textarea', 'select'].includes(e.tag)),
  }

  return (
    <AnimatePresence mode="wait">
      {open && (
        <motion.aside
          initial={{ x: -280, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: -280, opacity: 0 }}
          transition={smoothSpring}
          className="fixed top-[52px] left-0 bottom-0 w-[280px] bg-white border-r border-neutral-200 flex flex-col z-40 will-change-transform contain-layout"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-100">
            <span className="text-xs font-semibold text-neutral-500 uppercase tracking-wide">
              DOM Elements
            </span>
            <motion.span
              key={elements.length}
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="px-2 py-0.5 bg-neutral-100 rounded-full text-xs font-medium text-neutral-600"
            >
              {elements.length}
            </motion.span>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-3">
            {/* Extract Button */}
            <motion.button
              onClick={onExtract}
              disabled={isExtracting}
              className="w-full p-3 mb-4 border border-dashed border-neutral-300 rounded-lg bg-neutral-50 text-neutral-600 text-sm font-medium flex items-center justify-center gap-2 transition-colors hover:bg-neutral-100 hover:border-neutral-400 disabled:opacity-50"
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.98 }}
            >
              <RefreshCw className={cn('w-4 h-4', isExtracting && 'animate-spin')} />
              {isExtracting ? 'Extracting...' : 'Extract DOM'}
            </motion.button>

            {/* Element Tree */}
            <AnimatePresence mode="wait">
              {elements.length > 0 ? (
                <motion.div
                  key="tree"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-2"
                >
                  <TreeSection
                    label="Links"
                    icon={Link}
                    items={groups.links}
                    selectedId={selectedElement}
                    onSelect={onSelectElement}
                  />
                  <TreeSection
                    label="Buttons"
                    icon={Square}
                    items={groups.buttons}
                    selectedId={selectedElement}
                    onSelect={onSelectElement}
                  />
                  <TreeSection
                    label="Inputs"
                    icon={Type}
                    items={groups.inputs}
                    selectedId={selectedElement}
                    onSelect={onSelectElement}
                  />
                  <TreeSection
                    label="Other"
                    icon={Box}
                    items={groups.other}
                    selectedId={selectedElement}
                    onSelect={onSelectElement}
                  />
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center py-12 text-center"
                >
                  <div className="w-12 h-12 bg-neutral-100 rounded-xl flex items-center justify-center mb-3">
                    <Box className="w-6 h-6 text-neutral-400" />
                  </div>
                  <p className="text-sm text-neutral-500">
                    Load a page and extract DOM
                    <br />
                    to see elements here
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
})

const TreeSection = memo(function TreeSection({
  label,
  icon: Icon,
  items,
  selectedId,
  onSelect,
}: {
  label: string
  icon: typeof Link
  items: DomElement[]
  selectedId: string | null
  onSelect: (id: string | null) => void
}) {
  const [expanded, setExpanded] = useState(true)

  if (items.length === 0) return null

  return (
    <div className="rounded-lg overflow-hidden">
      {/* Section Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 bg-neutral-50 hover:bg-neutral-100 transition-colors duration-150 rounded-lg"
      >
        <motion.div
          animate={{ rotate: expanded ? 90 : 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 25 }}
        >
          <ChevronRight className="w-4 h-4 text-neutral-400" />
        </motion.div>
        <Icon className="w-4 h-4 text-neutral-500" />
        <span className="flex-1 text-left text-sm font-medium text-neutral-700">
          {label}
        </span>
        <span className="text-xs font-mono text-neutral-400">{items.length}</span>
      </button>

      {/* Items */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 500, damping: 40 }}
            className="overflow-hidden"
          >
            <div className="pl-5 py-1">
              {items.slice(0, 20).map((item, index) => (
                <motion.button
                  key={item.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.02 }}
                  onClick={() => onSelect(selectedId === item.id ? null : item.id)}
                  className={cn(
                    'w-full flex items-center gap-2 px-3 py-2 rounded-md text-left transition-colors duration-150',
                    selectedId === item.id
                      ? 'bg-neutral-900/5 text-neutral-900'
                      : 'hover:bg-neutral-50 text-neutral-600'
                  )}
                  whileTap={{ scale: 0.98 }}
                >
                  <span className="px-1.5 py-0.5 bg-neutral-100 rounded text-[10px] font-mono font-medium text-neutral-500">
                    {item.tag}
                  </span>
                  <span className="flex-1 text-xs truncate">
                    {item.text || item.placeholder || item.href || item.name || 'Element'}
                  </span>
                </motion.button>
              ))}
              {items.length > 20 && (
                <div className="px-3 py-2 text-xs text-neutral-400 italic">
                  +{items.length - 20} more elements
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
})
