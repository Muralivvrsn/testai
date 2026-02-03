import { memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { RefreshCw, Link, Square, Type, Box, Layers, Scan } from 'lucide-react'
import { cn } from '@/lib/cn'
import { Button } from './ui/button'
import { ScrollArea } from './ui/scroll-area'
import { Badge } from './ui/badge'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from './ui/accordion'
import type { DomElement } from '@/lib/types'

interface SidebarProps {
  open: boolean
  elements: DomElement[]
  isExtracting: boolean
  onExtract: () => void
  selectedElement: string | null
  onSelectElement: (id: string | null) => void
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

  // Parent handles slide animation, this just renders content
  return (
    <aside className="h-full w-full bg-white/95 dark:bg-[#111113]/95 backdrop-blur-2xl border-r border-[#4A5D6A]/10 dark:border-white/[0.06] flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#4A5D6A]/10 dark:border-white/[0.06]">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-[#4A5D6A]/5 dark:bg-white/[0.06] flex items-center justify-center">
                <Layers className="w-5 h-5 text-[#4A5D6A] dark:text-white/60" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-[#2a3a42] dark:text-white">Elements</h2>
                <p className="text-xs text-[#4A5D6A] dark:text-white/40">DOM Inspector</p>
              </div>
            </div>
            <Badge variant="secondary" className="font-mono text-[11px] bg-[#4A5D6A]/5 dark:bg-white/[0.06] text-[#4A5D6A]">
              {elements.length}
            </Badge>
          </div>

          {/* Content */}
          <ScrollArea className="flex-1">
            <div className="p-4">
              {/* Extract Button */}
              <Button
                onClick={onExtract}
                disabled={isExtracting}
                className={cn(
                  'w-full mb-5 h-11 gap-2.5 font-medium rounded-xl transition-all duration-200',
                  isExtracting
                    ? 'bg-[#4A5D6A] text-white'
                    : 'bg-[#f8f9f6] dark:bg-white/[0.04] hover:bg-[#4A5D6A]/10 dark:hover:bg-white/[0.08] text-[#4A5D6A] dark:text-white/80'
                )}
              >
                {isExtracting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Scanning page...
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4" />
                    Scan DOM Elements
                  </>
                )}
              </Button>

              {/* Element Tree */}
              <AnimatePresence mode="wait">
                {elements.length > 0 ? (
                  <motion.div
                    key="tree"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Accordion type="multiple" defaultValue={['links', 'buttons', 'inputs']} className="space-y-2">
                      <TreeSection
                        value="links"
                        label="Links"
                        icon={Link}
                        items={groups.links}
                        selectedId={selectedElement}
                        onSelect={onSelectElement}
                        color="blue"
                      />
                      <TreeSection
                        value="buttons"
                        label="Buttons"
                        icon={Square}
                        items={groups.buttons}
                        selectedId={selectedElement}
                        onSelect={onSelectElement}
                        color="purple"
                      />
                      <TreeSection
                        value="inputs"
                        label="Inputs"
                        icon={Type}
                        items={groups.inputs}
                        selectedId={selectedElement}
                        onSelect={onSelectElement}
                        color="emerald"
                      />
                      <TreeSection
                        value="other"
                        label="Other"
                        icon={Box}
                        items={groups.other}
                        selectedId={selectedElement}
                        onSelect={onSelectElement}
                        color="neutral"
                      />
                    </Accordion>
                  </motion.div>
                ) : (
                  <motion.div
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="flex flex-col items-center justify-center py-16 text-center"
                  >
                    <div className="w-16 h-16 bg-[#4A5D6A]/5 dark:bg-white/[0.04] rounded-2xl flex items-center justify-center mb-5">
                      <Box className="w-8 h-8 text-[#4A5D6A]/40 dark:text-white/30" />
                    </div>
                    <p className="text-sm font-medium text-[#4A5D6A] dark:text-white/50 mb-1">
                      No elements found
                    </p>
                    <p className="text-xs text-[#4A5D6A]/60 dark:text-white/30 leading-relaxed max-w-[200px]">
                      Load a page and click "Scan DOM Elements" to inspect
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </aside>
  )
})

// Calm, unified slate color palette
const colorMap = {
  blue: {
    bg: 'bg-[#4A5D6A]/5 dark:bg-[#4A5D6A]/10',
    text: 'text-[#4A5D6A] dark:text-white/60',
    border: 'border-[#4A5D6A]/10 dark:border-[#4A5D6A]/20',
  },
  purple: {
    bg: 'bg-[#4A5D6A]/8 dark:bg-[#4A5D6A]/12',
    text: 'text-[#3a4d5a] dark:text-white/70',
    border: 'border-[#4A5D6A]/15 dark:border-[#4A5D6A]/20',
  },
  emerald: {
    bg: 'bg-emerald-50 dark:bg-emerald-500/10',
    text: 'text-emerald-600 dark:text-emerald-400',
    border: 'border-emerald-200/50 dark:border-emerald-500/20',
  },
  neutral: {
    bg: 'bg-[#4A5D6A]/[0.03] dark:bg-white/[0.04]',
    text: 'text-[#4A5D6A]/70 dark:text-white/60',
    border: 'border-[#4A5D6A]/10 dark:border-white/[0.06]',
  },
}

const TreeSection = memo(function TreeSection({
  value,
  label,
  icon: Icon,
  items,
  selectedId,
  onSelect,
  color,
}: {
  value: string
  label: string
  icon: typeof Link
  items: DomElement[]
  selectedId: string | null
  onSelect: (id: string | null) => void
  color: keyof typeof colorMap
}) {
  if (items.length === 0) return null

  const colors = colorMap[color]

  return (
    <AccordionItem value={value} className="border-0 bg-[#f8f9f6]/80 dark:bg-white/[0.02] rounded-xl overflow-hidden">
      <AccordionTrigger className="px-4 py-3 hover:no-underline hover:bg-[#4A5D6A]/5 dark:hover:bg-white/[0.04] rounded-xl data-[state=open]:rounded-b-none">
        <div className="flex items-center gap-3 flex-1">
          <div className={cn('w-8 h-8 rounded-lg flex items-center justify-center', colors.bg)}>
            <Icon className={cn('w-4 h-4', colors.text)} />
          </div>
          <span className="text-sm font-semibold text-[#2a3a42] dark:text-white/90">
            {label}
          </span>
          <Badge variant="secondary" className="ml-auto text-[10px] font-mono bg-[#4A5D6A]/5 dark:bg-white/[0.06] text-[#4A5D6A]">
            {items.length}
          </Badge>
        </div>
      </AccordionTrigger>
      <AccordionContent className="pb-2 pt-0 px-2">
        <div className="space-y-1">
          {items.slice(0, 20).map((item, index) => (
            <motion.button
              key={item.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.02 }}
              onClick={() => onSelect(selectedId === item.id ? null : item.id)}
              className={cn(
                'w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-all duration-150',
                selectedId === item.id
                  ? cn('border', colors.bg, colors.border)
                  : 'hover:bg-[#4A5D6A]/5 dark:hover:bg-white/[0.04]'
              )}
            >
              <Badge
                variant="outline"
                className={cn(
                  'px-1.5 py-0 text-[10px] font-mono shrink-0',
                  selectedId === item.id && colors.text
                )}
              >
                {item.tag}
              </Badge>
              <span className={cn(
                'flex-1 text-xs truncate',
                selectedId === item.id
                  ? 'text-[#2a3a42] dark:text-white font-medium'
                  : 'text-[#4A5D6A] dark:text-white/60'
              )}>
                {item.text || item.placeholder || item.href || item.name || 'Element'}
              </span>
            </motion.button>
          ))}
          {items.length > 20 && (
            <div className="px-3 py-2 text-xs text-[#4A5D6A]/50 dark:text-white/30 italic">
              +{items.length - 20} more elements
            </div>
          )}
        </div>
      </AccordionContent>
    </AccordionItem>
  )
})
