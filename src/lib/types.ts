export interface DomElement {
  id: string
  tag: string
  text: string
  type: string
  href: string
  name: string
  placeholder: string
  className: string
  bounds: {
    x: number
    y: number
    width: number
    height: number
  }
}

export interface Message {
  id: string
  content: string
  role: 'user' | 'assistant'
  timestamp: Date
  details?: string // Expandable details (shown on "Read more")
  type?: 'text' | 'script' | 'action' | 'error' | 'success' // Message type for styling
}

export type ViewportType = 'desktop' | 'laptop' | 'tablet' | 'mobile'

export interface ViewportSize {
  width: number
  height: number
  label: string
}

export const VIEWPORTS: Record<ViewportType, ViewportSize> = {
  desktop: { width: 0, height: 0, label: 'Desktop' },
  laptop: { width: 1366, height: 768, label: 'Laptop' },
  tablet: { width: 768, height: 1024, label: 'Tablet' },
  mobile: { width: 375, height: 812, label: 'Mobile' },
}

// QA Orchestrator TODO Types
export type TaskPriority = 1 | 2 | 3 | 4 | 5  // CRITICAL=1, HIGH=2, MEDIUM=3, LOW=4, DISCOVERY=5
export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped' | 'blocked'

export interface TodoTask {
  id: string
  title: string
  description?: string
  priority: TaskPriority
  status: TaskStatus
  steps?: TodoStep[]
  currentStepIndex?: number
  durationMs?: number
  error?: string
}

export interface TodoStep {
  stepNumber: number
  action: string
  target?: string
  description?: string
  status: TaskStatus
}

export interface TodoSummary {
  current: string | null
  currentStep: string | null
  pending: number
  completed: number
  failed: number
  total: number
  progress: number
}

export interface TodoListData {
  summary: TodoSummary
  currentTask?: TodoTask | null
  pendingTasks: TodoTask[]
  completedTasks: TodoTask[]
  failedTasks: TodoTask[]
}
