/**
 * TestAI Agent Types
 * Core type definitions for the autonomous testing agent
 */

// ============================================================================
// DOM Element Types (from Electron extraction)
// ============================================================================

export interface DomElement {
  id: string
  tag: string
  text: string
  type: string
  href: string
  name: string
  placeholder: string
  bounds: {
    x: number
    y: number
    width: number
    height: number
  }
}

// ============================================================================
// Test Script Types (Human-Readable Format)
// ============================================================================

export interface TestScript {
  id: string
  name: string
  description: string
  url: string
  steps: TestStep[]
  expectedResults: string[]
  generatedAt: Date
}

export interface TestStep {
  order: number
  action: TestAction
  target?: string       // Element selector or description
  value?: string        // Input value
  waitFor?: string      // Wait condition
  description: string   // Human-readable description
}

export type TestAction =
  | 'navigate'
  | 'click'
  | 'type'
  | 'select'
  | 'check'
  | 'uncheck'
  | 'wait'
  | 'assert'
  | 'scroll'
  | 'hover'

// ============================================================================
// Page Analysis Types
// ============================================================================

export interface PageAnalysis {
  url: string
  title: string
  pageType: PageType
  confidence: number
  elements: ClassifiedElement[]
  forms: FormInfo[]
  suggestedTests: string[]
}

export type PageType =
  | 'login'
  | 'signup'
  | 'dashboard'
  | 'settings'
  | 'checkout'
  | 'search'
  | 'list'
  | 'detail'
  | 'form'
  | 'unknown'

export interface ClassifiedElement {
  id: string
  tag: string
  text: string
  elementType: ElementType
  priority: 'high' | 'medium' | 'low'
  testActions: TestAction[]
}

export type ElementType =
  | 'navigation'
  | 'button'
  | 'input'
  | 'link'
  | 'form'
  | 'dropdown'
  | 'checkbox'
  | 'submit'
  | 'other'

export interface FormInfo {
  id: string
  name: string
  fields: FormField[]
  submitButton?: string
}

export interface FormField {
  id: string
  name: string
  type: string
  label: string
  required: boolean
  placeholder: string
}

// ============================================================================
// Autonomous Testing Types
// ============================================================================

export interface TestSession {
  id: string
  startUrl: string
  startedAt: Date
  status: 'running' | 'paused' | 'completed' | 'error'

  // Progress
  pagesVisited: string[]
  elementsInteracted: number
  testsGenerated: number

  // Results
  scripts: TestScript[]
  errors: TestError[]
  coverage: TestCoverage
}

export interface TestError {
  timestamp: Date
  action: string
  element?: string
  message: string
  recoverable: boolean
}

export interface TestCoverage {
  totalElements: number
  testedElements: number
  totalForms: number
  testedForms: number
  totalLinks: number
  testedLinks: number
}

// ============================================================================
// Agent Message Types
// ============================================================================

export interface AgentMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface AgentResponse {
  content: string
  usage?: {
    inputTokens: number
    outputTokens: number
    totalTokens: number
  }
  model?: string
}
