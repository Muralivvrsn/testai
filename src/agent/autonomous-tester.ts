/**
 * Autonomous Testing Agent
 *
 * Coordinates the entire autonomous testing flow:
 * 1. Extract DOM elements from the page
 * 2. Analyze the page and classify elements
 * 3. Decide what to test next (like a senior QA engineer)
 * 4. Execute tests and record results
 * 5. Generate human-readable test scripts
 */

import type {
  DomElement,
  TestScript,
  TestSession,
  PageAnalysis,
  TestError,
  TestCoverage
} from './types'
import { DeepSeekClient } from './deepseek-client'
import { ScriptGenerator } from './script-generator'

const QA_BRAIN_PROMPT = `You are a senior QA engineer with 15 years of experience. You think systematically and thoroughly.

Your testing philosophy:
1. Always start with the critical path (what users do most)
2. Then test edge cases that could break the system
3. Security is non-negotiable - always test for vulnerabilities
4. Test what happens when things go wrong
5. Performance matters - slow is broken

When analyzing a page, think:
- What is the primary purpose of this page?
- What are the most important user actions?
- What could go wrong?
- How can a malicious user break this?
- What happens with bad data?

When deciding what to test next, prioritize:
1. Untested critical elements (login, submit, payment)
2. Forms that haven't been validated
3. Error scenarios
4. Edge cases
5. Accessibility concerns`

interface TesterConfig {
  apiKey: string
  maxActionsPerPage?: number
  testTimeout?: number
}

interface TestingState {
  currentUrl: string
  currentPage: PageAnalysis | null
  testedElements: Set<string>
  visitedUrls: Set<string>
  actionQueue: QueuedAction[]
}

interface QueuedAction {
  elementId: string
  action: string
  priority: number
  reason: string
}

export class AutonomousTester {
  private client: DeepSeekClient
  private scriptGenerator: ScriptGenerator
  private state: TestingState
  private session: TestSession | null = null

  // Callbacks for Electron integration
  public onProgress?: (message: string) => void
  public onScriptGenerated?: (script: TestScript) => void
  public onError?: (error: TestError) => void
  public onComplete?: (session: TestSession) => void

  constructor(config: TesterConfig) {
    this.client = new DeepSeekClient({
      apiKey: config.apiKey,
      model: 'deepseek-chat',
      temperature: 0.2
    })
    this.scriptGenerator = new ScriptGenerator(this.client)
    this.state = this.createInitialState()
  }

  /**
   * Start autonomous testing session
   */
  async start(startUrl: string): Promise<TestSession> {
    this.session = this.createSession(startUrl)
    this.state = this.createInitialState()
    this.state.currentUrl = startUrl
    this.state.visitedUrls.add(startUrl)

    this.emit('progress', `Starting autonomous testing on ${startUrl}`)

    return this.session
  }

  /**
   * Process extracted DOM and decide next actions
   */
  async processPage(
    url: string,
    title: string,
    elements: DomElement[]
  ): Promise<{
    analysis: PageAnalysis
    scripts: TestScript[]
    nextActions: QueuedAction[]
  }> {
    if (!this.session) {
      throw new Error('No active session. Call start() first.')
    }

    this.emit('progress', `Analyzing page: ${title}`)
    this.state.currentUrl = url

    // Analyze the page
    const analysis = await this.scriptGenerator.analyzePage(url, title, elements)
    this.state.currentPage = analysis

    this.emit('progress', `Page type: ${analysis.pageType} (confidence: ${(analysis.confidence * 100).toFixed(0)}%)`)

    // Generate test scripts
    this.emit('progress', 'Generating test cases...')
    const scripts = await this.scriptGenerator.generateTests(url, title, elements)

    scripts.forEach(script => {
      this.session!.scripts.push(script)
      this.onScriptGenerated?.(script)
    })

    // Decide what to test next
    this.emit('progress', 'Deciding next test actions...')
    const nextActions = await this.decideNextActions(elements, analysis)
    this.state.actionQueue = nextActions

    // Update session stats
    this.session.testsGenerated += scripts.length
    if (!this.session.pagesVisited.includes(url)) {
      this.session.pagesVisited.push(url)
    }

    return { analysis, scripts, nextActions }
  }

  /**
   * AI decides what to test next based on QA expertise
   */
  async decideNextActions(
    elements: DomElement[],
    analysis: PageAnalysis
  ): Promise<QueuedAction[]> {
    const untestedElements = elements.filter(el => !this.state.testedElements.has(el.id))

    if (untestedElements.length === 0) {
      this.emit('progress', 'All elements have been tested')
      return []
    }

    const prompt = `Given this page analysis and untested elements, decide what to test next.

Page Type: ${analysis.pageType}
URL: ${analysis.url}

Untested Elements (${untestedElements.length}):
${JSON.stringify(untestedElements.slice(0, 20), null, 2)}

Already Tested: ${this.state.testedElements.size} elements
Visited URLs: ${this.state.visitedUrls.size}

Prioritize elements that:
1. Are critical for the page's main function
2. Could cause security issues
3. Handle user input
4. Navigate to new pages
5. Submit data

Return JSON:
{
  "actions": [
    {
      "elementId": "element id",
      "action": "click|type|select",
      "priority": 1-10,
      "reason": "why test this"
    }
  ],
  "reasoning": "Overall testing strategy explanation"
}`

    const response = await this.client.complete(
      [
        { role: 'system', content: QA_BRAIN_PROMPT },
        { role: 'user', content: prompt }
      ],
      { jsonMode: true, maxTokens: 2000 }
    )

    const parsed = this.client.parseJson<{
      actions: QueuedAction[]
      reasoning: string
    }>(response.content)

    if (parsed?.reasoning) {
      this.emit('progress', `Strategy: ${parsed.reasoning}`)
    }

    return (parsed?.actions || [])
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 10) // Limit to top 10 actions
  }

  /**
   * Mark an element as tested
   */
  markTested(elementId: string): void {
    this.state.testedElements.add(elementId)
    if (this.session) {
      this.session.elementsInteracted++
    }
  }

  /**
   * Record a test error
   */
  recordError(error: TestError): void {
    if (this.session) {
      this.session.errors.push(error)
    }
    this.onError?.(error)
  }

  /**
   * Get the next action to execute
   */
  getNextAction(): QueuedAction | null {
    return this.state.actionQueue.shift() || null
  }

  /**
   * Complete the testing session
   */
  complete(): TestSession | null {
    if (!this.session) return null

    this.session.status = 'completed'
    this.session.coverage = this.calculateCoverage()

    this.emit('progress', 'Testing session completed')
    this.onComplete?.(this.session)

    return this.session
  }

  /**
   * Get current session status
   */
  getSession(): TestSession | null {
    return this.session
  }

  /**
   * Get all generated scripts
   */
  getScripts(): TestScript[] {
    return this.session?.scripts || []
  }

  /**
   * Export scripts in human-readable format
   */
  exportReadableScripts(): string {
    const scripts = this.getScripts()
    return scripts.map(s => this.scriptGenerator.toHumanReadable(s)).join('\n\n---\n\n')
  }

  /**
   * Export scripts as Playwright tests
   */
  exportPlaywrightScripts(): string {
    const scripts = this.getScripts()
    return scripts.map(s => this.scriptGenerator.toPlaywright(s)).join('\n\n')
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private createInitialState(): TestingState {
    return {
      currentUrl: '',
      currentPage: null,
      testedElements: new Set(),
      visitedUrls: new Set(),
      actionQueue: []
    }
  }

  private createSession(startUrl: string): TestSession {
    return {
      id: `session-${Date.now()}`,
      startUrl,
      startedAt: new Date(),
      status: 'running',
      pagesVisited: [],
      elementsInteracted: 0,
      testsGenerated: 0,
      scripts: [],
      errors: [],
      coverage: {
        totalElements: 0,
        testedElements: 0,
        totalForms: 0,
        testedForms: 0,
        totalLinks: 0,
        testedLinks: 0
      }
    }
  }

  private calculateCoverage(): TestCoverage {
    const page = this.state.currentPage
    if (!page) {
      return {
        totalElements: 0,
        testedElements: this.state.testedElements.size,
        totalForms: 0,
        testedForms: 0,
        totalLinks: 0,
        testedLinks: 0
      }
    }

    const links = page.elements.filter(e => e.elementType === 'link')
    const forms = page.forms.length

    return {
      totalElements: page.elements.length,
      testedElements: this.state.testedElements.size,
      totalForms: forms,
      testedForms: Math.min(forms, this.session?.testsGenerated || 0),
      totalLinks: links.length,
      testedLinks: links.filter(l => this.state.testedElements.has(l.id)).length
    }
  }

  private emit(event: 'progress', message: string): void {
    if (event === 'progress' && this.onProgress) {
      this.onProgress(message)
    }
  }
}

export function createAutonomousTester(apiKey: string): AutonomousTester {
  return new AutonomousTester({ apiKey })
}
