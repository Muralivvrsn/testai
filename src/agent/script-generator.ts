/**
 * Human-Readable Test Script Generator
 *
 * Generates test scripts that:
 * 1. Are human-readable and understandable
 * 2. Can be converted to Playwright/Cypress
 * 3. Don't require AI to replay
 */

import type {
  TestScript,
  TestStep,
  DomElement,
  PageAnalysis,
  ClassifiedElement
} from './types'
import { DeepSeekClient } from './deepseek-client'

const SYSTEM_PROMPT = `You are a senior QA engineer. Your job is to analyze web pages and generate comprehensive test cases.

When generating tests, think like a senior QA engineer would:
1. Test happy paths first (main user flows)
2. Test edge cases (empty inputs, max length, special characters)
3. Test error handling (invalid inputs, network errors)
4. Test security (XSS, SQL injection attempts)
5. Test accessibility (keyboard navigation, screen readers)

Output Format:
Return a JSON object with this structure:
{
  "tests": [
    {
      "name": "Test name",
      "description": "What this test verifies",
      "priority": "high|medium|low",
      "steps": [
        {
          "action": "navigate|click|type|select|wait|assert",
          "target": "element description or selector",
          "value": "input value if applicable",
          "waitFor": "condition to wait for",
          "description": "Human readable step description"
        }
      ],
      "expectedResults": ["What should happen"]
    }
  ]
}

Important:
- Use human-readable descriptions, not CSS selectors
- Write steps that a human tester could follow
- Include wait conditions after actions that trigger page changes
- Be specific about expected results`

export class ScriptGenerator {
  private client: DeepSeekClient

  constructor(client: DeepSeekClient) {
    this.client = client
  }

  /**
   * Analyze a page and generate test cases
   */
  async generateTests(
    url: string,
    title: string,
    elements: DomElement[]
  ): Promise<TestScript[]> {
    // First, classify the page and elements
    const analysis = await this.analyzePage(url, title, elements)

    // Then generate test cases based on analysis
    const scripts = await this.generateTestScripts(analysis)

    return scripts
  }

  /**
   * Analyze the page to understand its purpose and key elements
   */
  async analyzePage(
    url: string,
    title: string,
    elements: DomElement[]
  ): Promise<PageAnalysis> {
    const elementsSummary = this.summarizeElements(elements)

    const prompt = `Analyze this web page:

URL: ${url}
Title: ${title}

Interactive Elements:
${elementsSummary}

Return JSON with:
{
  "pageType": "login|signup|dashboard|settings|checkout|search|list|detail|form|unknown",
  "confidence": 0.0-1.0,
  "purpose": "What this page is for",
  "keyElements": [
    {
      "id": "element id",
      "elementType": "navigation|button|input|link|form|dropdown|checkbox|submit|other",
      "priority": "high|medium|low",
      "testActions": ["click", "type", etc]
    }
  ],
  "forms": [
    {
      "name": "form name",
      "fields": ["field names"],
      "purpose": "what the form does"
    }
  ],
  "suggestedTests": ["List of test scenarios to cover"]
}`

    const response = await this.client.complete(
      [
        { role: 'system', content: 'You are a web page analyzer. Return valid JSON only.' },
        { role: 'user', content: prompt }
      ],
      { jsonMode: true, maxTokens: 2000 }
    )

    const parsed = this.client.parseJson<any>(response.content)

    if (!parsed) {
      return this.createDefaultAnalysis(url, title, elements)
    }

    return {
      url,
      title,
      pageType: parsed.pageType || 'unknown',
      confidence: parsed.confidence || 0.5,
      elements: this.mapClassifiedElements(elements, parsed.keyElements || []),
      forms: parsed.forms || [],
      suggestedTests: parsed.suggestedTests || []
    }
  }

  /**
   * Generate test scripts from page analysis
   */
  async generateTestScripts(analysis: PageAnalysis): Promise<TestScript[]> {
    const prompt = `Generate comprehensive test cases for this page:

Page Type: ${analysis.pageType}
URL: ${analysis.url}
Title: ${analysis.title}

Key Elements:
${JSON.stringify(analysis.elements.slice(0, 30), null, 2)}

Forms:
${JSON.stringify(analysis.forms, null, 2)}

Suggested Test Areas:
${analysis.suggestedTests.join('\n')}

Generate test cases covering:
1. Happy path (normal user flow)
2. Edge cases (boundaries, empty values)
3. Error handling (invalid inputs)
4. Form validation
5. Navigation flows

Return JSON with "tests" array as specified in the system prompt.`

    const response = await this.client.complete(
      [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: prompt }
      ],
      { jsonMode: true, maxTokens: 4000, temperature: 0.3 }
    )

    const parsed = this.client.parseJson<{ tests: any[] }>(response.content)

    if (!parsed?.tests) {
      return []
    }

    return parsed.tests.map((test, index) => this.normalizeTestScript(test, analysis, index))
  }

  /**
   * Convert test script to human-readable format
   */
  toHumanReadable(script: TestScript): string {
    const lines: string[] = [
      `# ${script.name}`,
      `## Description: ${script.description}`,
      `## URL: ${script.url}`,
      '',
      '## Steps:'
    ]

    script.steps.forEach((step, index) => {
      let stepLine = `${index + 1}. ${step.description}`

      // Add action details in a format that can be parsed
      const actionParts: string[] = []

      if (step.action === 'navigate') {
        actionParts.push(`navigate:${step.value}`)
      } else if (step.action === 'click') {
        actionParts.push(`click:${step.target}`)
      } else if (step.action === 'type') {
        actionParts.push(`type:${step.target}:"${step.value}"`)
      } else if (step.action === 'select') {
        actionParts.push(`select:${step.target}:"${step.value}"`)
      } else if (step.action === 'wait') {
        actionParts.push(`wait:${step.waitFor || step.value}`)
      } else if (step.action === 'assert') {
        actionParts.push(`assert:${step.target}:"${step.value}"`)
      }

      if (step.waitFor) {
        actionParts.push(`waitFor:${step.waitFor}`)
      }

      if (actionParts.length > 0) {
        lines.push(`   ${actionParts.join(', ')}`)
      }

      lines.push(stepLine)
    })

    lines.push('')
    lines.push('## Expected Results:')
    script.expectedResults.forEach((result, index) => {
      lines.push(`- ${result}`)
    })

    return lines.join('\n')
  }

  /**
   * Convert test script to Playwright code
   */
  toPlaywright(script: TestScript): string {
    const lines: string[] = [
      `import { test, expect } from '@playwright/test';`,
      '',
      `test('${script.name}', async ({ page }) => {`,
      `  // ${script.description}`,
      ''
    ]

    script.steps.forEach(step => {
      const indent = '  '

      switch (step.action) {
        case 'navigate':
          lines.push(`${indent}await page.goto('${step.value}');`)
          break
        case 'click':
          lines.push(`${indent}// ${step.description}`)
          lines.push(`${indent}await page.click('${this.toSelector(step.target)}');`)
          break
        case 'type':
          lines.push(`${indent}// ${step.description}`)
          lines.push(`${indent}await page.fill('${this.toSelector(step.target)}', '${step.value}');`)
          break
        case 'select':
          lines.push(`${indent}await page.selectOption('${this.toSelector(step.target)}', '${step.value}');`)
          break
        case 'wait':
          if (step.waitFor === 'load') {
            lines.push(`${indent}await page.waitForLoadState('networkidle');`)
          } else {
            lines.push(`${indent}await page.waitForTimeout(${step.value || 1000});`)
          }
          break
        case 'assert':
          lines.push(`${indent}await expect(page.locator('${this.toSelector(step.target)}')).toBeVisible();`)
          break
      }

      if (step.waitFor && step.action !== 'wait') {
        lines.push(`${indent}await page.waitForLoadState('networkidle');`)
      }
    })

    lines.push('});')
    return lines.join('\n')
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private summarizeElements(elements: DomElement[]): string {
    const grouped: Record<string, DomElement[]> = {}

    elements.forEach(el => {
      const key = el.tag
      if (!grouped[key]) grouped[key] = []
      grouped[key].push(el)
    })

    const lines: string[] = []
    Object.entries(grouped).forEach(([tag, els]) => {
      lines.push(`\n${tag.toUpperCase()} (${els.length}):`)
      els.slice(0, 10).forEach(el => {
        const desc = el.text || el.placeholder || el.name || el.href || 'unnamed'
        lines.push(`  - [${el.id}] ${desc.slice(0, 50)}${el.type ? ` (type: ${el.type})` : ''}`)
      })
      if (els.length > 10) {
        lines.push(`  ... and ${els.length - 10} more`)
      }
    })

    return lines.join('\n')
  }

  private mapClassifiedElements(
    elements: DomElement[],
    classified: any[]
  ): ClassifiedElement[] {
    const classMap = new Map(classified.map(c => [c.id, c]))

    return elements.map(el => {
      const classification = classMap.get(el.id)
      return {
        id: el.id,
        tag: el.tag,
        text: el.text || el.placeholder || el.name || '',
        elementType: classification?.elementType || this.guessElementType(el),
        priority: classification?.priority || 'medium',
        testActions: classification?.testActions || this.guessTestActions(el)
      }
    })
  }

  private guessElementType(el: DomElement): ClassifiedElement['elementType'] {
    if (el.tag === 'a') return 'link'
    if (el.tag === 'button') return 'button'
    if (el.tag === 'input') {
      if (el.type === 'submit') return 'submit'
      if (el.type === 'checkbox') return 'checkbox'
      return 'input'
    }
    if (el.tag === 'select') return 'dropdown'
    if (el.tag === 'form') return 'form'
    return 'other'
  }

  private guessTestActions(el: DomElement): string[] {
    if (el.tag === 'a') return ['click']
    if (el.tag === 'button') return ['click']
    if (el.tag === 'input') {
      if (el.type === 'submit') return ['click']
      if (el.type === 'checkbox') return ['check', 'uncheck']
      return ['type', 'click']
    }
    if (el.tag === 'select') return ['select']
    return ['click']
  }

  private createDefaultAnalysis(
    url: string,
    title: string,
    elements: DomElement[]
  ): PageAnalysis {
    return {
      url,
      title,
      pageType: 'unknown',
      confidence: 0.3,
      elements: elements.map(el => ({
        id: el.id,
        tag: el.tag,
        text: el.text || '',
        elementType: this.guessElementType(el),
        priority: 'medium' as const,
        testActions: this.guessTestActions(el)
      })),
      forms: [],
      suggestedTests: ['Basic navigation test', 'Element interaction test']
    }
  }

  private normalizeTestScript(test: any, analysis: PageAnalysis, index: number): TestScript {
    return {
      id: `test-${Date.now()}-${index}`,
      name: test.name || `Test ${index + 1}`,
      description: test.description || '',
      url: analysis.url,
      steps: (test.steps || []).map((step: any, stepIndex: number) => ({
        order: stepIndex + 1,
        action: step.action || 'click',
        target: step.target,
        value: step.value,
        waitFor: step.waitFor,
        description: step.description || `Step ${stepIndex + 1}`
      })),
      expectedResults: test.expectedResults || [],
      generatedAt: new Date()
    }
  }

  private toSelector(target?: string): string {
    if (!target) return ''

    // If it looks like a selector already, use it
    if (target.startsWith('#') || target.startsWith('.') || target.startsWith('[')) {
      return target
    }

    // Otherwise, create a text-based selector
    return `text=${target}`
  }
}

export function createScriptGenerator(client: DeepSeekClient): ScriptGenerator {
  return new ScriptGenerator(client)
}
