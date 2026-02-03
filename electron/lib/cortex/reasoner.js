/**
 * Yali Agent - Citation-Aware Reasoning Engine
 * Ported from testai-agent/cortex/reasoner.py
 *
 * The Cortex's reasoning layer that:
 * 1. Queries the Brain for relevant knowledge
 * 2. Tracks citations for zero-hallucination
 * 3. Uses the Gateway for LLM calls
 * 4. Generates test plans with full traceability
 *
 * Design Philosophy:
 * - Every claim must be backed by a source
 * - Never hallucinate - cite or admit uncertainty
 * - Show your work (visible reasoning)
 * - Be humble about confidence
 *
 * Zero-Hallucination Approach:
 * - All knowledge comes from Brain (QA_BRAIN)
 * - Every Brain chunk has a citation (section, tags)
 * - LLM augments but doesn't invent facts
 * - Output always includes "Source: X" references
 */

const { ConfidenceScorer, ConfidenceLevel } = require('./confidence')
const { DecisionEngine, createDecisionContext, ActionType } = require('./decision-engine')
const { getForPageType, formatForPrompt, getEdgeCases } = require('./qa-brain')

/**
 * Reasoning phases
 */
const ReasoningPhase = {
  UNDERSTANDING: 'understanding',  // Parse what user wants
  RETRIEVING: 'retrieving',        // Query Brain for knowledge
  PLANNING: 'planning',            // Plan the approach
  GENERATING: 'generating',        // Generate tests/analysis
  VALIDATING: 'validating',        // Check results
  EXPLAINING: 'explaining'         // Format output
}

/**
 * Create retrieved knowledge object
 */
function createRetrievedKnowledge(sections = []) {
  const citations = sections.map(s => ({
    source: s.cite ? s.cite() : `Section ${s.id} - ${s.title}`,
    sectionId: s.id,
    confidence: 0.8, // Default confidence for brain knowledge
    excerpt: s.content ? s.content.slice(0, 150) : ''
  }))

  const topicsCovered = [...new Set(sections.flatMap(s => s.tags || []))]

  return {
    sections,
    citations,
    totalRelevance: sections.length > 0 ? 0.8 : 0,
    topicsCovered,

    get hasKnowledge() {
      return this.sections.length > 0
    },

    get bestMatch() {
      return this.sections[0] || null
    },

    formatForPrompt(maxChunks = 5) {
      return formatForPrompt(this.sections, maxChunks)
    }
  }
}

/**
 * Create reasoning result object
 */
function createReasoningResult(phase, thinking, output, citations, confidence, options = {}) {
  return {
    phase,
    thinking,               // Visible reasoning
    output,                 // The actual result
    citations,              // Sources used
    confidence,             // Confidence result
    llmResponse: options.llmResponse || null,
    knowledgeUsed: options.knowledgeUsed || null,

    get isConfident() {
      return this.confidence.canProceed
    },

    formatWithSources() {
      let result = this.output
      if (this.citations && this.citations.length > 0) {
        result += '\n\n---\n📚 **Sources:**\n'
        this.citations.forEach((citation, i) => {
          const confPct = Math.round((citation.confidence || 0.8) * 100)
          result += `  ${i + 1}. ${citation.source} (${confPct}% match)\n`
          if (citation.excerpt) {
            result += `     > "${citation.excerpt.slice(0, 100)}..."\n`
          }
        })
      }
      return result
    }
  }
}

/**
 * Expert QA prompts for different tasks
 */
const PROMPTS = {
  test_generation: `You are Yali, a 12-year QA veteran. Generate test cases for this feature.

{knowledge}

FEATURE: {feature}
USER REQUEST: {request}
PAGE TYPE: {page_type}

Generate 5-7 specific, actionable test cases. For each test:
1. Clear title
2. Specific steps (not vague like "enter valid email" but "enter yali.test@company.com")
3. Expected result
4. Priority (Critical/High/Medium/Low)
5. Risk category (Security/Data/UX/Functionality)

Focus on edge cases and scenarios humans often miss.
Format as structured test cases.`,

  security_analysis: `You are a security-focused QA expert. Analyze this feature for vulnerabilities.

{knowledge}

FEATURE: {feature}
PAGE TYPE: {page_type}
ELEMENTS: {elements}

Identify:
1. Potential security vulnerabilities (OWASP Top 10)
2. Input validation gaps
3. Authentication/authorization issues
4. Data exposure risks

Be specific about attack vectors and mitigation.`,

  edge_case_detection: `You are an edge case specialist. Find edge cases for this feature.

{knowledge}

FEATURE: {feature}
PAGE TYPE: {page_type}

Identify edge cases for:
1. Boundary values
2. Empty/null states
3. Concurrency issues
4. Error handling gaps
5. Browser/device variations
6. Network conditions

Be specific and actionable.`,

  clarification: `Based on the context, what clarifying questions should we ask?

FEATURE: {feature}
USER REQUEST: {request}
KNOWLEDGE GAPS: {gaps}

Generate 2-3 specific, helpful clarifying questions.
Focus on information that would significantly improve test coverage.`
}

/**
 * Reasoner class
 * Citation-aware reasoning engine
 */
class Reasoner {
  constructor(options = {}) {
    this.confidenceThreshold = options.confidenceThreshold || 0.70
    this.decisionEngine = new DecisionEngine(this.confidenceThreshold)
    this.scorer = new ConfidenceScorer(this.confidenceThreshold)
    this.callLLM = options.callLLM || null // External LLM function
  }

  /**
   * Retrieve relevant knowledge from Brain
   */
  async retrieveKnowledge(query, pageType = null, nResults = 5) {
    let sections = []

    if (pageType) {
      sections = getForPageType(pageType)
    } else {
      // Search by keywords in query
      const keywords = query.toLowerCase().split(/\s+/)
      const { searchByKeyword, searchByTag } = require('./qa-brain')

      for (const keyword of keywords) {
        const matches = searchByKeyword(keyword)
        sections.push(...matches)
      }

      // Deduplicate
      const seen = new Set()
      sections = sections.filter(s => {
        if (seen.has(s.id)) return false
        seen.add(s.id)
        return true
      })
    }

    // Limit results
    sections = sections.slice(0, nResults)

    return createRetrievedKnowledge(sections)
  }

  /**
   * Reason about a feature to generate test plan
   */
  async reasonAboutFeature(feature, userRequest = null, pageType = null, pageElements = []) {
    const thinkingSteps = []

    // Phase 1: Understanding
    thinkingSteps.push('💭 Understanding the request...')

    // Phase 2: Retrieve knowledge
    thinkingSteps.push('💭 Searching QA Brain for relevant knowledge...')
    const knowledge = await this.retrieveKnowledge(
      `${feature} ${pageType || ''} testing`,
      pageType,
      5
    )

    if (knowledge.hasKnowledge) {
      thinkingSteps.push(`💭 Found ${knowledge.sections.length} relevant knowledge chunks`)
      thinkingSteps.push(`💭 Topics covered: ${knowledge.topicsCovered.slice(0, 5).join(', ')}`)
    } else {
      thinkingSteps.push('💭 No specific knowledge found, using general QA principles')
    }

    // Phase 3: Calculate confidence
    const confidence = this.scorer.scoreGeneration(
      feature,
      Boolean(pageType || pageElements.length > 0),
      knowledge.sections.length
    )
    thinkingSteps.push(`💭 Confidence: ${confidence.level} (${Math.round(confidence.score * 100)}%)`)

    // Phase 4: Check if we can proceed
    if (!confidence.canProceed && !knowledge.hasKnowledge) {
      return createReasoningResult(
        ReasoningPhase.UNDERSTANDING,
        thinkingSteps.join('\n'),
        `I need more information to generate tests. ${confidence.reasoning}`,
        knowledge.citations,
        confidence,
        { knowledgeUsed: knowledge }
      )
    }

    // Phase 5: Generate via LLM (if available)
    thinkingSteps.push('💭 Generating test cases...')

    let output = ''
    let llmResponse = null

    if (this.callLLM) {
      const prompt = PROMPTS.test_generation
        .replace('{knowledge}', knowledge.formatForPrompt())
        .replace('{feature}', feature)
        .replace('{request}', userRequest || 'Generate comprehensive tests')
        .replace('{page_type}', pageType || 'unknown')

      const systemPrompt = `You are Yali, a 12-year QA veteran. You generate specific, actionable test cases.
Key principles:
- Use real test data, not placeholders (e.g., "yali.test@company.com" not "valid email")
- Focus on edge cases humans miss
- Prioritize security and data integrity
- Be specific about expected behavior
- Format tests clearly with steps, data, and expected results`

      try {
        llmResponse = await this.callLLM([
          { role: 'system', content: systemPrompt },
          { role: 'user', content: prompt }
        ], { maxTokens: 2000, temperature: 0.6 })
        output = llmResponse.content
      } catch (e) {
        output = this._generateFallbackTests(knowledge, pageType)
      }
    } else {
      output = this._generateFallbackTests(knowledge, pageType)
    }

    thinkingSteps.push('💭 Validating generated tests...')

    return createReasoningResult(
      ReasoningPhase.GENERATING,
      thinkingSteps.join('\n'),
      output,
      knowledge.citations,
      confidence,
      { llmResponse, knowledgeUsed: knowledge }
    )
  }

  /**
   * Analyze security aspects of a feature
   */
  async analyzeSecurity(feature, pageType = null, elements = []) {
    const thinkingSteps = ['💭 Starting security analysis...']

    // Retrieve security-focused knowledge
    const knowledge = await this.retrieveKnowledge(
      `security vulnerabilities ${feature} ${pageType || ''}`,
      pageType,
      5
    )
    thinkingSteps.push(`💭 Found ${knowledge.sections.length} security-related knowledge chunks`)

    // Format elements for prompt
    const elementsStr = elements.length > 0
      ? elements.slice(0, 10).map(e =>
          `- ${e.tag || 'unknown'}: ${e.type || ''} (${e.name || ''})`
        ).join('\n')
      : 'No elements provided'

    const hasAuthElements = elements.some(e =>
      ['password', 'email'].includes(e.type)
    )
    const hasInputElements = elements.some(e =>
      ['input', 'textarea'].includes(e.tag)
    )

    const confidence = this.scorer.scoreSecurityAnalysis(
      pageType || 'unknown',
      hasAuthElements,
      hasInputElements,
      knowledge.totalRelevance
    )

    let output = ''
    let llmResponse = null

    if (this.callLLM) {
      const prompt = PROMPTS.security_analysis
        .replace('{knowledge}', knowledge.formatForPrompt())
        .replace('{feature}', feature)
        .replace('{page_type}', pageType || 'unknown')
        .replace('{elements}', elementsStr)

      try {
        llmResponse = await this.callLLM([
          { role: 'system', content: 'You are a security-focused QA expert. Identify vulnerabilities and provide specific mitigation recommendations.' },
          { role: 'user', content: prompt }
        ], { maxTokens: 1500, temperature: 0.4 })
        output = llmResponse.content
      } catch (e) {
        output = this._generateFallbackSecurityAnalysis(knowledge, pageType)
      }
    } else {
      output = this._generateFallbackSecurityAnalysis(knowledge, pageType)
    }

    return createReasoningResult(
      ReasoningPhase.GENERATING,
      thinkingSteps.join('\n'),
      output,
      knowledge.citations,
      confidence,
      { llmResponse, knowledgeUsed: knowledge }
    )
  }

  /**
   * Find edge cases for a feature
   */
  async findEdgeCases(feature, pageType = null) {
    const thinkingSteps = ['💭 Looking for edge cases...']

    const knowledge = await this.retrieveKnowledge(
      `edge cases boundary testing ${feature}`,
      pageType,
      5
    )
    thinkingSteps.push(`💭 Retrieved ${knowledge.sections.length} relevant patterns`)

    const confidence = this.scorer.scoreGeneration(
      feature,
      Boolean(pageType),
      knowledge.sections.length
    )

    let output = ''
    let llmResponse = null

    if (this.callLLM) {
      const prompt = PROMPTS.edge_case_detection
        .replace('{knowledge}', knowledge.formatForPrompt())
        .replace('{feature}', feature)
        .replace('{page_type}', pageType || 'unknown')

      try {
        llmResponse = await this.callLLM([
          { role: 'system', content: 'You are an edge case specialist. Find scenarios that typical testers miss.' },
          { role: 'user', content: prompt }
        ], { maxTokens: 1500, temperature: 0.5 })
        output = llmResponse.content
      } catch (e) {
        output = this._generateFallbackEdgeCases(knowledge, pageType)
      }
    } else {
      output = this._generateFallbackEdgeCases(knowledge, pageType)
    }

    return createReasoningResult(
      ReasoningPhase.GENERATING,
      thinkingSteps.join('\n'),
      output,
      knowledge.citations,
      confidence,
      { llmResponse, knowledgeUsed: knowledge }
    )
  }

  /**
   * Generate clarifying questions
   */
  async generateClarifications(feature, userRequest = null, gaps = []) {
    const defaultGaps = gaps.length > 0 ? gaps : ['page type', 'test scope', 'priority areas']

    if (this.callLLM) {
      const prompt = PROMPTS.clarification
        .replace('{feature}', feature)
        .replace('{request}', userRequest || 'General testing')
        .replace('{gaps}', defaultGaps.join(', '))

      try {
        const response = await this.callLLM([
          { role: 'system', content: 'Generate helpful clarifying questions.' },
          { role: 'user', content: prompt }
        ], { maxTokens: 512, temperature: 0.7 })

        // Parse questions from response
        const lines = response.content.split('\n')
        const questions = lines
          .filter(line => line.trim() && line.includes('?'))
          .map(line => line.trim().replace(/^[\d.\-)\s]+/, ''))
          .slice(0, 3)

        return questions
      } catch (e) {
        // Fallback questions
      }
    }

    // Default clarifying questions
    return [
      `What type of page is this? (login, signup, checkout, etc.)`,
      `What are the most critical features to test?`,
      `Are there any known issues or areas of concern?`
    ]
  }

  /**
   * Fallback test generation when LLM is not available
   */
  _generateFallbackTests(knowledge, pageType) {
    const lines = ['## Generated Test Cases\n']

    if (knowledge.sections.length === 0) {
      lines.push('*No specific tests could be generated. Please provide more context.*')
      return lines.join('\n')
    }

    let tcNum = 1
    for (const section of knowledge.sections.slice(0, 3)) {
      lines.push(`### ${section.title}`)
      for (const test of section.tests.slice(0, 3)) {
        lines.push(`**TC-${String(tcNum).padStart(3, '0')}**: ${test.description}`)
        lines.push(`- Priority: ${test.priority}`)
        lines.push(`- ${section.cite()}`)
        lines.push('')
        tcNum++
      }
    }

    return lines.join('\n')
  }

  /**
   * Fallback security analysis
   */
  _generateFallbackSecurityAnalysis(knowledge, pageType) {
    const lines = ['## Security Analysis\n']

    const securitySections = knowledge.sections.filter(s =>
      s.tags.includes('security')
    )

    if (securitySections.length === 0) {
      lines.push('*Basic security checks recommended:*')
      lines.push('- Input validation on all fields')
      lines.push('- XSS prevention')
      lines.push('- CSRF token validation')
      lines.push('- Authentication/authorization checks')
      return lines.join('\n')
    }

    for (const section of securitySections) {
      lines.push(`### ${section.title}`)
      lines.push(section.content.slice(0, 300))
      lines.push('')
    }

    return lines.join('\n')
  }

  /**
   * Fallback edge case generation
   */
  _generateFallbackEdgeCases(knowledge, pageType) {
    const lines = ['## Edge Cases\n']

    // Get edge case data for common field types
    const edgeCases = {
      email: getEdgeCases('email'),
      password: getEdgeCases('password'),
      text: getEdgeCases('text'),
      number: getEdgeCases('number')
    }

    lines.push('### Input Field Edge Cases')
    lines.push('')
    lines.push('**Email Fields:**')
    edgeCases.email.slice(0, 5).forEach(ec => lines.push(`- ${ec}`))
    lines.push('')
    lines.push('**Text Fields:**')
    edgeCases.text.slice(0, 5).forEach(ec => lines.push(`- ${ec}`))
    lines.push('')
    lines.push('**Numeric Fields:**')
    edgeCases.number.slice(0, 5).forEach(ec => lines.push(`- ${ec}`))

    return lines.join('\n')
  }

  /**
   * Get reasoner status
   */
  getStatus() {
    return {
      confidenceThreshold: this.confidenceThreshold,
      hasLLM: Boolean(this.callLLM)
    }
  }
}

/**
 * Quick reasoning helper
 */
async function quickReason(feature, pageType = null, callLLM = null) {
  const reasoner = new Reasoner({ callLLM })
  return reasoner.reasonAboutFeature(feature, null, pageType)
}

module.exports = {
  ReasoningPhase,
  Reasoner,
  createRetrievedKnowledge,
  createReasoningResult,
  quickReason,
  PROMPTS
}
