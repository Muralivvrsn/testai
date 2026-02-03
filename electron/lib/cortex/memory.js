/**
 * Yali Agent - Conversational Memory System
 * Ported from testai-agent/conversation/memory.py
 *
 * Maintains conversation context like a human QA consultant.
 * Remembers what was discussed, decisions made, and insights gained.
 */

/**
 * Memory types
 */
const MemoryType = {
  FEATURE: 'feature',
  CLARIFICATION: 'clarification',
  DECISION: 'decision',
  INSIGHT: 'insight',
  TEST: 'test',
  RISK: 'risk',
  PREFERENCE: 'preference'
}

/**
 * Create a memory unit
 */
function createMemory(type, content, metadata = {}) {
  return {
    id: `mem_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
    type,
    content,
    metadata,
    importance: metadata.importance || 0.5,
    timestamp: Date.now(),

    isRecent(maxAgeMs = 300000) {
      return Date.now() - this.timestamp < maxAgeMs
    },

    matches(query) {
      const queryLower = query.toLowerCase()
      const contentLower = this.content.toLowerCase()
      return contentLower.includes(queryLower) ||
             Object.values(this.metadata).some(v =>
               String(v).toLowerCase().includes(queryLower)
             )
    }
  }
}

/**
 * Create a conversation turn
 */
function createConversationTurn(role, content, metadata = {}) {
  return {
    id: `turn_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
    role,
    content,
    metadata,
    timestamp: Date.now(),

    extractEntities() {
      const entities = { pageTypes: [], actions: [], elements: [] }
      const pageTypes = content.match(/\b(login|signup|checkout|payment|search|profile|settings|dashboard|form)\b/gi) || []
      const actions = content.match(/\b(click|type|fill|submit|test|verify|check|validate)\b/gi) || []
      const elements = content.match(/\b(button|input|field|link|form|dropdown|checkbox)\b/gi) || []

      entities.pageTypes = [...new Set(pageTypes.map(p => p.toLowerCase()))]
      entities.actions = [...new Set(actions.map(a => a.toLowerCase()))]
      entities.elements = [...new Set(elements.map(e => e.toLowerCase()))]
      return entities
    }
  }
}

/**
 * Working context for current task
 */
function createWorkingContext(options = {}) {
  return {
    feature: options.feature || null,
    pageType: options.pageType || null,
    url: options.url || null,
    elements: options.elements || [],
    risks: options.risks || [],
    testCases: options.testCases || [],
    clarifications: options.clarifications || {},
    startTime: Date.now(),

    isActive() {
      return this.feature !== null || this.pageType !== null
    },

    getDuration() {
      return Date.now() - this.startTime
    },

    getSummary() {
      const parts = []
      if (this.feature) parts.push(`Feature: ${this.feature}`)
      if (this.pageType) parts.push(`Page: ${this.pageType}`)
      if (this.testCases.length) parts.push(`Tests: ${this.testCases.length}`)
      if (this.risks.length) parts.push(`Risks: ${this.risks.length}`)
      return parts.join(' | ')
    }
  }
}

/**
 * Conversational Memory class
 */
class ConversationalMemory {
  constructor(options = {}) {
    this.conversationHistory = []
    this.longTermMemory = new Map()
    this.workingContext = createWorkingContext()
    this.maxTurns = options.maxTurns || 50
    this.maxMemoriesPerType = options.maxMemoriesPerType || 100
  }

  addUserTurn(content, metadata = {}) {
    const turn = createConversationTurn('user', content, metadata)
    this._addTurn(turn)
    const entities = turn.extractEntities()
    if (entities.pageTypes.length > 0) {
      this.workingContext.pageType = entities.pageTypes[0]
    }
    return turn
  }

  addAssistantTurn(content, metadata = {}) {
    const turn = createConversationTurn('assistant', content, metadata)
    this._addTurn(turn)
    return turn
  }

  _addTurn(turn) {
    this.conversationHistory.push(turn)
    if (this.conversationHistory.length > this.maxTurns) {
      const removed = this.conversationHistory.shift()
      if (removed.metadata.important) {
        this.remember(MemoryType.INSIGHT, removed.content, { fromConversation: true })
      }
    }
  }

  setWorkingContext(options) {
    this.workingContext = createWorkingContext({ ...this.workingContext, ...options })
  }

  updateContext(updates) {
    Object.assign(this.workingContext, updates)
  }

  clearContext() {
    this.workingContext = createWorkingContext()
  }

  remember(type, content, metadata = {}) {
    if (!this.longTermMemory.has(type)) {
      this.longTermMemory.set(type, [])
    }
    const memories = this.longTermMemory.get(type)
    const memory = createMemory(type, content, metadata)
    memories.push(memory)
    if (memories.length > this.maxMemoriesPerType) {
      memories.sort((a, b) => {
        const scoreA = a.importance + (a.isRecent() ? 0.3 : 0)
        const scoreB = b.importance + (b.isRecent() ? 0.3 : 0)
        return scoreB - scoreA
      })
      memories.length = this.maxMemoriesPerType
    }
    return memory
  }

  recall(query, type = null, limit = 5) {
    let memories = []
    if (type) {
      memories = this.longTermMemory.get(type) || []
    } else {
      for (const typeMemories of this.longTermMemory.values()) {
        memories.push(...typeMemories)
      }
    }
    const matching = memories.filter(m => m.matches(query))
    matching.sort((a, b) => {
      const scoreA = a.importance + (a.isRecent() ? 0.3 : 0)
      const scoreB = b.importance + (b.isRecent() ? 0.3 : 0)
      return scoreB - scoreA
    })
    return matching.slice(0, limit)
  }

  getRecentTurns(count = 10) {
    return this.conversationHistory.slice(-count)
  }

  buildContextForLLM(maxTurns = 10) {
    const lines = []
    if (this.workingContext.isActive()) {
      lines.push('## Current Context')
      lines.push(this.workingContext.getSummary())
      lines.push('')
    }
    const recentInsights = this.recall('', MemoryType.INSIGHT, 3)
    if (recentInsights.length > 0) {
      lines.push('## Recent Insights')
      recentInsights.forEach(m => lines.push(`- ${m.content}`))
      lines.push('')
    }
    const recentTurns = this.getRecentTurns(maxTurns)
    if (recentTurns.length > 0) {
      lines.push('## Conversation History')
      recentTurns.forEach(turn => {
        const role = turn.role === 'user' ? 'User' : 'Yali'
        lines.push(`**${role}:** ${turn.content.slice(0, 200)}${turn.content.length > 200 ? '...' : ''}`)
      })
    }
    return lines.join('\n')
  }

  getMessagesForLLM(systemPrompt = null, maxTurns = 10) {
    const messages = []
    if (systemPrompt) {
      messages.push({ role: 'system', content: systemPrompt })
    }
    const context = this.buildContextForLLM(0)
    if (context.trim()) {
      messages.push({ role: 'system', content: `Current context:\n${context}` })
    }
    const recentTurns = this.getRecentTurns(maxTurns)
    for (const turn of recentTurns) {
      messages.push({ role: turn.role, content: turn.content })
    }
    return messages
  }

  exportSession() {
    return {
      conversationHistory: this.conversationHistory,
      workingContext: this.workingContext,
      memories: Object.fromEntries(this.longTermMemory),
      exportedAt: new Date().toISOString()
    }
  }

  importSession(data) {
    if (data.conversationHistory) this.conversationHistory = data.conversationHistory
    if (data.workingContext) this.workingContext = createWorkingContext(data.workingContext)
    if (data.memories) {
      for (const [type, memories] of Object.entries(data.memories)) {
        this.longTermMemory.set(type, memories)
      }
    }
  }

  clear() {
    this.conversationHistory = []
    this.longTermMemory.clear()
    this.workingContext = createWorkingContext()
  }

  getStats() {
    const memoryCount = {}
    for (const [type, memories] of this.longTermMemory) {
      memoryCount[type] = memories.length
    }
    return {
      conversationTurns: this.conversationHistory.length,
      memoryCount,
      contextActive: this.workingContext.isActive(),
      contextDuration: this.workingContext.getDuration()
    }
  }
}

module.exports = {
  MemoryType,
  ConversationalMemory,
  createMemory,
  createConversationTurn,
  createWorkingContext
}
