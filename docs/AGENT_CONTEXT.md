# Agent Context Management

> Strategies for managing the LLM context window effectively - the key to long-running autonomous agents.

---

## Table of Contents

1. [The Context Challenge](#the-context-challenge)
2. [Context Engineering Principles](#context-engineering-principles)
3. [Dynamic Context Assembly](#dynamic-context-assembly)
4. [Compaction Strategies](#compaction-strategies)
5. [Just-in-Time Loading](#just-in-time-loading)
6. [Multi-Session Continuity](#multi-session-continuity)

---

## The Context Challenge

### Why Context Management Matters

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        THE CONTEXT WINDOW PROBLEM                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Context Window = Finite Resource (~100-200K tokens)                            │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                                                                          │    │
│  │  Token 0                                            Token 200K          │    │
│  │  │                                                           │          │    │
│  │  ▼                                                           ▼          │    │
│  │  ├───────────────────────────────────────────────────────────┤          │    │
│  │  │ System │ Knowledge │ History │ Current Task │ Tools │ ??? │          │    │
│  │  │ Prompt │   Base    │         │              │       │     │          │    │
│  │  ├────────┼───────────┼─────────┼──────────────┼───────┼─────┤          │    │
│  │  │  15%   │    20%    │   35%   │     15%      │  10%  │ 5%  │          │    │
│  │  └────────┴───────────┴─────────┴──────────────┴───────┴─────┘          │    │
│  │                                                                          │    │
│  │  Problems without management:                                            │    │
│  │  • History grows unbounded                                               │    │
│  │  • Knowledge base too large to include                                   │    │
│  │  • Running out of space = losing context = confused agent               │    │
│  │                                                                          │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  Solution: Dynamic context engineering - include only what's needed             │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Context Budget Allocation

```typescript
/**
 * Token budget allocation for different context components
 */

interface ContextBudget {
  total: number;      // Total available tokens (e.g., 100000)

  // Fixed allocations
  system: number;     // System prompt (15%)
  tools: number;      // Tool definitions (10%)
  buffer: number;     // Safety buffer (5%)

  // Dynamic allocations
  knowledge: number;  // Retrieved knowledge (20%)
  history: number;    // Conversation history (35%)
  current: number;    // Current task context (15%)
}

class ContextBudgetManager {
  private budget: ContextBudget;

  constructor(totalTokens: number = 100000) {
    this.budget = {
      total: totalTokens,
      system: Math.floor(totalTokens * 0.15),
      tools: Math.floor(totalTokens * 0.10),
      buffer: Math.floor(totalTokens * 0.05),
      knowledge: Math.floor(totalTokens * 0.20),
      history: Math.floor(totalTokens * 0.35),
      current: Math.floor(totalTokens * 0.15)
    };
  }

  /**
   * Check if we can fit content in a budget category
   */
  canFit(category: keyof ContextBudget, tokens: number): boolean {
    return tokens <= this.budget[category];
  }

  /**
   * Get remaining tokens after current usage
   */
  getRemaining(currentUsage: ContextUsage): number {
    const used = Object.values(currentUsage).reduce((a, b) => a + b, 0);
    return this.budget.total - used - this.budget.buffer;
  }

  /**
   * Suggest what to trim when over budget
   */
  suggestTrim(currentUsage: ContextUsage): TrimSuggestion[] {
    const suggestions: TrimSuggestion[] = [];
    const remaining = this.getRemaining(currentUsage);

    if (remaining < 0) {
      // Over budget - need to trim
      const overBy = Math.abs(remaining);

      // Prioritize trimming history (most expendable)
      if (currentUsage.history > this.budget.history * 0.5) {
        suggestions.push({
          category: 'history',
          action: 'compact',
          targetTokens: currentUsage.history - (this.budget.history * 0.3),
          priority: 1
        });
      }

      // Then trim knowledge if still over
      if (currentUsage.knowledge > this.budget.knowledge * 0.5) {
        suggestions.push({
          category: 'knowledge',
          action: 'reduce',
          targetTokens: currentUsage.knowledge * 0.5,
          priority: 2
        });
      }
    }

    return suggestions.sort((a, b) => a.priority - b.priority);
  }
}
```

---

## Context Engineering Principles

### 1. Relevance Over Completeness

```typescript
/**
 * Include only what's relevant to the current task
 */

class RelevanceFilter {
  private embedder: Embedder;
  private threshold: number = 0.7;

  /**
   * Filter knowledge base to only relevant sections
   */
  async filterKnowledge(
    fullKnowledge: KnowledgeSection[],
    taskContext: string,
    maxTokens: number
  ): Promise<KnowledgeSection[]> {
    // 1. Embed the task context
    const taskEmbedding = await this.embedder.embed(taskContext);

    // 2. Score each knowledge section
    const scored = await Promise.all(
      fullKnowledge.map(async (section) => ({
        section,
        score: await this.calculateRelevance(section, taskEmbedding)
      }))
    );

    // 3. Filter by threshold and sort
    const relevant = scored
      .filter(s => s.score >= this.threshold)
      .sort((a, b) => b.score - a.score);

    // 4. Take sections until token limit
    const selected: KnowledgeSection[] = [];
    let tokens = 0;

    for (const { section } of relevant) {
      const sectionTokens = this.countTokens(section);
      if (tokens + sectionTokens <= maxTokens) {
        selected.push(section);
        tokens += sectionTokens;
      }
    }

    return selected;
  }

  /**
   * Calculate relevance score between section and task
   */
  private async calculateRelevance(
    section: KnowledgeSection,
    taskEmbedding: number[]
  ): Promise<number> {
    const sectionEmbedding = await this.embedder.embed(section.content);
    return this.cosineSimilarity(taskEmbedding, sectionEmbedding);
  }
}
```

### 2. Recency Weighting

```typescript
/**
 * Recent information is more relevant than old
 */

class RecencyWeighter {
  private decayRate: number = 0.1; // 10% per hour

  /**
   * Weight messages by recency
   */
  weightByRecency(messages: Message[]): WeightedMessage[] {
    const now = Date.now();

    return messages.map(msg => {
      const ageHours = (now - msg.timestamp.getTime()) / (1000 * 60 * 60);
      const weight = Math.exp(-this.decayRate * ageHours);

      return {
        ...msg,
        weight,
        adjustedImportance: msg.importance * weight
      };
    });
  }

  /**
   * Select messages within token budget, prioritizing recent
   */
  selectWithinBudget(
    messages: WeightedMessage[],
    budget: number
  ): Message[] {
    // Sort by adjusted importance (importance × recency)
    const sorted = [...messages].sort(
      (a, b) => b.adjustedImportance - a.adjustedImportance
    );

    const selected: Message[] = [];
    let tokens = 0;

    for (const msg of sorted) {
      const msgTokens = this.countTokens(msg);
      if (tokens + msgTokens <= budget) {
        selected.push(msg);
        tokens += msgTokens;
      }
    }

    // Re-sort by original order (chronological)
    return selected.sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );
  }
}
```

### 3. Hierarchical Summarization

```typescript
/**
 * Summarize at multiple levels of detail
 */

interface SummaryHierarchy {
  oneLiner: string;      // 1 sentence (~20 tokens)
  brief: string;         // 2-3 sentences (~50 tokens)
  detailed: string;      // Paragraph (~200 tokens)
  full: string;          // Complete context (~1000+ tokens)
}

class HierarchicalSummarizer {
  /**
   * Create summary hierarchy for a conversation segment
   */
  async summarize(messages: Message[]): Promise<SummaryHierarchy> {
    // Generate full context first
    const full = messages.map(m => `${m.role}: ${m.content}`).join('\n\n');

    // Generate detailed summary
    const detailed = await this.llm.chat({
      model: 'haiku', // Cheap model for summarization
      messages: [{
        role: 'user',
        content: `Summarize this conversation in one paragraph:\n\n${full}`
      }]
    }).then(r => r.content);

    // Generate brief summary
    const brief = await this.llm.chat({
      model: 'haiku',
      messages: [{
        role: 'user',
        content: `Summarize in 2-3 sentences:\n\n${detailed}`
      }]
    }).then(r => r.content);

    // Generate one-liner
    const oneLiner = await this.llm.chat({
      model: 'haiku',
      messages: [{
        role: 'user',
        content: `Summarize in one sentence:\n\n${brief}`
      }]
    }).then(r => r.content);

    return { oneLiner, brief, detailed, full };
  }

  /**
   * Select appropriate summary level based on available tokens
   */
  selectLevel(hierarchy: SummaryHierarchy, availableTokens: number): string {
    const levels: [keyof SummaryHierarchy, number][] = [
      ['full', this.countTokens(hierarchy.full)],
      ['detailed', this.countTokens(hierarchy.detailed)],
      ['brief', this.countTokens(hierarchy.brief)],
      ['oneLiner', this.countTokens(hierarchy.oneLiner)]
    ];

    for (const [level, tokens] of levels) {
      if (tokens <= availableTokens) {
        return hierarchy[level];
      }
    }

    return hierarchy.oneLiner; // Fallback
  }
}
```

---

## Dynamic Context Assembly

### Context Assembly Pipeline

```typescript
/**
 * Assemble context dynamically based on current task
 */

class ContextAssembler {
  private budgetManager: ContextBudgetManager;
  private relevanceFilter: RelevanceFilter;
  private summarizer: HierarchicalSummarizer;
  private memoryManager: MemoryManager;

  /**
   * Assemble complete context for LLM
   */
  async assemble(task: Task): Promise<AssembledContext> {
    const usage: ContextUsage = {
      system: 0,
      tools: 0,
      knowledge: 0,
      history: 0,
      current: 0
    };

    // 1. SYSTEM PROMPT (fixed)
    const systemPrompt = await this.buildSystemPrompt(task);
    usage.system = this.countTokens(systemPrompt);

    // 2. TOOL DEFINITIONS (fixed)
    const tools = this.getRelevantTools(task);
    usage.tools = this.countTokensForTools(tools);

    // 3. CURRENT TASK (priority)
    const currentContext = await this.buildCurrentContext(task);
    usage.current = this.countTokens(currentContext);

    // 4. RELEVANT KNOWLEDGE (dynamic)
    const remainingForKnowledge = this.budgetManager.budget.knowledge;
    const knowledge = await this.relevanceFilter.filterKnowledge(
      await this.loadKnowledgeBase(),
      task.description,
      remainingForKnowledge
    );
    usage.knowledge = this.countTokens(knowledge);

    // 5. HISTORY (fill remaining space)
    const remainingForHistory = this.budgetManager.getRemaining(usage);
    const history = await this.buildHistory(remainingForHistory);
    usage.history = this.countTokens(history);

    return {
      messages: this.assembleMessages({
        systemPrompt,
        knowledge,
        history,
        currentContext
      }),
      tools,
      usage,
      remaining: this.budgetManager.getRemaining(usage)
    };
  }

  /**
   * Build system prompt for task
   */
  private async buildSystemPrompt(task: Task): Promise<string> {
    const basePrompt = `You are an autonomous QA testing agent...`;

    // Add task-specific instructions
    const taskInstructions = this.getTaskInstructions(task.type);

    // Add current session context
    const sessionContext = await this.memoryManager.session.getSummary();

    return `${basePrompt}\n\n${taskInstructions}\n\n[Session Context]\n${sessionContext}`;
  }

  /**
   * Build context for current task
   */
  private async buildCurrentContext(task: Task): Promise<string> {
    const parts: string[] = [];

    // Task description
    parts.push(`## Current Task\n${task.description}`);

    // Page state (if available)
    if (task.pageState) {
      parts.push(`## Current Page\nURL: ${task.pageState.url}\nType: ${task.pageState.type}`);

      // Include relevant elements (truncated)
      const elements = task.pageState.elements
        .slice(0, 20)
        .map(e => `- ${e.mmid}: ${e.type} "${e.text}"`)
        .join('\n');
      parts.push(`## Interactive Elements\n${elements}`);
    }

    // Relevant findings from this session
    const relevantBugs = await this.memoryManager.recall({
      text: task.description,
      filter: { type: 'bug_report' },
      limit: 3
    });

    if (relevantBugs.combined.length > 0) {
      parts.push(`## Related Bugs Found\n${
        relevantBugs.combined.map(b =>
          `- ${b.content.title} (${b.content.severity})`
        ).join('\n')
      }`);
    }

    return parts.join('\n\n');
  }

  /**
   * Build conversation history within budget
   */
  private async buildHistory(budget: number): Promise<Message[]> {
    const allHistory = this.memoryManager.working.getContext();

    // If history fits, use it all
    if (this.countTokens(allHistory) <= budget) {
      return allHistory;
    }

    // Otherwise, summarize older messages
    const recentCount = 10; // Keep last 10 messages intact
    const recent = allHistory.slice(-recentCount);
    const older = allHistory.slice(0, -recentCount);

    const recentTokens = this.countTokens(recent);
    const olderBudget = budget - recentTokens;

    // Summarize older messages
    const olderSummary = await this.summarizer.summarize(older);
    const summaryText = this.summarizer.selectLevel(olderSummary, olderBudget);

    return [
      { role: 'system', content: `[Earlier conversation summary]\n${summaryText}` },
      ...recent
    ];
  }
}
```

### Context Refresh Strategy

```typescript
/**
 * When and how to refresh context
 */

class ContextRefreshStrategy {
  private thresholds = {
    navigationRefresh: true,      // Refresh on page navigation
    toolResultRefresh: 5,         // Refresh after N tool results
    tokenThreshold: 0.85,         // Refresh at 85% usage
    timeThreshold: 5 * 60 * 1000  // Refresh every 5 minutes
  };

  private lastRefresh: Date = new Date();
  private toolResultsSinceRefresh: number = 0;

  /**
   * Check if context should be refreshed
   */
  shouldRefresh(event: ContextEvent, usage: ContextUsage): RefreshDecision {
    // 1. Navigation always triggers refresh
    if (event.type === 'navigation') {
      return { refresh: true, reason: 'Page navigation' };
    }

    // 2. Too many tool results
    if (event.type === 'tool_result') {
      this.toolResultsSinceRefresh++;
      if (this.toolResultsSinceRefresh >= this.thresholds.toolResultRefresh) {
        return { refresh: true, reason: 'Tool result accumulation' };
      }
    }

    // 3. Token threshold exceeded
    const usagePercent = this.calculateUsagePercent(usage);
    if (usagePercent >= this.thresholds.tokenThreshold) {
      return { refresh: true, reason: 'Token threshold exceeded' };
    }

    // 4. Time threshold
    const elapsed = Date.now() - this.lastRefresh.getTime();
    if (elapsed >= this.thresholds.timeThreshold) {
      return { refresh: true, reason: 'Time threshold exceeded' };
    }

    return { refresh: false };
  }

  /**
   * Perform context refresh
   */
  async refresh(assembler: ContextAssembler, task: Task): Promise<AssembledContext> {
    // Reset counters
    this.lastRefresh = new Date();
    this.toolResultsSinceRefresh = 0;

    // Reassemble context
    return assembler.assemble(task);
  }
}
```

---

## Compaction Strategies

### Progressive Compaction

```typescript
/**
 * Compact context progressively as it grows
 */

class ProgressiveCompactor {
  private levels: CompactionLevel[] = [
    { threshold: 0.60, strategy: 'trim_tool_outputs' },
    { threshold: 0.70, strategy: 'summarize_older_messages' },
    { threshold: 0.80, strategy: 'aggressive_summarization' },
    { threshold: 0.90, strategy: 'emergency_compaction' }
  ];

  /**
   * Apply appropriate compaction based on usage
   */
  async compact(
    messages: Message[],
    usage: number,
    budget: number
  ): Promise<CompactionResult> {
    const usagePercent = usage / budget;

    // Find applicable level
    const level = this.levels
      .filter(l => l.threshold <= usagePercent)
      .pop();

    if (!level) {
      return { messages, compacted: false };
    }

    switch (level.strategy) {
      case 'trim_tool_outputs':
        return this.trimToolOutputs(messages);

      case 'summarize_older_messages':
        return this.summarizeOlderMessages(messages);

      case 'aggressive_summarization':
        return this.aggressiveSummarization(messages);

      case 'emergency_compaction':
        return this.emergencyCompaction(messages);

      default:
        return { messages, compacted: false };
    }
  }

  /**
   * Trim verbose tool outputs (keep summary only)
   */
  private async trimToolOutputs(messages: Message[]): Promise<CompactionResult> {
    const trimmed = messages.map(msg => {
      if (msg.role === 'tool') {
        const content = JSON.parse(msg.content);
        // Keep only summary and success status
        return {
          ...msg,
          content: JSON.stringify({
            success: content.success,
            summary: content.output?.summary || content.output?.message || 'Completed'
          })
        };
      }
      return msg;
    });

    return {
      messages: trimmed,
      compacted: true,
      strategy: 'trim_tool_outputs',
      tokensSaved: this.countTokens(messages) - this.countTokens(trimmed)
    };
  }

  /**
   * Summarize messages older than N turns
   */
  private async summarizeOlderMessages(
    messages: Message[]
  ): Promise<CompactionResult> {
    const keepRecent = 10;

    if (messages.length <= keepRecent) {
      return { messages, compacted: false };
    }

    const recent = messages.slice(-keepRecent);
    const older = messages.slice(0, -keepRecent);

    // Generate summary
    const summary = await this.generateSummary(older);

    const compacted = [
      { role: 'system', content: `[Conversation summary]\n${summary}` },
      ...recent
    ];

    return {
      messages: compacted,
      compacted: true,
      strategy: 'summarize_older_messages',
      tokensSaved: this.countTokens(messages) - this.countTokens(compacted)
    };
  }

  /**
   * Aggressive summarization - keep only essentials
   */
  private async aggressiveSummarization(
    messages: Message[]
  ): Promise<CompactionResult> {
    // Extract key facts and decisions
    const keyFacts = await this.extractKeyFacts(messages);
    const recentActions = this.getRecentActions(messages, 5);

    const compacted = [
      {
        role: 'system',
        content: `[Key facts from conversation]\n${keyFacts.join('\n')}`
      },
      ...recentActions
    ];

    return {
      messages: compacted,
      compacted: true,
      strategy: 'aggressive_summarization',
      tokensSaved: this.countTokens(messages) - this.countTokens(compacted)
    };
  }

  /**
   * Emergency compaction - absolute minimum context
   */
  private async emergencyCompaction(
    messages: Message[]
  ): Promise<CompactionResult> {
    // Keep only: last task + last 3 messages
    const oneLiner = await this.generateOneLiner(messages);
    const lastThree = messages.slice(-3);

    const compacted = [
      { role: 'system', content: `[Previous: ${oneLiner}]` },
      ...lastThree
    ];

    return {
      messages: compacted,
      compacted: true,
      strategy: 'emergency_compaction',
      tokensSaved: this.countTokens(messages) - this.countTokens(compacted)
    };
  }
}
```

---

## Just-in-Time Loading

### Lazy Knowledge Loading

```typescript
/**
 * Load knowledge only when needed
 */

class LazyKnowledgeLoader {
  private cache: Map<string, KnowledgeSection> = new Map();
  private knowledgeIndex: KnowledgeIndex;

  /**
   * Load knowledge relevant to current action
   */
  async loadForAction(action: PlannedAction): Promise<KnowledgeSection[]> {
    // Determine what knowledge sections are relevant
    const relevantSections = this.knowledgeIndex.findRelevant(action);

    // Load only those sections
    const loaded: KnowledgeSection[] = [];
    for (const sectionId of relevantSections) {
      const section = await this.loadSection(sectionId);
      if (section) loaded.push(section);
    }

    return loaded;
  }

  /**
   * Load section (from cache or disk)
   */
  private async loadSection(id: string): Promise<KnowledgeSection | null> {
    // Check cache
    if (this.cache.has(id)) {
      return this.cache.get(id)!;
    }

    // Load from disk
    const section = await this.loadFromDisk(id);

    // Cache for future use (with LRU eviction)
    if (section) {
      this.addToCache(id, section);
    }

    return section;
  }

  /**
   * LRU cache management
   */
  private addToCache(id: string, section: KnowledgeSection): void {
    const maxCacheSize = 20;

    if (this.cache.size >= maxCacheSize) {
      // Evict least recently used
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    this.cache.set(id, section);
  }
}

/**
 * Index for quick knowledge lookup
 */

class KnowledgeIndex {
  private actionToSections: Map<string, string[]>;
  private pageTypeToSections: Map<string, string[]>;
  private keywordIndex: Map<string, string[]>;

  constructor() {
    this.buildIndex();
  }

  /**
   * Build index from QA_BRAIN
   */
  private buildIndex(): void {
    // Action type -> relevant sections
    this.actionToSections = new Map([
      ['click', ['Part 4: Operations', 'Part 8: UI Patterns']],
      ['type', ['Part 7: Input Validations', 'Part 8: UI Patterns']],
      ['navigate', ['Part 5: States & Workflows']],
      ['assertVisible', ['Part 8: UI Patterns', 'Part 17: Checklists']],
      ['analyzeAccessibility', ['Part 13: Accessibility Testing']],
      ['analyzePerformance', ['Part 12: Performance Testing']],
    ]);

    // Page type -> relevant sections
    this.pageTypeToSections = new Map([
      ['login', ['Part 2.1: Login Pages', 'Part 11: Security Testing']],
      ['form', ['Part 7: Input Validations', 'Part 10: Edge Cases']],
      ['dashboard', ['Part 5: States & Workflows', 'Part 6: Permissions']],
      ['ecommerce', ['Part 4: CRUD Operations', 'Part 9: Integrations']],
    ]);
  }

  /**
   * Find relevant sections for an action
   */
  findRelevant(action: PlannedAction): string[] {
    const sections = new Set<string>();

    // By action type
    const actionSections = this.actionToSections.get(action.tool) || [];
    actionSections.forEach(s => sections.add(s));

    // By page type
    if (action.pageType) {
      const pageSections = this.pageTypeToSections.get(action.pageType) || [];
      pageSections.forEach(s => sections.add(s));
    }

    return Array.from(sections);
  }
}
```

---

## Multi-Session Continuity

### Session Handoff

```typescript
/**
 * Pass context between sessions
 */

class SessionHandoff {
  /**
   * Prepare handoff package for next session
   */
  async prepareHandoff(
    currentSession: Session,
    memoryManager: MemoryManager
  ): Promise<HandoffPackage> {
    // 1. Generate session summary
    const summary = await this.generateSessionSummary(currentSession);

    // 2. Extract key learnings
    const learnings = await this.extractLearnings(currentSession);

    // 3. Identify unfinished tasks
    const pendingTasks = currentSession.taskQueue.filter(t =>
      t.status === 'pending' || t.status === 'in_progress'
    );

    // 4. Capture current state
    const state = {
      lastUrl: currentSession.currentPage?.url,
      lastAction: currentSession.lastAction,
      discoveredBugs: currentSession.bugs.length,
      testedElements: currentSession.testedElements.size
    };

    // 5. Generate next steps
    const nextSteps = await this.generateNextSteps(currentSession, pendingTasks);

    return {
      sessionId: currentSession.id,
      timestamp: new Date(),
      summary,
      learnings,
      pendingTasks,
      state,
      nextSteps,
      resumptionPrompt: this.buildResumptionPrompt({
        summary,
        pendingTasks,
        nextSteps
      })
    };
  }

  /**
   * Build prompt for resuming in new session
   */
  private buildResumptionPrompt(data: {
    summary: string;
    pendingTasks: Task[];
    nextSteps: string[];
  }): string {
    return `
# Session Resumption Context

## Previous Session Summary
${data.summary}

## Pending Tasks
${data.pendingTasks.map((t, i) =>
  `${i + 1}. ${t.description} (Priority: ${t.priority})`
).join('\n')}

## Recommended Next Steps
${data.nextSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

## Instructions
Continue testing from where the previous session left off.
Focus on completing pending tasks in priority order.
`.trim();
  }

  /**
   * Resume from handoff package
   */
  async resumeFromHandoff(
    handoff: HandoffPackage,
    newSession: Session
  ): Promise<void> {
    // 1. Load resumption prompt into working memory
    newSession.workingMemory.add({
      role: 'system',
      content: handoff.resumptionPrompt
    });

    // 2. Restore task queue
    newSession.taskQueue = handoff.pendingTasks;

    // 3. Apply learnings
    for (const learning of handoff.learnings) {
      await newSession.memoryManager.persistent.store({
        type: 'learned_pattern',
        content: learning,
        metadata: { source: `session-${handoff.sessionId}` }
      });
    }
  }
}
```

### Context Window Bridging

```typescript
/**
 * Bridge context across context window boundaries
 */

class ContextWindowBridge {
  /**
   * Detect when approaching context limit
   */
  isApproachingLimit(usage: ContextUsage, threshold: number = 0.9): boolean {
    const total = Object.values(usage).reduce((a, b) => a + b, 0);
    return total >= (this.maxTokens * threshold);
  }

  /**
   * Create checkpoint for context window transition
   */
  async createCheckpoint(
    state: AgentState,
    assembler: ContextAssembler
  ): Promise<ContextCheckpoint> {
    // 1. Summarize everything
    const fullSummary = await this.summarizeState(state);

    // 2. Extract critical state
    const criticalState = {
      currentTask: state.currentTask,
      currentUrl: state.currentPage?.url,
      lastSuccessfulAction: state.lastSuccessfulAction,
      discoveredBugs: state.bugs,
      testedElements: Array.from(state.testedElements)
    };

    // 3. Prepare continuation prompt
    const continuationPrompt = `
[CONTEXT WINDOW CONTINUATION]

The previous context window has been compacted. Here's the essential state:

## Summary
${fullSummary}

## Critical State
- Current task: ${criticalState.currentTask?.description || 'None'}
- Current page: ${criticalState.currentUrl || 'None'}
- Bugs found: ${criticalState.discoveredBugs.length}
- Elements tested: ${criticalState.testedElements.length}

## Last Action
${criticalState.lastSuccessfulAction?.description || 'None'}

Continue from this point.
`.trim();

    return {
      timestamp: new Date(),
      summary: fullSummary,
      criticalState,
      continuationPrompt
    };
  }

  /**
   * Restore from checkpoint
   */
  restoreFromCheckpoint(checkpoint: ContextCheckpoint): Message[] {
    return [{
      role: 'system',
      content: checkpoint.continuationPrompt
    }];
  }
}
```

---

## Context Management Best Practices

### Do's and Don'ts

| Do | Don't |
|---|---|
| Include only relevant knowledge | Load entire knowledge base |
| Summarize old conversations | Keep all messages verbatim |
| Use hierarchical summaries | Use one-size-fits-all summaries |
| Track token usage | Ignore context limits |
| Refresh on navigation | Keep stale page context |
| Cache frequently used data | Re-fetch everything |
| Use cheap models for summarization | Use expensive models for utility tasks |

### Token Budget Guidelines

```typescript
const BUDGET_GUIDELINES = {
  // System prompt: Keep minimal but complete
  system: {
    maxTokens: 15000,
    includes: ['core identity', 'task instructions', 'tool usage rules'],
    excludes: ['verbose examples', 'edge case handling']
  },

  // Knowledge: Load just-in-time
  knowledge: {
    maxTokens: 20000,
    strategy: 'relevance_filtered',
    refreshOn: ['task_change', 'page_type_change']
  },

  // History: Aggressive compaction
  history: {
    maxTokens: 35000,
    keepRecentVerbatim: 10, // messages
    summarizeOlder: true,
    compactionTrigger: 0.7 // 70% of budget
  },

  // Current task: Priority allocation
  current: {
    maxTokens: 15000,
    includes: ['task description', 'page state', 'relevant elements'],
    truncateElements: 20 // max elements to include
  },

  // Tools: Static but filterable
  tools: {
    maxTokens: 10000,
    strategy: 'task_relevant_only'
  },

  // Buffer: Safety margin
  buffer: {
    minTokens: 5000,
    purpose: 'response generation space'
  }
};
```

---

## Next Steps

- **[AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md)** - Multi-agent coordination
- **[AGENT_PROMPTS.md](./AGENT_PROMPTS.md)** - Prompt engineering
- **[AGENT_ESCALATION.md](./AGENT_ESCALATION.md)** - Human-in-the-loop
