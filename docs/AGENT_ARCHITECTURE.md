# Agent Architecture Overview

> Complete system architecture for building a humanoid QA agent that operates autonomously like Claude Code.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Component Interactions](#component-interactions)
5. [Deployment Architecture](#deployment-architecture)

---

## System Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           HUMANOID QA AGENT SYSTEM                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         ORCHESTRATION LAYER                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │    │
│  │  │   CORTEX     │  │  HIPPOCAMPUS │  │   SYNAPSE    │  │ CONSCIENCE │  │    │
│  │  │  (Planner)   │  │   (Memory)   │  │  (Prompts)   │  │ (Escalate) │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                       │                                          │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                          EXECUTION LAYER                                 │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │    │
│  │  │ AGENT LOOP   │  │    TOOL      │  │   CONTEXT    │  │  SUBAGENT  │  │    │
│  │  │  (ReAct)     │  │  EXECUTOR    │  │   MANAGER    │  │  SPAWNER   │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                       │                                          │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                          INTEGRATION LAYER                               │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │    │
│  │  │   BROWSER    │  │     LLM      │  │   STORAGE    │  │  EXTERNAL  │  │    │
│  │  │  (Playwright)│  │    (APIs)    │  │  (DB/Files)  │  │   (MCP)    │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Design Principles

| Principle | Description | Implementation |
|-----------|-------------|----------------|
| **Modularity** | Each component is independent and replaceable | Interface-based design with dependency injection |
| **Observability** | Every action is logged and traceable | Structured logging with correlation IDs |
| **Recoverability** | System can resume from any failure point | Persistent state with git-based snapshots |
| **Bounded Autonomy** | Clear limits on agent actions | Escalation policies and permission systems |
| **Cost Awareness** | Token usage tracked and optimized | Model routing based on task complexity |

---

## Core Components

### 1. Orchestration Layer

#### 1.1 Cortex (Planning & Prioritization)

```typescript
/**
 * CORTEX - The planning center of the agent
 * Decides WHAT to test and in WHAT ORDER
 */

interface CortexConfig {
  prioritizationStrategy: 'risk-based' | 'coverage-based' | 'exploratory';
  maxParallelTasks: number;
  planningHorizon: number; // How many steps ahead to plan
}

interface TestPlan {
  id: string;
  tasks: PlannedTask[];
  estimatedDuration: number;
  riskScore: number;
  coverageTarget: number;
}

interface PlannedTask {
  id: string;
  type: TaskType;
  target: TestTarget;
  priority: number;
  dependencies: string[];
  estimatedComplexity: 'low' | 'medium' | 'high';
  requiredTools: string[];
}

type TaskType =
  | 'explore_page'
  | 'test_form'
  | 'verify_navigation'
  | 'check_accessibility'
  | 'validate_api'
  | 'test_edge_case'
  | 'regression_check';

class Cortex {
  private config: CortexConfig;
  private knowledgeBase: KnowledgeBase;
  private riskCalculator: RiskCalculator;

  /**
   * Generate a test plan for the current session
   */
  async generatePlan(context: SessionContext): Promise<TestPlan> {
    // 1. Gather context from memory
    const previousResults = await this.knowledgeBase.getRecentResults();
    const knownBugs = await this.knowledgeBase.getKnownBugs();
    const productionErrors = await this.knowledgeBase.getProductionErrors();

    // 2. Calculate risk scores for all testable areas
    const riskMap = await this.riskCalculator.calculateRisks({
      previousResults,
      productionErrors,
      codeChanges: context.recentCodeChanges
    });

    // 3. Generate prioritized task list
    const tasks = await this.prioritizeTasks(riskMap, context);

    // 4. Optimize task ordering (dependencies, parallelization)
    const orderedTasks = this.optimizeTaskOrder(tasks);

    return {
      id: generateId(),
      tasks: orderedTasks,
      estimatedDuration: this.estimateDuration(orderedTasks),
      riskScore: this.calculatePlanRisk(orderedTasks),
      coverageTarget: context.coverageGoal || 0.8
    };
  }

  /**
   * Adapt plan based on runtime discoveries
   */
  async adaptPlan(
    currentPlan: TestPlan,
    discovery: Discovery
  ): Promise<TestPlan> {
    switch (discovery.type) {
      case 'new_page_found':
        return this.addExplorationTask(currentPlan, discovery);
      case 'bug_found':
        return this.addRegressionTasks(currentPlan, discovery);
      case 'blocked':
        return this.reroutePlan(currentPlan, discovery);
      default:
        return currentPlan;
    }
  }
}
```

#### 1.2 Hippocampus (Memory & State)

```typescript
/**
 * HIPPOCAMPUS - Memory management system
 * Handles short-term, medium-term, and long-term memory
 */

interface HippocampusConfig {
  shortTermLimit: number;      // Max messages in working memory
  compactionThreshold: number; // When to trigger compaction
  vectorDimensions: number;    // For semantic search
  persistenceInterval: number; // How often to save state
}

interface MemoryLayers {
  working: WorkingMemory;
  session: SessionMemory;
  persistent: PersistentMemory;
}

interface WorkingMemory {
  messages: Message[];
  currentTask: PlannedTask | null;
  toolResults: ToolResult[];
  observations: Observation[];
}

interface SessionMemory {
  summary: string;
  completedTasks: string[];
  discoveredBugs: Bug[];
  testedElements: Set<string>;
  startTime: Date;
}

interface PersistentMemory {
  knowledgeGraph: KnowledgeGraph;
  bugPatterns: BugPattern[];
  pageModels: Map<string, PageModel>;
  testHistory: TestHistoryEntry[];
  learnings: Learning[];
}

class Hippocampus {
  private config: HippocampusConfig;
  private vectorStore: VectorStore;
  private sqliteDb: Database;
  private fileSystem: FileSystem;

  /**
   * Store a new memory with appropriate categorization
   */
  async store(memory: Memory): Promise<void> {
    // 1. Determine memory layer
    const layer = this.categorizeMemory(memory);

    // 2. Store in appropriate location
    switch (layer) {
      case 'working':
        this.workingMemory.push(memory);
        break;
      case 'session':
        await this.updateSessionSummary(memory);
        break;
      case 'persistent':
        await this.persistToLongTerm(memory);
        break;
    }

    // 3. Check for compaction need
    if (this.needsCompaction()) {
      await this.compact();
    }
  }

  /**
   * Recall relevant memories for current context
   */
  async recall(query: RecallQuery): Promise<RelevantMemories> {
    const results: RelevantMemories = {
      direct: [],
      semantic: [],
      temporal: []
    };

    // 1. Direct keyword search
    results.direct = await this.sqliteDb.search(query.keywords);

    // 2. Semantic similarity search
    const embedding = await this.embed(query.context);
    results.semantic = await this.vectorStore.search(embedding, query.limit);

    // 3. Temporal relevance (recent similar situations)
    results.temporal = await this.getTemporallyRelevant(query.timeWindow);

    // 4. Merge and rank results
    return this.rankAndMerge(results);
  }

  /**
   * Compact working memory when approaching limits
   */
  async compact(): Promise<CompactionResult> {
    const messages = this.workingMemory.messages;

    // 1. Summarize older messages
    const olderMessages = messages.slice(0, -10); // Keep last 10 intact
    const summary = await this.summarize(olderMessages);

    // 2. Extract key facts for long-term storage
    const keyFacts = await this.extractKeyFacts(olderMessages);
    await this.persistToLongTerm({ type: 'facts', data: keyFacts });

    // 3. Replace with summary
    this.workingMemory.messages = [
      { role: 'system', content: `Previous context summary:\n${summary}` },
      ...messages.slice(-10)
    ];

    return {
      compacted: olderMessages.length,
      retained: 10,
      extractedFacts: keyFacts.length
    };
  }
}
```

#### 1.3 Synapse (Dynamic Prompt Generation)

```typescript
/**
 * SYNAPSE - Generates context-aware prompts
 * Assembles the right knowledge for each situation
 */

interface SynapseConfig {
  maxPromptTokens: number;
  knowledgeSources: KnowledgeSource[];
  templateEngine: 'handlebars' | 'custom';
}

interface PromptContext {
  task: PlannedTask;
  pageState: PageState;
  recentHistory: Message[];
  relevantKnowledge: Knowledge[];
  constraints: Constraint[];
}

interface GeneratedPrompt {
  system: string;
  context: string;
  instructions: string;
  examples: Example[];
  tools: ToolDefinition[];
}

class Synapse {
  private config: SynapseConfig;
  private knowledgeBase: KnowledgeBase;
  private templateEngine: TemplateEngine;

  /**
   * Generate a complete prompt for the current task
   */
  async generatePrompt(context: PromptContext): Promise<GeneratedPrompt> {
    // 1. Select relevant knowledge sections from QA_BRAIN
    const relevantKnowledge = await this.selectRelevantKnowledge(context);

    // 2. Build system prompt
    const system = this.buildSystemPrompt(context, relevantKnowledge);

    // 3. Add contextual instructions
    const instructions = this.buildInstructions(context);

    // 4. Select relevant examples
    const examples = await this.selectExamples(context);

    // 5. Filter tools for current task
    const tools = this.filterTools(context.task);

    // 6. Ensure within token limits
    return this.optimizeForTokens({
      system,
      context: this.buildContextBlock(context),
      instructions,
      examples,
      tools
    });
  }

  /**
   * Select relevant sections from QA_BRAIN based on task
   */
  private async selectRelevantKnowledge(
    context: PromptContext
  ): Promise<Knowledge[]> {
    const taskType = context.task.type;
    const pageType = context.pageState.classification;

    // Map task types to relevant QA_BRAIN sections
    const sectionMap: Record<TaskType, string[]> = {
      'explore_page': ['Part 2: Page Understanding', 'Part 3: Data Types'],
      'test_form': ['Part 7: Input Validations', 'Part 8: UI Patterns'],
      'verify_navigation': ['Part 5: States & Workflows'],
      'check_accessibility': ['Part 13: Accessibility Testing'],
      'validate_api': ['Part 9: Integration Types', 'Part 19.3: API Contract'],
      'test_edge_case': ['Part 10: Edge Cases'],
      'regression_check': ['Part 34: Exploratory Testing']
    };

    const sections = sectionMap[taskType] || [];

    // Also add page-type specific knowledge
    const pageKnowledge = await this.getPageTypeKnowledge(pageType);

    return [...sections.map(s => this.loadSection(s)), ...pageKnowledge];
  }
}
```

#### 1.4 Conscience (Human-in-the-Loop)

```typescript
/**
 * CONSCIENCE - Manages escalation and human approval
 * Knows when to stop and ask for help
 */

interface ConscienceConfig {
  autoApproveThreshold: number;      // Confidence above this = auto-approve
  escalationTimeout: number;          // Max wait time for human response
  maxAutonomousActions: number;       // Actions before mandatory check-in
  sensitivePatterns: RegExp[];        // Patterns requiring approval
}

interface EscalationRequest {
  id: string;
  type: EscalationType;
  context: EscalationContext;
  question: string;
  options: EscalationOption[];
  recommendation: string;
  urgency: 'low' | 'medium' | 'high' | 'critical';
  timeout: number;
}

type EscalationType =
  | 'low_confidence'
  | 'destructive_action'
  | 'security_sensitive'
  | 'ambiguous_requirement'
  | 'cost_threshold'
  | 'unexpected_state'
  | 'mandatory_checkpoint';

interface EscalationOption {
  id: string;
  label: string;
  description: string;
  action: () => Promise<void>;
}

class Conscience {
  private config: ConscienceConfig;
  private actionCounter: number = 0;
  private escalationQueue: EscalationRequest[] = [];

  /**
   * Check if action requires human approval
   */
  async checkAction(action: PlannedAction): Promise<ApprovalResult> {
    const checks = [
      this.checkConfidence(action),
      this.checkDestructive(action),
      this.checkSensitivity(action),
      this.checkCost(action),
      this.checkMandatoryCheckpoint()
    ];

    const results = await Promise.all(checks);
    const needsApproval = results.some(r => r.needsApproval);

    if (needsApproval) {
      const reason = results.find(r => r.needsApproval)!;
      return this.requestApproval(action, reason);
    }

    this.actionCounter++;
    return { approved: true, automatic: true };
  }

  /**
   * Request human approval for an action
   */
  private async requestApproval(
    action: PlannedAction,
    reason: CheckResult
  ): Promise<ApprovalResult> {
    const request: EscalationRequest = {
      id: generateId(),
      type: reason.type,
      context: {
        currentPage: action.pageUrl,
        recentActions: this.getRecentActions(5),
        taskDescription: action.task.description
      },
      question: this.formulateQuestion(action, reason),
      options: this.generateOptions(action, reason),
      recommendation: this.makeRecommendation(action, reason),
      urgency: this.determineUrgency(reason),
      timeout: this.config.escalationTimeout
    };

    // Emit escalation event for UI/CLI to handle
    this.emit('escalation', request);

    // Wait for response or timeout
    const response = await this.waitForResponse(request);

    return {
      approved: response.approved,
      automatic: false,
      humanFeedback: response.feedback,
      selectedOption: response.selectedOption
    };
  }

  /**
   * Formulate a clear question for the human
   */
  private formulateQuestion(
    action: PlannedAction,
    reason: CheckResult
  ): string {
    const templates: Record<EscalationType, string> = {
      'low_confidence':
        `I'm ${Math.round(action.confidence * 100)}% confident about this action. ` +
        `Should I ${action.description}?`,
      'destructive_action':
        `This action will ${action.description} which cannot be undone. Proceed?`,
      'security_sensitive':
        `This involves security-sensitive data (${reason.details}). ` +
        `Should I continue with ${action.description}?`,
      'ambiguous_requirement':
        `I'm unsure how to interpret "${reason.details}". ` +
        `Which approach should I take?`,
      'cost_threshold':
        `This will use approximately ${reason.estimatedCost} tokens. Continue?`,
      'unexpected_state':
        `The page is in an unexpected state: ${reason.details}. ` +
        `How should I proceed?`,
      'mandatory_checkpoint':
        `I've completed ${this.actionCounter} actions. ` +
        `Here's my progress. Should I continue?`
    };

    return templates[reason.type];
  }
}
```

### 2. Execution Layer

#### 2.1 Agent Loop (ReAct Pattern)

See [AGENT_LOOP.md](./AGENT_LOOP.md) for complete implementation.

#### 2.2 Tool Executor

See [AGENT_TOOLS.md](./AGENT_TOOLS.md) for complete tool definitions.

#### 2.3 Context Manager

See [AGENT_CONTEXT.md](./AGENT_CONTEXT.md) for context management strategies.

#### 2.4 Subagent Spawner

See [AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md) for multi-agent patterns.

### 3. Integration Layer

#### 3.1 Browser Integration (Playwright)

```typescript
/**
 * Browser integration with enhanced capabilities for QA testing
 */

interface BrowserConfig {
  headless: boolean;
  viewport: ViewportConfig;
  timeout: number;
  screenshots: ScreenshotConfig;
  network: NetworkConfig;
}

interface EnhancedPage {
  page: Page;
  mmidMap: Map<string, ElementHandle>;
  domSnapshot: DOMSnapshot;
  networkLog: NetworkRequest[];
  consoleLog: ConsoleMessage[];
}

class BrowserController {
  private browser: Browser;
  private context: BrowserContext;
  private pages: Map<string, EnhancedPage> = new Map();

  /**
   * Navigate and extract DOM with mmid injection
   */
  async navigateAndExtract(url: string): Promise<PageExtraction> {
    const page = await this.getOrCreatePage(url);

    await page.page.goto(url, { waitUntil: 'networkidle' });

    // Inject mmid attributes for element targeting
    const elements = await this.injectMmids(page.page);

    // Extract DOM structure
    const domSnapshot = await this.extractDOM(page.page);

    // Classify page type
    const pageType = await this.classifyPage(domSnapshot);

    // Capture initial state
    const screenshot = await page.page.screenshot({ fullPage: true });

    return {
      url,
      pageType,
      elements,
      domSnapshot,
      screenshot,
      networkLog: page.networkLog,
      consoleLog: page.consoleLog
    };
  }

  /**
   * Inject unique identifiers for element targeting
   */
  private async injectMmids(page: Page): Promise<ExtractedElement[]> {
    return await page.evaluate(() => {
      const selector = [
        'a[href]',
        'button',
        'input:not([type=hidden])',
        'select',
        'textarea',
        '[role=button]',
        '[role=link]',
        '[onclick]',
        '[tabindex]'
      ].join(',');

      const elements = document.querySelectorAll(selector);
      const extracted: ExtractedElement[] = [];

      elements.forEach((el, index) => {
        const mmid = `el-${index}`;
        el.setAttribute('data-mmid', mmid);

        extracted.push({
          mmid,
          tag: el.tagName.toLowerCase(),
          text: el.textContent?.trim().slice(0, 80) || '',
          type: classifyElement(el),
          attributes: extractAttributes(el),
          rect: el.getBoundingClientRect(),
          visible: isVisible(el),
          interactive: isInteractive(el)
        });
      });

      return extracted;
    });
  }
}
```

#### 3.2 LLM Integration

```typescript
/**
 * Multi-model LLM integration with routing
 */

interface LLMConfig {
  models: ModelConfig[];
  defaultModel: string;
  routingRules: RoutingRule[];
  retryConfig: RetryConfig;
  costTracking: boolean;
}

interface ModelConfig {
  id: string;
  provider: 'anthropic' | 'openai' | 'local';
  model: string;
  maxTokens: number;
  costPer1kTokens: number;
  capabilities: string[];
}

interface RoutingRule {
  condition: (task: Task) => boolean;
  model: string;
  reason: string;
}

class LLMRouter {
  private config: LLMConfig;
  private clients: Map<string, LLMClient> = new Map();
  private usageTracker: UsageTracker;

  /**
   * Route request to appropriate model
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    // 1. Determine best model for this request
    const modelId = this.routeRequest(request);
    const client = this.clients.get(modelId)!;

    // 2. Track usage
    const startTokens = this.countTokens(request);
    this.usageTracker.recordRequest(modelId, startTokens);

    // 3. Execute with retry logic
    const response = await this.executeWithRetry(client, request);

    // 4. Track response tokens
    const responseTokens = this.countTokens(response);
    this.usageTracker.recordResponse(modelId, responseTokens);

    return response;
  }

  /**
   * Route based on task characteristics
   */
  private routeRequest(request: ChatRequest): string {
    // Check routing rules in order
    for (const rule of this.config.routingRules) {
      if (rule.condition(request.task)) {
        return rule.model;
      }
    }

    return this.config.defaultModel;
  }
}

// Example routing configuration
const routingRules: RoutingRule[] = [
  {
    condition: (task) => task.type === 'classification',
    model: 'haiku',
    reason: 'Simple classification tasks use cheap model'
  },
  {
    condition: (task) => task.type === 'visual_analysis',
    model: 'gpt-4o',
    reason: 'Visual analysis requires strong vision model'
  },
  {
    condition: (task) => task.complexity === 'high',
    model: 'claude-opus',
    reason: 'Complex reasoning tasks use most capable model'
  },
  {
    condition: (task) => task.type === 'code_generation',
    model: 'claude-sonnet',
    reason: 'Code generation uses balanced model'
  }
];
```

#### 3.3 Storage Integration

```typescript
/**
 * Unified storage interface for all persistence needs
 */

interface StorageConfig {
  sqlite: SQLiteConfig;
  vector: VectorConfig;
  file: FileConfig;
}

class StorageManager {
  private sqlite: Database;
  private vector: VectorStore;
  private fileSystem: FileSystem;

  /**
   * Store test result with all associated data
   */
  async storeTestResult(result: TestResult): Promise<void> {
    // 1. Store structured data in SQLite
    await this.sqlite.run(`
      INSERT INTO test_results (
        id, task_id, page_url, status, duration,
        bug_found, evidence_path, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      result.id,
      result.taskId,
      result.pageUrl,
      result.status,
      result.duration,
      result.bugFound ? 1 : 0,
      result.evidencePath,
      new Date().toISOString()
    ]);

    // 2. Store embeddings for semantic search
    const embedding = await this.embed(result.summary);
    await this.vector.upsert({
      id: result.id,
      vector: embedding,
      metadata: {
        type: 'test_result',
        pageUrl: result.pageUrl,
        status: result.status,
        bugType: result.bugType
      }
    });

    // 3. Store evidence files
    if (result.screenshot) {
      await this.fileSystem.write(
        `evidence/${result.id}/screenshot.png`,
        result.screenshot
      );
    }
    if (result.networkLog) {
      await this.fileSystem.write(
        `evidence/${result.id}/network.json`,
        JSON.stringify(result.networkLog)
      );
    }
  }
}
```

---

## Data Flow

### Complete Request Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           COMPLETE REQUEST FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  USER INPUT                                                                      │
│      │                                                                           │
│      ▼                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  1. INITIALIZATION                                                       │    │
│  │     ├── Load progress.txt (previous session state)                      │    │
│  │     ├── Load QA_BRAIN.md (knowledge base)                               │    │
│  │     ├── Initialize browser context                                       │    │
│  │     └── Run smoke tests (verify environment)                            │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│      │                                                                           │
│      ▼                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  2. PLANNING (Cortex)                                                    │    │
│  │     ├── Analyze target URL/application                                   │    │
│  │     ├── Calculate risk scores                                            │    │
│  │     ├── Generate prioritized test plan                                   │    │
│  │     └── Identify dependencies between tasks                              │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│      │                                                                           │
│      ▼                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  3. EXECUTION LOOP (for each task)                                       │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  a. PROMPT GENERATION (Synapse)                               │    │    │
│  │     │     ├── Select relevant knowledge                             │    │    │
│  │     │     ├── Build context from memory                             │    │    │
│  │     │     └── Generate task-specific prompt                         │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  │                          │                                               │    │
│  │                          ▼                                               │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  b. LLM REASONING                                             │    │    │
│  │     │     ├── Send prompt to appropriate model                      │    │    │
│  │     │     ├── Receive thought + action                              │    │    │
│  │     │     └── Parse tool calls                                      │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  │                          │                                               │    │
│  │                          ▼                                               │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  c. APPROVAL CHECK (Conscience)                               │    │    │
│  │     │     ├── Check confidence threshold                            │    │    │
│  │     │     ├── Check for destructive actions                         │    │    │
│  │     │     └── Escalate if needed                                    │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  │                          │                                               │    │
│  │                          ▼                                               │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  d. TOOL EXECUTION                                            │    │    │
│  │     │     ├── Execute browser actions                               │    │    │
│  │     │     ├── Capture observations                                  │    │    │
│  │     │     └── Handle errors                                         │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  │                          │                                               │    │
│  │                          ▼                                               │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  e. MEMORY UPDATE (Hippocampus)                               │    │    │
│  │     │     ├── Add observation to working memory                     │    │    │
│  │     │     ├── Check for compaction need                             │    │    │
│  │     │     └── Update persistent storage if significant              │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  │                          │                                               │    │
│  │                          ▼                                               │    │
│  │     ┌──────────────────────────────────────────────────────────────┐    │    │
│  │     │  f. LOOP OR COMPLETE?                                         │    │    │
│  │     │     ├── Task complete? → Next task                            │    │    │
│  │     │     ├── Need more actions? → Back to (a)                      │    │    │
│  │     │     └── Plan needs adaptation? → Back to Planning             │    │    │
│  │     └──────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│      │                                                                           │
│      ▼                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  4. FINALIZATION                                                         │    │
│  │     ├── Generate session summary                                         │    │
│  │     ├── Write progress.txt for next session                             │    │
│  │     ├── Commit evidence to git                                           │    │
│  │     └── Output final report                                              │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Architecture

### Single-Machine Deployment

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SINGLE-MACHINE DEPLOYMENT                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                           NODE.JS PROCESS                                │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐               │    │
│  │  │  Agent Core   │  │   Playwright  │  │  LLM Clients  │               │    │
│  │  │  (TypeScript) │  │   (Browser)   │  │  (API calls)  │               │    │
│  │  └───────────────┘  └───────────────┘  └───────────────┘               │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                       │                                          │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                           LOCAL STORAGE                                  │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐               │    │
│  │  │    SQLite     │  │    Qdrant     │  │  File System  │               │    │
│  │  │  (test_db)    │  │  (vectors)    │  │  (evidence)   │               │    │
│  │  └───────────────┘  └───────────────┘  └───────────────┘               │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  External APIs:                                                                  │
│  ├── Anthropic API (Claude)                                                     │
│  ├── OpenAI API (GPT-4o for vision)                                            │
│  └── Target Application (being tested)                                          │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### File Structure

```
qa-agent/
├── src/
│   ├── core/
│   │   ├── agent-loop.ts        # Main execution loop
│   │   ├── cortex.ts            # Planning & prioritization
│   │   ├── hippocampus.ts       # Memory management
│   │   ├── synapse.ts           # Prompt generation
│   │   └── conscience.ts        # Human escalation
│   ├── tools/
│   │   ├── browser/
│   │   │   ├── navigate.ts
│   │   │   ├── click.ts
│   │   │   ├── type.ts
│   │   │   └── extract.ts
│   │   ├── assertions/
│   │   │   ├── assert-visible.ts
│   │   │   ├── assert-text.ts
│   │   │   └── compare-screenshot.ts
│   │   └── analysis/
│   │       ├── accessibility.ts
│   │       ├── performance.ts
│   │       └── security.ts
│   ├── integrations/
│   │   ├── llm/
│   │   │   ├── router.ts
│   │   │   ├── anthropic.ts
│   │   │   └── openai.ts
│   │   ├── storage/
│   │   │   ├── sqlite.ts
│   │   │   ├── vector.ts
│   │   │   └── files.ts
│   │   └── browser/
│   │       └── playwright.ts
│   └── utils/
│       ├── tokens.ts
│       ├── logging.ts
│       └── errors.ts
├── knowledge/
│   ├── QA_BRAIN.md              # Main knowledge base
│   └── prompts/
│       ├── system.md
│       ├── exploration.md
│       └── bug-reporting.md
├── data/
│   ├── test.db                  # SQLite database
│   ├── vectors/                 # Qdrant data
│   └── evidence/                # Screenshots, logs
├── progress.txt                 # Session continuity
└── package.json
```

---

## Next Steps

1. **[AGENT_LOOP.md](./AGENT_LOOP.md)** - Detailed ReAct loop implementation
2. **[AGENT_TOOLS.md](./AGENT_TOOLS.md)** - Complete tool definitions
3. **[AGENT_MEMORY.md](./AGENT_MEMORY.md)** - Memory architecture deep dive
4. **[AGENT_CONTEXT.md](./AGENT_CONTEXT.md)** - Context management strategies
5. **[AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md)** - Multi-agent patterns
6. **[AGENT_PROMPTS.md](./AGENT_PROMPTS.md)** - Prompt engineering
7. **[AGENT_ESCALATION.md](./AGENT_ESCALATION.md)** - Human-in-the-loop patterns
