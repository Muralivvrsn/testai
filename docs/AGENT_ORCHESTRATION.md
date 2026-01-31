# Agent Orchestration & Multi-Agent Patterns

> How to coordinate multiple agents, spawn subagents, and manage parallel execution.

---

## Table of Contents

1. [Orchestration Overview](#orchestration-overview)
2. [Subagent Architecture](#subagent-architecture)
3. [Parallel Execution](#parallel-execution)
4. [Communication Patterns](#communication-patterns)
5. [Task Distribution](#task-distribution)
6. [Error Coordination](#error-coordination)

---

## Orchestration Overview

### Why Multi-Agent?

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     WHY MULTI-AGENT ARCHITECTURE?                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Single Agent Problems:              Multi-Agent Solutions:                      │
│  ┌─────────────────────┐             ┌─────────────────────┐                    │
│  │ • Context limit     │             │ • Each agent has    │                    │
│  │   for complex tasks │             │   focused context   │                    │
│  │ • Serial execution  │             │ • Parallel testing  │                    │
│  │ • One failure =     │             │ • Isolated failures │                    │
│  │   whole task fails  │             │ • Specialized skills│                    │
│  │ • Jack of all trades│             │                     │                    │
│  └─────────────────────┘             └─────────────────────┘                    │
│                                                                                  │
│  Example: Testing a web app                                                      │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         ORCHESTRATOR AGENT                               │    │
│  │                    (Plans, coordinates, synthesizes)                     │    │
│  └──────────────────────────────┬──────────────────────────────────────────┘    │
│                                 │                                                │
│           ┌─────────────────────┼─────────────────────┐                         │
│           ▼                     ▼                     ▼                         │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐               │
│  │  EXPLORER AGENT │   │   FORM TESTER   │   │ A11Y CHECKER    │               │
│  │  (Finds pages,  │   │   (Tests forms, │   │ (Accessibility  │               │
│  │   maps site)    │   │   validations)  │   │  audits)        │               │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘               │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Orchestration Models

```typescript
/**
 * Different orchestration patterns
 */

// 1. HIERARCHICAL: One orchestrator coordinates subagents
interface HierarchicalOrchestration {
  pattern: 'hierarchical';
  orchestrator: {
    role: 'coordinator';
    capabilities: ['planning', 'task_distribution', 'result_synthesis'];
  };
  subagents: {
    role: 'executor';
    capabilities: ['specific_task_execution'];
    reportTo: 'orchestrator';
  }[];
}

// 2. PIPELINE: Agents process in sequence
interface PipelineOrchestration {
  pattern: 'pipeline';
  stages: {
    agent: string;
    input: string;
    output: string;
  }[];
  // explore -> plan -> execute -> report
}

// 3. SWARM: Agents work independently, share findings
interface SwarmOrchestration {
  pattern: 'swarm';
  agents: {
    role: string;
    autonomy: 'full';
    sharedMemory: 'vector_store';
  }[];
  coordination: 'emergent';
}

// 4. HYBRID: Combination based on task
interface HybridOrchestration {
  pattern: 'hybrid';
  orchestrator: 'main_agent';
  subagents: 'spawned_as_needed';
  parallel: 'when_independent';
  sequential: 'when_dependent';
}
```

---

## Subagent Architecture

### Subagent Definition

```typescript
/**
 * Subagent - specialized agent spawned for specific tasks
 */

interface SubagentConfig {
  id: string;
  type: SubagentType;
  systemPrompt: string;
  tools: string[];
  contextLimit: number;
  timeout: number;
  isolation: 'full' | 'shared_memory' | 'shared_browser';
}

type SubagentType =
  | 'explorer'       // Discovers pages and elements
  | 'form_tester'    // Tests form inputs
  | 'navigator'      // Tests navigation flows
  | 'accessibility'  // A11y audits
  | 'performance'    // Performance checks
  | 'security'       // Security testing
  | 'visual'         // Visual regression
  | 'api'            // API testing
  | 'reporter';      // Generates reports

/**
 * Subagent spawner - creates specialized agents
 */

class SubagentSpawner {
  private runningAgents: Map<string, SubagentInstance> = new Map();
  private configs: Map<SubagentType, SubagentConfig>;

  constructor() {
    this.configs = this.loadConfigs();
  }

  /**
   * Spawn a new subagent
   */
  async spawn(
    type: SubagentType,
    task: Task,
    context: SpawnContext
  ): Promise<SubagentInstance> {
    const config = this.configs.get(type);
    if (!config) throw new Error(`Unknown subagent type: ${type}`);

    // Create isolated context for subagent
    const subagentContext = await this.createContext(config, context);

    // Build specialized prompt
    const prompt = this.buildPrompt(config, task);

    // Create agent instance
    const instance: SubagentInstance = {
      id: generateId(),
      type,
      config,
      status: 'running',
      startTime: new Date(),
      task,
      context: subagentContext,
      messages: [{ role: 'system', content: prompt }]
    };

    this.runningAgents.set(instance.id, instance);

    // Start execution in background
    this.execute(instance).catch(error => {
      instance.status = 'failed';
      instance.error = error;
    });

    return instance;
  }

  /**
   * Execute subagent task
   */
  private async execute(instance: SubagentInstance): Promise<SubagentResult> {
    const loop = new AgentLoop({
      config: {
        maxIterations: 20,
        maxTokens: instance.config.contextLimit,
        timeout: instance.config.timeout
      },
      tools: this.getToolsForAgent(instance.config.tools),
      context: instance.context
    });

    try {
      const result = await loop.run(instance.task);
      instance.status = 'completed';
      instance.result = result;
      return result;
    } catch (error) {
      instance.status = 'failed';
      instance.error = error;
      throw error;
    }
  }

  /**
   * Wait for subagent to complete
   */
  async wait(instanceId: string): Promise<SubagentResult> {
    const instance = this.runningAgents.get(instanceId);
    if (!instance) throw new Error(`Unknown agent: ${instanceId}`);

    while (instance.status === 'running') {
      await sleep(100);
    }

    if (instance.status === 'failed') {
      throw instance.error;
    }

    return instance.result!;
  }

  /**
   * Get all results from multiple subagents
   */
  async waitAll(instanceIds: string[]): Promise<SubagentResult[]> {
    return Promise.all(instanceIds.map(id => this.wait(id)));
  }
}
```

### Subagent Types

```typescript
/**
 * Specialized subagent configurations
 */

const SUBAGENT_CONFIGS: Record<SubagentType, SubagentConfig> = {
  explorer: {
    id: 'explorer',
    type: 'explorer',
    systemPrompt: `You are a web exploration agent. Your job is to:
1. Navigate to pages and discover their structure
2. Identify all interactive elements
3. Map out the navigation flow
4. Report findings to the orchestrator

Focus on DISCOVERY, not testing. Report what you find.`,
    tools: ['navigate', 'extractDOM', 'screenshot', 'saveToMemory'],
    contextLimit: 50000,
    timeout: 60000,
    isolation: 'shared_browser'
  },

  form_tester: {
    id: 'form_tester',
    type: 'form_tester',
    systemPrompt: `You are a form testing specialist. Your job is to:
1. Identify form fields and their validation rules
2. Test with valid inputs
3. Test with invalid inputs (empty, wrong format, edge cases)
4. Test with security inputs (XSS, SQL injection)
5. Report validation behavior

Be thorough with edge cases.`,
    tools: ['click', 'type', 'assertText', 'assertVisible', 'generateTestData', 'screenshot', 'logBug'],
    contextLimit: 50000,
    timeout: 120000,
    isolation: 'shared_browser'
  },

  accessibility: {
    id: 'accessibility',
    type: 'accessibility',
    systemPrompt: `You are an accessibility testing specialist. Your job is to:
1. Run axe-core audits
2. Check keyboard navigation
3. Verify screen reader compatibility
4. Check color contrast
5. Verify ARIA attributes

Report all WCAG violations with severity.`,
    tools: ['analyzeAccessibility', 'screenshot', 'logBug', 'saveToMemory'],
    contextLimit: 30000,
    timeout: 60000,
    isolation: 'shared_browser'
  },

  performance: {
    id: 'performance',
    type: 'performance',
    systemPrompt: `You are a performance testing specialist. Your job is to:
1. Measure Core Web Vitals (LCP, FID, CLS)
2. Check resource loading
3. Identify performance bottlenecks
4. Compare against thresholds

Report metrics with recommendations.`,
    tools: ['analyzePerformance', 'screenshot', 'logBug', 'saveToMemory'],
    contextLimit: 30000,
    timeout: 60000,
    isolation: 'shared_browser'
  },

  reporter: {
    id: 'reporter',
    type: 'reporter',
    systemPrompt: `You are a report generation specialist. Your job is to:
1. Synthesize findings from all agents
2. Prioritize issues by severity
3. Generate actionable recommendations
4. Create structured reports

Output should be clear and actionable.`,
    tools: ['recallFromMemory', 'saveToMemory'],
    contextLimit: 100000,
    timeout: 60000,
    isolation: 'full'
  }
};
```

---

## Parallel Execution

### Parallel Task Runner

```typescript
/**
 * Run multiple subagents in parallel
 */

class ParallelExecutor {
  private spawner: SubagentSpawner;
  private maxConcurrency: number;

  constructor(config: { maxConcurrency: number }) {
    this.spawner = new SubagentSpawner();
    this.maxConcurrency = config.maxConcurrency;
  }

  /**
   * Execute tasks in parallel with concurrency limit
   */
  async executeParallel(
    tasks: ParallelTask[]
  ): Promise<ParallelExecutionResult> {
    const results: SubagentResult[] = [];
    const errors: Error[] = [];
    const running: Map<string, Promise<void>> = new Map();

    // Process tasks with concurrency limit
    for (const task of tasks) {
      // Wait if at max concurrency
      while (running.size >= this.maxConcurrency) {
        await Promise.race(running.values());
      }

      // Spawn subagent
      const instance = await this.spawner.spawn(
        task.agentType,
        task.task,
        task.context
      );

      // Track execution
      const execution = this.spawner.wait(instance.id)
        .then(result => {
          results.push(result);
          running.delete(instance.id);
        })
        .catch(error => {
          errors.push(error);
          running.delete(instance.id);
        });

      running.set(instance.id, execution);
    }

    // Wait for all remaining
    await Promise.all(running.values());

    return {
      results,
      errors,
      totalTasks: tasks.length,
      successful: results.length,
      failed: errors.length
    };
  }

  /**
   * Execute tasks across multiple pages in parallel
   */
  async executeAcrossPages(
    pages: string[],
    taskGenerator: (page: string) => ParallelTask[]
  ): Promise<ParallelExecutionResult> {
    const allTasks: ParallelTask[] = [];

    for (const page of pages) {
      const pageTasks = taskGenerator(page);
      allTasks.push(...pageTasks);
    }

    return this.executeParallel(allTasks);
  }
}

interface ParallelTask {
  agentType: SubagentType;
  task: Task;
  context: SpawnContext;
  dependencies?: string[]; // Task IDs that must complete first
}

/**
 * Dependency-aware parallel execution
 */

class DependencyAwareExecutor {
  /**
   * Execute tasks respecting dependencies
   */
  async execute(tasks: ParallelTask[]): Promise<ParallelExecutionResult> {
    const completed = new Set<string>();
    const results: SubagentResult[] = [];
    const taskMap = new Map(tasks.map(t => [t.task.id, t]));

    while (completed.size < tasks.length) {
      // Find tasks ready to run (no pending dependencies)
      const ready = tasks.filter(t =>
        !completed.has(t.task.id) &&
        (t.dependencies || []).every(d => completed.has(d))
      );

      if (ready.length === 0) {
        throw new Error('Circular dependency detected');
      }

      // Run ready tasks in parallel
      const batchResults = await Promise.all(
        ready.map(t => this.spawner.spawn(t.agentType, t.task, t.context)
          .then(i => this.spawner.wait(i.id)))
      );

      // Mark completed
      for (const task of ready) {
        completed.add(task.task.id);
      }
      results.push(...batchResults);
    }

    return {
      results,
      errors: [],
      totalTasks: tasks.length,
      successful: results.length,
      failed: 0
    };
  }
}
```

### Browser Context Sharing

```typescript
/**
 * Share browser context across parallel agents
 */

class SharedBrowserContext {
  private browser: Browser;
  private contexts: Map<string, BrowserContext> = new Map();
  private pages: Map<string, Page> = new Map();

  /**
   * Get or create browser context for an agent
   */
  async getContext(agentId: string, isolation: string): Promise<BrowserContext> {
    if (isolation === 'full') {
      // Fully isolated context
      return this.browser.newContext();
    }

    // Shared context (same cookies, storage)
    const sharedId = 'shared';
    if (!this.contexts.has(sharedId)) {
      this.contexts.set(sharedId, await this.browser.newContext());
    }
    return this.contexts.get(sharedId)!;
  }

  /**
   * Get or create page for an agent
   */
  async getPage(agentId: string, context: BrowserContext): Promise<Page> {
    // Each agent gets its own page
    if (!this.pages.has(agentId)) {
      this.pages.set(agentId, await context.newPage());
    }
    return this.pages.get(agentId)!;
  }

  /**
   * Cleanup agent resources
   */
  async cleanup(agentId: string): Promise<void> {
    const page = this.pages.get(agentId);
    if (page) {
      await page.close();
      this.pages.delete(agentId);
    }
  }
}
```

---

## Communication Patterns

### Inter-Agent Communication

```typescript
/**
 * Communication between agents
 */

interface AgentMessage {
  id: string;
  from: string;
  to: string | 'broadcast';
  type: MessageType;
  payload: any;
  timestamp: Date;
}

type MessageType =
  | 'task_assignment'
  | 'task_result'
  | 'discovery'
  | 'bug_report'
  | 'question'
  | 'answer'
  | 'status_update'
  | 'abort';

class AgentMessageBus {
  private subscribers: Map<string, MessageHandler[]> = new Map();
  private messageQueue: AgentMessage[] = [];

  /**
   * Subscribe to messages
   */
  subscribe(agentId: string, handler: MessageHandler): void {
    const handlers = this.subscribers.get(agentId) || [];
    handlers.push(handler);
    this.subscribers.set(agentId, handlers);
  }

  /**
   * Send message to specific agent
   */
  async send(message: AgentMessage): Promise<void> {
    this.messageQueue.push(message);

    if (message.to === 'broadcast') {
      // Broadcast to all
      for (const [agentId, handlers] of this.subscribers) {
        if (agentId !== message.from) {
          for (const handler of handlers) {
            await handler(message);
          }
        }
      }
    } else {
      // Send to specific agent
      const handlers = this.subscribers.get(message.to) || [];
      for (const handler of handlers) {
        await handler(message);
      }
    }
  }

  /**
   * Wait for response to a message
   */
  async waitForResponse(
    messageId: string,
    timeout: number = 30000
  ): Promise<AgentMessage> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Response timeout'));
      }, timeout);

      const checkResponse = (msg: AgentMessage) => {
        if (msg.type === 'answer' && msg.payload.replyTo === messageId) {
          clearTimeout(timer);
          resolve(msg);
        }
      };

      // Subscribe to all messages temporarily
      const tempId = `temp-${Date.now()}`;
      this.subscribe(tempId, checkResponse);
    });
  }
}

type MessageHandler = (message: AgentMessage) => Promise<void>;
```

### Discovery Sharing

```typescript
/**
 * Share discoveries between agents
 */

class DiscoverySharing {
  private sharedMemory: VectorMemory;
  private messageBus: AgentMessageBus;

  /**
   * Share a discovery with other agents
   */
  async shareDiscovery(
    fromAgent: string,
    discovery: Discovery
  ): Promise<void> {
    // 1. Store in shared memory
    await this.sharedMemory.store({
      id: discovery.id,
      type: 'discovery',
      content: discovery,
      metadata: {
        source: fromAgent,
        timestamp: new Date()
      }
    });

    // 2. Broadcast to other agents
    await this.messageBus.send({
      id: generateId(),
      from: fromAgent,
      to: 'broadcast',
      type: 'discovery',
      payload: {
        discoveryId: discovery.id,
        summary: discovery.summary,
        relevantTo: discovery.relevantAgentTypes
      },
      timestamp: new Date()
    });
  }

  /**
   * Query relevant discoveries for a task
   */
  async getRelevantDiscoveries(
    agentType: SubagentType,
    taskContext: string
  ): Promise<Discovery[]> {
    const results = await this.sharedMemory.search(taskContext, {
      limit: 10,
      filter: { type: 'discovery' }
    });

    return results
      .filter(r => r.content.relevantAgentTypes.includes(agentType))
      .map(r => r.content);
  }
}

interface Discovery {
  id: string;
  type: DiscoveryType;
  summary: string;
  details: any;
  relevantAgentTypes: SubagentType[];
  pageUrl?: string;
  elements?: string[];
}

type DiscoveryType =
  | 'new_page'
  | 'form_found'
  | 'bug_found'
  | 'pattern_identified'
  | 'blocker';
```

---

## Task Distribution

### Orchestrator Implementation

```typescript
/**
 * Main orchestrator agent
 */

class OrchestratorAgent {
  private spawner: SubagentSpawner;
  private parallel: ParallelExecutor;
  private messageBus: AgentMessageBus;
  private cortex: Cortex;

  /**
   * Execute a complete testing session
   */
  async execute(config: TestConfig): Promise<TestSessionResult> {
    // 1. PLANNING PHASE
    console.log('Phase 1: Planning');
    const plan = await this.planSession(config);

    // 2. EXPLORATION PHASE
    console.log('Phase 2: Exploration');
    const siteMap = await this.exploreSite(config.targetUrl);

    // 3. TASK DISTRIBUTION PHASE
    console.log('Phase 3: Distribution');
    const distribution = await this.distributeTasks(plan, siteMap);

    // 4. EXECUTION PHASE
    console.log('Phase 4: Execution');
    const results = await this.executeDistribution(distribution);

    // 5. SYNTHESIS PHASE
    console.log('Phase 5: Synthesis');
    const report = await this.synthesizeResults(results);

    return report;
  }

  /**
   * Plan the testing session
   */
  private async planSession(config: TestConfig): Promise<TestPlan> {
    return this.cortex.generatePlan({
      targetUrl: config.targetUrl,
      testTypes: config.testTypes,
      coverage: config.coverageGoal,
      priorities: config.priorities
    });
  }

  /**
   * Explore the site to map pages and elements
   */
  private async exploreSite(url: string): Promise<SiteMap> {
    const explorer = await this.spawner.spawn('explorer', {
      id: 'explore-main',
      description: `Explore and map the site at ${url}`,
      type: 'exploration'
    }, { startUrl: url });

    const result = await this.spawner.wait(explorer.id);
    return result.output as SiteMap;
  }

  /**
   * Distribute tasks to appropriate agents
   */
  private async distributeTasks(
    plan: TestPlan,
    siteMap: SiteMap
  ): Promise<TaskDistribution> {
    const distribution: TaskDistribution = {
      parallel: [],
      sequential: []
    };

    for (const task of plan.tasks) {
      // Determine best agent type for task
      const agentType = this.selectAgentType(task);

      // Check if task can run in parallel
      const canParallel = this.canRunParallel(task, plan.tasks);

      const taskAssignment: TaskAssignment = {
        task,
        agentType,
        pages: this.getPagesForTask(task, siteMap),
        priority: task.priority
      };

      if (canParallel) {
        distribution.parallel.push(taskAssignment);
      } else {
        distribution.sequential.push(taskAssignment);
      }
    }

    return distribution;
  }

  /**
   * Execute the task distribution
   */
  private async executeDistribution(
    distribution: TaskDistribution
  ): Promise<ExecutionResults> {
    const results: SubagentResult[] = [];

    // Run parallel tasks
    if (distribution.parallel.length > 0) {
      const parallelResults = await this.parallel.executeParallel(
        distribution.parallel.map(a => ({
          agentType: a.agentType,
          task: a.task,
          context: { pages: a.pages }
        }))
      );
      results.push(...parallelResults.results);
    }

    // Run sequential tasks
    for (const assignment of distribution.sequential) {
      const instance = await this.spawner.spawn(
        assignment.agentType,
        assignment.task,
        { pages: assignment.pages }
      );
      const result = await this.spawner.wait(instance.id);
      results.push(result);
    }

    return { results };
  }

  /**
   * Select best agent type for a task
   */
  private selectAgentType(task: Task): SubagentType {
    const typeMap: Record<string, SubagentType> = {
      'explore_page': 'explorer',
      'test_form': 'form_tester',
      'check_accessibility': 'accessibility',
      'check_performance': 'performance',
      'test_security': 'security',
      'visual_regression': 'visual',
      'test_api': 'api'
    };

    return typeMap[task.type] || 'form_tester';
  }
}
```

### Load Balancing

```typescript
/**
 * Distribute load across agents
 */

class LoadBalancer {
  private agentLoad: Map<string, number> = new Map();
  private maxLoadPerAgent: number;

  constructor(config: { maxLoadPerAgent: number }) {
    this.maxLoadPerAgent = config.maxLoadPerAgent;
  }

  /**
   * Assign task to least loaded agent
   */
  assign(
    task: Task,
    availableAgents: SubagentInstance[]
  ): SubagentInstance | null {
    // Sort by current load
    const sorted = [...availableAgents].sort((a, b) => {
      const loadA = this.agentLoad.get(a.id) || 0;
      const loadB = this.agentLoad.get(b.id) || 0;
      return loadA - loadB;
    });

    // Find agent with capacity
    for (const agent of sorted) {
      const currentLoad = this.agentLoad.get(agent.id) || 0;
      if (currentLoad < this.maxLoadPerAgent) {
        this.agentLoad.set(agent.id, currentLoad + 1);
        return agent;
      }
    }

    return null; // All agents at capacity
  }

  /**
   * Release load when task completes
   */
  release(agentId: string): void {
    const currentLoad = this.agentLoad.get(agentId) || 0;
    this.agentLoad.set(agentId, Math.max(0, currentLoad - 1));
  }
}
```

---

## Error Coordination

### Failure Handling

```typescript
/**
 * Coordinate error handling across agents
 */

class ErrorCoordinator {
  private messageBus: AgentMessageBus;
  private orchestrator: OrchestratorAgent;

  /**
   * Handle agent failure
   */
  async handleAgentFailure(
    agentId: string,
    error: Error,
    context: FailureContext
  ): Promise<RecoveryAction> {
    // 1. Assess failure severity
    const severity = this.assessSeverity(error, context);

    // 2. Determine recovery strategy
    switch (severity) {
      case 'recoverable':
        return this.retryAgent(agentId, context);

      case 'redistribute':
        return this.redistributeTask(context.task);

      case 'skip':
        return this.skipTask(context.task, error);

      case 'abort':
        return this.abortSession(error);
    }
  }

  /**
   * Assess failure severity
   */
  private assessSeverity(error: Error, context: FailureContext): Severity {
    // Timeout errors - retry
    if (error.message.includes('timeout')) {
      return context.retryCount < 3 ? 'recoverable' : 'redistribute';
    }

    // Network errors - retry
    if (error.message.includes('network') || error.message.includes('ECONNRESET')) {
      return context.retryCount < 3 ? 'recoverable' : 'redistribute';
    }

    // Element not found - might be page-specific, redistribute
    if (error.message.includes('not found')) {
      return 'redistribute';
    }

    // Critical errors - abort
    if (error.message.includes('FATAL') || error.message.includes('authentication')) {
      return 'abort';
    }

    // Default - skip and continue
    return 'skip';
  }

  /**
   * Retry the same agent
   */
  private async retryAgent(
    agentId: string,
    context: FailureContext
  ): Promise<RecoveryAction> {
    // Wait before retry (exponential backoff)
    await sleep(Math.pow(2, context.retryCount) * 1000);

    // Respawn agent with same task
    return {
      action: 'retry',
      details: { agentId, retryCount: context.retryCount + 1 }
    };
  }

  /**
   * Redistribute task to different agent
   */
  private async redistributeTask(task: Task): Promise<RecoveryAction> {
    // Broadcast task available
    await this.messageBus.send({
      id: generateId(),
      from: 'coordinator',
      to: 'broadcast',
      type: 'task_assignment',
      payload: { task, reassigned: true },
      timestamp: new Date()
    });

    return {
      action: 'redistribute',
      details: { taskId: task.id }
    };
  }

  /**
   * Skip task and continue
   */
  private skipTask(task: Task, error: Error): RecoveryAction {
    console.warn(`Skipping task ${task.id}: ${error.message}`);
    return {
      action: 'skip',
      details: { taskId: task.id, reason: error.message }
    };
  }

  /**
   * Abort entire session
   */
  private async abortSession(error: Error): Promise<RecoveryAction> {
    // Notify all agents to stop
    await this.messageBus.send({
      id: generateId(),
      from: 'coordinator',
      to: 'broadcast',
      type: 'abort',
      payload: { reason: error.message },
      timestamp: new Date()
    });

    return {
      action: 'abort',
      details: { reason: error.message }
    };
  }
}

type Severity = 'recoverable' | 'redistribute' | 'skip' | 'abort';

interface RecoveryAction {
  action: string;
  details: Record<string, any>;
}
```

---

## Orchestration Best Practices

### When to Use Subagents

| Use Subagent When | Don't Use When |
|---|---|
| Task requires specialized skills | Task is simple and quick |
| Need parallel execution | Tasks have tight dependencies |
| Task might fail/timeout | Need tight coordination |
| Context isolation helps | Shared state is essential |
| Different tool requirements | Tools overlap significantly |

### Performance Considerations

```typescript
const ORCHESTRATION_GUIDELINES = {
  // Concurrency
  maxConcurrentAgents: 5,         // Balance with resources
  maxAgentsPerPage: 2,            // Avoid conflicts

  // Timeouts
  agentTimeout: 120000,           // 2 minutes per agent
  communicationTimeout: 5000,     // 5 seconds for messages

  // Memory
  sharedMemorySize: '1GB',        // Vector store limit
  contextPerAgent: 50000,         // Tokens per subagent

  // Recovery
  maxRetries: 3,                  // Per agent
  retryBackoff: 'exponential',    // Backoff strategy

  // Cleanup
  cleanupOnComplete: true,        // Close browsers/contexts
  preserveEvidence: true          // Keep screenshots/logs
};
```

---

## Next Steps

- **[AGENT_PROMPTS.md](./AGENT_PROMPTS.md)** - Prompt engineering for agents
- **[AGENT_ESCALATION.md](./AGENT_ESCALATION.md)** - Human-in-the-loop patterns
