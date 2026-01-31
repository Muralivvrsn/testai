# Agent Execution Loop (ReAct Pattern)

> Deep dive into the core execution loop that powers the autonomous QA agent - the Reason + Act (ReAct) pattern implementation.

---

## Table of Contents

1. [ReAct Pattern Overview](#react-pattern-overview)
2. [Loop Implementation](#loop-implementation)
3. [Thought-Action-Observation Cycle](#thought-action-observation-cycle)
4. [Error Handling & Recovery](#error-handling--recovery)
5. [Loop Termination Conditions](#loop-termination-conditions)
6. [Performance Optimization](#performance-optimization)

---

## ReAct Pattern Overview

### What is ReAct?

ReAct (Reasoning and Acting) is a prompting paradigm that interleaves reasoning traces with action execution. The agent:

1. **Thinks** about what to do (reasoning)
2. **Acts** using available tools (action)
3. **Observes** the result (observation)
4. **Repeats** until task is complete

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ReAct LOOP PATTERN                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│     ┌────────────────────────────────────────────────────────────────────┐      │
│     │                                                                     │      │
│     │    ┌──────────┐         ┌──────────┐         ┌──────────┐         │      │
│     │    │          │         │          │         │          │         │      │
│     │    │  THOUGHT │────────▶│  ACTION  │────────▶│OBSERVATION│        │      │
│     │    │          │         │          │         │          │         │      │
│     │    └──────────┘         └──────────┘         └──────────┘         │      │
│     │          │                                         │               │      │
│     │          │                                         │               │      │
│     │          │    ┌────────────────────────────────────┘               │      │
│     │          │    │                                                    │      │
│     │          │    │    Not Done                                        │      │
│     │          │    │                                                    │      │
│     │          ▼    ▼                                                    │      │
│     │    ┌──────────┐                                                    │      │
│     │    │          │                                                    │      │
│     │    │   DONE?  │─────── Yes ──────▶ RETURN RESULT                  │      │
│     │    │          │                                                    │      │
│     │    └──────────┘                                                    │      │
│     │                                                                     │      │
│     └────────────────────────────────────────────────────────────────────┘      │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why ReAct for QA Testing?

| Benefit | Description |
|---------|-------------|
| **Transparency** | Every decision is visible - crucial for debugging and auditing |
| **Grounding** | Actions are based on real observations, reducing hallucinations |
| **Adaptability** | Can adjust strategy based on what's actually found |
| **Reliability** | Failures are isolated to specific steps, not the whole task |
| **Human-like** | Mimics how human testers think through problems |

---

## Loop Implementation

### Core Loop Structure

```typescript
/**
 * Core ReAct Agent Loop Implementation
 * This is the heart of the autonomous QA agent
 */

interface AgentLoopConfig {
  maxIterations: number;          // Prevent infinite loops
  maxTokensPerIteration: number;  // Cost control
  timeoutMs: number;              // Overall timeout
  retryAttempts: number;          // Retries per tool call
  verbose: boolean;               // Detailed logging
}

interface LoopState {
  iteration: number;
  messages: Message[];
  toolResults: ToolResult[];
  observations: Observation[];
  totalTokensUsed: number;
  startTime: Date;
  status: 'running' | 'completed' | 'failed' | 'timeout' | 'escalated';
}

interface AgentLoopResult {
  success: boolean;
  finalAnswer: string | null;
  iterations: number;
  tokensUsed: number;
  duration: number;
  toolsUsed: string[];
  errors: Error[];
  escalations: Escalation[];
}

class AgentLoop {
  private config: AgentLoopConfig;
  private llm: LLMRouter;
  private tools: ToolRegistry;
  private conscience: Conscience;
  private hippocampus: Hippocampus;
  private synapse: Synapse;
  private logger: Logger;

  constructor(dependencies: AgentDependencies) {
    this.config = dependencies.config;
    this.llm = dependencies.llm;
    this.tools = dependencies.tools;
    this.conscience = dependencies.conscience;
    this.hippocampus = dependencies.hippocampus;
    this.synapse = dependencies.synapse;
    this.logger = dependencies.logger;
  }

  /**
   * Main execution loop
   */
  async run(task: Task): Promise<AgentLoopResult> {
    const state: LoopState = {
      iteration: 0,
      messages: [],
      toolResults: [],
      observations: [],
      totalTokensUsed: 0,
      startTime: new Date(),
      status: 'running'
    };

    // Initialize with task context
    await this.initialize(task, state);

    try {
      // Main loop
      while (this.shouldContinue(state)) {
        state.iteration++;
        this.logger.debug(`Starting iteration ${state.iteration}`);

        // 1. GENERATE THOUGHT + ACTION
        const response = await this.think(state);

        // 2. CHECK IF DONE
        if (this.isComplete(response)) {
          state.status = 'completed';
          return this.buildResult(state, response.content);
        }

        // 3. VALIDATE AND EXECUTE ACTIONS
        for (const toolCall of response.toolCalls) {
          // 3a. Check with conscience
          const approval = await this.conscience.checkAction({
            tool: toolCall.name,
            arguments: toolCall.arguments,
            confidence: response.confidence
          });

          if (!approval.approved) {
            if (approval.escalated) {
              state.status = 'escalated';
              return this.buildResult(state, null, approval.escalation);
            }
            continue; // Skip this action
          }

          // 3b. Execute the tool
          const result = await this.executeTool(toolCall);

          // 3c. Add observation to state
          state.toolResults.push(result);
          state.observations.push(this.buildObservation(toolCall, result));

          // 3d. Update memory
          await this.hippocampus.store({
            type: 'tool_result',
            data: result,
            timestamp: new Date()
          });
        }

        // 4. UPDATE MESSAGES WITH OBSERVATIONS
        this.updateMessages(state, response, state.observations);

        // 5. CHECK CONTEXT LIMITS
        if (this.approachingContextLimit(state)) {
          await this.compactContext(state);
        }
      }

      // Loop terminated without completion
      state.status = 'timeout';
      return this.buildResult(state, null);

    } catch (error) {
      state.status = 'failed';
      this.logger.error('Agent loop failed', error);
      return this.buildResult(state, null, null, error);
    }
  }

  /**
   * Initialize loop state with task context
   */
  private async initialize(task: Task, state: LoopState): Promise<void> {
    // 1. Generate initial prompt
    const prompt = await this.synapse.generatePrompt({
      task,
      pageState: null,
      recentHistory: [],
      relevantKnowledge: await this.hippocampus.recall({ task }),
      constraints: task.constraints || []
    });

    // 2. Build initial messages
    state.messages = [
      {
        role: 'system',
        content: prompt.system
      },
      {
        role: 'user',
        content: this.buildTaskMessage(task, prompt)
      }
    ];

    // 3. Log initialization
    this.logger.info('Agent loop initialized', {
      task: task.description,
      tools: this.tools.getAvailableTools().map(t => t.name)
    });
  }

  /**
   * Generate thought and action via LLM
   */
  private async think(state: LoopState): Promise<LLMResponse> {
    const startTime = Date.now();

    const response = await this.llm.chat({
      messages: state.messages,
      tools: this.tools.getToolDefinitions(),
      task: { complexity: this.estimateComplexity(state) }
    });

    const duration = Date.now() - startTime;
    state.totalTokensUsed += response.usage.totalTokens;

    this.logger.debug('LLM response received', {
      iteration: state.iteration,
      hasToolCalls: response.toolCalls.length > 0,
      tokens: response.usage.totalTokens,
      duration
    });

    return response;
  }
}
```

### Detailed Step Implementations

#### Step 1: Thought Generation

```typescript
/**
 * The thinking phase - where the agent reasons about what to do
 */

interface ThoughtProcess {
  analysis: string;         // Understanding of current situation
  goal: string;             // What we're trying to achieve
  options: string[];        // Possible actions
  selectedAction: string;   // Chosen action with reasoning
  confidence: number;       // How confident in this choice
}

class ThoughtGenerator {
  /**
   * Parse structured thought from LLM response
   */
  parseThought(response: string): ThoughtProcess {
    // Extract thought components using markers
    const thoughtRegex = /Thought:\s*([\s\S]*?)(?=Action:|$)/i;
    const analysisRegex = /Analysis:\s*([\s\S]*?)(?=Goal:|Options:|$)/i;
    const goalRegex = /Goal:\s*([\s\S]*?)(?=Options:|Action:|$)/i;

    const thoughtMatch = response.match(thoughtRegex);
    const analysisMatch = response.match(analysisRegex);
    const goalMatch = response.match(goalRegex);

    return {
      analysis: analysisMatch?.[1]?.trim() || '',
      goal: goalMatch?.[1]?.trim() || '',
      options: this.extractOptions(response),
      selectedAction: this.extractSelectedAction(response),
      confidence: this.extractConfidence(response)
    };
  }

  /**
   * Validate thought quality
   */
  validateThought(thought: ThoughtProcess): ValidationResult {
    const issues: string[] = [];

    if (!thought.analysis) {
      issues.push('Missing situation analysis');
    }

    if (!thought.goal) {
      issues.push('Missing goal statement');
    }

    if (thought.confidence < 0.3) {
      issues.push('Very low confidence - may need human input');
    }

    return {
      valid: issues.length === 0,
      issues,
      suggestions: this.generateSuggestions(issues)
    };
  }
}
```

#### Step 2: Action Parsing

```typescript
/**
 * Parse and validate tool calls from LLM response
 */

interface ParsedAction {
  id: string;
  tool: string;
  arguments: Record<string, any>;
  reasoning: string;
}

class ActionParser {
  private tools: ToolRegistry;

  /**
   * Parse tool calls from LLM response
   */
  parseActions(response: LLMResponse): ParsedAction[] {
    const actions: ParsedAction[] = [];

    for (const toolCall of response.toolCalls) {
      // Validate tool exists
      const tool = this.tools.get(toolCall.name);
      if (!tool) {
        this.logger.warn(`Unknown tool: ${toolCall.name}`);
        continue;
      }

      // Validate arguments
      const validation = this.validateArguments(tool, toolCall.arguments);
      if (!validation.valid) {
        this.logger.warn(`Invalid arguments for ${toolCall.name}`, validation.errors);
        continue;
      }

      actions.push({
        id: toolCall.id,
        tool: toolCall.name,
        arguments: this.normalizeArguments(tool, toolCall.arguments),
        reasoning: this.extractReasoning(response, toolCall)
      });
    }

    return actions;
  }

  /**
   * Validate tool arguments against schema
   */
  private validateArguments(
    tool: Tool,
    args: Record<string, any>
  ): ValidationResult {
    const errors: string[] = [];

    // Check required parameters
    for (const param of tool.parameters) {
      if (param.required && !(param.name in args)) {
        errors.push(`Missing required parameter: ${param.name}`);
      }
    }

    // Check parameter types
    for (const [name, value] of Object.entries(args)) {
      const param = tool.parameters.find(p => p.name === name);
      if (!param) {
        errors.push(`Unknown parameter: ${name}`);
        continue;
      }

      if (!this.checkType(value, param.type)) {
        errors.push(`Invalid type for ${name}: expected ${param.type}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}
```

#### Step 3: Tool Execution

```typescript
/**
 * Execute tools with error handling and retry logic
 */

interface ExecutionResult {
  success: boolean;
  output: any;
  error?: Error;
  duration: number;
  retries: number;
}

class ToolExecutor {
  private config: ExecutorConfig;
  private tools: ToolRegistry;
  private rateLimiter: RateLimiter;

  /**
   * Execute a single tool call with retries
   */
  async execute(action: ParsedAction): Promise<ExecutionResult> {
    const tool = this.tools.get(action.tool);
    const startTime = Date.now();
    let lastError: Error | undefined;
    let retries = 0;

    // Rate limiting
    await this.rateLimiter.acquire(action.tool);

    while (retries <= this.config.maxRetries) {
      try {
        // Execute with timeout
        const output = await this.executeWithTimeout(
          tool,
          action.arguments,
          this.config.timeoutMs
        );

        return {
          success: true,
          output,
          duration: Date.now() - startTime,
          retries
        };

      } catch (error) {
        lastError = error as Error;
        retries++;

        // Check if error is retryable
        if (!this.isRetryable(error)) {
          break;
        }

        // Exponential backoff
        await this.delay(Math.pow(2, retries) * 100);
      }
    }

    return {
      success: false,
      output: null,
      error: lastError,
      duration: Date.now() - startTime,
      retries
    };
  }

  /**
   * Execute tool with timeout wrapper
   */
  private async executeWithTimeout(
    tool: Tool,
    args: Record<string, any>,
    timeoutMs: number
  ): Promise<any> {
    return Promise.race([
      tool.execute(args),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Tool execution timeout')), timeoutMs)
      )
    ]);
  }

  /**
   * Determine if error is retryable
   */
  private isRetryable(error: Error): boolean {
    const retryablePatterns = [
      /timeout/i,
      /network/i,
      /ECONNRESET/i,
      /rate limit/i,
      /temporarily unavailable/i
    ];

    return retryablePatterns.some(pattern => pattern.test(error.message));
  }
}
```

#### Step 4: Observation Building

```typescript
/**
 * Build structured observations from tool results
 */

interface Observation {
  id: string;
  toolId: string;
  toolName: string;
  timestamp: Date;
  success: boolean;
  summary: string;
  details: any;
  implications: string[];
  suggestedNextSteps: string[];
}

class ObservationBuilder {
  /**
   * Build observation from tool execution result
   */
  build(action: ParsedAction, result: ExecutionResult): Observation {
    const observation: Observation = {
      id: generateId(),
      toolId: action.id,
      toolName: action.tool,
      timestamp: new Date(),
      success: result.success,
      summary: this.summarize(action, result),
      details: result.output,
      implications: this.analyzeImplications(action, result),
      suggestedNextSteps: this.suggestNextSteps(action, result)
    };

    return observation;
  }

  /**
   * Generate human-readable summary
   */
  private summarize(action: ParsedAction, result: ExecutionResult): string {
    if (!result.success) {
      return `Failed to ${action.tool}: ${result.error?.message}`;
    }

    // Tool-specific summaries
    switch (action.tool) {
      case 'navigate':
        return `Navigated to ${action.arguments.url}. Page loaded successfully.`;

      case 'click':
        return `Clicked element "${action.arguments.selector}". ` +
               `${result.output.triggered ? 'Action triggered.' : 'No visible change.'}`;

      case 'extractDOM':
        return `Extracted ${result.output.elementCount} interactive elements. ` +
               `Page type: ${result.output.pageType}.`;

      case 'assertVisible':
        return result.output.visible
          ? `Element "${action.arguments.selector}" is visible as expected.`
          : `Element "${action.arguments.selector}" is NOT visible (potential bug).`;

      case 'screenshot':
        return `Captured screenshot: ${result.output.path}`;

      default:
        return `Executed ${action.tool} successfully.`;
    }
  }

  /**
   * Analyze implications of the result
   */
  private analyzeImplications(
    action: ParsedAction,
    result: ExecutionResult
  ): string[] {
    const implications: string[] = [];

    if (!result.success) {
      implications.push('Action failed - may need alternative approach');
      implications.push('Check if element exists and is interactable');
      return implications;
    }

    // Tool-specific implications
    switch (action.tool) {
      case 'navigate':
        if (result.output.redirected) {
          implications.push(`Page redirected to ${result.output.finalUrl}`);
        }
        if (result.output.slowLoad) {
          implications.push('Page loaded slowly - potential performance issue');
        }
        break;

      case 'click':
        if (result.output.navigationTriggered) {
          implications.push('Click caused navigation - need to re-extract DOM');
        }
        if (result.output.modalOpened) {
          implications.push('Modal/dialog opened - may need to interact with it');
        }
        break;

      case 'assertVisible':
        if (!result.output.visible) {
          implications.push('POTENTIAL BUG: Expected element not visible');
          implications.push('Capture screenshot for evidence');
        }
        break;
    }

    return implications;
  }
}
```

---

## Thought-Action-Observation Cycle

### Message Format

```typescript
/**
 * Message formats for the ReAct loop
 */

// System message template
const SYSTEM_MESSAGE = `
You are an autonomous QA testing agent. You test web applications by:
1. THINKING about what to test and why
2. ACTING using the available tools
3. OBSERVING the results
4. REPEATING until the task is complete

For each step, structure your response as:

Thought: [Your reasoning about the current situation and what to do next]
Action: [The tool you want to use]
Action Input: [The arguments for the tool as JSON]

When you have enough information to complete the task, respond with:

Thought: [Summary of findings]
Final Answer: [Your conclusion or report]

Available tools:
{tools}

Current task: {task}
`;

// Observation message template
const OBSERVATION_MESSAGE = `
Observation from {tool_name}:
{summary}

Details:
{details}

Implications:
{implications}
`;

// Example conversation flow
const exampleMessages: Message[] = [
  {
    role: 'system',
    content: SYSTEM_MESSAGE
  },
  {
    role: 'user',
    content: 'Test the login form on https://example.com/login'
  },
  {
    role: 'assistant',
    content: `
Thought: I need to first navigate to the login page and understand its structure.
I'll extract the DOM to identify the form elements.

Action: navigate
Action Input: {"url": "https://example.com/login"}
`
  },
  {
    role: 'tool',
    tool_call_id: 'call_1',
    content: `
Observation from navigate:
Navigated to https://example.com/login. Page loaded successfully.

Details:
- Load time: 1.2s
- Status: 200
- Title: "Login - Example App"

Implications:
- Page loaded normally
- Ready for DOM extraction
`
  },
  {
    role: 'assistant',
    content: `
Thought: The page loaded successfully. Now I need to extract the DOM to find
the login form elements (username/email field, password field, submit button).

Action: extractDOM
Action Input: {}
`
  },
  {
    role: 'tool',
    tool_call_id: 'call_2',
    content: `
Observation from extractDOM:
Extracted 15 interactive elements. Page type: login.

Details:
- input#email (email input)
- input#password (password input)
- button#submit (submit button)
- a.forgot-password (link)
- a.signup (link)

Implications:
- Standard login form identified
- Has email and password fields
- Has submit button
`
  },
  {
    role: 'assistant',
    content: `
Thought: I've identified the login form structure. Now I should test:
1. Empty submission (should show validation errors)
2. Invalid email format
3. Valid credentials (if test account available)

Let me start with testing empty submission.

Action: click
Action Input: {"selector": "button#submit"}
`
  }
  // ... continues
];
```

### State Machine View

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AGENT STATE MACHINE                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│                              ┌────────────┐                                      │
│                              │            │                                      │
│              ┌───────────────│   IDLE     │                                      │
│              │               │            │                                      │
│              │               └─────┬──────┘                                      │
│              │                     │                                             │
│              │                     │ Task received                               │
│              │                     ▼                                             │
│              │               ┌────────────┐                                      │
│              │               │            │                                      │
│              │               │ INITIALIZING│                                     │
│              │               │            │                                      │
│              │               └─────┬──────┘                                      │
│              │                     │                                             │
│              │                     │ Context loaded                              │
│              │                     ▼                                             │
│              │               ┌────────────┐                                      │
│              │    Timeout    │            │◀─────────────────────┐               │
│              │◀──────────────│  THINKING  │                      │               │
│              │               │            │                      │               │
│              │               └─────┬──────┘                      │               │
│              │                     │                             │               │
│              │                     │ Tool call                   │ Observation   │
│              │                     ▼                             │ received      │
│              │               ┌────────────┐                      │               │
│              │    Error      │            │                      │               │
│              │◀──────────────│  EXECUTING │──────────────────────┘               │
│              │               │            │                                      │
│              │               └─────┬──────┘                                      │
│              │                     │                                             │
│              │                     │ Needs approval                              │
│              │                     ▼                                             │
│              │               ┌────────────┐                                      │
│              │    Rejected   │            │                                      │
│              │◀──────────────│ ESCALATING │                                      │
│              │               │            │                                      │
│              │               └─────┬──────┘                                      │
│              │                     │                                             │
│              │                     │ Approved                                    │
│              │                     ▼                                             │
│              │               ┌────────────┐                                      │
│              └──────────────▶│            │                                      │
│                              │ COMPLETED  │                                      │
│                              │            │                                      │
│                              └────────────┘                                      │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Error Handling & Recovery

### Error Categories

```typescript
/**
 * Comprehensive error handling for the agent loop
 */

enum ErrorCategory {
  // Recoverable errors - retry or adapt
  TOOL_TIMEOUT = 'TOOL_TIMEOUT',
  NETWORK_ERROR = 'NETWORK_ERROR',
  ELEMENT_NOT_FOUND = 'ELEMENT_NOT_FOUND',
  RATE_LIMITED = 'RATE_LIMITED',

  // Requires adaptation - try different approach
  PAGE_CHANGED = 'PAGE_CHANGED',
  UNEXPECTED_STATE = 'UNEXPECTED_STATE',
  ASSERTION_FAILED = 'ASSERTION_FAILED',

  // Requires escalation - ask human
  AMBIGUOUS_SITUATION = 'AMBIGUOUS_SITUATION',
  SECURITY_CONCERN = 'SECURITY_CONCERN',
  COST_THRESHOLD = 'COST_THRESHOLD',

  // Fatal errors - stop execution
  INVALID_CONFIGURATION = 'INVALID_CONFIGURATION',
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  CONTEXT_EXHAUSTED = 'CONTEXT_EXHAUSTED'
}

interface ErrorHandler {
  category: ErrorCategory;
  canRecover: boolean;
  maxRetries: number;
  handler: (error: Error, context: ErrorContext) => Promise<RecoveryAction>;
}

class ErrorManager {
  private handlers: Map<ErrorCategory, ErrorHandler> = new Map();

  constructor() {
    this.registerDefaultHandlers();
  }

  /**
   * Handle an error based on its category
   */
  async handle(error: Error, context: ErrorContext): Promise<RecoveryAction> {
    const category = this.categorize(error);
    const handler = this.handlers.get(category);

    if (!handler) {
      return { action: 'abort', reason: 'Unknown error category' };
    }

    // Check retry count
    if (context.retryCount >= handler.maxRetries) {
      return { action: 'escalate', reason: 'Max retries exceeded' };
    }

    return handler.handler(error, context);
  }

  /**
   * Register default error handlers
   */
  private registerDefaultHandlers(): void {
    // Tool timeout - retry with longer timeout
    this.handlers.set(ErrorCategory.TOOL_TIMEOUT, {
      category: ErrorCategory.TOOL_TIMEOUT,
      canRecover: true,
      maxRetries: 3,
      handler: async (error, context) => ({
        action: 'retry',
        modifications: { timeout: context.originalTimeout * 2 }
      })
    });

    // Element not found - try alternative selectors
    this.handlers.set(ErrorCategory.ELEMENT_NOT_FOUND, {
      category: ErrorCategory.ELEMENT_NOT_FOUND,
      canRecover: true,
      maxRetries: 3,
      handler: async (error, context) => {
        const alternatives = await this.findAlternativeSelectors(context);
        if (alternatives.length > 0) {
          return {
            action: 'retry',
            modifications: { selector: alternatives[0] }
          };
        }
        return { action: 'skip', reason: 'No alternative selectors found' };
      }
    });

    // Page changed - re-extract DOM and adapt
    this.handlers.set(ErrorCategory.PAGE_CHANGED, {
      category: ErrorCategory.PAGE_CHANGED,
      canRecover: true,
      maxRetries: 2,
      handler: async (error, context) => ({
        action: 'adapt',
        newTask: 're-extract DOM and update plan'
      })
    });

    // Ambiguous situation - escalate to human
    this.handlers.set(ErrorCategory.AMBIGUOUS_SITUATION, {
      category: ErrorCategory.AMBIGUOUS_SITUATION,
      canRecover: false,
      maxRetries: 0,
      handler: async (error, context) => ({
        action: 'escalate',
        question: `Encountered ambiguous situation: ${error.message}`,
        options: context.possibleActions
      })
    });
  }
}
```

### Recovery Strategies

```typescript
/**
 * Recovery strategies for different failure scenarios
 */

interface RecoveryStrategy {
  name: string;
  applicableTo: ErrorCategory[];
  execute: (context: RecoveryContext) => Promise<RecoveryResult>;
}

const recoveryStrategies: RecoveryStrategy[] = [
  {
    name: 'retry_with_backoff',
    applicableTo: [ErrorCategory.TOOL_TIMEOUT, ErrorCategory.NETWORK_ERROR],
    execute: async (context) => {
      const delay = Math.pow(2, context.attempt) * 1000;
      await sleep(delay);
      return { shouldRetry: true };
    }
  },

  {
    name: 'alternative_selector',
    applicableTo: [ErrorCategory.ELEMENT_NOT_FOUND],
    execute: async (context) => {
      // Try data-testid
      const testId = await findByTestId(context.targetElement);
      if (testId) {
        return { shouldRetry: true, newSelector: `[data-testid="${testId}"]` };
      }

      // Try text content
      const textSelector = await findByText(context.targetElement);
      if (textSelector) {
        return { shouldRetry: true, newSelector: textSelector };
      }

      // Try XPath
      const xpath = await findByXPath(context.targetElement);
      if (xpath) {
        return { shouldRetry: true, newSelector: xpath };
      }

      return { shouldRetry: false, reason: 'No alternatives found' };
    }
  },

  {
    name: 'page_refresh',
    applicableTo: [ErrorCategory.PAGE_CHANGED, ErrorCategory.UNEXPECTED_STATE],
    execute: async (context) => {
      await context.page.reload();
      await context.page.waitForLoadState('networkidle');

      // Re-extract DOM
      const newDom = await extractDOM(context.page);

      return {
        shouldRetry: true,
        updatedContext: { dom: newDom }
      };
    }
  },

  {
    name: 'reduce_scope',
    applicableTo: [ErrorCategory.CONTEXT_EXHAUSTED],
    execute: async (context) => {
      // Compact current context
      await context.hippocampus.compact();

      // Simplify remaining tasks
      const simplifiedPlan = context.cortex.simplifyPlan(context.currentPlan);

      return {
        shouldRetry: true,
        updatedPlan: simplifiedPlan
      };
    }
  }
];
```

---

## Loop Termination Conditions

```typescript
/**
 * Conditions that determine when the loop should stop
 */

interface TerminationCondition {
  name: string;
  check: (state: LoopState) => TerminationResult;
  priority: number; // Higher = checked first
}

interface TerminationResult {
  shouldTerminate: boolean;
  reason?: string;
  status: 'completed' | 'timeout' | 'failed' | 'escalated';
}

const terminationConditions: TerminationCondition[] = [
  {
    name: 'task_completed',
    priority: 100,
    check: (state) => {
      const lastMessage = state.messages[state.messages.length - 1];
      if (lastMessage.role === 'assistant' && lastMessage.content.includes('Final Answer:')) {
        return {
          shouldTerminate: true,
          reason: 'Task completed successfully',
          status: 'completed'
        };
      }
      return { shouldTerminate: false, status: 'completed' };
    }
  },

  {
    name: 'max_iterations',
    priority: 90,
    check: (state) => {
      if (state.iteration >= state.config.maxIterations) {
        return {
          shouldTerminate: true,
          reason: `Max iterations (${state.config.maxIterations}) reached`,
          status: 'timeout'
        };
      }
      return { shouldTerminate: false, status: 'timeout' };
    }
  },

  {
    name: 'time_limit',
    priority: 85,
    check: (state) => {
      const elapsed = Date.now() - state.startTime.getTime();
      if (elapsed >= state.config.timeoutMs) {
        return {
          shouldTerminate: true,
          reason: `Time limit (${state.config.timeoutMs}ms) exceeded`,
          status: 'timeout'
        };
      }
      return { shouldTerminate: false, status: 'timeout' };
    }
  },

  {
    name: 'token_budget',
    priority: 80,
    check: (state) => {
      const maxTokens = state.config.maxTokens || Infinity;
      if (state.totalTokensUsed >= maxTokens) {
        return {
          shouldTerminate: true,
          reason: `Token budget (${maxTokens}) exhausted`,
          status: 'timeout'
        };
      }
      return { shouldTerminate: false, status: 'timeout' };
    }
  },

  {
    name: 'stuck_detection',
    priority: 70,
    check: (state) => {
      // Check if agent is repeating same actions
      const recentActions = state.toolResults.slice(-5);
      if (recentActions.length === 5) {
        const uniqueActions = new Set(recentActions.map(r =>
          `${r.tool}:${JSON.stringify(r.arguments)}`
        ));
        if (uniqueActions.size === 1) {
          return {
            shouldTerminate: true,
            reason: 'Agent appears stuck in a loop',
            status: 'failed'
          };
        }
      }
      return { shouldTerminate: false, status: 'failed' };
    }
  },

  {
    name: 'consecutive_failures',
    priority: 60,
    check: (state) => {
      const recentResults = state.toolResults.slice(-3);
      const allFailed = recentResults.length === 3 &&
                        recentResults.every(r => !r.success);
      if (allFailed) {
        return {
          shouldTerminate: true,
          reason: 'Three consecutive tool failures',
          status: 'failed'
        };
      }
      return { shouldTerminate: false, status: 'failed' };
    }
  }
];

/**
 * Check all termination conditions
 */
function shouldTerminate(state: LoopState): TerminationResult {
  // Sort by priority (highest first)
  const sorted = [...terminationConditions].sort((a, b) => b.priority - a.priority);

  for (const condition of sorted) {
    const result = condition.check(state);
    if (result.shouldTerminate) {
      return result;
    }
  }

  return { shouldTerminate: false, status: 'completed' };
}
```

---

## Performance Optimization

### Token Optimization

```typescript
/**
 * Strategies to minimize token usage without losing effectiveness
 */

class TokenOptimizer {
  /**
   * Optimize messages before sending to LLM
   */
  optimizeMessages(messages: Message[]): Message[] {
    return messages.map(msg => {
      if (msg.role === 'tool') {
        return this.optimizeToolMessage(msg);
      }
      if (msg.role === 'system') {
        return this.optimizeSystemMessage(msg);
      }
      return msg;
    });
  }

  /**
   * Compress tool output to essential information
   */
  private optimizeToolMessage(msg: Message): Message {
    const content = JSON.parse(msg.content);

    // Remove verbose details if output is large
    if (JSON.stringify(content).length > 2000) {
      return {
        ...msg,
        content: JSON.stringify({
          summary: content.summary,
          success: content.success,
          keyFacts: this.extractKeyFacts(content),
          // Note: Full details available in tool_call_id reference
        })
      };
    }

    return msg;
  }

  /**
   * Dynamically include only relevant system prompt sections
   */
  private optimizeSystemMessage(msg: Message): Message {
    // This is handled by Synapse - only include relevant knowledge
    return msg;
  }
}
```

### Parallel Execution

```typescript
/**
 * Execute independent tool calls in parallel
 */

class ParallelExecutor {
  /**
   * Identify and execute independent actions in parallel
   */
  async executeParallel(actions: ParsedAction[]): Promise<ExecutionResult[]> {
    // Group actions by dependency
    const groups = this.groupByDependency(actions);

    const results: ExecutionResult[] = [];

    for (const group of groups) {
      // Execute group in parallel
      const groupResults = await Promise.all(
        group.map(action => this.executor.execute(action))
      );
      results.push(...groupResults);
    }

    return results;
  }

  /**
   * Group actions by their dependencies
   */
  private groupByDependency(actions: ParsedAction[]): ParsedAction[][] {
    const groups: ParsedAction[][] = [];
    let currentGroup: ParsedAction[] = [];

    for (const action of actions) {
      if (this.hasDependency(action, currentGroup)) {
        // Start new group
        groups.push(currentGroup);
        currentGroup = [action];
      } else {
        // Add to current group
        currentGroup.push(action);
      }
    }

    if (currentGroup.length > 0) {
      groups.push(currentGroup);
    }

    return groups;
  }

  /**
   * Check if action depends on previous group
   */
  private hasDependency(action: ParsedAction, group: ParsedAction[]): boolean {
    // Navigation always starts new group
    if (action.tool === 'navigate') return true;

    // Click/type on dynamic elements depends on previous extractions
    if (['click', 'type'].includes(action.tool)) {
      return group.some(a => a.tool === 'extractDOM');
    }

    return false;
  }
}
```

### Caching

```typescript
/**
 * Cache frequently used data to reduce redundant operations
 */

class LoopCache {
  private domCache: Map<string, CachedDOM> = new Map();
  private selectorCache: Map<string, string[]> = new Map();
  private embeddingCache: Map<string, number[]> = new Map();

  /**
   * Get cached DOM or extract fresh
   */
  async getDOM(page: Page, maxAge: number = 5000): Promise<DOMSnapshot> {
    const url = page.url();
    const cached = this.domCache.get(url);

    if (cached && Date.now() - cached.timestamp < maxAge) {
      return cached.dom;
    }

    const dom = await extractDOM(page);
    this.domCache.set(url, { dom, timestamp: Date.now() });

    return dom;
  }

  /**
   * Get cached alternative selectors
   */
  async getAlternativeSelectors(element: ElementInfo): Promise<string[]> {
    const key = `${element.mmid}:${element.tag}`;
    const cached = this.selectorCache.get(key);

    if (cached) {
      return cached;
    }

    const alternatives = await findAlternativeSelectors(element);
    this.selectorCache.set(key, alternatives);

    return alternatives;
  }

  /**
   * Invalidate cache on navigation
   */
  invalidateOnNavigation(): void {
    this.domCache.clear();
    this.selectorCache.clear();
  }
}
```

---

## Next Steps

- **[AGENT_TOOLS.md](./AGENT_TOOLS.md)** - Complete tool definitions and implementations
- **[AGENT_MEMORY.md](./AGENT_MEMORY.md)** - Memory architecture deep dive
- **[AGENT_CONTEXT.md](./AGENT_CONTEXT.md)** - Context management strategies
