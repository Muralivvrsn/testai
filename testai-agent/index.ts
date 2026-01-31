/**
 * TestAI Agent - Main Entry Point
 *
 * A revolutionary QA testing agent that generates comprehensive test cases
 * from feature specifications using intelligent LLM routing and RAG.
 *
 * ============================================================================
 * ARCHITECTURE OVERVIEW
 * ============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                         TESTAI AGENT ARCHITECTURE                         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐            │
 * │  │   Providers  │     │    Brain     │     │   Context    │            │
 * │  │   (Multi-LLM)│     │  (QA Rules)  │     │  (Manager)   │            │
 * │  │              │     │              │     │              │            │
 * │  │ - OpenAI     │     │ - Knowledge  │     │ - Token      │            │
 * │  │ - Anthropic  │     │   Base       │     │   Budget     │            │
 * │  │ - Google     │     │ - RAG        │     │ - Retrieval  │            │
 * │  │ - DeepSeek   │     │ - Memory     │     │ - Compress   │            │
 * │  └──────────────┘     └──────────────┘     └──────────────┘            │
 * │          │                   │                   │                      │
 * │          └───────────────────┼───────────────────┘                      │
 * │                              ▼                                          │
 * │  ┌───────────────────────────────────────────────────────────────────┐ │
 * │  │                      Smart Model Router                            │ │
 * │  │  Routes tasks to the optimal model based on:                       │ │
 * │  │  - Task type (classify, generate, security, etc.)                  │ │
 * │  │  - Cost constraints                                                │ │
 * │  │  - Required capabilities (vision, tools, etc.)                     │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌───────────────────────────────────────────────────────────────────┐ │
 * │  │                     Test Case Generator                            │ │
 * │  │  - Happy path tests                                                │ │
 * │  │  - Edge case tests                                                 │ │
 * │  │  - Security tests                                                  │ │
 * │  │  - Accessibility tests                                             │ │
 * │  │  - Performance tests                                               │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌───────────────────────────────────────────────────────────────────┐ │
 * │  │                        OUTPUT                                      │ │
 * │  │  - Structured TestCase objects                                     │ │
 * │  │  - Coverage reports                                                │ │
 * │  │  - Cost/token tracking                                             │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ============================================================================
 * QUICK START
 * ============================================================================
 *
 * ```typescript
 * import { createQAAgent, createSpecificationTemplate } from './testai-agent';
 *
 * // 1. Create the agent
 * const agent = await createQAAgent({
 *   openaiApiKey: 'sk-...',     // Or use OPENAI_API_KEY env var
 *   anthropicApiKey: 'sk-...',  // Or use ANTHROPIC_API_KEY env var
 * });
 *
 * // 2. Load QA knowledge base
 * await agent.loadKnowledge('./QA_BRAIN.md');
 *
 * // 3. Create a specification (use template or custom)
 * const spec = createSpecificationTemplate('login_flow', {
 *   name: 'My App Login',
 *   description: 'User authentication for My App',
 * });
 *
 * // 4. Generate test cases
 * const result = await agent.generateTests(spec, {
 *   includeEdgeCases: true,
 *   includeSecurityTests: true,
 *   includeAccessibilityTests: true,
 * });
 *
 * console.log(`Generated ${result.testCases.length} test cases`);
 * console.log(`Cost: $${result.metadata.cost.toFixed(4)}`);
 * ```
 *
 * ============================================================================
 * WHY THIS BEATS LARGER MODELS
 * ============================================================================
 *
 * 1. SMART ROUTING: Uses cheap models (GPT-4o-mini) for classification,
 *    expensive models (Claude Sonnet) only for complex tasks
 *
 * 2. RELEVANT CONTEXT: RAG retrieves only relevant QA rules from the
 *    knowledge base, keeping prompts small and focused
 *
 * 3. SPECIALIZED PROMPTS: Each task type has optimized prompts with
 *    examples and output schemas
 *
 * 4. MULTI-MODEL: Can use any provider (OpenAI, Anthropic, Google, DeepSeek)
 *    to get the best of each
 *
 * ============================================================================
 */

// Core Agent
export { QAAgent, createQAAgent, quickGenerateTests, AgentConfig, AgentStatus } from './core/agent';

// Types
export * from './types';

// Providers
export {
  BaseLLMProvider,
  ProviderRegistry,
  providerRegistry,
  SmartModelRouter,
  getSmartRouter,
  getProviderForTask,
  initializeProviders,
  // OpenAI
  OpenAIProvider,
  createOpenAIProvider,
  OPENAI_MODELS,
  // Anthropic
  AnthropicProvider,
  createAnthropicProvider,
  ANTHROPIC_MODELS,
  // Google
  GoogleProvider,
  createGoogleProvider,
  GOOGLE_MODELS,
  // DeepSeek
  DeepSeekProvider,
  createDeepSeekProvider,
  DEEPSEEK_MODELS,
} from './providers';

// Brain (Knowledge Base)
export {
  BaseKnowledgeBase,
  InMemoryKnowledgeBase,
  KnowledgeChunk,
  SearchOptions,
  createKnowledgeBase,
} from './brain';

// Context Management
export {
  ContextManager,
  createContextManager,
  ContextConfig,
  BuiltContext,
  DEFAULT_STRATEGIES,
} from './context/manager';

// Prompts
export {
  QA_AGENT_PERSONA,
  TASK_PROMPTS,
  getSystemPrompt,
  getFeaturePrompt,
  getPageTypeHints,
} from './prompts/system';

// Generators
export {
  TestCaseGenerator,
  createTestGenerator,
  GenerationOptions,
  GenerationResult,
} from './generators/test-generator';

// Templates
export {
  createSpecificationTemplate,
  SPECIFICATION_TEMPLATES,
  getAvailableTemplates,
  getTemplateDescription,
} from './templates/specifications';
