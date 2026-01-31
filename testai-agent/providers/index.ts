/**
 * TestAI Agent - Provider Index & Smart Router
 *
 * This module exports all providers and implements intelligent model routing.
 *
 * ★ Insight ─────────────────────────────────────
 * The key to beating larger models with smaller ones is SMART ROUTING:
 * 1. Use cheap fast models (GPT-4o-mini) for classification
 * 2. Use specialized models (DeepSeek Coder) for code generation
 * 3. Use reasoning models (Claude Sonnet) for security/edge cases
 * 4. Use large context models (Gemini) for massive specifications
 *
 * This hybrid approach achieves better results at 1/10th the cost.
 * ─────────────────────────────────────────────────
 */

// Re-export base types and classes
export * from './base';

// Export individual providers
export { OpenAIProvider, createOpenAIProvider, OPENAI_MODELS } from './openai';
export { AnthropicProvider, createAnthropicProvider, ANTHROPIC_MODELS } from './anthropic';
export { GoogleProvider, createGoogleProvider, GOOGLE_MODELS } from './google';
export { DeepSeekProvider, createDeepSeekProvider, DEEPSEEK_MODELS } from './deepseek';

// Import for use in this file
import { BaseLLMProvider, ProviderRegistry, providerRegistry } from './base';
import { createOpenAIProvider, OPENAI_MODELS } from './openai';
import { createAnthropicProvider, ANTHROPIC_MODELS } from './anthropic';
import { createGoogleProvider, GOOGLE_MODELS } from './google';
import { createDeepSeekProvider, DEEPSEEK_MODELS } from './deepseek';
import { TaskType, LLMProvider } from '../types';

/**
 * Smart Model Router - Automatically selects the best model for each task
 *
 * This is the SECRET SAUCE that makes small models beat large ones.
 */
export class SmartModelRouter {
  private registry: ProviderRegistry;
  private taskModelMap: Map<TaskType, { primary: string; fallback: string[] }>;

  constructor(registry: ProviderRegistry = providerRegistry) {
    this.registry = registry;
    this.taskModelMap = this.initializeTaskModelMap();
  }

  /**
   * Define the best model for each task type
   */
  private initializeTaskModelMap(): Map<TaskType, { primary: string; fallback: string[] }> {
    return new Map([
      // Classification tasks - use fast, cheap models
      ['classify_page', {
        primary: 'openai:gpt-4o-mini',
        fallback: ['google:gemini-2.0-flash', 'deepseek:deepseek-chat'],
      }],
      ['classify_elements', {
        primary: 'openai:gpt-4o-mini',
        fallback: ['google:gemini-2.0-flash', 'anthropic:claude-3-haiku'],
      }],

      // Test generation - use balanced models with good code skills
      ['generate_test_cases', {
        primary: 'deepseek:deepseek-chat',
        fallback: ['openai:gpt-4o', 'anthropic:claude-sonnet-4'],
      }],

      // Edge cases - use reasoning models
      ['generate_edge_cases', {
        primary: 'anthropic:claude-sonnet-4',
        fallback: ['deepseek:deepseek-reasoner', 'openai:gpt-4o'],
      }],

      // Security - use Claude (trained with safety focus)
      ['security_analysis', {
        primary: 'anthropic:claude-sonnet-4',
        fallback: ['anthropic:claude-opus-4', 'openai:gpt-4o'],
      }],

      // Accessibility - balanced reasoning
      ['accessibility_audit', {
        primary: 'openai:gpt-4o',
        fallback: ['anthropic:claude-sonnet-4', 'google:gemini-1.5-pro'],
      }],

      // API analysis - code-focused
      ['api_contract_analysis', {
        primary: 'deepseek:deepseek-coder',
        fallback: ['openai:gpt-4o', 'anthropic:claude-sonnet-4'],
      }],

      // Visual regression - needs vision
      ['visual_regression_analysis', {
        primary: 'openai:gpt-4o',
        fallback: ['google:gemini-1.5-pro', 'anthropic:claude-sonnet-4'],
      }],

      // Performance - balanced
      ['performance_analysis', {
        primary: 'openai:gpt-4o',
        fallback: ['deepseek:deepseek-chat', 'google:gemini-1.5-pro'],
      }],

      // i18n - needs language understanding
      ['i18n_analysis', {
        primary: 'google:gemini-1.5-pro',
        fallback: ['anthropic:claude-sonnet-4', 'openai:gpt-4o'],
      }],

      // Context summarization - fast is key
      ['summarize_context', {
        primary: 'openai:gpt-4o-mini',
        fallback: ['google:gemini-2.0-flash', 'deepseek:deepseek-chat'],
      }],

      // Test prioritization - reasoning
      ['prioritize_tests', {
        primary: 'anthropic:claude-sonnet-4',
        fallback: ['openai:gpt-4o', 'deepseek:deepseek-reasoner'],
      }],
    ]);
  }

  /**
   * Get the best provider for a task
   */
  async getProvider(
    task: TaskType,
    options?: {
      preferredProvider?: LLMProvider;
      maxCost?: number;
      requireVision?: boolean;
      requireTools?: boolean;
    }
  ): Promise<BaseLLMProvider> {
    const taskConfig = this.taskModelMap.get(task);

    if (!taskConfig) {
      // Fallback to GPT-4o-mini for unknown tasks
      const provider = this.registry.get('openai', 'gpt-4o-mini');
      if (provider && await provider.isAvailable()) {
        return provider;
      }
      throw new Error(`No provider available for task: ${task}`);
    }

    // Try primary model first
    const [primaryProvider, primaryModel] = taskConfig.primary.split(':');
    let provider = this.registry.get(primaryProvider as LLMProvider, primaryModel);

    // Apply filters
    if (provider) {
      if (options?.requireVision && !provider.supportsVision()) {
        provider = undefined;
      }
      if (options?.requireTools && !provider.supportsTools()) {
        provider = undefined;
      }
      if (options?.preferredProvider && provider.getProvider() !== options.preferredProvider) {
        // Try to find a model from preferred provider
        const preferredModels = this.registry.getAll().filter(
          (p) => p.getProvider() === options.preferredProvider
        );
        if (preferredModels.length > 0) {
          // Get best scoring one for this task
          const scored = preferredModels
            .map((p) => ({ provider: p, score: p.getTaskSuitabilityScore(task) }))
            .sort((a, b) => b.score - a.score);
          provider = scored[0]?.provider;
        }
      }
    }

    // Check if primary is available
    if (provider && await provider.isAvailable()) {
      return provider;
    }

    // Try fallbacks
    for (const fallback of taskConfig.fallback) {
      const [fbProvider, fbModel] = fallback.split(':');
      const fallbackProvider = this.registry.get(fbProvider as LLMProvider, fbModel);

      if (fallbackProvider && await fallbackProvider.isAvailable()) {
        // Apply same filters
        if (options?.requireVision && !fallbackProvider.supportsVision()) continue;
        if (options?.requireTools && !fallbackProvider.supportsTools()) continue;

        return fallbackProvider;
      }
    }

    throw new Error(`No available provider for task: ${task}`);
  }

  /**
   * Get estimated cost for a task based on typical usage
   */
  estimateTaskCost(task: TaskType): { inputTokens: number; outputTokens: number; estimatedCost: number } {
    // Typical token usage per task type
    const taskUsage: Record<TaskType, { input: number; output: number }> = {
      classify_page: { input: 2000, output: 200 },
      classify_elements: { input: 5000, output: 500 },
      generate_test_cases: { input: 8000, output: 3000 },
      generate_edge_cases: { input: 6000, output: 2000 },
      security_analysis: { input: 10000, output: 2000 },
      accessibility_audit: { input: 5000, output: 1500 },
      api_contract_analysis: { input: 4000, output: 2000 },
      visual_regression_analysis: { input: 3000, output: 1000 },
      performance_analysis: { input: 5000, output: 1500 },
      i18n_analysis: { input: 4000, output: 1000 },
      summarize_context: { input: 10000, output: 500 },
      prioritize_tests: { input: 5000, output: 1000 },
    };

    const usage = taskUsage[task] || { input: 5000, output: 1000 };
    const taskConfig = this.taskModelMap.get(task);

    if (!taskConfig) {
      return { inputTokens: usage.input, outputTokens: usage.output, estimatedCost: 0.01 };
    }

    const [primaryProvider, primaryModel] = taskConfig.primary.split(':');
    const provider = this.registry.get(primaryProvider as LLMProvider, primaryModel);

    if (!provider) {
      return { inputTokens: usage.input, outputTokens: usage.output, estimatedCost: 0.01 };
    }

    const cost = provider.estimateCost(usage.input, usage.output);
    return { inputTokens: usage.input, outputTokens: usage.output, estimatedCost: cost };
  }
}

/**
 * Initialize all providers from environment variables
 */
export function initializeProviders(): ProviderRegistry {
  // OpenAI
  if (process.env.OPENAI_API_KEY) {
    providerRegistry.register(createOpenAIProvider('gpt-4o-mini'));
    providerRegistry.register(createOpenAIProvider('gpt-4o'));
    providerRegistry.register(createOpenAIProvider('gpt-4-turbo'));
    providerRegistry.register(createOpenAIProvider('gpt-3.5-turbo'));
  }

  // Anthropic
  if (process.env.ANTHROPIC_API_KEY) {
    providerRegistry.register(createAnthropicProvider('claude-sonnet-4'));
    providerRegistry.register(createAnthropicProvider('claude-3.5-sonnet'));
    providerRegistry.register(createAnthropicProvider('claude-3-haiku'));
    providerRegistry.register(createAnthropicProvider('claude-opus-4'));
  }

  // Google
  if (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY) {
    providerRegistry.register(createGoogleProvider('gemini-2.0-flash'));
    providerRegistry.register(createGoogleProvider('gemini-1.5-pro'));
    providerRegistry.register(createGoogleProvider('gemini-1.5-flash'));
  }

  // DeepSeek
  if (process.env.DEEPSEEK_API_KEY) {
    providerRegistry.register(createDeepSeekProvider('deepseek-chat'));
    providerRegistry.register(createDeepSeekProvider('deepseek-coder'));
    providerRegistry.register(createDeepSeekProvider('deepseek-reasoner'));
  }

  return providerRegistry;
}

/**
 * Get a singleton instance of the smart router
 */
let _smartRouter: SmartModelRouter | null = null;

export function getSmartRouter(): SmartModelRouter {
  if (!_smartRouter) {
    initializeProviders();
    _smartRouter = new SmartModelRouter(providerRegistry);
  }
  return _smartRouter;
}

/**
 * Quick access to get a provider for a task
 */
export async function getProviderForTask(
  task: TaskType,
  options?: {
    preferredProvider?: LLMProvider;
    maxCost?: number;
    requireVision?: boolean;
    requireTools?: boolean;
  }
): Promise<BaseLLMProvider> {
  return getSmartRouter().getProvider(task, options);
}
