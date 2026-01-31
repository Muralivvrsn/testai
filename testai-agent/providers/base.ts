/**
 * TestAI Agent - Base LLM Provider
 *
 * Abstract base class for all LLM providers. This enables the agent to work
 * with any LLM (OpenAI, Anthropic, Google, DeepSeek, etc.) through a unified interface.
 *
 * ★ Insight ─────────────────────────────────────
 * The provider abstraction is key to beating larger models with smaller ones.
 * By routing tasks to the most appropriate model, we can achieve:
 * - Cost efficiency: Use cheap models for classification
 * - Quality: Use expensive models only when needed
 * - Speed: Use fast models for real-time tasks
 * ─────────────────────────────────────────────────
 */

import {
  LLMConfig,
  LLMProvider,
  TaskType,
  ModelCapabilities,
  JSONSchema,
} from '../types';

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string | ContentPart[];
}

export interface ContentPart {
  type: 'text' | 'image_url';
  text?: string;
  image_url?: { url: string; detail?: 'low' | 'high' | 'auto' };
}

export interface LLMResponse {
  content: string;
  usage: TokenUsage;
  model: string;
  finishReason: 'stop' | 'length' | 'tool_calls' | 'content_filter' | 'error';
  structuredOutput?: any;
  toolCalls?: ToolCall[];
}

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  estimatedCost: number;
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: JSONSchema;
}

export interface CompletionOptions {
  messages: LLMMessage[];
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  stopSequences?: string[];
  responseFormat?: ResponseFormat;
  tools?: ToolDefinition[];
  toolChoice?: 'auto' | 'required' | 'none' | { name: string };
}

export interface ResponseFormat {
  type: 'text' | 'json_object' | 'json_schema';
  schema?: JSONSchema;
  schemaName?: string;
}

/**
 * Abstract base class for all LLM providers
 */
export abstract class BaseLLMProvider {
  protected config: LLMConfig;
  protected capabilities: ModelCapabilities;

  constructor(config: LLMConfig) {
    this.config = config;
    this.capabilities = this.initializeCapabilities();
  }

  /**
   * Each provider must implement this to define model capabilities
   */
  protected abstract initializeCapabilities(): ModelCapabilities;

  /**
   * Send a completion request to the LLM
   */
  abstract complete(options: CompletionOptions): Promise<LLMResponse>;

  /**
   * Count tokens in a string (provider-specific)
   */
  abstract countTokens(text: string): Promise<number>;

  /**
   * Generate embeddings for text
   */
  abstract embed(text: string): Promise<number[]>;

  /**
   * Check if provider is available and configured
   */
  abstract isAvailable(): Promise<boolean>;

  // =========================================================================
  // Common Methods (shared across providers)
  // =========================================================================

  /**
   * Get the provider name
   */
  getProvider(): LLMProvider {
    return this.config.provider;
  }

  /**
   * Get model configuration
   */
  getConfig(): LLMConfig {
    return { ...this.config };
  }

  /**
   * Get model capabilities
   */
  getCapabilities(): ModelCapabilities {
    return { ...this.capabilities };
  }

  /**
   * Calculate estimated cost for a completion
   */
  estimateCost(inputTokens: number, outputTokens: number): number {
    return (
      (inputTokens / 1_000_000) * this.config.costPerInputToken +
      (outputTokens / 1_000_000) * this.config.costPerOutputToken
    );
  }

  /**
   * Check if model supports a feature
   */
  supportsVision(): boolean {
    return this.config.supportsVision;
  }

  supportsTools(): boolean {
    return this.config.supportsTools;
  }

  supportsStructuredOutput(): boolean {
    return this.config.supportsStructuredOutput;
  }

  /**
   * Get available context window (minus reserved space)
   */
  getAvailableContext(reservedForOutput: number = 4000): number {
    return this.config.contextWindow - reservedForOutput;
  }

  /**
   * Get the best task type this model is suited for
   */
  getBestTaskTypes(): TaskType[] {
    const tasks: TaskType[] = [];

    // Fast, cheap models are good for classification
    if (this.capabilities.speed > 70 && this.capabilities.costEfficiency > 70) {
      tasks.push('classify_page', 'classify_elements', 'summarize_context');
    }

    // High reasoning models for complex tasks
    if (this.capabilities.reasoning > 80) {
      tasks.push('generate_test_cases', 'prioritize_tests');
    }

    // Security analysis needs specialized reasoning
    if (this.capabilities.securityAnalysis > 70) {
      tasks.push('security_analysis');
    }

    // Edge case detection
    if (this.capabilities.edgeCaseDetection > 70) {
      tasks.push('generate_edge_cases');
    }

    // Code generation
    if (this.capabilities.codeGeneration > 70) {
      tasks.push('api_contract_analysis');
    }

    return tasks;
  }

  /**
   * Get a score for how suitable this model is for a task (0-100)
   */
  getTaskSuitabilityScore(task: TaskType): number {
    const weights: Record<TaskType, Partial<Record<keyof ModelCapabilities, number>>> = {
      classify_page: { classification: 0.6, speed: 0.3, costEfficiency: 0.1 },
      classify_elements: { classification: 0.6, speed: 0.3, costEfficiency: 0.1 },
      generate_test_cases: { reasoning: 0.5, codeGeneration: 0.3, edgeCaseDetection: 0.2 },
      generate_edge_cases: { edgeCaseDetection: 0.6, reasoning: 0.3, codeGeneration: 0.1 },
      security_analysis: { securityAnalysis: 0.7, reasoning: 0.2, codeGeneration: 0.1 },
      accessibility_audit: { reasoning: 0.4, classification: 0.4, codeGeneration: 0.2 },
      api_contract_analysis: { codeGeneration: 0.5, reasoning: 0.3, classification: 0.2 },
      visual_regression_analysis: { reasoning: 0.5, classification: 0.3, costEfficiency: 0.2 },
      performance_analysis: { reasoning: 0.5, codeGeneration: 0.3, classification: 0.2 },
      i18n_analysis: { reasoning: 0.4, classification: 0.4, edgeCaseDetection: 0.2 },
      summarize_context: { speed: 0.4, costEfficiency: 0.4, reasoning: 0.2 },
      prioritize_tests: { reasoning: 0.6, classification: 0.2, costEfficiency: 0.2 },
    };

    const taskWeights = weights[task] || {};
    let score = 0;

    for (const [capability, weight] of Object.entries(taskWeights)) {
      score += (this.capabilities[capability as keyof ModelCapabilities] || 0) * weight;
    }

    return Math.round(score);
  }
}

/**
 * Registry for all available LLM providers
 */
export class ProviderRegistry {
  private providers: Map<string, BaseLLMProvider> = new Map();

  /**
   * Register a provider
   */
  register(provider: BaseLLMProvider): void {
    const key = this.getKey(provider.getProvider(), provider.getConfig().model);
    this.providers.set(key, provider);
  }

  /**
   * Get a specific provider
   */
  get(providerName: LLMProvider, model: string): BaseLLMProvider | undefined {
    return this.providers.get(this.getKey(providerName, model));
  }

  /**
   * Get all registered providers
   */
  getAll(): BaseLLMProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Get available providers
   */
  async getAvailable(): Promise<BaseLLMProvider[]> {
    const available: BaseLLMProvider[] = [];

    for (const provider of this.providers.values()) {
      if (await provider.isAvailable()) {
        available.push(provider);
      }
    }

    return available;
  }

  /**
   * Get the best provider for a task
   */
  async getBestForTask(
    task: TaskType,
    constraints?: { maxCost?: number; preferredProvider?: LLMProvider }
  ): Promise<BaseLLMProvider | null> {
    const available = await this.getAvailable();

    // Filter by constraints
    let candidates = available;

    if (constraints?.preferredProvider) {
      const preferred = candidates.filter(
        (p) => p.getProvider() === constraints.preferredProvider
      );
      if (preferred.length > 0) {
        candidates = preferred;
      }
    }

    // Score candidates for the task
    const scored = candidates.map((p) => ({
      provider: p,
      score: p.getTaskSuitabilityScore(task),
    }));

    // Sort by score (highest first)
    scored.sort((a, b) => b.score - a.score);

    return scored[0]?.provider || null;
  }

  /**
   * Get providers ranked by suitability for a task
   */
  async getRankedForTask(task: TaskType): Promise<Array<{ provider: BaseLLMProvider; score: number }>> {
    const available = await this.getAvailable();

    return available
      .map((p) => ({
        provider: p,
        score: p.getTaskSuitabilityScore(task),
      }))
      .sort((a, b) => b.score - a.score);
  }

  private getKey(provider: LLMProvider, model: string): string {
    return `${provider}:${model}`;
  }
}

// Global provider registry
export const providerRegistry = new ProviderRegistry();
