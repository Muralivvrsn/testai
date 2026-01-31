/**
 * TestAI Agent - DeepSeek Provider
 *
 * Implementation for DeepSeek models (DeepSeek V3, DeepSeek Coder, etc.)
 *
 * ★ Insight ─────────────────────────────────────
 * DeepSeek offers INCREDIBLE value:
 * - DeepSeek V3: GPT-4 level quality at 1/10th the cost
 * - DeepSeek Coder: Specialized for code tasks
 * - Uses OpenAI-compatible API format
 * Perfect for high-volume test generation where cost matters.
 * ─────────────────────────────────────────────────
 */

import {
  BaseLLMProvider,
  CompletionOptions,
  LLMResponse,
  TokenUsage,
  ModelCapabilities,
} from './base';
import { LLMConfig } from '../types';

export class DeepSeekProvider extends BaseLLMProvider {
  private client: any;

  constructor(config: LLMConfig, apiKey?: string) {
    super({
      ...config,
      provider: 'deepseek',
      apiKey: apiKey || process.env.DEEPSEEK_API_KEY,
      baseUrl: config.baseUrl || 'https://api.deepseek.com/v1',
    });
  }

  protected initializeCapabilities(): ModelCapabilities {
    const modelCapabilities: Record<string, ModelCapabilities> = {
      'deepseek-chat': {
        reasoning: 88,
        codeGeneration: 92, // Excellent at code
        classification: 82,
        edgeCaseDetection: 85,
        securityAnalysis: 78,
        speed: 75,
        costEfficiency: 98, // Incredibly cost-effective
      },
      'deepseek-coder': {
        reasoning: 80,
        codeGeneration: 95, // Best-in-class for code
        classification: 75,
        edgeCaseDetection: 82,
        securityAnalysis: 75,
        speed: 80,
        costEfficiency: 99,
      },
      'deepseek-reasoner': {
        reasoning: 95, // Specialized for reasoning
        codeGeneration: 88,
        classification: 85,
        edgeCaseDetection: 92,
        securityAnalysis: 85,
        speed: 50,
        costEfficiency: 90,
      },
    };

    return modelCapabilities[this.config.model] || modelCapabilities['deepseek-chat'];
  }

  async complete(options: CompletionOptions): Promise<LLMResponse> {
    // DeepSeek uses OpenAI-compatible API
    const OpenAI = (await import('openai')).default;

    if (!this.client) {
      this.client = new OpenAI({
        apiKey: this.config.apiKey,
        baseURL: this.config.baseUrl,
      });
    }

    const requestBody: any = {
      model: this.config.model,
      messages: options.messages.map((m) => ({
        role: m.role,
        content: m.content,
      })),
      max_tokens: options.maxTokens || this.config.maxTokens,
      temperature: options.temperature ?? this.config.temperature,
    };

    // Add response format if specified
    if (options.responseFormat?.type === 'json_object') {
      requestBody.response_format = { type: 'json_object' };
    }

    // Add tools if specified
    if (options.tools && options.tools.length > 0) {
      requestBody.tools = options.tools.map((tool) => ({
        type: 'function',
        function: {
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
        },
      }));

      if (options.toolChoice) {
        if (typeof options.toolChoice === 'string') {
          requestBody.tool_choice = options.toolChoice;
        } else {
          requestBody.tool_choice = {
            type: 'function',
            function: { name: options.toolChoice.name },
          };
        }
      }
    }

    // Add stop sequences
    if (options.stopSequences) {
      requestBody.stop = options.stopSequences;
    }

    try {
      const response = await this.client.chat.completions.create(requestBody);

      const message = response.choices[0]?.message;
      const usage: TokenUsage = {
        inputTokens: response.usage?.prompt_tokens || 0,
        outputTokens: response.usage?.completion_tokens || 0,
        totalTokens: response.usage?.total_tokens || 0,
        estimatedCost: this.estimateCost(
          response.usage?.prompt_tokens || 0,
          response.usage?.completion_tokens || 0
        ),
      };

      // Parse structured output if JSON was requested
      let structuredOutput: any;
      if (options.responseFormat?.type === 'json_object' && message?.content) {
        try {
          structuredOutput = JSON.parse(message.content);
        } catch {
          // Failed to parse JSON
        }
      }

      // Extract tool calls
      const toolCalls = message?.tool_calls?.map((tc: any) => ({
        id: tc.id,
        name: tc.function.name,
        arguments: tc.function.arguments,
      }));

      return {
        content: message?.content || '',
        usage,
        model: this.config.model,
        finishReason: this.mapFinishReason(response.choices[0]?.finish_reason),
        structuredOutput,
        toolCalls,
      };
    } catch (error: any) {
      throw new Error(`DeepSeek completion failed: ${error.message}`);
    }
  }

  async countTokens(text: string): Promise<number> {
    // DeepSeek uses similar tokenization to GPT
    return Math.ceil(text.length / 4);
  }

  async embed(text: string): Promise<number[]> {
    // DeepSeek doesn't have a native embedding API
    // Use OpenAI embeddings instead
    throw new Error('DeepSeek does not support embeddings. Use OpenAI embeddings.');
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey) return false;

    try {
      const OpenAI = (await import('openai')).default;
      const client = new OpenAI({
        apiKey: this.config.apiKey,
        baseURL: this.config.baseUrl,
      });

      await client.chat.completions.create({
        model: this.config.model,
        messages: [{ role: 'user', content: 'Hi' }],
        max_tokens: 10,
      });
      return true;
    } catch {
      return false;
    }
  }

  private mapFinishReason(reason: string): LLMResponse['finishReason'] {
    const mapping: Record<string, LLMResponse['finishReason']> = {
      stop: 'stop',
      length: 'length',
      tool_calls: 'tool_calls',
      content_filter: 'content_filter',
    };
    return mapping[reason] || 'stop';
  }
}

/**
 * Pre-configured DeepSeek models
 */
export const DEEPSEEK_MODELS = {
  // General purpose - excellent value
  'deepseek-chat': {
    provider: 'deepseek' as const,
    model: 'deepseek-chat',
    maxTokens: 8192,
    temperature: 0.2,
    costPerInputToken: 0.14,  // Incredibly cheap!
    costPerOutputToken: 0.28,
    contextWindow: 128000,
    supportsVision: false,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Code specialized
  'deepseek-coder': {
    provider: 'deepseek' as const,
    model: 'deepseek-coder',
    maxTokens: 8192,
    temperature: 0.1,
    costPerInputToken: 0.14,
    costPerOutputToken: 0.28,
    contextWindow: 128000,
    supportsVision: false,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Reasoning specialized (R1)
  'deepseek-reasoner': {
    provider: 'deepseek' as const,
    model: 'deepseek-reasoner',
    maxTokens: 8192,
    temperature: 0.3,
    costPerInputToken: 0.55,
    costPerOutputToken: 2.19,
    contextWindow: 64000,
    supportsVision: false,
    supportsTools: false,
    supportsStructuredOutput: false,
  },
};

/**
 * Create a DeepSeek provider with a pre-configured model
 */
export function createDeepSeekProvider(
  modelName: keyof typeof DEEPSEEK_MODELS,
  apiKey?: string
): DeepSeekProvider {
  return new DeepSeekProvider(DEEPSEEK_MODELS[modelName], apiKey);
}
