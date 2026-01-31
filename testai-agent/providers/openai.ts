/**
 * TestAI Agent - OpenAI Provider
 *
 * Implementation for OpenAI models (GPT-4o, GPT-4o-mini, GPT-4-turbo, etc.)
 */

import {
  BaseLLMProvider,
  CompletionOptions,
  LLMResponse,
  TokenUsage,
  ModelCapabilities,
} from './base';
import { LLMConfig } from '../types';

export class OpenAIProvider extends BaseLLMProvider {
  private client: any; // Will be OpenAI instance

  constructor(config: LLMConfig, apiKey?: string) {
    super({
      ...config,
      provider: 'openai',
      apiKey: apiKey || process.env.OPENAI_API_KEY,
    });
  }

  protected initializeCapabilities(): ModelCapabilities {
    // Capabilities vary by model
    const modelCapabilities: Record<string, ModelCapabilities> = {
      'gpt-4o': {
        reasoning: 90,
        codeGeneration: 92,
        classification: 88,
        edgeCaseDetection: 85,
        securityAnalysis: 82,
        speed: 60,
        costEfficiency: 40,
      },
      'gpt-4o-mini': {
        reasoning: 75,
        codeGeneration: 78,
        classification: 85,
        edgeCaseDetection: 70,
        securityAnalysis: 65,
        speed: 90,
        costEfficiency: 95,
      },
      'gpt-4-turbo': {
        reasoning: 88,
        codeGeneration: 90,
        classification: 85,
        edgeCaseDetection: 83,
        securityAnalysis: 80,
        speed: 50,
        costEfficiency: 35,
      },
      'gpt-3.5-turbo': {
        reasoning: 60,
        codeGeneration: 65,
        classification: 75,
        edgeCaseDetection: 55,
        securityAnalysis: 50,
        speed: 95,
        costEfficiency: 98,
      },
    };

    return modelCapabilities[this.config.model] || modelCapabilities['gpt-4o-mini'];
  }

  async complete(options: CompletionOptions): Promise<LLMResponse> {
    // Dynamically import OpenAI to avoid issues if not installed
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
    if (options.responseFormat) {
      if (options.responseFormat.type === 'json_object') {
        requestBody.response_format = { type: 'json_object' };
      } else if (options.responseFormat.type === 'json_schema' && options.responseFormat.schema) {
        requestBody.response_format = {
          type: 'json_schema',
          json_schema: {
            name: options.responseFormat.schemaName || 'response',
            schema: options.responseFormat.schema,
            strict: true,
          },
        };
      }
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

    // Add stop sequences if specified
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
      if (options.responseFormat?.type.startsWith('json') && message?.content) {
        try {
          structuredOutput = JSON.parse(message.content);
        } catch {
          // Failed to parse JSON, leave as undefined
        }
      }

      // Extract tool calls if present
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
      throw new Error(`OpenAI completion failed: ${error.message}`);
    }
  }

  async countTokens(text: string): Promise<number> {
    // Use tiktoken for accurate token counting
    try {
      const { encoding_for_model } = await import('tiktoken');
      const enc = encoding_for_model(this.config.model as any);
      const tokens = enc.encode(text);
      enc.free();
      return tokens.length;
    } catch {
      // Fallback: rough estimate (1 token ≈ 4 chars)
      return Math.ceil(text.length / 4);
    }
  }

  async embed(text: string): Promise<number[]> {
    const OpenAI = (await import('openai')).default;

    if (!this.client) {
      this.client = new OpenAI({
        apiKey: this.config.apiKey,
        baseURL: this.config.baseUrl,
      });
    }

    const response = await this.client.embeddings.create({
      model: 'text-embedding-3-small',
      input: text,
    });

    return response.data[0]?.embedding || [];
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey) return false;

    try {
      const OpenAI = (await import('openai')).default;
      const client = new OpenAI({
        apiKey: this.config.apiKey,
        baseURL: this.config.baseUrl,
      });

      // Simple test call
      await client.models.retrieve(this.config.model);
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
 * Pre-configured OpenAI models
 */
export const OPENAI_MODELS = {
  // Fast, cheap - for classification
  'gpt-4o-mini': {
    provider: 'openai' as const,
    model: 'gpt-4o-mini',
    maxTokens: 4096,
    temperature: 0.1,
    costPerInputToken: 0.15,
    costPerOutputToken: 0.60,
    contextWindow: 128000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Balanced - for test generation
  'gpt-4o': {
    provider: 'openai' as const,
    model: 'gpt-4o',
    maxTokens: 4096,
    temperature: 0.2,
    costPerInputToken: 2.50,
    costPerOutputToken: 10.00,
    contextWindow: 128000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Large context - for complex analysis
  'gpt-4-turbo': {
    provider: 'openai' as const,
    model: 'gpt-4-turbo',
    maxTokens: 4096,
    temperature: 0.2,
    costPerInputToken: 10.00,
    costPerOutputToken: 30.00,
    contextWindow: 128000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Budget - for simple tasks
  'gpt-3.5-turbo': {
    provider: 'openai' as const,
    model: 'gpt-3.5-turbo',
    maxTokens: 4096,
    temperature: 0.1,
    costPerInputToken: 0.50,
    costPerOutputToken: 1.50,
    contextWindow: 16385,
    supportsVision: false,
    supportsTools: true,
    supportsStructuredOutput: true,
  },
};

/**
 * Create an OpenAI provider with a pre-configured model
 */
export function createOpenAIProvider(
  modelName: keyof typeof OPENAI_MODELS,
  apiKey?: string
): OpenAIProvider {
  return new OpenAIProvider(OPENAI_MODELS[modelName], apiKey);
}
