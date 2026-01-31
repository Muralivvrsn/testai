/**
 * TestAI Agent - Anthropic Provider
 *
 * Implementation for Anthropic models (Claude Sonnet, Claude Haiku, Claude Opus)
 *
 * ★ Insight ─────────────────────────────────────
 * Claude models excel at:
 * - Security analysis (trained with safety in mind)
 * - Edge case detection (strong reasoning)
 * - Nuanced understanding of complex specifications
 * Use Claude for critical thinking tasks, not simple classification.
 * ─────────────────────────────────────────────────
 */

import {
  BaseLLMProvider,
  CompletionOptions,
  LLMResponse,
  TokenUsage,
  ModelCapabilities,
  LLMMessage,
} from './base';
import { LLMConfig } from '../types';

export class AnthropicProvider extends BaseLLMProvider {
  private client: any;

  constructor(config: LLMConfig, apiKey?: string) {
    super({
      ...config,
      provider: 'anthropic',
      apiKey: apiKey || process.env.ANTHROPIC_API_KEY,
    });
  }

  protected initializeCapabilities(): ModelCapabilities {
    const modelCapabilities: Record<string, ModelCapabilities> = {
      'claude-sonnet-4-20250514': {
        reasoning: 92,
        codeGeneration: 90,
        classification: 85,
        edgeCaseDetection: 90,
        securityAnalysis: 95, // Claude excels at security
        speed: 55,
        costEfficiency: 45,
      },
      'claude-3-5-sonnet-20241022': {
        reasoning: 90,
        codeGeneration: 88,
        classification: 83,
        edgeCaseDetection: 88,
        securityAnalysis: 93,
        speed: 60,
        costEfficiency: 50,
      },
      'claude-3-haiku-20240307': {
        reasoning: 70,
        codeGeneration: 72,
        classification: 80,
        edgeCaseDetection: 68,
        securityAnalysis: 70,
        speed: 95,
        costEfficiency: 92,
      },
      'claude-opus-4-20250514': {
        reasoning: 98,
        codeGeneration: 95,
        classification: 90,
        edgeCaseDetection: 96,
        securityAnalysis: 98,
        speed: 30,
        costEfficiency: 20,
      },
    };

    return modelCapabilities[this.config.model] || modelCapabilities['claude-sonnet-4-20250514'];
  }

  async complete(options: CompletionOptions): Promise<LLMResponse> {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;

    if (!this.client) {
      this.client = new Anthropic({
        apiKey: this.config.apiKey,
      });
    }

    // Extract system message
    const systemMessage = options.messages.find((m) => m.role === 'system');
    const otherMessages = options.messages.filter((m) => m.role !== 'system');

    const requestBody: any = {
      model: this.config.model,
      max_tokens: options.maxTokens || this.config.maxTokens,
      messages: this.convertMessages(otherMessages),
    };

    // Add system prompt if present
    if (systemMessage) {
      requestBody.system = typeof systemMessage.content === 'string'
        ? systemMessage.content
        : systemMessage.content.map((c) => c.text).join('\n');
    }

    // Add temperature
    if (options.temperature !== undefined) {
      requestBody.temperature = options.temperature;
    }

    // Add tools if specified
    if (options.tools && options.tools.length > 0) {
      requestBody.tools = options.tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema: tool.parameters,
      }));

      if (options.toolChoice) {
        if (typeof options.toolChoice === 'string') {
          requestBody.tool_choice = { type: options.toolChoice === 'required' ? 'any' : options.toolChoice };
        } else {
          requestBody.tool_choice = {
            type: 'tool',
            name: options.toolChoice.name,
          };
        }
      }
    }

    // Add stop sequences
    if (options.stopSequences) {
      requestBody.stop_sequences = options.stopSequences;
    }

    try {
      const response = await this.client.messages.create(requestBody);

      // Extract text content
      const textContent = response.content
        .filter((block: any) => block.type === 'text')
        .map((block: any) => block.text)
        .join('');

      // Extract tool use
      const toolUseBlocks = response.content.filter((block: any) => block.type === 'tool_use');
      const toolCalls = toolUseBlocks.map((block: any) => ({
        id: block.id,
        name: block.name,
        arguments: JSON.stringify(block.input),
      }));

      const usage: TokenUsage = {
        inputTokens: response.usage?.input_tokens || 0,
        outputTokens: response.usage?.output_tokens || 0,
        totalTokens: (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0),
        estimatedCost: this.estimateCost(
          response.usage?.input_tokens || 0,
          response.usage?.output_tokens || 0
        ),
      };

      // Parse structured output if JSON was requested
      let structuredOutput: any;
      if (options.responseFormat?.type.startsWith('json') && textContent) {
        try {
          // Extract JSON from the response (Claude might wrap it in markdown)
          const jsonMatch = textContent.match(/```(?:json)?\s*([\s\S]*?)```/) ||
                          textContent.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            structuredOutput = JSON.parse(jsonMatch[1] || jsonMatch[0]);
          }
        } catch {
          // Failed to parse JSON
        }
      }

      return {
        content: textContent,
        usage,
        model: this.config.model,
        finishReason: this.mapStopReason(response.stop_reason),
        structuredOutput,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      };
    } catch (error: any) {
      throw new Error(`Anthropic completion failed: ${error.message}`);
    }
  }

  private convertMessages(messages: LLMMessage[]): any[] {
    return messages.map((m) => {
      if (typeof m.content === 'string') {
        return { role: m.role, content: m.content };
      }

      // Handle multi-part content (images)
      const content = m.content.map((part) => {
        if (part.type === 'text') {
          return { type: 'text', text: part.text };
        }
        if (part.type === 'image_url' && part.image_url) {
          // Convert to Anthropic's image format
          const url = part.image_url.url;
          if (url.startsWith('data:')) {
            const [header, base64] = url.split(',');
            const mediaType = header.match(/data:(.+);/)?.[1] || 'image/png';
            return {
              type: 'image',
              source: {
                type: 'base64',
                media_type: mediaType,
                data: base64,
              },
            };
          }
          return {
            type: 'image',
            source: {
              type: 'url',
              url: url,
            },
          };
        }
        return { type: 'text', text: '' };
      });

      return { role: m.role, content };
    });
  }

  async countTokens(text: string): Promise<number> {
    // Anthropic's tokenization is roughly similar to OpenAI's
    // Use a simple approximation (1 token ≈ 4 chars for English)
    // For production, use the official @anthropic-ai/tokenizer
    return Math.ceil(text.length / 4);
  }

  async embed(text: string): Promise<number[]> {
    // Anthropic doesn't have a native embedding API
    // Fall back to OpenAI embeddings or use Voyage AI (Anthropic's partner)
    throw new Error('Anthropic does not support embeddings. Use OpenAI or Voyage AI.');
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey) return false;

    try {
      const Anthropic = (await import('@anthropic-ai/sdk')).default;
      const client = new Anthropic({
        apiKey: this.config.apiKey,
      });

      // Simple test - try to make a minimal request
      await client.messages.create({
        model: this.config.model,
        max_tokens: 10,
        messages: [{ role: 'user', content: 'Hi' }],
      });
      return true;
    } catch {
      return false;
    }
  }

  private mapStopReason(reason: string): LLMResponse['finishReason'] {
    const mapping: Record<string, LLMResponse['finishReason']> = {
      end_turn: 'stop',
      max_tokens: 'length',
      tool_use: 'tool_calls',
      stop_sequence: 'stop',
    };
    return mapping[reason] || 'stop';
  }
}

/**
 * Pre-configured Anthropic models
 */
export const ANTHROPIC_MODELS = {
  // Latest Sonnet - best for security and edge cases
  'claude-sonnet-4': {
    provider: 'anthropic' as const,
    model: 'claude-sonnet-4-20250514',
    maxTokens: 8192,
    temperature: 0.2,
    costPerInputToken: 3.00,
    costPerOutputToken: 15.00,
    contextWindow: 200000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: false, // Anthropic doesn't have native JSON mode
  },

  // Previous Sonnet - still excellent
  'claude-3.5-sonnet': {
    provider: 'anthropic' as const,
    model: 'claude-3-5-sonnet-20241022',
    maxTokens: 8192,
    temperature: 0.2,
    costPerInputToken: 3.00,
    costPerOutputToken: 15.00,
    contextWindow: 200000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: false,
  },

  // Fast and cheap - for quick tasks
  'claude-3-haiku': {
    provider: 'anthropic' as const,
    model: 'claude-3-haiku-20240307',
    maxTokens: 4096,
    temperature: 0.1,
    costPerInputToken: 0.25,
    costPerOutputToken: 1.25,
    contextWindow: 200000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: false,
  },

  // Most capable - for complex reasoning
  'claude-opus-4': {
    provider: 'anthropic' as const,
    model: 'claude-opus-4-20250514',
    maxTokens: 8192,
    temperature: 0.3,
    costPerInputToken: 15.00,
    costPerOutputToken: 75.00,
    contextWindow: 200000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: false,
  },
};

/**
 * Create an Anthropic provider with a pre-configured model
 */
export function createAnthropicProvider(
  modelName: keyof typeof ANTHROPIC_MODELS,
  apiKey?: string
): AnthropicProvider {
  return new AnthropicProvider(ANTHROPIC_MODELS[modelName], apiKey);
}
