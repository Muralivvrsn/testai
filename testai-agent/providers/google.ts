/**
 * TestAI Agent - Google Gemini Provider
 *
 * Implementation for Google Gemini models (Gemini 1.5 Pro, Gemini 2.0 Flash, etc.)
 *
 * ★ Insight ─────────────────────────────────────
 * Gemini models have MASSIVE context windows (up to 2M tokens).
 * This makes them excellent for:
 * - Analyzing entire codebases
 * - Processing large specifications
 * - Understanding complex multi-page workflows
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

export class GoogleProvider extends BaseLLMProvider {
  private client: any;

  constructor(config: LLMConfig, apiKey?: string) {
    super({
      ...config,
      provider: 'google',
      apiKey: apiKey || process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY,
    });
  }

  protected initializeCapabilities(): ModelCapabilities {
    const modelCapabilities: Record<string, ModelCapabilities> = {
      'gemini-2.0-flash': {
        reasoning: 82,
        codeGeneration: 85,
        classification: 88,
        edgeCaseDetection: 78,
        securityAnalysis: 75,
        speed: 92,
        costEfficiency: 90,
      },
      'gemini-1.5-pro': {
        reasoning: 88,
        codeGeneration: 87,
        classification: 85,
        edgeCaseDetection: 82,
        securityAnalysis: 80,
        speed: 50,
        costEfficiency: 60,
      },
      'gemini-1.5-flash': {
        reasoning: 75,
        codeGeneration: 78,
        classification: 82,
        edgeCaseDetection: 70,
        securityAnalysis: 68,
        speed: 95,
        costEfficiency: 95,
      },
    };

    return modelCapabilities[this.config.model] || modelCapabilities['gemini-2.0-flash'];
  }

  async complete(options: CompletionOptions): Promise<LLMResponse> {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');

    if (!this.client) {
      this.client = new GoogleGenerativeAI(this.config.apiKey!);
    }

    const model = this.client.getGenerativeModel({
      model: this.config.model,
      generationConfig: {
        maxOutputTokens: options.maxTokens || this.config.maxTokens,
        temperature: options.temperature ?? this.config.temperature,
        topP: options.topP,
        stopSequences: options.stopSequences,
      },
    });

    // Convert messages to Gemini format
    const contents = this.convertMessages(options.messages);

    // Add tools if specified
    let tools: any[] | undefined;
    if (options.tools && options.tools.length > 0) {
      tools = [{
        functionDeclarations: options.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
        })),
      }];
    }

    try {
      const result = await model.generateContent({
        contents,
        tools,
      });

      const response = result.response;
      const text = response.text();

      // Extract function calls
      const functionCalls = response.functionCalls?.() || [];
      const toolCalls = functionCalls.map((fc: any, idx: number) => ({
        id: `call_${idx}`,
        name: fc.name,
        arguments: JSON.stringify(fc.args),
      }));

      // Estimate token usage (Gemini doesn't always return this)
      const inputTokens = await this.countTokens(
        options.messages.map((m) => typeof m.content === 'string' ? m.content : '').join(' ')
      );
      const outputTokens = await this.countTokens(text);

      const usage: TokenUsage = {
        inputTokens,
        outputTokens,
        totalTokens: inputTokens + outputTokens,
        estimatedCost: this.estimateCost(inputTokens, outputTokens),
      };

      // Parse structured output if JSON was requested
      let structuredOutput: any;
      if (options.responseFormat?.type.startsWith('json') && text) {
        try {
          const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/) ||
                          text.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            structuredOutput = JSON.parse(jsonMatch[1] || jsonMatch[0]);
          }
        } catch {
          // Failed to parse JSON
        }
      }

      return {
        content: text,
        usage,
        model: this.config.model,
        finishReason: this.mapFinishReason(response.candidates?.[0]?.finishReason),
        structuredOutput,
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      };
    } catch (error: any) {
      throw new Error(`Google Gemini completion failed: ${error.message}`);
    }
  }

  private convertMessages(messages: LLMMessage[]): any[] {
    const contents: any[] = [];
    let systemInstruction = '';

    for (const message of messages) {
      if (message.role === 'system') {
        // Gemini handles system prompts differently
        systemInstruction = typeof message.content === 'string'
          ? message.content
          : message.content.map((c) => c.text || '').join('\n');
        continue;
      }

      const role = message.role === 'assistant' ? 'model' : 'user';
      let parts: any[];

      if (typeof message.content === 'string') {
        parts = [{ text: message.content }];
      } else {
        parts = message.content.map((part) => {
          if (part.type === 'text') {
            return { text: part.text };
          }
          if (part.type === 'image_url' && part.image_url) {
            const url = part.image_url.url;
            if (url.startsWith('data:')) {
              const [header, base64] = url.split(',');
              const mimeType = header.match(/data:(.+);/)?.[1] || 'image/png';
              return {
                inlineData: {
                  mimeType,
                  data: base64,
                },
              };
            }
            return { fileData: { fileUri: url } };
          }
          return { text: '' };
        });
      }

      contents.push({ role, parts });
    }

    // Prepend system instruction to first user message if present
    if (systemInstruction && contents.length > 0) {
      const firstUserIdx = contents.findIndex((c) => c.role === 'user');
      if (firstUserIdx >= 0) {
        contents[firstUserIdx].parts.unshift({
          text: `System Instructions:\n${systemInstruction}\n\n---\n\n`,
        });
      }
    }

    return contents;
  }

  async countTokens(text: string): Promise<number> {
    // Gemini uses a similar tokenizer to GPT
    // Rough approximation: 1 token ≈ 4 chars
    return Math.ceil(text.length / 4);
  }

  async embed(text: string): Promise<number[]> {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');

    if (!this.client) {
      this.client = new GoogleGenerativeAI(this.config.apiKey!);
    }

    const model = this.client.getGenerativeModel({ model: 'text-embedding-004' });
    const result = await model.embedContent(text);

    return result.embedding.values;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey) return false;

    try {
      const { GoogleGenerativeAI } = await import('@google/generative-ai');
      const client = new GoogleGenerativeAI(this.config.apiKey);
      const model = client.getGenerativeModel({ model: this.config.model });

      // Simple test
      await model.generateContent('Hi');
      return true;
    } catch {
      return false;
    }
  }

  private mapFinishReason(reason: string | undefined): LLMResponse['finishReason'] {
    if (!reason) return 'stop';
    const mapping: Record<string, LLMResponse['finishReason']> = {
      STOP: 'stop',
      MAX_TOKENS: 'length',
      SAFETY: 'content_filter',
      RECITATION: 'content_filter',
    };
    return mapping[reason] || 'stop';
  }
}

/**
 * Pre-configured Google Gemini models
 */
export const GOOGLE_MODELS = {
  // Fastest - for real-time tasks
  'gemini-2.0-flash': {
    provider: 'google' as const,
    model: 'gemini-2.0-flash',
    maxTokens: 8192,
    temperature: 0.1,
    costPerInputToken: 0.075,
    costPerOutputToken: 0.30,
    contextWindow: 1000000, // 1M tokens!
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Balanced - for most tasks
  'gemini-1.5-pro': {
    provider: 'google' as const,
    model: 'gemini-1.5-pro',
    maxTokens: 8192,
    temperature: 0.2,
    costPerInputToken: 1.25,
    costPerOutputToken: 5.00,
    contextWindow: 2000000, // 2M tokens!
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },

  // Fast and cheap
  'gemini-1.5-flash': {
    provider: 'google' as const,
    model: 'gemini-1.5-flash',
    maxTokens: 8192,
    temperature: 0.1,
    costPerInputToken: 0.075,
    costPerOutputToken: 0.30,
    contextWindow: 1000000,
    supportsVision: true,
    supportsTools: true,
    supportsStructuredOutput: true,
  },
};

/**
 * Create a Google provider with a pre-configured model
 */
export function createGoogleProvider(
  modelName: keyof typeof GOOGLE_MODELS,
  apiKey?: string
): GoogleProvider {
  return new GoogleProvider(GOOGLE_MODELS[modelName], apiKey);
}
