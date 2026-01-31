/**
 * DeepSeek API Client
 *
 * Handles communication with DeepSeek API for test generation.
 * Uses OpenAI-compatible API format.
 */

import type { AgentMessage, AgentResponse } from './types'

const DEEPSEEK_API_URL = 'https://api.deepseek.com/v1/chat/completions'

interface DeepSeekConfig {
  apiKey: string
  model?: string
  maxTokens?: number
  temperature?: number
}

interface DeepSeekResponse {
  id: string
  object: string
  created: number
  model: string
  choices: {
    index: number
    message: {
      role: string
      content: string
    }
    finish_reason: string
  }[]
  usage: {
    prompt_tokens: number
    completion_tokens: number
    total_tokens: number
  }
}

export class DeepSeekClient {
  private apiKey: string
  private model: string
  private maxTokens: number
  private temperature: number

  constructor(config: DeepSeekConfig) {
    this.apiKey = config.apiKey
    this.model = config.model || 'deepseek-chat'
    this.maxTokens = config.maxTokens || 4096
    this.temperature = config.temperature || 0.2
  }

  async complete(messages: AgentMessage[], options?: {
    maxTokens?: number
    temperature?: number
    jsonMode?: boolean
  }): Promise<AgentResponse> {
    const requestBody: any = {
      model: this.model,
      messages: messages.map(m => ({
        role: m.role,
        content: m.content
      })),
      max_tokens: options?.maxTokens || this.maxTokens,
      temperature: options?.temperature ?? this.temperature
    }

    // Enable JSON mode if requested
    if (options?.jsonMode) {
      requestBody.response_format = { type: 'json_object' }
    }

    try {
      const response = await fetch(DEEPSEEK_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify(requestBody)
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`DeepSeek API error: ${response.status} - ${error}`)
      }

      const data: DeepSeekResponse = await response.json()
      const content = data.choices[0]?.message?.content || ''

      return {
        content,
        usage: {
          inputTokens: data.usage.prompt_tokens,
          outputTokens: data.usage.completion_tokens,
          totalTokens: data.usage.total_tokens
        },
        model: data.model
      }
    } catch (error: any) {
      throw new Error(`DeepSeek completion failed: ${error.message}`)
    }
  }

  /**
   * Parse JSON response safely
   */
  parseJson<T>(content: string): T | null {
    try {
      // Try to extract JSON from markdown code blocks
      const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/)
      if (jsonMatch) {
        return JSON.parse(jsonMatch[1].trim())
      }
      return JSON.parse(content)
    } catch {
      return null
    }
  }

  /**
   * Check if API key is valid
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.complete([{ role: 'user', content: 'Hi' }], { maxTokens: 10 })
      return true
    } catch {
      return false
    }
  }
}

/**
 * Create DeepSeek client from environment or config
 */
export function createDeepSeekClient(apiKey?: string): DeepSeekClient {
  const key = apiKey || process.env.DEEPSEEK_API_KEY || ''

  if (!key) {
    throw new Error('DeepSeek API key is required. Set DEEPSEEK_API_KEY environment variable.')
  }

  return new DeepSeekClient({ apiKey: key })
}
