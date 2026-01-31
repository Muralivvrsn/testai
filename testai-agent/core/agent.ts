/**
 * TestAI Agent - Main Agent Class
 *
 * The unified QA Agent that orchestrates all components to generate test cases.
 *
 * ★ Insight ─────────────────────────────────────
 * This is the main entry point that ties everything together.
 *
 * Usage:
 * ```typescript
 * const agent = await createQAAgent();
 *
 * // Load QA knowledge base
 * await agent.loadKnowledge('./QA_BRAIN.md');
 *
 * // Generate test cases for a feature
 * const result = await agent.generateTests({
 *   name: 'Login Flow',
 *   type: 'login_flow',
 *   description: 'User authentication system',
 *   userStories: [...],
 *   acceptanceCriteria: [...],
 * });
 *
 * console.log(result.testCases);
 * ```
 *
 * The agent automatically:
 * - Routes to the best LLM for each task
 * - Manages context to avoid token limits
 * - Retrieves relevant QA rules
 * - Generates comprehensive test cases
 * ─────────────────────────────────────────────────
 */

import { readFileSync } from 'fs';
import {
  FeatureSpecification,
  PageContext,
  TestCase,
  TestReport,
  TaskType,
  LLMProvider,
} from '../types';
import {
  initializeProviders,
  getSmartRouter,
  SmartModelRouter,
  providerRegistry,
} from '../providers';
import {
  createKnowledgeBase,
  BaseKnowledgeBase,
} from '../brain';
import { ContextManager, createContextManager } from '../context/manager';
import { TestCaseGenerator, createTestGenerator, GenerationOptions, GenerationResult } from '../generators/test-generator';

/**
 * Configuration for the QA Agent
 */
export interface AgentConfig {
  // LLM API Keys (optional - can also use env vars)
  openaiApiKey?: string;
  anthropicApiKey?: string;
  googleApiKey?: string;
  deepseekApiKey?: string;

  // Knowledge base options
  knowledgeBaseType?: 'memory' | 'qdrant';

  // Context options
  maxContextTokens?: number;

  // Provider preferences
  preferredProvider?: LLMProvider;
  costLimit?: number;
}

/**
 * Status of the agent
 */
export interface AgentStatus {
  isInitialized: boolean;
  knowledgeBaseLoaded: boolean;
  knowledgeBaseStats?: {
    totalChunks: number;
    byType: Record<string, number>;
    totalTokens: number;
  };
  availableProviders: string[];
}

/**
 * The QA Agent - Main interface for test generation
 */
export class QAAgent {
  private config: AgentConfig;
  private knowledgeBase: BaseKnowledgeBase;
  private contextManager: ContextManager;
  private testGenerator: TestCaseGenerator;
  private router: SmartModelRouter;
  private isInitialized: boolean = false;

  constructor(config: AgentConfig = {}) {
    this.config = config;

    // Initialize components
    this.knowledgeBase = createKnowledgeBase(config.knowledgeBaseType || 'memory');
    this.contextManager = createContextManager(this.knowledgeBase, {
      maxTokens: config.maxContextTokens || 8000,
    });
    this.testGenerator = createTestGenerator(this.knowledgeBase);

    // Initialize providers
    this.initializeProviders();
    this.router = getSmartRouter();
    this.isInitialized = true;
  }

  /**
   * Initialize LLM providers from config or environment
   */
  private initializeProviders(): void {
    // Set env vars from config if provided
    if (this.config.openaiApiKey) {
      process.env.OPENAI_API_KEY = this.config.openaiApiKey;
    }
    if (this.config.anthropicApiKey) {
      process.env.ANTHROPIC_API_KEY = this.config.anthropicApiKey;
    }
    if (this.config.googleApiKey) {
      process.env.GOOGLE_API_KEY = this.config.googleApiKey;
    }
    if (this.config.deepseekApiKey) {
      process.env.DEEPSEEK_API_KEY = this.config.deepseekApiKey;
    }

    // Initialize provider registry
    initializeProviders();
  }

  /**
   * Load the QA knowledge base from a file
   */
  async loadKnowledge(filePath: string): Promise<void> {
    const content = readFileSync(filePath, 'utf-8');
    await this.knowledgeBase.load(content);
  }

  /**
   * Load knowledge from a string
   */
  async loadKnowledgeFromString(content: string): Promise<void> {
    await this.knowledgeBase.load(content);
  }

  /**
   * Generate comprehensive test cases for a feature specification
   */
  async generateTests(
    specification: FeatureSpecification,
    options?: Partial<GenerationOptions>
  ): Promise<GenerationResult> {
    if (!this.knowledgeBase.isReady()) {
      throw new Error('Knowledge base not loaded. Call loadKnowledge() first.');
    }

    return this.testGenerator.generate({
      specification,
      ...options,
      includeEdgeCases: options?.includeEdgeCases ?? true,
      includeSecurityTests: options?.includeSecurityTests ?? false,
      includeAccessibilityTests: options?.includeAccessibilityTests ?? false,
    });
  }

  /**
   * Generate test cases with page context (from browser automation)
   */
  async generateTestsWithContext(
    specification: FeatureSpecification,
    pageContext: PageContext,
    options?: Partial<GenerationOptions>
  ): Promise<GenerationResult> {
    if (!this.knowledgeBase.isReady()) {
      throw new Error('Knowledge base not loaded. Call loadKnowledge() first.');
    }

    return this.testGenerator.generate({
      specification,
      pageContext,
      ...options,
      includeEdgeCases: options?.includeEdgeCases ?? true,
    });
  }

  /**
   * Classify a page based on its URL and DOM
   */
  async classifyPage(url: string, title: string, elements: any[]): Promise<{
    pageType: string;
    confidence: number;
    primaryPurpose: string;
    keyElements: any[];
  }> {
    const provider = await this.router.getProvider('classify_page');

    const prompt = `Classify this page:
URL: ${url}
Title: ${title}
Elements: ${JSON.stringify(elements.slice(0, 30), null, 2)}

Return JSON with: pageType, confidence, primaryPurpose, keyElements`;

    const response = await provider.complete({
      messages: [
        { role: 'system', content: 'You are a page classifier. Return valid JSON only.' },
        { role: 'user', content: prompt },
      ],
      maxTokens: 500,
      temperature: 0.1,
      responseFormat: { type: 'json_object' },
    });

    try {
      return response.structuredOutput || JSON.parse(response.content);
    } catch {
      return {
        pageType: 'unknown',
        confidence: 0.5,
        primaryPurpose: 'Unknown',
        keyElements: [],
      };
    }
  }

  /**
   * Analyze security vulnerabilities in a feature
   */
  async analyzeSecurit(specification: FeatureSpecification): Promise<{
    vulnerabilities: any[];
    securityTests: any[];
  }> {
    const provider = await this.router.getProvider('security_analysis');

    const context = await this.contextManager.buildContext({
      task: 'security_analysis',
      query: `Security analysis for ${specification.name}`,
      specification,
    });

    const response = await provider.complete({
      messages: [
        {
          role: 'system',
          content: `You are a security expert. Analyze the specification for vulnerabilities.
Return JSON with: vulnerabilities (array), securityTests (array)`,
        },
        {
          role: 'user',
          content: `Feature: ${specification.name}
Type: ${specification.type}
Description: ${specification.description}

Context:
${this.contextManager.formatContext(context)}`,
        },
      ],
      maxTokens: 2000,
      temperature: 0.2,
      responseFormat: { type: 'json_object' },
    });

    try {
      return response.structuredOutput || JSON.parse(response.content);
    } catch {
      return { vulnerabilities: [], securityTests: [] };
    }
  }

  /**
   * Get agent status
   */
  getStatus(): AgentStatus {
    return {
      isInitialized: this.isInitialized,
      knowledgeBaseLoaded: this.knowledgeBase.isReady(),
      knowledgeBaseStats: this.knowledgeBase.isReady()
        ? this.knowledgeBase.getStats()
        : undefined,
      availableProviders: providerRegistry.getAll().map(
        (p) => `${p.getProvider()}:${p.getConfig().model}`
      ),
    };
  }

  /**
   * Get the smart router for advanced usage
   */
  getRouter(): SmartModelRouter {
    return this.router;
  }

  /**
   * Get the knowledge base for advanced usage
   */
  getKnowledgeBase(): BaseKnowledgeBase {
    return this.knowledgeBase;
  }

  /**
   * Get the context manager for advanced usage
   */
  getContextManager(): ContextManager {
    return this.contextManager;
  }
}

/**
 * Factory function to create a QA Agent
 */
export async function createQAAgent(config?: AgentConfig): Promise<QAAgent> {
  return new QAAgent(config);
}

/**
 * Quick helper to generate tests from a specification string
 */
export async function quickGenerateTests(
  specificationJson: string,
  knowledgePath?: string
): Promise<GenerationResult> {
  const agent = await createQAAgent();

  if (knowledgePath) {
    await agent.loadKnowledge(knowledgePath);
  }

  const specification: FeatureSpecification = JSON.parse(specificationJson);
  return agent.generateTests(specification);
}
