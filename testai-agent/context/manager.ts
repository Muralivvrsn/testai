/**
 * TestAI Agent - Context Manager
 *
 * Intelligent context management to avoid LLM context window limits.
 *
 * ★ Insight ─────────────────────────────────────
 * The Context Manager is CRITICAL for beating larger models.
 *
 * Problem: QA_BRAIN.md alone is 50k+ tokens
 * Solution: Smart context budgeting
 *
 * 1. Reserve space for:
 *    - System prompt (~500 tokens)
 *    - Output (~2000 tokens)
 *    - User input (~1000 tokens)
 *
 * 2. Fill remaining space with:
 *    - Most relevant QA rules (ranked by similarity)
 *    - Page context (compressed DOM)
 *    - Recent action history (summarized)
 *
 * 3. Result:
 *    - Small models see only relevant context
 *    - No wasted tokens on irrelevant info
 *    - Better quality outputs
 * ─────────────────────────────────────────────────
 */

import {
  ContextChunk,
  ContextType,
  ContextBudget,
  ContextStrategy,
  TaskType,
  PageType,
  PageContext,
} from '../types';
import { BaseKnowledgeBase } from '../brain/knowledge-base';

/**
 * Configuration for context building
 */
export interface ContextConfig {
  maxTokens: number;
  reservedForSystem: number;
  reservedForOutput: number;
  reservedForUserInput: number;
  strategy: ContextStrategy;
}

/**
 * Built context ready for LLM
 */
export interface BuiltContext {
  chunks: ContextChunk[];
  totalTokens: number;
  budget: ContextBudget;
  summary?: string;
}

/**
 * Default context strategies for different task types
 */
export const DEFAULT_STRATEGIES: Record<TaskType, ContextStrategy> = {
  classify_page: {
    name: 'classification',
    prioritize: ['qa_rule', 'qa_example'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 3, qa_example: 2, qa_checklist: 0, page_context: 1, element_context: 0, specification: 0, previous_result: 0, memory: 0, custom: 0 },
  },
  classify_elements: {
    name: 'element_classification',
    prioritize: ['qa_rule', 'qa_example', 'element_context'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 3, qa_example: 2, qa_checklist: 0, page_context: 1, element_context: 5, specification: 0, previous_result: 0, memory: 0, custom: 0 },
  },
  generate_test_cases: {
    name: 'test_generation',
    prioritize: ['specification', 'qa_rule', 'qa_checklist', 'qa_example'],
    compress: false,
    summarize: true,
    maxChunksPerType: { qa_rule: 5, qa_example: 3, qa_checklist: 3, page_context: 2, element_context: 5, specification: 5, previous_result: 2, memory: 1, custom: 0 },
  },
  generate_edge_cases: {
    name: 'edge_case_generation',
    prioritize: ['qa_rule', 'qa_checklist', 'qa_example', 'specification'],
    compress: false,
    summarize: true,
    maxChunksPerType: { qa_rule: 8, qa_example: 5, qa_checklist: 5, page_context: 1, element_context: 3, specification: 3, previous_result: 1, memory: 1, custom: 0 },
  },
  security_analysis: {
    name: 'security',
    prioritize: ['qa_rule', 'qa_checklist', 'page_context'],
    compress: false,
    summarize: false,
    maxChunksPerType: { qa_rule: 10, qa_example: 3, qa_checklist: 5, page_context: 2, element_context: 5, specification: 2, previous_result: 1, memory: 0, custom: 0 },
  },
  accessibility_audit: {
    name: 'accessibility',
    prioritize: ['qa_rule', 'qa_checklist', 'page_context', 'element_context'],
    compress: false,
    summarize: false,
    maxChunksPerType: { qa_rule: 8, qa_example: 3, qa_checklist: 5, page_context: 2, element_context: 10, specification: 1, previous_result: 1, memory: 0, custom: 0 },
  },
  api_contract_analysis: {
    name: 'api_analysis',
    prioritize: ['qa_rule', 'qa_example', 'specification'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 5, qa_example: 5, qa_checklist: 2, page_context: 0, element_context: 0, specification: 10, previous_result: 2, memory: 0, custom: 0 },
  },
  visual_regression_analysis: {
    name: 'visual',
    prioritize: ['qa_rule', 'qa_example'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 3, qa_example: 3, qa_checklist: 1, page_context: 1, element_context: 0, specification: 1, previous_result: 3, memory: 0, custom: 0 },
  },
  performance_analysis: {
    name: 'performance',
    prioritize: ['qa_rule', 'qa_checklist', 'page_context'],
    compress: true,
    summarize: true,
    maxChunksPerType: { qa_rule: 5, qa_example: 3, qa_checklist: 3, page_context: 2, element_context: 0, specification: 2, previous_result: 2, memory: 1, custom: 0 },
  },
  i18n_analysis: {
    name: 'i18n',
    prioritize: ['qa_rule', 'qa_checklist', 'qa_example'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 5, qa_example: 5, qa_checklist: 3, page_context: 2, element_context: 3, specification: 2, previous_result: 1, memory: 0, custom: 0 },
  },
  summarize_context: {
    name: 'summarization',
    prioritize: ['page_context', 'element_context', 'memory'],
    compress: true,
    summarize: false,
    maxChunksPerType: { qa_rule: 0, qa_example: 0, qa_checklist: 0, page_context: 5, element_context: 10, specification: 3, previous_result: 5, memory: 5, custom: 0 },
  },
  prioritize_tests: {
    name: 'prioritization',
    prioritize: ['qa_rule', 'specification', 'previous_result', 'memory'],
    compress: true,
    summarize: true,
    maxChunksPerType: { qa_rule: 5, qa_example: 2, qa_checklist: 2, page_context: 1, element_context: 3, specification: 5, previous_result: 5, memory: 3, custom: 0 },
  },
};

/**
 * Context Manager - Builds optimized context for LLM calls
 */
export class ContextManager {
  private knowledgeBase: BaseKnowledgeBase;
  private defaultConfig: ContextConfig;

  constructor(knowledgeBase: BaseKnowledgeBase, config?: Partial<ContextConfig>) {
    this.knowledgeBase = knowledgeBase;
    this.defaultConfig = {
      maxTokens: config?.maxTokens || 8000,
      reservedForSystem: config?.reservedForSystem || 500,
      reservedForOutput: config?.reservedForOutput || 2000,
      reservedForUserInput: config?.reservedForUserInput || 1000,
      strategy: config?.strategy || DEFAULT_STRATEGIES.generate_test_cases,
    };
  }

  /**
   * Build context for a specific task
   */
  async buildContext(options: {
    task: TaskType;
    query: string;
    pageContext?: PageContext;
    specification?: any;
    previousResults?: any[];
    memory?: any[];
    customChunks?: ContextChunk[];
    maxTokens?: number;
  }): Promise<BuiltContext> {
    const strategy = DEFAULT_STRATEGIES[options.task] || this.defaultConfig.strategy;
    const maxTokens = options.maxTokens || this.defaultConfig.maxTokens;

    // Calculate budget
    const budget: ContextBudget = {
      maxTokens,
      reservedForOutput: this.defaultConfig.reservedForOutput,
      reservedForSystem: this.defaultConfig.reservedForSystem,
      availableForContext: maxTokens -
        this.defaultConfig.reservedForOutput -
        this.defaultConfig.reservedForSystem -
        this.defaultConfig.reservedForUserInput,
    };

    const chunks: ContextChunk[] = [];
    let usedTokens = 0;

    // 1. Add specification context (highest priority for test generation)
    if (options.specification && strategy.maxChunksPerType.specification > 0) {
      const specChunk = this.createSpecificationChunk(options.specification);
      if (usedTokens + specChunk.tokenCount <= budget.availableForContext) {
        chunks.push(specChunk);
        usedTokens += specChunk.tokenCount;
      }
    }

    // 2. Search knowledge base for relevant QA rules
    const searchResults = await this.knowledgeBase.search({
      query: options.query,
      taskType: options.task,
      limit: 20,
      minScore: 0.2,
    });

    // Group by type and apply limits
    const byType = this.groupByType(searchResults);

    for (const type of strategy.prioritize) {
      const typeChunks = byType.get(type) || [];
      const maxForType = strategy.maxChunksPerType[type] || 0;
      let addedForType = 0;

      for (const chunk of typeChunks) {
        if (addedForType >= maxForType) break;
        if (usedTokens + chunk.tokenCount > budget.availableForContext) continue;

        // Optionally compress the chunk
        const finalChunk = strategy.compress
          ? this.compressChunk(chunk)
          : chunk;

        chunks.push(finalChunk);
        usedTokens += finalChunk.tokenCount;
        addedForType++;
      }
    }

    // 3. Add page context if available
    if (options.pageContext && strategy.maxChunksPerType.page_context > 0) {
      const pageChunk = this.createPageContextChunk(options.pageContext, strategy.compress);
      if (usedTokens + pageChunk.tokenCount <= budget.availableForContext) {
        chunks.push(pageChunk);
        usedTokens += pageChunk.tokenCount;
      }
    }

    // 4. Add previous results for learning
    if (options.previousResults && strategy.maxChunksPerType.previous_result > 0) {
      const resultsChunk = this.createResultsChunk(
        options.previousResults,
        strategy.maxChunksPerType.previous_result
      );
      if (usedTokens + resultsChunk.tokenCount <= budget.availableForContext) {
        chunks.push(resultsChunk);
        usedTokens += resultsChunk.tokenCount;
      }
    }

    // 5. Add memory context
    if (options.memory && strategy.maxChunksPerType.memory > 0) {
      const memoryChunk = this.createMemoryChunk(
        options.memory,
        strategy.maxChunksPerType.memory
      );
      if (usedTokens + memoryChunk.tokenCount <= budget.availableForContext) {
        chunks.push(memoryChunk);
        usedTokens += memoryChunk.tokenCount;
      }
    }

    // 6. Add custom chunks
    if (options.customChunks) {
      for (const chunk of options.customChunks) {
        if (usedTokens + chunk.tokenCount <= budget.availableForContext) {
          chunks.push(chunk);
          usedTokens += chunk.tokenCount;
        }
      }
    }

    // Generate summary if strategy requires it
    let summary: string | undefined;
    if (strategy.summarize && chunks.length > 5) {
      summary = this.generateContextSummary(chunks);
    }

    return {
      chunks,
      totalTokens: usedTokens,
      budget,
      summary,
    };
  }

  /**
   * Format context chunks into a string for the LLM
   */
  formatContext(builtContext: BuiltContext): string {
    const sections: string[] = [];

    // Group chunks by type for better organization
    const byType = this.groupByType(builtContext.chunks);

    // Format each type
    const typeOrder: ContextType[] = [
      'specification',
      'qa_rule',
      'qa_checklist',
      'qa_example',
      'page_context',
      'element_context',
      'previous_result',
      'memory',
      'custom',
    ];

    for (const type of typeOrder) {
      const chunks = byType.get(type);
      if (!chunks || chunks.length === 0) continue;

      const typeLabel = this.getTypeLabel(type);
      const typeContent = chunks.map((c) => c.content).join('\n\n');

      sections.push(`## ${typeLabel}\n\n${typeContent}`);
    }

    // Add summary if present
    if (builtContext.summary) {
      sections.unshift(`## Context Summary\n\n${builtContext.summary}`);
    }

    return sections.join('\n\n---\n\n');
  }

  /**
   * Get approximate token count for a string
   */
  countTokens(text: string): number {
    // Rough approximation: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  // =========================================================================
  // Private Methods
  // =========================================================================

  private groupByType(chunks: ContextChunk[]): Map<ContextType, ContextChunk[]> {
    const grouped = new Map<ContextType, ContextChunk[]>();

    for (const chunk of chunks) {
      const existing = grouped.get(chunk.type) || [];
      existing.push(chunk);
      grouped.set(chunk.type, existing);
    }

    return grouped;
  }

  private createSpecificationChunk(spec: any): ContextChunk {
    const content = typeof spec === 'string'
      ? spec
      : JSON.stringify(spec, null, 2);

    return {
      id: 'spec_' + Date.now(),
      type: 'specification',
      content: `Feature Specification:\n${content}`,
      tokenCount: this.countTokens(content),
      relevanceScore: 1.0,
      source: 'user_input',
      metadata: {},
    };
  }

  private createPageContextChunk(pageContext: PageContext, compress: boolean): ContextChunk {
    let content: string;

    if (compress) {
      // Create compressed version
      const elements = pageContext.elements.slice(0, 20).map((e) => ({
        mmid: e.mmid,
        tag: e.tag,
        type: e.type,
        text: e.text.slice(0, 50),
      }));

      content = `Page: ${pageContext.url}
Type: ${pageContext.type}
Title: ${pageContext.title}
Elements (${pageContext.elements.length} total):
${JSON.stringify(elements, null, 2)}`;
    } else {
      content = `Page: ${pageContext.url}
Type: ${pageContext.type}
Title: ${pageContext.title}
Elements (${pageContext.elements.length} total):
${JSON.stringify(pageContext.elements, null, 2)}
Forms (${pageContext.forms.length}):
${JSON.stringify(pageContext.forms, null, 2)}`;
    }

    return {
      id: 'page_' + Date.now(),
      type: 'page_context',
      content,
      tokenCount: this.countTokens(content),
      relevanceScore: 1.0,
      source: pageContext.url,
      metadata: { pageType: pageContext.type },
    };
  }

  private createResultsChunk(results: any[], maxCount: number): ContextChunk {
    const recentResults = results.slice(-maxCount);
    const content = `Previous Test Results:
${recentResults.map((r) => `- ${r.testId || r.name}: ${r.status} (${r.duration}ms)`).join('\n')}`;

    return {
      id: 'results_' + Date.now(),
      type: 'previous_result',
      content,
      tokenCount: this.countTokens(content),
      relevanceScore: 0.8,
      source: 'history',
      metadata: { count: recentResults.length },
    };
  }

  private createMemoryChunk(memory: any[], maxCount: number): ContextChunk {
    const recentMemory = memory.slice(-maxCount);
    const content = `Session Memory:
${recentMemory.map((m) => `- ${m.action || m.type}: ${m.summary || JSON.stringify(m)}`).join('\n')}`;

    return {
      id: 'memory_' + Date.now(),
      type: 'memory',
      content,
      tokenCount: this.countTokens(content),
      relevanceScore: 0.7,
      source: 'session',
      metadata: { count: recentMemory.length },
    };
  }

  private compressChunk(chunk: ContextChunk): ContextChunk {
    // Simple compression: remove extra whitespace and limit length
    const compressed = chunk.content
      .replace(/\s+/g, ' ')
      .replace(/```[\s\S]*?```/g, '[code example]')
      .slice(0, 2000);

    return {
      ...chunk,
      content: compressed,
      tokenCount: this.countTokens(compressed),
    };
  }

  private generateContextSummary(chunks: ContextChunk[]): string {
    const types = new Set(chunks.map((c) => c.type));
    const totalTokens = chunks.reduce((sum, c) => sum + c.tokenCount, 0);

    return `Context includes ${chunks.length} chunks (${totalTokens} tokens) covering: ${Array.from(types).join(', ')}`;
  }

  private getTypeLabel(type: ContextType): string {
    const labels: Record<ContextType, string> = {
      qa_rule: 'QA Rules & Best Practices',
      qa_example: 'Examples & Code Patterns',
      qa_checklist: 'Checklists',
      page_context: 'Current Page Context',
      element_context: 'Element Details',
      specification: 'Feature Specification',
      previous_result: 'Previous Test Results',
      memory: 'Session Memory',
      custom: 'Additional Context',
    };
    return labels[type] || type;
  }
}

/**
 * Factory function to create a context manager
 */
export function createContextManager(
  knowledgeBase: BaseKnowledgeBase,
  config?: Partial<ContextConfig>
): ContextManager {
  return new ContextManager(knowledgeBase, config);
}
