/**
 * TestAI Agent - QA Knowledge Base
 *
 * This module implements the QA Brain - a RAG (Retrieval Augmented Generation)
 * system that stores and retrieves QA rules, examples, and checklists.
 *
 * ★ Insight ─────────────────────────────────────
 * The QA Brain is the SECRET to beating larger models:
 *
 * 1. Instead of stuffing 50k+ tokens into a prompt, we:
 *    - Index the knowledge base into chunks
 *    - Retrieve only relevant chunks for each task
 *    - Keep prompts small and focused (3-5k tokens)
 *
 * 2. This allows small models to perform like large ones because:
 *    - They see only relevant context
 *    - No confusion from irrelevant information
 *    - Lower token costs, faster responses
 *
 * 3. The knowledge base includes:
 *    - QA rules (validation, security, accessibility)
 *    - Examples (code patterns, test templates)
 *    - Checklists (comprehensive test categories)
 *    - Best practices (from QA_BRAIN.md)
 * ─────────────────────────────────────────────────
 */

import { ContextChunk, ContextType, PageType, TaskType } from '../types';

/**
 * Represents a chunk of knowledge stored in the brain
 */
export interface KnowledgeChunk {
  id: string;
  content: string;
  type: ContextType;
  section: string;
  partNumber: number;
  tags: string[];
  pageTypes?: PageType[];
  taskTypes?: TaskType[];
  tokenCount: number;
  embedding?: number[];
}

/**
 * Search options for querying the knowledge base
 */
export interface SearchOptions {
  query: string;
  type?: ContextType;
  pageType?: PageType;
  taskType?: TaskType;
  tags?: string[];
  limit?: number;
  minScore?: number;
}

/**
 * Abstract base class for knowledge base implementations
 */
export abstract class BaseKnowledgeBase {
  protected chunks: KnowledgeChunk[] = [];
  protected isLoaded: boolean = false;

  /**
   * Load and index the knowledge base
   */
  abstract load(source: string): Promise<void>;

  /**
   * Search for relevant chunks
   */
  abstract search(options: SearchOptions): Promise<ContextChunk[]>;

  /**
   * Get chunks by type
   */
  abstract getByType(type: ContextType, limit?: number): Promise<ContextChunk[]>;

  /**
   * Get chunks for a specific page type
   */
  abstract getForPageType(pageType: PageType, limit?: number): Promise<ContextChunk[]>;

  /**
   * Get chunks for a specific task
   */
  abstract getForTask(task: TaskType, limit?: number): Promise<ContextChunk[]>;

  /**
   * Add a new chunk to the knowledge base
   */
  abstract addChunk(chunk: Omit<KnowledgeChunk, 'id' | 'embedding'>): Promise<void>;

  /**
   * Check if the knowledge base is loaded
   */
  isReady(): boolean {
    return this.isLoaded;
  }

  /**
   * Get statistics about the knowledge base
   */
  getStats(): { totalChunks: number; byType: Record<string, number>; totalTokens: number } {
    const byType: Record<string, number> = {};
    let totalTokens = 0;

    for (const chunk of this.chunks) {
      byType[chunk.type] = (byType[chunk.type] || 0) + 1;
      totalTokens += chunk.tokenCount;
    }

    return { totalChunks: this.chunks.length, byType, totalTokens };
  }
}

/**
 * In-memory knowledge base implementation
 * Good for development and small knowledge bases
 */
export class InMemoryKnowledgeBase extends BaseKnowledgeBase {
  private embedder: (text: string) => Promise<number[]>;

  constructor(embedder?: (text: string) => Promise<number[]>) {
    super();
    // Default embedder that creates simple bag-of-words vectors
    this.embedder = embedder || this.defaultEmbedder.bind(this);
  }

  async load(source: string): Promise<void> {
    // Parse the markdown document into chunks
    const chunks = this.parseMarkdown(source);

    // Generate embeddings for each chunk
    for (const chunk of chunks) {
      chunk.embedding = await this.embedder(chunk.content);
      this.chunks.push(chunk);
    }

    this.isLoaded = true;
  }

  async search(options: SearchOptions): Promise<ContextChunk[]> {
    let candidates = [...this.chunks];

    // Filter by type
    if (options.type) {
      candidates = candidates.filter((c) => c.type === options.type);
    }

    // Filter by page type
    if (options.pageType) {
      candidates = candidates.filter(
        (c) => !c.pageTypes || c.pageTypes.includes(options.pageType!)
      );
    }

    // Filter by task type
    if (options.taskType) {
      candidates = candidates.filter(
        (c) => !c.taskTypes || c.taskTypes.includes(options.taskType!)
      );
    }

    // Filter by tags
    if (options.tags && options.tags.length > 0) {
      candidates = candidates.filter((c) =>
        options.tags!.some((tag) => c.tags.includes(tag))
      );
    }

    // Score by relevance using embeddings
    const queryEmbedding = await this.embedder(options.query);
    const scored = candidates.map((chunk) => ({
      chunk,
      score: this.cosineSimilarity(queryEmbedding, chunk.embedding || []),
    }));

    // Sort by score
    scored.sort((a, b) => b.score - a.score);

    // Apply minimum score filter
    const minScore = options.minScore || 0.3;
    const filtered = scored.filter((s) => s.score >= minScore);

    // Limit results
    const limit = options.limit || 10;
    const limited = filtered.slice(0, limit);

    // Convert to ContextChunk
    return limited.map((s) => ({
      id: s.chunk.id,
      type: s.chunk.type,
      content: s.chunk.content,
      tokenCount: s.chunk.tokenCount,
      relevanceScore: s.score,
      source: s.chunk.section,
      metadata: {
        partNumber: s.chunk.partNumber,
        tags: s.chunk.tags,
      },
    }));
  }

  async getByType(type: ContextType, limit: number = 10): Promise<ContextChunk[]> {
    const filtered = this.chunks.filter((c) => c.type === type);
    return filtered.slice(0, limit).map((c) => this.toContextChunk(c, 1.0));
  }

  async getForPageType(pageType: PageType, limit: number = 10): Promise<ContextChunk[]> {
    const filtered = this.chunks.filter(
      (c) => c.pageTypes && c.pageTypes.includes(pageType)
    );
    return filtered.slice(0, limit).map((c) => this.toContextChunk(c, 1.0));
  }

  async getForTask(task: TaskType, limit: number = 10): Promise<ContextChunk[]> {
    const filtered = this.chunks.filter(
      (c) => c.taskTypes && c.taskTypes.includes(task)
    );
    return filtered.slice(0, limit).map((c) => this.toContextChunk(c, 1.0));
  }

  async addChunk(chunk: Omit<KnowledgeChunk, 'id' | 'embedding'>): Promise<void> {
    const id = `chunk_${this.chunks.length + 1}_${Date.now()}`;
    const embedding = await this.embedder(chunk.content);
    this.chunks.push({ ...chunk, id, embedding });
  }

  // =========================================================================
  // Private Methods
  // =========================================================================

  private parseMarkdown(source: string): KnowledgeChunk[] {
    const chunks: KnowledgeChunk[] = [];
    let chunkId = 0;

    // Split by major sections (## headers)
    const sections = source.split(/(?=^## )/gm);

    for (const section of sections) {
      if (!section.trim()) continue;

      // Extract section info
      const headerMatch = section.match(/^## (\d+)?\.\s*(.+)/);
      const partNumber = headerMatch ? parseInt(headerMatch[1] || '0', 10) : 0;
      const sectionName = headerMatch ? headerMatch[2].trim() : 'Unknown';

      // Split section into smaller chunks (max ~1000 tokens)
      const subChunks = this.splitIntoChunks(section, 4000); // ~1000 tokens

      for (const content of subChunks) {
        const chunk: KnowledgeChunk = {
          id: `chunk_${++chunkId}`,
          content,
          type: this.detectType(content),
          section: sectionName,
          partNumber,
          tags: this.extractTags(content, sectionName),
          pageTypes: this.detectPageTypes(content),
          taskTypes: this.detectTaskTypes(content),
          tokenCount: Math.ceil(content.length / 4),
        };

        chunks.push(chunk);
      }
    }

    return chunks;
  }

  private splitIntoChunks(text: string, maxChars: number): string[] {
    const chunks: string[] = [];
    const paragraphs = text.split(/\n\n+/);
    let currentChunk = '';

    for (const para of paragraphs) {
      if ((currentChunk + para).length > maxChars && currentChunk.length > 0) {
        chunks.push(currentChunk.trim());
        currentChunk = para;
      } else {
        currentChunk += (currentChunk ? '\n\n' : '') + para;
      }
    }

    if (currentChunk.trim()) {
      chunks.push(currentChunk.trim());
    }

    return chunks;
  }

  private detectType(content: string): ContextType {
    if (content.includes('```')) return 'qa_example';
    if (content.includes('- [ ]') || content.includes('☐')) return 'qa_checklist';
    return 'qa_rule';
  }

  private extractTags(content: string, section: string): string[] {
    const tags: string[] = [];

    // Section-based tags
    const sectionLower = section.toLowerCase();
    if (sectionLower.includes('security')) tags.push('security');
    if (sectionLower.includes('validation')) tags.push('validation');
    if (sectionLower.includes('accessibility')) tags.push('accessibility');
    if (sectionLower.includes('performance')) tags.push('performance');
    if (sectionLower.includes('integration')) tags.push('integration');
    if (sectionLower.includes('edge')) tags.push('edge-case');

    // Content-based tags
    const contentLower = content.toLowerCase();
    if (contentLower.includes('xss') || contentLower.includes('injection')) tags.push('security');
    if (contentLower.includes('a11y') || contentLower.includes('aria')) tags.push('accessibility');
    if (contentLower.includes('email') || contentLower.includes('password')) tags.push('auth');
    if (contentLower.includes('form')) tags.push('forms');
    if (contentLower.includes('api')) tags.push('api');

    return [...new Set(tags)];
  }

  private detectPageTypes(content: string): PageType[] | undefined {
    const types: PageType[] = [];
    const contentLower = content.toLowerCase();

    if (contentLower.includes('login')) types.push('login');
    if (contentLower.includes('signup') || contentLower.includes('registration')) types.push('signup');
    if (contentLower.includes('dashboard')) types.push('dashboard');
    if (contentLower.includes('settings')) types.push('settings');
    if (contentLower.includes('checkout')) types.push('checkout');
    if (contentLower.includes('search')) types.push('search');
    if (contentLower.includes('cart')) types.push('cart');
    if (contentLower.includes('product')) types.push('product');
    if (contentLower.includes('admin')) types.push('admin');

    return types.length > 0 ? types : undefined;
  }

  private detectTaskTypes(content: string): TaskType[] | undefined {
    const tasks: TaskType[] = [];
    const contentLower = content.toLowerCase();

    if (contentLower.includes('security') || contentLower.includes('xss') || contentLower.includes('injection')) {
      tasks.push('security_analysis');
    }
    if (contentLower.includes('accessibility') || contentLower.includes('wcag') || contentLower.includes('aria')) {
      tasks.push('accessibility_audit');
    }
    if (contentLower.includes('edge case') || contentLower.includes('boundary')) {
      tasks.push('generate_edge_cases');
    }
    if (contentLower.includes('test case') || contentLower.includes('test scenario')) {
      tasks.push('generate_test_cases');
    }
    if (contentLower.includes('api') || contentLower.includes('endpoint')) {
      tasks.push('api_contract_analysis');
    }
    if (contentLower.includes('i18n') || contentLower.includes('locale') || contentLower.includes('rtl')) {
      tasks.push('i18n_analysis');
    }
    if (contentLower.includes('performance') || contentLower.includes('load time')) {
      tasks.push('performance_analysis');
    }

    return tasks.length > 0 ? tasks : undefined;
  }

  private toContextChunk(chunk: KnowledgeChunk, score: number): ContextChunk {
    return {
      id: chunk.id,
      type: chunk.type,
      content: chunk.content,
      tokenCount: chunk.tokenCount,
      relevanceScore: score,
      source: chunk.section,
      metadata: {
        partNumber: chunk.partNumber,
        tags: chunk.tags,
      },
    };
  }

  /**
   * Simple bag-of-words embedder for development
   * In production, use OpenAI or other embedding services
   */
  private async defaultEmbedder(text: string): Promise<number[]> {
    // Create a simple TF-IDF-like vector
    const words = text.toLowerCase().match(/\b\w+\b/g) || [];
    const wordCounts = new Map<string, number>();

    for (const word of words) {
      wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
    }

    // Use a fixed vocabulary of common QA terms
    const vocabulary = [
      'test', 'input', 'validation', 'error', 'click', 'button', 'form',
      'submit', 'login', 'password', 'email', 'user', 'page', 'element',
      'security', 'xss', 'injection', 'auth', 'token', 'session',
      'accessibility', 'aria', 'label', 'contrast', 'keyboard',
      'edge', 'case', 'boundary', 'empty', 'null', 'special',
      'api', 'request', 'response', 'status', 'code', 'endpoint',
      'performance', 'load', 'time', 'speed', 'memory',
      'integration', 'webhook', 'oauth', 'callback',
      'visual', 'screenshot', 'diff', 'regression',
      'checkout', 'cart', 'payment', 'order', 'product',
      'dashboard', 'settings', 'profile', 'admin',
      'navigation', 'link', 'href', 'url', 'route',
      'data', 'schema', 'field', 'required', 'optional',
    ];

    // Create vector
    const vector: number[] = vocabulary.map((word) => {
      const count = wordCounts.get(word) || 0;
      // Normalize by text length
      return count / Math.max(words.length, 1);
    });

    return vector;
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length || a.length === 0) return 0;

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
    return magnitude === 0 ? 0 : dotProduct / magnitude;
  }
}

/**
 * Factory function to create a knowledge base
 */
export function createKnowledgeBase(
  type: 'memory' | 'qdrant' = 'memory',
  options?: { embedder?: (text: string) => Promise<number[]> }
): BaseKnowledgeBase {
  // For now, only in-memory is implemented
  // Qdrant implementation can be added later
  return new InMemoryKnowledgeBase(options?.embedder);
}
