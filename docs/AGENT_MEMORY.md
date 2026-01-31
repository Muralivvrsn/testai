# Agent Memory Architecture

> Deep dive into the memory system that enables the QA agent to learn, remember, and maintain context across sessions.

---

## Table of Contents

1. [Memory Overview](#memory-overview)
2. [Three-Layer Memory Model](#three-layer-memory-model)
3. [Working Memory (Short-Term)](#working-memory-short-term)
4. [Session Memory (Medium-Term)](#session-memory-medium-term)
5. [Persistent Memory (Long-Term)](#persistent-memory-long-term)
6. [Memory Operations](#memory-operations)
7. [Vector Store Integration](#vector-store-integration)
8. [Session Continuity](#session-continuity)

---

## Memory Overview

### Why Memory Matters

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WHY AGENTS NEED MEMORY                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Without Memory:                        With Memory:                             │
│  ┌─────────────────────┐                ┌─────────────────────┐                 │
│  │ • Forgets previous  │                │ • Recalls previous  │                 │
│  │   test results      │                │   bugs found        │                 │
│  │ • Repeats same      │                │ • Avoids redundant  │                 │
│  │   tests             │                │   testing           │                 │
│  │ • Can't learn from  │                │ • Learns patterns   │                 │
│  │   mistakes          │                │   over time         │                 │
│  │ • No session        │                │ • Continues where   │                 │
│  │   continuity        │                │   it left off       │                 │
│  │ • Limited context   │                │ • Rich context      │                 │
│  │   understanding     │                │   from history      │                 │
│  └─────────────────────┘                └─────────────────────┘                 │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Memory Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MEMORY ARCHITECTURE                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                     WORKING MEMORY (Context Window)                      │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │    │
│  │  │ Message │  │ Message │  │ Message │  │ Message │  │ Message │  ...  │    │
│  │  │    1    │  │    2    │  │    3    │  │    4    │  │    5    │       │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │    │
│  │                                                                          │    │
│  │  Capacity: ~100K tokens | Lifetime: Current task | Access: Immediate    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                       │                                          │
│                                       │ Compaction                               │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                     SESSION MEMORY (Summarized)                          │    │
│  │  ┌────────────────────────────────────────────────────────────────┐     │    │
│  │  │  Summary: "Tested login page. Found 2 bugs: validation error   │     │    │
│  │  │  on empty email, password field accepts spaces. Tested 15      │     │    │
│  │  │  elements. Coverage: 80%."                                      │     │    │
│  │  └────────────────────────────────────────────────────────────────┘     │    │
│  │                                                                          │    │
│  │  Capacity: ~10K tokens | Lifetime: Current session | Access: Fast       │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                       │                                          │
│                                       │ Extraction & Indexing                    │
│                                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                     PERSISTENT MEMORY (Long-term)                        │    │
│  │                                                                          │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐               │    │
│  │  │  SQLite DB    │  │  Vector Store │  │  File System  │               │    │
│  │  │  (Structured) │  │  (Semantic)   │  │  (Evidence)   │               │    │
│  │  │               │  │               │  │               │               │    │
│  │  │ • Test results│  │ • Bug embeds  │  │ • Screenshots │               │    │
│  │  │ • Bug history │  │ • Page embeds │  │ • Logs        │               │    │
│  │  │ • Metrics     │  │ • Pattern     │  │ • Reports     │               │    │
│  │  │ • Config      │  │   similarity  │  │ • Baselines   │               │    │
│  │  └───────────────┘  └───────────────┘  └───────────────┘               │    │
│  │                                                                          │    │
│  │  Capacity: Unlimited | Lifetime: Forever | Access: Query-based          │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Three-Layer Memory Model

### Core Interfaces

```typescript
/**
 * Core memory system interfaces
 */

interface MemorySystem {
  working: WorkingMemory;
  session: SessionMemory;
  persistent: PersistentMemory;
}

interface WorkingMemory {
  messages: Message[];
  currentTask: Task | null;
  recentObservations: Observation[];
  activeElements: Map<string, ElementInfo>;

  // Limits
  maxMessages: number;
  maxTokens: number;

  // Operations
  add(message: Message): void;
  getContext(): Message[];
  clear(): void;
}

interface SessionMemory {
  id: string;
  startTime: Date;
  summary: string;

  // Task tracking
  completedTasks: TaskResult[];
  currentTask: Task | null;
  taskQueue: Task[];

  // Findings
  bugs: Bug[];
  observations: Observation[];
  testedElements: Set<string>;

  // State
  visitedUrls: Set<string>;
  pageSnapshots: Map<string, PageSnapshot>;

  // Operations
  update(data: Partial<SessionMemory>): void;
  getSummary(): string;
  export(): SessionExport;
}

interface PersistentMemory {
  // Structured storage
  db: Database;

  // Semantic storage
  vectorStore: VectorStore;

  // File storage
  fileSystem: FileSystem;

  // Operations
  store(entry: MemoryEntry): Promise<void>;
  query(query: MemoryQuery): Promise<MemoryEntry[]>;
  search(embedding: number[], limit: number): Promise<MemoryEntry[]>;
}

interface MemoryEntry {
  id: string;
  type: MemoryType;
  content: any;
  embedding?: number[];
  metadata: MemoryMetadata;
  timestamp: Date;
}

type MemoryType =
  | 'test_result'
  | 'bug_report'
  | 'page_model'
  | 'learned_pattern'
  | 'user_preference'
  | 'session_summary';

interface MemoryMetadata {
  source: string;
  confidence: number;
  tags: string[];
  relatedIds: string[];
  expiresAt?: Date;
}
```

---

## Working Memory (Short-Term)

### Implementation

```typescript
/**
 * Working Memory - holds current conversation context
 * Equivalent to the LLM's context window
 */

class WorkingMemoryManager {
  private messages: Message[] = [];
  private config: WorkingMemoryConfig;
  private tokenCounter: TokenCounter;

  constructor(config: WorkingMemoryConfig) {
    this.config = config;
    this.tokenCounter = new TokenCounter(config.model);
  }

  /**
   * Add a message to working memory
   */
  add(message: Message): void {
    this.messages.push(message);

    // Check if we need to compact
    if (this.shouldCompact()) {
      this.compact();
    }
  }

  /**
   * Get messages for LLM context
   */
  getContext(): Message[] {
    return [...this.messages];
  }

  /**
   * Get current token usage
   */
  getTokenUsage(): { used: number; limit: number; percentage: number } {
    const used = this.tokenCounter.count(this.messages);
    return {
      used,
      limit: this.config.maxTokens,
      percentage: (used / this.config.maxTokens) * 100
    };
  }

  /**
   * Check if compaction is needed
   */
  private shouldCompact(): boolean {
    const usage = this.getTokenUsage();
    return usage.percentage > this.config.compactionThreshold;
  }

  /**
   * Compact older messages into summaries
   */
  private async compact(): Promise<void> {
    const usage = this.getTokenUsage();
    console.log(`Compacting working memory (${usage.percentage.toFixed(1)}% used)`);

    // Keep system message and recent messages
    const systemMessage = this.messages.find(m => m.role === 'system');
    const recentMessages = this.messages.slice(-this.config.keepRecentCount);
    const oldMessages = this.messages.slice(
      systemMessage ? 1 : 0,
      -this.config.keepRecentCount
    );

    if (oldMessages.length === 0) return;

    // Summarize old messages
    const summary = await this.summarize(oldMessages);

    // Extract key facts for long-term storage
    const keyFacts = await this.extractKeyFacts(oldMessages);

    // Store key facts in persistent memory
    for (const fact of keyFacts) {
      await this.persistentMemory.store({
        type: 'learned_pattern',
        content: fact,
        timestamp: new Date()
      });
    }

    // Rebuild messages array
    this.messages = [
      ...(systemMessage ? [systemMessage] : []),
      {
        role: 'system',
        content: `[Previous context summary]\n${summary}`
      },
      ...recentMessages
    ];

    const newUsage = this.getTokenUsage();
    console.log(`Compaction complete (${newUsage.percentage.toFixed(1)}% used)`);
  }

  /**
   * Summarize a list of messages
   */
  private async summarize(messages: Message[]): Promise<string> {
    // Use a cheap model for summarization
    const response = await this.llm.chat({
      model: 'haiku',
      messages: [
        {
          role: 'system',
          content: 'Summarize the following conversation, preserving key facts, decisions, and findings. Be concise but complete.'
        },
        {
          role: 'user',
          content: messages.map(m => `${m.role}: ${m.content}`).join('\n\n')
        }
      ]
    });

    return response.content;
  }

  /**
   * Extract key facts worth preserving long-term
   */
  private async extractKeyFacts(messages: Message[]): Promise<string[]> {
    const response = await this.llm.chat({
      model: 'haiku',
      messages: [
        {
          role: 'system',
          content: `Extract key facts from this conversation that should be remembered long-term.
Output as a JSON array of strings. Focus on:
- Bugs discovered
- Patterns learned
- Important decisions made
- User preferences observed`
        },
        {
          role: 'user',
          content: messages.map(m => `${m.role}: ${m.content}`).join('\n\n')
        }
      ]
    });

    try {
      return JSON.parse(response.content);
    } catch {
      return [];
    }
  }
}

interface WorkingMemoryConfig {
  model: string;
  maxTokens: number;
  compactionThreshold: number; // e.g., 0.8 = 80%
  keepRecentCount: number;     // Messages to keep intact
}
```

### Token Management

```typescript
/**
 * Token counting and budget management
 */

class TokenCounter {
  private encoder: Tiktoken;

  constructor(model: string) {
    this.encoder = getEncoding(model);
  }

  /**
   * Count tokens in messages
   */
  count(messages: Message[]): number {
    let total = 0;

    for (const message of messages) {
      // Base tokens per message
      total += 4; // <role>, content, etc.

      // Content tokens
      if (typeof message.content === 'string') {
        total += this.encoder.encode(message.content).length;
      } else if (Array.isArray(message.content)) {
        // Multi-part content
        for (const part of message.content) {
          if (part.type === 'text') {
            total += this.encoder.encode(part.text).length;
          } else if (part.type === 'image') {
            total += this.estimateImageTokens(part);
          }
        }
      }

      // Tool calls
      if (message.tool_calls) {
        for (const call of message.tool_calls) {
          total += this.encoder.encode(call.name).length;
          total += this.encoder.encode(JSON.stringify(call.arguments)).length;
        }
      }
    }

    return total;
  }

  /**
   * Estimate tokens for image content
   */
  private estimateImageTokens(image: ImageContent): number {
    // Rough estimate based on image size
    // Actual calculation depends on the model
    const { width, height } = image.dimensions || { width: 1024, height: 1024 };
    return Math.ceil((width * height) / 750);
  }
}

class TokenBudget {
  private config: TokenBudgetConfig;
  private usage: TokenUsage = { input: 0, output: 0 };

  /**
   * Allocate tokens for different purposes
   */
  allocate(): TokenAllocation {
    const total = this.config.maxContextTokens;

    return {
      system: Math.floor(total * 0.15),      // 15% for system prompt
      knowledge: Math.floor(total * 0.20),   // 20% for relevant knowledge
      history: Math.floor(total * 0.35),     // 35% for conversation history
      currentTask: Math.floor(total * 0.15), // 15% for current task
      tools: Math.floor(total * 0.10),       // 10% for tool definitions
      buffer: Math.floor(total * 0.05)       // 5% safety buffer
    };
  }

  /**
   * Check if we can afford a message
   */
  canAfford(tokens: number): boolean {
    const allocation = this.allocate();
    const used = this.usage.input + this.usage.output;
    return (used + tokens) < (this.config.maxContextTokens - allocation.buffer);
  }
}
```

---

## Session Memory (Medium-Term)

### Implementation

```typescript
/**
 * Session Memory - maintains state within a testing session
 */

class SessionMemoryManager {
  private session: SessionState;
  private progressFile: string;

  constructor(sessionId: string) {
    this.session = this.createNewSession(sessionId);
    this.progressFile = `progress-${sessionId}.txt`;
  }

  /**
   * Create a new session
   */
  private createNewSession(id: string): SessionState {
    return {
      id,
      startTime: new Date(),

      // Summary (updated periodically)
      summary: '',

      // Task tracking
      completedTasks: [],
      currentTask: null,
      taskQueue: [],

      // Findings
      bugs: [],
      observations: [],

      // Coverage tracking
      testedElements: new Set(),
      visitedUrls: new Set(),

      // Page state cache
      pageSnapshots: new Map(),

      // Statistics
      stats: {
        actionsPerformed: 0,
        assertionsPassed: 0,
        assertionsFailed: 0,
        errorsEncountered: 0
      }
    };
  }

  /**
   * Update session with new data
   */
  update(data: Partial<SessionState>): void {
    Object.assign(this.session, data);

    // Update summary if significant changes
    if (this.shouldUpdateSummary(data)) {
      this.updateSummary();
    }
  }

  /**
   * Mark an element as tested
   */
  markTested(elementId: string, result: TestResult): void {
    this.session.testedElements.add(elementId);
    this.session.stats.actionsPerformed++;

    if (result.assertion) {
      if (result.passed) {
        this.session.stats.assertionsPassed++;
      } else {
        this.session.stats.assertionsFailed++;
      }
    }
  }

  /**
   * Record a discovered bug
   */
  recordBug(bug: Bug): void {
    this.session.bugs.push(bug);
    this.updateSummary();
  }

  /**
   * Get current session summary
   */
  getSummary(): string {
    return this.session.summary;
  }

  /**
   * Update the session summary
   */
  private async updateSummary(): Promise<void> {
    this.session.summary = `
Session: ${this.session.id}
Started: ${this.session.startTime.toISOString()}
Duration: ${this.getDuration()}

Progress:
- Tasks completed: ${this.session.completedTasks.length}
- Current task: ${this.session.currentTask?.description || 'None'}
- Tasks remaining: ${this.session.taskQueue.length}

Coverage:
- Elements tested: ${this.session.testedElements.size}
- Pages visited: ${this.session.visitedUrls.size}

Findings:
- Bugs found: ${this.session.bugs.length}
- Critical: ${this.session.bugs.filter(b => b.severity === 'critical').length}
- High: ${this.session.bugs.filter(b => b.severity === 'high').length}

Stats:
- Actions: ${this.session.stats.actionsPerformed}
- Assertions passed: ${this.session.stats.assertionsPassed}
- Assertions failed: ${this.session.stats.assertionsFailed}
`.trim();
  }

  /**
   * Save session to progress file
   */
  async saveProgress(): Promise<void> {
    const progress = {
      sessionId: this.session.id,
      timestamp: new Date().toISOString(),
      summary: this.session.summary,
      completedTasks: this.session.completedTasks.map(t => t.id),
      currentTask: this.session.currentTask?.id,
      bugs: this.session.bugs,
      testedElements: Array.from(this.session.testedElements),
      visitedUrls: Array.from(this.session.visitedUrls),
      stats: this.session.stats
    };

    await fs.writeFile(
      this.progressFile,
      JSON.stringify(progress, null, 2)
    );
  }

  /**
   * Load session from progress file
   */
  async loadProgress(): Promise<boolean> {
    try {
      const content = await fs.readFile(this.progressFile, 'utf-8');
      const progress = JSON.parse(content);

      this.session = {
        ...this.createNewSession(progress.sessionId),
        summary: progress.summary,
        bugs: progress.bugs,
        testedElements: new Set(progress.testedElements),
        visitedUrls: new Set(progress.visitedUrls),
        stats: progress.stats
      };

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Export session for persistent storage
   */
  export(): SessionExport {
    return {
      id: this.session.id,
      startTime: this.session.startTime,
      endTime: new Date(),
      duration: this.getDuration(),
      summary: this.session.summary,
      bugs: this.session.bugs,
      stats: this.session.stats,
      coverage: {
        elements: this.session.testedElements.size,
        urls: this.session.visitedUrls.size
      }
    };
  }

  private getDuration(): string {
    const ms = Date.now() - this.session.startTime.getTime();
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }
}

interface SessionState {
  id: string;
  startTime: Date;
  summary: string;

  completedTasks: TaskResult[];
  currentTask: Task | null;
  taskQueue: Task[];

  bugs: Bug[];
  observations: Observation[];

  testedElements: Set<string>;
  visitedUrls: Set<string>;
  pageSnapshots: Map<string, PageSnapshot>;

  stats: SessionStats;
}

interface SessionStats {
  actionsPerformed: number;
  assertionsPassed: number;
  assertionsFailed: number;
  errorsEncountered: number;
}
```

---

## Persistent Memory (Long-Term)

### SQLite Schema

```typescript
/**
 * SQLite database schema for persistent storage
 */

const SCHEMA = `
-- Test Results
CREATE TABLE IF NOT EXISTS test_results (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  page_url TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_ms INTEGER,
  bug_found INTEGER DEFAULT 0,
  evidence_path TEXT,
  created_at TEXT NOT NULL,

  FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX idx_test_results_session ON test_results(session_id);
CREATE INDEX idx_test_results_url ON test_results(page_url);
CREATE INDEX idx_test_results_status ON test_results(status);

-- Bug Reports
CREATE TABLE IF NOT EXISTS bugs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT,
  steps_to_reproduce TEXT,
  expected TEXT,
  actual TEXT,
  page_url TEXT,
  screenshot_path TEXT,
  status TEXT DEFAULT 'open',
  created_at TEXT NOT NULL,
  resolved_at TEXT,

  FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX idx_bugs_severity ON bugs(severity);
CREATE INDEX idx_bugs_status ON bugs(status);
CREATE INDEX idx_bugs_url ON bugs(page_url);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  start_time TEXT NOT NULL,
  end_time TEXT,
  summary TEXT,
  total_tests INTEGER DEFAULT 0,
  bugs_found INTEGER DEFAULT 0,
  coverage_percent REAL DEFAULT 0,
  status TEXT DEFAULT 'active'
);

-- Page Models (learned page structures)
CREATE TABLE IF NOT EXISTS page_models (
  id TEXT PRIMARY KEY,
  url_pattern TEXT NOT NULL,
  page_type TEXT NOT NULL,
  elements_json TEXT,
  last_updated TEXT NOT NULL,
  stability_score REAL DEFAULT 1.0
);

CREATE INDEX idx_page_models_pattern ON page_models(url_pattern);

-- Learned Patterns
CREATE TABLE IF NOT EXISTS patterns (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  pattern_data TEXT NOT NULL,
  confidence REAL DEFAULT 0.5,
  usage_count INTEGER DEFAULT 0,
  last_used TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_patterns_type ON patterns(type);
CREATE INDEX idx_patterns_confidence ON patterns(confidence);

-- Memory Embeddings (for vector search reference)
CREATE TABLE IF NOT EXISTS embeddings (
  id TEXT PRIMARY KEY,
  content_type TEXT NOT NULL,
  content_id TEXT NOT NULL,
  vector_id TEXT NOT NULL,
  created_at TEXT NOT NULL,

  FOREIGN KEY (content_id) REFERENCES test_results(id)
);
`;

class SQLiteStorage {
  private db: Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(SCHEMA);
  }

  /**
   * Store a test result
   */
  async storeTestResult(result: TestResult): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO test_results (
        id, session_id, task_id, page_url, status,
        duration_ms, bug_found, evidence_path, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      result.id,
      result.sessionId,
      result.taskId,
      result.pageUrl,
      result.status,
      result.durationMs,
      result.bugFound ? 1 : 0,
      result.evidencePath,
      new Date().toISOString()
    );
  }

  /**
   * Query test results with filters
   */
  async queryTestResults(filters: TestResultFilters): Promise<TestResult[]> {
    let query = 'SELECT * FROM test_results WHERE 1=1';
    const params: any[] = [];

    if (filters.sessionId) {
      query += ' AND session_id = ?';
      params.push(filters.sessionId);
    }

    if (filters.status) {
      query += ' AND status = ?';
      params.push(filters.status);
    }

    if (filters.pageUrl) {
      query += ' AND page_url LIKE ?';
      params.push(`%${filters.pageUrl}%`);
    }

    if (filters.startDate) {
      query += ' AND created_at >= ?';
      params.push(filters.startDate.toISOString());
    }

    query += ' ORDER BY created_at DESC';

    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    }

    return this.db.prepare(query).all(...params) as TestResult[];
  }

  /**
   * Get bug statistics
   */
  async getBugStats(): Promise<BugStats> {
    const stats = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
        SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
      FROM bugs
    `).get() as BugStats;

    return stats;
  }

  /**
   * Store or update a page model
   */
  async upsertPageModel(model: PageModel): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO page_models (id, url_pattern, page_type, elements_json, last_updated, stability_score)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        elements_json = excluded.elements_json,
        last_updated = excluded.last_updated,
        stability_score = excluded.stability_score
    `);

    stmt.run(
      model.id,
      model.urlPattern,
      model.pageType,
      JSON.stringify(model.elements),
      new Date().toISOString(),
      model.stabilityScore
    );
  }

  /**
   * Find similar pages by URL pattern
   */
  async findSimilarPages(url: string): Promise<PageModel[]> {
    // Normalize URL to pattern
    const pattern = this.urlToPattern(url);

    return this.db.prepare(`
      SELECT * FROM page_models
      WHERE url_pattern LIKE ?
      ORDER BY last_updated DESC
      LIMIT 5
    `).all(`%${pattern}%`) as PageModel[];
  }

  private urlToPattern(url: string): string {
    // Convert URL to pattern (remove dynamic parts)
    return url
      .replace(/\/\d+/g, '/:id')  // /123 -> /:id
      .replace(/\?.*$/, '')       // Remove query string
      .replace(/#.*$/, '');       // Remove hash
  }
}
```

### Vector Store Integration

```typescript
/**
 * Vector store for semantic search
 */

class VectorMemory {
  private client: QdrantClient;
  private embedder: Embedder;
  private collectionName: string = 'qa_memories';

  constructor(config: VectorConfig) {
    this.client = new QdrantClient(config.qdrantUrl);
    this.embedder = new Embedder(config.embeddingModel);
    this.initialize();
  }

  private async initialize(): Promise<void> {
    // Create collection if not exists
    const collections = await this.client.getCollections();
    const exists = collections.collections.some(c => c.name === this.collectionName);

    if (!exists) {
      await this.client.createCollection(this.collectionName, {
        vectors: {
          size: 1536, // OpenAI embedding size
          distance: 'Cosine'
        }
      });
    }
  }

  /**
   * Store a memory with its embedding
   */
  async store(memory: MemoryEntry): Promise<void> {
    // Generate embedding
    const embedding = await this.embedder.embed(this.memoryToText(memory));

    // Store in Qdrant
    await this.client.upsert(this.collectionName, {
      points: [{
        id: memory.id,
        vector: embedding,
        payload: {
          type: memory.type,
          content: memory.content,
          metadata: memory.metadata,
          timestamp: memory.timestamp.toISOString()
        }
      }]
    });
  }

  /**
   * Search for similar memories
   */
  async search(query: string, options: SearchOptions = {}): Promise<MemoryEntry[]> {
    const embedding = await this.embedder.embed(query);

    const results = await this.client.search(this.collectionName, {
      vector: embedding,
      limit: options.limit || 10,
      filter: this.buildFilter(options),
      with_payload: true
    });

    return results.map(result => ({
      id: result.id as string,
      type: result.payload!.type as MemoryType,
      content: result.payload!.content,
      metadata: result.payload!.metadata as MemoryMetadata,
      timestamp: new Date(result.payload!.timestamp as string),
      score: result.score
    }));
  }

  /**
   * Find memories similar to a bug report
   */
  async findSimilarBugs(bug: Bug): Promise<MemoryEntry[]> {
    const query = `Bug: ${bug.title}\nDescription: ${bug.description}\nSteps: ${bug.stepsToReproduce?.join(', ')}`;

    return this.search(query, {
      limit: 5,
      filter: { type: 'bug_report' }
    });
  }

  /**
   * Find relevant patterns for a page
   */
  async findRelevantPatterns(pageContext: string): Promise<MemoryEntry[]> {
    return this.search(pageContext, {
      limit: 10,
      filter: { type: 'learned_pattern' }
    });
  }

  /**
   * Convert memory to searchable text
   */
  private memoryToText(memory: MemoryEntry): string {
    switch (memory.type) {
      case 'bug_report':
        const bug = memory.content as Bug;
        return `Bug: ${bug.title}. ${bug.description}. Steps: ${bug.stepsToReproduce?.join(', ')}`;

      case 'test_result':
        const result = memory.content as TestResult;
        return `Test on ${result.pageUrl}: ${result.status}. ${result.summary || ''}`;

      case 'learned_pattern':
        return `Pattern: ${memory.content}`;

      case 'page_model':
        const model = memory.content as PageModel;
        return `Page ${model.pageType} at ${model.urlPattern}`;

      default:
        return JSON.stringify(memory.content);
    }
  }

  /**
   * Build Qdrant filter from options
   */
  private buildFilter(options: SearchOptions): any {
    const conditions: any[] = [];

    if (options.filter?.type) {
      conditions.push({
        key: 'type',
        match: { value: options.filter.type }
      });
    }

    if (options.filter?.afterDate) {
      conditions.push({
        key: 'timestamp',
        range: { gte: options.filter.afterDate.toISOString() }
      });
    }

    if (conditions.length === 0) return undefined;

    return {
      must: conditions
    };
  }
}

interface SearchOptions {
  limit?: number;
  filter?: {
    type?: MemoryType;
    afterDate?: Date;
    tags?: string[];
  };
}
```

---

## Memory Operations

### Unified Memory Manager

```typescript
/**
 * Unified memory manager - coordinates all memory layers
 */

class MemoryManager {
  private working: WorkingMemoryManager;
  private session: SessionMemoryManager;
  private sqlite: SQLiteStorage;
  private vector: VectorMemory;

  constructor(config: MemoryConfig) {
    this.working = new WorkingMemoryManager(config.working);
    this.session = new SessionMemoryManager(config.sessionId);
    this.sqlite = new SQLiteStorage(config.dbPath);
    this.vector = new VectorMemory(config.vector);
  }

  /**
   * Store a new memory (routes to appropriate layer)
   */
  async store(entry: MemoryInput): Promise<void> {
    // Always add to working memory if it's a message
    if (entry.type === 'message') {
      this.working.add(entry.content as Message);
    }

    // Update session memory
    if (['bug_report', 'test_result', 'observation'].includes(entry.type)) {
      this.session.update(this.toSessionUpdate(entry));
    }

    // Store in persistent memory
    if (this.shouldPersist(entry)) {
      const memoryEntry = this.toMemoryEntry(entry);

      // Store in SQLite (structured)
      await this.sqlite.store(memoryEntry);

      // Store in vector store (semantic)
      await this.vector.store(memoryEntry);
    }
  }

  /**
   * Recall relevant memories for a context
   */
  async recall(query: RecallQuery): Promise<RelevantMemories> {
    const results: RelevantMemories = {
      fromWorking: [],
      fromSession: [],
      fromPersistent: [],
      combined: []
    };

    // 1. Check working memory (immediate context)
    results.fromWorking = this.searchWorkingMemory(query);

    // 2. Check session memory (current session)
    results.fromSession = this.searchSessionMemory(query);

    // 3. Search persistent memory
    if (query.searchPersistent !== false) {
      // Semantic search
      const semanticResults = await this.vector.search(query.text, {
        limit: query.limit || 10,
        filter: query.filter
      });

      // Structured search
      const structuredResults = await this.sqlite.queryByContext(query);

      results.fromPersistent = this.mergeResults(semanticResults, structuredResults);
    }

    // 4. Combine and rank
    results.combined = this.rankAndCombine(results, query);

    return results;
  }

  /**
   * Get context for LLM (optimized for token budget)
   */
  async getContextForLLM(task: Task, budget: TokenBudget): Promise<LLMContext> {
    // 1. Get working memory messages
    const workingContext = this.working.getContext();

    // 2. Get session summary
    const sessionSummary = this.session.getSummary();

    // 3. Get relevant persistent memories
    const relevantMemories = await this.recall({
      text: task.description,
      limit: 5,
      filter: { type: this.getRelevantTypes(task) }
    });

    // 4. Build context within budget
    return this.buildContext({
      working: workingContext,
      session: sessionSummary,
      persistent: relevantMemories.combined,
      budget
    });
  }

  /**
   * Compact working memory and persist important information
   */
  async compact(): Promise<CompactionResult> {
    // 1. Compact working memory
    const compacted = await this.working.compact();

    // 2. Update session summary
    await this.session.updateSummary();

    // 3. Save session progress
    await this.session.saveProgress();

    return compacted;
  }

  /**
   * End session and persist all data
   */
  async endSession(): Promise<SessionExport> {
    // 1. Final compaction
    await this.compact();

    // 2. Export session data
    const sessionExport = this.session.export();

    // 3. Store session summary in persistent memory
    await this.sqlite.storeSession(sessionExport);

    // 4. Store session summary embedding for future reference
    await this.vector.store({
      id: `session-${sessionExport.id}`,
      type: 'session_summary',
      content: sessionExport,
      metadata: {
        source: 'session_end',
        confidence: 1.0,
        tags: ['session', sessionExport.id]
      },
      timestamp: new Date()
    });

    return sessionExport;
  }
}
```

---

## Session Continuity

### Progress File Format

```typescript
/**
 * Progress file for session continuity
 */

interface ProgressFile {
  // Identification
  sessionId: string;
  agentVersion: string;
  timestamp: string;

  // State summary
  summary: string;

  // Task tracking
  completedTasks: CompletedTask[];
  currentTask: CurrentTask | null;
  pendingTasks: PendingTask[];

  // Findings
  bugs: BugSummary[];
  criticalFindings: string[];

  // Coverage
  coverage: {
    pagesVisited: string[];
    elementsTestedCount: number;
    coveragePercent: number;
  };

  // Next steps (for resumption)
  nextSteps: string[];
  blockers: string[];

  // Git integration
  lastCommit: string;
  uncommittedChanges: string[];
}

interface CompletedTask {
  id: string;
  description: string;
  status: 'passed' | 'failed' | 'skipped';
  summary: string;
  completedAt: string;
}

interface CurrentTask {
  id: string;
  description: string;
  startedAt: string;
  progress: string;
  lastAction: string;
}

interface PendingTask {
  id: string;
  description: string;
  priority: number;
  blockedBy?: string[];
}

/**
 * Progress file manager
 */

class ProgressFileManager {
  private filePath: string;

  constructor(sessionId: string) {
    this.filePath = `progress-${sessionId}.json`;
  }

  /**
   * Write progress file
   */
  async write(progress: ProgressFile): Promise<void> {
    const content = JSON.stringify(progress, null, 2);
    await fs.writeFile(this.filePath, content);

    // Also write human-readable summary
    const summary = this.generateHumanReadable(progress);
    await fs.writeFile(this.filePath.replace('.json', '.txt'), summary);
  }

  /**
   * Read progress file
   */
  async read(): Promise<ProgressFile | null> {
    try {
      const content = await fs.readFile(this.filePath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  /**
   * Generate human-readable progress summary
   */
  private generateHumanReadable(progress: ProgressFile): string {
    return `
===========================================
QA Agent Progress Report
===========================================
Session: ${progress.sessionId}
Last Updated: ${progress.timestamp}

SUMMARY
-------
${progress.summary}

COMPLETED TASKS (${progress.completedTasks.length})
---------------
${progress.completedTasks.map(t =>
  `[${t.status.toUpperCase()}] ${t.description}`
).join('\n')}

CURRENT TASK
------------
${progress.currentTask
  ? `${progress.currentTask.description}\nProgress: ${progress.currentTask.progress}`
  : 'None'
}

PENDING TASKS (${progress.pendingTasks.length})
-------------
${progress.pendingTasks.map(t =>
  `- ${t.description} (Priority: ${t.priority})`
).join('\n')}

BUGS FOUND (${progress.bugs.length})
----------
${progress.bugs.map(b =>
  `[${b.severity.toUpperCase()}] ${b.title}`
).join('\n')}

COVERAGE
--------
Pages visited: ${progress.coverage.pagesVisited.length}
Elements tested: ${progress.coverage.elementsTestedCount}
Coverage: ${progress.coverage.coveragePercent.toFixed(1)}%

NEXT STEPS
----------
${progress.nextSteps.map(s => `- ${s}`).join('\n')}

${progress.blockers.length > 0 ? `
BLOCKERS
--------
${progress.blockers.map(b => `! ${b}`).join('\n')}
` : ''}
===========================================
`.trim();
  }
}
```

### Session Resumption

```typescript
/**
 * Resume a session from progress file
 */

class SessionResumer {
  private memoryManager: MemoryManager;
  private progressManager: ProgressFileManager;

  /**
   * Resume a previous session
   */
  async resume(sessionId: string): Promise<ResumeResult> {
    const progress = await this.progressManager.read();

    if (!progress) {
      return { success: false, reason: 'No progress file found' };
    }

    // 1. Restore session memory
    await this.restoreSessionMemory(progress);

    // 2. Restore working memory context
    await this.restoreWorkingMemory(progress);

    // 3. Restore task queue
    const taskQueue = this.restoreTaskQueue(progress);

    // 4. Generate resumption prompt
    const resumptionPrompt = this.generateResumptionPrompt(progress);

    return {
      success: true,
      progress,
      taskQueue,
      resumptionPrompt,
      summary: `Resumed session ${sessionId}. ${progress.completedTasks.length} tasks completed, ${progress.pendingTasks.length} pending.`
    };
  }

  /**
   * Generate prompt for LLM to understand previous context
   */
  private generateResumptionPrompt(progress: ProgressFile): string {
    return `
You are resuming a QA testing session. Here's what happened before:

## Previous Progress
${progress.summary}

## Completed Tasks
${progress.completedTasks.map(t => `- ${t.description}: ${t.status}`).join('\n')}

## Bugs Found
${progress.bugs.map(b => `- [${b.severity}] ${b.title}`).join('\n')}

## Current State
${progress.currentTask
  ? `Was working on: ${progress.currentTask.description}\nLast action: ${progress.currentTask.lastAction}`
  : 'No task was in progress.'
}

## Recommended Next Steps
${progress.nextSteps.map(s => `1. ${s}`).join('\n')}

${progress.blockers.length > 0
  ? `## Blockers to Address\n${progress.blockers.map(b => `- ${b}`).join('\n')}`
  : ''
}

Please continue testing from where we left off.
`.trim();
  }
}
```

---

## Memory Best Practices

### 1. When to Store

| Event | Working | Session | Persistent |
|-------|---------|---------|------------|
| LLM message | ✅ | - | - |
| Tool result | ✅ | ✅ | - |
| Bug found | ✅ | ✅ | ✅ |
| Test completed | ✅ | ✅ | ✅ |
| Pattern learned | - | ✅ | ✅ |
| Page model | - | ✅ | ✅ |
| Session end | - | - | ✅ |

### 2. When to Recall

| Situation | What to Recall |
|-----------|---------------|
| Starting new task | Similar past bugs, relevant patterns |
| Encountering error | Past solutions to similar errors |
| Testing form | Known validation rules for field types |
| Visual regression | Previous baselines, known flaky elements |
| Session start | Previous session summary, pending tasks |

### 3. Memory Hygiene

```typescript
// Periodic cleanup
async function cleanupMemory(manager: MemoryManager): Promise<void> {
  // 1. Remove stale embeddings (> 90 days old, never accessed)
  await manager.sqlite.query(`
    DELETE FROM embeddings
    WHERE created_at < datetime('now', '-90 days')
    AND id NOT IN (SELECT DISTINCT vector_id FROM access_log)
  `);

  // 2. Merge duplicate patterns
  await manager.mergeSimilarPatterns(threshold: 0.95);

  // 3. Update confidence scores based on usage
  await manager.updatePatternConfidence();

  // 4. Archive old sessions
  await manager.archiveSessions(olderThan: 30); // days
}
```

---

## Next Steps

- **[AGENT_CONTEXT.md](./AGENT_CONTEXT.md)** - Context window management strategies
- **[AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md)** - Multi-agent coordination
- **[AGENT_PROMPTS.md](./AGENT_PROMPTS.md)** - Prompt engineering techniques
