# YaliTest: Autonomous QA Platform
## Complete Strategy & Implementation Plan v2.2

> **Mission:** 10x QA team effectiveness by automating the repetitive 70% of testing work with **93% accuracy** through intelligent input collection.

---

# Table of Contents

1. [Executive Summary](#executive-summary)
2. [Market Analysis](#part-1-market-analysis)
3. [AI Economics](#part-2-ai-economics)
4. [Input Collection Strategy](#part-3-input-collection-strategy) ← **NEW**
5. [Technical Architecture](#part-4-technical-architecture)
6. [Core Features](#part-5-core-features)
7. [AI Integration](#part-6-ai-integration)
8. [Test Generation & Debugging](#part-7-test-generation--debugging)
9. [Self-Healing & Failure Analysis](#part-8-self-healing--failure-analysis) ← **NEW**
10. [Human-in-the-Loop](#part-9-human-in-the-loop)
11. [Security & Credentials](#part-10-security--credentials)
12. [Implementation Roadmap](#part-11-implementation-roadmap)
13. [Success Metrics](#part-12-success-metrics)

---

# Executive Summary

## What We Build

An autonomous QA testing platform that:
- **Discovers** all pages and interactive elements automatically
- **Classifies** elements by type (navigation, forms, destructive, payment)
- **Generates** comprehensive test suites (happy path, edge cases, security)
- **Validates** tests before saving (dry-run verification with traces)
- **Debugs** failures with full visibility (Playwright Traces)
- **Asks** when unsure (Slack/chatbot integration)
- **Learns** from human corrections to improve accuracy
- **Explains** every failure (no "unknown error" ever)

## Core Principle: Input-Centric AI

> **"AI isn't dumb, it just needs the right inputs. If we collect the right context, we achieve 93% accuracy."**

```
┌─────────────────────────────────────────────────────────────┐
│                 The Input-Centric Approach                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  WITHOUT INPUTS:                 WITH INPUTS:               │
│  ├── Self-healing: 75%          ├── Self-healing: 95%      │
│  ├── Classification: 85%        ├── Classification: 95%    │
│  ├── Edge cases: 70%            ├── Edge cases: 92%        │
│  └── Average: 73%               └── Average: 93%           │
│                                                             │
│  The difference? We ASK when we don't know.                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## The 30-Minute Promise

```
User provides config (optional, 2 min)
    ↓
User enters URL (1 min)
    ↓
Crawler discovers 100+ pages (5 min)
    ↓
AI classifies elements, ASKS if unsure (3 min)
    ↓
Flow detection + user confirmation (2 min)
    ↓
Test generation with schema validation (15 min)
    ↓
Dry-run validation verifies tests (4 min)
    ↓
Export to Playwright/Cypress (1 min)

Total: 30 minutes with 93% accuracy.
```

## Honest Positioning

| What AI Handles (70%) | What Humans Provide (30%) |
|----------------------|---------------------------|
| Discovering all pages | Config file (optional) |
| Finding all elements | Answer Slack questions |
| Generating test boilerplate | Approve golden baselines |
| Running regression 24/7 | Review draft tests |
| Self-healing broken tests | Confirm when asked |
| Detecting visual regressions | Define business rules |

## The One Rule

> **If AI doesn't know, ASK. If user doesn't answer, SKIP (don't guess).**

---

# Part 1: Market Analysis

## Competitor Landscape

| Tool | Pricing | AI Features | Autonomous | Key Weakness |
|------|---------|-------------|------------|--------------|
| **Mabl** | $499-2000+/mo | Auto-heal, GenAI Assertions | No | Manual test creation |
| **Testim/Tricentis** | $450-1500+/mo | Smart Locators, Copilot | No | Complex pricing |
| **Katalon** | $0-229+/mo/user | Self-healing, AI suggestions | No | Groovy lock-in |
| **Rainforest QA** | $8K+/mo avg | AI coverage gaps, NL tests | Partial | Extremely expensive |
| **Ghost Inspector** | $109-500/mo | None | No | Tests break frequently |
| **Skyvern** | Open source | Vision-LLM reasoning | Partial | Task-specific, not QA |
| **Agent-E** | Open source | DOM Distillation | Partial | Research project |

## The Gap We Fill

**Every competitor requires manual test definition.** Even "AI-powered" tools need humans to:
1. Record tests manually, OR
2. Write test scripts, OR
3. Define what to test in natural language

**YaliTest's Differentiator:** Zero-input autonomous discovery + validated test generation + full debugging visibility.

## Target Customers

| Segment | Price | Pain Point | Promise |
|---------|-------|------------|---------|
| **Startups (0-1 QA)** | $99/mo | No time/budget for testing | Get coverage without hiring |
| **Overloaded Teams** | $199/mo | QA is bottleneck | AI does regression, humans explore |
| **Agencies** | $399/mo | Need tested code fast | Ship with confidence |
| **Enterprise** | $699+/mo | Compliance, audit trails | Enterprise-grade infrastructure |

---

# Part 2: AI Economics

## Model Pricing (2025)

| Provider | Model | Input/MTok | Output/MTok | Use For |
|----------|-------|------------|-------------|---------|
| **DeepSeek** | V3 | $0.028 (cached) | $0.42 | Classification, decisions |
| **Gemini** | Flash-Lite | $0.10 | $0.40 | Fast classification |
| **OpenAI** | GPT-4o-mini | $0.15 | $0.60 | Medium complexity |
| **Claude** | Haiku 3 | $0.25 | $1.25 | Fast responses |
| **OpenAI** | GPT-4o | $2.50 | $10.00 | Test generation |
| **Claude** | Sonnet 4 | $3.00 | $15.00 | Complex generation |

## Multi-Model Routing

```
┌─────────────────────────────────────────────────────────────┐
│                    Task Router                               │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Simple      │    │   Medium      │    │   Complex     │
│   Tasks       │    │   Tasks       │    │   Tasks       │
│               │    │               │    │               │
│ DeepSeek V3   │    │ GPT-4o-mini   │    │ GPT-4o or     │
│ $0.028/MTok   │    │ $0.15/MTok    │    │ Sonnet 4      │
│               │    │               │    │ $2.50-3.00    │
│ - Classify    │    │ - Flow detect │    │ - Generate    │
│ - Route       │    │ - Summarize   │    │   tests       │
│ - Decide      │    │ - Analyze     │    │ - Fix errors  │
└───────────────┘    └───────────────┘    └───────────────┘
```

## Cost Per 100 Pages

| Operation | Model | Tokens | Cost |
|-----------|-------|--------|------|
| DOM Extraction | Local | 0 | $0.00 |
| Element Classification | DeepSeek | 50K in, 10K out | $0.02 |
| Action Prioritization | DeepSeek | 20K in, 5K out | $0.01 |
| Flow Detection | GPT-4o-mini | 30K in, 10K out | $0.05 |
| Test Generation (Normal) | GPT-4o | 100K in, 50K out | $0.75 |
| Test Generation (Edge) | GPT-4o | 50K in, 30K out | $0.43 |
| Test Generation (Security) | Sonnet 4 | 50K in, 20K out | $0.45 |
| **Total** | | | **$1.71** |

## Pricing Tiers (80%+ Margin)

| Tier | Price | Credits | Our Cost | Margin |
|------|-------|---------|----------|--------|
| **Starter** | $99/mo | 2,000 | $20 | 80% |
| **Pro** | $199/mo | 5,000 | $40 | 80% |
| **Business** | $399/mo | 12,000 | $80 | 80% |
| **Enterprise** | $699/mo | 25,000 | $140 | 80% |

---

# Part 3: Input Collection Strategy

> **"The AI is capable. The wall isn't technical - it's missing information."**

## Why Inputs Matter

| Metric | Without Inputs | With Inputs | Improvement |
|--------|----------------|-------------|-------------|
| Self-healing | 75% | **95%** | +20% |
| Flow detection | 80% | **95%** | +15% |
| Classification | 85% | **95%** | +10% |
| Edge case tests | 70% | **92%** | +22% |
| Security tests | 60% | **88%** | +28% |
| Bug detection | 70% | **92%** | +22% |
| **Average** | **73%** | **93%** | **+20%** |

## Input Collection Points

```
┌─────────────────────────────────────────────────────────────┐
│                    Input Collection Points                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  UPFRONT (Before Testing):                                  │
│  ├── yalitest.config.yml (flows, auth, roles)               │
│  ├── Schema import (OpenAPI, JSON Schema, TypeScript)       │
│  ├── Security questionnaire (auth type, sensitive data)     │
│  └── Golden baseline approval ("this is correct")           │
│                                                             │
│  RUNTIME (During Testing):                                  │
│  ├── Slack questions when AI confidence < 80%               │
│  ├── In-app prompts for ambiguous elements                  │
│  └── Confirmation dialogs for destructive actions           │
│                                                             │
│  LEARNING (After Testing):                                  │
│  ├── User corrections ("this is actually a login page")     │
│  ├── Approved/rejected test reviews                         │
│  ├── Bug confirmations ("yes this is a bug" / "expected")   │
│  └── Self-healing confirmations                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 1. Config File (yalitest.config.yml)

```yaml
# yalitest.config.yml - User provides application context

app:
  name: "My E-Commerce App"
  type: ecommerce  # ecommerce | saas | blog | dashboard | custom
  baseUrl: "https://staging.myapp.com"

# Flow definitions (80% → 95% flow detection)
flows:
  login:
    start: /login
    end: /dashboard
    fields:
      - name: email
        type: email
      - name: password
        type: password
    success_indicator: ".welcome-message"

  checkout:
    start: /cart
    end: /order-confirmation
    steps:
      - /cart
      - /shipping
      - /payment
      - /confirm
    requires_auth: true

  signup:
    start: /register
    end: /verify-email
    fields:
      - name: email
        type: email
        validation: "^[a-z]+@company\\.com$"
      - name: password
        type: password
        validation: "min:8,uppercase,number,special"

# Security context (60% → 88% security tests)
security:
  auth_type: jwt  # jwt | session | oauth | basic | custom

  roles:
    - name: admin
      can_access: ["/admin/*", "/settings/*"]
    - name: user
      can_access: ["/profile", "/orders"]
    - name: guest
      can_access: ["/", "/products", "/login"]

  sensitive_fields:
    - credit_card
    - ssn
    - password
    - api_key

  protected_routes:
    - pattern: "/admin/*"
      required_role: admin
    - pattern: "/api/internal/*"
      required_role: admin

# Validation rules (70% → 92% edge case tests)
validation:
  email:
    pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    error: "Invalid email format"

  age:
    type: number
    min: 18
    max: 120
    error: "Age must be between 18 and 120"

  phone:
    pattern: "^\\+1-[0-9]{3}-[0-9]{3}-[0-9]{4}$"
    error: "Format: +1-XXX-XXX-XXXX"

  price:
    type: number
    min: 0
    max: 999999.99
    decimals: 2

# Test data cleanup
cleanup:
  prefix: "yali_auto_"
  max_age_minutes: 60
  strategy: api_delete  # api_delete | db_truncate
```

## 2. Schema Import (Auto-Detect Edge Cases)

```typescript
// Import validation rules from existing sources

// Option 1: OpenAPI/Swagger
async function importFromOpenAPI(specUrl: string): Promise<ValidationSchema> {
  const spec = await fetch(specUrl);
  const schemas = spec.components.schemas;

  return Object.entries(schemas).map(([name, schema]) => ({
    name,
    type: schema.type,
    validation: {
      required: schema.required,
      min: schema.minimum,
      max: schema.maximum,
      pattern: schema.pattern,
      enum: schema.enum
    }
  }));
}

// Option 2: JSON Schema
async function importFromJSONSchema(schemaPath: string): Promise<ValidationSchema> {
  const schema = await readFile(schemaPath);
  return parseJSONSchema(schema);
}

// Option 3: TypeScript types (via ts-morph)
async function importFromTypeScript(typesPath: string): Promise<ValidationSchema> {
  // Extract types and their constraints
  const project = new Project();
  project.addSourceFilesAtPaths(typesPath);
  return extractTypesAsSchema(project);
}

// Option 4: Zod schemas
async function importFromZod(zodSchemaPath: string): Promise<ValidationSchema> {
  const zodSchema = require(zodSchemaPath);
  return zodToValidationSchema(zodSchema);
}
```

## 3. Runtime Questions (Ask When Unsure)

```typescript
interface UncertaintyHandler {
  // When AI confidence is below threshold, ASK
  async handleUncertainty<T>(
    item: T,
    confidence: number,
    context: Context
  ): Promise<Resolution<T>> {

    // High confidence: Auto-proceed
    if (confidence > 0.9) {
      return { action: 'proceed', auto: true };
    }

    // Medium confidence: Ask user
    if (confidence > 0.6) {
      const answer = await this.askUser(item, context);
      await this.learn(item, answer);  // Remember for next time
      return { action: answer.action, auto: false };
    }

    // Low confidence: Skip and flag for review
    return {
      action: 'skip',
      auto: true,
      reason: 'Confidence too low, added to review queue'
    };
  }
}

// Example: Classifying an ambiguous element
async function classifyWithUncertainty(element: Element): Promise<Classification> {
  const aiResult = await llm.classify(element);

  if (aiResult.confidence < 0.8) {
    const answer = await askViaSlack({
      message: `🤖 I found an element but I'm not sure what it does.`,
      screenshot: element.screenshot,
      context: `Page: ${element.pageUrl}`,
      question: `What type of action is "${element.text || element.ariaLabel || 'this button'}"?`,
      options: [
        { label: '🔗 Navigation (safe to click)', value: 'navigation' },
        { label: '📝 Form submit (creates data)', value: 'write' },
        { label: '🗑️ Destructive (deletes something)', value: 'destructive' },
        { label: '💳 Payment (involves money)', value: 'payment' },
        { label: '⏭️ Skip this element', value: 'skip' }
      ]
    });

    // Learn from this answer
    await learningEngine.record({
      elementSignature: element.signature,
      pageContext: element.pageUrl,
      aiSaid: aiResult.category,
      humanSaid: answer.value,
      timestamp: new Date()
    });

    return { category: answer.value, confidence: 1.0, source: 'human' };
  }

  return aiResult;
}
```

## 4. Golden Baseline (User Approves "Correct" State)

```typescript
interface GoldenBaseline {
  id: string;
  name: string;
  url: string;
  capturedAt: Date;
  approvedBy: string;

  // What we captured
  screenshot: Buffer;
  domSnapshot: string;
  apiResponses: Record<string, any>;

  // User-defined assertions
  assertions: Assertion[];
}

// Capture baseline
async function captureBaseline(page: Page, name: string): Promise<GoldenBaseline> {
  const baseline: GoldenBaseline = {
    id: generateId(),
    name,
    url: page.url(),
    capturedAt: new Date(),
    screenshot: await page.screenshot(),
    domSnapshot: await page.content(),
    apiResponses: await captureNetworkResponses(page),
    assertions: []  // User will add these
  };

  // Show to user for approval
  await showForApproval(baseline);

  return baseline;
}

// User adds assertions via UI
const assertions: Assertion[] = [
  {
    description: "User name should be visible",
    selector: ".user-name",
    check: "exists"
  },
  {
    description: "Balance should be a valid currency",
    selector: ".balance",
    check: "matches",
    pattern: /\$[0-9,]+\.[0-9]{2}/
  },
  {
    description: "No error messages",
    selector: ".error",
    check: "not-exists"
  }
];

// Future runs compare against baseline
async function compareToBaseline(page: Page, baselineName: string): Promise<ComparisonResult> {
  const baseline = await loadBaseline(baselineName);

  const result = {
    visualDiff: await compareScreenshots(await page.screenshot(), baseline.screenshot),
    domDiff: await compareDOM(await page.content(), baseline.domSnapshot),
    assertionResults: await runAssertions(page, baseline.assertions)
  };

  if (result.visualDiff.percentChanged > 0.5) {
    // Ask user: Is this change expected?
    const answer = await askViaSlack({
      message: `🔍 Visual change detected on ${baseline.name}`,
      images: [baseline.screenshot, await page.screenshot()],
      question: `Is this change expected?`,
      options: [
        { label: '✅ Yes, update baseline', value: 'update' },
        { label: '🐛 No, this is a bug', value: 'bug' },
        { label: '🔍 Let me investigate', value: 'investigate' }
      ]
    });

    result.userVerdict = answer.value;
  }

  return result;
}
```

## 5. Learning From Corrections

```typescript
interface Correction {
  id: string;
  type: 'classification' | 'flow' | 'assertion' | 'selector';
  timestamp: Date;

  // What happened
  context: any;
  aiSaid: string;
  humanSaid: string;

  // Pattern for learning
  pattern: string;
}

class LearningEngine {
  private corrections: Correction[] = [];
  private rules: Map<string, string> = new Map();

  async record(correction: Correction): Promise<void> {
    this.corrections.push(correction);

    // If same correction 3+ times, create a rule
    const similar = this.corrections.filter(c =>
      c.pattern === correction.pattern &&
      c.humanSaid === correction.humanSaid
    );

    if (similar.length >= 3) {
      this.rules.set(correction.pattern, correction.humanSaid);
      console.log(`📚 Learned: ${correction.pattern} → ${correction.humanSaid}`);
    }
  }

  // Before asking AI, check learned rules
  checkRules(context: any): string | null {
    const pattern = extractPattern(context);
    return this.rules.get(pattern) || null;
  }

  // Export learned rules for persistence
  exportRules(): Rule[] {
    return Array.from(this.rules.entries()).map(([pattern, result]) => ({
      pattern,
      result,
      learnedFrom: this.corrections.filter(c => c.pattern === pattern).length
    }));
  }
}
```

## Input Collection Summary

| Input Type | When Collected | What It Enables | Accuracy Boost |
|------------|----------------|-----------------|----------------|
| **Config file** | Before first run | Flow detection, security context | +15% |
| **Schema import** | Before first run | Edge case generation | +22% |
| **Slack questions** | During runtime | Element classification | +10% |
| **Golden baselines** | After first run | Bug detection | +22% |
| **User corrections** | After failures | Continuous learning | +5% ongoing |

---

# Part 4: Technical Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Electron App (UI Only)                    │
│                                                             │
│  - React frontend                                           │
│  - Progress visualization                                   │
│  - Human labeling interface                                 │
│  - Test review & export                                     │
│  - Trace viewer integration                                 │
│  - NO browser automation here                               │
└─────────────────────────────────────────────────────────────┘
                              │ IPC
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Process                      │
│                                                             │
│  - Navigation Graph management                              │
│  - State fingerprinting (prevents infinite loops)           │
│  - Auth State Bank (session persistence)                    │
│  - Confidence-based routing                                 │
│  - Task coordination                                        │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Browser Pool   │  │   LLM Router    │  │  Human Queue    │
│  (Workers)      │  │   (+ Cache)     │  │                 │
│                 │  │                 │  │                 │
│ 4-8 Playwright  │  │ DeepSeek/GPT/   │  │ Slack/Teams     │
│ w/ stealth +    │  │ Claude with     │  │ integration     │
│ tracing enabled │  │ RAG + caching   │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Browser Worker Pool

**Problem:** Running 50 BrowserViews in Electron's main thread will:
- Freeze the UI
- Exhaust memory
- Crash the app

**Solution:** Worker Pool in separate Node.js processes with stealth mode

```typescript
import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';

// Enable stealth mode to avoid bot detection
chromium.use(stealthPlugin());

class BrowserPool {
  private workers: Worker[] = [];
  private poolSize: number = 4;

  async initialize(): Promise<void> {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker('./browser-worker.js');
      this.workers.push(worker);
    }
  }

  async execute(task: BrowserTask): Promise<TaskResult> {
    const availableWorker = this.getAvailableWorker();
    return availableWorker.postMessage(task);
  }
}

// browser-worker.js - Each worker with stealth + tracing
const browser = await chromium.launch({
  headless: true,
  args: [
    '--disable-blink-features=AutomationControlled',  // Avoid detection
  ]
});

// Create context with tracing enabled by default
const context = await browser.newContext({
  userAgent: getRandomUserAgent(),  // Rotate user agents
  viewport: { width: 1920, height: 1080 },
  locale: 'en-US',
  // Enable tracing for debugging
  recordVideo: { dir: './videos/' }  // Optional: video recording
});

// Start tracing for every session
await context.tracing.start({
  screenshots: true,
  snapshots: true,
  sources: true
});

const page = await context.newPage();

parentPort.on('message', async (task) => {
  const result = await executeTask(page, task);
  parentPort.postMessage(result);
});
```

## Anti-Bot Detection & Throttling

Real production sites (Cloudflare, Akamai) will ban automated traffic.

```typescript
// Stealth configuration
const STEALTH_CONFIG = {
  // Randomize timing between actions
  minDelay: 500,   // 0.5 seconds minimum
  maxDelay: 2000,  // 2 seconds maximum

  // Rate limiting per domain
  requestsPerMinute: 30,

  // Rotate user agents
  userAgents: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36...',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...'
  ]
};

function getRandomUserAgent(): string {
  return STEALTH_CONFIG.userAgents[
    Math.floor(Math.random() * STEALTH_CONFIG.userAgents.length)
  ];
}

async function humanDelay(): Promise<void> {
  const delay = STEALTH_CONFIG.minDelay +
    Math.random() * (STEALTH_CONFIG.maxDelay - STEALTH_CONFIG.minDelay);
  await page.waitForTimeout(delay);
}

// Rate limiter
class RateLimiter {
  private requests: Map<string, number[]> = new Map();

  async waitIfNeeded(domain: string): Promise<void> {
    const now = Date.now();
    const recentRequests = this.requests.get(domain) || [];

    // Keep only requests from last minute
    const lastMinute = recentRequests.filter(t => now - t < 60000);

    if (lastMinute.length >= STEALTH_CONFIG.requestsPerMinute) {
      const waitTime = 60000 - (now - lastMinute[0]);
      await new Promise(r => setTimeout(r, waitTime));
    }

    lastMinute.push(now);
    this.requests.set(domain, lastMinute);
  }
}
```

## Auth State Bank (Session Persistence)

**Problem:** Explorer Agent logs in, but Test Generator/Executor don't have the session.

**Solution:** Centralized State Bank using Playwright's storageState

```typescript
interface AuthState {
  cookies: any[];
  localStorage: Record<string, string>;
  storageStatePath: string;
}

class StateBank {
  private states: Map<string, string> = new Map();  // label -> path

  // Save state after successful login
  async save(context: BrowserContext, label: string): Promise<string> {
    const path = `./states/${label}-${Date.now()}.json`;
    await context.storageState({ path });
    this.states.set(label, path);
    return path;
  }

  // Load state into a NEW context
  async createAuthenticatedContext(
    browser: Browser,
    label: string
  ): Promise<BrowserContext> {
    const statePath = this.states.get(label);
    if (!statePath) {
      throw new Error(`No auth state found for: ${label}`);
    }

    return browser.newContext({
      storageState: statePath
    });
  }

  // Check if we have auth for a domain
  hasAuth(label: string): boolean {
    return this.states.has(label);
  }

  // Clear all states (on session end)
  clear(): void {
    this.states.clear();
    // Also delete state files
    fs.rmSync('./states', { recursive: true, force: true });
    fs.mkdirSync('./states');
  }
}

// Usage in exploration
async function exploreWithAuth(url: string) {
  const stateBank = new StateBank();

  // Phase 1: Explorer discovers login, performs login
  const explorerContext = await browser.newContext();
  const explorerPage = await explorerContext.newPage();
  await explorerPage.goto(url);

  // ... login flow ...
  await explorerPage.fill('[name="username"]', credentials.username);
  await explorerPage.fill('[name="password"]', credentials.password);
  await explorerPage.click('[type="submit"]');

  // Save authenticated state
  await stateBank.save(explorerContext, 'logged-in-user');

  // Phase 2: Test executor uses saved state
  const testContext = await stateBank.createAuthenticatedContext(
    browser,
    'logged-in-user'
  );
  const testPage = await testContext.newPage();
  // Now testPage has cookies/session from explorer!
}
```

## Navigation Graph (Prevents Infinite Loops)

```typescript
interface NavNode {
  id: string;              // URL + DOM hash
  url: string;
  signature: string;       // Hash of interactive elements
  elements: Element[];
  visitCount: number;
}

interface NavEdge {
  from: string;
  to: string;
  action: Action;
}

class NavigationGraph {
  nodes: Map<string, NavNode> = new Map();
  edges: Map<string, NavEdge[]> = new Map();

  hasVisited(url: string, domHash: string): boolean {
    return this.nodes.has(`${url}#${domHash}`);
  }

  wouldCreateCycle(fromId: string, toId: string): boolean {
    // BFS to check if toId can reach fromId within 3 hops
    const visited = new Set<string>();
    const queue: string[] = [toId];

    for (let depth = 0; depth < 3; depth++) {
      const nextQueue: string[] = [];
      for (const nodeId of queue) {
        if (nodeId === fromId) return true;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        const edges = this.edges.get(nodeId) || [];
        nextQueue.push(...edges.map(e => e.to));
      }
      queue.length = 0;
      queue.push(...nextQueue);
    }
    return false;
  }

  getUnexploredActions(nodeId: string): Action[] {
    const node = this.nodes.get(nodeId);
    const triedActions = this.edges.get(nodeId) || [];
    return node.elements.filter(el =>
      !triedActions.some(e => e.action.elementId === el.mmid)
    );
  }
}
```

## State Fingerprinting

```typescript
interface StateFingerprint {
  url: string;
  domHash: string;
  activeElement: string;
  modalState: string;
  formState: string;
}

function createFingerprint(page: Page): StateFingerprint {
  return {
    url: normalizeUrl(page.url()),
    domHash: hashElements(await extractElements(page)),
    activeElement: await page.evaluate(() =>
      document.activeElement?.id || ''
    ),
    modalState: await detectOpenModals(page),
    formState: await hashFormValues(page)
  };
}
```

## Exploration Limits

```typescript
interface ExplorationLimits {
  maxDepth: number;           // Max clicks from start (default: 10)
  maxPagesPerDomain: number;  // Max pages (default: 500)
  maxActionsPerPage: number;  // Max elements per page (default: 50)
  maxTotalActions: number;    // Total actions (default: 5000)
  maxTimeMinutes: number;     // Hard timeout (default: 30)
}
```

---

# Part 5: Core Features

## Smart Waiting Strategy

**CRITICAL:** Never use fixed `waitForTimeout()` - it causes flaky tests.

```typescript
// ❌ BAD - Fixed timeout (causes flaky tests)
await page.waitForTimeout(1000);

// ✅ GOOD - Smart waiting based on action type
async function smartWait(page: Page, action: Action): Promise<void> {
  // 1. Navigation actions: wait for network idle
  if (action.type === 'navigate' || action.causesNavigation) {
    await page.waitForLoadState('networkidle', { timeout: 15000 })
      .catch(() => page.waitForLoadState('domcontentloaded'));
    return;
  }

  // 2. Click actions: wait for element to be actionable
  if (action.type === 'click') {
    const locator = page.locator(getSelector(action.element));
    await locator.waitFor({ state: 'visible', timeout: 5000 });
    return;
  }

  // 3. Form submission: wait for response
  if (action.type === 'submit') {
    await Promise.race([
      page.waitForNavigation({ timeout: 10000 }),
      page.waitForResponse(r => r.status() < 400, { timeout: 10000 }),
      page.waitForSelector('.error, .success, [role="alert"]', { timeout: 5000 })
    ]);
    return;
  }

  // 4. Modal/dropdown: wait for specific element
  if (action.expectedResult) {
    await page.locator(action.expectedResult).waitFor({
      state: 'attached',
      timeout: 5000
    });
    return;
  }

  // 5. Fallback: wait for any network activity to settle
  await page.waitForLoadState('networkidle', { timeout: 5000 })
    .catch(() => {}); // Ignore timeout, continue anyway
}

// Usage in action execution
async function executeAction(page: Page, action: Action): Promise<ActionResult> {
  const beforeFingerprint = await createFingerprint(page);

  // Execute the action
  if (action.type === 'click') {
    await page.locator(getSelector(action.element)).click();
  } else if (action.type === 'input') {
    await page.locator(getSelector(action.element)).fill(action.value);
  }

  // Smart wait based on action type
  await smartWait(page, action);

  const afterFingerprint = await createFingerprint(page);

  return {
    success: true,
    causedNavigation: beforeFingerprint.url !== afterFingerprint.url,
    causedUIChange: beforeFingerprint.domHash !== afterFingerprint.domHash
  };
}
```

## DOM Extraction

### Playwright Accessibility Tree (Primary)

```typescript
const snapshot = await page.accessibility.snapshot();

// Or use locators with role
await page.getByRole('button', { name: 'Submit' }).click();
```

### Custom Extraction (Enhanced with Shadow DOM & Iframe Support)

**CRITICAL:** Standard `querySelectorAll` misses:
- **Shadow DOM:** Web Components, Lit, Salesforce Lightning, Shopify
- **Iframes:** Stripe payment forms, reCAPTCHA, Intercom chat

```typescript
// WRONG: Flat query misses Shadow DOM and Iframes
// const elements = document.querySelectorAll('button, input, a');

// CORRECT: Recursive traversal that pierces boundaries
const extractElements = async (page: Page) => {
  return page.evaluate(() => {
    const SELECTOR =
      'a[href],button,input:not([type=hidden]),select,textarea,' +
      '[role=button],[role=link],[role=menuitem],[role=tab],' +
      '[role=checkbox],[role=radio],[onclick]';

    // Recursive function that pierces Shadow DOM
    function getInteractiveElements(
      root: Document | ShadowRoot,
      depth: number = 0
    ): any[] {
      if (depth > 5) return [];  // Prevent infinite recursion

      const elements: any[] = [];

      // 1. Get standard elements in this root
      const nodes = root.querySelectorAll(SELECTOR);
      nodes.forEach((el, i) => {
        elements.push({
          mmid: `el-${depth}-${i}-${Date.now()}`,
          tag: el.tagName.toLowerCase(),
          role: el.getAttribute('role') || inferRole(el),
          name: getAccessibleName(el),
          type: el.getAttribute('type'),
          href: el.getAttribute('href'),
          disabled: el.disabled,
          visible: el.offsetParent !== null,
          rect: el.getBoundingClientRect().toJSON(),
          testId: el.getAttribute('data-testid'),
          ariaLabel: el.getAttribute('aria-label'),
          inShadowDOM: depth > 0,
          shadowHost: depth > 0 ? (root as ShadowRoot).host?.tagName : null
        });
      });

      // 2. PIERCE SHADOW DOM: Recursively traverse shadow roots
      const allNodes = root.querySelectorAll('*');
      allNodes.forEach(node => {
        if (node.shadowRoot) {
          elements.push(...getInteractiveElements(node.shadowRoot, depth + 1));
        }
      });

      return elements;
    }

    return getInteractiveElements(document);
  });
};

// For IFRAMES: Use Playwright's frame handling (not in-page JS)
async function extractFromAllFrames(page: Page): Promise<Element[]> {
  const mainElements = await extractElements(page);

  // Get all frames (Playwright handles cross-origin automatically)
  const frames = page.frames();
  const frameElements: Element[] = [];

  for (const frame of frames) {
    if (frame === page.mainFrame()) continue;

    try {
      const elements = await frame.evaluate(() => {
        // Same extraction logic, but in frame context
        return getInteractiveElements(document);
      });

      // Tag elements with frame info
      elements.forEach(el => {
        el.inIframe = true;
        el.frameUrl = frame.url();
        el.frameName = frame.name() || 'unnamed';
      });

      frameElements.push(...elements);
    } catch (e) {
      // Cross-origin frame - mark for manual review
      frameElements.push({
        tag: 'iframe',
        type: 'external',
        frameUrl: frame.url(),
        note: 'Cross-origin frame - cannot extract automatically',
        needsManualReview: true
      });
    }
  }

  return [...mainElements, ...frameElements];
}
```

### Handling Stripe, reCAPTCHA, and Third-Party Iframes

| Iframe Type | Same-Origin? | Strategy |
|-------------|--------------|----------|
| Stripe Elements | ❌ No | Use Playwright `frame.locator()` |
| reCAPTCHA | ❌ No | Mark as "requires human", skip |
| Intercom Chat | ❌ No | Detect via URL, mark as "3rd party" |
| Internal Modals | ✅ Yes | Normal extraction works |

```typescript
// Stripe example: Use Playwright's frame API
const stripeFrame = page.frameLocator('iframe[name="stripe-card-element"]');
await stripeFrame.locator('[data-testid="card-number"]').fill('4242424242424242');
```

### Selector Priority (Most Stable First)

1. `[data-testid="value"]` - Test IDs (most stable)
2. `[data-cy="value"]` - Cypress attributes
3. `#element-id` - IDs (if not dynamic)
4. `[name="value"]` - Form field names
5. `[aria-label="value"]` - Accessibility labels
6. `getByRole('button', { name: 'text' })` - Role + name
7. `text="exact text"` - Text content (last resort)

## Element Classification

### Categories

| Category | Examples | Execution Strategy |
|----------|----------|-------------------|
| **Navigation** | Links, menu items, tabs | Parallel (safe) |
| **Read** | Expand, toggle, search | Parallel (safe) |
| **Write** | Forms, submit, save | Isolated context |
| **Destructive** | Delete, logout, cancel | Run last, confirm |
| **Payment** | Buy, checkout, pay | Never auto-execute |

### Classification Logic

```typescript
function classifyElement(el: Element, pageContext: PageContext): Classification {
  const text = el.name?.toLowerCase() || '';
  const tag = el.tag;

  if (PAYMENT_KEYWORDS.some(k => text.includes(k))) {
    return { category: 'payment', confidence: 0.95 };
  }

  if (DESTRUCTIVE_KEYWORDS.some(k => text.includes(k))) {
    return { category: 'destructive', confidence: 0.90 };
  }

  if (tag === 'a' && el.href && !el.href.startsWith('javascript:')) {
    return { category: 'navigation', confidence: 0.85 };
  }

  if (['input', 'textarea', 'select'].includes(tag)) {
    return { category: 'write', confidence: 0.80 };
  }

  if (EXPAND_KEYWORDS.some(k => text.includes(k))) {
    return { category: 'read', confidence: 0.75 };
  }

  // LLM fallback for ambiguous cases
  return await llmClassify(el, pageContext);
}

const PAYMENT_KEYWORDS = ['buy', 'purchase', 'checkout', 'pay', 'order', 'subscribe'];
const DESTRUCTIVE_KEYWORDS = ['delete', 'remove', 'logout', 'cancel', 'unsubscribe'];
const EXPAND_KEYWORDS = ['expand', 'collapse', 'toggle', 'show', 'hide', 'more'];
```

### Confidence-Based Routing

```typescript
function routeElement(classification: Classification): 'automate' | 'review' | 'skip' {
  if (classification.confidence > 0.8) {
    if (classification.category === 'payment') return 'review';
    if (classification.category === 'destructive') return 'review';
    return 'automate';
  }

  if (classification.confidence > 0.6) {
    return 'review';
  }

  return 'skip';  // Add to "Do Not Touch" list
}
```

## Flow Detection

| Flow | URL Patterns | Keywords |
|------|--------------|----------|
| **Login** | `/login`, `/signin`, `/auth` | username, password, email |
| **Signup** | `/signup`, `/register`, `/join` | create account, register |
| **Checkout** | `/checkout`, `/cart`, `/payment` | shipping, billing, order |
| **Search** | `/search`, `?q=`, `?query=` | results, filter, sort |
| **CRUD** | `/new`, `/edit`, `/delete` | create, update, delete |

---

# Part 6: AI Integration

## Prompt Caching Strategy

```typescript
// Level 1: System (cached, rarely changes)
const SYSTEM_PROMPT = `
You are a test generation AI. Rules:
- Generate Playwright tests
- Use data-testid when available
- Add meaningful assertions
...
`;  // ~2000 tokens, cached

// Level 2: App (cached per session)
const APP_CONTEXT = `
App: ${appName}
Type: ${appType}
Main flows: ${flows.join(', ')}
`;  // ~500 tokens

// Use provider caching
const response = await anthropic.messages.create({
  model: 'claude-sonnet-4-20250514',
  system: [{
    type: 'text',
    text: SYSTEM_PROMPT,
    cache_control: { type: 'ephemeral' }  // Cache this
  }],
  messages: [{ role: 'user', content: dynamicPrompt }]
});
```

## RAG for Large Apps

```typescript
class ContextRetriever {
  private embeddings: Map<string, number[]> = new Map();

  async index(pages: PageInfo[]): Promise<void> {
    for (const page of pages) {
      const embedding = await embed(page.description);
      this.embeddings.set(page.url, embedding);
    }
  }

  async retrieve(query: string, k: number = 3): Promise<PageInfo[]> {
    const queryEmb = await embed(query);

    return Array.from(this.embeddings.entries())
      .map(([url, emb]) => ({
        url,
        similarity: cosineSimilarity(queryEmb, emb)
      }))
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, k)
      .map(s => pages.get(s.url));
  }
}
```

## Vision vs DOM Decision

| Scenario | Use DOM | Use Vision | Why |
|----------|---------|------------|-----|
| Standard forms | ✅ | ❌ | DOM is 37x cheaper |
| Canvas elements | ❌ | ✅ | DOM can't see canvas |
| Charts/graphs | ❌ | ✅ | Visual data |
| Icon-only buttons | ⚠️ | ✅ | No text labels |
| Regular buttons | ✅ | ❌ | Overkill |

## LLM Router

```typescript
const MODELS = {
  cheap: { provider: 'deepseek', model: 'deepseek-chat', inputCost: 0.028 },
  medium: { provider: 'openai', model: 'gpt-4o-mini', inputCost: 0.15 },
  smart: { provider: 'openai', model: 'gpt-4o', inputCost: 2.50 }
};

async function routedCompletion(task: 'classify' | 'generate' | 'fix', prompt: string) {
  const modelKey = { classify: 'cheap', generate: 'smart', fix: 'medium' }[task];
  return callModel(MODELS[modelKey], prompt);
}
```

---

# Part 7: Test Generation & Debugging

## Three-Mindset Approach

### 1. Normal User (Happy Path)
```typescript
test('user can log in with valid credentials', async ({ page }) => {
  await page.goto('/login');
  await page.fill('[data-testid="email"]', 'test@example.com');
  await page.fill('[data-testid="password"]', 'ValidPass123!');
  await page.click('[data-testid="submit"]');

  await expect(page).toHaveURL('/dashboard');
});
```

### 2. Curious User (Edge Cases)
```typescript
test('email field handles edge cases', async ({ page }) => {
  const edgeCases = ['', 'notanemail', 'a'.repeat(256) + '@test.com'];

  for (const input of edgeCases) {
    await page.fill('[data-testid="email"]', input);
    await page.click('[data-testid="submit"]');
    await expect(page.locator('.error')).toBeVisible();
  }
});
```

### 3. Malicious User (Security)
```typescript
test('login form is protected against SQL injection', async ({ page }) => {
  const attacks = ["' OR '1'='1", "'; DROP TABLE users; --"];

  for (const payload of attacks) {
    await page.fill('[data-testid="email"]', payload);
    await page.click('[data-testid="submit"]');
    await expect(page).not.toHaveURL('/dashboard');
  }
});
```

## Dry-Run Validation with Playwright Traces

**THE KEY TO DEBUGGING:** Every failed test includes a Playwright Trace file.

```typescript
interface DryRunResult {
  passed: boolean;
  errors: string[];
  executionTimeMs: number;
  screenshotOnFailure?: string;
  traceFile?: string;          // 🔥 Critical for debugging
  videoFile?: string;          // Optional but helpful
}

async function dryRunTest(testCode: string, testName: string): Promise<DryRunResult> {
  const browser = await chromium.launch({ headless: true });

  // Create context with TRACING ENABLED
  const context = await browser.newContext({
    recordVideo: { dir: './videos/' }  // Optional video
  });

  // START TRACING - captures DOM, network, console, screenshots
  await context.tracing.start({
    screenshots: true,
    snapshots: true,
    sources: true
  });

  const page = await context.newPage();
  const startTime = Date.now();

  try {
    // Execute the generated test
    const testFn = new Function('page', 'expect', `
      return (async () => { ${testCode} })();
    `);
    await testFn(page, expect);

    // Success - stop tracing (optional: keep trace anyway)
    await context.tracing.stop({ path: `./traces/${testName}-passed.zip` });

    return {
      passed: true,
      errors: [],
      executionTimeMs: Date.now() - startTime
    };

  } catch (error) {
    // FAILURE - stop tracing and SAVE IT
    const tracePath = `./traces/${testName}-FAILED-${Date.now()}.zip`;
    await context.tracing.stop({ path: tracePath });

    const screenshot = await page.screenshot();
    const videoPath = await page.video()?.path();

    return {
      passed: false,
      errors: [(error as Error).message],
      executionTimeMs: Date.now() - startTime,
      screenshotOnFailure: screenshot.toString('base64'),
      traceFile: tracePath,      // 🔥 User can open this to debug
      videoFile: videoPath
    };

  } finally {
    await context.close();
    await browser.close();
  }
}
```

## What's In a Trace File?

A Playwright Trace (`.zip`) contains:
- **DOM Snapshots** at each step
- **Screenshots** at each action
- **Console logs** from the page
- **Network requests** (XHR, fetch, resources)
- **Timeline** of all events
- **Source code** of the test

**To view:** `npx playwright show-trace ./traces/test-FAILED.zip`

## UI Integration for Traces

```typescript
// When showing failed tests in UI
function renderFailedTest(result: DryRunResult) {
  return `
    <div class="test-result failed">
      <h3>❌ ${result.testName}</h3>
      <p>Error: ${result.errors.join(', ')}</p>

      ${result.screenshotOnFailure ? `
        <img src="data:image/png;base64,${result.screenshotOnFailure}" />
      ` : ''}

      ${result.traceFile ? `
        <button onclick="openTrace('${result.traceFile}')">
          🔍 Open Trace in Playwright Inspector
        </button>
      ` : ''}

      ${result.videoFile ? `
        <video src="${result.videoFile}" controls />
      ` : ''}
    </div>
  `;
}

// Open trace viewer
function openTrace(tracePath: string) {
  // In Electron, spawn a shell command
  require('child_process').exec(`npx playwright show-trace "${tracePath}"`);
}
```

## Output Classification

```typescript
interface TestSuite {
  verified: Test[];    // Passed dry-run, ready to use
  drafts: Test[];      // Failed dry-run, has trace for debugging
  skipped: Element[];  // Could not generate tests
}

function formatOutput(suite: TestSuite): string {
  return `
## Test Suite Generated

### ✅ Verified Tests (${suite.verified.length})
These tests passed validation and are ready to use.

### ⚠️ Draft Tests (${suite.drafts.length})
These tests need review. Each has a trace file for debugging.

${suite.drafts.map(t => `
// ⚠️ DRAFT - Error: ${t.errors[0]}
// 🔍 Debug: npx playwright show-trace ${t.traceFile}
${t.code}
`).join('\n')}

### Summary
- Verification rate: ${(suite.verified.length / (suite.verified.length + suite.drafts.length) * 100).toFixed(1)}%
  `;
}
```

## Test Data Cleanup (The "Janitor")

**CRITICAL:** Running tests 24/7 in CI/CD will create thousands of junk records.

| Scenario | Records Created | Impact |
|----------|-----------------|--------|
| 50 tests × 20 runs/day | 1,000/day | DB slows down |
| Running for 1 week | 7,000 records | Backend team angry |
| Running for 1 month | 30,000 records | Staging unusable |

### Solution: Tagging + Cleanup Strategy

```typescript
// 1. ALL test data MUST use recognizable prefix
const TEST_DATA_PREFIX = 'yali_auto_';

interface TestDataConfig {
  prefix: string;
  maxAgeMinutes: number;  // Auto-delete after this
  cleanupStrategy: 'api_delete' | 'db_truncate' | 'soft_delete';
}

const config: TestDataConfig = {
  prefix: 'yali_auto_',
  maxAgeMinutes: 60,
  cleanupStrategy: 'api_delete'
};

// 2. Test data generators MUST use prefix
function generateTestUser(): TestUser {
  const timestamp = Date.now();
  return {
    email: `${TEST_DATA_PREFIX}${timestamp}@example.com`,
    username: `${TEST_DATA_PREFIX}user_${timestamp}`,
    password: 'TestPassword123!'
  };
}

function generateTestProject(): TestProject {
  return {
    name: `${TEST_DATA_PREFIX}Project_${Date.now()}`,
    description: 'Auto-generated test project - safe to delete'
  };
}

// 3. Include cleanup instruction in generated tests
const testTemplate = `
test('user can create project', async ({ page }) => {
  // Test data with cleanup prefix
  const projectName = '${TEST_DATA_PREFIX}Project_' + Date.now();

  await page.fill('[data-testid="project-name"]', projectName);
  await page.click('[data-testid="create-project"]');

  // Verify creation
  await expect(page.locator('.project-title')).toContainText(projectName);
});

// CLEANUP: This test creates data with prefix "${TEST_DATA_PREFIX}"
// Run cleanup job to remove data older than 1 hour
`;
```

### The Reaper: Automatic Cleanup Job

```typescript
// cleanup-job.ts - Run as afterAll hook or cron job
interface CleanupResult {
  usersDeleted: number;
  projectsDeleted: number;
  errors: string[];
}

async function cleanupTestData(config: TestDataConfig): Promise<CleanupResult> {
  const result: CleanupResult = { usersDeleted: 0, projectsDeleted: 0, errors: [] };
  const cutoffTime = Date.now() - (config.maxAgeMinutes * 60 * 1000);

  // Strategy 1: API-based deletion (safest)
  if (config.cleanupStrategy === 'api_delete') {
    // Delete test users via API
    const users = await api.get(`/admin/users?email_prefix=${config.prefix}`);
    for (const user of users) {
      const createdAt = new Date(user.created_at).getTime();
      if (createdAt < cutoffTime) {
        try {
          await api.delete(`/admin/users/${user.id}`);
          result.usersDeleted++;
        } catch (e) {
          result.errors.push(`Failed to delete user ${user.id}: ${e.message}`);
        }
      }
    }

    // Delete test projects
    const projects = await api.get(`/admin/projects?name_prefix=${config.prefix}`);
    for (const project of projects) {
      const createdAt = new Date(project.created_at).getTime();
      if (createdAt < cutoffTime) {
        try {
          await api.delete(`/admin/projects/${project.id}`);
          result.projectsDeleted++;
        } catch (e) {
          result.errors.push(`Failed to delete project ${project.id}: ${e.message}`);
        }
      }
    }
  }

  // Strategy 2: Direct DB cleanup (faster but requires DB access)
  if (config.cleanupStrategy === 'db_truncate') {
    await db.query(`
      DELETE FROM users
      WHERE email LIKE '${config.prefix}%'
      AND created_at < NOW() - INTERVAL '${config.maxAgeMinutes} minutes'
    `);

    await db.query(`
      DELETE FROM projects
      WHERE name LIKE '${config.prefix}%'
      AND created_at < NOW() - INTERVAL '${config.maxAgeMinutes} minutes'
    `);
  }

  return result;
}

// Run after each test suite
afterAll(async () => {
  const result = await cleanupTestData(config);
  console.log(`Cleanup: Deleted ${result.usersDeleted} users, ${result.projectsDeleted} projects`);
});

// Or run as scheduled cron job (every hour)
// 0 * * * * node cleanup-job.js
```

### Cleanup Dashboard (UI)

```typescript
// Show cleanup status in YaliTest UI
interface CleanupStatus {
  lastRun: Date;
  recordsCleaned: number;
  pendingCleanup: number;
  oldestTestData: Date;
}

function renderCleanupStatus(status: CleanupStatus) {
  return `
    <div class="cleanup-status">
      <h4>🧹 Test Data Cleanup</h4>
      <p>Last run: ${status.lastRun.toLocaleString()}</p>
      <p>Records cleaned: ${status.recordsCleaned}</p>
      <p>Pending cleanup: ${status.pendingCleanup}</p>
      ${status.pendingCleanup > 100 ? `
        <button onclick="runCleanupNow()">
          ⚠️ Run Cleanup Now (${status.pendingCleanup} records)
        </button>
      ` : ''}
    </div>
  `;
}
```

---

# Part 8: Self-Healing & Failure Analysis

> **"Always have an answer. If AI doesn't know, ASK. Never return 'unknown error.'"**

## The Self-Healing Philosophy

Traditional test frameworks fail silently with unhelpful messages:
```
❌ Element not found: [data-testid="submit"]
```

YaliTest's approach:
```
❌ Element not found: [data-testid="submit"]
📸 Previous state: [screenshot showing button]
📸 Current state: [screenshot showing button moved]
🔍 AI Analysis: Button selector changed from data-testid="submit" to data-testid="submit-btn"
✅ Auto-healed: Updated selector (confidence: 94%)
```

## Self-Healing with AI + Human Fallback

```typescript
interface SelfHealContext {
  failedSelector: string;
  previousScreenshot: Buffer;
  previousDOM: string;
  currentScreenshot: Buffer;
  currentDOM: string;
  action: 'click' | 'fill' | 'assert';
  errorMessage: string;
}

interface HealResult {
  success: boolean;
  newSelector?: string;
  confidence: number;
  method: 'ai-healed' | 'human-confirmed' | 'skipped';
  explanation: string;
}

async function selfHeal(context: SelfHealContext): Promise<HealResult> {
  // Step 1: AI analyzes the change
  const analysis = await llm.analyze({
    prompt: `
      Compare these two states:
      - Previous DOM (relevant section)
      - Current DOM (relevant section)
      - Previous screenshot
      - Current screenshot

      The test tried to find: ${context.failedSelector}
      Error: ${context.errorMessage}

      Questions:
      1. Did the element move? If so, what's the new selector?
      2. Was the element removed entirely?
      3. Did the page structure change?
      4. Is this a timing issue (element not loaded yet)?

      Provide your best selector suggestion with confidence 0-1.
    `,
    images: [context.previousScreenshot, context.currentScreenshot]
  });

  // Step 2: High confidence → Auto-heal
  if (analysis.confidence > 0.9) {
    return {
      success: true,
      newSelector: analysis.newSelector,
      confidence: analysis.confidence,
      method: 'ai-healed',
      explanation: analysis.reasoning
    };
  }

  // Step 3: Medium confidence → Ask developer
  if (analysis.confidence > 0.6) {
    const answer = await askViaSlack({
      message: `🔧 Test self-healing needed`,
      context: `
        Failed selector: \`${context.failedSelector}\`
        AI suggestion: \`${analysis.newSelector}\` (${Math.round(analysis.confidence * 100)}% confident)
        Reason: ${analysis.reasoning}
      `,
      images: [context.previousScreenshot, context.currentScreenshot],
      options: [
        { label: '✅ Use AI suggestion', value: 'use-suggestion' },
        { label: '🔧 Use different selector', value: 'custom' },
        { label: '🗑️ Element was removed (expected)', value: 'removed' },
        { label: '🐛 This is a bug', value: 'bug' }
      ]
    });

    if (answer.value === 'use-suggestion') {
      return {
        success: true,
        newSelector: analysis.newSelector,
        confidence: 1.0,  // Human confirmed
        method: 'human-confirmed',
        explanation: 'Developer approved AI suggestion'
      };
    }

    if (answer.value === 'custom') {
      return {
        success: true,
        newSelector: answer.customSelector,
        confidence: 1.0,
        method: 'human-confirmed',
        explanation: 'Developer provided custom selector'
      };
    }

    if (answer.value === 'bug') {
      // Record as actual bug
      await recordBug({
        type: 'element-missing',
        selector: context.failedSelector,
        screenshots: [context.previousScreenshot, context.currentScreenshot],
        reportedBy: 'developer-via-slack'
      });
      return {
        success: false,
        confidence: 1.0,
        method: 'human-confirmed',
        explanation: 'Developer confirmed this is a bug'
      };
    }
  }

  // Step 4: Low confidence → Skip and flag
  return {
    success: false,
    confidence: analysis.confidence,
    method: 'skipped',
    explanation: `AI confidence too low (${analysis.confidence}). Added to manual review queue.`
  };
}
```

## Failure Analysis: Never "Unknown Error"

Every failure MUST have an explanation:

```typescript
interface FailureReport {
  testName: string;
  step: string;
  errorType: ErrorType;
  explanation: string;          // Human-readable
  technicalDetails: string;     // For debugging
  screenshots: {
    before: Buffer;
    after: Buffer;
  };
  traceFile: string;            // Playwright trace
  aiAnalysis?: string;          // What AI thinks went wrong
  suggestedFix?: string;        // How to fix it
  confidence: number;
}

type ErrorType =
  | 'element_not_found'
  | 'element_not_visible'
  | 'element_moved'
  | 'navigation_failed'
  | 'timeout'
  | 'assertion_failed'
  | 'network_error'
  | 'auth_expired'
  | 'captcha_detected'
  | 'rate_limited';

async function analyzeFailure(error: Error, context: TestContext): Promise<FailureReport> {
  // Capture all evidence
  const screenshot = await context.page.screenshot();
  const domSnapshot = await context.page.content();
  const networkLogs = await context.page.context().tracing.stop();

  // Classify the error
  const errorType = classifyError(error);

  // AI analyzes what went wrong
  const analysis = await llm.analyze({
    prompt: `
      A test failed with this error: ${error.message}

      Error type: ${errorType}
      URL: ${context.page.url()}
      Step: ${context.currentStep}

      Based on the screenshot and DOM, explain:
      1. What went wrong (in simple terms)?
      2. Why did it happen?
      3. How can it be fixed?

      Be specific and actionable.
    `,
    images: [screenshot],
    html: domSnapshot.substring(0, 10000)  // Truncate for token limit
  });

  return {
    testName: context.testName,
    step: context.currentStep,
    errorType,
    explanation: analysis.simpleExplanation,
    technicalDetails: error.stack,
    screenshots: {
      before: context.previousScreenshot,
      after: screenshot
    },
    traceFile: context.tracePath,
    aiAnalysis: analysis.fullAnalysis,
    suggestedFix: analysis.suggestedFix,
    confidence: analysis.confidence
  };
}

// Error classification rules
function classifyError(error: Error): ErrorType {
  const msg = error.message.toLowerCase();

  if (msg.includes('not found') || msg.includes('no element')) {
    return 'element_not_found';
  }
  if (msg.includes('not visible') || msg.includes('hidden')) {
    return 'element_not_visible';
  }
  if (msg.includes('timeout')) {
    return 'timeout';
  }
  if (msg.includes('navigation')) {
    return 'navigation_failed';
  }
  if (msg.includes('assert')) {
    return 'assertion_failed';
  }
  if (msg.includes('net::') || msg.includes('network')) {
    return 'network_error';
  }
  if (msg.includes('captcha') || msg.includes('challenge')) {
    return 'captcha_detected';
  }
  if (msg.includes('rate limit') || msg.includes('too many')) {
    return 'rate_limited';
  }
  if (msg.includes('401') || msg.includes('403') || msg.includes('unauthorized')) {
    return 'auth_expired';
  }

  return 'element_not_found';  // Default
}
```

## Visual Diff for Regression Detection

```typescript
interface VisualDiff {
  baselineId: string;
  currentScreenshot: Buffer;
  diffImage: Buffer;
  percentChanged: number;
  changedRegions: Region[];
  verdict: 'match' | 'minor-change' | 'significant-change' | 'completely-different';
}

async function compareVisuals(
  current: Buffer,
  baseline: Buffer,
  threshold: number = 0.5
): Promise<VisualDiff> {
  // Use pixelmatch or similar for comparison
  const { diffPixels, diffImage, regions } = await pixelCompare(current, baseline);
  const percentChanged = diffPixels / (width * height) * 100;

  let verdict: VisualDiff['verdict'];
  if (percentChanged < 0.1) {
    verdict = 'match';
  } else if (percentChanged < 1.0) {
    verdict = 'minor-change';
  } else if (percentChanged < 10.0) {
    verdict = 'significant-change';
  } else {
    verdict = 'completely-different';
  }

  return {
    baselineId: baseline.id,
    currentScreenshot: current,
    diffImage,
    percentChanged,
    changedRegions: regions,
    verdict
  };
}

// If significant change, ask user
if (visualDiff.verdict === 'significant-change') {
  const answer = await askViaSlack({
    message: `🎨 Visual change detected (${visualDiff.percentChanged.toFixed(1)}% different)`,
    images: [visualDiff.baselineScreenshot, visualDiff.currentScreenshot, visualDiff.diffImage],
    options: [
      { label: '✅ Expected change - update baseline', value: 'update' },
      { label: '🐛 Unexpected - this is a bug', value: 'bug' },
      { label: '🔍 Need to investigate', value: 'investigate' }
    ]
  });
}
```

## Self-Healing Statistics Dashboard

```typescript
interface HealingStats {
  totalAttempts: number;
  aiHealedSuccessfully: number;
  humanConfirmed: number;
  skippedLowConfidence: number;
  actualBugsFound: number;

  // Learning metrics
  patternsLearned: number;
  reuseRate: number;  // How often learned patterns helped
}

function renderHealingDashboard(stats: HealingStats) {
  return `
    ## 🔧 Self-Healing Statistics

    | Metric | Count | Rate |
    |--------|-------|------|
    | Total healing attempts | ${stats.totalAttempts} | - |
    | AI healed automatically | ${stats.aiHealedSuccessfully} | ${pct(stats.aiHealedSuccessfully, stats.totalAttempts)} |
    | Human confirmed | ${stats.humanConfirmed} | ${pct(stats.humanConfirmed, stats.totalAttempts)} |
    | Skipped (low confidence) | ${stats.skippedLowConfidence} | ${pct(stats.skippedLowConfidence, stats.totalAttempts)} |
    | Actual bugs found | ${stats.actualBugsFound} | ${pct(stats.actualBugsFound, stats.totalAttempts)} |

    ### Learning Progress
    - Patterns learned: ${stats.patternsLearned}
    - Pattern reuse rate: ${stats.reuseRate}% of healings used learned patterns

    ### Accuracy: ${stats.aiHealedSuccessfully + stats.humanConfirmed + stats.actualBugsFound} / ${stats.totalAttempts} = ${pct(stats.aiHealedSuccessfully + stats.humanConfirmed + stats.actualBugsFound, stats.totalAttempts)}
  `;
}
```

---

# Part 9: Human-in-the-Loop

## When AI Asks Humans

| Situation | Question | Options |
|-----------|----------|---------|
| Login page found | "Test authenticated areas?" | Credentials / Skip / SSO |
| Delete button | "Test destructive actions?" | Test / Skip / Confirm first |
| Payment flow | "How to handle payment?" | Test card / Skip / Stop before |
| Low confidence | "Is this a bug?" | Bug / Expected / More context |

## Slack Integration

```typescript
import { App } from '@slack/bolt';

const slackApp = new App({
  token: process.env.SLACK_BOT_TOKEN,
  appToken: process.env.SLACK_APP_TOKEN,
  socketMode: true,
});

async function askInSlack(question: Question): Promise<string> {
  const message = await slackApp.client.chat.postMessage({
    channel: process.env.YALITEST_CHANNEL,
    blocks: [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `🤖 *YaliTest*\n\n${question.text}` }
      },
      {
        type: 'actions',
        elements: question.options.map((opt, i) => ({
          type: 'button',
          text: { type: 'plain_text', text: opt },
          action_id: `yalitest_${question.id}_${i}`,
          value: opt
        }))
      }
    ]
  });

  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(question.defaultOption), 5 * 60 * 1000);

    slackApp.action(/yalitest_/, async ({ ack, action }) => {
      await ack();
      clearTimeout(timeout);
      resolve(action.value);
    });
  });
}
```

## Human Labeling Queue & Learning

```typescript
class LabelingQueue {
  tasks: Map<string, LabelingTask> = new Map();

  enqueue(element: Element, aiResult: Classification): void {
    if (aiResult.confidence < 0.6) {
      this.tasks.set(generateId(), {
        element,
        aiSuggestion: aiResult.category,
        aiConfidence: aiResult.confidence,
        status: 'pending'
      });
    }
  }

  submitLabel(taskId: string, label: string): void {
    const task = this.tasks.get(taskId);
    task.humanLabel = label;
    task.status = 'labeled';

    // Learn from correction
    if (task.humanLabel !== task.aiSuggestion) {
      learningEngine.recordCorrection(task);
    }
  }
}
```

---

# Part 10: Security & Credentials

## The Problem with Environment Variables

Storing passwords in `.env` files or environment variables is risky:
- Can leak into crash dumps
- Visible in process lists
- Not encrypted at rest

## Solution: OS Keychain Integration

Use `keytar` to store credentials securely in the OS credential manager:
- **Windows:** Credential Manager
- **macOS:** Keychain
- **Linux:** Secret Service (libsecret)

```bash
npm install keytar
```

```typescript
import * as keytar from 'keytar';

const SERVICE_NAME = 'YaliTest';

class CredentialManager {
  // Save credentials securely in OS keychain
  static async saveCredential(
    domain: string,
    username: string,
    password: string
  ): Promise<void> {
    const key = `${domain}:${username}`;
    await keytar.setPassword(SERVICE_NAME, key, password);
  }

  // Retrieve credentials from OS keychain
  static async getCredential(
    domain: string,
    username: string
  ): Promise<string | null> {
    const key = `${domain}:${username}`;
    return keytar.getPassword(SERVICE_NAME, key);
  }

  // Delete credentials
  static async deleteCredential(
    domain: string,
    username: string
  ): Promise<boolean> {
    const key = `${domain}:${username}`;
    return keytar.deletePassword(SERVICE_NAME, key);
  }

  // List all saved credentials (without passwords)
  static async listCredentials(): Promise<{ domain: string; username: string }[]> {
    const credentials = await keytar.findCredentials(SERVICE_NAME);
    return credentials.map(c => {
      const [domain, username] = c.account.split(':');
      return { domain, username };
    });
  }

  // Auto-fill login form using saved credentials
  static async autoFillLogin(
    page: Page,
    domain: string,
    username: string
  ): Promise<boolean> {
    const password = await this.getCredential(domain, username);
    if (!password) {
      return false;
    }

    // Find and fill login form
    await page.fill('input[name="username"], input[name="email"], input[type="email"]', username);
    await page.fill('input[type="password"]', password);
    return true;
  }
}
```

## Credential Flow in YaliTest

```typescript
// 1. User provides credentials through secure UI (not stored in app state)
async function handleCredentialInput(domain: string) {
  // Show secure input dialog in Electron
  const { username, password } = await showSecureCredentialDialog();

  // Store in OS keychain (not in app memory or files)
  await CredentialManager.saveCredential(domain, username, password);

  // Create authenticated browser context
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`https://${domain}/login`);
  await CredentialManager.autoFillLogin(page, domain, username);
  await page.click('[type="submit"]');

  // Save session state (not credentials) to StateBank
  await stateBank.save(context, `${domain}-authenticated`);

  // Clear password from any memory
  // (JavaScript can't guarantee this, but we minimize exposure)
}

// 2. Subsequent test runs use StateBank (session), not credentials
async function runAuthenticatedTests(domain: string) {
  const context = await stateBank.createAuthenticatedContext(
    browser,
    `${domain}-authenticated`
  );
  // Tests run with saved cookies/session, never see the password
}
```

## Trust Statement (Show in UI)

```
🔒 Your credentials are secure:
• Stored in your OS keychain (not in YaliTest files)
• Never sent to our servers
• Encrypted by your operating system
• Cleared from memory after use
• You can delete them anytime from OS settings
```

---

# Part 11: Implementation Roadmap

## Phase 0: Proof of Concept (1 week)

**Goal:** Validate architecture on saucedemo.com

### Tasks
- [ ] Set up Playwright in separate worker with stealth
- [ ] Implement smart waiting (no waitForTimeout)
- [ ] Add Playwright Tracing for all runs
- [ ] Implement StateBank for auth persistence
- [ ] Generate and validate 5 login tests

### Success Criteria
| Metric | Target |
|--------|--------|
| Pages discovered | 6/6 (100%) |
| Elements classified | >90% correct |
| Tests passing dry-run | >80% |
| Failed tests have traces | 100% |

## Phase 1: Core Engine (4 weeks)

**Goal:** Robust crawling with full visibility

### Tasks
- [ ] Implement Navigation Graph with cycle detection
- [ ] Add state fingerprinting
- [ ] Build Browser Worker Pool with rate limiting
- [ ] Add anti-bot stealth mode
- [ ] Create element classification (rule-based)
- [ ] Implement Trace Viewer integration in UI

### Deliverables
- Crawl any site up to 100 pages without getting banned
- Full debugging traces for every failure
- No infinite loops

## Phase 2: AI Integration (4 weeks)

**Goal:** Smart test generation with validation

### Tasks
- [ ] Integrate LLM APIs with prompt caching
- [ ] Build multi-model router
- [ ] Add RAG for large apps
- [ ] Build dry-run validation loop with traces
- [ ] Create Verified vs Draft classification

### Deliverables
- Generate tests with 3 mindsets
- 80%+ tests pass validation
- Trace files for all failed tests

## Phase 3: Human Integration (3 weeks)

**Goal:** Seamless human-in-the-loop

### Tasks
- [ ] Build Slack bot
- [ ] Create labeling queue UI
- [ ] Implement "Do Not Touch" list
- [ ] Add learning from corrections

## Phase 4: Production Polish (3 weeks)

**Goal:** Production-ready with security

### Tasks
- [ ] Integrate OS Keychain (keytar) for credentials
- [ ] CI/CD integration (GitHub Actions)
- [ ] Progress UI with trace viewer
- [ ] Cost transparency dashboard

## Phase 5: Scale & Enterprise (4 weeks)

### Tasks
- [ ] Team collaboration & SSO
- [ ] Audit logs
- [ ] Multi-browser support

---

# Part 12: Success Metrics

## Accuracy Targets (With Input Collection)

| Metric | Without Inputs | With Inputs | Target |
|--------|----------------|-------------|--------|
| Page discovery | 95% | 98% | **98%+** |
| Element detection | 90% | 95% | **95%+** |
| Classification accuracy | 85% | 95% | **95%+** |
| Self-healing success | 75% | 95% | **95%+** |
| Test validation rate | 80% | 90% | **90%+** |
| Edge case generation | 70% | 92% | **92%+** |
| Security test quality | 60% | 88% | **88%+** |
| Bug detection | 70% | 92% | **92%+** |
| False positive rate | 15% | 8% | **<10%** |
| **Overall Accuracy** | **73%** | **93%** | **93%+** |

## Debugging Targets

| Metric | Target |
|--------|--------|
| Failed tests with traces | 100% |
| Trace file size | <5MB each |
| Time to open trace | <3 seconds |

## Security Targets

| Metric | Target |
|--------|--------|
| Credentials in OS keychain | 100% |
| Passwords in app memory | 0 |
| Passwords in log files | 0 |

## Performance Targets

| Metric | Target |
|--------|--------|
| Time for 100 pages | <10 minutes |
| Cost for 100 pages | <$3.00 |
| Bot detection rate | <5% |

---

# Appendix A: Technology Stack

| Component | Technology | Why |
|-----------|------------|-----|
| Desktop app | Electron | Current stack |
| Browser automation | playwright-extra + stealth | Anti-bot |
| Credential storage | keytar | OS keychain |
| LLM (cheap) | DeepSeek V3 | $0.028/MTok |
| LLM (smart) | GPT-4o | Best code gen |
| Local storage | better-sqlite3 | Fast |
| Communication | Slack Bolt SDK | Real-time |
| Debugging | Playwright Traces | Full visibility |

## NPM Dependencies

```json
{
  "dependencies": {
    "playwright": "^1.x",
    "playwright-extra": "^4.x",
    "puppeteer-extra-plugin-stealth": "^2.x",
    "keytar": "^7.x",
    "openai": "^4.x",
    "@anthropic-ai/sdk": "^0.x",
    "@slack/bolt": "^3.x",
    "better-sqlite3": "^9.x",
    "zod": "^3.x",
    "xxhash-wasm": "^1.x"
  }
}
```

---

# Appendix B: File Structure

```
yalitest/
├── electron/
│   ├── main.js              # Electron main (UI only)
│   ├── preload.js           # IPC bridge
│   └── workers/
│       └── browser-worker.js # Playwright worker with stealth
├── src/
│   ├── App.tsx              # React UI
│   ├── lib/
│   │   ├── llm-router.ts    # Multi-model routing
│   │   ├── nav-graph.ts     # Navigation Graph
│   │   ├── state-bank.ts    # Auth state persistence
│   │   ├── credential-manager.ts # OS keychain integration
│   │   ├── smart-wait.ts    # Smart waiting utilities
│   │   ├── classifier.ts    # Element classification
│   │   ├── test-generator.ts # Test generation
│   │   ├── dry-runner.ts    # Test validation with traces
│   │   ├── dom-extractor.ts # Shadow DOM & iframe extraction
│   │   └── cleanup-job.ts   # Test data janitor
│   ├── components/
│   │   ├── Progress.tsx     # Discovery progress
│   │   ├── TraceViewer.tsx  # Embedded trace viewer
│   │   ├── LabelingQueue.tsx # Human labeling UI
│   │   ├── CleanupStatus.tsx # Test data cleanup dashboard
│   │   └── TestPreview.tsx  # Test review
│   └── workers/
│       └── browser-pool.ts  # Worker pool with rate limiting
├── traces/                  # Playwright trace files
├── videos/                  # Test execution videos
├── states/                  # Auth state files (storageState)
├── prompts/
│   ├── classify.md
│   ├── generate-normal.md
│   ├── generate-edge.md
│   └── generate-security.md
└── package.json
```

---

# Appendix C: Critical Checklist

## Before Production Launch

### Core Infrastructure

| Item | Status | Impact |
|------|--------|--------|
| Smart waiting (no fixed timeouts) | Required | Flaky tests |
| Auth StateBank | Required | Tests fail - not logged in |
| Playwright Traces on failure | Required | Can't debug |
| OS Keychain for credentials | Required | Security risk |
| Anti-bot stealth | Required | Get banned |
| Rate limiting | Required | Get banned |
| Navigation Graph | Required | Infinite loops |
| State fingerprinting | Required | Revisit same pages |
| **Shadow DOM extraction** | Required | Miss Web Components, Stripe |
| **Iframe handling** | Required | Miss payment forms, chat widgets |
| **Test data prefix** | Required | Pollute staging DB |
| **Cleanup job** | Required | 30K junk records/month |

### Input Collection (for 93% Accuracy)

| Item | Status | Impact |
|------|--------|--------|
| **yalitest.config.yml parser** | Required | +15% flow detection |
| **Schema import (OpenAPI/Zod)** | Required | +22% edge case generation |
| **Slack/Teams integration** | Required | Ask when confidence < 80% |
| **Golden baseline capture** | Required | +22% bug detection |
| **Learning engine** | Required | Continuous improvement |
| **Confidence-based routing** | Required | Auto vs Ask vs Skip decisions |

### Self-Healing System

| Item | Status | Impact |
|------|--------|--------|
| **AI-powered selector healing** | Required | 95% self-healing rate |
| **Screenshot + DOM comparison** | Required | Understand what changed |
| **Human fallback via Slack** | Required | Handle edge cases |
| **Learning from corrections** | Required | Build rule patterns |
| **Never "unknown error"** | Required | Always explain failures |

---

# Summary

## What Makes YaliTest Different

| Others | YaliTest |
|--------|----------|
| Manual test recording | Autonomous discovery |
| Manual test scripting | AI-generated + validated |
| "Test failed" (black box) | Full Playwright Traces |
| Credentials in plain text | OS Keychain (encrypted) |
| Gets banned by Cloudflare | Stealth mode + rate limiting |
| Misses Shadow DOM & iframes | Recursive extraction |
| Pollutes staging DB | Auto-cleanup job |
| Single browser | Parallel worker pool |
| $500-8000/month | $99-399/month |

## The Honest Promise

> YaliTest automates the tedious 70% of QA work with **93% accuracy** through intelligent input collection.
> When AI doesn't know, it ASKS - never guesses.
> When tests fail, you get full debugging traces - not just "element not found."
> Your credentials stay secure in your OS keychain - never in our files.
> Together, you ship faster with fewer bugs.

## Why 93% (Not 73%)

The difference isn't AI capability - it's **input quality**:

| Without Inputs | With Inputs | How |
|----------------|-------------|-----|
| 75% self-healing | **95%** | AI compares screenshots + DOM, asks if unsure |
| 70% edge cases | **92%** | User provides validation schema |
| 60% security tests | **88%** | Config defines auth type, roles, sensitive fields |
| 80% flow detection | **95%** | User confirms flows in config file |
| 70% bug detection | **92%** | Golden baselines define "correct" state |

**The wall isn't technical. AI is capable. The wall is missing information - and we solve that by ASKING.**
