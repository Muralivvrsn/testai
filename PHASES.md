# YaliTest: The Living Organism

## Implementation Phases as Body Parts

> **"A QA platform is like a human body - each organ must work in harmony. Build the skeleton first, then the heart, then the brain. Skip nothing."**

---

```
                    THE YALITEST ORGANISM

                         [MEMORY]
                      Learning Engine
                            |
                    +----- BRAIN -----+
                    |  AI Intelligence |
                    +--------+---------+
                             |
        +--------+     +-----+-----+     +--------+
        |  EYES  |-----|  NERVOUS  |-----|  EARS  |
        | Vision |     |  SYSTEM   |     | Input  |
        +--------+     | Coordin.  |     +--------+
             |         +-----+-----+         |
             |               |               |
        +----+----+    +-----+-----+    +----+----+
        |  HANDS  |    |   HEART   |    |  LUNGS  |
        | Actions |    |  Browser  |    | Config  |
        +----+----+    |   Engine  |    +----+----+
             |         +-----+-----+         |
             |               |               |
        +----+----+    +-----+-----+    +----+----+
        | STOMACH |    |  IMMUNE   |    |  LIVER  |
        |  Test   |    |  SYSTEM   |    | Cleanup |
        | Generate|    | Self-Heal |    +---------+
        +---------+    +-----------+
                             |
                    +--------+--------+
                    |      SKIN       |
                    |    Security     |
                    +-----------------+
                             |
                    +--------+--------+
                    |     VOICE       |
                    |  Communication  |
                    +-----------------+
                             |
                    +-----------------+
                    |    SKELETON     |
                    |   Foundation    |
                    +-----------------+
```

---

# Phase Overview

| Phase | Body Part | Name | Duration | Difficulty | Criticality | Dependencies |
|-------|-----------|------|----------|------------|-------------|--------------|
| **0** | DNA | Blueprint | Done | - | - | None |
| **1** | SKELETON | Foundation | 1 week | Easy | Critical | None |
| **2** | HEART | Browser Engine | 2 weeks | Hard | Critical | Skeleton |
| **3** | EYES | Vision System | 2 weeks | Medium | Critical | Heart |
| **4** | NERVOUS SYSTEM | Coordination | 2 weeks | Hard | Critical | Eyes |
| **5** | HANDS | Action System | 1.5 weeks | Medium | High | Nervous System |
| **6** | LUNGS | Input Breathing | 2 weeks | Medium | High | Hands |
| **7** | BRAIN | Intelligence | 3 weeks | Hard | Critical | Lungs |
| **8** | STOMACH | Test Digestion | 2.5 weeks | Hard | Critical | Brain |
| **9** | IMMUNE SYSTEM | Self-Healing | 2 weeks | Hard | High | Stomach |
| **10** | LIVER | Cleanup System | 1 week | Easy | Medium | Immune |
| **11** | SKIN | Security Layer | 1.5 weeks | Medium | High | Liver |
| **12** | MEMORY | Learning Engine | 2 weeks | Medium | High | All above |
| **13** | VOICE | Communication | 2 weeks | Medium | High | Memory |
| **14** | SOUL | Launch Polish | 1.5 weeks | Easy | High | Voice |

**Total: ~24 weeks (6 months)**

---

# Detailed Phase Breakdown

---

## Phase 0: DNA (Blueprint)
### *"The genetic code that defines everything"*

**Status:** COMPLETE

**What It Is:**
The DNA is the plan itself - the architectural blueprint that every other phase follows. Without DNA, you'd be building randomly.

**What We Have:**
- `plan_v2.md` - Complete strategy document
- `CLAUDE.md` - Technical documentation
- Architecture diagrams
- Cost analysis
- Competitor analysis

**Why It Matters:**
> "A body without DNA is just random cells. A project without a plan is just random code."

---

## Phase 1: SKELETON (Foundation)
### *"The bones that hold everything together"*

```
┌─────────────────────────────────────────────────────────────┐
│                       SKELETON                               │
│                                                             │
│  Like human bones:                                          │
│  - Provides STRUCTURE                                       │
│  - Everything ATTACHES to it                               │
│  - Must be SOLID before adding organs                      │
│  - If broken, the whole body collapses                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 1 week
**Difficulty:** Easy (but must be perfect)
**Criticality:** CRITICAL - everything depends on this

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Electron Shell | `electron/main.js` | Application container |
| IPC Bridge | `electron/preload.js` | Communication channel |
| React App | `src/App.tsx` | User interface shell |
| File Structure | `src/lib/*` | Code organization |
| Type Definitions | `src/types/*` | TypeScript foundation |
| Build System | `package.json`, `vite.config` | Development tooling |

**Technical Requirements:**
```typescript
// SKELETON must provide:
interface SkeletonCapabilities {
  electronApp: {
    createWindow(): BrowserWindow;
    handleIPC(): void;
    gracefulShutdown(): void;
  };

  fileStructure: {
    src: { lib: {}, components: {}, workers: {} };
    electron: { workers: {} };
    traces: {};    // For debugging
    states: {};    // For auth
  };

  typeSystem: {
    Element: Interface;
    Page: Interface;
    Action: Interface;
    TestCase: Interface;
  };
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| App launches without errors | 100% |
| IPC communication works | 100% |
| Hot reload functional | Yes |
| TypeScript compiles | 0 errors |
| Basic UI renders | Yes |

**Deliverables:**
- [ ] Electron app that opens a window
- [ ] React UI with basic layout
- [ ] IPC bridge between main/renderer
- [ ] TypeScript configured with strict mode
- [ ] File structure matching architecture
- [ ] Development scripts working

**Why SKELETON First:**
> "You can't hang muscles on thin air. You can't install eyes without a skull. The skeleton must exist before any organ."

---

## Phase 2: HEART (Browser Engine)
### *"The pump that gives life to everything"*

```
┌─────────────────────────────────────────────────────────────┐
│                         HEART                                │
│                                                             │
│  Like the human heart:                                      │
│  - PUMPS blood (browser instances) to all organs           │
│  - Must NEVER stop (critical for operation)                │
│  - Works in RHYTHM (rate limiting)                         │
│  - Has CHAMBERS (worker pool)                              │
│  - If heart fails, organism DIES                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** HARD (most complex infrastructure)
**Criticality:** CRITICAL - if heart stops, everything dies

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Browser Pool | `src/workers/browser-pool.ts` | Worker management |
| Browser Worker | `electron/workers/browser-worker.js` | Individual browser |
| Stealth Config | `src/lib/stealth.ts` | Anti-bot detection |
| Rate Limiter | `src/lib/rate-limiter.ts` | Request throttling |
| Tracing System | `src/lib/tracer.ts` | Debugging capture |

**Technical Requirements:**
```typescript
// HEART must provide:
interface HeartCapabilities {
  browserPool: {
    poolSize: number;              // 4-8 workers
    initialize(): Promise<void>;
    getWorker(): Promise<Worker>;
    releaseWorker(worker: Worker): void;
    shutdown(): Promise<void>;
  };

  stealth: {
    userAgentRotation: string[];
    humanDelay(): Promise<void>;   // 500-2000ms
    fingerprint: BrowserFingerprint;
  };

  rateLimiter: {
    requestsPerMinute: number;     // 30 default
    waitIfNeeded(domain: string): Promise<void>;
  };

  tracing: {
    startTrace(context: BrowserContext): Promise<void>;
    stopTrace(path: string): Promise<void>;
    enabled: boolean;              // Always true
  };
}
```

**Implementation Details:**
```typescript
// browser-pool.ts
import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';

chromium.use(stealthPlugin());

class BrowserPool {
  private workers: Worker[] = [];
  private available: Worker[] = [];
  private poolSize = 4;

  async initialize(): Promise<void> {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker('./browser-worker.js');
      await this.setupWorker(worker);
      this.workers.push(worker);
      this.available.push(worker);
    }
    console.log(`💓 Heart started: ${this.poolSize} chambers ready`);
  }

  async getWorker(): Promise<Worker> {
    if (this.available.length === 0) {
      // Wait for a worker to become available
      await this.waitForAvailable();
    }
    return this.available.pop()!;
  }

  releaseWorker(worker: Worker): void {
    this.available.push(worker);
  }
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Workers initialize | 100% success |
| Parallel browsing | 4-8 concurrent |
| Stealth mode active | Not detected |
| Rate limiting works | <30 req/min/domain |
| Tracing captures | 100% of sessions |
| Memory stable | No leaks after 1hr |

**Deliverables:**
- [ ] Browser worker pool (4-8 workers)
- [ ] Playwright with stealth plugin
- [ ] Rate limiter per domain
- [ ] User agent rotation
- [ ] Human-like delays
- [ ] Tracing enabled by default
- [ ] Graceful shutdown

**Why HEART Second:**
> "The heart must beat before any organ can receive blood. The browser engine must work before we can see, think, or act."

**Risks:**
| Risk | Impact | Mitigation |
|------|--------|------------|
| Memory leaks | High | Proper worker cleanup |
| Bot detection | High | Stealth plugin + delays |
| Race conditions | Medium | Worker isolation |

---

## Phase 3: EYES (Vision System)
### *"The windows to the web page soul"*

```
┌─────────────────────────────────────────────────────────────┐
│                          EYES                                │
│                                                             │
│  Like human eyes:                                           │
│  - SEES everything on the page                             │
│  - Can see INSIDE shadow DOM (X-ray vision)                │
│  - Can see THROUGH iframes (telescopic)                    │
│  - CAPTURES screenshots (photographic memory)              │
│  - Sends visual data to BRAIN for processing               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** MEDIUM
**Criticality:** CRITICAL - can't test what you can't see

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| DOM Extractor | `src/lib/dom-extractor.ts` | Element extraction |
| Shadow DOM Pierce | Inside extractor | Web components |
| Iframe Handler | Inside extractor | Cross-frame elements |
| Screenshot Capture | `src/lib/screenshot.ts` | Visual evidence |
| Accessibility Tree | `src/lib/a11y-tree.ts` | Playwright a11y |

**Technical Requirements:**
```typescript
// EYES must provide:
interface EyesCapabilities {
  domExtractor: {
    extractElements(page: Page): Promise<Element[]>;
    extractFromShadowDOM(root: ShadowRoot): Element[];
    extractFromIframes(page: Page): Promise<Element[]>;
    getAccessibilityTree(page: Page): Promise<A11yNode>;
  };

  screenshot: {
    captureFullPage(page: Page): Promise<Buffer>;
    captureElement(element: Element): Promise<Buffer>;
    captureViewport(page: Page): Promise<Buffer>;
  };

  elementInfo: {
    mmid: string;           // Unique identifier
    tag: string;
    role: string;
    name: string;           // Accessible name
    visible: boolean;
    rect: BoundingBox;
    testId: string | null;
    inShadowDOM: boolean;
    inIframe: boolean;
  };
}
```

**Shadow DOM Extraction:**
```typescript
// The EYES can pierce shadow boundaries
function extractWithShadowPiercing(
  root: Document | ShadowRoot,
  depth: number = 0
): Element[] {
  if (depth > 5) return [];  // Prevent infinite recursion

  const elements: Element[] = [];

  // Standard elements
  root.querySelectorAll(INTERACTIVE_SELECTOR).forEach(el => {
    elements.push(createElementInfo(el, depth));
  });

  // X-RAY VISION: Pierce shadow roots
  root.querySelectorAll('*').forEach(node => {
    if (node.shadowRoot) {
      console.log(`👁️ Piercing shadow DOM of <${node.tagName}>`);
      elements.push(...extractWithShadowPiercing(node.shadowRoot, depth + 1));
    }
  });

  return elements;
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Standard elements found | 100% |
| Shadow DOM elements | 100% |
| Iframe elements | Same-origin 100%, cross-origin flagged |
| Screenshots captured | All pages |
| Element attributes | All relevant extracted |

**Deliverables:**
- [ ] DOM extraction with Shadow DOM support
- [ ] Iframe content extraction
- [ ] Screenshot capture system
- [ ] Accessibility tree extraction
- [ ] Element bounding boxes
- [ ] Element visibility detection

**Why EYES Third:**
> "A body can survive without eyes, but it cannot navigate the world. YaliTest needs to SEE the web page before it can understand or interact with it."

---

## Phase 4: NERVOUS SYSTEM (Coordination)
### *"The wiring that connects and coordinates everything"*

```
┌─────────────────────────────────────────────────────────────┐
│                    NERVOUS SYSTEM                            │
│                                                             │
│  Like the human nervous system:                             │
│  - CONNECTS all organs with signals                        │
│  - PREVENTS harmful actions (reflexes)                     │
│  - REMEMBERS where we've been (state)                      │
│  - COORDINATES complex movements (workflows)               │
│  - Has SYNAPSES (event handlers)                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** HARD (complex state management)
**Criticality:** CRITICAL - prevents crashes and infinite loops

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Navigation Graph | `src/lib/nav-graph.ts` | Track visited pages |
| State Fingerprint | `src/lib/fingerprint.ts` | Detect state changes |
| StateBank | `src/lib/state-bank.ts` | Auth persistence |
| Cycle Detector | `src/lib/cycle-detector.ts` | Prevent loops |
| Event Bus | `src/lib/event-bus.ts` | Component communication |

**Technical Requirements:**
```typescript
// NERVOUS SYSTEM must provide:
interface NervousSystemCapabilities {
  navGraph: {
    addNode(url: string, domHash: string): NavNode;
    addEdge(from: string, to: string, action: Action): void;
    hasVisited(url: string, domHash: string): boolean;
    wouldCreateCycle(from: string, to: string): boolean;
    getUnexploredActions(nodeId: string): Action[];
  };

  stateBank: {
    save(context: BrowserContext, label: string): Promise<string>;
    load(browser: Browser, label: string): Promise<BrowserContext>;
    hasAuth(label: string): boolean;
    clear(): void;
  };

  fingerprint: {
    create(page: Page): Promise<StateFingerprint>;
    compare(a: StateFingerprint, b: StateFingerprint): boolean;
    hasChanged(page: Page, previous: StateFingerprint): Promise<boolean>;
  };

  limits: {
    maxDepth: number;           // 10
    maxPagesPerDomain: number;  // 500
    maxActionsPerPage: number;  // 50
    maxTotalActions: number;    // 5000
    maxTimeMinutes: number;     // 30
  };
}
```

**State Fingerprinting:**
```typescript
// The NERVOUS SYSTEM knows when things change
interface StateFingerprint {
  url: string;
  domHash: string;        // Hash of interactive elements
  activeElement: string;
  modalState: string;     // Open modals
  formState: string;      // Form values
  timestamp: number;
}

function createFingerprint(page: Page): StateFingerprint {
  return {
    url: normalizeUrl(page.url()),
    domHash: xxhash(await extractElements(page)),
    activeElement: await page.evaluate(() => document.activeElement?.id || ''),
    modalState: await detectOpenModals(page),
    formState: await hashFormValues(page),
    timestamp: Date.now()
  };
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Infinite loops prevented | 100% |
| State changes detected | 100% |
| Auth state persists | Across workers |
| Cycle detection | Within 3 hops |
| Memory usage | Constant (no unbounded growth) |

**Deliverables:**
- [ ] Navigation Graph with cycle detection
- [ ] State fingerprinting system
- [ ] StateBank for auth persistence
- [ ] Exploration limits enforcement
- [ ] Event bus for coordination
- [ ] URL normalization

**Why NERVOUS SYSTEM Fourth:**
> "Without a nervous system, the body has no reflexes - it will keep touching fire. Without state management, the crawler will visit the same page forever."

---

## Phase 5: HANDS (Action System)
### *"The appendages that interact with the world"*

```
┌─────────────────────────────────────────────────────────────┐
│                         HANDS                                │
│                                                             │
│  Like human hands:                                          │
│  - Can CLICK (tap fingers)                                 │
│  - Can TYPE (keyboard)                                     │
│  - Can SCROLL (swipe)                                      │
│  - Can DRAG (grab and move)                               │
│  - Has FINE MOTOR CONTROL (precise timing)                │
│  - WAITS appropriately (doesn't rush)                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 1.5 weeks
**Difficulty:** MEDIUM
**Criticality:** HIGH - core interaction capability

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Smart Wait | `src/lib/smart-wait.ts` | Context-aware waiting |
| Action Executor | `src/lib/action-executor.ts` | Click, type, etc. |
| Scroll Handler | `src/lib/scroll.ts` | Infinite scroll, lazy load |
| Form Filler | `src/lib/form-filler.ts` | Smart form interaction |

**Technical Requirements:**
```typescript
// HANDS must provide:
interface HandsCapabilities {
  actions: {
    click(element: Element): Promise<ActionResult>;
    type(element: Element, text: string): Promise<ActionResult>;
    scroll(direction: 'up' | 'down', amount?: number): Promise<void>;
    hover(element: Element): Promise<void>;
    drag(from: Element, to: Element): Promise<ActionResult>;
    select(element: Element, value: string): Promise<ActionResult>;
  };

  smartWait: {
    forNavigation(page: Page): Promise<void>;
    forElement(selector: string): Promise<void>;
    forNetwork(page: Page): Promise<void>;
    forResponse(pattern: string): Promise<void>;
    // NEVER: waitForTimeout() - BANNED
  };

  formFiller: {
    detectFieldType(element: Element): FieldType;
    generateValue(fieldType: FieldType): string;
    fillForm(page: Page, formData: FormData): Promise<void>;
  };
}
```

**Smart Waiting (CRITICAL):**
```typescript
// HANDS never rush - they wait appropriately
// ❌ BANNED: page.waitForTimeout(1000)

async function smartWait(page: Page, action: Action): Promise<void> {
  switch (action.type) {
    case 'navigate':
      // Wait for network to settle
      await page.waitForLoadState('networkidle', { timeout: 15000 })
        .catch(() => page.waitForLoadState('domcontentloaded'));
      break;

    case 'click':
      // Wait for element to be actionable
      await page.locator(action.selector).waitFor({ state: 'visible' });
      break;

    case 'submit':
      // Wait for response (navigation OR error message)
      await Promise.race([
        page.waitForNavigation({ timeout: 10000 }),
        page.waitForSelector('.error, .success, [role="alert"]', { timeout: 5000 })
      ]);
      break;

    default:
      // Wait for any network activity to settle
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  }
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Click success rate | 95%+ |
| Type accuracy | 100% |
| No flaky waits | 0 fixed timeouts |
| Form detection | 90%+ field types |
| Scroll detection | Handles infinite |

**Deliverables:**
- [ ] Smart waiting system (NO fixed timeouts)
- [ ] Click with retry logic
- [ ] Type with clear-first option
- [ ] Scroll with lazy load detection
- [ ] Form field type detection
- [ ] Test data generation per field type

**Why HANDS Fifth:**
> "Eyes can see, but without hands we cannot interact. The action system lets YaliTest touch and manipulate the web page."

---

## Phase 6: LUNGS (Input Breathing)
### *"The organ that breathes in life-giving oxygen"*

```
┌─────────────────────────────────────────────────────────────┐
│                         LUNGS                                │
│                                                             │
│  Like human lungs:                                          │
│  - BREATHES IN oxygen (user inputs)                        │
│  - PROCESSES air (parses config)                           │
│  - DISTRIBUTES to all organs (context)                     │
│  - Without oxygen, brain CAN'T THINK                       │
│  - Better air = better performance                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** MEDIUM
**Criticality:** HIGH - enables 93% accuracy

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Config Parser | `src/lib/config-parser.ts` | yalitest.config.yml |
| Schema Importer | `src/lib/schema-import.ts` | OpenAPI, Zod, etc. |
| Golden Baselines | `src/lib/baselines.ts` | Approved states |
| Runtime Questions | `src/lib/questions.ts` | Ask when unsure |

**Technical Requirements:**
```typescript
// LUNGS must provide:
interface LungsCapabilities {
  configParser: {
    load(path: string): Promise<YaliConfig>;
    validate(config: YaliConfig): ValidationResult;
    getFlows(): Flow[];
    getSecurityContext(): SecurityContext;
    getValidationRules(): ValidationRule[];
  };

  schemaImporter: {
    fromOpenAPI(url: string): Promise<ValidationSchema>;
    fromZod(path: string): Promise<ValidationSchema>;
    fromTypeScript(path: string): Promise<ValidationSchema>;
    fromJSONSchema(path: string): Promise<ValidationSchema>;
  };

  baselines: {
    capture(page: Page, name: string): Promise<Baseline>;
    compare(page: Page, baseline: Baseline): Promise<ComparisonResult>;
    approve(baseline: Baseline): Promise<void>;
    reject(baseline: Baseline, reason: string): Promise<void>;
  };

  questions: {
    ask(question: Question): Promise<Answer>;
    askInApp(question: Question): Promise<Answer>;
    askViaSlack(question: Question): Promise<Answer>;
    timeout: number;  // 5 minutes default
  };
}
```

**Config File Structure:**
```yaml
# yalitest.config.yml - The oxygen we breathe
app:
  name: "My App"
  type: ecommerce
  baseUrl: "https://staging.myapp.com"

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

security:
  auth_type: jwt
  roles:
    - name: admin
      can_access: ["/admin/*"]
    - name: user
      can_access: ["/profile"]

validation:
  email:
    pattern: "^[a-z]+@[a-z]+\\.[a-z]+$"
  age:
    min: 18
    max: 120
```

**Accuracy Impact:**
| Input Type | Without | With | Boost |
|------------|---------|------|-------|
| Config file | 80% | 95% | +15% |
| Schema import | 70% | 92% | +22% |
| Golden baselines | 70% | 92% | +22% |

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Config parsing | 100% valid configs |
| Schema import | All 4 formats |
| Baseline capture | With screenshots |
| Question timeout | 5 min default |

**Deliverables:**
- [ ] YAML config parser
- [ ] OpenAPI schema importer
- [ ] Zod schema importer
- [ ] TypeScript type extractor
- [ ] Baseline capture system
- [ ] In-app question prompts

**Why LUNGS Sixth:**
> "The brain cannot think without oxygen. The AI cannot achieve 93% accuracy without the right inputs. LUNGS breathe in the context that makes intelligence possible."

---

## Phase 7: BRAIN (Intelligence)
### *"The command center that thinks and decides"*

```
┌─────────────────────────────────────────────────────────────┐
│                         BRAIN                                │
│                                                             │
│  Like the human brain:                                      │
│  - THINKS about what to do                                 │
│  - DECIDES priority and strategy                           │
│  - Has REGIONS for different tasks                         │
│  - Uses different ENERGY levels (model costs)              │
│  - LEARNS from experience                                   │
│  - ASKS when confused (not guess)                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 3 weeks
**Difficulty:** HARD (AI integration complexity)
**Criticality:** CRITICAL - the intelligence layer

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| LLM Router | `src/lib/llm-router.ts` | Multi-model routing |
| Classifier | `src/lib/classifier.ts` | Element classification |
| Flow Detector | `src/lib/flow-detector.ts` | Multi-step flows |
| Prompt Cache | `src/lib/prompt-cache.ts` | Token optimization |
| RAG System | `src/lib/rag.ts` | Large app context |

**Technical Requirements:**
```typescript
// BRAIN must provide:
interface BrainCapabilities {
  llmRouter: {
    cheap: Model;   // DeepSeek - $0.028/MTok
    medium: Model;  // GPT-4o-mini - $0.15/MTok
    smart: Model;   // GPT-4o/Sonnet - $2.50-3.00/MTok
    route(task: Task): Model;
    complete(model: Model, prompt: string): Promise<string>;
  };

  classifier: {
    classify(element: Element, context: PageContext): Promise<Classification>;
    categories: ['navigation', 'read', 'write', 'destructive', 'payment'];
    confidence: number;  // 0-1
    askIfUnsure: boolean;
  };

  flowDetector: {
    detectFlows(pages: Page[]): Promise<Flow[]>;
    flowTypes: ['login', 'signup', 'checkout', 'search', 'crud'];
  };

  rag: {
    index(pages: PageInfo[]): Promise<void>;
    retrieve(query: string, k: number): Promise<PageInfo[]>;
  };
}
```

**Multi-Model Routing:**
```typescript
// BRAIN uses different energy levels for different tasks
const MODELS = {
  cheap: {
    provider: 'deepseek',
    model: 'deepseek-chat',
    cost: 0.028,
    use: ['classify', 'route', 'decide']
  },
  medium: {
    provider: 'openai',
    model: 'gpt-4o-mini',
    cost: 0.15,
    use: ['flow-detect', 'summarize', 'analyze']
  },
  smart: {
    provider: 'openai',
    model: 'gpt-4o',
    cost: 2.50,
    use: ['generate-tests', 'fix-errors', 'complex-reasoning']
  }
};

function routeTask(task: string): Model {
  if (['classify', 'route', 'decide'].includes(task)) return MODELS.cheap;
  if (['flow-detect', 'summarize'].includes(task)) return MODELS.medium;
  return MODELS.smart;
}
```

**Classification with Confidence:**
```typescript
// BRAIN knows when it doesn't know
async function classifyElement(element: Element): Promise<Classification> {
  // Rule-based first (fast, free)
  const ruleResult = classifyByRules(element);
  if (ruleResult.confidence > 0.9) return ruleResult;

  // LLM for ambiguous (cheap)
  const llmResult = await llmClassify(element);

  // If still unsure, ASK (never guess)
  if (llmResult.confidence < 0.8) {
    const answer = await askViaSlack({
      message: `What type of action is "${element.name}"?`,
      options: ['navigation', 'write', 'destructive', 'payment', 'skip']
    });
    return { category: answer, confidence: 1.0, source: 'human' };
  }

  return llmResult;
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Classification accuracy | 95%+ |
| LLM cost per 100 pages | <$2.00 |
| Prompt cache hit rate | 80%+ |
| Flow detection | 95%+ with config |
| Decision latency | <2s average |

**Deliverables:**
- [ ] Multi-model LLM router
- [ ] Rule-based + LLM classifier
- [ ] Flow detection system
- [ ] Prompt caching (provider + local)
- [ ] RAG for large apps
- [ ] Confidence-based "ask" trigger

**Why BRAIN Seventh:**
> "The brain needs eyes to see, hands to act, and oxygen to think. Without the previous phases, the AI would be blind, paralyzed, and suffocating."

---

## Phase 8: STOMACH (Test Digestion)
### *"The organ that transforms food into energy"*

```
┌─────────────────────────────────────────────────────────────┐
│                        STOMACH                               │
│                                                             │
│  Like the human stomach:                                    │
│  - Takes in RAW MATERIAL (elements, flows)                 │
│  - BREAKS DOWN into components                             │
│  - TRANSFORMS into usable form (test code)                 │
│  - Different ENZYMES for different food (3 mindsets)       │
│  - VALIDATES before passing along (dry-run)                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2.5 weeks
**Difficulty:** HARD (code generation complexity)
**Criticality:** CRITICAL - the main output

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Test Generator | `src/lib/test-generator.ts` | Code generation |
| Three Mindsets | `src/prompts/*.md` | Normal/Curious/Malicious |
| Dry Runner | `src/lib/dry-runner.ts` | Test validation |
| Output Formatter | `src/lib/formatter.ts` | Playwright/Cypress |

**Technical Requirements:**
```typescript
// STOMACH must provide:
interface StomachCapabilities {
  testGenerator: {
    generate(flow: Flow, mindset: Mindset): Promise<TestCase>;
    mindsets: ['normal', 'curious', 'malicious'];
    outputFormat: ['playwright', 'cypress'];
  };

  dryRunner: {
    run(test: TestCase): Promise<DryRunResult>;
    tracingEnabled: boolean;  // Always true
    result: {
      passed: boolean;
      errors: string[];
      traceFile: string;
      screenshot: string;
    };
  };

  outputClassifier: {
    verified: TestCase[];    // Passed dry-run
    drafts: TestCase[];      // Failed, has trace
    skipped: Element[];      // Could not generate
  };
}
```

**Three Mindsets (Enzymes):**
```typescript
// Different enzymes digest food differently
const MINDSETS = {
  normal: {
    // Happy path - test what should work
    prompts: 'Generate tests for normal user behavior',
    examples: ['valid login', 'successful checkout', 'profile update']
  },
  curious: {
    // Edge cases - test boundaries
    prompts: 'Generate tests for edge cases and boundaries',
    examples: ['empty inputs', 'max length', 'special characters', '-1']
  },
  malicious: {
    // Security - test attacks
    prompts: 'Generate tests for security vulnerabilities',
    examples: ['SQL injection', 'XSS', 'auth bypass', 'CSRF']
  }
};

async function generateTestSuite(flow: Flow): Promise<TestSuite> {
  const tests: TestCase[] = [];

  for (const mindset of ['normal', 'curious', 'malicious']) {
    const test = await generator.generate(flow, mindset);
    tests.push(test);
  }

  return { tests, mindsets: 3 };
}
```

**Dry-Run Validation:**
```typescript
// STOMACH validates before passing along
async function dryRunTest(test: TestCase): Promise<DryRunResult> {
  const context = await browser.newContext();

  // Always trace
  await context.tracing.start({
    screenshots: true,
    snapshots: true,
    sources: true
  });

  const page = await context.newPage();

  try {
    await runTestCode(page, test.code);
    await context.tracing.stop({ path: `./traces/${test.name}-passed.zip` });
    return { passed: true, verified: true };
  } catch (error) {
    const tracePath = `./traces/${test.name}-FAILED.zip`;
    await context.tracing.stop({ path: tracePath });
    return {
      passed: false,
      errors: [error.message],
      traceFile: tracePath,
      screenshot: await page.screenshot()
    };
  }
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Tests generated per flow | 3 (one per mindset) |
| Dry-run pass rate | 80%+ |
| All failures have traces | 100% |
| Output formats | Playwright + Cypress |

**Deliverables:**
- [ ] Test generator with 3 mindsets
- [ ] Prompt templates for each mindset
- [ ] Dry-run validation system
- [ ] Trace capture for all tests
- [ ] Playwright output format
- [ ] Cypress output format
- [ ] Verified vs Draft classification

**Why STOMACH Eighth:**
> "The stomach receives food (data) and transforms it into energy (tests). Without digestion, we have raw ingredients but no usable output."

---

## Phase 9: IMMUNE SYSTEM (Self-Healing)
### *"The defense that keeps the organism healthy"*

```
┌─────────────────────────────────────────────────────────────┐
│                     IMMUNE SYSTEM                            │
│                                                             │
│  Like the human immune system:                              │
│  - DETECTS problems (broken selectors)                     │
│  - HEALS automatically when possible                       │
│  - ESCALATES to specialists (humans) when needed           │
│  - LEARNS from past infections (patterns)                  │
│  - NEVER says "unknown virus" (always explains)            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** HARD (requires AI + state comparison)
**Criticality:** HIGH - prevents test rot

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Self Healer | `src/lib/self-healer.ts` | AI-powered healing |
| Error Analyzer | `src/lib/error-analyzer.ts` | Failure classification |
| Visual Diff | `src/lib/visual-diff.ts` | Screenshot comparison |
| Explanation Engine | `src/lib/explainer.ts` | Human-readable errors |

**Technical Requirements:**
```typescript
// IMMUNE SYSTEM must provide:
interface ImmuneSystemCapabilities {
  selfHealer: {
    heal(context: HealContext): Promise<HealResult>;
    strategies: ['ai-analysis', 'human-confirm', 'skip'];
    confidenceThreshold: number;  // 0.9 for auto, 0.6 for ask
  };

  errorAnalyzer: {
    classify(error: Error): ErrorType;
    types: [
      'element_not_found', 'element_moved', 'timeout',
      'navigation_failed', 'auth_expired', 'captcha_detected'
    ];
  };

  visualDiff: {
    compare(current: Buffer, baseline: Buffer): Promise<VisualDiff>;
    threshold: number;  // % change
  };

  explainer: {
    explain(failure: Failure): Promise<Explanation>;
    // NEVER returns "Unknown error"
    suggestedFix: string;
  };
}
```

**Self-Healing Flow:**
```typescript
// IMMUNE SYSTEM heals or escalates
async function selfHeal(context: HealContext): Promise<HealResult> {
  // 1. AI analyzes the change
  const analysis = await llm.analyze({
    previousScreenshot: context.previous,
    currentScreenshot: context.current,
    failedSelector: context.selector,
    question: 'What happened to this element?'
  });

  // 2. High confidence → Auto-heal
  if (analysis.confidence > 0.9) {
    return {
      success: true,
      newSelector: analysis.suggestion,
      method: 'ai-healed'
    };
  }

  // 3. Medium confidence → Ask human
  if (analysis.confidence > 0.6) {
    const answer = await askViaSlack({
      message: 'Test self-healing needed',
      options: ['Use AI suggestion', 'Custom selector', 'It\'s a bug']
    });
    return handleHumanAnswer(answer);
  }

  // 4. Low confidence → Skip and flag
  return {
    success: false,
    method: 'skipped',
    reason: 'Confidence too low, added to review queue'
  };
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Auto-heal success | 95%+ (with inputs) |
| Failures explained | 100% (never unknown) |
| Human escalation | Only when confidence <0.6 |
| Visual diff accuracy | 99%+ |

**Deliverables:**
- [ ] AI-powered selector healing
- [ ] Screenshot + DOM comparison
- [ ] Error classification system
- [ ] Human-readable explanations
- [ ] Slack escalation integration
- [ ] "Never unknown error" guarantee

**Why IMMUNE SYSTEM Ninth:**
> "A body without an immune system will die from the first infection. Tests without self-healing will rot and become useless. The immune system keeps YaliTest alive."

---

## Phase 10: LIVER (Cleanup System)
### *"The filter that removes toxins"*

```
┌─────────────────────────────────────────────────────────────┐
│                         LIVER                                │
│                                                             │
│  Like the human liver:                                      │
│  - FILTERS out toxins (test data)                          │
│  - PROCESSES waste (cleanup jobs)                          │
│  - Runs CONTINUOUSLY in background                         │
│  - Without it, body gets POISONED (DB pollution)           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 1 week
**Difficulty:** EASY
**Criticality:** MEDIUM (but prevents long-term poisoning)

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Test Data Cleanup | `src/lib/cleanup-job.ts` | Remove junk data |
| Prefix Manager | `src/lib/prefix.ts` | Tag test data |
| Cleanup Dashboard | `src/components/Cleanup.tsx` | Status UI |

**Technical Requirements:**
```typescript
// LIVER must provide:
interface LiverCapabilities {
  cleanup: {
    prefix: string;          // 'yali_auto_'
    maxAgeMinutes: number;   // 60 default
    strategy: 'api_delete' | 'db_truncate';
    run(): Promise<CleanupResult>;
    schedule(cron: string): void;  // '0 * * * *' hourly
  };

  prefix: {
    tag(data: any): any;     // Add prefix to identifiers
    isTagged(value: string): boolean;
    extractTimestamp(value: string): number;
  };
}
```

**Implementation:**
```typescript
// LIVER filters out test data toxins
const TEST_DATA_PREFIX = 'yali_auto_';

function generateTestUser(): TestUser {
  return {
    email: `${TEST_DATA_PREFIX}${Date.now()}@example.com`,
    username: `${TEST_DATA_PREFIX}user_${Date.now()}`
  };
}

async function cleanupTestData(): Promise<CleanupResult> {
  const cutoff = Date.now() - (60 * 60 * 1000);  // 1 hour

  // Find and delete test users
  const users = await api.get(`/admin/users?prefix=${TEST_DATA_PREFIX}`);
  for (const user of users) {
    if (new Date(user.created_at).getTime() < cutoff) {
      await api.delete(`/admin/users/${user.id}`);
    }
  }

  return { deleted: users.length };
}

// Run hourly
cron.schedule('0 * * * *', cleanupTestData);
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| All test data prefixed | 100% |
| Cleanup runs | Hourly |
| Old data removed | Within 1 hour |
| No DB pollution | 0 orphaned records |

**Deliverables:**
- [ ] Test data prefix system
- [ ] Cleanup job (API-based)
- [ ] Scheduled execution (hourly)
- [ ] Cleanup dashboard in UI
- [ ] Manual cleanup button

**Why LIVER Tenth:**
> "Without a liver, toxins accumulate and poison the body. Without cleanup, test data accumulates and poisons the database. The liver keeps the system clean."

---

## Phase 11: SKIN (Security Layer)
### *"The protective barrier against the outside world"*

```
┌─────────────────────────────────────────────────────────────┐
│                          SKIN                                │
│                                                             │
│  Like human skin:                                           │
│  - PROTECTS internal organs from external threats          │
│  - BARRIER between inside and outside                      │
│  - SENSITIVE to touch (credential handling)                │
│  - HEALS from minor wounds (anti-bot recovery)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 1.5 weeks
**Difficulty:** MEDIUM
**Criticality:** HIGH (security is non-negotiable)

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Credential Manager | `src/lib/credential-manager.ts` | OS Keychain |
| Trust Statement | `src/components/Trust.tsx` | Security UI |
| Secure Input | `src/components/SecureInput.tsx` | Password entry |

**Technical Requirements:**
```typescript
// SKIN must provide:
interface SkinCapabilities {
  credentials: {
    save(domain: string, username: string, password: string): Promise<void>;
    get(domain: string, username: string): Promise<string | null>;
    delete(domain: string, username: string): Promise<void>;
    list(): Promise<Credential[]>;
    // Uses OS Keychain - NEVER stores in files
  };

  secureInput: {
    showDialog(): Promise<{ username: string; password: string }>;
    // Password never stored in app state
    // Cleared from memory after use
  };
}
```

**OS Keychain Integration:**
```typescript
import * as keytar from 'keytar';

const SERVICE_NAME = 'YaliTest';

class CredentialManager {
  async save(domain: string, username: string, password: string): Promise<void> {
    const key = `${domain}:${username}`;
    await keytar.setPassword(SERVICE_NAME, key, password);
    // Password now in OS Keychain, not our files
  }

  async get(domain: string, username: string): Promise<string | null> {
    const key = `${domain}:${username}`;
    return keytar.getPassword(SERVICE_NAME, key);
  }
}
```

**Trust Statement:**
```typescript
// Show this in UI
const TRUST_STATEMENT = `
🔒 Your credentials are secure:
• Stored in your OS keychain (not in YaliTest files)
• Never sent to our servers
• Encrypted by your operating system
• Cleared from memory after use
• You can delete them anytime from OS settings
`;
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Credentials in keychain | 100% |
| Passwords in memory | 0 (after use) |
| Passwords in files | 0 |
| Passwords in logs | 0 |

**Deliverables:**
- [ ] OS Keychain integration (keytar)
- [ ] Secure credential dialog
- [ ] Trust statement UI
- [ ] Auto-fill login form
- [ ] Credential deletion

**Why SKIN Eleventh:**
> "Skin is the last line of defense - without it, any bacteria can invade. Credentials are sensitive - without proper protection, they leak everywhere."

---

## Phase 12: MEMORY (Learning Engine)
### *"The system that learns from experience"*

```
┌─────────────────────────────────────────────────────────────┐
│                        MEMORY                                │
│                                                             │
│  Like human memory:                                         │
│  - REMEMBERS past experiences (corrections)                │
│  - RECOGNIZES patterns (repeated corrections)              │
│  - BUILDS rules (3+ same correction = rule)               │
│  - Gets SMARTER over time                                  │
│  - FORGETS irrelevant (prunes old rules)                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** MEDIUM
**Criticality:** HIGH (enables continuous improvement)

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Learning Engine | `src/lib/learning-engine.ts` | Pattern learning |
| Correction Store | `src/lib/corrections.ts` | Store corrections |
| Rule Builder | `src/lib/rules.ts` | Create rules |

**Technical Requirements:**
```typescript
// MEMORY must provide:
interface MemoryCapabilities {
  corrections: {
    record(correction: Correction): Promise<void>;
    similar(pattern: string): Correction[];
    count: number;
  };

  rules: {
    create(pattern: string, result: string): Rule;
    match(context: any): Rule | null;
    threshold: number;  // 3 similar = rule
  };

  learning: {
    checkBeforeAI(context: any): string | null;  // Use rule if exists
    improveFromCorrection(correction: Correction): void;
    exportRules(): Rule[];
    importRules(rules: Rule[]): void;
  };
}
```

**Learning Flow:**
```typescript
// MEMORY learns from corrections
class LearningEngine {
  private corrections: Correction[] = [];
  private rules: Map<string, string> = new Map();

  async record(correction: Correction): Promise<void> {
    this.corrections.push(correction);

    // If 3+ similar corrections, create a rule
    const similar = this.corrections.filter(c =>
      c.pattern === correction.pattern &&
      c.humanSaid === correction.humanSaid
    );

    if (similar.length >= 3) {
      this.rules.set(correction.pattern, correction.humanSaid);
      console.log(`📚 Learned: ${correction.pattern} → ${correction.humanSaid}`);
    }
  }

  // Check learned rules BEFORE asking AI
  checkRules(context: any): string | null {
    const pattern = extractPattern(context);
    return this.rules.get(pattern) || null;
  }
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Corrections recorded | 100% |
| Rules created | After 3 similar |
| Rule reuse rate | Track % |
| Memory growth | Bounded |

**Deliverables:**
- [ ] Correction recording
- [ ] Pattern extraction
- [ ] Rule creation (3+ threshold)
- [ ] Rule matching before AI
- [ ] Rule export/import
- [ ] Learning dashboard

**Why MEMORY Twelfth:**
> "Without memory, we make the same mistakes forever. The learning engine ensures YaliTest gets smarter with every correction, never repeating the same error."

---

## Phase 13: VOICE (Communication)
### *"The mouth that speaks to the outside world"*

```
┌─────────────────────────────────────────────────────────────┐
│                         VOICE                                │
│                                                             │
│  Like the human voice:                                      │
│  - SPEAKS to humans (reports, questions)                   │
│  - LISTENS to responses (Slack answers)                    │
│  - EXPLAINS clearly (not jargon)                           │
│  - ASKS when unsure (doesn't mumble)                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 2 weeks
**Difficulty:** MEDIUM
**Criticality:** HIGH (human-in-the-loop)

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| Slack Bot | `src/lib/slack-bot.ts` | Slack integration |
| Question Queue | `src/lib/question-queue.ts` | Pending questions |
| Labeling UI | `src/components/Labeling.tsx` | In-app labeling |
| Report Generator | `src/lib/reports.ts` | Test reports |

**Technical Requirements:**
```typescript
// VOICE must provide:
interface VoiceCapabilities {
  slack: {
    ask(question: Question): Promise<Answer>;
    notify(message: string): Promise<void>;
    sendReport(report: Report): Promise<void>;
    timeout: number;  // 5 minutes
  };

  inApp: {
    showQuestion(question: Question): Promise<Answer>;
    showLabeling(element: Element): Promise<Label>;
    showConfirmation(action: Action): Promise<boolean>;
  };

  reports: {
    generate(results: TestResults): Report;
    formats: ['html', 'json', 'markdown'];
    sendTo: ['slack', 'email', 'jira'];
  };
}
```

**Slack Integration:**
```typescript
import { App } from '@slack/bolt';

const slackApp = new App({
  token: process.env.SLACK_BOT_TOKEN,
  appToken: process.env.SLACK_APP_TOKEN,
  socketMode: true
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

  // Wait for response (5 min timeout)
  return waitForAnswer(question.id, 5 * 60 * 1000);
}
```

**Success Criteria:**
| Metric | Target |
|--------|--------|
| Slack messages sent | 100% delivery |
| Response wait | 5 min timeout |
| In-app questions | Blocking UI |
| Report generation | All formats |

**Deliverables:**
- [ ] Slack bot setup
- [ ] Question sending/receiving
- [ ] In-app question UI
- [ ] Human labeling queue
- [ ] Report generator
- [ ] Email notifications (optional)

**Why VOICE Thirteenth:**
> "A body without a voice cannot ask for help or communicate needs. YaliTest needs to speak to humans when it's unsure and report its findings clearly."

---

## Phase 14: SOUL (Launch Polish)
### *"The final spark that brings it all to life"*

```
┌─────────────────────────────────────────────────────────────┐
│                          SOUL                                │
│                                                             │
│  Like the human soul:                                       │
│  - The SPARK that makes it alive                           │
│  - INTEGRATES all organs into one being                    │
│  - The IDENTITY and personality                            │
│  - Makes the whole GREATER than parts                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Duration:** 1.5 weeks
**Difficulty:** EASY (but important)
**Criticality:** HIGH (launch readiness)

**What We Build:**
| Component | File | Purpose |
|-----------|------|---------|
| CI/CD Integration | `.github/workflows/*` | GitHub Actions |
| Documentation | `docs/*` | User guides |
| Onboarding | `src/components/Onboarding.tsx` | First-run experience |
| Cost Dashboard | `src/components/Costs.tsx` | Usage transparency |

**Deliverables:**
- [ ] GitHub Actions integration
- [ ] GitLab CI support
- [ ] User documentation
- [ ] First-run onboarding wizard
- [ ] Cost transparency dashboard
- [ ] Progress UI polish
- [ ] Error handling polish
- [ ] Performance optimization

**Why SOUL Last:**
> "The soul is what makes a collection of organs into a living being. The final polish is what makes a collection of features into a product."

---

# Summary: The Complete Organism

```
┌─────────────────────────────────────────────────────────────┐
│                  THE YALITEST ORGANISM                       │
│                                                             │
│  Phase 1:  SKELETON    - Foundation (1 week)    [CRITICAL] │
│  Phase 2:  HEART       - Browser Engine (2 wk)  [CRITICAL] │
│  Phase 3:  EYES        - Vision (2 weeks)       [CRITICAL] │
│  Phase 4:  NERVOUS     - Coordination (2 wk)    [CRITICAL] │
│  Phase 5:  HANDS       - Actions (1.5 weeks)    [HIGH]     │
│  Phase 6:  LUNGS       - Inputs (2 weeks)       [HIGH]     │
│  Phase 7:  BRAIN       - Intelligence (3 wk)    [CRITICAL] │
│  Phase 8:  STOMACH     - Generation (2.5 wk)    [CRITICAL] │
│  Phase 9:  IMMUNE      - Self-Healing (2 wk)    [HIGH]     │
│  Phase 10: LIVER       - Cleanup (1 week)       [MEDIUM]   │
│  Phase 11: SKIN        - Security (1.5 weeks)   [HIGH]     │
│  Phase 12: MEMORY      - Learning (2 weeks)     [HIGH]     │
│  Phase 13: VOICE       - Communication (2 wk)   [HIGH]     │
│  Phase 14: SOUL        - Polish (1.5 weeks)     [HIGH]     │
│                                                             │
│  TOTAL: ~24 weeks (6 months)                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Critical Path

The following phases are on the critical path - delays here delay everything:

1. **SKELETON** → 2. **HEART** → 3. **EYES** → 4. **NERVOUS** → 7. **BRAIN** → 8. **STOMACH**

## Parallel Opportunities

After NERVOUS SYSTEM, some phases can run in parallel:
- HANDS + LUNGS (both depend on NERVOUS, independent of each other)
- LIVER + SKIN (both are protective, can parallelize)
- MEMORY + VOICE (both are enhancement, can parallelize)

## The Living Test

When all phases are complete, YaliTest will be a **living organism** that:
- **SEES** web pages (EYES)
- **THINKS** about what it sees (BRAIN)
- **ACTS** on decisions (HANDS)
- **HEALS** when things break (IMMUNE)
- **LEARNS** from mistakes (MEMORY)
- **SPEAKS** to humans (VOICE)
- **PROTECTS** its secrets (SKIN)
- **CLEANS** up after itself (LIVER)

**A complete QA testing organism, alive and autonomous.**
