# YaliTest: Complete Strategy & Implementation Plan

## Executive Summary

Build an autonomous QA testing platform that replaces 100 QA engineers in 30 minutes by combining intelligent web crawling, AI-powered test generation, and multi-agent orchestration. Target: 100% profit margin through smart model routing and DOM distillation.

---

# Part 1: Competitor Deep Analysis

## Pricing Comparison Table

| Tool | Pricing | AI Features | Autonomous | Key Weakness |
|------|---------|-------------|------------|--------------|
| **Mabl** | $499-2000+/mo | Auto-heal, GenAI Assertions | No | Manual test creation required |
| **Testim/Tricentis** | $450-1500+/mo | Smart Locators, Copilot | No | Complex pricing, learning curve |
| **Katalon** | $0-229+/mo/user | Self-healing, AI suggestions | No | Groovy lock-in, desktop-only |
| **Rainforest QA** | $8K+/mo avg | AI coverage gaps, NL tests | Partial | Extremely expensive |
| **Ghost Inspector** | $109-500/mo | None | No | Tests break frequently |
| **LambdaTest** | $100-400/mo | None (infrastructure only) | No | No test creation |
| **Skyvern** | Open source/Cloud | Vision-LLM, Visual reasoning | Partial | Task-specific, not QA-focused |
| **Agent-E** | Open source | DOM Distillation | Partial | Research project, not product |

## Critical Insight: The Gap in the Market

**Every competitor requires manual test definition.** Even "AI-powered" tools like Mabl, Testim, and Rainforest need humans to:
1. Record tests manually, OR
2. Write test scripts, OR
3. Define what to test in natural language

**YaliTest's Differentiator:** Zero-input autonomous discovery + test generation.

---

# Part 2: AI Model Pricing Analysis

## Cost Per Million Tokens (2025)

| Provider | Model | Input | Output | Best For |
|----------|-------|-------|--------|----------|
| **DeepSeek** | V3.2-Exp | $0.028 (cache) / $0.28 | $0.42 | **Cheapest - Use for decisions** |
| **Gemini** | 2.5 Flash-Lite | $0.10 | $0.40 | Fast, cheap classification |
| **OpenAI** | GPT-4o-mini | $0.15 | $0.60 | Good balance |
| **Gemini** | 2.5 Flash | $0.15 | $3.50 | Good for reasoning |
| **Claude** | Haiku 3 | $0.25 | $1.25 | Fast responses |
| **OpenAI** | GPT-4o | $2.50 | $10.00 | Complex generation |
| **Claude** | Sonnet 4 | $3.00 | $15.00 | Complex generation |
| **Gemini** | 3 Pro | $2.00 | $12.00 | High quality |
| **Claude** | Opus 4.5 | $5.00 | $25.00 | Best quality (avoid unless needed) |

## Cost Optimization Strategy

### Multi-Model Routing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Task Classification                       │
│              (DeepSeek V3.2 - $0.028/MTok)                  │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Simple      │    │   Medium      │    │   Complex     │
│   Decisions   │    │   Analysis    │    │   Generation  │
│               │    │               │    │               │
│ DeepSeek/     │    │ Gemini Flash  │    │ GPT-4o or     │
│ Flash-Lite    │    │ or Haiku 3    │    │ Sonnet 4      │
│ $0.028-0.10   │    │ $0.15-0.25    │    │ $2.50-3.00    │
└───────────────┘    └───────────────┘    └───────────────┘
```

### Token Estimation Per Page

| Operation | Tokens (Raw HTML) | Tokens (Distilled) | Savings |
|-----------|-------------------|--------------------| --------|
| Page HTML | 50,000-100,000 | 2,000-5,000 | 95% |
| Element Classification | 5,000 | 500 | 90% |
| Test Generation | 3,000 | 800 | 73% |
| **Total Per Page** | **58,000-108,000** | **3,300-6,300** | **94%** |

---

# Part 3: Cost Calculation for 100% Margin

## Per-Page Cost Breakdown (Distilled DOM)

### Scenario: 100-Page Application

| Operation | Model | Tokens | Cost |
|-----------|-------|--------|------|
| DOM Extraction | N/A (local) | 0 | $0.00 |
| Element Classification (100 pages) | DeepSeek | 50K input, 10K output | $0.018 |
| Action Prioritization (100 pages) | DeepSeek | 20K input, 5K output | $0.008 |
| User Flow Detection | Gemini Flash | 30K input, 10K output | $0.040 |
| Test Case Generation (Normal) | GPT-4o | 100K input, 50K output | $0.75 |
| Test Case Generation (Edge) | GPT-4o | 50K input, 30K output | $0.43 |
| Test Case Generation (Security) | Sonnet 4 | 50K input, 20K output | $0.45 |
| **TOTAL COST** | | | **$1.70** |

### For 1000-Action Complex Page

| Operation | Model | Tokens | Cost |
|-----------|-------|--------|------|
| DOM Distillation | N/A (local) | 0 | $0.00 |
| Classification (1000 elements) | DeepSeek | 100K input, 20K output | $0.037 |
| Prioritization | DeepSeek | 30K input, 10K output | $0.013 |
| Flow Detection | Gemini Flash | 50K input, 20K output | $0.078 |
| Test Generation (All mindsets) | GPT-4o/Sonnet | 200K input, 100K output | $1.75 |
| **TOTAL COST** | | | **$1.88** |

## Pricing for 100% Margin

### Credit System Design

| Credit Type | Description | Cost to Us | Sell At | Margin |
|-------------|-------------|------------|---------|--------|
| 1 Page Credit (DOM) | Simple page extraction | $0.02 | $0.20 | 900% |
| 1 Page Credit (Vision) | With screenshot analysis | $0.05 | $0.50 | 900% |
| 1 Test Suite Gen | 50 test cases | $0.50 | $5.00 | 900% |
| 1 API Test | Single endpoint test | $0.01 | $0.10 | 900% |

### Subscription Tiers

| Tier | Monthly Price | Credits | Cost to Us | Profit | Margin |
|------|---------------|---------|------------|--------|--------|
| **Starter** | $99 | 2,000 | $20 | $79 | 80% |
| **Professional** | $299 | 8,000 | $60 | $239 | 80% |
| **Business** | $599 | 20,000 | $120 | $479 | 80% |
| **Enterprise** | $1,499 | 60,000 | $300 | $1,199 | 80% |

### Pay-As-You-Go

| Item | Price | Our Cost | Margin |
|------|-------|----------|--------|
| Per Page (DOM) | $0.25 | $0.02 | 92% |
| Per Page (Vision) | $0.75 | $0.08 | 89% |
| Per Test Suite | $7.50 | $0.75 | 90% |
| Per API Test | $0.15 | $0.015 | 90% |

---

# Part 4: Features to Build

## Phase 1: Core Autonomous Engine (MVP)

### 1.1 Intelligent Web Crawler
- **DOM Distillation Engine**: Extract only interactive elements (95% token reduction)
- **Smart Navigation Queue**: Parallel exploration with 5-10 browser contexts
- **Deduplication System**: URL normalization, element signature hashing
- **Infinite Scroll Handler**: Auto-scroll to load dynamic content
- **SPA Detection**: Handle client-side routing

### 1.2 Element Classification System
- **Category Detection**: Navigation, Read, Write, Destructive, Payment
- **Confidence Scoring**: Based on text, attributes, position, context
- **Page Context Awareness**: Settings, Profile, Auth, Checkout, Dashboard
- **Form Field Type Detection**: Email, Password, Phone, CC, CVV, Search

### 1.3 Basic Automation
- **Click All Elements**: Sequential with wait and re-extraction
- **Form Filling**: Smart test data based on field type
- **Screenshot Capture**: Before/after each action
- **Error Recovery**: Retry failed actions, skip broken elements

## Phase 2: AI-Powered Intelligence

### 2.1 Multi-Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                        │
│            (Coordinates all other agents)                    │
└─────────────────────────────────────────────────────────────┘
        │           │           │           │           │
        ▼           ▼           ▼           ▼           ▼
┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐
│ Explorer  │ │ Classifier│ │ Tester    │ │ Security  │ │ Reporter  │
│ Agent     │ │ Agent     │ │ Agent     │ │ Agent     │ │ Agent     │
│           │ │           │ │           │ │           │ │           │
│ Discovers │ │ Categorize│ │ Generate  │ │ Generate  │ │ Create    │
│ pages and │ │ elements  │ │ test      │ │ security  │ │ reports & │
│ elements  │ │ and flows │ │ cases     │ │ tests     │ │ summaries │
└───────────┘ └───────────┘ └───────────┘ └───────────┘ └───────────┘
```

### 2.2 Three-Mindset Test Generation

**Normal User Agent:**
- Happy path tests
- Common user flows
- Positive assertions

**Curious User Agent:**
- Empty inputs
- Boundary values (0, -1, MAX_INT)
- Special characters
- Very long strings
- Rapid clicks

**Malicious User Agent:**
- SQL Injection patterns
- XSS payloads
- Auth bypass attempts
- CSRF tests
- Directory traversal

### 2.3 User Flow Detection
- **Login Flow**: Detect auth pages, remember credentials
- **Signup Flow**: Multi-step registration
- **Checkout Flow**: Cart → Address → Payment → Confirm
- **Search Flow**: Query → Results → Filters → Sort
- **CRUD Flow**: Create → Read → Update → Delete

## Phase 3: Advanced Features

### 3.1 Vision-Based Testing
- Screenshot analysis for canvas elements
- Icon/image recognition without labels
- Visual regression detection
- Layout validation

### 3.2 API Discovery & Testing
- Network request monitoring
- Endpoint extraction (REST/GraphQL)
- Request/response capture
- Auto-generate API tests

### 3.3 Parallel Execution Engine
- Multi-tab browser pool (10-50 tabs)
- Isolated browser contexts for write operations
- Smart queue management
- Progress tracking and ETA

### 3.4 Self-Healing Tests
- Multiple selector strategies
- Confidence-based fallback
- Auto-update broken locators
- Human-in-the-loop for low confidence

## Phase 4: Enterprise Features

### 4.1 CI/CD Integration
- GitHub Actions
- GitLab CI
- Jenkins
- CircleCI
- Azure DevOps

### 4.2 Reporting & Analytics
- Application DNA graph visualization
- Coverage metrics
- Trend analysis
- Export to Jira, TestRail

### 4.3 Team Collaboration
- Shared projects
- Role-based access
- Audit logs
- SSO integration

---

# Part 5: Open Source Tools & Libraries

## Browser Automation Layer

| Tool | Purpose | Why |
|------|---------|-----|
| **Playwright** | Browser automation | Multi-browser, auto-wait, best for complex sites |
| **Puppeteer** | Chrome-specific | Mature stealth plugins |
| **browser-use** | AI agent wrapper | LLM integration, DOM distillation |
| **Steel Browser** | Managed browser API | Infrastructure handling |

**Recommendation:** Start with **Playwright** for multi-browser support, integrate **browser-use** patterns for AI integration.

## AI/LLM Framework

| Tool | Purpose | Why |
|------|---------|-----|
| **LangChain** | LLM orchestration | Tool calling, chains, agents |
| **AutoGen** | Multi-agent | Agent-E uses this, proven |
| **CrewAI** | Agent coordination | Simpler than AutoGen |
| **OpenAI SDK** | Direct API calls | For GPT models |
| **Anthropic SDK** | Direct API calls | For Claude models |

**Recommendation:** Use **LangChain** for model abstraction + custom multi-agent layer.

## DOM Processing

| Tool | Purpose | Why |
|------|---------|-----|
| **Cheerio** | HTML parsing | Fast, jQuery-like |
| **JSDOM** | DOM emulation | Full DOM API |
| **Readability** | Content extraction | Article content |
| **turndown** | HTML to Markdown | LLM-friendly format |

**Recommendation:** **Cheerio** for extraction + **turndown** for LLM input.

## Testing Framework Output

| Tool | Purpose | Why |
|------|---------|-----|
| **Playwright Test** | Test runner | Best DX, auto-wait |
| **Cypress** | E2E tests | Popular, good debugging |
| **Jest** | Unit/API tests | Standard for JS |
| **pytest** | Python tests | For Python users |

**Recommendation:** Generate **Playwright Test** files by default, with export options.

## Infrastructure

| Tool | Purpose | Why |
|------|---------|-----|
| **Electron** | Desktop app | Current stack |
| **SQLite/DuckDB** | Local storage | Crawl history, caching |
| **Redis** | Queue management | For cloud version |
| **MinIO/S3** | Screenshot storage | Scalable |

---

# Part 6: Human QA Actions → AI Agent Mapping

## Complete QA Task Replication

| Human QA Action | AI Agent Implementation |
|-----------------|-------------------------|
| **Explore application** | Explorer Agent: Autonomous crawling with DOM distillation |
| **Find all features** | Element extraction + flow detection |
| **Understand user flows** | Flow Detection Agent: Multi-step sequence analysis |
| **Write test cases** | Test Generator Agent: Three-mindset generation |
| **Execute tests** | Parallel browser execution engine |
| **Report bugs** | Issue Detection Agent: Error monitoring + screenshots |
| **Regression testing** | Compare current vs baseline Application DNA |
| **Cross-browser testing** | Multi-browser Playwright contexts |
| **Mobile testing** | Viewport emulation + touch events |
| **Performance testing** | Network timing + Core Web Vitals capture |
| **Security testing** | Security Agent: OWASP test patterns |
| **API testing** | API Agent: Endpoint discovery + payload generation |
| **Visual testing** | Vision Agent: Screenshot comparison |
| **Accessibility testing** | A11y Agent: WCAG compliance checks |
| **Documentation** | Reporter Agent: Auto-generate test documentation |

## Agent Specialization

### Explorer Agent
```
Skills:
- Navigate to URLs
- Extract DOM (distilled)
- Identify interactive elements
- Detect page type/context
- Handle infinite scroll
- Manage authentication

Tools:
- Playwright browser
- Cheerio parser
- URL normalizer
- Cookie/session manager
```

### Classifier Agent
```
Skills:
- Categorize elements (Nav/Read/Write/Destructive/Payment)
- Detect form field types
- Identify user flows
- Calculate confidence scores
- Prioritize action queue

Tools:
- DeepSeek for classification
- Rule-based fallbacks
- Confidence calculator
```

### Test Generator Agent
```
Skills:
- Generate happy path tests
- Generate edge case tests
- Generate security tests
- Create test data fixtures
- Output Playwright/Cypress code

Tools:
- GPT-4o/Sonnet for generation
- Template engine
- Code formatter
```

### Security Agent
```
Skills:
- Identify injection points
- Generate attack payloads
- Test auth bypass
- Check CSRF tokens
- Validate input sanitization

Tools:
- OWASP payload library
- Custom injection patterns
- Response analyzer
```

### Reporter Agent
```
Skills:
- Aggregate test results
- Generate coverage reports
- Create Application DNA visualization
- Export to external tools
- Track trends over time

Tools:
- Chart generation
- Markdown/HTML templates
- Jira/TestRail API
```

---

# Part 7: Implementation Roadmap

## Sprint 1-2: Foundation (4 weeks)

### Goals:
- [ ] Upgrade DOM extraction with distillation
- [ ] Implement multi-tab parallel crawling
- [ ] Add element classification with confidence
- [ ] Create action queue system

### Technical Tasks:
```
1. Refactor electron/main.js to support:
   - Multiple BrowserViews
   - Parallel page processing
   - Screenshot capture pipeline

2. Implement DOM Distillation:
   - Extract only interactive elements
   - Convert to compact JSON format
   - Calculate element signatures

3. Build Classification System:
   - Rule-based primary classification
   - LLM fallback for ambiguous cases
   - Confidence scoring
```

## Sprint 3-4: AI Integration (4 weeks)

### Goals:
- [ ] Integrate LLM APIs (DeepSeek, GPT-4o, Sonnet)
- [ ] Build multi-model routing
- [ ] Implement flow detection
- [ ] Create test generation pipeline

### Technical Tasks:
```
1. LLM Integration:
   - Model router with cost optimization
   - Prompt templates for each task
   - Response parsers

2. Flow Detection:
   - Track navigation sequences
   - Identify multi-step processes
   - Map dependencies

3. Test Generation:
   - Three-mindset prompts
   - Playwright code templates
   - Test data fixtures
```

## Sprint 5-6: Production Features (4 weeks)

### Goals:
- [ ] Parallel execution engine
- [ ] API discovery & testing
- [ ] Security test generation
- [ ] Reporting dashboard

### Technical Tasks:
```
1. Parallel Execution:
   - Browser pool management
   - Isolated contexts for write ops
   - Progress tracking

2. API Testing:
   - Network request capture
   - Endpoint extraction
   - Payload generation

3. Security Tests:
   - OWASP patterns
   - Injection test library
   - Auth bypass checks
```

## Sprint 7-8: Polish & Launch (4 weeks)

### Goals:
- [ ] CI/CD integrations
- [ ] Team features
- [ ] Billing/credits system
- [ ] Documentation & onboarding

---

# Part 8: Verification Plan

## How to Test the Implementation

### 1. Unit Tests
```bash
# Run test generation on sample pages
npm run test:generation

# Verify DOM distillation accuracy
npm run test:distillation

# Check classification accuracy
npm run test:classification
```

### 2. Integration Tests
```bash
# Full crawl of test site
npm run test:crawl -- --url="https://example.com"

# Verify generated tests pass
npm run test:generated

# Check API discovery
npm run test:api-discovery
```

### 3. End-to-End Verification
```bash
# Complete flow: URL → Test Suite
npm run e2e -- --url="https://demo-site.com" --output="./tests"

# Run generated tests
npx playwright test ./tests
```

### 4. Cost Verification
- Log all LLM API calls with token counts
- Calculate actual cost per page
- Compare against target margins
- Adjust model routing if needed

### 5. Quality Metrics
- Page discovery rate (target: 95%+)
- Element classification accuracy (target: 90%+)
- Test generation success rate (target: 85%+)
- Generated test pass rate (target: 80%+)

---

# Part 9: Key Files to Modify

```
/Users/muralivvrsngurajapu/testai/
├── electron/
│   ├── main.js              # Add parallel browsing, distillation
│   └── preload.js           # Expose new APIs
├── src/
│   ├── App.tsx              # New UI for agents, progress
│   ├── lib/
│   │   ├── api.ts           # Replace Tauri with Electron IPC
│   │   ├── llm-router.ts    # NEW: Multi-model routing
│   │   ├── dom-distiller.ts # NEW: DOM distillation
│   │   ├── classifier.ts    # NEW: Element classification
│   │   └── test-generator.ts# NEW: Test code generation
│   └── agents/              # NEW: Agent implementations
│       ├── explorer.ts
│       ├── classifier.ts
│       ├── tester.ts
│       ├── security.ts
│       └── reporter.ts
├── prompts/                 # NEW: LLM prompt templates
│   ├── classify-element.md
│   ├── detect-flow.md
│   ├── generate-test-normal.md
│   ├── generate-test-edge.md
│   └── generate-test-security.md
└── package.json             # Add LLM SDKs, new deps
```

---

# Summary: What Makes YaliTest Win

| Competitor Approach | YaliTest Approach |
|--------------------|-------------------|
| Manual test recording | Autonomous discovery |
| Manual test scripting | AI-generated tests |
| Test what you define | Test everything found |
| Single browser at a time | 10-50 parallel browsers |
| $500-8000/month | $99-599/month |
| Needs QA team | Replaces QA team |

**The 30-Minute Promise:**
1. User enters URL (1 min)
2. Crawler discovers 100+ pages (5 min)
3. AI classifies 1000+ elements (2 min)
4. Flow detection finds 10+ user journeys (2 min)
5. Test generation creates 500+ test cases (15 min)
6. Export to Playwright/Cypress (1 min)
7. Run tests in CI (4 min)

**Total: 30 minutes to achieve what would take a QA team days.**

---

# Part 10: AI Capabilities - Honest Assessment & Context Architecture

## The Key Insight: Context Is Everything

AI CAN do most QA tasks - but only with proper context. The difference between 50% and 90% accuracy is **structured context**.

## Revised Capability Assessment

| Task | Without Context | With Good Context | How to Provide Context |
|------|-----------------|-------------------|------------------------|
| Understanding business context | 40% | **90%** | Business Context Document |
| Exploratory testing (creativity) | 50% | **85%** | Persona-based prompts |
| Prioritizing what matters | 45% | **95%** | Scoring framework |
| Communicating with stakeholders | 70% | **90%** | Report templates |
| Judging "is this a bug?" | 40% | **80%** | Expected behavior specs |

## Business Context Document (User Provides Once)

```markdown
# Business Context Document Template

## App Overview
- App type: [E-commerce / SaaS / Social / etc.]
- Daily revenue: $X
- Daily active users: X
- Primary business model: [Subscription / Transaction / Ads]

## Critical Paths (Never Break These)
1. [e.g., Login → Browse → Add to Cart → Checkout → Payment]
2. [e.g., Search → Product Page → Reviews]
3. [e.g., Account → Order History → Reorder]

## Known Pain Points
- [e.g., Mobile checkout abandonment is 40%]
- [e.g., Search is slow, team is rewriting it]
- [e.g., Payment failures on Safari]

## Current Sprint Focus
- [e.g., New discount system launching Friday]
- [e.g., Don't touch user profile this sprint]

## Compliance Requirements
- [e.g., GDPR - user data deletion must work]
- [e.g., PCI DSS - payment data handling]
- [e.g., WCAG 2.1 AA - accessibility]

## User Segments
- [e.g., 60% mobile, 40% desktop]
- [e.g., 30% first-time users, 70% returning]
- [e.g., Peak hours: 6-9 PM EST]
```

**Token Cost:** ~2,000 tokens = $0.006 per AI decision (GPT-4o)

## Persona-Based Exploratory Testing

Instead of random exploration, AI adopts specific user personas:

### 5 Test Personas (Feed to AI)

```markdown
## Persona 1: Confused First-Timer
- Never used this type of app before
- Doesn't understand jargon ("cart", "checkout", "SKU")
- Might double-click everything
- Will try to go back with browser button
- Expects hand-holding and clear instructions

## Persona 2: Impatient Power User
- Uses keyboard shortcuts exclusively
- Opens 10+ tabs simultaneously
- Clicks before page fully loads
- Uses browser back/forward constantly
- Expects everything to be instant

## Persona 3: Malicious Attacker
- Looking for XSS, SQL injection, CSRF
- Tries to access other users' data
- Manipulates URLs, cookies, localStorage
- Intercepts and modifies API requests
- Tests authentication boundaries

## Persona 4: Edge Case Explorer
- Enters empty values everywhere
- Uses maximum length strings (10,000+ chars)
- Puts emojis and special characters in every field
- Uploads 100MB files when 1MB expected
- Sets dates to year 1900 and 2100

## Persona 5: Flaky Network User
- 3G connection speed
- Connection drops mid-transaction
- Refreshes page during form submission
- Session expires while filling long form
- Multiple devices, same account
```

**Result:** AI generates 50+ unique, creative test scenarios per persona.

## Prioritization Scoring Framework

```markdown
# Bug Prioritization Framework (Feed to AI)

## Severity Score (1-5)
- 5: Data loss, security breach, payment failure, app crash
- 4: Feature completely broken, no workaround
- 3: Feature partially broken, workaround exists
- 2: Cosmetic issue affecting UX significantly
- 1: Minor visual glitch, barely noticeable

## Frequency Score (1-5)
- 5: Affects 100% of users
- 4: Affects >50% of users
- 3: Affects 10-50% of users
- 2: Affects <10% of users
- 1: Edge case, rare occurrence

## Business Impact Score (1-5)
- 5: Directly blocks revenue/conversion
- 4: Affects critical user flow
- 3: Affects important but secondary features
- 2: Affects internal tools or admin features
- 1: No measurable business impact

## Final Priority = Severity × Frequency × Business Impact
- 100-125: P0 - Stop everything, fix now
- 50-99: P1 - Fix this sprint
- 20-49: P2 - Fix next sprint
- 8-19: P3 - Backlog
- 1-7: P4 - Won't fix / Nice to have
```

**AI Advantage:** Applies these rules MORE consistently than humans (no mood, no bias, no fatigue).

## Expected Behavior Specifications

```markdown
# Expected Behavior Spec Template

## Login Form
- Email field:
  - Valid: any@email.com format
  - Invalid: show inline error "Please enter a valid email"
  - Empty: show error on submit attempt
- Password field:
  - Min 8 characters
  - Show/hide toggle must work
  - Strength meter updates in real-time
- Submit button:
  - Disabled until both fields have content
  - Shows loading spinner during request
  - Timeout after 30 seconds with retry option
- Success: Redirect to /dashboard within 2 seconds
- Failure: Show "Invalid credentials" (never reveal which field)
- Rate limiting: Lock after 5 failed attempts for 15 minutes

## Checkout Flow
- Empty cart: Show "Your cart is empty" with "Continue Shopping" CTA
- Expired session: Redirect to login, preserve cart contents
- Payment decline: Show specific error, allow retry, don't clear card info
- Success: Show confirmation, send email within 1 minute
- Inventory conflict: Show "Item no longer available" before payment
```

**With specs, AI achieves 80%+ accuracy in bug judgment.**

---

# Part 11: Context-Aware Architecture

## The Context Layer

```
┌─────────────────────────────────────────────────────────────┐
│                    Context Layer (Persistent)                │
├─────────────────────────────────────────────────────────────┤
│  • Business Context Doc (user provides once, updates rarely)│
│  • App Structure Map (auto-discovered, cached)              │
│  • Historical Bugs (learned from past runs)                 │
│  • User Corrections (when human overrides AI decision)      │
│  • Expected Behaviors (specs for critical flows)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    AI Decision Engine                        │
├─────────────────────────────────────────────────────────────┤
│  Input: Element + Action + Full Context                     │
│  Output: Decision + Confidence Score (0-100%)               │
│                                                             │
│  Confidence > 85%  → Auto-proceed                           │
│  Confidence 50-85% → Proceed but flag for human review      │
│  Confidence < 50%  → Pause and ask human                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Learning Loop                             │
├─────────────────────────────────────────────────────────────┤
│  • Human approves AI decision → Reinforce pattern           │
│  • Human rejects AI decision → Learn correction             │
│  • Same correction 3+ times → Update rules automatically    │
└─────────────────────────────────────────────────────────────┘
```

## Confidence-Based Automation

```typescript
interface AIDecision {
  action: string;
  reasoning: string;
  confidence: number;  // 0-100
  contextUsed: string[];
  alternatives: string[];
}

// Examples:

// High confidence - auto proceed
{
  action: "click_login_button",
  confidence: 95,
  reasoning: "Clear login flow, button labeled 'Sign In', matches expected behavior spec",
  contextUsed: ["business_context", "behavior_spec"],
  alternatives: []
}

// Medium confidence - proceed but flag
{
  action: "click_ambiguous_icon",
  confidence: 65,
  reasoning: "Icon has no label or aria-label, position suggests settings based on common patterns",
  contextUsed: ["app_structure"],
  alternatives: ["Could be profile", "Could be notifications"]
}

// Low confidence - ask human
{
  action: "submit_form_with_unusual_fields",
  confidence: 30,
  reasoning: "Form contains custom field 'x-internal-code' not in any spec, unclear if test data is valid",
  contextUsed: [],
  alternatives: ["Skip this form", "Use placeholder data", "Mark as needs-manual-test"]
}
```

## Cost of "Smart" AI (Tiered)

| Intelligence Level | Context Size | Tokens/Page | Cost/100 Pages | Accuracy |
|-------------------|--------------|-------------|----------------|----------|
| **Basic** | None | 500 | $0.15 | 50% |
| **Standard** | App structure only | 1,500 | $0.45 | 65% |
| **Smart** | + Business context | 4,000 | $1.20 | 80% |
| **Genius** | + Behavior specs + History | 8,000 | $2.40 | 90% |
| **Expert** | + Learning from corrections | 12,000 | $3.60 | 95% |

---

# Part 12: Revised Product Positioning

## Don't Say This:
> "Replace 100 QA engineers in 30 minutes"

**Why it's problematic:**
- Sets unrealistic expectations
- Customers will be disappointed when edge cases are missed
- Makes us look naive about QA complexity

## Do Say This:
> "10x your QA team's effectiveness by eliminating grunt work"

Or:
> "Get 80% test coverage in 30 minutes. Let your humans find the clever bugs."

Or:
> "AI handles the repetitive 70% of QA so your team can focus on the 30% that matters."

## Revised Value Proposition

| What AI Handles (70%) | What Humans Handle (30%) |
|----------------------|--------------------------|
| Discovering all pages | Deciding what's critical |
| Finding all elements | Judging edge case validity |
| Generating test boilerplate | Adding business logic assertions |
| Running regression 24/7 | Investigating root causes |
| Detecting obvious bugs | Prioritizing based on politics |
| Maintaining selectors | Final sign-off for release |

## Target Customer Segments (Revised)

### Segment 1: Startups with 0-1 QA ($49-149/mo)
**Pain:** No time or budget for testing
**Promise:** "Get test coverage without hiring"
**Reality:** AI does 80%, founder reviews 20%

### Segment 2: Teams with Overloaded QA ($149-349/mo)
**Pain:** QA is bottleneck, can't keep up with dev
**Promise:** "Let AI do regression, humans do exploration"
**Reality:** QA focuses on strategy, AI handles execution

### Segment 3: Agencies ($349-599/mo)
**Pain:** Need to deliver tested code to clients fast
**Promise:** "Ship with confidence, every time"
**Reality:** Automated baseline, manual for client-specific logic

### Segment 4: Enterprise ($599+/mo)
**Pain:** Compliance, audit trails, integration
**Promise:** "Enterprise-grade testing infrastructure"
**Reality:** AI + human review workflow with full audit trail

## Revised Pricing Tiers (Intelligence-Based)

| Tier | Price | Intelligence | Best For |
|------|-------|--------------|----------|
| **Starter** | $49/mo | Basic (50% accuracy) | Side projects, learning |
| **Pro** | $149/mo | Smart (80% accuracy) | Startups, small teams |
| **Business** | $349/mo | Genius (90% accuracy) | Growing companies |
| **Enterprise** | $599+/mo | Expert (95% accuracy) | Large teams, compliance |

## Honest Limitations (Put in Docs)

```markdown
## What YaliTest Does Well
✅ Discovers all pages and interactive elements
✅ Generates comprehensive test coverage
✅ Runs tests continuously without fatigue
✅ Maintains tests when UI changes
✅ Applies consistent prioritization rules
✅ Scales to any size application

## What YaliTest Needs Human Help For
⚠️ Business-specific logic assertions (we generate templates, you verify)
⚠️ "Feels wrong" intuition (we flag uncertainty, you decide)
⚠️ Political prioritization (we score objectively, you adjust for context)
⚠️ Final release sign-off (we provide evidence, you make the call)

## What YaliTest Cannot Do
❌ Replace human judgment for critical decisions
❌ Understand implicit requirements not documented
❌ Navigate complex multi-user scenarios without setup
❌ Guarantee 100% bug detection (no tool can)
```

---

# Part 13: Implementation Priority (Revised)

## Phase 1: Foundation + Basic Context (MVP)
1. DOM Distillation Engine
2. Parallel Crawling (5-10 tabs)
3. Element Classification (rule-based)
4. Basic Test Generation
5. **Business Context Input UI** ← NEW

## Phase 2: Smart Context + Confidence
1. LLM Integration with multi-model routing
2. **Confidence Scoring System** ← NEW
3. **Persona-Based Exploration** ← NEW
4. Flow Detection
5. **Human-in-the-loop for low confidence** ← NEW

## Phase 3: Learning + Expert Mode
1. **Learning from human corrections** ← NEW
2. Expected Behavior Spec System
3. Historical pattern matching
4. Security Testing
5. API Discovery

## Phase 4: Enterprise + Scale
1. CI/CD Integration
2. Team Collaboration
3. Audit Trails
4. Custom Model Training (Enterprise)
5. On-premise Deployment

---

# Summary: Realistic Expectations

| Metric | Realistic Target | Notes |
|--------|------------------|-------|
| Page discovery | 95%+ | Excluding auth-gated pages without credentials |
| Element detection | 90%+ | May miss custom web components |
| Classification accuracy | 85%+ | With business context |
| Test generation | 80%+ | Human review recommended |
| Bug detection | 70%+ | For obvious bugs; subtle bugs need humans |
| False positive rate | <15% | Flagged items that aren't actually bugs |
| Time savings | 70-80% | Of repetitive QA work |

**The honest promise:**
> "YaliTest automates the tedious 70% of QA work with 85% accuracy.
> Your team focuses on the critical 30% that requires human judgment.
> Together, you ship faster with fewer bugs."

---

# Part 14: Actual Tools & Libraries (Not Just Ideas)

## DOM Extraction - Real Libraries

### Option 1: Playwright Accessibility Tree (RECOMMENDED)
```typescript
// One line to get accessibility tree
const snapshot = await page.accessibility.snapshot();

// Or use ARIA snapshots for testing
await expect(page.locator('body')).toMatchAriaSnapshot(`
  - banner:
    - heading "My App" [level=1]
  - navigation:
    - link "Home"
    - link "About"
  - main:
    - button "Submit"
`);
```

**Why:** Built-in, no extra dependency, reflects what screen readers see.

### Option 2: @codemonkcompany/llm-dom-selector
```bash
npm install @codemonkcompany/llm-dom-selector
```

```typescript
import { DOMSelector } from '@codemonkcompany/llm-dom-selector';

const selector = new DOMSelector(page);
const elements = await selector.getAllInteractiveElements();
// Returns: [{ index: 1, tag: 'button', text: 'Submit', ... }]
```

**Why:** Specifically designed for LLM integration, assigns numeric indices.

### Option 3: dom-accessibility-api
```bash
npm install dom-accessibility-api
```

```typescript
import { computeAccessibleName, computeAccessibleDescription } from 'dom-accessibility-api';

const name = computeAccessibleName(element);
const description = computeAccessibleDescription(element);
```

**Why:** W3C spec compliant, gets true accessible names.

### Option 4: Custom Extraction (Current Approach - Enhanced)
```typescript
// Enhanced extraction with accessibility info
const extractElements = async (page) => {
  return page.evaluate(() => {
    const selector = 'a[href],button,input:not([type=hidden]),select,textarea,' +
                     '[role=button],[role=link],[role=menuitem],[role=tab],' +
                     '[role=checkbox],[role=radio],[role=switch],[onclick]';

    return Array.from(document.querySelectorAll(selector)).map((el, i) => ({
      mmid: `el-${i}`,
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute('role') || el.tagName.toLowerCase(),
      name: el.getAttribute('aria-label') ||
            el.innerText?.slice(0, 80) ||
            el.getAttribute('placeholder') || '',
      type: el.getAttribute('type'),
      href: el.getAttribute('href'),
      disabled: el.disabled || el.getAttribute('aria-disabled') === 'true',
      visible: el.offsetParent !== null,
      rect: el.getBoundingClientRect().toJSON()
    }));
  });
};
```

## Browser Automation - Decision Matrix

| Tool | Use When | Avoid When |
|------|----------|------------|
| **Playwright** | Multi-browser, complex sites, auto-wait needed | Need Chrome-specific stealth |
| **Puppeteer** | Chrome only, stealth needed, simple tasks | Need Firefox/Safari |
| **browser-use** | AI agent wrapper, LLM integration | Simple automation |
| **Electron BrowserView** | Desktop app embedding (current) | Headless/cloud execution |

### Playwright Setup (RECOMMENDED for production)
```bash
npm install playwright
npx playwright install
```

```typescript
import { chromium, firefox, webkit } from 'playwright';

// Multi-browser support
const browsers = [chromium, firefox, webkit];
for (const browserType of browsers) {
  const browser = await browserType.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  // ... test
}
```

## AI/LLM Integration - Actual Libraries

### Multi-Model Router Implementation
```typescript
// src/lib/llm-router.ts
import OpenAI from 'openai';
import Anthropic from 'anthropic';

interface ModelConfig {
  provider: 'openai' | 'anthropic' | 'deepseek';
  model: string;
  costPerMTokInput: number;
  costPerMTokOutput: number;
}

const MODELS: Record<string, ModelConfig> = {
  cheap: { provider: 'deepseek', model: 'deepseek-chat', costPerMTokInput: 0.028, costPerMTokOutput: 0.42 },
  medium: { provider: 'openai', model: 'gpt-4o-mini', costPerMTokInput: 0.15, costPerMTokOutput: 0.60 },
  smart: { provider: 'openai', model: 'gpt-4o', costPerMTokInput: 2.50, costPerMTokOutput: 10.00 },
  vision: { provider: 'openai', model: 'gpt-4o', costPerMTokInput: 2.50, costPerMTokOutput: 10.00 },
};

export async function routedCompletion(
  task: 'classify' | 'generate' | 'vision' | 'decide',
  messages: Message[],
  options?: { forceModel?: string }
): Promise<{ result: string; cost: number; tokens: number }> {
  const modelKey = options?.forceModel || {
    classify: 'cheap',
    decide: 'cheap',
    generate: 'smart',
    vision: 'vision'
  }[task];

  const config = MODELS[modelKey];
  // ... implementation
}
```

### Required NPM Packages
```json
{
  "dependencies": {
    "openai": "^4.x",
    "@anthropic-ai/sdk": "^0.x",
    "playwright": "^1.x",
    "@langchain/core": "^0.x",
    "@langchain/openai": "^0.x",
    "cheerio": "^1.x",
    "turndown": "^7.x",
    "zod": "^3.x"
  }
}
```

## Vision vs DOM: When to Use What

| Scenario | DOM | Vision | Why |
|----------|-----|--------|-----|
| Standard forms | ✅ | ❌ | DOM is 10x cheaper, more accurate |
| Canvas elements | ❌ | ✅ | DOM can't see canvas content |
| Charts/graphs | ❌ | ✅ | Data visualizations need vision |
| Icon-only buttons | ⚠️ | ✅ | DOM may miss unlabeled icons |
| Custom web components | ⚠️ | ✅ | Shadow DOM issues |
| Regular buttons/links | ✅ | ❌ | Overkill to use vision |

### Vision Cost Reality
```
Screenshot at 1920x1080 = ~1000 tokens
Cost with GPT-4o: $0.0025 per screenshot

100 pages with vision = $0.25 (vision only)
100 pages with DOM = $0.015 (DOM extraction)

Vision is 16x more expensive, use sparingly!
```

### Hybrid Approach (RECOMMENDED)
```typescript
async function extractPage(page: Page): Promise<PageData> {
  // Always do DOM extraction first (cheap)
  const domElements = await extractDOMElements(page);

  // Check if vision is needed
  const needsVision = domElements.some(el =>
    el.tag === 'canvas' ||
    el.role === 'img' && !el.name ||
    el.tag === 'svg' && !el.name
  );

  if (needsVision) {
    const screenshot = await page.screenshot({ type: 'png' });
    const visionElements = await analyzeWithVision(screenshot);
    return mergeElements(domElements, visionElements);
  }

  return { elements: domElements, usedVision: false };
}
```

---

# Part 15: Product Manager Perspective

## User Experience Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Enter URL (5 seconds)                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  🌐 https://myapp.com                        [Start] │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Watch Discovery (2-5 minutes)                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  📊 Discovering: 47/~100 pages                          │ │
│  │  ████████████░░░░░░░░░░░ 47%                            │ │
│  │                                                         │ │
│  │  Found: 234 buttons, 89 links, 45 forms                │ │
│  │  Flows detected: Login, Checkout, Search               │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Review & Configure (2 minutes)                      │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  ⚙️ What to test?                                       │ │
│  │  ☑️ Happy paths (normal user)                           │ │
│  │  ☑️ Edge cases (curious user)                           │ │
│  │  ☐ Security tests (malicious user) [Pro]               │ │
│  │                                                         │ │
│  │  🔐 Need credentials?                                   │ │
│  │  [Add login for protected areas]                        │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Generate Tests (5-15 minutes)                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  🤖 Generating test suite...                            │ │
│  │                                                         │ │
│  │  ✅ Login flow: 12 tests                                │ │
│  │  ✅ Product browse: 34 tests                            │ │
│  │  ⏳ Checkout flow: generating...                        │ │
│  │                                                         │ │
│  │  Total: 127 tests | Est. cost: $2.34                   │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 5: Export & Run (1 minute)                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  📦 Your test suite is ready!                           │ │
│  │                                                         │ │
│  │  [Download Playwright] [Download Cypress] [Copy to CI]  │ │
│  │                                                         │ │
│  │  Preview:                                               │ │
│  │  test('login with valid credentials', async () => {    │ │
│  │    await page.goto('/login');                          │ │
│  │    await page.fill('[name=email]', 'test@ex...');     │ │
│  │  });                                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Problems We Solve (With Evidence)

| Problem | How We Solve It | Measurable Outcome |
|---------|-----------------|-------------------|
| "Writing tests takes weeks" | Auto-generate from discovery | **2 hours → 30 minutes** |
| "We only test what we remember" | Autonomous discovery finds everything | **60% → 95% coverage** |
| "Tests break when UI changes" | Self-healing locators | **40% less maintenance** |
| "No time for edge cases" | AI generates edge cases automatically | **3x more edge cases** |
| "Security testing is expensive" | Built-in OWASP patterns | **$5K → $49/month** |
| "Can't afford QA team" | AI does 70% of QA work | **$8K → $149/month** |

## Time Savings Calculation

| Task | Manual Time | YaliTest Time | Savings |
|------|-------------|---------------|---------|
| Discover all pages | 4 hours | 5 minutes | 98% |
| Find all interactive elements | 2 hours | 2 minutes | 98% |
| Write happy path tests | 8 hours | 10 minutes | 98% |
| Write edge case tests | 4 hours | 5 minutes | 98% |
| Identify user flows | 2 hours | 2 minutes | 98% |
| **Total for 100-page app** | **20 hours** | **24 minutes** | **98%** |

## Outcomes We Show

### Dashboard Metrics
- Pages discovered: 127
- Elements found: 1,234
- Tests generated: 456
- Flows detected: 8
- Issues found: 23
- Coverage estimate: 87%
- Time saved: ~18 hours
- Cost: $3.47

### Exportable Reports
- Application structure map
- Test coverage report
- Issue summary by severity
- Recommended manual tests
- CI/CD configuration

---

# Part 16: Engineer Perspective (Technical Deep Dive)

## What If DOM Reading Fails?

### Failure Modes & Solutions

| Failure Mode | Detection | Solution |
|--------------|-----------|----------|
| **Page not loaded** | `page.waitForLoadState('networkidle')` timeout | Retry with longer timeout, fallback to `domcontentloaded` |
| **SPA not rendered** | Element count = 0 | Wait for specific element, use `waitForSelector` |
| **Infinite scroll** | Same elements on re-extract | Scroll + re-extract loop with max iterations |
| **Shadow DOM** | Elements missing | Use `page.locator()` with `has-text` piercing |
| **iframes** | Main frame empty | `frame.locator()` for each iframe |
| **Canvas elements** | No interactive elements found | Trigger vision fallback |
| **Auth wall** | Redirect to login | Pause, ask user for credentials |

### Robust Extraction with Fallbacks
```typescript
async function robustExtract(page: Page, maxRetries = 3): Promise<Elements> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Wait for page to be ready
      await page.waitForLoadState('networkidle', { timeout: 10000 })
        .catch(() => page.waitForLoadState('domcontentloaded'));

      // Try DOM extraction
      let elements = await extractDOMElements(page);

      // If too few elements, page might not be ready
      if (elements.length < 3) {
        await page.waitForTimeout(2000);
        elements = await extractDOMElements(page);
      }

      // Check for shadow DOM
      const shadowRoots = await page.evaluate(() =>
        document.querySelectorAll('*').length -
        document.body.querySelectorAll('*').length
      );
      if (shadowRoots > 10) {
        elements = await extractWithShadowPiercing(page);
      }

      // Check for iframes
      const frames = page.frames();
      if (frames.length > 1) {
        for (const frame of frames.slice(1)) {
          const frameElements = await extractDOMElements(frame);
          elements.push(...frameElements.map(e => ({ ...e, inIframe: true })));
        }
      }

      return elements;

    } catch (error) {
      if (attempt === maxRetries - 1) throw error;
      await page.waitForTimeout(1000 * (attempt + 1));
    }
  }
}
```

## Vision Every Time - Cost Analysis

### If We Use Vision for Every Page:
```
100 pages × 1 screenshot each = 100 screenshots
100 screenshots × 1000 tokens = 100,000 tokens
100,000 tokens × $2.50/MTok = $0.25 input
+ LLM analysis output ~50,000 tokens = $0.50 output
Total vision cost: $0.75 per 100 pages

Compare to DOM-only: $0.02 per 100 pages
Vision is 37x more expensive!
```

### When Vision Actually Helps Accuracy:

| Scenario | DOM Accuracy | DOM+Vision Accuracy | Worth It? |
|----------|--------------|---------------------|-----------|
| Standard forms | 95% | 96% | ❌ No (+1% for 37x cost) |
| Icon buttons | 60% | 95% | ✅ Yes |
| Canvas apps | 0% | 85% | ✅ Yes (only option) |
| Chart testing | 0% | 80% | ✅ Yes |
| Complex layouts | 80% | 90% | ⚠️ Maybe |

### Recommended Strategy: Smart Vision
```typescript
function shouldUseVision(elements: Element[]): boolean {
  // Use vision only when needed
  const hasCanvas = elements.some(e => e.tag === 'canvas');
  const hasUnlabeledIcons = elements.filter(e =>
    e.tag === 'button' && !e.name && e.hasIcon
  ).length > 5;
  const lowConfidenceElements = elements.filter(e => e.confidence < 0.5).length;

  return hasCanvas || hasUnlabeledIcons || lowConfidenceElements > 10;
}
```

## Browser Choice Decision

### Electron BrowserView (Current) - Limitations
- ❌ Single browser only (Chromium)
- ❌ Can't run headless easily
- ❌ Hard to scale to parallel
- ✅ Good for desktop app demo
- ✅ User sees what's happening

### Playwright (RECOMMENDED for production)
```typescript
// Can run multiple browsers in parallel
const contexts = await Promise.all([
  chromium.launch().then(b => b.newContext()),
  chromium.launch().then(b => b.newContext()),
  chromium.launch().then(b => b.newContext()),
  // ... up to 10 parallel contexts
]);

// Each context is isolated (like incognito)
for (const context of contexts) {
  const page = await context.newPage();
  // Process pages in parallel
}
```

### Hybrid Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Electron App (UI)                         │
│  - Shows progress, results                                  │
│  - User configuration                                        │
│  - NOT used for actual browsing                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Playwright Engine (Backend)                   │
│  - Actual browser automation                                │
│  - Parallel execution                                       │
│  - Headless or headed mode                                  │
│  - Multi-browser support                                    │
└─────────────────────────────────────────────────────────────┘
```

## Prompt Engineering for Code Generation

### Structured Chain-of-Thought (SCoT) for Tests
```markdown
# Prompt Template: Generate Playwright Test

## Context
You are generating a Playwright test for the following element:
- Element: {{element}}
- Page URL: {{url}}
- Page context: {{pageType}}
- User flow: {{flowName}}

## Instructions
Think step by step using programming structures:

1. SEQUENTIAL: What setup steps are needed?
2. BRANCH: What conditions might affect the test?
3. LOOP: What needs to be repeated or verified multiple times?
4. ASSERTION: What should be true after the action?

## Output Format
```typescript
test('{{testName}}', async ({ page }) => {
  // SETUP (sequential)

  // ACTION

  // ASSERTION
});
```
```

### Few-Shot Example for Edge Cases
```markdown
## Example 1: Empty Input
Input: Email field
Test: Should show error for empty email
```typescript
test('email field shows error when empty', async ({ page }) => {
  await page.fill('[name=email]', '');
  await page.click('[type=submit]');
  await expect(page.locator('.error')).toContainText('required');
});
```

## Example 2: Boundary Value
Input: Quantity field (max 99)
Test: Should reject quantity over max
```typescript
test('quantity rejects values over 99', async ({ page }) => {
  await page.fill('[name=quantity]', '100');
  await expect(page.locator('[name=quantity]')).toHaveValue('99');
});
```

Now generate for: {{element}}
```

## Context/Memory Architecture

### Short-Term Memory (Current Session)
```typescript
interface SessionMemory {
  visitedUrls: Set<string>;
  discoveredElements: Map<string, Element>;
  actionHistory: Action[];
  errorLog: Error[];
  currentFlow: string | null;
}
```

### Long-Term Memory (Persistent)
```typescript
// Using SQLite for local storage
interface AppMemory {
  appId: string;
  structure: PageMap;
  previousRuns: RunSummary[];
  knownBugs: Bug[];
  userCorrections: Correction[];
  credentials: EncryptedCredentials;
}

// Vector DB for semantic search (optional, for large apps)
interface VectorMemory {
  embeddings: Map<string, number[]>;
  search(query: string, k: number): Element[];
}
```

### Memory Implementation
```typescript
// Using better-sqlite3 for persistence
import Database from 'better-sqlite3';

const db = new Database('yalitest.db');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS apps (
    id TEXT PRIMARY KEY,
    url TEXT,
    structure JSON,
    last_crawl TEXT
  );

  CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    app_id TEXT,
    timestamp TEXT,
    pages_found INTEGER,
    elements_found INTEGER,
    tests_generated INTEGER,
    issues_found INTEGER
  );

  CREATE TABLE IF NOT EXISTS corrections (
    id TEXT PRIMARY KEY,
    app_id TEXT,
    element_signature TEXT,
    ai_decision TEXT,
    human_correction TEXT,
    timestamp TEXT
  );
`);
```

## Error Rate Reduction Strategy

### Target: <5% Error Rate

| Error Type | Cause | Mitigation |
|------------|-------|------------|
| Timeout | Slow page | Adaptive timeout based on page complexity |
| Stale element | DOM changed | Re-query before action, use Playwright locators |
| Click intercepted | Overlay/modal | Dismiss overlays first, wait for animations |
| Navigation failed | Network error | Retry with exponential backoff |
| Element not found | Wrong selector | Multiple selector strategies, confidence scoring |
| Vision hallucination | AI error | Verify with DOM when possible |

### Error Handling Wrapper
```typescript
async function safeAction<T>(
  action: () => Promise<T>,
  options: {
    retries?: number;
    timeout?: number;
    onError?: (e: Error) => void;
  } = {}
): Promise<{ success: boolean; result?: T; error?: Error }> {
  const { retries = 3, timeout = 10000, onError } = options;

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const result = await Promise.race([
        action(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), timeout)
        )
      ]) as T;

      return { success: true, result };
    } catch (error) {
      onError?.(error as Error);

      if (attempt < retries - 1) {
        await sleep(1000 * Math.pow(2, attempt)); // Exponential backoff
      }
    }
  }

  return { success: false, error: new Error(`Failed after ${retries} attempts`) };
}
```

---

# Part 17: QA Perspective

## Complete Test Categories

### 1. Functional Testing
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **Happy Path** | Normal user flow works | Follow detected flows |
| **Negative** | Invalid inputs rejected | Generate invalid data |
| **Boundary** | Min/max values handled | Use 0, -1, MAX, MAX+1 |
| **Error Handling** | Errors shown correctly | Trigger error conditions |

### 2. UI/UX Testing
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **Element Presence** | All elements visible | Assert element exists |
| **Text Content** | Labels are correct | Snapshot text content |
| **Layout** | Elements positioned correctly | Visual regression |
| **Responsiveness** | Works on all viewports | Test at multiple sizes |

### 3. Integration Testing
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **API Calls** | Correct endpoints called | Monitor network |
| **Data Flow** | Data passes between pages | Track state changes |
| **Third-party** | External services work | Mock responses |

### 4. Security Testing (OWASP Top 10)
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **XSS** | Scripts not executed | Inject `<script>` tags |
| **SQL Injection** | Queries sanitized | Inject SQL patterns |
| **Auth Bypass** | Protected routes secure | Access without auth |
| **CSRF** | Tokens validated | Submit without token |
| **Broken Access** | Users can't access others' data | Try different user IDs |

### 5. Accessibility Testing
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **ARIA Labels** | Elements have labels | Check aria-* attributes |
| **Keyboard Nav** | Tab order correct | Simulate tab presses |
| **Color Contrast** | Text readable | Analyze color values |
| **Screen Reader** | Content announced | Check accessibility tree |

### 6. Performance Testing
| Category | What We Test | How We Generate |
|----------|--------------|-----------------|
| **Load Time** | Page loads quickly | Measure timing |
| **Core Web Vitals** | LCP, FID, CLS good | Use Lighthouse |
| **Bundle Size** | JS not too large | Analyze resources |

## User Personas for Test Generation

### Persona 1: First-Time User (Confused)
```typescript
const confusedUserTests = {
  behaviors: [
    'double-clicks everything',
    'uses browser back button mid-flow',
    'doesn\'t read labels',
    'expects hand-holding',
    'gets lost easily'
  ],
  testCases: [
    'double-click on submit doesn\'t duplicate',
    'browser back preserves form data',
    'form works without reading instructions',
    'error messages are clear',
    'can return to any step'
  ]
};
```

### Persona 2: Power User (Impatient)
```typescript
const powerUserTests = {
  behaviors: [
    'uses keyboard shortcuts',
    'opens multiple tabs',
    'clicks before page loads',
    'expects instant response',
    'skips optional steps'
  ],
  testCases: [
    'Enter key submits form',
    'same action in multiple tabs handled',
    'clicking during load doesn\'t break',
    'loading indicators shown',
    'optional steps truly optional'
  ]
};
```

### Persona 3: Malicious User (Attacker)
```typescript
const attackerTests = {
  behaviors: [
    'tries SQL injection',
    'attempts XSS',
    'manipulates URLs',
    'modifies cookies',
    'intercepts requests'
  ],
  testCases: [
    '\' OR 1=1 -- rejected',
    '<script>alert(1)</script> escaped',
    '/admin without auth redirects',
    'tampered session rejected',
    'API validates all inputs'
  ]
};
```

### Persona 4: Edge Case User
```typescript
const edgeCaseTests = {
  behaviors: [
    'enters maximum length strings',
    'uses special characters',
    'uploads huge files',
    'sets extreme dates',
    'uses emojis everywhere'
  ],
  testCases: [
    '10000 char input handled',
    '日本語 in name field works',
    '100MB file shows size error',
    'year 2100 date accepted',
    '🎉 in comments saved correctly'
  ]
};
```

### Persona 5: Flaky Network User
```typescript
const flakyNetworkTests = {
  behaviors: [
    'connection drops mid-request',
    'very slow responses',
    'times out frequently',
    'switches networks',
    'offline mode'
  ],
  testCases: [
    'retry button on network error',
    'request timeout shows message',
    '30s delay doesn\'t crash',
    'form data preserved on reconnect',
    'offline indicator shown'
  ]
};
```

## Bug vs Feature vs Expected Behavior

### Decision Framework
```typescript
interface BehaviorAnalysis {
  observed: string;
  expected: string | null;  // From spec if available
  isDocumented: boolean;
  userImpact: 'none' | 'minor' | 'major' | 'critical';
  classification: 'bug' | 'feature' | 'expected' | 'unclear';
  confidence: number;
  needsHumanReview: boolean;
}

function classifyBehavior(analysis: BehaviorAnalysis): string {
  // If documented, use documentation
  if (analysis.isDocumented && analysis.expected) {
    if (analysis.observed !== analysis.expected) {
      return 'bug'; // Clear deviation from spec
    }
    return 'expected';
  }

  // If undocumented but matches common patterns
  if (analysis.userImpact === 'none') {
    return 'expected'; // No impact = probably fine
  }

  // If high impact and undocumented
  if (analysis.userImpact === 'critical') {
    return 'bug'; // Assume critical issues are bugs
  }

  // Otherwise, needs human review
  return 'unclear';
}
```

## Information AI Needs to Ask

### When to Ask Human (via Slack/UI)
```typescript
const questionsToAsk = {
  credentials: {
    trigger: 'login page detected',
    question: 'I found a login page. Should I test authenticated flows?',
    options: ['Skip auth areas', 'Provide test credentials', 'Use SSO']
  },

  destructiveAction: {
    trigger: 'delete/remove button found',
    question: 'Found delete buttons. Should I test destructive actions?',
    options: ['Skip destructive tests', 'Test on staging only', 'Test with confirmation']
  },

  payment: {
    trigger: 'payment form detected',
    question: 'Found payment flow. How should I handle it?',
    options: ['Skip payment tests', 'Use test card (4111...)', 'Stop before payment']
  },

  ambiguousBehavior: {
    trigger: 'confidence < 50%',
    question: 'Unsure if this is a bug: {{description}}',
    options: ['It\'s a bug', 'It\'s expected', 'Need more context']
  },

  missingSpec: {
    trigger: 'undocumented behavior found',
    question: 'No spec found for {{feature}}. Where can I find documentation?',
    options: ['Link to docs', 'It\'s undocumented', 'Ask product team']
  }
};
```

---

# Part 18: User Perspective

## Trust Building Features

### 1. Transparency
```
┌─────────────────────────────────────────────────────────────┐
│  🔍 What YaliTest is doing right now:                        │
│                                                             │
│  Visiting: https://myapp.com/products                       │
│  Found: 34 buttons, 12 links, 8 forms                       │
│  AI decision: "Clicking 'Add to Cart' button"               │
│  Confidence: 94%                                            │
│                                                             │
│  [View live browser] [Pause] [See AI reasoning]             │
└─────────────────────────────────────────────────────────────┘
```

### 2. Control
- User can pause at any time
- User can skip specific elements
- User can add/remove test categories
- User approves before any destructive tests
- User controls credentials (never stored in cloud)

### 3. Explainability
```
┌─────────────────────────────────────────────────────────────┐
│  📋 Why this test was generated:                             │
│                                                             │
│  Test: "Login with empty password shows error"              │
│                                                             │
│  Reasoning:                                                 │
│  - Found login form with password field                     │
│  - Password field is required (has 'required' attribute)    │
│  - No empty password test exists                            │
│  - Generated from "Curious User" persona                    │
│                                                             │
│  Confidence: 92%                                            │
│  [Edit test] [Delete] [Mark as not useful]                  │
└─────────────────────────────────────────────────────────────┘
```

## Credential Handling

### User Concerns (Real)
1. "Will you store my password?"
2. "Can I use test/staging credentials?"
3. "What if my session expires?"
4. "Can you access my production data?"

### Our Approach
```typescript
// Credentials are NEVER sent to our servers
// They stay in user's local Electron app or their own Vault

interface CredentialConfig {
  // Option 1: User enters directly (stays in local memory)
  direct: { username: string; password: string };

  // Option 2: Environment variables
  env: { usernameVar: string; passwordVar: string };

  // Option 3: HashiCorp Vault
  vault: { path: string; usernameKey: string; passwordKey: string };

  // Option 4: AWS Secrets Manager
  aws: { secretId: string; region: string };
}

// Clear credentials after session
afterSession(() => {
  credentials = null;
  // Clear browser cookies/storage
});
```

### Trust Statement (For UI)
```
🔒 Your credentials never leave your computer.
- Stored in local memory only
- Cleared after each session
- Never sent to YaliTest servers
- You can use environment variables instead
```

## Ease of Use Metrics

### Time to First Test
- Install: 2 minutes (npm install)
- Enter URL: 5 seconds
- First discovery: 30 seconds
- First test generated: 2 minutes
- **Total: ~5 minutes to first value**

### Learning Curve
- Basic use: Zero learning (just paste URL)
- Configuration: 5 minutes (checkboxes)
- Custom rules: 30 minutes (documentation)
- Advanced: 2 hours (API integration)

## Cost Transparency

### User Dashboard
```
┌─────────────────────────────────────────────────────────────┐
│  💰 This Session Cost Breakdown                              │
│                                                             │
│  Pages crawled: 127                                         │
│  AI calls made: 45                                          │
│                                                             │
│  ├── Classification (DeepSeek): $0.12                       │
│  ├── Test generation (GPT-4o): $1.89                        │
│  ├── Vision analysis: $0.00 (not needed)                    │
│  └── Total: $2.01                                           │
│                                                             │
│  Credits used: 201 / 2000 remaining                         │
│  Estimated tests you can generate: ~900 more                │
└─────────────────────────────────────────────────────────────┘
```

---

# Part 19: AI Communication Integration (Slack/Teams)

## Why AI Needs to Communicate

During autonomous testing, AI encounters situations where it MUST ask humans:
1. **Credentials needed** - Can't guess login info
2. **Ambiguous behavior** - Not sure if bug or feature
3. **Destructive actions** - Should I click "Delete"?
4. **Missing documentation** - What's expected here?
5. **Low confidence** - I'm not sure, please verify

## Slack Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YaliTest Engine                           │
│                                                             │
│  1. Encounters question                                     │
│  2. Checks if answer in memory                              │
│  3. If not, sends to Slack                                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Slack Bot                                 │
│                                                             │
│  @yalitest-bot:                                             │
│  🤖 I'm testing myapp.com and found a login page.           │
│                                                             │
│  Should I test authenticated areas?                         │
│                                                             │
│  [Yes, here are credentials] [Skip auth] [Pause testing]    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    User Response                             │
│                                                             │
│  @dev-team: Yes, use test@example.com / TestPass123         │
│                                                             │
│  (Credentials sent via Slack DM, not in channel)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    YaliTest Continues                        │
│                                                             │
│  ✅ Received credentials                                    │
│  ✅ Logged in successfully                                  │
│  ✅ Found 47 more pages behind auth                         │
│  ✅ Continuing test generation...                           │
└─────────────────────────────────────────────────────────────┘
```

## Implementation with Slack Bolt

```typescript
// slack-integration.ts
import { App } from '@slack/bolt';

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  appToken: process.env.SLACK_APP_TOKEN,
  socketMode: true,
});

// Question types
interface AIQuestion {
  id: string;
  type: 'credentials' | 'confirmation' | 'clarification' | 'bug_or_feature';
  context: string;
  options: string[];
  timeout: number;
  defaultAction: string;
}

// Ask question and wait for response
async function askInSlack(question: AIQuestion): Promise<string> {
  const message = await app.client.chat.postMessage({
    channel: process.env.YALITEST_CHANNEL,
    text: question.context,
    blocks: [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `🤖 *YaliTest needs input*\n\n${question.context}` }
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

  // Wait for response or timeout
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve(question.defaultAction);
    }, question.timeout);

    // Listen for button click
    app.action(new RegExp(`yalitest_${question.id}_`), async ({ ack, body, action }) => {
      await ack();
      clearTimeout(timeout);
      resolve((action as any).value);
    });
  });
}

// Example usage
const response = await askInSlack({
  id: 'q-123',
  type: 'bug_or_feature',
  context: `Found unexpected behavior on /checkout:\n\n` +
           `When quantity is 0, the "Add to Cart" button is still clickable.\n\n` +
           `Is this a bug or expected?`,
  options: ['Bug - should be disabled', 'Expected - backend validates', 'Need more context'],
  timeout: 300000, // 5 minutes
  defaultAction: 'Need more context'
});
```

## Microsoft Teams Integration

```typescript
// teams-integration.ts
import { TeamsActivityHandler, TurnContext } from 'botbuilder';

class YaliTestBot extends TeamsActivityHandler {
  constructor() {
    super();

    this.onMessage(async (context: TurnContext, next) => {
      const text = context.activity.text?.toLowerCase();

      if (text?.includes('credentials')) {
        // Handle credentials in DM
        await context.sendActivity('Please DM me the credentials for security.');
      }

      await next();
    });
  }

  async askQuestion(context: TurnContext, question: AIQuestion) {
    await context.sendActivity({
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          type: 'AdaptiveCard',
          body: [
            { type: 'TextBlock', text: '🤖 YaliTest needs input', weight: 'bolder' },
            { type: 'TextBlock', text: question.context, wrap: true }
          ],
          actions: question.options.map(opt => ({
            type: 'Action.Submit',
            title: opt,
            data: { questionId: question.id, answer: opt }
          }))
        }
      }]
    });
  }
}
```

## Conversation Memory for AI

```typescript
// The AI remembers answers for similar situations
interface AnswerMemory {
  question_pattern: string;
  user_answer: string;
  context: string;
  timestamp: Date;
  app_id: string;
}

// Example: User said "Skip all delete buttons" once
// AI remembers this for future delete buttons in same app
const memory: AnswerMemory = {
  question_pattern: 'destructive_action:delete',
  user_answer: 'skip',
  context: 'User prefers not to test destructive actions',
  timestamp: new Date(),
  app_id: 'app-123'
};

// Before asking, check memory
function shouldAsk(question: AIQuestion, memory: AnswerMemory[]): boolean {
  const similar = memory.find(m =>
    m.question_pattern === question.type &&
    m.app_id === currentAppId
  );

  if (similar) {
    // Use remembered answer instead of asking
    console.log(`Using remembered answer: ${similar.user_answer}`);
    return false;
  }

  return true;
}
```

---

# Part 20: Complete Test Type Coverage

## Test Generation Matrix

| Test Type | Trigger | Generation Method | Output Format |
|-----------|---------|-------------------|---------------|
| **Unit-like UI** | Button click | Assert result | Playwright test |
| **Integration** | Form submit | Assert API call + UI | Playwright + API test |
| **E2E Flow** | Multi-step flow detected | Chain of actions | Playwright test suite |
| **Visual** | Every page | Screenshot baseline | Visual regression test |
| **Accessibility** | Every page | Axe-core scan | A11y report |
| **Performance** | Every page | Lighthouse metrics | Performance report |
| **Security** | Forms, auth | OWASP patterns | Security test suite |
| **API** | Network monitoring | Request/response tests | API test suite |

## Generated Test Examples

### Happy Path Test
```typescript
// Generated for: Login flow
test('user can log in with valid credentials', async ({ page }) => {
  await page.goto('/login');

  await page.fill('[name="email"]', 'test@example.com');
  await page.fill('[name="password"]', 'TestPassword123!');
  await page.click('[type="submit"]');

  await expect(page).toHaveURL('/dashboard');
  await expect(page.locator('h1')).toContainText('Welcome');
});
```

### Edge Case Test
```typescript
// Generated for: Email field - boundary testing
test('email field rejects invalid formats', async ({ page }) => {
  await page.goto('/login');

  const invalidEmails = [
    '',                    // Empty
    'notanemail',          // No @
    '@nodomain.com',       // No local part
    'spaces in@email.com', // Spaces
    'a'.repeat(255) + '@test.com', // Too long
  ];

  for (const email of invalidEmails) {
    await page.fill('[name="email"]', email);
    await page.click('[type="submit"]');
    await expect(page.locator('.error')).toBeVisible();
  }
});
```

### Security Test
```typescript
// Generated for: Login form - SQL injection
test('login form is protected against SQL injection', async ({ page }) => {
  await page.goto('/login');

  const sqlPayloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "admin'--",
    "1; SELECT * FROM users",
  ];

  for (const payload of sqlPayloads) {
    await page.fill('[name="email"]', payload);
    await page.fill('[name="password"]', 'test');
    await page.click('[type="submit"]');

    // Should not log in
    await expect(page).not.toHaveURL('/dashboard');
    // Should not show database errors
    await expect(page.locator('body')).not.toContainText(/SQL|syntax|database/i);
  }
});
```

### Accessibility Test
```typescript
// Generated for: All pages
test('page meets WCAG 2.1 AA standards', async ({ page }) => {
  await page.goto('/');

  // Run axe-core
  const accessibilityScanResults = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa'])
    .analyze();

  expect(accessibilityScanResults.violations).toEqual([]);
});
```

### API Test (from network monitoring)
```typescript
// Generated from: Observed API call during checkout
test('POST /api/orders creates order correctly', async ({ request }) => {
  const response = await request.post('/api/orders', {
    data: {
      items: [{ productId: '123', quantity: 2 }],
      address: { street: '123 Test St', city: 'Test City' }
    }
  });

  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.orderId).toBeDefined();
  expect(body.status).toBe('pending');
});
```

---

# Part 21: Final Implementation Checklist

## Must-Have for MVP

### Core Engine
- [ ] Playwright-based browser automation
- [ ] DOM extraction with accessibility tree
- [ ] Element classification (rule-based)
- [ ] Page discovery with deduplication
- [ ] Screenshot capture

### AI Integration
- [ ] Multi-model router (DeepSeek for cheap, GPT-4o for smart)
- [ ] Test generation prompts (happy path, edge cases)
- [ ] Confidence scoring
- [ ] Cost tracking per request

### User Interface
- [ ] URL input
- [ ] Progress visualization
- [ ] Test preview
- [ ] Export (Playwright format)
- [ ] Cost display

### Error Handling
- [ ] Retry logic with exponential backoff
- [ ] Timeout handling
- [ ] Network error recovery
- [ ] Graceful degradation

## Nice-to-Have for V1.1

- [ ] Vision fallback for canvas/icons
- [ ] Slack/Teams integration
- [ ] Security test generation
- [ ] Visual regression testing
- [ ] CI/CD export (GitHub Actions, GitLab)

## Future (V2+)

- [ ] Multi-browser parallel execution
- [ ] Credential vault integration
- [ ] Custom AI model fine-tuning
- [ ] Self-healing test maintenance
- [ ] Team collaboration features

---

# Summary: What We Actually Build

| Component | Library/Tool | Why This One |
|-----------|--------------|--------------|
| Browser automation | Playwright | Multi-browser, auto-wait, best DX |
| DOM extraction | Playwright accessibility + custom | Built-in, reliable |
| LLM cheap | DeepSeek V3 | $0.028/MTok, good enough |
| LLM smart | GPT-4o | Best code generation |
| LLM vision | GPT-4o | Only when needed |
| Local storage | better-sqlite3 | Fast, no server needed |
| Desktop app | Electron (current) | Already have it |
| Slack integration | @slack/bolt | Official SDK |
| Test output | Playwright Test format | Most popular |

**Total new dependencies:** ~8 packages
**Estimated development time:** 8-12 weeks for MVP
**Target cost per 100 pages:** $1.50-3.00
**Target accuracy:** 85% with context

---

# Part 22: Senior Engineer Review #2 - Critical Architecture Fixes

## Issue 1: Infinite Loop / State Explosion

### The Problem
A simple queue system doesn't prevent revisiting the same state. Example:
```
Home → Products → Cart → Home → Products → Cart → ... (infinite loop)
```

The queue sees different URLs but the application state is the same.

### Solution: State Fingerprinting

```typescript
interface StateFingerprint {
  url: string;
  domHash: string;        // Hash of interactive element signatures
  activeElement: string;  // Currently focused element
  modalState: string;     // Open modals/dialogs
  formState: string;      // Hash of form field values
}

function createFingerprint(page: Page): StateFingerprint {
  return {
    url: normalizeUrl(page.url()),
    domHash: hashInteractiveElements(await extractElements(page)),
    activeElement: await page.evaluate(() => document.activeElement?.id || ''),
    modalState: await detectOpenModals(page),
    formState: await hashFormValues(page)
  };
}

// Before taking any action, check if we've been here
const visited = new Set<string>();

function shouldProceed(fingerprint: StateFingerprint): boolean {
  const key = JSON.stringify(fingerprint);
  if (visited.has(key)) {
    console.log('Already visited this state, skipping');
    return false;
  }
  visited.add(key);
  return true;
}
```

### DOM Hash Algorithm

```typescript
function hashInteractiveElements(elements: Element[]): string {
  // Create stable signature from interactive elements
  const signature = elements
    .filter(e => e.isInteractive)
    .map(e => `${e.tag}:${e.role}:${e.name?.slice(0, 20)}`)
    .sort()
    .join('|');

  // Use fast hash (xxhash or similar)
  return xxhash(signature).toString(16);
}
```

### Max Depth & Breadth Limits

```typescript
interface ExplorationLimits {
  maxDepth: number;           // Max clicks from starting page (default: 10)
  maxPagesPerDomain: number;  // Max pages to discover (default: 500)
  maxActionsPerPage: number;  // Max elements to interact with per page (default: 50)
  maxTotalActions: number;    // Total actions before stopping (default: 5000)
  maxTimeMinutes: number;     // Hard timeout (default: 30)
}

// Track depth from entry point
interface ExplorationState {
  depth: number;
  actionCount: number;
  startTime: Date;
}

function checkLimits(state: ExplorationState, limits: ExplorationLimits): boolean {
  if (state.depth > limits.maxDepth) return false;
  if (state.actionCount > limits.maxTotalActions) return false;
  if (minutesSince(state.startTime) > limits.maxTimeMinutes) return false;
  return true;
}
```

---

# Part 23: Navigation Graph (Not Simple Queue)

## The Problem with Simple Queues

```typescript
// BAD: Simple queue doesn't prevent cycles
const queue: Action[] = [];
queue.push(action1);
queue.push(action2);
// Can easily add same action multiple times
// No awareness of page relationships
```

## Solution: Navigation Graph

```typescript
interface NavNode {
  id: string;                    // URL + domHash
  url: string;
  signature: string;             // DOM fingerprint
  elements: Element[];           // Interactive elements on this page
  discovered: Date;
  visitCount: number;
}

interface NavEdge {
  from: string;                  // Source node ID
  to: string;                    // Target node ID
  action: Action;                // What action caused this transition
  discovered: Date;
}

class NavigationGraph {
  nodes: Map<string, NavNode> = new Map();
  edges: Map<string, NavEdge[]> = new Map();

  // Check if we've seen this page state before
  hasNode(url: string, domHash: string): boolean {
    return this.nodes.has(`${url}#${domHash}`);
  }

  // Add a new page to the graph
  addNode(node: NavNode): void {
    const id = `${node.url}#${node.signature}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, node);
    }
  }

  // Record a transition between pages
  addEdge(fromUrl: string, fromHash: string, toUrl: string, toHash: string, action: Action): void {
    const fromId = `${fromUrl}#${fromHash}`;
    const toId = `${toUrl}#${toHash}`;

    if (!this.edges.has(fromId)) {
      this.edges.set(fromId, []);
    }

    // Check if this edge already exists
    const existing = this.edges.get(fromId)!;
    if (!existing.some(e => e.to === toId && e.action.type === action.type)) {
      existing.push({ from: fromId, to: toId, action, discovered: new Date() });
    }
  }

  // Get unexplored edges (actions we haven't tried)
  getUnexploredActions(nodeId: string): Action[] {
    const node = this.nodes.get(nodeId);
    if (!node) return [];

    const exploredActions = (this.edges.get(nodeId) || []).map(e => e.action.elementId);
    return node.elements.filter(el => !exploredActions.includes(el.mmid));
  }

  // Detect if adding this edge would create a cycle
  wouldCreateCycle(fromId: string, toId: string, maxDepth: number = 3): boolean {
    // BFS to check if toId can reach fromId within maxDepth
    const visited = new Set<string>();
    const queue: { id: string; depth: number }[] = [{ id: toId, depth: 0 }];

    while (queue.length > 0) {
      const { id, depth } = queue.shift()!;
      if (id === fromId) return true;
      if (depth >= maxDepth) continue;
      if (visited.has(id)) continue;

      visited.add(id);
      const edges = this.edges.get(id) || [];
      for (const edge of edges) {
        queue.push({ id: edge.to, depth: depth + 1 });
      }
    }

    return false;
  }

  // Export graph for visualization
  toMermaid(): string {
    let mermaid = 'graph LR\n';
    for (const [fromId, edges] of this.edges) {
      for (const edge of edges) {
        const fromLabel = fromId.split('#')[0].split('/').pop() || 'home';
        const toLabel = edge.to.split('#')[0].split('/').pop() || 'home';
        mermaid += `  ${fromLabel}-->|${edge.action.type}|${toLabel}\n`;
      }
    }
    return mermaid;
  }
}
```

## Graph-Based Exploration Algorithm

```typescript
async function exploreWithGraph(startUrl: string, limits: ExplorationLimits): Promise<NavigationGraph> {
  const graph = new NavigationGraph();
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(startUrl);

  // Add starting node
  const startFingerprint = await createFingerprint(page);
  const startNode: NavNode = {
    id: `${startFingerprint.url}#${startFingerprint.domHash}`,
    url: startFingerprint.url,
    signature: startFingerprint.domHash,
    elements: await extractElements(page),
    discovered: new Date(),
    visitCount: 1
  };
  graph.addNode(startNode);

  // Exploration loop
  let actionCount = 0;
  const startTime = new Date();

  while (actionCount < limits.maxTotalActions) {
    // Check time limit
    if (minutesSince(startTime) > limits.maxTimeMinutes) {
      console.log('Time limit reached');
      break;
    }

    // Find node with unexplored actions
    let currentNodeId: string | null = null;
    let nextAction: Action | null = null;

    for (const [nodeId, node] of graph.nodes) {
      const unexplored = graph.getUnexploredActions(nodeId);
      if (unexplored.length > 0) {
        currentNodeId = nodeId;
        nextAction = {
          type: 'click',
          elementId: unexplored[0].mmid,
          element: unexplored[0]
        };
        break;
      }
    }

    if (!nextAction || !currentNodeId) {
      console.log('All actions explored');
      break;
    }

    // Navigate to the page if not already there
    const currentNode = graph.nodes.get(currentNodeId)!;
    if (page.url() !== currentNode.url) {
      await page.goto(currentNode.url);
    }

    // Execute action
    const beforeFingerprint = await createFingerprint(page);
    await executeAction(page, nextAction);
    actionCount++;

    // Wait for navigation/changes
    await page.waitForTimeout(1000);

    // Get new state
    const afterFingerprint = await createFingerprint(page);

    // Check if state changed
    if (beforeFingerprint.domHash !== afterFingerprint.domHash ||
        beforeFingerprint.url !== afterFingerprint.url) {

      // Check if this is a new node
      const newNodeId = `${afterFingerprint.url}#${afterFingerprint.domHash}`;
      if (!graph.hasNode(afterFingerprint.url, afterFingerprint.domHash)) {
        // Don't add if it would create a short cycle
        if (!graph.wouldCreateCycle(currentNodeId, newNodeId, 2)) {
          const newNode: NavNode = {
            id: newNodeId,
            url: afterFingerprint.url,
            signature: afterFingerprint.domHash,
            elements: await extractElements(page),
            discovered: new Date(),
            visitCount: 1
          };
          graph.addNode(newNode);
        }
      }

      // Record the edge
      graph.addEdge(
        beforeFingerprint.url, beforeFingerprint.domHash,
        afterFingerprint.url, afterFingerprint.domHash,
        nextAction
      );
    }

    // Progress logging
    if (actionCount % 10 === 0) {
      console.log(`Explored ${actionCount} actions, ${graph.nodes.size} unique pages`);
    }
  }

  await browser.close();
  return graph;
}
```

---

# Part 24: Electron Architecture Fix (Worker Pool)

## The Problem

Running 50 BrowserViews in Electron's UI thread will:
- Freeze the UI
- Exhaust memory
- Crash the app

## Solution: Separate Worker Pool

```
┌─────────────────────────────────────────────────────────────┐
│                    Electron Main Process                     │
│                                                             │
│  - Renders UI (React)                                       │
│  - Receives user input                                      │
│  - Shows progress                                           │
│  - DOES NOT run browsers                                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ IPC (progress, results)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Browser Worker Pool (Separate Process)          │
│                                                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Worker 1│ │ Worker 2│ │ Worker 3│ │ Worker 4│           │
│  │Playwright│ │Playwright│ │Playwright│ │Playwright│         │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
│                                                             │
│  - Each worker: 1 browser instance                          │
│  - Pool size: 4-8 (configurable)                           │
│  - Communicates via IPC                                     │
└─────────────────────────────────────────────────────────────┘
```

### Implementation with Worker Threads

```typescript
// browser-pool.ts - Run in separate Node.js process
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { chromium, Browser, Page } from 'playwright';

interface WorkerTask {
  type: 'navigate' | 'extract' | 'click' | 'screenshot';
  url?: string;
  mmid?: string;
}

interface WorkerResult {
  success: boolean;
  data?: any;
  error?: string;
}

if (!isMainThread) {
  // This is a worker
  let browser: Browser;
  let page: Page;

  async function initialize() {
    browser = await chromium.launch({ headless: true });
    page = await browser.newPage();
  }

  async function handleTask(task: WorkerTask): Promise<WorkerResult> {
    try {
      switch (task.type) {
        case 'navigate':
          await page.goto(task.url!, { timeout: 30000 });
          return { success: true, data: { url: page.url() } };

        case 'extract':
          const elements = await extractElements(page);
          return { success: true, data: { elements } };

        case 'click':
          await page.click(`[data-mmid="${task.mmid}"]`);
          return { success: true };

        case 'screenshot':
          const buffer = await page.screenshot({ type: 'png' });
          return { success: true, data: { screenshot: buffer.toString('base64') } };

        default:
          return { success: false, error: 'Unknown task type' };
      }
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  }

  // Initialize and listen for tasks
  initialize().then(() => {
    parentPort!.on('message', async (task: WorkerTask) => {
      const result = await handleTask(task);
      parentPort!.postMessage(result);
    });
  });
}

// Main thread pool manager
class BrowserPool {
  private workers: Worker[] = [];
  private taskQueue: { task: WorkerTask; resolve: Function; reject: Function }[] = [];
  private availableWorkers: Worker[] = [];

  constructor(private poolSize: number = 4) {}

  async initialize(): Promise<void> {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker(__filename);
      this.workers.push(worker);
      this.availableWorkers.push(worker);

      worker.on('message', (result: WorkerResult) => {
        // Worker finished task, mark as available
        this.availableWorkers.push(worker);
        this.processQueue();
      });
    }
  }

  async execute(task: WorkerTask): Promise<WorkerResult> {
    return new Promise((resolve, reject) => {
      this.taskQueue.push({ task, resolve, reject });
      this.processQueue();
    });
  }

  private processQueue(): void {
    while (this.availableWorkers.length > 0 && this.taskQueue.length > 0) {
      const worker = this.availableWorkers.pop()!;
      const { task, resolve, reject } = this.taskQueue.shift()!;

      const timeout = setTimeout(() => {
        reject(new Error('Task timeout'));
      }, 60000);

      worker.once('message', (result: WorkerResult) => {
        clearTimeout(timeout);
        if (result.success) {
          resolve(result);
        } else {
          reject(new Error(result.error));
        }
      });

      worker.postMessage(task);
    }
  }

  async shutdown(): Promise<void> {
    for (const worker of this.workers) {
      await worker.terminate();
    }
  }
}

// Export for Electron main process
export { BrowserPool };
```

### Integration with Electron

```typescript
// electron/main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const { BrowserPool } = require('./browser-pool');

let pool: BrowserPool;

app.on('ready', async () => {
  // Initialize browser pool in background
  pool = new BrowserPool(4);
  await pool.initialize();

  // Create main window (UI only)
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadURL('http://localhost:5173');
});

// IPC handlers delegate to pool
ipcMain.handle('navigate', async (event, url) => {
  return pool.execute({ type: 'navigate', url });
});

ipcMain.handle('extract-elements', async (event) => {
  return pool.execute({ type: 'extract' });
});

ipcMain.handle('click-element', async (event, mmid) => {
  return pool.execute({ type: 'click', mmid });
});

// Progress reporting
ipcMain.handle('start-exploration', async (event, config) => {
  const exploration = new Exploration(pool, config);

  exploration.on('progress', (progress) => {
    mainWindow.webContents.send('exploration-progress', progress);
  });

  exploration.on('page-discovered', (page) => {
    mainWindow.webContents.send('page-discovered', page);
  });

  return exploration.start();
});
```

---

# Part 25: Closed-Loop Validation ("Dry Run" Mode)

## The Problem

Generated tests might:
- Have incorrect selectors
- Make wrong assertions
- Fail immediately when run
- Waste user time

## Solution: Validate Before Saving

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Generation                           │
│                                                             │
│  AI generates test code                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Dry Run Validation                        │
│                                                             │
│  1. Parse generated test code                               │
│  2. Execute in isolated browser                             │
│  3. Check for errors                                        │
│  4. Verify assertions                                       │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│   Test Passed       │             │   Test Failed       │
│                     │             │                     │
│   → Save as         │             │   → Attempt auto-   │
│     "Verified"      │             │     fix (3 tries)   │
│                     │             │   → If still fails, │
│                     │             │     save as "Draft" │
└─────────────────────┘             └─────────────────────┘
```

### Dry Run Implementation

```typescript
interface DryRunResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  executionTimeMs: number;
  screenshotOnFailure?: string;
}

async function dryRunTest(testCode: string, config: DryRunConfig): Promise<DryRunResult> {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const errors: string[] = [];
  const warnings: string[] = [];
  const startTime = Date.now();

  try {
    // Create a test function from the generated code
    const testFn = new Function('page', 'expect', `
      return (async () => {
        ${testCode}
      })();
    `);

    // Custom expect that captures failures
    const expect = createMockExpect((error) => {
      errors.push(error.message);
    });

    // Run the test
    await testFn(page, expect);

    return {
      passed: errors.length === 0,
      errors,
      warnings,
      executionTimeMs: Date.now() - startTime
    };

  } catch (error) {
    // Capture screenshot on error
    const screenshot = await page.screenshot({ type: 'png' });

    return {
      passed: false,
      errors: [(error as Error).message],
      warnings,
      executionTimeMs: Date.now() - startTime,
      screenshotOnFailure: screenshot.toString('base64')
    };

  } finally {
    await browser.close();
  }
}
```

### Auto-Fix Loop

```typescript
interface TestWithValidation {
  code: string;
  status: 'verified' | 'draft' | 'failed';
  dryRunAttempts: number;
  errors: string[];
  fixHistory: string[];
}

async function generateAndValidateTest(
  element: Element,
  context: PageContext,
  maxAttempts: number = 3
): Promise<TestWithValidation> {

  let testCode = await generateTestCode(element, context);
  let attempts = 0;
  const fixHistory: string[] = [];

  while (attempts < maxAttempts) {
    attempts++;

    const result = await dryRunTest(testCode, { timeout: 10000 });

    if (result.passed) {
      return {
        code: testCode,
        status: 'verified',
        dryRunAttempts: attempts,
        errors: [],
        fixHistory
      };
    }

    // Attempt to fix based on error
    const fixPrompt = `
      The following test failed with error: ${result.errors.join(', ')}

      Original test:
      ${testCode}

      Please fix the test. Common issues:
      - Wrong selector (try more specific or different strategy)
      - Wrong assertion (check actual vs expected)
      - Missing wait (add await or waitFor)
      - Wrong URL (check navigation)
    `;

    fixHistory.push(`Attempt ${attempts}: ${result.errors.join(', ')}`);
    testCode = await llmFix(fixPrompt, testCode);
  }

  // Failed after all attempts
  return {
    code: testCode,
    status: 'draft',
    dryRunAttempts: attempts,
    errors: fixHistory,
    fixHistory
  };
}
```

### Output Classification

```typescript
interface TestSuiteOutput {
  verified: TestWithValidation[];   // Passed dry run - high confidence
  drafts: TestWithValidation[];     // Failed dry run - needs human review
  skipped: Element[];               // Elements we couldn't test
  summary: {
    totalGenerated: number;
    verifiedCount: number;
    draftCount: number;
    verificationRate: number;       // verified / total
  };
}

// User sees clear distinction
function formatOutput(suite: TestSuiteOutput): string {
  return `
## Test Suite Generated

### ✅ Verified Tests (${suite.verified.length})
These tests passed dry-run validation and are ready to use.

${suite.verified.map(t => formatTest(t)).join('\n')}

### ⚠️ Draft Tests (${suite.drafts.length})
These tests need human review. They may have:
- Incorrect selectors
- Wrong assertions
- Timing issues

${suite.drafts.map(t => formatDraftTest(t)).join('\n')}

### Summary
- Verification rate: ${(suite.summary.verificationRate * 100).toFixed(1)}%
- Ready to run: ${suite.summary.verifiedCount} tests
- Need review: ${suite.summary.draftCount} tests
  `;
}
```

---

# Part 26: Prompt Caching & RAG Strategy

## The Problem

Sending entire app context with every prompt:
- Expensive (more tokens = more cost)
- Slow (larger prompts = longer latency)
- Context window limits (can't fit everything)

## Solution: Smart Context Management

### 1. Prompt Caching (Provider-Level)

```typescript
// Use provider caching features
const CACHED_SYSTEM_PROMPT = `
You are a test generation AI for web applications.
You generate Playwright tests following these patterns:
...
[Long system prompt that rarely changes]
`;

// Anthropic caching
const response = await anthropic.messages.create({
  model: 'claude-sonnet-4-20250514',
  system: [
    {
      type: 'text',
      text: CACHED_SYSTEM_PROMPT,
      cache_control: { type: 'ephemeral' }  // Cache this part
    }
  ],
  messages: [
    { role: 'user', content: dynamicPrompt }  // Only this changes
  ]
});

// OpenAI predicted outputs (for structured output)
const response = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [...],
  prediction: {
    type: 'content',
    content: 'test(\' ... '  // Predict test structure
  }
});
```

### 2. RAG for Context Retrieval

```typescript
// Don't send entire app context - retrieve relevant parts

interface AppKnowledge {
  pages: Map<string, PageInfo>;
  flows: Flow[];
  patterns: Pattern[];
  corrections: Correction[];
}

class ContextRetriever {
  private embeddings: Map<string, number[]> = new Map();

  // Index app knowledge
  async index(knowledge: AppKnowledge): Promise<void> {
    for (const [url, page] of knowledge.pages) {
      const embedding = await embed(page.description);
      this.embeddings.set(url, embedding);
    }
  }

  // Retrieve relevant context for a query
  async retrieve(query: string, k: number = 5): Promise<string[]> {
    const queryEmbedding = await embed(query);

    // Find most similar pages
    const similarities = Array.from(this.embeddings.entries())
      .map(([url, emb]) => ({
        url,
        similarity: cosineSimilarity(queryEmbedding, emb)
      }))
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, k);

    return similarities.map(s => s.url);
  }
}

// Usage in test generation
async function generateWithRAG(element: Element, page: PageInfo): Promise<string> {
  // Retrieve only relevant context
  const relevantPages = await retriever.retrieve(
    `${element.name} ${element.role} on ${page.url}`,
    3
  );

  const context = relevantPages.map(url => appKnowledge.pages.get(url)!);

  // Much smaller prompt
  const prompt = `
    Generate test for: ${element.name} (${element.role})
    On page: ${page.url}

    Related context:
    ${context.map(p => `- ${p.url}: ${p.description}`).join('\n')}

    Element details:
    ${JSON.stringify(element, null, 2)}
  `;

  return llm.complete(prompt);
}
```

### 3. Hierarchical Context

```typescript
// Level 1: Always included (cached)
const SYSTEM_CONTEXT = `
  Test generation rules...
  Output format...
  Best practices...
`;

// Level 2: App-level (cached per session)
const APP_CONTEXT = `
  App type: ${appType}
  Main flows: ${flows.join(', ')}
  Auth required: ${hasAuth}
`;

// Level 3: Page-level (changes per page)
const PAGE_CONTEXT = `
  URL: ${url}
  Page type: ${pageType}
  Elements: ${elementCount}
`;

// Level 4: Element-level (changes per element)
const ELEMENT_CONTEXT = `
  Element: ${element.name}
  Type: ${element.role}
  Attributes: ${JSON.stringify(element.attributes)}
`;

// Compose prompt with appropriate detail level
function buildPrompt(task: 'classify' | 'generate', element: Element): string {
  switch (task) {
    case 'classify':
      // Classification needs less context
      return `${SYSTEM_CONTEXT}\n${PAGE_CONTEXT}\n${ELEMENT_CONTEXT}`;

    case 'generate':
      // Generation needs more context
      return `${SYSTEM_CONTEXT}\n${APP_CONTEXT}\n${PAGE_CONTEXT}\n${ELEMENT_CONTEXT}`;
  }
}
```

### Token Budget Management

```typescript
interface TokenBudget {
  system: number;      // 2000 tokens - cached
  appContext: number;  // 1000 tokens - per session
  pageContext: number; // 500 tokens - per page
  element: number;     // 200 tokens - per element
  response: number;    // 1000 tokens - reserved for output
  total: number;       // 4700 tokens max per call
}

function trimToFit(content: string, maxTokens: number): string {
  const tokens = countTokens(content);
  if (tokens <= maxTokens) return content;

  // Truncate intelligently (keep start and end)
  const ratio = maxTokens / tokens;
  const keepChars = Math.floor(content.length * ratio * 0.9);
  const half = Math.floor(keepChars / 2);

  return content.slice(0, half) + '\n...[truncated]...\n' + content.slice(-half);
}
```

---

# Part 27: "Do Not Touch" List & Human Labeling Queue

## The Problem

Some elements are:
- Ambiguous (can't tell what they do)
- Dangerous (might cause damage)
- Complex (need human understanding)

## Solution: Confidence-Based Routing

```typescript
interface ElementClassification {
  element: Element;
  category: 'navigation' | 'read' | 'write' | 'destructive' | 'payment' | 'unknown';
  confidence: number;  // 0.0 - 1.0
  reasons: string[];
}

function routeElement(classification: ElementClassification): 'automate' | 'review' | 'skip' {
  // High confidence (>80%): Automate
  if (classification.confidence > 0.8) {
    // But never automate certain categories
    if (classification.category === 'payment') return 'review';
    if (classification.category === 'destructive') return 'review';
    return 'automate';
  }

  // Medium confidence (60-80%): Review
  if (classification.confidence > 0.6) {
    return 'review';
  }

  // Low confidence (<60%): Add to "Do Not Touch" list
  return 'skip';
}
```

### "Do Not Touch" List

```typescript
interface DoNotTouchEntry {
  elementSignature: string;  // Stable identifier
  reason: string;            // Why we're skipping
  confidence: number;        // How confident we are in classification
  discoveredAt: Date;
  pageUrl: string;
  screenshot?: string;       // Visual reference for human
}

class DoNotTouchList {
  entries: DoNotTouchEntry[] = [];

  add(element: Element, reason: string, confidence: number): void {
    this.entries.push({
      elementSignature: createElementSignature(element),
      reason,
      confidence,
      discoveredAt: new Date(),
      pageUrl: element.pageUrl
    });
  }

  // Export for human review
  toReviewFormat(): string {
    return `
# Elements Needing Human Review

These elements were skipped because AI confidence was too low.
Please review and either:
1. Provide classification (navigation/read/write/destructive/payment)
2. Confirm "skip" is correct
3. Add to permanent skip list

${this.entries.map(e => `
## ${e.elementSignature}
- **Page**: ${e.pageUrl}
- **Reason**: ${e.reason}
- **AI Confidence**: ${(e.confidence * 100).toFixed(1)}%
- **Discovered**: ${e.discoveredAt.toISOString()}

\`\`\`
[Review in app to see element]
\`\`\`
`).join('\n')}
    `;
  }
}
```

### Human Labeling Queue

```typescript
interface LabelingTask {
  id: string;
  element: Element;
  context: PageContext;
  aiSuggestion: string;
  aiConfidence: number;
  status: 'pending' | 'labeled' | 'skipped';
  humanLabel?: string;
  labeledBy?: string;
  labeledAt?: Date;
}

class HumanLabelingQueue {
  private tasks: Map<string, LabelingTask> = new Map();

  // Add element for human review
  enqueue(element: Element, context: PageContext, aiResult: ElementClassification): string {
    const taskId = `label-${Date.now()}-${Math.random().toString(36).slice(2)}`;

    this.tasks.set(taskId, {
      id: taskId,
      element,
      context,
      aiSuggestion: aiResult.category,
      aiConfidence: aiResult.confidence,
      status: 'pending'
    });

    return taskId;
  }

  // Get next item for human to label
  getNext(): LabelingTask | null {
    for (const task of this.tasks.values()) {
      if (task.status === 'pending') {
        return task;
      }
    }
    return null;
  }

  // Human provides label
  submitLabel(taskId: string, label: string, userId: string): void {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error('Task not found');

    task.humanLabel = label;
    task.labeledBy = userId;
    task.labeledAt = new Date();
    task.status = 'labeled';

    // Learn from this correction
    if (task.humanLabel !== task.aiSuggestion) {
      this.recordCorrection(task);
    }
  }

  // Track AI vs human disagreements for learning
  private recordCorrection(task: LabelingTask): void {
    corrections.add({
      elementSignature: createElementSignature(task.element),
      aiSaid: task.aiSuggestion,
      humanSaid: task.humanLabel!,
      context: task.context,
      timestamp: new Date()
    });

    // If same correction 3+ times, update classification rules
    const similarCorrections = corrections.filter(c =>
      c.aiSaid === task.aiSuggestion &&
      c.humanSaid === task.humanLabel
    );

    if (similarCorrections.length >= 3) {
      updateClassificationRules(similarCorrections);
    }
  }

  // UI for labeling queue
  getQueueStats(): { pending: number; labeled: number; skipped: number } {
    let pending = 0, labeled = 0, skipped = 0;
    for (const task of this.tasks.values()) {
      if (task.status === 'pending') pending++;
      if (task.status === 'labeled') labeled++;
      if (task.status === 'skipped') skipped++;
    }
    return { pending, labeled, skipped };
  }
}
```

### Integration Flow

```typescript
async function processElement(element: Element, context: PageContext): Promise<void> {
  // 1. Classify element
  const classification = await classifyElement(element, context);

  // 2. Route based on confidence
  const route = routeElement(classification);

  switch (route) {
    case 'automate':
      // High confidence - proceed automatically
      await automateElement(element, classification);
      break;

    case 'review':
      // Medium confidence - add to human queue
      labelingQueue.enqueue(element, context, classification);
      // Continue with other elements, human will review later
      break;

    case 'skip':
      // Low confidence - add to "Do Not Touch"
      doNotTouchList.add(
        element,
        `AI confidence too low: ${classification.reasons.join(', ')}`,
        classification.confidence
      );
      break;
  }
}
```

---

# Part 28: Proof of Concept Strategy

## Before Building 100-Page Crawler

Build and validate on ONE complex flow first:

### Target: saucedemo.com (Swag Labs)

Why this site:
- Well-known test site
- Login flow
- Product catalog
- Shopping cart
- Checkout flow
- Multiple test scenarios

### PoC Goals

1. **Login Flow**
   - Discover login form
   - Classify fields correctly
   - Generate login tests (valid, invalid, edge cases)
   - Dry-run validate tests

2. **Product Catalog**
   - Navigate to products
   - Identify all product cards
   - Classify "Add to Cart" buttons
   - Generate product interaction tests

3. **Checkout Flow**
   - Complete purchase flow
   - Detect multi-step process
   - Generate full E2E test

### Success Criteria

| Metric | Target |
|--------|--------|
| Pages discovered | 6/6 (100%) |
| Elements classified correctly | >90% |
| Tests generated | >20 |
| Tests passing dry-run | >80% |
| Time to complete | <5 minutes |

### PoC Code

```typescript
// poc.ts - Proof of Concept
import { chromium } from 'playwright';
import { BrowserPool } from './browser-pool';
import { NavigationGraph } from './nav-graph';
import { TestGenerator } from './test-generator';

async function runPoC() {
  console.log('Starting YaliTest PoC on saucedemo.com');

  // 1. Initialize
  const pool = new BrowserPool(2);
  await pool.initialize();

  const graph = new NavigationGraph();
  const generator = new TestGenerator();

  // 2. Discover site
  console.log('\n=== Phase 1: Discovery ===');
  const startUrl = 'https://www.saucedemo.com';

  await pool.execute({ type: 'navigate', url: startUrl });
  const elements = await pool.execute({ type: 'extract' });

  console.log(`Found ${elements.data.elements.length} elements on login page`);

  // 3. Classify elements
  console.log('\n=== Phase 2: Classification ===');
  const classified = await classifyElements(elements.data.elements);

  console.log('Classification results:');
  for (const [category, els] of Object.entries(grouped(classified, 'category'))) {
    console.log(`  ${category}: ${els.length} elements`);
  }

  // 4. Generate tests
  console.log('\n=== Phase 3: Test Generation ===');
  const tests = await generator.generateForPage({
    url: startUrl,
    elements: classified,
    pageType: 'login'
  });

  console.log(`Generated ${tests.length} tests`);

  // 5. Dry-run validation
  console.log('\n=== Phase 4: Validation ===');
  let verified = 0, failed = 0;

  for (const test of tests) {
    const result = await dryRunTest(test.code, { timeout: 5000 });
    if (result.passed) {
      verified++;
      console.log(`  ✅ ${test.name}`);
    } else {
      failed++;
      console.log(`  ❌ ${test.name}: ${result.errors[0]}`);
    }
  }

  // 6. Summary
  console.log('\n=== Results ===');
  console.log(`Tests generated: ${tests.length}`);
  console.log(`Verified: ${verified} (${(verified/tests.length*100).toFixed(1)}%)`);
  console.log(`Failed: ${failed}`);

  await pool.shutdown();
}

runPoC().catch(console.error);
```

---

# Summary: Architecture After Reviews

## Key Changes from Reviews

| Issue | Solution | Part |
|-------|----------|------|
| Infinite loops | State fingerprinting + depth limits | Part 22 |
| Simple queue cycles | Navigation Graph | Part 23 |
| Electron bottleneck | Separate Worker Pool | Part 24 |
| Unvalidated tests | Dry-run validation loop | Part 25 |
| Context explosion | Prompt caching + RAG | Part 26 |
| Low confidence elements | "Do Not Touch" + Human Queue | Part 27 |
| Premature scaling | PoC on single site first | Part 28 |

## Revised Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Electron UI (React)                       │
│  - Shows progress, results                                  │
│  - Human labeling interface                                 │
│  - Test review/export                                       │
└─────────────────────────────────────────────────────────────┘
                              │ IPC
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator                              │
│  - Navigation Graph management                              │
│  - State fingerprinting                                     │
│  - Confidence routing                                       │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Browser   │      │     LLM     │      │    Human    │
│   Worker    │      │   Router    │      │   Queue     │
│    Pool     │      │ (+ Cache)   │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Playwright │      │ DeepSeek/   │      │   Slack/    │
│  Instances  │      │ GPT-4o/     │      │   Teams     │
│  (Headless) │      │ Claude      │      │   Bot       │
└─────────────┘      └─────────────┘      └─────────────┘
```

## Next Steps (In Order)

1. **Build PoC** on saucedemo.com (Part 28)
2. **Implement Navigation Graph** (Part 23)
3. **Implement Worker Pool** (Part 24)
4. **Add Dry-run Validation** (Part 25)
5. **Add Prompt Caching** (Part 26)
6. **Build Human Labeling UI** (Part 27)
7. **Scale to multi-site testing**
