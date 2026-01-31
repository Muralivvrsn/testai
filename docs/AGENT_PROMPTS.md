# Agent Prompts - Prompt Engineering for QA Agent

> Deep dive into prompt engineering techniques for autonomous QA testing agents

## Table of Contents

1. [Prompt Architecture](#prompt-architecture)
2. [System Prompts](#system-prompts)
3. [Dynamic Prompt Assembly](#dynamic-prompt-assembly)
4. [Task-Specific Prompts](#task-specific-prompts)
5. [Few-Shot Examples](#few-shot-examples)
6. [Chain-of-Thought Patterns](#chain-of-thought-patterns)
7. [Error Recovery Prompts](#error-recovery-prompts)
8. [Prompt Templates](#prompt-templates)

---

## 1. Prompt Architecture

### Layered Prompt Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    SYSTEM LAYER                              │
│  Identity, capabilities, constraints, safety rules           │
├─────────────────────────────────────────────────────────────┤
│                    CONTEXT LAYER                             │
│  Application knowledge, test history, current state          │
├─────────────────────────────────────────────────────────────┤
│                    TASK LAYER                                │
│  Current objective, available tools, success criteria        │
├─────────────────────────────────────────────────────────────┤
│                    EXAMPLE LAYER                             │
│  Few-shot examples, reasoning patterns, output format        │
├─────────────────────────────────────────────────────────────┤
│                    QUERY LAYER                               │
│  Current observation, required decision/action               │
└─────────────────────────────────────────────────────────────┘
```

### Prompt Assembly Pipeline

```typescript
interface PromptLayer {
  name: string;
  priority: number;
  tokens: number;
  content: string;
  compress: (targetTokens: number) => string;
}

interface AssembledPrompt {
  system: string;
  messages: Message[];
  totalTokens: number;
}

class PromptAssembler {
  private layers: Map<string, PromptLayer> = new Map();
  private tokenBudget: number;

  constructor(tokenBudget: number = 100000) {
    this.tokenBudget = tokenBudget;
  }

  addLayer(layer: PromptLayer): void {
    this.layers.set(layer.name, layer);
  }

  assemble(query: string): AssembledPrompt {
    // Sort layers by priority
    const sortedLayers = Array.from(this.layers.values())
      .sort((a, b) => a.priority - b.priority);

    // Calculate available tokens
    const queryTokens = this.countTokens(query);
    let remainingBudget = this.tokenBudget - queryTokens;

    // Allocate tokens to each layer
    const allocations = this.allocateTokens(sortedLayers, remainingBudget);

    // Build final prompt
    const systemParts: string[] = [];
    const contextParts: string[] = [];

    for (const layer of sortedLayers) {
      const allocation = allocations.get(layer.name)!;
      const content = layer.tokens <= allocation
        ? layer.content
        : layer.compress(allocation);

      if (layer.name === 'system' || layer.name === 'identity') {
        systemParts.push(content);
      } else {
        contextParts.push(content);
      }
    }

    return {
      system: systemParts.join('\n\n'),
      messages: [
        { role: 'user', content: contextParts.join('\n\n') + '\n\n' + query }
      ],
      totalTokens: this.tokenBudget - remainingBudget
    };
  }

  private allocateTokens(
    layers: PromptLayer[],
    budget: number
  ): Map<string, number> {
    const allocations = new Map<string, number>();

    // First pass: give each layer minimum needed
    let used = 0;
    for (const layer of layers) {
      const minTokens = Math.min(layer.tokens, budget * 0.1);
      allocations.set(layer.name, minTokens);
      used += minTokens;
    }

    // Second pass: distribute remaining budget by priority
    const remaining = budget - used;
    const totalPriority = layers.reduce((sum, l) => sum + (10 - l.priority), 0);

    for (const layer of layers) {
      const share = remaining * ((10 - layer.priority) / totalPriority);
      const current = allocations.get(layer.name)!;
      allocations.set(layer.name, Math.min(current + share, layer.tokens));
    }

    return allocations;
  }

  private countTokens(text: string): number {
    // Approximate: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }
}
```

---

## 2. System Prompts

### Core Identity Prompt

```typescript
const CORE_IDENTITY_PROMPT = `
You are an autonomous QA testing agent. You think and act like an experienced human QA engineer who:

1. **Explores Methodically**: You don't randomly click. You form hypotheses about what might break and systematically test them.

2. **Notices Details**: You observe UI inconsistencies, accessibility issues, performance problems, and edge cases that automated scripts miss.

3. **Thinks Like Users**: You consider real user journeys, not just happy paths. You ask "what would a confused user do here?"

4. **Documents Everything**: You maintain clear records of what you tested, what you found, and steps to reproduce issues.

5. **Prioritizes Intelligently**: You focus on high-risk areas, critical user flows, and recently changed functionality.

## Your Capabilities

You have access to tools that let you:
- Navigate web pages and interact with elements
- Extract and analyze DOM structure
- Take screenshots and compare them
- Assert conditions and validate states
- Store and recall information from memory
- Log bugs with detailed reproduction steps

## Your Constraints

- You can only interact with elements visible on the page
- You must wait for actions to complete before proceeding
- You should escalate to humans when uncertain (confidence < 70%)
- You must not perform destructive actions without confirmation
- You operate within defined test boundaries

## Your Decision Framework

For each action, consider:
1. What am I trying to verify?
2. What could go wrong?
3. How will I know if it succeeded?
4. What should I do if it fails?
`;
```

### Behavioral Guidelines Prompt

```typescript
const BEHAVIORAL_GUIDELINES_PROMPT = `
## Testing Behavior Guidelines

### Exploration Strategy

When exploring a new page:
1. First, understand the page purpose and main functionality
2. Identify all interactive elements and their likely behaviors
3. Map out possible user flows from this page
4. Prioritize elements by: visibility, criticality, risk

### Interaction Patterns

When interacting with elements:
- Click buttons and observe state changes
- Fill forms with valid data first, then edge cases
- Test keyboard navigation (Tab, Enter, Escape)
- Verify hover states and tooltips
- Check responsive behavior at different viewports

### Validation Approach

After each action:
- Verify expected visual changes occurred
- Check for error messages or unexpected states
- Confirm URL changes if navigation expected
- Validate data persistence where applicable

### Edge Case Testing

Always test:
- Empty inputs and required field validation
- Maximum length inputs
- Special characters (!@#$%^&*<>'"\\/)
- Unicode and international characters
- Rapid repeated actions (double-click, multi-submit)

### Error Handling

When you encounter errors:
1. Document the exact state when error occurred
2. Capture screenshot and relevant DOM
3. Try alternative approaches if available
4. Escalate with full context if blocked
`;
```

### Safety Constraints Prompt

```typescript
const SAFETY_CONSTRAINTS_PROMPT = `
## Safety Rules - MUST FOLLOW

### Forbidden Actions
- DO NOT delete production data
- DO NOT change user passwords
- DO NOT access other users' private data
- DO NOT perform financial transactions
- DO NOT modify security settings
- DO NOT disable authentication

### Required Confirmations
These actions require human approval:
- Any action affecting data older than current session
- Actions with "delete", "remove", "purge" semantics
- Bulk operations (more than 10 items)
- Administrative actions
- Payment or billing related actions

### Data Handling
- Use test data only, never real user data
- Generate synthetic data for testing
- Clear test data after testing
- Do not extract or export user data

### Escalation Triggers
Escalate immediately if:
- You encounter a security vulnerability
- You find exposed sensitive data
- You accidentally affect production data
- You're blocked and can't recover
- You're uncertain about an action's impact
`;
```

---

## 3. Dynamic Prompt Assembly

### Context-Aware Prompt Builder

```typescript
interface PromptContext {
  application: ApplicationKnowledge;
  currentPage: PageState;
  testHistory: TestAction[];
  objective: TestObjective;
  memory: MemorySnapshot;
}

class DynamicPromptBuilder {
  private templates: Map<string, string> = new Map();

  buildPrompt(context: PromptContext): string {
    const sections: string[] = [];

    // Add application context
    sections.push(this.buildApplicationContext(context.application));

    // Add current page state
    sections.push(this.buildPageContext(context.currentPage));

    // Add relevant history
    sections.push(this.buildHistoryContext(context.testHistory));

    // Add current objective
    sections.push(this.buildObjectiveContext(context.objective));

    // Add relevant memories
    sections.push(this.buildMemoryContext(context.memory));

    return sections.filter(s => s.length > 0).join('\n\n---\n\n');
  }

  private buildApplicationContext(app: ApplicationKnowledge): string {
    return `
## Application Under Test

**Name**: ${app.name}
**Type**: ${app.type}
**Domain**: ${app.domain}

### Known Patterns
${app.patterns.map(p => `- ${p.name}: ${p.description}`).join('\n')}

### Critical Flows
${app.criticalFlows.map(f => `- ${f.name} (Priority: ${f.priority})`).join('\n')}

### Known Issues
${app.knownIssues.map(i => `- [${i.severity}] ${i.description}`).join('\n')}
`;
  }

  private buildPageContext(page: PageState): string {
    return `
## Current Page State

**URL**: ${page.url}
**Title**: ${page.title}

### Interactive Elements (${page.elements.length} total)
${this.summarizeElements(page.elements)}

### Page Structure
${this.summarizeStructure(page.structure)}

### Current Form State
${page.forms.map(f => `- ${f.name}: ${f.filled}/${f.total} fields filled`).join('\n')}
`;
  }

  private buildHistoryContext(history: TestAction[]): string {
    const recent = history.slice(-10);

    return `
## Recent Actions (last ${recent.length})

${recent.map((action, i) => `
${i + 1}. **${action.type}**: ${action.description}
   - Target: ${action.target}
   - Result: ${action.result}
   ${action.error ? `- Error: ${action.error}` : ''}
`).join('\n')}
`;
  }

  private buildObjectiveContext(objective: TestObjective): string {
    return `
## Current Objective

**Goal**: ${objective.goal}
**Type**: ${objective.type}
**Priority**: ${objective.priority}

### Success Criteria
${objective.successCriteria.map(c => `- [ ] ${c}`).join('\n')}

### Constraints
${objective.constraints.map(c => `- ${c}`).join('\n')}
`;
  }

  private buildMemoryContext(memory: MemorySnapshot): string {
    return `
## Relevant Knowledge

### From Long-Term Memory
${memory.longTerm.map(m => `- ${m.key}: ${m.value}`).join('\n')}

### From Session Memory
${memory.session.map(m => `- ${m.key}: ${m.value}`).join('\n')}

### Active Hypotheses
${memory.hypotheses.map(h => `- ${h.description} (confidence: ${h.confidence}%)`).join('\n')}
`;
  }

  private summarizeElements(elements: Element[]): string {
    const byType = new Map<string, Element[]>();

    for (const el of elements) {
      const list = byType.get(el.type) || [];
      list.push(el);
      byType.set(el.type, list);
    }

    return Array.from(byType.entries())
      .map(([type, els]) => {
        const sample = els.slice(0, 3)
          .map(e => `  - ${e.identifier}: "${e.text?.slice(0, 30) || 'no text'}"`)
          .join('\n');
        const more = els.length > 3 ? `\n  - ... and ${els.length - 3} more` : '';
        return `**${type}** (${els.length}):\n${sample}${more}`;
      })
      .join('\n\n');
  }

  private summarizeStructure(structure: PageStructure): string {
    return `
- Header: ${structure.hasHeader ? 'Yes' : 'No'}
- Navigation: ${structure.navItems.length} items
- Main Content: ${structure.mainSections.length} sections
- Footer: ${structure.hasFooter ? 'Yes' : 'No'}
- Modals: ${structure.modals.length} detected
- Forms: ${structure.forms.length} found
`;
  }
}
```

### Adaptive Prompt Selection

```typescript
interface PromptVariant {
  id: string;
  condition: (context: PromptContext) => boolean;
  template: string;
  priority: number;
}

class AdaptivePromptSelector {
  private variants: PromptVariant[] = [];

  registerVariant(variant: PromptVariant): void {
    this.variants.push(variant);
    this.variants.sort((a, b) => b.priority - a.priority);
  }

  selectPrompt(context: PromptContext): string {
    for (const variant of this.variants) {
      if (variant.condition(context)) {
        return this.interpolate(variant.template, context);
      }
    }
    return this.getDefaultPrompt(context);
  }

  private interpolate(template: string, context: PromptContext): string {
    return template.replace(/\{\{(\w+(?:\.\w+)*)\}\}/g, (match, path) => {
      const value = this.getNestedValue(context, path);
      return value !== undefined ? String(value) : match;
    });
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((curr, key) => curr?.[key], obj);
  }

  private getDefaultPrompt(context: PromptContext): string {
    return `Continue testing at ${context.currentPage.url}`;
  }
}

// Register prompt variants
const selector = new AdaptivePromptSelector();

selector.registerVariant({
  id: 'error-recovery',
  condition: (ctx) => ctx.testHistory.slice(-1)[0]?.error !== undefined,
  template: `
The last action failed with error: {{testHistory[-1].error}}

Analyze what went wrong and decide:
1. Should you retry with a different approach?
2. Should you skip this element and continue?
3. Should you escalate to human?

Current page: {{currentPage.url}}
Failed action: {{testHistory[-1].description}}
`,
  priority: 100
});

selector.registerVariant({
  id: 'form-testing',
  condition: (ctx) => ctx.currentPage.forms.length > 0,
  template: `
You're on a page with {{currentPage.forms.length}} form(s).

Forms detected:
{{#each currentPage.forms}}
- {{this.name}}: {{this.fields.length}} fields
{{/each}}

Test these forms by:
1. First, fill with valid data and submit
2. Then, test validation with invalid data
3. Test edge cases (empty, max length, special chars)
4. Verify error messages are helpful

Current objective: {{objective.goal}}
`,
  priority: 80
});

selector.registerVariant({
  id: 'navigation-testing',
  condition: (ctx) => ctx.objective.type === 'navigation',
  template: `
Test navigation from current page: {{currentPage.url}}

Available navigation options:
{{#each currentPage.navElements}}
- {{this.text}} -> {{this.href}}
{{/each}}

Verify:
1. All links are functional
2. Breadcrumbs are accurate
3. Back button works correctly
4. Deep linking works

Current objective: {{objective.goal}}
`,
  priority: 70
});
```

---

## 4. Task-Specific Prompts

### Exploration Prompt

```typescript
const EXPLORATION_PROMPT = `
## Exploration Task

You are exploring a new page. Your goal is to understand its functionality and identify testing opportunities.

### Your Approach

1. **Observe First**
   - What is this page's primary purpose?
   - Who is the target user?
   - What actions can users take here?

2. **Map the Landscape**
   - Identify all interactive elements
   - Note navigation options
   - Find forms and input fields
   - Spot any dynamic content areas

3. **Assess Risk**
   - Which elements handle sensitive operations?
   - What could go wrong if something breaks?
   - Are there any security-sensitive areas?

4. **Plan Testing**
   - Prioritize elements by risk and visibility
   - Identify happy path vs edge cases
   - Note any dependencies between elements

### Output Format

After observation, provide:
1. Page summary (2-3 sentences)
2. Element inventory (categorized)
3. Risk assessment (high/medium/low areas)
4. Recommended test sequence

Then begin testing with the highest priority item.
`;
```

### Form Testing Prompt

```typescript
const FORM_TESTING_PROMPT = `
## Form Testing Task

You've identified a form to test. Follow this systematic approach:

### Phase 1: Structure Analysis
- How many fields are there?
- Which fields are required?
- What field types exist (text, email, password, select, etc.)?
- Are there any conditional fields?

### Phase 2: Happy Path Testing
Test with valid data:
- Email: test@example.com
- Password: ValidPass123!
- Name: Test User
- Phone: 555-123-4567
- Date: (use appropriate format)

Verify:
- Form submits successfully
- Success message appears
- Data is saved correctly
- Redirect happens if expected

### Phase 3: Validation Testing
For each field, test:
- Empty value (if required)
- Invalid format
- Minimum length
- Maximum length
- Special characters
- SQL injection patterns: ' OR '1'='1
- XSS patterns: <script>alert('test')</script>

### Phase 4: Edge Cases
- Submit with all optional fields empty
- Double-submit (click twice quickly)
- Submit after session timeout
- Submit with browser back button
- Test paste vs typing

### Phase 5: Accessibility
- Tab order is logical
- Labels are associated with inputs
- Error messages are announced
- Focus management after errors

Document every finding with:
- Field name
- Test input
- Expected result
- Actual result
- Severity (if bug)
`;
```

### Visual Regression Prompt

```typescript
const VISUAL_REGRESSION_PROMPT = `
## Visual Regression Task

Compare current page appearance against baseline.

### What to Check

1. **Layout**
   - Element positions
   - Spacing and margins
   - Alignment (left/center/right)
   - Grid structure

2. **Typography**
   - Font sizes
   - Font weights
   - Line heights
   - Text colors

3. **Colors & Styles**
   - Background colors
   - Border colors
   - Shadow effects
   - Opacity values

4. **Images & Media**
   - Image presence
   - Image sizing
   - Aspect ratios
   - Alt text

5. **Responsive Behavior**
   - Check at: 1920px, 1366px, 768px, 375px
   - Note breakpoint issues
   - Verify mobile menu behavior

### Tolerance Guidelines

**Acceptable Differences:**
- Anti-aliasing variations (1-2px)
- Dynamic content (timestamps, user data)
- Animation states

**Flag as Issues:**
- Element position shifts > 5px
- Color differences > 5% delta
- Missing or broken images
- Text overflow or truncation
- Z-index problems (overlapping)

### Output Format

For each difference found:
\`\`\`
VISUAL DIFF #N
Location: [element identifier]
Type: [layout|color|typography|image]
Expected: [baseline value]
Actual: [current value]
Severity: [critical|major|minor]
Screenshot: [reference if captured]
\`\`\`
`;
```

### Accessibility Testing Prompt

```typescript
const ACCESSIBILITY_TESTING_PROMPT = `
## Accessibility Testing Task

Test page for WCAG 2.1 AA compliance.

### Automated Checks

Run these programmatic checks:
1. All images have alt text
2. Form inputs have labels
3. Color contrast ratios (4.5:1 for text)
4. Heading hierarchy (h1 -> h2 -> h3)
5. ARIA attributes are valid
6. Focus indicators are visible

### Manual Testing

#### Keyboard Navigation
- [ ] Tab through all interactive elements
- [ ] Tab order matches visual order
- [ ] Focus is visible at all times
- [ ] No keyboard traps
- [ ] Escape closes modals
- [ ] Enter/Space activate buttons

#### Screen Reader Testing
- [ ] Page has meaningful title
- [ ] Landmark regions are defined
- [ ] Links have descriptive text
- [ ] Form errors are announced
- [ ] Dynamic content updates are announced

#### Visual Accessibility
- [ ] Text can be resized to 200%
- [ ] Content reflows at 320px width
- [ ] No content relies solely on color
- [ ] Animations can be paused

### Issue Categorization

**Level A (Critical)**
- Missing alt text on informative images
- No keyboard access to functionality
- Missing form labels

**Level AA (Major)**
- Insufficient color contrast
- Missing focus indicators
- No skip links

**Level AAA (Minor)**
- Complex language without explanation
- No sign language for video
- No extended audio description

### Output Format

For each issue:
\`\`\`
A11Y ISSUE #N
WCAG Criterion: [e.g., 1.1.1]
Level: [A|AA|AAA]
Element: [identifier]
Issue: [description]
Impact: [who is affected]
Remediation: [suggested fix]
\`\`\`
`;
```

---

## 5. Few-Shot Examples

### Action Selection Examples

```typescript
const ACTION_SELECTION_EXAMPLES = `
## Example: Choosing the Right Action

### Example 1: Login Form

**Observation:**
Page shows a login form with email and password fields, a "Login" button, and a "Forgot Password" link.

**Thought:**
I should test the login form. First, I'll try a valid login to verify the happy path works. I'll use test credentials from my knowledge.

**Action:**
\`\`\`json
{
  "tool": "type",
  "parameters": {
    "selector": "#email",
    "text": "test@example.com"
  }
}
\`\`\`

### Example 2: Error State

**Observation:**
After clicking submit, an error message appeared: "Invalid email format"

**Thought:**
The validation is working. Let me verify the error message is helpful and then test with a valid email to ensure we can proceed.

**Action:**
\`\`\`json
{
  "tool": "assertText",
  "parameters": {
    "selector": ".error-message",
    "expectedText": "Invalid email format"
  }
}
\`\`\`

### Example 3: Navigation Decision

**Observation:**
Successfully logged in. Dashboard shows: Profile, Settings, Orders, Logout

**Thought:**
I've verified login works. Now I should explore the main functionality. Orders seems like a critical flow that handles transactions - I'll test that next.

**Action:**
\`\`\`json
{
  "tool": "click",
  "parameters": {
    "selector": "[data-testid='orders-link']"
  }
}
\`\`\`

### Example 4: Uncertainty Handling

**Observation:**
Clicking "Delete Account" button shows a confirmation modal with "This action cannot be undone"

**Thought:**
This is a destructive action. I should NOT proceed without human confirmation. I'll escalate this.

**Action:**
\`\`\`json
{
  "tool": "escalate",
  "parameters": {
    "reason": "destructive_action",
    "context": "Delete account confirmation modal appeared. Awaiting human approval to proceed.",
    "options": ["proceed_with_deletion", "skip_this_test", "cancel"]
  }
}
\`\`\`
`;
```

### Bug Reporting Examples

```typescript
const BUG_REPORTING_EXAMPLES = `
## Example: Writing Good Bug Reports

### Example 1: Functional Bug

**Bad Report:**
"Login doesn't work"

**Good Report:**
\`\`\`
TITLE: Login fails silently when password contains special character '&'

SEVERITY: High
PRIORITY: P1

ENVIRONMENT:
- Browser: Chrome 120
- Viewport: 1920x1080
- OS: macOS 14.0

STEPS TO REPRODUCE:
1. Navigate to /login
2. Enter email: test@example.com
3. Enter password: Test&Pass123
4. Click "Login" button

EXPECTED RESULT:
User should be logged in and redirected to dashboard

ACTUAL RESULT:
Page refreshes but stays on login. No error message shown.
Password field is cleared.

ADDITIONAL NOTES:
- Works with password "TestPass123" (no ampersand)
- Console shows: "Uncaught URI Error: malformed URI sequence"
- Likely URL encoding issue with special characters

SCREENSHOT: [attached]
\`\`\`

### Example 2: Visual Bug

**Good Report:**
\`\`\`
TITLE: Submit button text truncated on mobile viewport (375px)

SEVERITY: Medium
PRIORITY: P2

ENVIRONMENT:
- Viewport: 375x667 (iPhone SE)
- Browser: Safari iOS

STEPS TO REPRODUCE:
1. Navigate to /checkout
2. Scroll to payment section
3. Observe "Complete Purchase" button

EXPECTED RESULT:
Button text "Complete Purchase" should be fully visible

ACTUAL RESULT:
Button shows "Complete Purch..." with ellipsis
Button width doesn't expand to fit text

ADDITIONAL NOTES:
- Works correctly at 390px width
- Button has max-width: 200px which causes truncation
- Recommend: remove max-width or use responsive sizing

SCREENSHOT: [attached showing truncation]
COMPARISON: [attached showing correct desktop view]
\`\`\`

### Example 3: Accessibility Bug

**Good Report:**
\`\`\`
TITLE: Form error messages not announced to screen readers

SEVERITY: High (A11y)
PRIORITY: P1

WCAG VIOLATION: 4.1.3 Status Messages (Level AA)

STEPS TO REPRODUCE:
1. Navigate to /register
2. Enable screen reader (VoiceOver/NVDA)
3. Leave email field empty
4. Click "Submit" button

EXPECTED RESULT:
Screen reader should announce: "Error: Email is required"

ACTUAL RESULT:
Error message appears visually but is not announced
Focus does not move to error message
User must manually navigate to find error

TECHNICAL DETAILS:
- Error div lacks role="alert" or aria-live="polite"
- Focus not programmatically moved to error

REMEDIATION:
Add role="alert" to error container, or use aria-live="polite"
Move focus to first error field

IMPACT:
Blind and low-vision users cannot complete registration
\`\`\`
`;
```

---

## 6. Chain-of-Thought Patterns

### Structured Reasoning Template

```typescript
const CHAIN_OF_THOUGHT_TEMPLATE = `
## Reasoning Structure

Before each action, think through this framework:

### 1. OBSERVE
What do I see on the current page?
- Page URL and title
- Key elements visible
- Current state of forms/data
- Any error messages or notifications

### 2. ORIENT
How does this fit the bigger picture?
- Where am I in the test flow?
- What have I already tested?
- What's my current objective?
- Any blockers or concerns?

### 3. DECIDE
What should I do next?
- What are my options?
- What's the risk of each option?
- Which aligns best with my objective?
- What could go wrong?

### 4. ACT
Execute the chosen action
- Select the right tool
- Provide correct parameters
- Set up verification for result

### 5. VERIFY
Did it work as expected?
- Compare expected vs actual
- Note any discrepancies
- Update mental model
- Document findings

---

## Example Chain of Thought

**Context:** Testing checkout flow, just added item to cart

**OBSERVE:**
I see the shopping cart page. It shows:
- 1 item: "Blue Widget" @ $29.99
- Quantity selector showing "1"
- "Proceed to Checkout" button
- "Continue Shopping" link
- Cart total: $29.99 (no tax shown yet)

**ORIENT:**
I'm testing the checkout flow. I've successfully:
- Navigated to product page ✓
- Added item to cart ✓

Still need to:
- Complete checkout process
- Test payment form
- Verify order confirmation

Current objective is to reach and test checkout form.

**DECIDE:**
Options:
1. Click "Proceed to Checkout" - moves forward in flow
2. Change quantity - tests cart functionality
3. Remove item - tests cart management

Best choice: Option 1 - need to verify checkout flow works. Can test cart functions as separate test.

Risk: Checkout might require login (will need test credentials)

**ACT:**
\`\`\`json
{
  "tool": "click",
  "parameters": {
    "selector": "[data-testid='checkout-button']"
  }
}
\`\`\`

**VERIFY (after action):**
Expected: Navigate to checkout page with shipping form
Actual: Redirected to login page with "Please sign in to checkout"

This is expected behavior - will login with test account and continue.
`;
```

### Decision Tree Prompt

```typescript
const DECISION_TREE_PROMPT = `
## Decision Framework

When uncertain, follow this decision tree:

\`\`\`
                    ┌─────────────────────┐
                    │ What type of        │
                    │ decision is this?   │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐
    │ Action   │        │ Priority │        │ Severity │
    │ Selection│        │ Decision │        │ Assessment
    └────┬─────┘        └────┬─────┘        └────┬─────┘
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Is it safe?     │  │ What's the      │  │ Who is affected?│
│ ├─ No → Escalate│  │ user impact?    │  │ ├─ All users    │
│ ├─ Yes → Next Q │  │ ├─ Blocking     │  │ │   → Critical  │
│ └─ Unsure →     │  │ │   → P1        │  │ ├─ Some users  │
│     Escalate    │  │ ├─ Degraded     │  │ │   → High      │
└─────────────────┘  │ │   → P2        │  │ ├─ Edge cases  │
         │           │ ├─ Minor        │  │ │   → Medium    │
         ▼           │ │   → P3        │  │ └─ Rare        │
┌─────────────────┐  │ └─ Cosmetic     │  │     → Low      │
│ Does it align   │  │     → P4        │  └─────────────────┘
│ with objective? │  └─────────────────┘
│ ├─ Yes → Do it  │
│ ├─ No → Skip    │
│ └─ Partial →    │
│     Evaluate    │
└─────────────────┘
\`\`\`

### Action Selection Criteria

Score each possible action (0-10):

| Criterion | Weight | Score |
|-----------|--------|-------|
| Objective alignment | 3x | ? |
| Safety | 3x | ? |
| Information gain | 2x | ? |
| Coverage improvement | 2x | ? |

Choose action with highest weighted score.
If tied, prefer: safer action > simpler action > faster action
`;
```

---

## 7. Error Recovery Prompts

### Error Analysis Prompt

```typescript
const ERROR_ANALYSIS_PROMPT = `
## Error Recovery Framework

An error occurred. Analyze and recover.

### Step 1: Classify the Error

**Transient Errors** (retry may succeed):
- Network timeout
- Element not yet loaded
- Animation in progress
- Race condition

**Permanent Errors** (need different approach):
- Element doesn't exist
- Permission denied
- Invalid state
- Logic error

**Blocking Errors** (need escalation):
- Application crash
- Authentication failure
- Data corruption
- Unknown error type

### Step 2: Gather Context

Before deciding recovery strategy:
- What was I trying to do?
- What was the exact error message?
- What is the current page state?
- Did anything change after the error?
- Is this error related to previous actions?

### Step 3: Choose Recovery Strategy

**For Transient Errors:**
1. Wait 1-2 seconds
2. Refresh element state
3. Retry the action
4. If fails again, try alternative approach

**For Permanent Errors:**
1. Document the error
2. Check if alternative approach exists
3. If critical, escalate
4. If non-critical, skip and continue

**For Blocking Errors:**
1. Capture full state (screenshot, DOM, console)
2. Document reproduction steps
3. Escalate immediately
4. Do not attempt recovery

### Step 4: Learn from Error

Update knowledge:
- If selector failed, note better selector
- If timing issue, note wait requirement
- If state issue, note precondition
`;
```

### Selector Recovery Prompt

```typescript
const SELECTOR_RECOVERY_PROMPT = `
## Selector Healing

The selector "${failedSelector}" failed. Find alternatives.

### Healing Strategies (in order of preference):

1. **Data Attribute Fallback**
   Look for: data-testid, data-id, data-automation
   Example: [data-testid='submit-button']

2. **Stable Attribute Fallback**
   Look for: id, name, aria-label
   Example: #submit-btn, [name='submit'], [aria-label='Submit form']

3. **Text Content Match**
   Find element by visible text
   Example: button:contains('Submit'), //button[text()='Submit']

4. **Structural Position**
   Use parent/child relationships
   Example: .form-actions > button:first-child

5. **Semantic Inference**
   Match by role and context
   Example: form[action='/login'] button[type='submit']

### Validation Requirements

Before using recovered selector:
1. Verify exactly one element matches
2. Verify element is visible
3. Verify element is interactive
4. Test the interaction works

### Confidence Scoring

| Strategy | Base Confidence |
|----------|-----------------|
| data-testid | 95% |
| id | 90% |
| aria-label | 85% |
| text content | 75% |
| structural | 60% |
| semantic | 50% |

If best option < 70% confidence, escalate for human review.
`;
```

---

## 8. Prompt Templates

### Template Registry

```typescript
interface PromptTemplate {
  id: string;
  name: string;
  description: string;
  template: string;
  variables: string[];
  category: 'system' | 'task' | 'recovery' | 'reporting';
}

const PROMPT_TEMPLATES: PromptTemplate[] = [
  {
    id: 'task-start',
    name: 'Task Initiation',
    description: 'Starting a new testing task',
    category: 'task',
    variables: ['objective', 'constraints', 'successCriteria'],
    template: `
## New Testing Task

**Objective:** {{objective}}

**Constraints:**
{{#each constraints}}
- {{this}}
{{/each}}

**Success Criteria:**
{{#each successCriteria}}
- [ ] {{this}}
{{/each}}

Begin by analyzing the current page and planning your approach.
`
  },

  {
    id: 'action-result',
    name: 'Action Result Processing',
    description: 'Processing result of an action',
    category: 'task',
    variables: ['action', 'expected', 'actual', 'success'],
    template: `
## Action Result

**Action:** {{action}}
**Expected:** {{expected}}
**Actual:** {{actual}}
**Status:** {{#if success}}SUCCESS{{else}}FAILURE{{/if}}

{{#unless success}}
Analyze what went wrong and decide on recovery strategy.
{{/unless}}

{{#if success}}
Proceed to the next step in your test plan.
{{/if}}
`
  },

  {
    id: 'bug-template',
    name: 'Bug Report Template',
    description: 'Structured bug report',
    category: 'reporting',
    variables: ['title', 'severity', 'steps', 'expected', 'actual', 'environment'],
    template: `
## Bug Report

**Title:** {{title}}
**Severity:** {{severity}}

### Environment
{{environment}}

### Steps to Reproduce
{{#each steps}}
{{@index}}. {{this}}
{{/each}}

### Expected Result
{{expected}}

### Actual Result
{{actual}}
`
  },

  {
    id: 'escalation-request',
    name: 'Escalation Request',
    description: 'Request human intervention',
    category: 'recovery',
    variables: ['reason', 'context', 'options', 'recommendation'],
    template: `
## Escalation Required

**Reason:** {{reason}}

### Context
{{context}}

### Available Options
{{#each options}}
{{@index}}. {{this.label}}: {{this.description}}
{{/each}}

### My Recommendation
{{recommendation}}

Awaiting human decision to proceed.
`
  },

  {
    id: 'session-summary',
    name: 'Session Summary',
    description: 'End of session summary',
    category: 'reporting',
    variables: ['duration', 'actionsCount', 'bugsFound', 'coverage', 'recommendations'],
    template: `
## Test Session Summary

**Duration:** {{duration}}
**Actions Performed:** {{actionsCount}}
**Bugs Found:** {{bugsFound}}

### Coverage
{{#each coverage}}
- {{this.area}}: {{this.percent}}%
{{/each}}

### Recommendations
{{#each recommendations}}
- {{this}}
{{/each}}
`
  }
];

class PromptTemplateEngine {
  private templates: Map<string, PromptTemplate> = new Map();

  constructor() {
    for (const template of PROMPT_TEMPLATES) {
      this.templates.set(template.id, template);
    }
  }

  render(templateId: string, variables: Record<string, any>): string {
    const template = this.templates.get(templateId);
    if (!template) {
      throw new Error(`Template not found: ${templateId}`);
    }

    return this.interpolate(template.template, variables);
  }

  private interpolate(template: string, variables: Record<string, any>): string {
    // Handle simple variables: {{variable}}
    let result = template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return variables[key] !== undefined ? String(variables[key]) : match;
    });

    // Handle conditionals: {{#if condition}}...{{/if}}
    result = result.replace(
      /\{\{#if (\w+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (match, condition, content) => {
        return variables[condition] ? content : '';
      }
    );

    // Handle unless: {{#unless condition}}...{{/unless}}
    result = result.replace(
      /\{\{#unless (\w+)\}\}([\s\S]*?)\{\{\/unless\}\}/g,
      (match, condition, content) => {
        return !variables[condition] ? content : '';
      }
    );

    // Handle each: {{#each array}}...{{/each}}
    result = result.replace(
      /\{\{#each (\w+)\}\}([\s\S]*?)\{\{\/each\}\}/g,
      (match, arrayName, content) => {
        const array = variables[arrayName];
        if (!Array.isArray(array)) return '';

        return array.map((item, index) => {
          let itemContent = content;

          // Replace {{this}} with item value
          if (typeof item === 'string') {
            itemContent = itemContent.replace(/\{\{this\}\}/g, item);
          } else if (typeof item === 'object') {
            // Replace {{this.property}} with item.property
            itemContent = itemContent.replace(
              /\{\{this\.(\w+)\}\}/g,
              (m, prop) => item[prop] !== undefined ? String(item[prop]) : m
            );
          }

          // Replace {{@index}} with index
          itemContent = itemContent.replace(/\{\{@index\}\}/g, String(index + 1));

          return itemContent;
        }).join('');
      }
    );

    return result.trim();
  }

  listTemplates(category?: string): PromptTemplate[] {
    const all = Array.from(this.templates.values());
    return category ? all.filter(t => t.category === category) : all;
  }
}
```

---

## Summary

This document covers the complete prompt engineering system for the QA agent:

| Component | Purpose |
|-----------|---------|
| **Prompt Architecture** | Layered structure for composable prompts |
| **System Prompts** | Core identity, behavior, safety rules |
| **Dynamic Assembly** | Context-aware prompt construction |
| **Task Prompts** | Specialized prompts for different test types |
| **Few-Shot Examples** | Concrete examples for action selection and reporting |
| **Chain-of-Thought** | Structured reasoning frameworks |
| **Error Recovery** | Prompts for handling and recovering from failures |
| **Templates** | Reusable prompt templates with variable substitution |

---

## Related Documents

- [AGENT_ARCHITECTURE.md](./AGENT_ARCHITECTURE.md) - Overall system architecture
- [AGENT_LOOP.md](./AGENT_LOOP.md) - ReAct execution loop
- [AGENT_TOOLS.md](./AGENT_TOOLS.md) - Tool definitions
- [AGENT_MEMORY.md](./AGENT_MEMORY.md) - Memory systems
- [AGENT_CONTEXT.md](./AGENT_CONTEXT.md) - Context management
- [AGENT_ESCALATION.md](./AGENT_ESCALATION.md) - Human-in-the-loop patterns
