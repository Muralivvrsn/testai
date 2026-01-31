# Agent Escalation - Human-in-the-Loop Patterns

> Deep dive into human escalation mechanisms for autonomous QA testing agents

## Table of Contents

1. [Escalation Philosophy](#escalation-philosophy)
2. [Escalation Triggers](#escalation-triggers)
3. [Confidence Scoring](#confidence-scoring)
4. [Escalation Workflow](#escalation-workflow)
5. [Communication Protocols](#communication-protocols)
6. [Approval Mechanisms](#approval-mechanisms)
7. [Learning from Escalations](#learning-from-escalations)
8. [Emergency Procedures](#emergency-procedures)

---

## 1. Escalation Philosophy

### The Conscience Layer

The escalation system acts as the agent's "conscience" - a component that knows when to pause and ask for human guidance rather than proceeding autonomously.

```
┌─────────────────────────────────────────────────────────────┐
│                    CONSCIENCE LAYER                          │
│                                                              │
│  "Should I do this?"      "Is this right?"                  │
│          │                       │                           │
│          ▼                       ▼                           │
│  ┌───────────────┐      ┌───────────────┐                   │
│  │ Safety Check  │      │ Confidence    │                   │
│  │ - Destructive?│      │ Check         │                   │
│  │ - Reversible? │      │ - Certain?    │                   │
│  │ - Authorized? │      │ - Precedent?  │                   │
│  └───────┬───────┘      └───────┬───────┘                   │
│          │                       │                           │
│          └───────────┬───────────┘                           │
│                      ▼                                       │
│              ┌───────────────┐                               │
│              │   Decision    │                               │
│              │ - Proceed     │                               │
│              │ - Escalate    │                               │
│              │ - Abort       │                               │
│              └───────────────┘                               │
└─────────────────────────────────────────────────────────────┘
```

### Core Principles

```typescript
interface EscalationPrinciples {
  // When in doubt, escalate
  erringOnCaution: true;

  // Explain why escalating
  transparentReasoning: true;

  // Provide actionable options
  clearOptions: true;

  // Don't block on trivial decisions
  avoidOverEscalation: true;

  // Learn from human decisions
  continuousLearning: true;
}

const ESCALATION_PHILOSOPHY = `
## Guiding Principles

1. **Safety Over Speed**
   It's better to pause and ask than to cause damage.
   A few minutes of human review is worth avoiding hours of cleanup.

2. **Explain, Don't Just Ask**
   When escalating, explain:
   - What you're trying to do
   - Why you're uncertain
   - What options you see
   - What you recommend

3. **Provide Context**
   Humans shouldn't need to investigate.
   Give them everything they need to decide.

4. **Respect Human Time**
   Don't escalate trivial decisions.
   Batch related questions when possible.
   Learn from decisions to avoid repeat escalations.

5. **Maintain Momentum**
   While waiting for approval, continue safe work.
   Queue dependent tasks rather than blocking completely.
`;
```

---

## 2. Escalation Triggers

### Trigger Categories

```typescript
enum EscalationCategory {
  SAFETY = 'safety',           // Potentially harmful actions
  UNCERTAINTY = 'uncertainty', // Low confidence decisions
  ANOMALY = 'anomaly',         // Unexpected situations
  POLICY = 'policy',           // Policy-required approval
  RESOURCE = 'resource',       // Resource-intensive operations
  DISCOVERY = 'discovery'      // Important findings
}

interface EscalationTrigger {
  id: string;
  category: EscalationCategory;
  condition: (context: AgentContext) => boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  autoEscalate: boolean;
}
```

### Safety Triggers

```typescript
const SAFETY_TRIGGERS: EscalationTrigger[] = [
  {
    id: 'destructive-action',
    category: EscalationCategory.SAFETY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Action would delete or permanently modify data',
    condition: (ctx) => {
      const actionVerbs = ['delete', 'remove', 'purge', 'destroy', 'clear', 'reset'];
      const action = ctx.pendingAction?.description?.toLowerCase() || '';
      return actionVerbs.some(verb => action.includes(verb));
    }
  },

  {
    id: 'financial-action',
    category: EscalationCategory.SAFETY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Action involves financial transaction or payment',
    condition: (ctx) => {
      const financialIndicators = ['pay', 'purchase', 'charge', 'refund', 'billing'];
      const pageContent = ctx.currentPage?.text?.toLowerCase() || '';
      const action = ctx.pendingAction?.description?.toLowerCase() || '';
      return financialIndicators.some(ind =>
        pageContent.includes(ind) || action.includes(ind)
      );
    }
  },

  {
    id: 'authentication-change',
    category: EscalationCategory.SAFETY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Action would change authentication or security settings',
    condition: (ctx) => {
      const securityIndicators = ['password', 'mfa', '2fa', 'security', 'permission'];
      const action = ctx.pendingAction?.description?.toLowerCase() || '';
      return securityIndicators.some(ind => action.includes(ind));
    }
  },

  {
    id: 'bulk-operation',
    category: EscalationCategory.SAFETY,
    severity: 'high',
    autoEscalate: true,
    message: 'Action affects multiple records or users',
    condition: (ctx) => {
      const bulkIndicators = ['all', 'bulk', 'batch', 'mass', 'multiple'];
      const action = ctx.pendingAction?.description?.toLowerCase() || '';
      return bulkIndicators.some(ind => action.includes(ind));
    }
  },

  {
    id: 'production-environment',
    category: EscalationCategory.SAFETY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Detected production environment - requires confirmation',
    condition: (ctx) => {
      const url = ctx.currentPage?.url || '';
      const prodIndicators = ['prod', 'production', 'live'];
      const notProdIndicators = ['staging', 'dev', 'test', 'local', 'sandbox'];

      const isProd = prodIndicators.some(ind => url.includes(ind));
      const isNotProd = notProdIndicators.some(ind => url.includes(ind));

      return isProd && !isNotProd;
    }
  }
];
```

### Uncertainty Triggers

```typescript
const UNCERTAINTY_TRIGGERS: EscalationTrigger[] = [
  {
    id: 'low-confidence',
    category: EscalationCategory.UNCERTAINTY,
    severity: 'medium',
    autoEscalate: true,
    message: 'Confidence in action is below threshold',
    condition: (ctx) => {
      return ctx.confidence !== undefined && ctx.confidence < 70;
    }
  },

  {
    id: 'ambiguous-element',
    category: EscalationCategory.UNCERTAINTY,
    severity: 'medium',
    autoEscalate: true,
    message: 'Multiple elements match the target criteria',
    condition: (ctx) => {
      const matches = ctx.selectorMatches || 1;
      return matches > 1;
    }
  },

  {
    id: 'no-precedent',
    category: EscalationCategory.UNCERTAINTY,
    severity: 'low',
    autoEscalate: false,
    message: 'No similar action found in history',
    condition: (ctx) => {
      const similarActions = ctx.memory?.findSimilar(ctx.pendingAction, 5) || [];
      return similarActions.length === 0;
    }
  },

  {
    id: 'conflicting-signals',
    category: EscalationCategory.UNCERTAINTY,
    severity: 'high',
    autoEscalate: true,
    message: 'Received conflicting information about expected behavior',
    condition: (ctx) => {
      const expectations = ctx.expectations || [];
      if (expectations.length < 2) return false;

      // Check if expectations contradict each other
      return expectations.some((exp1, i) =>
        expectations.slice(i + 1).some(exp2 =>
          exp1.expected !== exp2.expected && exp1.element === exp2.element
        )
      );
    }
  }
];
```

### Anomaly Triggers

```typescript
const ANOMALY_TRIGGERS: EscalationTrigger[] = [
  {
    id: 'unexpected-state',
    category: EscalationCategory.ANOMALY,
    severity: 'high',
    autoEscalate: true,
    message: 'Page state differs significantly from expected',
    condition: (ctx) => {
      if (!ctx.expectedState || !ctx.actualState) return false;

      const diff = compareStates(ctx.expectedState, ctx.actualState);
      return diff.similarity < 0.5;
    }
  },

  {
    id: 'repeated-failures',
    category: EscalationCategory.ANOMALY,
    severity: 'high',
    autoEscalate: true,
    message: 'Multiple consecutive action failures detected',
    condition: (ctx) => {
      const recentActions = ctx.actionHistory?.slice(-5) || [];
      const failures = recentActions.filter(a => !a.success);
      return failures.length >= 3;
    }
  },

  {
    id: 'performance-degradation',
    category: EscalationCategory.ANOMALY,
    severity: 'medium',
    autoEscalate: false,
    message: 'Page load times significantly slower than baseline',
    condition: (ctx) => {
      const baseline = ctx.performanceBaseline?.loadTime || 3000;
      const current = ctx.currentPage?.loadTime || 0;
      return current > baseline * 3;
    }
  },

  {
    id: 'security-warning',
    category: EscalationCategory.ANOMALY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Security warning or certificate error detected',
    condition: (ctx) => {
      const pageContent = ctx.currentPage?.text || '';
      const securityWarnings = [
        'certificate',
        'not secure',
        'privacy error',
        'connection is not private'
      ];
      return securityWarnings.some(w =>
        pageContent.toLowerCase().includes(w)
      );
    }
  },

  {
    id: 'sensitive-data-exposure',
    category: EscalationCategory.ANOMALY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Potential sensitive data exposed on page',
    condition: (ctx) => {
      const pageContent = ctx.currentPage?.text || '';
      // Check for patterns that look like sensitive data
      const patterns = [
        /\b\d{3}-\d{2}-\d{4}\b/,  // SSN
        /\b\d{16}\b/,             // Credit card
        /password\s*[:=]\s*\S+/i,  // Exposed password
        /api[_-]?key\s*[:=]\s*\S+/i  // API key
      ];
      return patterns.some(p => p.test(pageContent));
    }
  }
];
```

### Discovery Triggers

```typescript
const DISCOVERY_TRIGGERS: EscalationTrigger[] = [
  {
    id: 'critical-bug',
    category: EscalationCategory.DISCOVERY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Critical bug discovered that blocks core functionality',
    condition: (ctx) => {
      return ctx.currentBug?.severity === 'critical';
    }
  },

  {
    id: 'security-vulnerability',
    category: EscalationCategory.DISCOVERY,
    severity: 'critical',
    autoEscalate: true,
    message: 'Potential security vulnerability discovered',
    condition: (ctx) => {
      return ctx.currentBug?.type === 'security';
    }
  },

  {
    id: 'data-inconsistency',
    category: EscalationCategory.DISCOVERY,
    severity: 'high',
    autoEscalate: true,
    message: 'Data inconsistency detected between pages or components',
    condition: (ctx) => {
      return ctx.observations?.some(o => o.type === 'data-mismatch');
    }
  }
];
```

### Trigger Evaluation Engine

```typescript
class TriggerEvaluator {
  private triggers: EscalationTrigger[] = [];

  constructor() {
    this.triggers = [
      ...SAFETY_TRIGGERS,
      ...UNCERTAINTY_TRIGGERS,
      ...ANOMALY_TRIGGERS,
      ...DISCOVERY_TRIGGERS
    ];
  }

  evaluate(context: AgentContext): EscalationTrigger[] {
    const triggered: EscalationTrigger[] = [];

    for (const trigger of this.triggers) {
      try {
        if (trigger.condition(context)) {
          triggered.push(trigger);
        }
      } catch (error) {
        console.error(`Error evaluating trigger ${trigger.id}:`, error);
      }
    }

    // Sort by severity
    return triggered.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  shouldEscalate(triggers: EscalationTrigger[]): boolean {
    // Always escalate if any critical trigger
    if (triggers.some(t => t.severity === 'critical')) {
      return true;
    }

    // Escalate if auto-escalate triggers present
    if (triggers.some(t => t.autoEscalate)) {
      return true;
    }

    // Escalate if multiple high-severity triggers
    const highSeverity = triggers.filter(t => t.severity === 'high');
    if (highSeverity.length >= 2) {
      return true;
    }

    return false;
  }
}
```

---

## 3. Confidence Scoring

### Multi-Factor Confidence Model

```typescript
interface ConfidenceFactors {
  // How certain are we about the action itself?
  actionClarity: number;      // 0-100

  // How reliable is our selector/target?
  selectorReliability: number; // 0-100

  // How predictable is the expected outcome?
  outcomePredictability: number; // 0-100

  // Have we done this successfully before?
  historicalSuccess: number;  // 0-100

  // How stable is the current page state?
  stateStability: number;     // 0-100
}

class ConfidenceCalculator {
  private weights: Record<keyof ConfidenceFactors, number> = {
    actionClarity: 0.25,
    selectorReliability: 0.25,
    outcomePredictability: 0.20,
    historicalSuccess: 0.15,
    stateStability: 0.15
  };

  calculate(factors: ConfidenceFactors): number {
    let totalWeight = 0;
    let weightedSum = 0;

    for (const [factor, value] of Object.entries(factors)) {
      const weight = this.weights[factor as keyof ConfidenceFactors];
      weightedSum += value * weight;
      totalWeight += weight;
    }

    return Math.round(weightedSum / totalWeight);
  }

  calculateActionClarity(action: PendingAction): number {
    let score = 100;

    // Reduce score for ambiguous actions
    if (!action.description) score -= 30;
    if (!action.expectedOutcome) score -= 20;
    if (action.alternatives?.length > 2) score -= 15;

    // Reduce for complex actions
    if (action.steps?.length > 3) score -= 10;

    return Math.max(0, score);
  }

  calculateSelectorReliability(selector: string, matches: number): number {
    let score = 100;

    // Penalize for multiple matches
    if (matches > 1) score -= 30;
    if (matches > 5) score -= 20;
    if (matches === 0) return 0;

    // Reward stable selectors
    if (selector.includes('[data-testid=')) score += 10;
    if (selector.includes('#')) score += 5;
    if (selector.includes('[aria-label=')) score += 5;

    // Penalize fragile selectors
    if (selector.includes(':nth-child')) score -= 15;
    if (selector.split('>').length > 3) score -= 10;
    if (selector.includes(':not(')) score -= 5;

    return Math.min(100, Math.max(0, score));
  }

  calculateHistoricalSuccess(
    action: PendingAction,
    history: ActionRecord[]
  ): number {
    // Find similar actions in history
    const similar = history.filter(h =>
      h.type === action.type &&
      this.isSimilarTarget(h.target, action.target)
    );

    if (similar.length === 0) return 50; // No history, neutral

    const successes = similar.filter(s => s.success).length;
    return Math.round((successes / similar.length) * 100);
  }

  private isSimilarTarget(target1: string, target2: string): boolean {
    // Check if targets reference same element type/pattern
    const normalize = (t: string) => t.replace(/\d+/g, 'N').toLowerCase();
    return normalize(target1) === normalize(target2);
  }
}
```

### Confidence Thresholds

```typescript
interface ConfidenceThresholds {
  // Above this: proceed automatically
  autoApprove: number;

  // Below this: always escalate
  alwaysEscalate: number;

  // Between thresholds: context-dependent
  contextualMin: number;
}

const DEFAULT_THRESHOLDS: ConfidenceThresholds = {
  autoApprove: 85,
  alwaysEscalate: 50,
  contextualMin: 70
};

class ConfidencePolicy {
  private thresholds: ConfidenceThresholds;

  constructor(thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS) {
    this.thresholds = thresholds;
  }

  shouldProceed(confidence: number, context: AgentContext): Decision {
    // High confidence: proceed
    if (confidence >= this.thresholds.autoApprove) {
      return { action: 'proceed', reason: 'High confidence' };
    }

    // Low confidence: escalate
    if (confidence < this.thresholds.alwaysEscalate) {
      return {
        action: 'escalate',
        reason: `Low confidence (${confidence}%)`
      };
    }

    // Medium confidence: check context
    return this.evaluateContext(confidence, context);
  }

  private evaluateContext(
    confidence: number,
    context: AgentContext
  ): Decision {
    // Allow lower confidence for reversible actions
    if (context.pendingAction?.reversible) {
      const adjustedThreshold = this.thresholds.contextualMin - 10;
      if (confidence >= adjustedThreshold) {
        return { action: 'proceed', reason: 'Reversible action' };
      }
    }

    // Require higher confidence for new pages
    if (!context.memory?.hasVisited(context.currentPage?.url)) {
      const adjustedThreshold = this.thresholds.contextualMin + 10;
      if (confidence < adjustedThreshold) {
        return {
          action: 'escalate',
          reason: 'New page requires higher confidence'
        };
      }
    }

    // Default: use contextual minimum
    if (confidence >= this.thresholds.contextualMin) {
      return { action: 'proceed', reason: 'Adequate confidence' };
    }

    return {
      action: 'escalate',
      reason: `Confidence ${confidence}% below threshold ${this.thresholds.contextualMin}%`
    };
  }
}
```

---

## 4. Escalation Workflow

### Escalation State Machine

```
┌─────────────────────────────────────────────────────────────────┐
│                    ESCALATION STATE MACHINE                      │
└─────────────────────────────────────────────────────────────────┘

                         ┌─────────────┐
                         │   NORMAL    │
                         │  OPERATION  │
                         └──────┬──────┘
                                │
                    Trigger detected
                                │
                                ▼
                         ┌─────────────┐
                         │   PENDING   │
                         │  ESCALATION │
                         └──────┬──────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
       ┌──────────┐      ┌──────────┐      ┌──────────┐
       │ BLOCKING │      │   ASYNC  │      │ ADVISORY │
       │  (P1/P2) │      │  (P3/P4) │      │   (P5)   │
       └────┬─────┘      └────┬─────┘      └────┬─────┘
            │                 │                 │
    Wait for human     Continue other    Log & continue
            │               work               │
            │                 │                 │
            ▼                 ▼                 │
       ┌──────────┐      ┌──────────┐          │
       │  HUMAN   │      │  QUEUED  │          │
       │ NOTIFIED │      │ FOR HUMAN│          │
       └────┬─────┘      └────┬─────┘          │
            │                 │                 │
    Human responds     Human responds          │
            │                 │                 │
            └────────┬────────┘                 │
                     │                          │
                     ▼                          │
              ┌──────────┐                      │
              │ RESOLVED │◀─────────────────────┘
              └──────────┘
```

### Escalation Request Structure

```typescript
interface EscalationRequest {
  id: string;
  timestamp: Date;
  category: EscalationCategory;
  severity: 'critical' | 'high' | 'medium' | 'low';
  priority: 'P1' | 'P2' | 'P3' | 'P4' | 'P5';

  // What triggered this escalation
  triggers: EscalationTrigger[];

  // Context for human decision
  context: {
    currentUrl: string;
    currentState: string;
    pendingAction: PendingAction;
    relevantHistory: ActionRecord[];
    screenshots: string[];
  };

  // What we're asking
  question: string;

  // Options for human
  options: EscalationOption[];

  // Agent's recommendation (if any)
  recommendation?: {
    option: string;
    confidence: number;
    reasoning: string;
  };

  // Timeout behavior
  timeout: {
    duration: number;
    defaultAction: 'wait' | 'skip' | 'abort';
  };
}

interface EscalationOption {
  id: string;
  label: string;
  description: string;
  risk: 'none' | 'low' | 'medium' | 'high';
  reversible: boolean;
}
```

### Escalation Manager

```typescript
class EscalationManager {
  private pendingEscalations: Map<string, EscalationRequest> = new Map();
  private notificationChannel: NotificationChannel;
  private escalationHistory: EscalationRecord[] = [];

  constructor(notificationChannel: NotificationChannel) {
    this.notificationChannel = notificationChannel;
  }

  async escalate(request: EscalationRequest): Promise<EscalationResponse> {
    // Store pending escalation
    this.pendingEscalations.set(request.id, request);

    // Determine escalation mode based on priority
    const mode = this.determineMode(request.priority);

    switch (mode) {
      case 'blocking':
        return this.handleBlockingEscalation(request);

      case 'async':
        return this.handleAsyncEscalation(request);

      case 'advisory':
        return this.handleAdvisoryEscalation(request);
    }
  }

  private determineMode(priority: string): 'blocking' | 'async' | 'advisory' {
    switch (priority) {
      case 'P1':
      case 'P2':
        return 'blocking';
      case 'P3':
      case 'P4':
        return 'async';
      case 'P5':
        return 'advisory';
      default:
        return 'blocking';
    }
  }

  private async handleBlockingEscalation(
    request: EscalationRequest
  ): Promise<EscalationResponse> {
    // Notify human immediately
    await this.notificationChannel.sendUrgent({
      title: `[${request.priority}] ${request.category} Escalation`,
      message: request.question,
      options: request.options,
      requiresResponse: true
    });

    // Wait for response
    const response = await this.waitForResponse(request.id, request.timeout);

    // Record and return
    this.recordEscalation(request, response);
    return response;
  }

  private async handleAsyncEscalation(
    request: EscalationRequest
  ): Promise<EscalationResponse> {
    // Queue notification
    await this.notificationChannel.queue({
      title: `[${request.priority}] ${request.category} - Review Needed`,
      message: request.question,
      options: request.options
    });

    // Return immediately with "pending" status
    return {
      status: 'pending',
      message: 'Escalation queued for human review',
      recommendation: request.recommendation?.option
    };
  }

  private async handleAdvisoryEscalation(
    request: EscalationRequest
  ): Promise<EscalationResponse> {
    // Log for later review
    this.escalationHistory.push({
      request,
      resolvedAt: new Date(),
      resolution: 'auto-logged',
      decision: null
    });

    // Continue with recommendation or skip
    return {
      status: 'logged',
      message: 'Advisory escalation logged',
      recommendation: request.recommendation?.option || 'continue'
    };
  }

  private async waitForResponse(
    escalationId: string,
    timeout: { duration: number; defaultAction: string }
  ): Promise<EscalationResponse> {
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({
          status: 'timeout',
          message: `No response within ${timeout.duration}ms`,
          action: timeout.defaultAction
        });
      }, timeout.duration);

      // Listen for human response
      this.notificationChannel.onResponse(escalationId, (response) => {
        clearTimeout(timeoutId);
        resolve({
          status: 'resolved',
          message: response.message,
          action: response.selectedOption,
          humanId: response.responderId
        });
      });
    });
  }

  private recordEscalation(
    request: EscalationRequest,
    response: EscalationResponse
  ): void {
    this.escalationHistory.push({
      request,
      response,
      resolvedAt: new Date()
    });

    // Remove from pending
    this.pendingEscalations.delete(request.id);
  }

  // Get pending escalations for dashboard
  getPending(): EscalationRequest[] {
    return Array.from(this.pendingEscalations.values());
  }

  // Get escalation statistics
  getStats(): EscalationStats {
    const total = this.escalationHistory.length;
    const byCategory = this.groupBy(this.escalationHistory, 'request.category');
    const avgResponseTime = this.calculateAvgResponseTime();

    return {
      total,
      byCategory,
      avgResponseTime,
      resolutionRate: this.calculateResolutionRate()
    };
  }

  private groupBy(items: any[], path: string): Record<string, number> {
    const result: Record<string, number> = {};
    for (const item of items) {
      const key = this.getNestedValue(item, path);
      result[key] = (result[key] || 0) + 1;
    }
    return result;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((curr, key) => curr?.[key], obj);
  }

  private calculateAvgResponseTime(): number {
    const withResponse = this.escalationHistory.filter(
      e => e.response?.status === 'resolved'
    );
    if (withResponse.length === 0) return 0;

    const totalTime = withResponse.reduce((sum, e) => {
      const requestTime = new Date(e.request.timestamp).getTime();
      const resolveTime = new Date(e.resolvedAt).getTime();
      return sum + (resolveTime - requestTime);
    }, 0);

    return totalTime / withResponse.length;
  }

  private calculateResolutionRate(): number {
    const total = this.escalationHistory.length;
    if (total === 0) return 100;

    const resolved = this.escalationHistory.filter(
      e => e.response?.status === 'resolved'
    ).length;

    return Math.round((resolved / total) * 100);
  }
}
```

---

## 5. Communication Protocols

### Message Formatting

```typescript
interface EscalationMessage {
  header: string;
  summary: string;
  details: EscalationDetails;
  options: FormattedOption[];
  footer: string;
}

class MessageFormatter {
  formatEscalation(request: EscalationRequest): EscalationMessage {
    return {
      header: this.formatHeader(request),
      summary: this.formatSummary(request),
      details: this.formatDetails(request),
      options: this.formatOptions(request.options),
      footer: this.formatFooter(request)
    };
  }

  private formatHeader(request: EscalationRequest): string {
    const priorityEmoji = {
      P1: '🚨',
      P2: '⚠️',
      P3: '📋',
      P4: '📝',
      P5: 'ℹ️'
    }[request.priority];

    return `${priorityEmoji} [${request.priority}] ${request.category.toUpperCase()} ESCALATION`;
  }

  private formatSummary(request: EscalationRequest): string {
    return `
**What I'm trying to do:**
${request.context.pendingAction.description}

**Why I'm asking:**
${request.triggers.map(t => `- ${t.message}`).join('\n')}

**Current page:** ${request.context.currentUrl}
`;
  }

  private formatDetails(request: EscalationRequest): EscalationDetails {
    return {
      screenshotUrl: request.context.screenshots[0],
      pendingAction: {
        type: request.context.pendingAction.type,
        target: request.context.pendingAction.target,
        expectedOutcome: request.context.pendingAction.expectedOutcome
      },
      recentHistory: request.context.relevantHistory.slice(-5).map(h => ({
        action: h.description,
        result: h.success ? '✓' : '✗',
        timestamp: h.timestamp
      }))
    };
  }

  private formatOptions(options: EscalationOption[]): FormattedOption[] {
    return options.map((opt, i) => ({
      number: i + 1,
      label: opt.label,
      description: opt.description,
      riskIndicator: this.getRiskIndicator(opt.risk),
      reversibleIndicator: opt.reversible ? '↩️ Reversible' : '⚠️ Not reversible'
    }));
  }

  private getRiskIndicator(risk: string): string {
    const indicators = {
      none: '🟢 Safe',
      low: '🟡 Low risk',
      medium: '🟠 Medium risk',
      high: '🔴 High risk'
    };
    return indicators[risk] || '';
  }

  private formatFooter(request: EscalationRequest): string {
    const timeoutInfo = request.timeout.duration > 0
      ? `Auto-${request.timeout.defaultAction} in ${request.timeout.duration / 1000}s`
      : 'Waiting for response';

    const recommendation = request.recommendation
      ? `\n💡 My recommendation: ${request.recommendation.option} (${request.recommendation.confidence}% confidence)\n   Reasoning: ${request.recommendation.reasoning}`
      : '';

    return `${timeoutInfo}${recommendation}`;
  }
}
```

### Notification Channels

```typescript
interface NotificationChannel {
  sendUrgent(notification: UrgentNotification): Promise<void>;
  queue(notification: QueuedNotification): Promise<void>;
  onResponse(escalationId: string, callback: ResponseCallback): void;
}

class SlackNotificationChannel implements NotificationChannel {
  private webhookUrl: string;
  private responseCallbacks: Map<string, ResponseCallback> = new Map();

  constructor(webhookUrl: string) {
    this.webhookUrl = webhookUrl;
  }

  async sendUrgent(notification: UrgentNotification): Promise<void> {
    const blocks = this.buildSlackBlocks(notification);

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: notification.title,
        blocks,
        // Mention channel for P1/P2
        link_names: true
      })
    });
  }

  async queue(notification: QueuedNotification): Promise<void> {
    // Similar but without urgency markers
    const blocks = this.buildSlackBlocks(notification);

    await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: notification.title,
        blocks
      })
    });
  }

  onResponse(escalationId: string, callback: ResponseCallback): void {
    this.responseCallbacks.set(escalationId, callback);
  }

  private buildSlackBlocks(notification: any): any[] {
    return [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: notification.title
        }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: notification.message
        }
      },
      {
        type: 'actions',
        elements: notification.options.map((opt: any, i: number) => ({
          type: 'button',
          text: {
            type: 'plain_text',
            text: opt.label
          },
          value: opt.id,
          action_id: `escalation_${notification.id}_${i}`,
          style: i === 0 ? 'primary' : undefined
        }))
      }
    ];
  }
}

class WebSocketNotificationChannel implements NotificationChannel {
  private ws: WebSocket;
  private responseCallbacks: Map<string, ResponseCallback> = new Map();

  constructor(wsUrl: string) {
    this.ws = new WebSocket(wsUrl);
    this.ws.onmessage = this.handleMessage.bind(this);
  }

  async sendUrgent(notification: UrgentNotification): Promise<void> {
    this.ws.send(JSON.stringify({
      type: 'escalation',
      priority: 'urgent',
      data: notification
    }));
  }

  async queue(notification: QueuedNotification): Promise<void> {
    this.ws.send(JSON.stringify({
      type: 'escalation',
      priority: 'normal',
      data: notification
    }));
  }

  onResponse(escalationId: string, callback: ResponseCallback): void {
    this.responseCallbacks.set(escalationId, callback);
  }

  private handleMessage(event: MessageEvent): void {
    const data = JSON.parse(event.data);

    if (data.type === 'escalation_response') {
      const callback = this.responseCallbacks.get(data.escalationId);
      if (callback) {
        callback(data.response);
        this.responseCallbacks.delete(data.escalationId);
      }
    }
  }
}
```

---

## 6. Approval Mechanisms

### Approval Workflow

```typescript
interface ApprovalWorkflow {
  id: string;
  name: string;
  steps: ApprovalStep[];
  escalationPath: string[];
}

interface ApprovalStep {
  approverRole: string;
  timeout: number;
  canDelegate: boolean;
  requiresComment: boolean;
}

const APPROVAL_WORKFLOWS: ApprovalWorkflow[] = [
  {
    id: 'destructive-action',
    name: 'Destructive Action Approval',
    steps: [
      {
        approverRole: 'qa-engineer',
        timeout: 300000, // 5 minutes
        canDelegate: true,
        requiresComment: true
      }
    ],
    escalationPath: ['qa-lead', 'engineering-manager']
  },

  {
    id: 'production-access',
    name: 'Production Environment Access',
    steps: [
      {
        approverRole: 'qa-lead',
        timeout: 600000, // 10 minutes
        canDelegate: false,
        requiresComment: true
      }
    ],
    escalationPath: ['engineering-manager', 'cto']
  },

  {
    id: 'security-finding',
    name: 'Security Finding Escalation',
    steps: [
      {
        approverRole: 'security-engineer',
        timeout: 300000,
        canDelegate: true,
        requiresComment: true
      }
    ],
    escalationPath: ['security-lead', 'ciso']
  }
];
```

### Approval Request Handler

```typescript
interface ApprovalRequest {
  id: string;
  workflowId: string;
  requestedBy: string;
  action: PendingAction;
  context: ApprovalContext;
  currentStep: number;
  approvals: Approval[];
  status: 'pending' | 'approved' | 'rejected' | 'expired';
}

interface Approval {
  approverId: string;
  approverRole: string;
  decision: 'approve' | 'reject' | 'delegate';
  comment?: string;
  timestamp: Date;
  delegatedTo?: string;
}

class ApprovalHandler {
  private workflows: Map<string, ApprovalWorkflow> = new Map();
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();

  constructor() {
    for (const workflow of APPROVAL_WORKFLOWS) {
      this.workflows.set(workflow.id, workflow);
    }
  }

  async requestApproval(
    workflowId: string,
    action: PendingAction,
    context: ApprovalContext
  ): Promise<ApprovalResult> {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Unknown workflow: ${workflowId}`);
    }

    const request: ApprovalRequest = {
      id: this.generateId(),
      workflowId,
      requestedBy: context.agentId,
      action,
      context,
      currentStep: 0,
      approvals: [],
      status: 'pending'
    };

    this.pendingApprovals.set(request.id, request);

    // Process first step
    return this.processStep(request, workflow);
  }

  private async processStep(
    request: ApprovalRequest,
    workflow: ApprovalWorkflow
  ): Promise<ApprovalResult> {
    const step = workflow.steps[request.currentStep];

    // Find available approvers for this role
    const approvers = await this.findApprovers(step.approverRole);

    if (approvers.length === 0) {
      // Escalate if no approvers available
      return this.escalateApproval(request, workflow);
    }

    // Notify approvers
    await this.notifyApprovers(approvers, request, step);

    // Wait for approval
    const approval = await this.waitForApproval(request.id, step.timeout);

    if (!approval) {
      // Timeout - escalate
      return this.escalateApproval(request, workflow);
    }

    // Process approval decision
    return this.processDecision(request, workflow, approval);
  }

  private async processDecision(
    request: ApprovalRequest,
    workflow: ApprovalWorkflow,
    approval: Approval
  ): Promise<ApprovalResult> {
    request.approvals.push(approval);

    switch (approval.decision) {
      case 'approve':
        // Check if more steps needed
        if (request.currentStep < workflow.steps.length - 1) {
          request.currentStep++;
          return this.processStep(request, workflow);
        }

        // All steps approved
        request.status = 'approved';
        return {
          approved: true,
          request,
          message: 'Action approved'
        };

      case 'reject':
        request.status = 'rejected';
        return {
          approved: false,
          request,
          message: approval.comment || 'Action rejected'
        };

      case 'delegate':
        if (!approval.delegatedTo) {
          throw new Error('Delegation requires delegatedTo');
        }
        // Re-request from delegated approver
        return this.requestFromDelegate(request, workflow, approval.delegatedTo);
    }
  }

  private async escalateApproval(
    request: ApprovalRequest,
    workflow: ApprovalWorkflow
  ): Promise<ApprovalResult> {
    const escalationIndex = workflow.escalationPath.findIndex(
      role => !request.approvals.some(a => a.approverRole === role)
    );

    if (escalationIndex === -1) {
      // No more escalation options
      request.status = 'expired';
      return {
        approved: false,
        request,
        message: 'Approval request expired - no available approvers'
      };
    }

    const escalationRole = workflow.escalationPath[escalationIndex];
    const approvers = await this.findApprovers(escalationRole);

    if (approvers.length === 0) {
      // Try next escalation level
      return this.escalateApproval(request, workflow);
    }

    // Notify escalated approvers
    await this.notifyApprovers(approvers, request, {
      approverRole: escalationRole,
      timeout: 600000, // 10 minutes for escalation
      canDelegate: false,
      requiresComment: true
    });

    const approval = await this.waitForApproval(request.id, 600000);

    if (!approval) {
      return this.escalateApproval(request, workflow);
    }

    return this.processDecision(request, workflow, approval);
  }

  private async findApprovers(role: string): Promise<Approver[]> {
    // Implementation would query user database
    // Placeholder:
    return [];
  }

  private async notifyApprovers(
    approvers: Approver[],
    request: ApprovalRequest,
    step: ApprovalStep
  ): Promise<void> {
    // Send notifications to all potential approvers
  }

  private async waitForApproval(
    requestId: string,
    timeout: number
  ): Promise<Approval | null> {
    // Wait for approval response with timeout
    return null;
  }

  private async requestFromDelegate(
    request: ApprovalRequest,
    workflow: ApprovalWorkflow,
    delegatedTo: string
  ): Promise<ApprovalResult> {
    // Request approval from delegated approver
    return { approved: false, request, message: '' };
  }

  private generateId(): string {
    return `apr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
```

---

## 7. Learning from Escalations

### Escalation Analysis

```typescript
interface EscalationPattern {
  trigger: string;
  frequency: number;
  avgResolutionTime: number;
  commonDecisions: Record<string, number>;
  suggestedAutomation?: string;
}

class EscalationLearner {
  private escalationHistory: EscalationRecord[] = [];
  private patterns: Map<string, EscalationPattern> = new Map();

  recordEscalation(record: EscalationRecord): void {
    this.escalationHistory.push(record);
    this.updatePatterns(record);
  }

  private updatePatterns(record: EscalationRecord): void {
    for (const trigger of record.request.triggers) {
      const pattern = this.patterns.get(trigger.id) || {
        trigger: trigger.id,
        frequency: 0,
        avgResolutionTime: 0,
        commonDecisions: {}
      };

      // Update frequency
      pattern.frequency++;

      // Update resolution time
      const resolutionTime = record.resolvedAt.getTime() -
        record.request.timestamp.getTime();
      pattern.avgResolutionTime = (
        (pattern.avgResolutionTime * (pattern.frequency - 1)) + resolutionTime
      ) / pattern.frequency;

      // Update common decisions
      if (record.response?.action) {
        pattern.commonDecisions[record.response.action] =
          (pattern.commonDecisions[record.response.action] || 0) + 1;
      }

      // Check if automation is possible
      pattern.suggestedAutomation = this.checkAutomationPotential(pattern);

      this.patterns.set(trigger.id, pattern);
    }
  }

  private checkAutomationPotential(pattern: EscalationPattern): string | undefined {
    // If same decision made 90%+ of the time, suggest automation
    const totalDecisions = Object.values(pattern.commonDecisions)
      .reduce((sum, count) => sum + count, 0);

    for (const [decision, count] of Object.entries(pattern.commonDecisions)) {
      const percentage = (count / totalDecisions) * 100;

      if (percentage >= 90 && pattern.frequency >= 10) {
        return `Consider auto-${decision} for ${pattern.trigger} (${percentage.toFixed(1)}% historical rate)`;
      }
    }

    return undefined;
  }

  getPatternInsights(): PatternInsight[] {
    const insights: PatternInsight[] = [];

    for (const pattern of this.patterns.values()) {
      // High-frequency escalations
      if (pattern.frequency >= 20) {
        insights.push({
          type: 'high-frequency',
          trigger: pattern.trigger,
          message: `"${pattern.trigger}" triggered ${pattern.frequency} times`,
          recommendation: pattern.suggestedAutomation ||
            'Review trigger conditions or provide better agent guidance'
        });
      }

      // Slow resolutions
      if (pattern.avgResolutionTime > 300000) { // > 5 minutes
        insights.push({
          type: 'slow-resolution',
          trigger: pattern.trigger,
          message: `Average resolution time for "${pattern.trigger}": ${(pattern.avgResolutionTime / 60000).toFixed(1)} minutes`,
          recommendation: 'Consider pre-approving or providing faster escalation path'
        });
      }

      // Automation opportunities
      if (pattern.suggestedAutomation) {
        insights.push({
          type: 'automation-opportunity',
          trigger: pattern.trigger,
          message: pattern.suggestedAutomation,
          recommendation: 'Review and implement if appropriate'
        });
      }
    }

    return insights;
  }

  suggestThresholdAdjustments(): ThresholdAdjustment[] {
    const adjustments: ThresholdAdjustment[] = [];

    // Analyze false positives (escalations that were always approved)
    for (const pattern of this.patterns.values()) {
      const approveRate = (pattern.commonDecisions['proceed'] || 0) /
        Object.values(pattern.commonDecisions).reduce((a, b) => a + b, 0);

      if (approveRate > 0.95 && pattern.frequency >= 10) {
        adjustments.push({
          trigger: pattern.trigger,
          currentBehavior: 'Always escalate',
          suggestedBehavior: 'Raise confidence threshold or auto-approve',
          reasoning: `${(approveRate * 100).toFixed(1)}% approval rate over ${pattern.frequency} escalations`
        });
      }
    }

    return adjustments;
  }
}
```

### Feedback Loop Integration

```typescript
interface EscalationFeedback {
  escalationId: string;
  wasCorrectDecision: boolean;
  wouldChangeApproach: boolean;
  comments: string;
  submittedBy: string;
  submittedAt: Date;
}

class FeedbackCollector {
  private feedback: Map<string, EscalationFeedback> = new Map();

  async collectFeedback(escalationId: string): Promise<void> {
    // Wait for outcome to be known (e.g., 24 hours after escalation)
    // Then prompt for feedback
  }

  analyzeFeedback(): FeedbackAnalysis {
    const allFeedback = Array.from(this.feedback.values());

    return {
      totalFeedback: allFeedback.length,
      correctDecisionRate: this.calculateRate(allFeedback, 'wasCorrectDecision'),
      wouldChangeApproachRate: this.calculateRate(allFeedback, 'wouldChangeApproach'),
      commonThemes: this.extractThemes(allFeedback.map(f => f.comments))
    };
  }

  private calculateRate(feedback: EscalationFeedback[], field: string): number {
    const positive = feedback.filter(f => f[field]).length;
    return positive / feedback.length;
  }

  private extractThemes(comments: string[]): string[] {
    // Simple theme extraction - could use NLP for better results
    const words = comments.join(' ').toLowerCase().split(/\W+/);
    const wordCounts = new Map<string, number>();

    for (const word of words) {
      if (word.length > 4) { // Filter short words
        wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
      }
    }

    return Array.from(wordCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([word]) => word);
  }
}
```

---

## 8. Emergency Procedures

### Emergency Classification

```typescript
enum EmergencyLevel {
  CRITICAL = 'critical',  // Immediate human intervention required
  URGENT = 'urgent',      // Human needed within minutes
  ELEVATED = 'elevated',  // Human needed within hour
  NORMAL = 'normal'       // Standard escalation
}

interface EmergencyCondition {
  id: string;
  level: EmergencyLevel;
  condition: (context: AgentContext) => boolean;
  response: EmergencyResponse;
}

const EMERGENCY_CONDITIONS: EmergencyCondition[] = [
  {
    id: 'data-breach-suspected',
    level: EmergencyLevel.CRITICAL,
    condition: (ctx) => {
      // Detected exposed credentials or PII
      return ctx.observations?.some(o =>
        o.type === 'security' &&
        o.severity === 'critical'
      );
    },
    response: {
      immediateAction: 'halt-all-operations',
      notify: ['security-team', 'on-call-engineer'],
      preserve: ['screenshots', 'dom-snapshot', 'network-logs'],
      escalateTo: 'incident-response'
    }
  },

  {
    id: 'production-impact',
    level: EmergencyLevel.CRITICAL,
    condition: (ctx) => {
      // Agent actions may have affected production
      return ctx.environment === 'production' &&
        ctx.lastAction?.mayHaveSideEffects;
    },
    response: {
      immediateAction: 'halt-all-operations',
      notify: ['engineering-lead', 'on-call-engineer'],
      preserve: ['action-history', 'screenshots'],
      escalateTo: 'engineering-manager'
    }
  },

  {
    id: 'stuck-in-loop',
    level: EmergencyLevel.URGENT,
    condition: (ctx) => {
      // Detect repeated failures
      const recent = ctx.actionHistory?.slice(-10) || [];
      const failures = recent.filter(a => !a.success);
      return failures.length >= 8;
    },
    response: {
      immediateAction: 'pause-execution',
      notify: ['qa-engineer'],
      preserve: ['action-history', 'error-logs'],
      escalateTo: 'qa-lead'
    }
  },

  {
    id: 'resource-exhaustion',
    level: EmergencyLevel.ELEVATED,
    condition: (ctx) => {
      return ctx.resources?.memoryUsage > 0.9 ||
        ctx.resources?.cpuUsage > 0.9;
    },
    response: {
      immediateAction: 'reduce-operations',
      notify: ['devops'],
      preserve: ['resource-metrics'],
      escalateTo: 'infrastructure-team'
    }
  }
];
```

### Emergency Response Handler

```typescript
interface EmergencyResponse {
  immediateAction: string;
  notify: string[];
  preserve: string[];
  escalateTo: string;
}

class EmergencyHandler {
  private isEmergencyMode: boolean = false;
  private currentEmergency: EmergencyCondition | null = null;

  async handleEmergency(
    emergency: EmergencyCondition,
    context: AgentContext
  ): Promise<void> {
    this.isEmergencyMode = true;
    this.currentEmergency = emergency;

    console.error(`🚨 EMERGENCY: ${emergency.id} (${emergency.level})`);

    // Execute immediate action
    await this.executeImmediateAction(emergency.response.immediateAction);

    // Preserve evidence
    await this.preserveEvidence(emergency.response.preserve, context);

    // Notify relevant parties
    await this.notifyParties(emergency.response.notify, emergency, context);

    // Escalate
    await this.escalateToHandler(emergency.response.escalateTo, emergency, context);
  }

  private async executeImmediateAction(action: string): Promise<void> {
    switch (action) {
      case 'halt-all-operations':
        // Stop all agent activity
        await this.haltOperations();
        break;

      case 'pause-execution':
        // Pause but don't terminate
        await this.pauseExecution();
        break;

      case 'reduce-operations':
        // Reduce concurrent operations
        await this.reduceOperations();
        break;
    }
  }

  private async preserveEvidence(
    items: string[],
    context: AgentContext
  ): Promise<void> {
    const evidence: Record<string, any> = {};

    for (const item of items) {
      switch (item) {
        case 'screenshots':
          evidence.screenshots = await this.captureScreenshots();
          break;
        case 'dom-snapshot':
          evidence.dom = context.currentPage?.dom;
          break;
        case 'network-logs':
          evidence.network = await this.getNetworkLogs();
          break;
        case 'action-history':
          evidence.actions = context.actionHistory;
          break;
        case 'error-logs':
          evidence.errors = await this.getErrorLogs();
          break;
        case 'resource-metrics':
          evidence.resources = context.resources;
          break;
      }
    }

    // Store evidence
    await this.storeEvidence(evidence);
  }

  private async notifyParties(
    parties: string[],
    emergency: EmergencyCondition,
    context: AgentContext
  ): Promise<void> {
    const message = this.formatEmergencyMessage(emergency, context);

    for (const party of parties) {
      await this.sendUrgentNotification(party, message);
    }
  }

  private formatEmergencyMessage(
    emergency: EmergencyCondition,
    context: AgentContext
  ): string {
    return `
🚨 EMERGENCY ALERT: ${emergency.id}
Level: ${emergency.level.toUpperCase()}

What happened:
- Current URL: ${context.currentPage?.url}
- Last action: ${context.actionHistory?.slice(-1)[0]?.description}
- Agent state: ${context.state}

Immediate action taken: ${emergency.response.immediateAction}

Evidence preserved: ${emergency.response.preserve.join(', ')}

Awaiting human intervention.
`;
  }

  private async haltOperations(): Promise<void> {
    // Implementation to stop all operations
  }

  private async pauseExecution(): Promise<void> {
    // Implementation to pause execution
  }

  private async reduceOperations(): Promise<void> {
    // Implementation to reduce operations
  }

  private async captureScreenshots(): Promise<string[]> {
    // Implementation to capture screenshots
    return [];
  }

  private async getNetworkLogs(): Promise<any[]> {
    // Implementation to get network logs
    return [];
  }

  private async getErrorLogs(): Promise<any[]> {
    // Implementation to get error logs
    return [];
  }

  private async storeEvidence(evidence: Record<string, any>): Promise<void> {
    // Store evidence for later analysis
  }

  private async sendUrgentNotification(party: string, message: string): Promise<void> {
    // Send urgent notification
  }

  private async escalateToHandler(
    handler: string,
    emergency: EmergencyCondition,
    context: AgentContext
  ): Promise<void> {
    // Escalate to appropriate handler
  }

  isInEmergencyMode(): boolean {
    return this.isEmergencyMode;
  }

  async resolveEmergency(resolution: string): Promise<void> {
    this.isEmergencyMode = false;
    this.currentEmergency = null;
    // Log resolution
  }
}
```

### Recovery Procedures

```typescript
interface RecoveryProcedure {
  emergencyId: string;
  steps: RecoveryStep[];
  verificationChecks: VerificationCheck[];
}

interface RecoveryStep {
  order: number;
  description: string;
  action: () => Promise<void>;
  rollbackAction?: () => Promise<void>;
}

interface VerificationCheck {
  name: string;
  check: () => Promise<boolean>;
  required: boolean;
}

const RECOVERY_PROCEDURES: RecoveryProcedure[] = [
  {
    emergencyId: 'stuck-in-loop',
    steps: [
      {
        order: 1,
        description: 'Clear action queue',
        action: async () => {
          // Clear pending actions
        }
      },
      {
        order: 2,
        description: 'Reset browser state',
        action: async () => {
          // Navigate to known good state
        }
      },
      {
        order: 3,
        description: 'Clear working memory',
        action: async () => {
          // Reset context
        }
      }
    ],
    verificationChecks: [
      {
        name: 'Browser responsive',
        check: async () => true,
        required: true
      },
      {
        name: 'Memory usage normal',
        check: async () => true,
        required: true
      }
    ]
  }
];

class RecoveryManager {
  async executeRecovery(emergencyId: string): Promise<RecoveryResult> {
    const procedure = RECOVERY_PROCEDURES.find(p => p.emergencyId === emergencyId);

    if (!procedure) {
      return {
        success: false,
        message: `No recovery procedure for ${emergencyId}`
      };
    }

    const completedSteps: number[] = [];

    try {
      // Execute recovery steps in order
      for (const step of procedure.steps.sort((a, b) => a.order - b.order)) {
        console.log(`Recovery step ${step.order}: ${step.description}`);
        await step.action();
        completedSteps.push(step.order);
      }

      // Run verification checks
      for (const check of procedure.verificationChecks) {
        const passed = await check.check();
        if (!passed && check.required) {
          throw new Error(`Verification failed: ${check.name}`);
        }
      }

      return {
        success: true,
        message: 'Recovery completed successfully',
        completedSteps
      };

    } catch (error) {
      // Attempt rollback of completed steps
      for (const stepOrder of completedSteps.reverse()) {
        const step = procedure.steps.find(s => s.order === stepOrder);
        if (step?.rollbackAction) {
          try {
            await step.rollbackAction();
          } catch (rollbackError) {
            console.error(`Rollback failed for step ${stepOrder}:`, rollbackError);
          }
        }
      }

      return {
        success: false,
        message: `Recovery failed: ${error.message}`,
        completedSteps,
        error
      };
    }
  }
}
```

---

## Summary

This document covers the complete human-in-the-loop escalation system:

| Component | Purpose |
|-----------|---------|
| **Escalation Triggers** | Conditions that require human review |
| **Confidence Scoring** | Multi-factor confidence calculation |
| **Escalation Workflow** | State machine for handling escalations |
| **Communication Protocols** | Formatting and delivering escalation messages |
| **Approval Mechanisms** | Structured approval workflows |
| **Learning System** | Improving from escalation outcomes |
| **Emergency Procedures** | Handling critical situations |

---

## Related Documents

- [AGENT_ARCHITECTURE.md](./AGENT_ARCHITECTURE.md) - Overall system architecture
- [AGENT_LOOP.md](./AGENT_LOOP.md) - ReAct execution loop
- [AGENT_TOOLS.md](./AGENT_TOOLS.md) - Tool definitions
- [AGENT_MEMORY.md](./AGENT_MEMORY.md) - Memory systems
- [AGENT_CONTEXT.md](./AGENT_CONTEXT.md) - Context management
- [AGENT_PROMPTS.md](./AGENT_PROMPTS.md) - Prompt engineering
- [AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md) - Multi-agent patterns
