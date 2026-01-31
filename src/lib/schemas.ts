/**
 * Zod schemas for runtime validation of Tauri API responses
 * Ensures type safety between Rust backend and React frontend
 */

import { z } from "zod";

// ============ DOM & Page Schemas ============

// Define base DOM node without recursion first
const BaseDOMNodeSchema = z.object({
  mmid: z.string(),
  tag: z.string(),
  role: z.string().nullable(),
  name: z.string().nullable(),
  text: z.string().nullable(),
  value: z.string().nullable(),
  placeholder: z.string().nullable(),
  href: z.string().nullable(),
  src: z.string().nullable(),
  type: z.string().nullable(),
  isInteractive: z.boolean(),
  attributes: z.record(z.string(), z.string()),
  children: z.array(z.unknown()), // Will be typed as DOMNode[] in the interface
});

export const DOMNodeSchema = BaseDOMNodeSchema;

export const PageStateSchema = z.object({
  id: z.string(),
  url: z.string(),
  title: z.string(),
  timestamp: z.string(),
  totalElements: z.number(),
  interactiveElements: z.number(),
  tree: DOMNodeSchema.nullable(),
  flatInteractive: z.array(DOMNodeSchema),
  screenshot: z.string().nullable(),
});

// ============ Action Schemas ============

export const PendingActionSchema = z.object({
  id: z.string(),
  mmid: z.string(),
  xpath: z.string().nullable().optional(),
  actionType: z.string(),
  inputValue: z.string().nullable(),
  tag: z.string(),
  label: z.string().nullable(),
  sourceUrl: z.string(),
  priority: z.number(),
  mightNavigate: z.boolean(),
});

export const ActionResultSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  newState: PageStateSchema.nullable(),
  actionType: z.string(),
  elementMmid: z.string(),
  newElements: z.array(DOMNodeSchema),
  causedNavigation: z.boolean(),
  causedUIChange: z.boolean(),
});

// ============ TESTAI Exploration Schemas ============

export const ElementCategorySchema = z.enum([
  "navigation",
  "read",
  "write",
  "destructive",
  "payment",
]);

export const ClassifiedActionSchema = z.object({
  action: PendingActionSchema,
  category: ElementCategorySchema,
  selector: z.string().nullable(),
  stableSelector: z.string().nullable().optional(),
  xpath: z.string().nullable().optional(),
  depth: z.number(),
  flowId: z.string().nullable(),
  fieldType: z.string().nullable().optional(),
  confidence: z.number().optional(),
});

export const DNAStatsSchema = z.object({
  totalPages: z.number(),
  totalElements: z.number(),
  totalTransitions: z.number(),
  navigationActions: z.number(),
  readActions: z.number(),
  writeActions: z.number(),
  destructiveActions: z.number(),
  paymentActions: z.number(),
  detectedFlows: z.number(),
});

export const DNAPageSchema = z.object({
  id: z.string(),
  url: z.string(),
  title: z.string(),
  elements: z.array(ClassifiedActionSchema),
  screenshot: z.string().nullable(),
  discoveredAt: z.string(),
  outgoingLinks: z.array(z.string()),
  incomingLinks: z.array(z.string()),
});

export const ApplicationDNASchema = z.object({
  domain: z.string(),
  pages: z.record(z.string(), DNAPageSchema),
  transitions: z.array(z.unknown()),
  flows: z.array(z.unknown()),
  apiEndpoints: z.array(z.string()),
  issues: z.array(z.unknown()).optional(),
  stats: DNAStatsSchema,
  startedAt: z.string(),
  completedAt: z.string().nullable(),
});

export const AutoExploreStartResultSchema = z.object({
  started: z.boolean(),
  initialState: PageStateSchema.nullable(),
  classifiedElements: z.array(ClassifiedActionSchema),
  queueStats: z.record(z.string(), z.number()),
  domain: z.string(),
});

export const ExplorationIterationResultSchema = z.object({
  actionsExecuted: z.number(),
  newPagesDiscovered: z.number(),
  newElementsDiscovered: z.number(),
  queueStats: z.record(z.string(), z.number()),
  explorationComplete: z.boolean(),
  errors: z.array(z.string()),
  dnaStats: DNAStatsSchema.nullable(),
});

// ============ Security & UX Issue Schemas ============

export const IssueSeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const IssueTypeSchema = z.enum([
  // Security Issues
  "insecure_form",
  "mixed_content",
  "exposed_api_key",
  "open_redirect",
  "missing_csrf",
  "sensitive_data_exposed",
  "insecure_password_field",
  "clickjacking_vulnerable",
  "debug_mode_enabled",
  "information_disclosure",
  "hardcoded_credentials",
  "insecure_direct_object_ref",
  // UX Issues
  "broken_link",
  "broken_image",
  "empty_state",
  "infinite_loop",
  "slow_page",
  "missing_alt_text",
  "poor_contrast",
  "missing_labels",
  "tiny_click_target",
  "missing_focus_indicator",
  // Functional Issues
  "form_validation_bypass",
  "dead_end",
  "duplicate_content",
  "unhandled_error",
  "session_leak",
  "caching_issue",
  "orphaned_page",
]);

export const DetectedIssueSchema = z.object({
  id: z.string(),
  issueType: IssueTypeSchema,
  severity: IssueSeveritySchema,
  title: z.string(),
  description: z.string(),
  pageUrl: z.string(),
  pageTitle: z.string(),
  elementSelector: z.string().nullable(),
  evidence: z.string().nullable(),
  recommendation: z.string().nullable(),
  detectedAt: z.string(),
});

export const IssueSummarySchema = z.object({
  total: z.number(),
  critical: z.number(),
  high: z.number(),
  medium: z.number(),
  low: z.number(),
  info: z.number(),
});

// ============ Validation Bypass Testing Schemas ============

export const ValidationBypassTestSchema = z.object({
  fieldType: z.string(),
  testName: z.string(),
  testValue: z.string(),
  expectedBehavior: z.string(),
  severity: IssueSeveritySchema,
});

export const BypassTestResultSchema = z.tuple([
  z.string(),
  z.array(ValidationBypassTestSchema),
]);

// ============ Exploration State Schemas ============

export const ExplorationStateSchema = z.object({
  visitedUrls: z.array(z.string()),
  pendingActions: z.array(PendingActionSchema),
  currentDepth: z.number(),
  maxDepth: z.number(),
  startTime: z.string().nullable(),
  isRunning: z.boolean(),
});

// ============ UI Change Schemas ============

export const UIChangeTypeSchema = z.enum([
  "none",
  "navigation",
  "modal_opened",
  "modal_closed",
  "dropdown_expanded",
  "dropdown_collapsed",
  "content_loaded",
  "form_validation",
  "notification_appeared",
  "multiple",
]);

export const ValueChangeSchema = z.object({
  elementMmid: z.string(),
  oldValue: z.string().nullable(),
  newValue: z.string().nullable(),
});

export const TitleChangeSchema = z.object({
  oldTitle: z.string(),
  newTitle: z.string(),
});

export const UIChangeResultSchema = z.object({
  addedElements: z.array(DOMNodeSchema),
  removedElements: z.array(DOMNodeSchema),
  urlChanged: z.boolean(),
  hasUIChanges: z.boolean(),
  changeType: UIChangeTypeSchema,
  newlyVisible: z.array(DOMNodeSchema),
  newlyHidden: z.array(DOMNodeSchema),
  valueChanges: z.array(ValueChangeSchema),
  titleChange: TitleChangeSchema.nullable(),
});

// ============ Network Monitoring Schemas ============

export const CapturedRequestSchema = z.object({
  url: z.string(),
  method: z.string(),
  resourceType: z.string(),
  isApiEndpoint: z.boolean(),
});

// ============ Form Field Type Schema ============

export const FormFieldTypeSchema = z.enum([
  "email",
  "password",
  "username",
  "firstName",
  "lastName",
  "fullName",
  "phone",
  "address",
  "city",
  "state",
  "zipCode",
  "country",
  "creditCard",
  "cvv",
  "expirationDate",
  "searchQuery",
  "url",
  "number",
  "date",
  "time",
  "textarea",
  "generic",
]);

// ============ Tab Pool & Parallel Execution Schemas ============

export const TabPoolConfigSchema = z.object({
  maxTabs: z.number(),
  tabTimeoutMs: z.number(),
  retryAttempts: z.number(),
  retryDelayMs: z.number(),
});

export const ExplorationMetricsSchema = z.object({
  totalActionsExecuted: z.number(),
  totalPagesVisited: z.number(),
  totalElementsFound: z.number(),
  avgPageLoadTimeMs: z.number(),
  avgActionTimeMs: z.number(),
  startTime: z.string().nullable(),
  elapsedMs: z.number(),
  errorsEncountered: z.number(),
  queuedActions: z.number(),
});

// ============ Flow Execution Schemas ============

export const FlowStepResultSchema = z.object({
  stepIndex: z.number(),
  action: ClassifiedActionSchema,
  result: ActionResultSchema.nullable(),
  error: z.string().nullable(),
  durationMs: z.number(),
});

export const FlowExecutionStateSchema = z.object({
  flowId: z.string(),
  flowType: z.string(),
  currentStep: z.number(),
  totalSteps: z.number(),
  status: z.enum(["pending", "running", "completed", "failed"]),
  stepResults: z.array(FlowStepResultSchema),
  startedAt: z.string().nullable(),
  completedAt: z.string().nullable(),
  error: z.string().nullable(),
});

// ============ Tab Action Result Schema ============

export const TabActionResultSchema = z.object({
  success: z.boolean(),
  tabId: z.string(),
  action: ClassifiedActionSchema,
  result: ActionResultSchema.nullable(),
  error: z.string().nullable(),
  retries: z.number(),
  durationMs: z.number(),
});

// ============ BFS Crawler Schemas ============

export const InteractionNodeSchema = z.object({
  id: z.string(),
  url: z.string(),
  title: z.string(),
  action: ClassifiedActionSchema.nullable(),
  parentId: z.string().nullable(),
  children: z.array(z.string()),
  elements: z.array(ClassifiedActionSchema),
  depth: z.number(),
  issues: z.array(DetectedIssueSchema),
  screenshot: z.string().nullable(),
  discoveredAt: z.string(),
  explored: z.boolean(),
});

export const DetectedFlowSchema = z.object({
  id: z.string(),
  flowType: z.string(),
  name: z.string(),
  entryUrl: z.string(),
  nodeIds: z.array(z.string()),
  hasFormEntry: z.boolean(),
  confidence: z.number(),
});

export const InteractionTreeSchema = z.object({
  rootUrl: z.string(),
  domain: z.string(),
  nodes: z.record(z.string(), InteractionNodeSchema),
  rootId: z.string(),
  totalPages: z.number(),
  totalElements: z.number(),
  totalInteractions: z.number(),
  issues: z.array(DetectedIssueSchema),
  flows: z.array(DetectedFlowSchema).optional(),
  apiEndpoints: z.array(z.string()),
  startedAt: z.string(),
  completedAt: z.string().nullable(),
  durationMs: z.number(),
});

export const FastCrawlResultSchema = z.object({
  tree: InteractionTreeSchema,
  pagesPerSecond: z.number(),
  totalTimeMs: z.number(),
  errors: z.array(z.string()),
});

// ============ Turbo Crawler Schemas ============

export const DiscoveredUrlSchema = z.object({
  url: z.string(),
  title: z.string(),
  depth: z.number(),
  linkCount: z.number(),
});

export const TurboCrawlResultSchema = z.object({
  urls: z.array(DiscoveredUrlSchema),
  totalUrls: z.number(),
  totalTimeMs: z.number(),
  pagesPerSecond: z.number(),
  errors: z.array(z.string()),
});

// ============ Database Schemas ============

export const CrawlSessionSummarySchema = z.object({
  id: z.string(),
  domain: z.string(),
  startedAt: z.string(),
  completedAt: z.string().nullable(),
  totalPages: z.number(),
  totalElements: z.number(),
  totalIssues: z.number(),
  durationMs: z.number().nullable(),
  crawlerType: z.string().nullable(),
});

export const CrawlComparisonSchema = z.object({
  newPages: z.array(z.string()),
  removedPages: z.array(z.string()),
  newIssues: z.number(),
  resolvedIssues: z.number(),
  newElements: z.number(),
  removedElements: z.number(),
});

export const DbStatsSchema = z.object({
  totalSessions: z.number(),
  totalPages: z.number(),
  totalElements: z.number(),
  totalIssues: z.number(),
  totalApis: z.number(),
  dbSizeBytes: z.number(),
  dbPath: z.string(),
});

// ============ Type Exports ============

export type DOMNode = z.infer<typeof DOMNodeSchema>;
export type PageState = z.infer<typeof PageStateSchema>;
export type PendingAction = z.infer<typeof PendingActionSchema>;
export type ActionResult = z.infer<typeof ActionResultSchema>;
export type ElementCategory = z.infer<typeof ElementCategorySchema>;
export type ClassifiedAction = z.infer<typeof ClassifiedActionSchema>;
export type DNAStats = z.infer<typeof DNAStatsSchema>;
export type DNAPage = z.infer<typeof DNAPageSchema>;
export type ApplicationDNA = z.infer<typeof ApplicationDNASchema>;
export type AutoExploreStartResult = z.infer<typeof AutoExploreStartResultSchema>;
export type ExplorationIterationResult = z.infer<typeof ExplorationIterationResultSchema>;
export type IssueSeverity = z.infer<typeof IssueSeveritySchema>;
export type IssueType = z.infer<typeof IssueTypeSchema>;
export type DetectedIssue = z.infer<typeof DetectedIssueSchema>;
export type IssueSummary = z.infer<typeof IssueSummarySchema>;
export type ValidationBypassTest = z.infer<typeof ValidationBypassTestSchema>;
export type ExplorationState = z.infer<typeof ExplorationStateSchema>;
export type UIChangeType = z.infer<typeof UIChangeTypeSchema>;
export type ValueChange = z.infer<typeof ValueChangeSchema>;
export type TitleChange = z.infer<typeof TitleChangeSchema>;
export type UIChangeResult = z.infer<typeof UIChangeResultSchema>;
export type CapturedRequest = z.infer<typeof CapturedRequestSchema>;
export type FormFieldType = z.infer<typeof FormFieldTypeSchema>;
export type TabPoolConfig = z.infer<typeof TabPoolConfigSchema>;
export type ExplorationMetrics = z.infer<typeof ExplorationMetricsSchema>;
export type FlowStepResult = z.infer<typeof FlowStepResultSchema>;
export type FlowExecutionState = z.infer<typeof FlowExecutionStateSchema>;
export type TabActionResult = z.infer<typeof TabActionResultSchema>;
export type InteractionNode = z.infer<typeof InteractionNodeSchema>;
export type DetectedFlow = z.infer<typeof DetectedFlowSchema>;
export type InteractionTree = z.infer<typeof InteractionTreeSchema>;
export type FastCrawlResult = z.infer<typeof FastCrawlResultSchema>;
export type DiscoveredUrl = z.infer<typeof DiscoveredUrlSchema>;
export type TurboCrawlResult = z.infer<typeof TurboCrawlResultSchema>;
export type CrawlSessionSummary = z.infer<typeof CrawlSessionSummarySchema>;
export type CrawlComparison = z.infer<typeof CrawlComparisonSchema>;
export type DbStats = z.infer<typeof DbStatsSchema>;

// ============ Safe Parse Helpers ============

/**
 * Safely parse and validate API response with detailed error logging
 */
export function safeParseWithLog<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  context: string
): T | null {
  const result = schema.safeParse(data);
  if (!result.success) {
    console.error(`[${context}] Validation failed:`, result.error.format());
    console.error(`[${context}] Received data:`, data);
    return null;
  }
  return result.data;
}

/**
 * Parse with fallback value on failure
 */
export function parseWithFallback<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  fallback: T,
  context: string
): T {
  const result = safeParseWithLog(schema, data, context);
  return result ?? fallback;
}
