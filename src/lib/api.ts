/**
 * Type-safe Tauri API wrapper with runtime validation and error handling
 */

import { invoke } from "@tauri-apps/api/core";
import {
  PageStateSchema,
  ActionResultSchema,
  ApplicationDNASchema,
  AutoExploreStartResultSchema,
  ExplorationIterationResultSchema,
  DetectedIssueSchema,
  ExplorationStateSchema,
  UIChangeResultSchema,
  CapturedRequestSchema,
  ValidationBypassTestSchema,
  ExplorationMetricsSchema,
  FlowExecutionStateSchema,
  TabActionResultSchema,
  ClassifiedActionSchema,
  PendingActionSchema,
  FastCrawlResultSchema,
  InteractionTreeSchema,
  TurboCrawlResultSchema,
  CrawlSessionSummarySchema,
  CrawlComparisonSchema,
  DbStatsSchema,
  safeParseWithLog,
  type PageState,
  type ActionResult,
  type ApplicationDNA,
  type AutoExploreStartResult,
  type ExplorationIterationResult,
  type DetectedIssue,
  type ExplorationState,
  type UIChangeResult,
  type CapturedRequest,
  type ValidationBypassTest,
  type ExplorationMetrics,
  type FlowExecutionState,
  type TabActionResult,
  type ClassifiedAction,
  type PendingAction,
  type DOMNode,
  type FormFieldType,
  type TabPoolConfig,
  type FastCrawlResult,
  type InteractionTree,
  type TurboCrawlResult,
  type CrawlSessionSummary,
  type CrawlComparison,
  type DbStats,
} from "./schemas";
import { z } from "zod";

// ============ Error Types ============

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly command: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class ValidationError extends Error {
  constructor(
    message: string,
    public readonly command: string,
    public readonly data: unknown
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

// ============ Retry Logic ============

interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

const defaultRetryOptions: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 500,
  maxDelayMs: 5000,
};

async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const { maxRetries, baseDelayMs, maxDelayMs } = {
    ...defaultRetryOptions,
    ...options,
  };

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < maxRetries) {
        // Exponential backoff with jitter
        const delay = Math.min(
          baseDelayMs * Math.pow(2, attempt) + Math.random() * 100,
          maxDelayMs
        );
        console.warn(
          `Attempt ${attempt + 1} failed, retrying in ${delay}ms...`,
          error
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

// ============ Validated API Calls ============

/**
 * Type-safe invoke with validation
 */
async function invokeValidated<T>(
  command: string,
  schema: z.ZodSchema<T>,
  args?: Record<string, unknown>
): Promise<T> {
  try {
    const result = await invoke(command, args);
    const validated = safeParseWithLog(schema, result, command);

    if (validated === null) {
      throw new ValidationError(
        `Response validation failed for ${command}`,
        command,
        result
      );
    }

    return validated;
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ApiError(
      `API call failed: ${command}`,
      command,
      error
    );
  }
}

// ============ Browser Commands ============

export async function startBrowser(): Promise<string> {
  return invoke<string>("start_browser");
}

export async function startBrowserWithProfile(
  profilePath: string
): Promise<string> {
  return invoke<string>("start_browser_with_profile", { profilePath });
}

export async function stopBrowser(): Promise<string> {
  return invoke<string>("stop_browser");
}

export async function getDefaultChromeProfilePath(): Promise<string> {
  return invoke<string>("get_default_chrome_profile_path");
}

// ============ Navigation Commands ============

export async function navigateTo(url: string): Promise<PageState> {
  return withRetry(
    () => invokeValidated("navigate_to", PageStateSchema, { url }),
    { maxRetries: 2 }
  );
}

export async function goBack(): Promise<PageState> {
  return invokeValidated("go_back", PageStateSchema);
}

// ============ Action Commands ============

export async function clickElement(mmid: string): Promise<ActionResult> {
  return invokeValidated("click_element", ActionResultSchema, { mmid });
}

export async function inputText(
  mmid: string,
  text: string
): Promise<ActionResult> {
  return invokeValidated("input_text", ActionResultSchema, { mmid, text });
}

// ============ Exploration Commands ============

export async function startAutonomousExploration(
  url: string,
  maxDepth?: number
): Promise<AutoExploreStartResult> {
  return invokeValidated(
    "start_autonomous_exploration",
    AutoExploreStartResultSchema,
    { url, maxDepth }
  );
}

export async function runExplorationIteration(
  parallelTabs?: number
): Promise<ExplorationIterationResult> {
  return invokeValidated(
    "run_exploration_iteration",
    ExplorationIterationResultSchema,
    { parallelTabs }
  );
}

export async function getDnaGraph(): Promise<ApplicationDNA | null> {
  const result = await invoke("get_dna_graph");
  if (result === null) return null;
  return safeParseWithLog(ApplicationDNASchema, result, "get_dna_graph");
}

export async function getQueueStats(): Promise<Record<string, number>> {
  return invoke<Record<string, number>>("get_queue_stats");
}

export async function stopAutonomousExploration(): Promise<ApplicationDNA | null> {
  const result = await invoke("stop_autonomous_exploration");
  if (result === null) return null;
  return safeParseWithLog(ApplicationDNASchema, result, "stop_autonomous_exploration");
}

export async function isExploring(): Promise<boolean> {
  return invoke<boolean>("is_exploring");
}

// ============ Issue Detection Commands ============

export async function getDetectedIssues(): Promise<DetectedIssue[]> {
  const result = await invoke<unknown[]>("get_detected_issues");
  return result
    .map((item, index) =>
      safeParseWithLog(DetectedIssueSchema, item, `get_detected_issues[${index}]`)
    )
    .filter((item): item is DetectedIssue => item !== null);
}

export async function getIssueSummary(): Promise<Record<string, number>> {
  return invoke<Record<string, number>>("get_issue_summary");
}

// ============ Utility Commands ============

export async function getCurrentState(): Promise<PageState | null> {
  const result = await invoke("get_current_state");
  if (result === null) return null;
  return safeParseWithLog(PageStateSchema, result, "get_current_state");
}

export async function captureScreenshot(): Promise<string | null> {
  return invoke<string | null>("capture_screenshot");
}

// ============ Exploration State Commands ============

export async function getExplorationState(): Promise<ExplorationState> {
  return invokeValidated("get_exploration_state", ExplorationStateSchema);
}

export async function shouldVisitUrl(url: string): Promise<boolean> {
  return invoke<boolean>("should_visit_url", { url });
}

export async function getActionableElements(): Promise<PendingAction[]> {
  const result = await invoke<unknown[]>("get_actionable_elements_cmd");
  return result
    .map((item, index) =>
      safeParseWithLog(PendingActionSchema, item, `get_actionable_elements[${index}]`)
    )
    .filter((item): item is PendingAction => item !== null);
}

export async function queueActions(actions: PendingAction[]): Promise<number> {
  return invoke<number>("queue_actions", { actions });
}

export async function getNextAction(): Promise<PendingAction | null> {
  const result = await invoke("get_next_action");
  if (result === null) return null;
  return safeParseWithLog(PendingActionSchema, result, "get_next_action");
}

export async function executeAction(action: PendingAction): Promise<ActionResult> {
  return invokeValidated("execute_action", ActionResultSchema, { action });
}

export async function smartNavigate(
  url: string
): Promise<{ navigated: boolean; state: PageState | null }> {
  const result = await invoke<[boolean, unknown]>("smart_navigate", { url });
  const [navigated, stateData] = result;
  const state = stateData
    ? safeParseWithLog(PageStateSchema, stateData, "smart_navigate")
    : null;
  return { navigated, state };
}

export async function resetExploration(): Promise<string> {
  return invoke<string>("reset_exploration");
}

export async function getUnvisitedLinks(): Promise<PendingAction[]> {
  const result = await invoke<unknown[]>("get_unvisited_links");
  return result
    .map((item, index) =>
      safeParseWithLog(PendingActionSchema, item, `get_unvisited_links[${index}]`)
    )
    .filter((item): item is PendingAction => item !== null);
}

// ============ UI Change Detection Commands ============

export async function getUIChanges(): Promise<UIChangeResult> {
  return invokeValidated("get_ui_changes", UIChangeResultSchema);
}

// ============ Network Monitoring Commands ============

export async function getApiEndpoints(): Promise<string[]> {
  return invoke<string[]>("get_api_endpoints");
}

export async function getCapturedRequests(): Promise<CapturedRequest[]> {
  const result = await invoke<unknown[]>("get_captured_requests");
  return result
    .map((item, index) =>
      safeParseWithLog(CapturedRequestSchema, item, `get_captured_requests[${index}]`)
    )
    .filter((item): item is CapturedRequest => item !== null);
}

// ============ Form Testing Commands ============

export async function getBypassTestsForForm(
  elements: DOMNode[]
): Promise<Array<[string, ValidationBypassTest[]]>> {
  const result = await invoke<Array<[string, unknown[]]>>("get_bypass_tests_for_form", {
    elements,
  });
  return result.map(([fieldId, tests]) => [
    fieldId,
    tests
      .map((test, index) =>
        safeParseWithLog(ValidationBypassTestSchema, test, `bypass_test[${index}]`)
      )
      .filter((test): test is ValidationBypassTest => test !== null),
  ]);
}

export async function generateTestInput(fieldType: FormFieldType): Promise<string> {
  return invoke<string>("generate_test_input", { fieldType });
}

// ============ Tab Pool & Parallel Execution Commands ============

export async function createIsolatedContext(): Promise<string> {
  return invoke<string>("create_isolated_context");
}

export async function getExplorationMetrics(): Promise<ExplorationMetrics> {
  return invokeValidated("get_exploration_metrics", ExplorationMetricsSchema);
}

export async function configureTabPool(config: TabPoolConfig): Promise<void> {
  return invoke("configure_tab_pool", { config });
}

// ============ Flow Execution Commands ============

export async function executeFlowSequence(flowId: string): Promise<FlowExecutionState> {
  return invokeValidated("execute_flow_sequence", FlowExecutionStateSchema, { flowId });
}

export async function getActiveFlows(): Promise<FlowExecutionState[]> {
  const result = await invoke<unknown[]>("get_active_flows");
  return result
    .map((item, index) =>
      safeParseWithLog(FlowExecutionStateSchema, item, `get_active_flows[${index}]`)
    )
    .filter((item): item is FlowExecutionState => item !== null);
}

export async function executeActionWithRetry(
  action: ClassifiedAction
): Promise<TabActionResult> {
  return invokeValidated("execute_action_with_retry", TabActionResultSchema, { action });
}

// ============ Page Classification Commands ============

export async function classifyCurrentPage(): Promise<ClassifiedAction[]> {
  const result = await invoke<unknown[]>("classify_current_page");
  return result
    .map((item, index) =>
      safeParseWithLog(ClassifiedActionSchema, item, `classify_current_page[${index}]`)
    )
    .filter((item): item is ClassifiedAction => item !== null);
}

// ============ Fast BFS Crawler Commands ============

export async function fastBfsCrawl(
  url: string,
  options?: {
    maxDepth?: number;
    maxPages?: number;
    parallelTabs?: number;
  }
): Promise<FastCrawlResult> {
  return invokeValidated("fast_bfs_crawl", FastCrawlResultSchema, {
    url,
    maxDepth: options?.maxDepth,
    maxPages: options?.maxPages,
    parallelTabs: options?.parallelTabs,
  });
}

/**
 * Parallel BFS crawl using multiple browser tabs for faster exploration
 * This is significantly faster than sequential crawling for large sites
 */
export async function parallelBfsCrawl(
  url: string,
  options?: {
    maxDepth?: number;
    maxPages?: number;
    parallelTabs?: number;
  }
): Promise<FastCrawlResult> {
  return invokeValidated("parallel_bfs_crawl", FastCrawlResultSchema, {
    url,
    maxDepth: options?.maxDepth,
    maxPages: options?.maxPages,
    parallelTabs: options?.parallelTabs,
  });
}

export async function getInteractionTree(): Promise<InteractionTree | null> {
  const result = await invoke("get_interaction_tree");
  if (result === null) return null;
  return safeParseWithLog(InteractionTreeSchema, result, "get_interaction_tree");
}

/**
 * TURBO BFS crawl - 10x faster URL discovery
 * Only extracts links, no full element analysis
 * Ideal for quickly mapping site structure before deep analysis
 */
export async function turboBfsCrawl(
  url: string,
  options?: {
    maxDepth?: number;
    maxPages?: number;
  }
): Promise<TurboCrawlResult> {
  return invokeValidated("turbo_bfs_crawl", TurboCrawlResultSchema, {
    url,
    maxDepth: options?.maxDepth,
    maxPages: options?.maxPages,
  });
}

/**
 * HYBRID BFS crawl - fastest comprehensive option
 * Phase 1: Turbo URL discovery (10-50 pages/sec)
 * Phase 2: Parallel element extraction (2-5 pages/sec with 10 tabs)
 * Best of both worlds: fast discovery + detailed analysis
 */
export async function hybridBfsCrawl(
  url: string,
  options?: {
    maxDepth?: number;
    maxPages?: number;
    parallelTabs?: number;
  }
): Promise<FastCrawlResult> {
  return invokeValidated("hybrid_bfs_crawl", FastCrawlResultSchema, {
    url,
    maxDepth: options?.maxDepth,
    maxPages: options?.maxPages,
    parallelTabs: options?.parallelTabs,
  });
}

// ============ Database Commands ============

/**
 * Initialize the database (call on app startup)
 */
export async function initDb(): Promise<string> {
  return invoke<string>("init_db");
}

/**
 * Save a crawl result to the database
 */
export async function saveCrawlToDb(
  tree: InteractionTree,
  crawlerType: string
): Promise<string> {
  return invoke<string>("save_crawl_to_db", { tree, crawlerType });
}

/**
 * Get all stored crawl sessions (history)
 */
export async function getCrawlHistory(): Promise<CrawlSessionSummary[]> {
  const result = await invoke<unknown[]>("get_crawl_history");
  return result
    .map((item, index) =>
      safeParseWithLog(CrawlSessionSummarySchema, item, `get_crawl_history[${index}]`)
    )
    .filter((item): item is CrawlSessionSummary => item !== null);
}

/**
 * Get issues from a specific crawl session
 */
export async function getCrawlIssues(sessionId: string): Promise<DetectedIssue[]> {
  const result = await invoke<unknown[]>("get_crawl_issues", { sessionId });
  return result
    .map((item, index) =>
      safeParseWithLog(DetectedIssueSchema, item, `get_crawl_issues[${index}]`)
    )
    .filter((item): item is DetectedIssue => item !== null);
}

/**
 * Compare two crawl sessions
 */
export async function compareCrawls(
  oldSessionId: string,
  newSessionId: string
): Promise<CrawlComparison> {
  return invokeValidated("compare_crawls", CrawlComparisonSchema, {
    oldSessionId,
    newSessionId,
  });
}

/**
 * Get database statistics
 */
export async function getDbStats(): Promise<DbStats> {
  return invokeValidated("get_db_stats", DbStatsSchema);
}

// ============ Simple Page Explorer Commands ============

export interface SimpleElement {
  mmid: string;
  tag: string;
  text: string;
  href: string | null;
  elementType: string;
  role: string | null;
  ariaLabel: string | null;
}

export interface PageElementsResult {
  navigationElements: SimpleElement[];
  inPageElements: SimpleElement[];
  url: string;
  title: string;
  screenshot: string | null;
}

export interface ClickObserveResult {
  success: boolean;
  message: string;
  urlChanged: boolean;
  newUrl: string | null;
  addedElements: SimpleElement[];
  removedElements: SimpleElement[];
  changeType: string;
  screenshotAfter: string | null;
}

/**
 * Get all interactive elements on the current page, categorized
 */
export async function explorePageElements(): Promise<PageElementsResult> {
  return invoke<PageElementsResult>("explore_page_elements");
}

/**
 * Click an element and observe what changes
 */
export async function clickAndObserve(mmid: string): Promise<ClickObserveResult> {
  return invoke<ClickObserveResult>("click_and_observe", { mmid });
}

/**
 * Click all non-navigation buttons and observe changes
 */
export async function exploreAllButtons(): Promise<ClickObserveResult[]> {
  return invoke<ClickObserveResult[]>("explore_all_buttons");
}

// ============ UI Interaction Tree ============

export interface UITreeNode {
  id: string;
  element: SimpleElement;
  children: UITreeNode[];
  clicked: boolean;
  causedNavigation: boolean;
  changeType: string;
  expanded: boolean;
}

export interface UITree {
  url: string;
  title: string;
  roots: UITreeNode[];
  navigationLinks: SimpleElement[];
  screenshot: string | null;
}

/**
 * Initialize UI tree for current page
 */
export async function initUITree(): Promise<UITree> {
  return invoke<UITree>("init_ui_tree");
}

/**
 * Click a tree node and update the tree with new children
 */
export async function clickTreeNode(nodeId: string): Promise<UITree> {
  return invoke<UITree>("click_tree_node", { nodeId });
}

/**
 * Get the current UI tree state
 */
export async function getUITree(): Promise<UITree | null> {
  return invoke<UITree | null>("get_ui_tree");
}
