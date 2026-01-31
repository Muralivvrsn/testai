/**
 * React Query hooks for Tauri API calls
 * Provides caching, automatic refetching, and loading/error states
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { queryKeys, invalidateExploration, invalidatePageState } from "@/lib/query";
import * as api from "@/lib/api";
import type {
  PageState,
  ActionResult,
  ApplicationDNA,
  AutoExploreStartResult,
  ExplorationIterationResult,
  DetectedIssue,
  FastCrawlResult,
  TurboCrawlResult,
  CrawlSessionSummary,
  CrawlComparison,
  DbStats,
  InteractionTree,
} from "@/lib/schemas";

// ============ Browser Hooks ============

export function useStartBrowser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.startBrowser,
    onSuccess: () => {
      queryClient.setQueryData(queryKeys.browserStatus, true);
    },
  });
}

export function useStartBrowserWithProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profilePath: string) => api.startBrowserWithProfile(profilePath),
    onSuccess: () => {
      queryClient.setQueryData(queryKeys.browserStatus, true);
    },
  });
}

export function useStopBrowser() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.stopBrowser,
    onSuccess: () => {
      queryClient.setQueryData(queryKeys.browserStatus, false);
      // Clear all cached data when browser stops
      queryClient.clear();
    },
  });
}

// ============ Navigation Hooks ============

export function useNavigateTo() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (url: string) => api.navigateTo(url),
    onSuccess: (data: PageState) => {
      queryClient.setQueryData(queryKeys.currentState, data);
      invalidatePageState();
    },
  });
}

export function useGoBack() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.goBack,
    onSuccess: (data: PageState) => {
      queryClient.setQueryData(queryKeys.currentState, data);
      invalidatePageState();
    },
  });
}

// ============ Page State Hooks ============

export function useCurrentState(enabled = true) {
  return useQuery<PageState | null>({
    queryKey: queryKeys.currentState,
    queryFn: api.getCurrentState,
    enabled,
    staleTime: 5000, // Page state changes frequently
  });
}

export function useScreenshot(enabled = true) {
  return useQuery<string | null>({
    queryKey: queryKeys.screenshot,
    queryFn: api.captureScreenshot,
    enabled,
    staleTime: 10000,
  });
}

// ============ Action Hooks ============

export function useClickElement() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (mmid: string) => api.clickElement(mmid),
    onSuccess: (data: ActionResult) => {
      if (data.newState) {
        queryClient.setQueryData(queryKeys.currentState, data.newState);
      }
      invalidatePageState();
    },
  });
}

export function useInputText() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ mmid, text }: { mmid: string; text: string }) =>
      api.inputText(mmid, text),
    onSuccess: (data: ActionResult) => {
      if (data.newState) {
        queryClient.setQueryData(queryKeys.currentState, data.newState);
      }
    },
  });
}

// ============ Exploration Hooks ============

export function useStartExploration() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ url, maxDepth }: { url: string; maxDepth?: number }) =>
      api.startAutonomousExploration(url, maxDepth),
    onSuccess: (data: AutoExploreStartResult) => {
      queryClient.setQueryData(queryKeys.explorationStatus, true);
      if (data.initialState) {
        queryClient.setQueryData(queryKeys.currentState, data.initialState);
      }
      invalidateExploration();
    },
  });
}

export function useRunIteration() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (parallelTabs?: number) => api.runExplorationIteration(parallelTabs),
    onSuccess: (data: ExplorationIterationResult) => {
      // Update exploration status based on completion
      if (data.explorationComplete) {
        queryClient.setQueryData(queryKeys.explorationStatus, false);
      }
      invalidateExploration();
    },
  });
}

export function useStopExploration() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.stopAutonomousExploration,
    onSuccess: (data: ApplicationDNA | null) => {
      queryClient.setQueryData(queryKeys.explorationStatus, false);
      if (data) {
        queryClient.setQueryData(queryKeys.dnaGraph, data);
      }
      invalidateExploration();
    },
  });
}

export function useIsExploring(enabled = true) {
  return useQuery<boolean>({
    queryKey: queryKeys.explorationStatus,
    queryFn: api.isExploring,
    enabled,
    refetchInterval: 2000, // Poll while exploring
  });
}

export function useQueueStats(enabled = true) {
  return useQuery<Record<string, number>>({
    queryKey: queryKeys.queueStats,
    queryFn: api.getQueueStats,
    enabled,
    staleTime: 1000, // Queue stats change frequently during exploration
    refetchInterval: (query) => {
      // Refetch more frequently during exploration
      return query.state.data ? 2000 : false;
    },
  });
}

export function useDnaGraph(enabled = true) {
  return useQuery<ApplicationDNA | null>({
    queryKey: queryKeys.dnaGraph,
    queryFn: api.getDnaGraph,
    enabled,
    staleTime: 5000,
  });
}

// ============ Issue Detection Hooks ============

export function useDetectedIssues(enabled = true) {
  return useQuery<DetectedIssue[]>({
    queryKey: queryKeys.detectedIssues,
    queryFn: api.getDetectedIssues,
    enabled,
    staleTime: 10000,
  });
}

export function useIssueSummary(enabled = true) {
  return useQuery<Record<string, number>>({
    queryKey: queryKeys.issueSummary,
    queryFn: api.getIssueSummary,
    enabled,
    staleTime: 10000,
  });
}

// ============ Utility Hooks ============

export function useDefaultChromeProfilePath() {
  return useQuery<string>({
    queryKey: ["chrome", "profilePath"],
    queryFn: api.getDefaultChromeProfilePath,
    staleTime: Infinity, // Path doesn't change
  });
}

// ============ Fast BFS Crawler Hooks ============

export function useFastBfsCrawl() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      url,
      maxDepth,
      maxPages,
      parallelTabs,
    }: {
      url: string;
      maxDepth?: number;
      maxPages?: number;
      parallelTabs?: number;
    }) => api.fastBfsCrawl(url, { maxDepth, maxPages, parallelTabs }),
    onSuccess: (data: FastCrawlResult) => {
      // Cache the crawl result
      queryClient.setQueryData(["crawl", "result"], data);
      // Invalidate exploration queries since we have new data
      invalidateExploration();
    },
  });
}

export function useParallelBfsCrawl() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      url,
      maxDepth,
      maxPages,
      parallelTabs,
    }: {
      url: string;
      maxDepth?: number;
      maxPages?: number;
      parallelTabs?: number;
    }) => api.parallelBfsCrawl(url, { maxDepth, maxPages, parallelTabs }),
    onSuccess: (data: FastCrawlResult) => {
      // Cache the crawl result
      queryClient.setQueryData(["crawl", "result"], data);
      // Invalidate exploration queries since we have new data
      invalidateExploration();
    },
  });
}

/**
 * TURBO BFS Crawl - 10x faster URL discovery
 * Only extracts links, skips full element analysis
 */
export function useTurboBfsCrawl() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      url,
      maxDepth,
      maxPages,
    }: {
      url: string;
      maxDepth?: number;
      maxPages?: number;
    }) => api.turboBfsCrawl(url, { maxDepth, maxPages }),
    onSuccess: (data: TurboCrawlResult) => {
      // Cache the turbo crawl result
      queryClient.setQueryData(["crawl", "turbo"], data);
    },
  });
}

/**
 * HYBRID BFS Crawl - fastest comprehensive option
 * Phase 1: Turbo URL discovery (10-50 pages/sec)
 * Phase 2: Parallel element extraction (2-5 pages/sec)
 */
export function useHybridBfsCrawl() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      url,
      maxDepth,
      maxPages,
      parallelTabs,
    }: {
      url: string;
      maxDepth?: number;
      maxPages?: number;
      parallelTabs?: number;
    }) => api.hybridBfsCrawl(url, { maxDepth, maxPages, parallelTabs }),
    onSuccess: (data: FastCrawlResult) => {
      // Cache the crawl result
      queryClient.setQueryData(["crawl", "result"], data);
      invalidateExploration();
    },
  });
}

// ============ Database Hooks ============

/**
 * Initialize the database on app startup
 */
export function useInitDb() {
  return useMutation({
    mutationFn: api.initDb,
  });
}

/**
 * Save crawl results to database
 */
export function useSaveCrawlToDb() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      tree,
      crawlerType,
    }: {
      tree: InteractionTree;
      crawlerType: string;
    }) => api.saveCrawlToDb(tree, crawlerType),
    onSuccess: () => {
      // Invalidate history to show new session
      queryClient.invalidateQueries({ queryKey: queryKeys.crawlHistory });
      queryClient.invalidateQueries({ queryKey: queryKeys.dbStats });
    },
  });
}

/**
 * Get crawl history from database
 */
export function useCrawlHistory(enabled = true) {
  return useQuery<CrawlSessionSummary[]>({
    queryKey: queryKeys.crawlHistory,
    queryFn: api.getCrawlHistory,
    enabled,
    staleTime: 30000,
  });
}

/**
 * Get issues for a specific crawl session
 */
export function useCrawlIssues(sessionId: string | null) {
  return useQuery<DetectedIssue[]>({
    queryKey: queryKeys.crawlIssues(sessionId || ""),
    queryFn: () => api.getCrawlIssues(sessionId!),
    enabled: !!sessionId,
    staleTime: 60000,
  });
}

/**
 * Compare two crawl sessions
 */
export function useCrawlComparison(
  oldSessionId: string | null,
  newSessionId: string | null
) {
  return useQuery<CrawlComparison>({
    queryKey: queryKeys.crawlComparison(oldSessionId || "", newSessionId || ""),
    queryFn: () => api.compareCrawls(oldSessionId!, newSessionId!),
    enabled: !!oldSessionId && !!newSessionId,
    staleTime: 60000,
  });
}

/**
 * Get database statistics
 */
export function useDbStats(enabled = true) {
  return useQuery<DbStats>({
    queryKey: queryKeys.dbStats,
    queryFn: api.getDbStats,
    enabled,
    staleTime: 30000,
  });
}
