/**
 * React Query configuration and custom hooks for Tauri API calls
 */

import { QueryClient } from "@tanstack/react-query";

// Query client with sensible defaults for desktop app
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Keep data fresh for 30 seconds
      staleTime: 30 * 1000,
      // Cache data for 5 minutes
      gcTime: 5 * 60 * 1000,
      // Retry failed queries 2 times
      retry: 2,
      // Don't refetch on window focus (desktop app behavior)
      refetchOnWindowFocus: false,
      // Refetch on reconnect
      refetchOnReconnect: true,
    },
    mutations: {
      // Retry mutations once
      retry: 1,
    },
  },
});

// Query keys for consistent cache management
export const queryKeys = {
  // Browser state
  browserStatus: ["browser", "status"] as const,

  // Page state
  currentState: ["page", "current"] as const,
  screenshot: ["page", "screenshot"] as const,

  // Exploration
  explorationStatus: ["exploration", "status"] as const,
  queueStats: ["exploration", "queue"] as const,
  dnaGraph: ["exploration", "dna"] as const,

  // Issues
  detectedIssues: ["issues", "list"] as const,
  issueSummary: ["issues", "summary"] as const,

  // Actionable elements
  actionableElements: (pageId: string) =>
    ["elements", "actionable", pageId] as const,

  // Database
  crawlHistory: ["db", "history"] as const,
  crawlIssues: (sessionId: string) => ["db", "issues", sessionId] as const,
  crawlComparison: (oldId: string, newId: string) =>
    ["db", "compare", oldId, newId] as const,
  dbStats: ["db", "stats"] as const,
} as const;

// Invalidation helpers
export const invalidateExploration = () => {
  queryClient.invalidateQueries({ queryKey: ["exploration"] });
  queryClient.invalidateQueries({ queryKey: ["issues"] });
};

export const invalidatePageState = () => {
  queryClient.invalidateQueries({ queryKey: ["page"] });
};

export const invalidateAll = () => {
  queryClient.invalidateQueries();
};
