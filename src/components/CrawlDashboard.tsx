/**
 * Crawl Dashboard - Main UI for viewing crawl results, history, and issues
 */

import { useState, useEffect } from "react";
import {
  useCrawlHistory,
  useCrawlIssues,
  useCrawlComparison,
  useDbStats,
  useInitDb,
  useSaveCrawlToDb,
} from "@/hooks/useApi";
import type {
  CrawlSessionSummary,
  InteractionTree,
  IssueSeverity,
} from "@/lib/schemas";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  History,
  Shield,
  GitCompare,
  Database,
  AlertCircle,
  AlertTriangle,
  Bug,
  Info,
  CheckCircle2,
  Clock,
  Globe,
  Layers,
  FileWarning,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  Save,
  RefreshCw,
  Loader2,
} from "lucide-react";

// Severity badge styling
const severityConfig: Record<IssueSeverity, { color: string; bg: string; icon: typeof AlertCircle }> = {
  critical: { color: "text-red-600", bg: "bg-red-100 dark:bg-red-950", icon: AlertCircle },
  high: { color: "text-orange-600", bg: "bg-orange-100 dark:bg-orange-950", icon: AlertTriangle },
  medium: { color: "text-yellow-600", bg: "bg-yellow-100 dark:bg-yellow-950", icon: Bug },
  low: { color: "text-blue-600", bg: "bg-blue-100 dark:bg-blue-950", icon: Info },
  info: { color: "text-gray-600", bg: "bg-gray-100 dark:bg-gray-950", icon: Info },
};

interface CrawlDashboardProps {
  currentTree?: InteractionTree | null;
  onSelectSession?: (session: CrawlSessionSummary) => void;
}

export function CrawlDashboard({ currentTree, onSelectSession }: CrawlDashboardProps) {
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [compareOldId, setCompareOldId] = useState<string | null>(null);
  const [compareNewId, setCompareNewId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<IssueSeverity | "all">("all");

  // Initialize database on mount
  const initDb = useInitDb();
  const saveCrawl = useSaveCrawlToDb();

  useEffect(() => {
    initDb.mutate();
  }, []);

  // Data fetching hooks
  const { data: history, isLoading: historyLoading, refetch: refetchHistory } = useCrawlHistory();
  const { data: sessionIssues, isLoading: issuesLoading } = useCrawlIssues(selectedSessionId);
  const { data: comparison, isLoading: comparisonLoading } = useCrawlComparison(
    compareOldId,
    compareNewId
  );
  const { data: dbStats, isLoading: statsLoading, refetch: refetchStats } = useDbStats();

  // Filter issues by severity
  const filteredIssues = sessionIssues?.filter(
    (issue) => severityFilter === "all" || issue.severity === severityFilter
  );

  // Save current crawl to database
  const handleSaveCrawl = () => {
    if (currentTree) {
      saveCrawl.mutate(
        { tree: currentTree, crawlerType: "hybrid" },
        {
          onSuccess: () => {
            refetchHistory();
            refetchStats();
          },
        }
      );
    }
  };

  // Format duration
  const formatDuration = (ms: number | null) => {
    if (!ms) return "N/A";
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };

  // Format date
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString() + " " + date.toLocaleTimeString();
  };

  // Format bytes
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="h-full flex flex-col">
      <Tabs defaultValue="history" className="flex-1 flex flex-col">
        <div className="flex items-center justify-between px-4 pt-2">
          <TabsList>
            <TabsTrigger value="history" className="gap-1">
              <History className="h-4 w-4" /> History
            </TabsTrigger>
            <TabsTrigger value="issues" className="gap-1">
              <Shield className="h-4 w-4" /> Issues
            </TabsTrigger>
            <TabsTrigger value="compare" className="gap-1">
              <GitCompare className="h-4 w-4" /> Compare
            </TabsTrigger>
            <TabsTrigger value="stats" className="gap-1">
              <Database className="h-4 w-4" /> Stats
            </TabsTrigger>
          </TabsList>

          {currentTree && (
            <Button
              size="sm"
              onClick={handleSaveCrawl}
              disabled={saveCrawl.isPending}
            >
              {saveCrawl.isPending ? (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              ) : (
                <Save className="h-4 w-4 mr-1" />
              )}
              Save Crawl
            </Button>
          )}
        </div>

        {/* History Tab */}
        <TabsContent value="history" className="flex-1 m-0 p-4">
          <Card className="h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">Crawl History</CardTitle>
                  <CardDescription>
                    Previous crawl sessions stored in database
                  </CardDescription>
                </div>
                <Button variant="outline" size="sm" onClick={() => refetchHistory()}>
                  <RefreshCw className="h-4 w-4 mr-1" /> Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden">
              {historyLoading ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : !history || history.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                  <History className="h-12 w-12 mb-4 opacity-30" />
                  <p>No crawl history yet</p>
                  <p className="text-sm">Run a crawl and save it to see it here</p>
                </div>
              ) : (
                <ScrollArea className="h-full">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Domain</TableHead>
                        <TableHead>Date</TableHead>
                        <TableHead className="text-right">Pages</TableHead>
                        <TableHead className="text-right">Elements</TableHead>
                        <TableHead className="text-right">Issues</TableHead>
                        <TableHead className="text-right">Duration</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {history.map((session) => (
                        <TableRow
                          key={session.id}
                          className={`cursor-pointer ${
                            selectedSessionId === session.id ? "bg-muted" : ""
                          }`}
                          onClick={() => {
                            setSelectedSessionId(session.id);
                            onSelectSession?.(session);
                          }}
                        >
                          <TableCell className="font-medium">
                            <div className="flex items-center gap-2">
                              <Globe className="h-4 w-4 text-muted-foreground" />
                              {session.domain}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1 text-sm text-muted-foreground">
                              <Clock className="h-3 w-3" />
                              {formatDate(session.startedAt)}
                            </div>
                          </TableCell>
                          <TableCell className="text-right">{session.totalPages}</TableCell>
                          <TableCell className="text-right">{session.totalElements}</TableCell>
                          <TableCell className="text-right">
                            {session.totalIssues > 0 ? (
                              <Badge variant="destructive" className="text-xs">
                                {session.totalIssues}
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="text-xs">0</Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-right">
                            {formatDuration(session.durationMs)}
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedSessionId(session.id);
                              }}
                            >
                              View
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Issues Tab */}
        <TabsContent value="issues" className="flex-1 m-0 p-4">
          <Card className="h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">Security & UX Issues</CardTitle>
                  <CardDescription>
                    {selectedSessionId
                      ? `Issues from selected session`
                      : "Select a session from history to view issues"}
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Select
                    value={severityFilter}
                    onValueChange={(v) => setSeverityFilter(v as IssueSeverity | "all")}
                  >
                    <SelectTrigger className="w-32">
                      <SelectValue placeholder="Filter" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden">
              {!selectedSessionId ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                  <Shield className="h-12 w-12 mb-4 opacity-30" />
                  <p>Select a session from History to view issues</p>
                </div>
              ) : issuesLoading ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : !filteredIssues || filteredIssues.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                  <CheckCircle2 className="h-12 w-12 mb-4 text-green-500 opacity-50" />
                  <p>No issues found</p>
                  <p className="text-sm">
                    {severityFilter !== "all"
                      ? `No ${severityFilter} severity issues`
                      : "This crawl session had no detected issues"}
                  </p>
                </div>
              ) : (
                <ScrollArea className="h-full">
                  <div className="space-y-3">
                    {filteredIssues.map((issue) => {
                      const config = severityConfig[issue.severity];
                      const Icon = config.icon;
                      return (
                        <Card key={issue.id} className={`${config.bg} border-l-4`} style={{
                          borderLeftColor: issue.severity === "critical" ? "#dc2626" :
                            issue.severity === "high" ? "#ea580c" :
                            issue.severity === "medium" ? "#ca8a04" :
                            issue.severity === "low" ? "#2563eb" : "#6b7280"
                        }}>
                          <CardContent className="p-4">
                            <div className="flex items-start gap-3">
                              <Icon className={`h-5 w-5 ${config.color} mt-0.5 flex-shrink-0`} />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="font-semibold">{issue.title}</span>
                                  <Badge
                                    variant={
                                      issue.severity === "critical"
                                        ? "destructive"
                                        : issue.severity === "high"
                                        ? "default"
                                        : "secondary"
                                    }
                                    className="text-xs"
                                  >
                                    {issue.severity}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    {issue.issueType.replace(/_/g, " ")}
                                  </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground mb-2">
                                  {issue.description}
                                </p>
                                <div className="text-xs text-muted-foreground truncate mb-2">
                                  <Globe className="h-3 w-3 inline mr-1" />
                                  {issue.pageUrl}
                                </div>
                                {issue.evidence && (
                                  <code className="text-xs bg-muted px-2 py-1 rounded block truncate mb-2">
                                    {issue.evidence}
                                  </code>
                                )}
                                {issue.recommendation && (
                                  <p className="text-sm text-green-600 dark:text-green-400">
                                    <CheckCircle2 className="h-3 w-3 inline mr-1" />
                                    {issue.recommendation}
                                  </p>
                                )}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Compare Tab */}
        <TabsContent value="compare" className="flex-1 m-0 p-4">
          <Card className="h-full flex flex-col">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg">Compare Crawl Sessions</CardTitle>
              <CardDescription>
                Compare two crawl sessions to see changes over time
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden">
              <div className="flex gap-4 mb-6">
                <div className="flex-1">
                  <label className="text-sm font-medium mb-2 block">Baseline (Old)</label>
                  <Select
                    value={compareOldId || ""}
                    onValueChange={(v) => setCompareOldId(v || null)}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select baseline session" />
                    </SelectTrigger>
                    <SelectContent>
                      {history?.map((session) => (
                        <SelectItem key={session.id} value={session.id}>
                          {session.domain} - {formatDate(session.startedAt)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1">
                  <label className="text-sm font-medium mb-2 block">Current (New)</label>
                  <Select
                    value={compareNewId || ""}
                    onValueChange={(v) => setCompareNewId(v || null)}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select current session" />
                    </SelectTrigger>
                    <SelectContent>
                      {history?.map((session) => (
                        <SelectItem key={session.id} value={session.id}>
                          {session.domain} - {formatDate(session.startedAt)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {!compareOldId || !compareNewId ? (
                <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                  <GitCompare className="h-12 w-12 mb-4 opacity-30" />
                  <p>Select two sessions to compare</p>
                </div>
              ) : comparisonLoading ? (
                <div className="flex items-center justify-center h-64">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : comparison ? (
                <div className="grid grid-cols-2 gap-6">
                  {/* Pages Comparison */}
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium">Pages</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">New Pages</span>
                          <div className="flex items-center gap-1">
                            <ArrowUpRight className="h-4 w-4 text-green-500" />
                            <span className="font-medium text-green-600">
                              +{comparison.newPages.length}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Removed Pages</span>
                          <div className="flex items-center gap-1">
                            <ArrowDownRight className="h-4 w-4 text-red-500" />
                            <span className="font-medium text-red-600">
                              -{comparison.removedPages.length}
                            </span>
                          </div>
                        </div>
                      </div>
                      {comparison.newPages.length > 0 && (
                        <div className="mt-4">
                          <p className="text-xs font-medium mb-2">New Pages:</p>
                          <ScrollArea className="h-24">
                            {comparison.newPages.map((url) => (
                              <p key={url} className="text-xs text-muted-foreground truncate">
                                {url}
                              </p>
                            ))}
                          </ScrollArea>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Issues Comparison */}
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium">Issues</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">New Issues</span>
                          <div className="flex items-center gap-1">
                            <ArrowUpRight className="h-4 w-4 text-red-500" />
                            <span className="font-medium text-red-600">
                              +{comparison.newIssues}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Resolved Issues</span>
                          <div className="flex items-center gap-1">
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                            <span className="font-medium text-green-600">
                              -{comparison.resolvedIssues}
                            </span>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Elements Comparison */}
                  <Card className="col-span-2">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium">Elements</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-8">
                        <div className="flex items-center gap-2">
                          <ArrowUpRight className="h-4 w-4 text-green-500" />
                          <span className="text-sm text-muted-foreground">New:</span>
                          <span className="font-medium text-green-600">
                            +{comparison.newElements}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <ArrowDownRight className="h-4 w-4 text-red-500" />
                          <span className="text-sm text-muted-foreground">Removed:</span>
                          <span className="font-medium text-red-600">
                            -{comparison.removedElements}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Minus className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm text-muted-foreground">Net Change:</span>
                          <span
                            className={`font-medium ${
                              comparison.newElements - comparison.removedElements > 0
                                ? "text-green-600"
                                : comparison.newElements - comparison.removedElements < 0
                                ? "text-red-600"
                                : "text-muted-foreground"
                            }`}
                          >
                            {comparison.newElements - comparison.removedElements > 0 ? "+" : ""}
                            {comparison.newElements - comparison.removedElements}
                          </span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Stats Tab */}
        <TabsContent value="stats" className="flex-1 m-0 p-4">
          <Card className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">Database Statistics</CardTitle>
                  <CardDescription>Storage and usage metrics</CardDescription>
                </div>
                <Button variant="outline" size="sm" onClick={() => refetchStats()}>
                  <RefreshCw className="h-4 w-4 mr-1" /> Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {statsLoading ? (
                <div className="flex items-center justify-center h-64">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : dbStats ? (
                <div className="grid grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-blue-100 dark:bg-blue-950">
                          <History className="h-6 w-6 text-blue-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{dbStats.totalSessions}</p>
                          <p className="text-sm text-muted-foreground">Crawl Sessions</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-green-100 dark:bg-green-950">
                          <Globe className="h-6 w-6 text-green-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{dbStats.totalPages}</p>
                          <p className="text-sm text-muted-foreground">Total Pages</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-orange-100 dark:bg-orange-950">
                          <Layers className="h-6 w-6 text-orange-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{dbStats.totalElements}</p>
                          <p className="text-sm text-muted-foreground">Total Elements</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-red-100 dark:bg-red-950">
                          <FileWarning className="h-6 w-6 text-red-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{dbStats.totalIssues}</p>
                          <p className="text-sm text-muted-foreground">Total Issues</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-purple-100 dark:bg-purple-950">
                          <Globe className="h-6 w-6 text-purple-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{dbStats.totalApis}</p>
                          <p className="text-sm text-muted-foreground">API Endpoints</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-lg bg-gray-100 dark:bg-gray-800">
                          <Database className="h-6 w-6 text-gray-600" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold">{formatBytes(dbStats.dbSizeBytes)}</p>
                          <p className="text-sm text-muted-foreground">Database Size</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="col-span-3">
                    <CardContent className="pt-6">
                      <p className="text-sm text-muted-foreground mb-2">Database Location</p>
                      <code className="text-sm bg-muted px-3 py-2 rounded block">
                        {dbStats.dbPath}
                      </code>
                    </CardContent>
                  </Card>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                  <Database className="h-12 w-12 mb-4 opacity-30" />
                  <p>No database statistics available</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default CrawlDashboard;
