/**
 * Interaction Tree View - Shows clickable elements as a tree
 * When you click an element, children appear (elements that showed up after click)
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  initUITree,
  clickTreeNode,
  type UITree,
  type UITreeNode,
} from "@/lib/api";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Play,
  Square,
  Loader2,
  ChevronRight,
  ChevronDown,
  MousePointer,
  Link2,
  ToggleLeft,
  Menu,
  Type,
  Globe,
  Layers,
  Circle,
  CheckCircle,
  ArrowRight,
  RefreshCw,
} from "lucide-react";

// Tree node component
function TreeNodeView({
  node,
  depth,
  onClickNode,
  isLoading,
}: {
  node: UITreeNode;
  depth: number;
  onClickNode: (id: string) => void;
  isLoading: boolean;
}) {
  const [isExpanded, setIsExpanded] = useState(node.expanded);

  const hasChildren = node.children.length > 0;

  const getIcon = () => {
    switch (node.element.elementType) {
      case "button":
        return <MousePointer className="h-4 w-4 text-orange-500" />;
      case "dropdown":
        return <Menu className="h-4 w-4 text-purple-500" />;
      case "toggle":
        return <ToggleLeft className="h-4 w-4 text-green-500" />;
      case "input":
        return <Type className="h-4 w-4 text-cyan-500" />;
      default:
        return <Circle className="h-4 w-4 text-gray-400" />;
    }
  };

  const getChangeIcon = () => {
    if (node.causedNavigation) {
      return <ArrowRight className="h-3 w-3 text-blue-500" />;
    }
    if (node.changeType === "modal") {
      return <Layers className="h-3 w-3 text-purple-500" />;
    }
    if (node.changeType === "dropdown") {
      return <ChevronDown className="h-3 w-3 text-purple-500" />;
    }
    if (node.changeType === "content") {
      return <CheckCircle className="h-3 w-3 text-green-500" />;
    }
    return null;
  };

  return (
    <div className="select-none">
      <div
        className={`flex items-center gap-1 py-1 px-2 rounded hover:bg-muted/50 cursor-pointer ${
          node.clicked ? "bg-muted/30" : ""
        }`}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => {
          if (hasChildren) {
            setIsExpanded(!isExpanded);
          } else if (!node.clicked && !isLoading) {
            onClickNode(node.id);
          }
        }}
      >
        {/* Expand/collapse or status indicator */}
        <span className="w-4 flex-shrink-0">
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )
          ) : node.clicked ? (
            getChangeIcon()
          ) : (
            <span className="w-4" />
          )}
        </span>

        {/* Element icon */}
        {getIcon()}

        {/* Element text */}
        <span className={`flex-1 truncate text-sm ${node.clicked ? "text-muted-foreground" : ""}`}>
          {node.element.text || `<${node.element.tag}>`}
        </span>

        {/* Badges */}
        {node.clicked && (
          <Badge variant="outline" className="text-[10px] h-4">
            {node.children.length > 0 ? `${node.children.length} children` : node.changeType}
          </Badge>
        )}

        {/* Click indicator */}
        {!node.clicked && !hasChildren && (
          <Badge variant="secondary" className="text-[10px] h-4">
            click
          </Badge>
        )}
      </div>

      {/* Children */}
      {isExpanded && hasChildren && (
        <div>
          {node.children.map((child) => (
            <TreeNodeView
              key={child.id}
              node={child}
              depth={depth + 1}
              onClickNode={onClickNode}
              isLoading={isLoading}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function InteractionTreeView() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("Enter a URL to start");
  const [loading, setLoading] = useState(false);
  const [browserRunning, setBrowserRunning] = useState(false);
  const [clickingNode, setClickingNode] = useState<string | null>(null);

  // Tree state
  const [tree, setTree] = useState<UITree | null>(null);

  // Screenshot state
  const [screenshot, setScreenshot] = useState<string | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const streamingRef = useRef(false);

  // Start browser
  async function startBrowser() {
    setLoading(true);
    setStatus("Starting headless browser...");
    try {
      await invoke("start_browser");
      setBrowserRunning(true);
      setStatus("Browser started");
      startScreenshotStream();
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Stop browser
  async function stopBrowser() {
    setLoading(true);
    stopScreenshotStream();
    try {
      await invoke("stop_browser");
      setBrowserRunning(false);
      setScreenshot(null);
      setTree(null);
      setStatus("Browser stopped");
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Navigate and initialize tree
  async function navigateAndInit() {
    if (!url.trim()) {
      setStatus("Please enter a URL");
      return;
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }

    setLoading(true);
    setStatus(`Loading ${targetUrl}...`);
    setTree(null);

    try {
      await invoke("navigate_to", { url: targetUrl });
      setStatus("Building interaction tree...");

      const uiTree = await initUITree();
      setTree(uiTree);
      if (uiTree.screenshot) {
        setScreenshot(uiTree.screenshot);
      }

      setStatus(`Found ${uiTree.roots.length} interactive elements, ${uiTree.navigationLinks.length} links`);
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Click a tree node
  async function handleClickNode(nodeId: string) {
    setClickingNode(nodeId);
    setStatus(`Clicking element...`);

    try {
      const updatedTree = await clickTreeNode(nodeId);
      setTree(updatedTree);
      if (updatedTree.screenshot) {
        setScreenshot(updatedTree.screenshot);
      }

      // Find the clicked node to report what happened
      const findNode = (nodes: UITreeNode[], id: string): UITreeNode | null => {
        for (const n of nodes) {
          if (n.id === id) return n;
          const found = findNode(n.children, id);
          if (found) return found;
        }
        return null;
      };

      const clickedNode = findNode(updatedTree.roots, nodeId);
      if (clickedNode) {
        if (clickedNode.causedNavigation) {
          setStatus(`Navigated to: ${updatedTree.url}`);
        } else if (clickedNode.children.length > 0) {
          setStatus(`${clickedNode.changeType}: ${clickedNode.children.length} new elements appeared`);
        } else {
          setStatus(`Clicked: ${clickedNode.changeType}`);
        }
      }
    } catch (error) {
      setStatus(`Click error: ${error}`);
    }

    setClickingNode(null);
  }

  // Screenshot streaming
  const captureScreenshot = useCallback(async () => {
    if (!browserRunning) return;
    try {
      const img = await invoke<string | null>("capture_screenshot");
      if (img) setScreenshot(img);
    } catch (e) {
      // Ignore
    }
  }, [browserRunning]);

  const startScreenshotStream = useCallback(() => {
    if (streamingRef.current) return;
    streamingRef.current = true;
    setIsStreaming(true);
    const stream = async () => {
      while (streamingRef.current) {
        await captureScreenshot();
        await new Promise((r) => setTimeout(r, 300)); // ~3 FPS
      }
    };
    stream();
  }, [captureScreenshot]);

  const stopScreenshotStream = useCallback(() => {
    streamingRef.current = false;
    setIsStreaming(false);
  }, []);

  useEffect(() => {
    return () => {
      streamingRef.current = false;
    };
  }, []);

  // Refresh tree
  async function refreshTree() {
    setLoading(true);
    setStatus("Refreshing tree...");
    try {
      const uiTree = await initUITree();
      setTree(uiTree);
      if (uiTree.screenshot) setScreenshot(uiTree.screenshot);
      setStatus(`Refreshed: ${uiTree.roots.length} elements`);
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="border-b px-4 py-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">UI Interaction Tree</h1>
            <p className="text-sm text-muted-foreground">
              Click elements to discover their children
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-80"
              onKeyDown={(e) => e.key === "Enter" && navigateAndInit()}
              disabled={!browserRunning || loading}
            />
            <Button onClick={navigateAndInit} disabled={!browserRunning || loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4 mr-1" />}
              Go
            </Button>
            {browserRunning ? (
              <Button variant="destructive" size="sm" onClick={stopBrowser} disabled={loading}>
                <Square className="h-4 w-4 mr-1" /> Stop
              </Button>
            ) : (
              <Button onClick={startBrowser} disabled={loading}>
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                Start
              </Button>
            )}
          </div>
        </div>
        <div className="flex items-center gap-4 mt-2">
          <p className={`text-sm ${loading || clickingNode ? "text-primary" : "text-muted-foreground"}`}>
            {status}
          </p>
          {isStreaming && (
            <Badge variant="outline" className="text-xs">
              <span className="w-2 h-2 bg-green-500 rounded-full mr-1 animate-pulse" />
              Live
            </Badge>
          )}
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex min-h-0">
        {/* Browser View */}
        <div className="flex-1 p-4 flex flex-col">
          <div className="flex-1 border rounded-lg overflow-hidden bg-muted/30 flex items-center justify-center">
            {screenshot ? (
              <img
                src={`data:image/png;base64,${screenshot}`}
                alt="Browser"
                className="max-w-full max-h-full object-contain"
              />
            ) : (
              <div className="text-muted-foreground text-center">
                <Globe className="h-12 w-12 mx-auto mb-2 opacity-30" />
                <p>{browserRunning ? "Enter a URL and click Go" : "Click Start to begin"}</p>
              </div>
            )}
          </div>
        </div>

        {/* Tree Panel */}
        <div className="w-[400px] border-l flex flex-col">
          <div className="p-3 border-b flex items-center justify-between">
            <h2 className="font-medium text-sm">
              {tree ? `${tree.title || "Page"}` : "Interaction Tree"}
            </h2>
            {tree && (
              <Button variant="ghost" size="sm" onClick={refreshTree} disabled={loading}>
                <RefreshCw className="h-3 w-3" />
              </Button>
            )}
          </div>

          <ScrollArea className="flex-1">
            <div className="p-2">
              {tree ? (
                <>
                  {/* Interactive elements tree */}
                  <div className="mb-4">
                    <p className="text-xs text-muted-foreground px-2 py-1">
                      Clickable Elements ({tree.roots.length})
                    </p>
                    {tree.roots.map((node) => (
                      <TreeNodeView
                        key={node.id}
                        node={node}
                        depth={0}
                        onClickNode={handleClickNode}
                        isLoading={clickingNode !== null}
                      />
                    ))}
                  </div>

                  {/* Navigation links */}
                  {tree.navigationLinks.length > 0 && (
                    <div>
                      <p className="text-xs text-muted-foreground px-2 py-1 border-t pt-3">
                        Navigation Links ({tree.navigationLinks.length})
                      </p>
                      {tree.navigationLinks.map((link) => (
                        <div
                          key={link.mmid}
                          className="flex items-center gap-2 py-1 px-2 text-sm"
                        >
                          <Link2 className="h-4 w-4 text-blue-500 flex-shrink-0" />
                          <span className="truncate">{link.text || link.href}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">
                  Navigate to a page to see the interaction tree
                </p>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}

export default InteractionTreeView;
