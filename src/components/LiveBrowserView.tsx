/**
 * Live Browser View - Shows headless Chrome screenshots in real-time
 * Simple page explorer - click buttons and see what changes
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  explorePageElements,
  clickAndObserve,
  type SimpleElement,
  type PageElementsResult,
  type ClickObserveResult,
} from "@/lib/api";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Play,
  Square,
  RefreshCw,
  Loader2,
  MousePointer,
  Link2,
  ToggleLeft,
  ChevronDown,
  Type,
  Globe,
  Layers,
  Plus,
  Minus,
  ArrowRight,
} from "lucide-react";

export function LiveBrowserView() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("Enter a URL to start");
  const [loading, setLoading] = useState(false);
  const [browserRunning, setBrowserRunning] = useState(false);

  // Screenshot state
  const [screenshot, setScreenshot] = useState<string | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const streamingRef = useRef(false);

  // Page elements state
  const [pageElements, setPageElements] = useState<PageElementsResult | null>(null);
  const [selectedElement, setSelectedElement] = useState<SimpleElement | null>(null);

  // Click results
  const [clickResults, setClickResults] = useState<ClickObserveResult[]>([]);

  // Start browser
  async function startBrowser() {
    setLoading(true);
    setStatus("Starting headless browser...");
    try {
      await invoke("start_browser");
      setBrowserRunning(true);
      setStatus("Browser started (headless mode)");
      // Start screenshot streaming
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
      setPageElements(null);
      setStatus("Browser stopped");
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Navigate to URL
  async function navigateToUrl() {
    if (!url.trim()) {
      setStatus("Please enter a URL");
      return;
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }

    setLoading(true);
    setStatus(`Navigating to ${targetUrl}...`);
    setPageElements(null);
    setClickResults([]);

    try {
      await invoke("navigate_to", { url: targetUrl });
      setStatus("Page loaded, analyzing elements...");

      // Get elements after navigation
      const elements = await explorePageElements();
      setPageElements(elements);
      setScreenshot(elements.screenshot);

      setStatus(`Found ${elements.inPageElements.length} buttons, ${elements.navigationElements.length} links`);
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Screenshot streaming
  const captureScreenshot = useCallback(async () => {
    if (!browserRunning) return;
    try {
      const img = await invoke<string | null>("capture_screenshot");
      if (img) {
        setScreenshot(img);
      }
    } catch (e) {
      // Ignore errors during streaming
    }
  }, [browserRunning]);

  const startScreenshotStream = useCallback(() => {
    if (streamingRef.current) return;
    streamingRef.current = true;
    setIsStreaming(true);

    const stream = async () => {
      while (streamingRef.current) {
        await captureScreenshot();
        await new Promise((resolve) => setTimeout(resolve, 200)); // 5 FPS
      }
    };
    stream();
  }, [captureScreenshot]);

  const stopScreenshotStream = useCallback(() => {
    streamingRef.current = false;
    setIsStreaming(false);
  }, []);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      streamingRef.current = false;
    };
  }, []);

  // Click element and observe
  async function handleClickElement(element: SimpleElement) {
    setSelectedElement(element);
    setLoading(true);
    setStatus(`Clicking: ${element.text || element.tag}...`);

    try {
      const result = await clickAndObserve(element.mmid);
      setClickResults((prev) => [...prev, result]);

      if (result.screenshotAfter) {
        setScreenshot(result.screenshotAfter);
      }

      if (result.urlChanged) {
        setStatus(`Navigated to: ${result.newUrl}`);
        // Refresh elements after navigation
        const elements = await explorePageElements();
        setPageElements(elements);
      } else if (result.addedElements.length > 0) {
        setStatus(`${result.changeType}: ${result.addedElements.length} new elements appeared`);
        // Refresh elements
        const elements = await explorePageElements();
        setPageElements(elements);
      } else {
        setStatus(result.message);
      }
    } catch (error) {
      setStatus(`Click failed: ${error}`);
    }
    setLoading(false);
  }

  // Refresh elements
  async function refreshElements() {
    setLoading(true);
    setStatus("Refreshing elements...");
    try {
      const elements = await explorePageElements();
      setPageElements(elements);
      if (elements.screenshot) {
        setScreenshot(elements.screenshot);
      }
      setStatus(`Found ${elements.inPageElements.length} buttons, ${elements.navigationElements.length} links`);
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Get icon for element type
  const getElementIcon = (type: string) => {
    switch (type) {
      case "button":
        return <MousePointer className="h-4 w-4 text-orange-500" />;
      case "link":
        return <Link2 className="h-4 w-4 text-blue-500" />;
      case "toggle":
        return <ToggleLeft className="h-4 w-4 text-green-500" />;
      case "dropdown":
        return <ChevronDown className="h-4 w-4 text-purple-500" />;
      case "input":
        return <Type className="h-4 w-4 text-cyan-500" />;
      default:
        return <Layers className="h-4 w-4 text-gray-500" />;
    }
  };

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="border-b px-4 py-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">TESTAI - Live Browser</h1>
            <p className="text-sm text-muted-foreground">
              Headless Chrome with live view
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-80"
              onKeyDown={(e) => e.key === "Enter" && navigateToUrl()}
              disabled={!browserRunning || loading}
            />
            <Button onClick={navigateToUrl} disabled={!browserRunning || loading}>
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
                Start Browser
              </Button>
            )}
          </div>
        </div>
        <div className="flex items-center gap-4 mt-2">
          <p className={`text-sm ${loading ? "text-primary" : "text-muted-foreground"}`}>
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
        {/* Live Browser View */}
        <div className="flex-1 p-4 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-medium">Browser View</h2>
            <Button variant="outline" size="sm" onClick={refreshElements} disabled={!browserRunning || loading}>
              <RefreshCw className="h-3 w-3 mr-1" /> Refresh
            </Button>
          </div>
          <div className="flex-1 border rounded-lg overflow-hidden bg-muted/30 flex items-center justify-center">
            {screenshot ? (
              <img
                src={`data:image/png;base64,${screenshot}`}
                alt="Browser view"
                className="max-w-full max-h-full object-contain"
              />
            ) : browserRunning ? (
              <div className="text-muted-foreground text-center">
                <Globe className="h-12 w-12 mx-auto mb-2 opacity-30" />
                <p>Enter a URL and click Go</p>
              </div>
            ) : (
              <div className="text-muted-foreground text-center">
                <Globe className="h-12 w-12 mx-auto mb-2 opacity-30" />
                <p>Click "Start Browser" to begin</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - Elements & Results */}
        <div className="w-[400px] border-l flex flex-col">
          <Tabs defaultValue="buttons" className="flex-1 flex flex-col">
            <TabsList className="mx-2 mt-2">
              <TabsTrigger value="buttons" className="text-xs">
                <MousePointer className="h-3 w-3 mr-1" />
                Buttons ({pageElements?.inPageElements.length || 0})
              </TabsTrigger>
              <TabsTrigger value="links" className="text-xs">
                <Link2 className="h-3 w-3 mr-1" />
                Links ({pageElements?.navigationElements.length || 0})
              </TabsTrigger>
              <TabsTrigger value="changes" className="text-xs">
                <ArrowRight className="h-3 w-3 mr-1" />
                Changes ({clickResults.length})
              </TabsTrigger>
            </TabsList>

            {/* Buttons/In-page Elements */}
            <TabsContent value="buttons" className="flex-1 m-0 overflow-hidden">
              <ScrollArea className="h-full">
                <div className="p-2 space-y-1">
                  {pageElements?.inPageElements.map((el) => (
                    <button
                      key={el.mmid}
                      className={`w-full text-left p-2 rounded border hover:bg-muted/50 transition-colors ${
                        selectedElement?.mmid === el.mmid ? "bg-primary/10 border-primary" : ""
                      }`}
                      onClick={() => handleClickElement(el)}
                      disabled={loading}
                    >
                      <div className="flex items-center gap-2">
                        {getElementIcon(el.elementType)}
                        <span className="flex-1 truncate text-sm">{el.text || `<${el.tag}>`}</span>
                        <Badge variant="outline" className="text-xs">{el.elementType}</Badge>
                      </div>
                    </button>
                  ))}
                  {!pageElements?.inPageElements.length && (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      No buttons found. Navigate to a page first.
                    </p>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* Links/Navigation Elements */}
            <TabsContent value="links" className="flex-1 m-0 overflow-hidden">
              <ScrollArea className="h-full">
                <div className="p-2 space-y-1">
                  {pageElements?.navigationElements.map((el) => (
                    <div
                      key={el.mmid}
                      className="p-2 rounded border"
                    >
                      <div className="flex items-center gap-2">
                        <Link2 className="h-4 w-4 text-blue-500" />
                        <span className="flex-1 truncate text-sm">{el.text || el.href}</span>
                      </div>
                      {el.href && (
                        <p className="text-xs text-muted-foreground truncate mt-1 pl-6">
                          {el.href}
                        </p>
                      )}
                    </div>
                  ))}
                  {!pageElements?.navigationElements.length && (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      No links found.
                    </p>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* Click Results / Changes */}
            <TabsContent value="changes" className="flex-1 m-0 overflow-hidden">
              <ScrollArea className="h-full">
                <div className="p-2 space-y-2">
                  {clickResults.map((result, index) => (
                    <Card key={index} className={result.urlChanged ? "border-blue-500" : ""}>
                      <CardContent className="p-3">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant={result.urlChanged ? "default" : "secondary"}>
                            {result.changeType}
                          </Badge>
                          {result.urlChanged && (
                            <Badge variant="outline">Navigation</Badge>
                          )}
                        </div>
                        <p className="text-sm">{result.message}</p>
                        {result.addedElements.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs text-muted-foreground flex items-center gap-1">
                              <Plus className="h-3 w-3 text-green-500" />
                              {result.addedElements.length} new elements
                            </p>
                          </div>
                        )}
                        {result.removedElements.length > 0 && (
                          <div className="mt-1">
                            <p className="text-xs text-muted-foreground flex items-center gap-1">
                              <Minus className="h-3 w-3 text-red-500" />
                              {result.removedElements.length} removed
                            </p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                  {clickResults.length === 0 && (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      Click buttons to see UI changes here.
                    </p>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}

export default LiveBrowserView;
