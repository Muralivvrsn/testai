/**
 * YaliTest - React UI for Electron
 *
 * Left panel: Controls, viewport selector, and element list
 * Right side: Embedded BrowserView (controlled by main process)
 */

import { useState, useEffect, ReactNode } from "react";
import {
  Play,
  Square,
  ChevronLeft,
  ChevronRight,
  RotateCw,
  Monitor,
  Laptop,
  Tablet,
  Smartphone,
  Maximize2,
  ChevronUp,
  ChevronDown,
  Bot,
  Pause,
  StopCircle,
  BarChart3,
  Globe,
  Search,
  Link,
  MousePointer2,
  TextCursor,
  FileText,
  ChevronDownSquare,
  CheckSquare,
  Circle,
  ToggleLeft,
  Pin,
  Layers,
  Hand,
  Compass,
  Keyboard,
  List,
  Send,
  Check,
  X,
  ExternalLink,
  Plus,
  AlertCircle,
  Target,
  RefreshCw,
  FlaskConical
} from "lucide-react";
import "./App.css";

// Types for DOM elements
interface DOMElement {
  mmid: string;
  tag: string;
  text: string;
  elementType: string;
  attributes: Record<string, string>;
  rect: { x: number; y: number; width: number; height: number } | null;
  visible: boolean;
  interactive: boolean;
}

interface ViewportPreset {
  width: number | null;
  height: number | null;
  name: string;
  icon: string;
}

interface ViewportInfo {
  viewport: string;
  width: number;
  height: number;
  displayWidth?: number;
  displayHeight?: number;
  scale?: number;
  preset: ViewportPreset | null;
}

// Automation types
interface AutomationAction {
  mmid: string;
  tag: string;
  text: string;
  classification: string;
  timestamp: number;
  urlBefore: string;
  urlAfter: string | null;
  success: boolean;
  error: string | null;
  newElements: number;
  inputValue?: string;
  navigated?: boolean;
}

interface AutomationStats {
  total: number;
  clicked: number;
  inputs: number;
  navigations: number;
  errors: number;
}

interface AutomationState {
  running: boolean;
  paused: boolean;
  queueSize: number;
  processedCount: number;
  stats: AutomationStats;
  currentAction: DOMElement | null;
  history: AutomationAction[];
}

// Type declaration for Electron API
declare global {
  interface Window {
    yalitest: {
      startEngine: () => Promise<{ success: boolean; error?: string }>;
      stopEngine: () => Promise<{ success: boolean }>;
      navigate: (url: string) => Promise<{ success: boolean; url?: string; error?: string }>;
      goBack: () => Promise<{ success: boolean; error?: string }>;
      goForward: () => Promise<{ success: boolean; error?: string }>;
      reload: () => Promise<{ success: boolean; error?: string }>;
      clickElement: (mmid: string) => Promise<{ success: boolean; error?: string }>;
      inputText: (mmid: string, text: string) => Promise<{ success: boolean; error?: string }>;
      getState: () => Promise<{ url: string; title: string; elements: DOMElement[] }>;
      refreshElements: () => Promise<{ success: boolean; elements: DOMElement[] }>;
      takeScreenshot: () => Promise<{ success: boolean; dataUrl?: string; error?: string }>;
      // Automation
      startAutomation: () => Promise<{ success: boolean; queueSize?: number; error?: string }>;
      pauseAutomation: () => Promise<{ success: boolean }>;
      resumeAutomation: () => Promise<{ success: boolean; error?: string }>;
      stopAutomation: () => Promise<{ success: boolean; stats?: AutomationStats }>;
      getAutomationState: () => Promise<AutomationState>;
      getViewportPresets: () => Promise<Record<string, ViewportPreset>>;
      setViewport: (viewport: string, customWidth?: number, customHeight?: number) => Promise<{ success: boolean; viewport: string; width: number; height: number }>;
      getCurrentViewport: () => Promise<{ viewport: string; width: number; height: number; presets: Record<string, ViewportPreset> }>;
      onEngineReady: (callback: (data: { success: boolean }) => void) => void;
      onEngineStopped: (callback: (data: object) => void) => void;
      onPageNavigated: (callback: (data: { url: string }) => void) => void;
      onPageTitle: (callback: (data: { title: string }) => void) => void;
      onPageLoaded: (callback: (data: { url: string; title: string }) => void) => void;
      onElementsExtracted: (callback: (data: { elements: DOMElement[]; count: number }) => void) => void;
      onExtractionError: (callback: (data: { message: string }) => void) => void;
      onViewportChanged: (callback: (data: ViewportInfo) => void) => void;
      // Automation events
      onAutomationStarted: (callback: (data: { queueSize: number; stats: AutomationStats }) => void) => void;
      onAutomationActionStart: (callback: (data: { element: DOMElement; remaining: number }) => void) => void;
      onAutomationActionComplete: (callback: (data: { action: AutomationAction; stats: AutomationStats; remaining: number; history: AutomationAction[] }) => void) => void;
      onAutomationPaused: (callback: (data: { stats: AutomationStats; remaining: number }) => void) => void;
      onAutomationResumed: (callback: (data: { stats: AutomationStats; remaining: number }) => void) => void;
      onAutomationStopped: (callback: (data: { stats: AutomationStats; history: AutomationAction[] }) => void) => void;
      onAutomationComplete: (callback: (data: { stats: AutomationStats; history: AutomationAction[] }) => void) => void;
      removeAllListeners: (channel: string) => void;
    };
  }
}

// Device categories for the viewport selector
const DEVICE_CATEGORIES = [
  {
    name: "Desktop",
    icon: Monitor,
    devices: [
      { id: "responsive", name: "Responsive", size: "Auto" },
      { id: "desktop", name: "1920×1080", size: "Full HD" },
      { id: "desktop-sm", name: "1440×900", size: "MacBook" },
    ]
  },
  {
    name: "Laptop",
    icon: Laptop,
    devices: [
      { id: "laptop", name: "1366×768", size: "Common" },
      { id: "laptop-sm", name: "1280×800", size: "Small" },
    ]
  },
  {
    name: "Tablet",
    icon: Tablet,
    devices: [
      { id: "tablet", name: "768×1024", size: "iPad" },
      { id: "tablet-landscape", name: "1024×768", size: "iPad Landscape" },
      { id: "tablet-pro", name: "1024×1366", size: "iPad Pro" },
    ]
  },
  {
    name: "Mobile",
    icon: Smartphone,
    devices: [
      { id: "mobile", name: "375×667", size: "iPhone SE" },
      { id: "mobile-lg", name: "390×844", size: "iPhone 12/13" },
      { id: "mobile-android", name: "360×740", size: "Android" },
      { id: "mobile-plus", name: "414×896", size: "iPhone Plus" },
    ]
  }
];

function App() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("Click 'Start' to launch browser");
  const [engineRunning, setEngineRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [elements, setElements] = useState<DOMElement[]>([]);
  const [currentUrl, setCurrentUrl] = useState("");
  const [pageTitle, setPageTitle] = useState("");

  // Viewport state
  const [currentViewport, setCurrentViewport] = useState("responsive");
  const [viewportSize, setViewportSize] = useState({ width: 0, height: 0 });
  const [viewportScale, setViewportScale] = useState(1);
  const [customWidth, setCustomWidth] = useState("1280");
  const [customHeight, setCustomHeight] = useState("720");
  const [showViewportPanel, setShowViewportPanel] = useState(false);

  // Automation state
  const [automationRunning, setAutomationRunning] = useState(false);
  const [automationPaused, setAutomationPaused] = useState(false);
  const [automationStats, setAutomationStats] = useState<AutomationStats>({ total: 0, clicked: 0, inputs: 0, navigations: 0, errors: 0 });
  const [automationQueue, setAutomationQueue] = useState(0);
  const [automationHistory, setAutomationHistory] = useState<AutomationAction[]>([]);
  const [currentAction, setCurrentAction] = useState<DOMElement | null>(null);
  const [showAutomationPanel, setShowAutomationPanel] = useState(true);

  // Set up event listeners
  useEffect(() => {
    if (!window.yalitest) {
      setStatus("Error: Electron API not available");
      return;
    }

    window.yalitest.onEngineReady((data) => {
      if (data.success) {
        setEngineRunning(true);
        setStatus("Browser ready - enter a URL");
        setLoading(false);
      }
    });

    window.yalitest.onEngineStopped(() => {
      setEngineRunning(false);
      setStatus("Browser stopped");
      setElements([]);
      setCurrentUrl("");
      setPageTitle("");
    });

    window.yalitest.onPageNavigated((data) => {
      setCurrentUrl(data.url);
      setStatus(`Navigated to ${data.url}`);
    });

    window.yalitest.onPageTitle((data) => {
      setPageTitle(data.title);
    });

    window.yalitest.onPageLoaded((data) => {
      setCurrentUrl(data.url);
      setPageTitle(data.title);
      setStatus(`Loaded: ${data.title || data.url}`);
      setLoading(false);
    });

    window.yalitest.onElementsExtracted((data) => {
      setElements(data.elements);
      setStatus(`Found ${data.count} interactive elements`);
    });

    window.yalitest.onExtractionError((data) => {
      setStatus(`Extraction error: ${data.message}`);
    });

    window.yalitest.onViewportChanged((data) => {
      setCurrentViewport(data.viewport);
      setViewportSize({ width: data.width, height: data.height });
      setViewportScale(data.scale || 1);
    });

    // Automation listeners
    window.yalitest.onAutomationStarted((data) => {
      setAutomationRunning(true);
      setAutomationPaused(false);
      setAutomationQueue(data.queueSize);
      setAutomationStats(data.stats);
      setAutomationHistory([]);
      setStatus(`Automation started - ${data.queueSize} elements queued`);
    });

    window.yalitest.onAutomationActionStart((data) => {
      setCurrentAction(data.element);
      setAutomationQueue(data.remaining);
      setStatus(`Processing: ${data.element.text || data.element.tag}`);
    });

    window.yalitest.onAutomationActionComplete((data) => {
      setCurrentAction(null);
      setAutomationStats(data.stats);
      setAutomationQueue(data.remaining);
      setAutomationHistory(data.history);
      const action = data.action;
      if (action.navigated) {
        setStatus(`Navigated to new page - ${data.remaining} remaining`);
      } else if (action.newElements > 0) {
        setStatus(`Found ${action.newElements} new elements - ${data.remaining} remaining`);
      } else {
        setStatus(`Action complete - ${data.remaining} remaining`);
      }
    });

    window.yalitest.onAutomationPaused((data) => {
      setAutomationPaused(true);
      setAutomationStats(data.stats);
      setStatus(`Automation paused - ${data.remaining} remaining`);
    });

    window.yalitest.onAutomationResumed((data) => {
      setAutomationPaused(false);
      setAutomationStats(data.stats);
      setStatus(`Automation resumed - ${data.remaining} remaining`);
    });

    window.yalitest.onAutomationStopped((data) => {
      setAutomationRunning(false);
      setAutomationPaused(false);
      setCurrentAction(null);
      setAutomationStats(data.stats);
      setAutomationHistory(data.history);
      setStatus(`Automation stopped - ${data.stats.clicked} clicks, ${data.stats.inputs} inputs`);
    });

    window.yalitest.onAutomationComplete((data) => {
      setAutomationRunning(false);
      setAutomationPaused(false);
      setCurrentAction(null);
      setAutomationStats(data.stats);
      setAutomationHistory(data.history);
      setStatus(`Automation complete! ${data.stats.clicked} clicks, ${data.stats.inputs} inputs, ${data.stats.navigations} navigations`);
    });

    return () => {
      window.yalitest.removeAllListeners('engine-ready');
      window.yalitest.removeAllListeners('engine-stopped');
      window.yalitest.removeAllListeners('page-navigated');
      window.yalitest.removeAllListeners('page-title');
      window.yalitest.removeAllListeners('page-loaded');
      window.yalitest.removeAllListeners('elements-extracted');
      window.yalitest.removeAllListeners('extraction-error');
      window.yalitest.removeAllListeners('viewport-changed');
      window.yalitest.removeAllListeners('automation-started');
      window.yalitest.removeAllListeners('automation-action-start');
      window.yalitest.removeAllListeners('automation-action-complete');
      window.yalitest.removeAllListeners('automation-paused');
      window.yalitest.removeAllListeners('automation-resumed');
      window.yalitest.removeAllListeners('automation-stopped');
      window.yalitest.removeAllListeners('automation-complete');
    };
  }, []);

  // Start browser engine
  async function startEngine() {
    setLoading(true);
    setStatus("Starting browser...");
    try {
      const result = await window.yalitest.startEngine();
      if (!result.success) {
        setStatus(`Failed: ${result.error}`);
        setLoading(false);
      }
    } catch (error) {
      setStatus(`Error: ${error}`);
      setLoading(false);
    }
  }

  // Stop browser engine
  async function stopEngine() {
    setLoading(true);
    setStatus("Stopping browser...");
    try {
      await window.yalitest.stopEngine();
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
    setLoading(false);
  }

  // Navigate to URL
  async function handleNavigate() {
    if (!url.trim()) {
      setStatus("Please enter a URL");
      return;
    }

    setLoading(true);
    setStatus(`Loading ${url}...`);
    setElements([]);

    try {
      const result = await window.yalitest.navigate(url.trim());
      if (!result.success) {
        setStatus(`Navigation failed: ${result.error}`);
        setLoading(false);
      }
    } catch (error) {
      setStatus(`Error: ${error}`);
      setLoading(false);
    }
  }

  // Click element
  async function handleClick(mmid: string, text: string) {
    setLoading(true);
    setStatus(`Clicking: ${text || mmid}...`);
    try {
      const result = await window.yalitest.clickElement(mmid);
      if (!result.success) {
        setStatus(`Click failed: ${result.error}`);
      }
      setLoading(false);
    } catch (error) {
      setStatus(`Error: ${error}`);
      setLoading(false);
    }
  }

  // Navigation buttons
  async function handleBack() {
    await window.yalitest.goBack();
  }

  async function handleForward() {
    await window.yalitest.goForward();
  }

  async function handleReload() {
    await window.yalitest.reload();
  }

  async function handleRefresh() {
    await window.yalitest.refreshElements();
  }

  // Automation functions
  async function startAutomation() {
    if (elements.length === 0) {
      setStatus("No elements to automate - navigate to a page first");
      return;
    }
    try {
      const result = await window.yalitest.startAutomation();
      if (!result.success) {
        setStatus(`Automation error: ${result.error}`);
      }
    } catch (error) {
      setStatus(`Error: ${error}`);
    }
  }

  async function pauseAutomation() {
    await window.yalitest.pauseAutomation();
  }

  async function resumeAutomation() {
    await window.yalitest.resumeAutomation();
  }

  async function stopAutomation() {
    await window.yalitest.stopAutomation();
  }

  // Viewport functions
  async function handleSetViewport(viewportId: string) {
    if (!engineRunning) return;
    await window.yalitest.setViewport(viewportId);
    setCurrentViewport(viewportId);
  }

  async function handleSetCustomViewport() {
    if (!engineRunning) return;
    const w = parseInt(customWidth) || 1280;
    const h = parseInt(customHeight) || 720;
    await window.yalitest.setViewport('custom', w, h);
    setCurrentViewport('custom');
  }

  // Get icon for action classification
  function getClassificationIcon(classification: string): ReactNode {
    const size = 14;
    switch (classification) {
      case "navigation": return <Compass size={size} />;
      case "input": return <Keyboard size={size} />;
      case "select": return <List size={size} />;
      case "toggle": return <ToggleLeft size={size} />;
      case "submit": return <Send size={size} />;
      case "click": return <Hand size={size} />;
      default: return <Circle size={size} />;
    }
  }

  // Get icon for element type
  function getTypeIcon(type: string): ReactNode {
    const size = 16;
    switch (type) {
      case "link": return <Link size={size} />;
      case "button": return <MousePointer2 size={size} />;
      case "input": return <TextCursor size={size} />;
      case "textarea": return <FileText size={size} />;
      case "dropdown": return <ChevronDownSquare size={size} />;
      case "checkbox": return <CheckSquare size={size} />;
      case "radio": return <Circle size={size} />;
      case "toggle": return <ToggleLeft size={size} />;
      case "menuitem": return <Pin size={size} />;
      case "tab": return <Layers size={size} />;
      case "clickable": return <Hand size={size} />;
      default: return <Circle size={size} />;
    }
  }

  // Get current viewport display name
  function getViewportDisplayName(): string {
    if (currentViewport === 'responsive') return 'Responsive';
    if (currentViewport === 'custom') return `Custom ${viewportSize.width}×${viewportSize.height}`;
    for (const cat of DEVICE_CATEGORIES) {
      for (const dev of cat.devices) {
        if (dev.id === currentViewport) return dev.name;
      }
    }
    return currentViewport;
  }

  // Group elements by type
  const groupedElements = elements.reduce((acc, el) => {
    const type = el.elementType || "other";
    if (!acc[type]) acc[type] = [];
    acc[type].push(el);
    return acc;
  }, {} as Record<string, DOMElement[]>);

  const typeOrder = ["link", "button", "input", "dropdown", "checkbox", "toggle", "tab", "menuitem", "clickable", "other"];

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <FlaskConical size={20} className="header-icon" />
          <h1 className="title">YaliTest</h1>
        </div>
        <div className="header-right">
          {!engineRunning ? (
            <button
              className="btn btn-primary"
              onClick={startEngine}
              disabled={loading}
            >
              <Play size={14} />
              {loading ? "Starting..." : "Start"}
            </button>
          ) : (
            <button
              className="btn btn-danger"
              onClick={stopEngine}
              disabled={loading}
            >
              <Square size={14} />
              Stop
            </button>
          )}
        </div>
      </header>

      {/* URL Bar */}
      <div className="url-bar">
        <div className="nav-buttons">
          <button className="btn btn-icon" onClick={handleBack} disabled={!engineRunning} title="Back">
            <ChevronLeft size={16} />
          </button>
          <button className="btn btn-icon" onClick={handleForward} disabled={!engineRunning} title="Forward">
            <ChevronRight size={16} />
          </button>
          <button className="btn btn-icon" onClick={handleReload} disabled={!engineRunning} title="Reload">
            <RotateCw size={14} />
          </button>
        </div>
        <input
          type="text"
          className="url-input"
          placeholder="Enter URL (e.g., google.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleNavigate()}
          disabled={!engineRunning || loading}
        />
        <button
          className="btn btn-go"
          onClick={handleNavigate}
          disabled={!engineRunning || loading || !url.trim()}
        >
          Go
        </button>
      </div>

      {/* Viewport Bar */}
      <div className="viewport-bar">
        <button
          className={`viewport-toggle ${showViewportPanel ? 'active' : ''}`}
          onClick={() => setShowViewportPanel(!showViewportPanel)}
          disabled={!engineRunning}
        >
          <Maximize2 size={14} className="viewport-icon" />
          <span className="viewport-label">{getViewportDisplayName()}</span>
          {viewportSize.width > 0 && (
            <span className="viewport-size">
              {viewportSize.width}×{viewportSize.height}
              {viewportScale < 1 && (
                <span className="viewport-scale"> @ {Math.round(viewportScale * 100)}%</span>
              )}
            </span>
          )}
          {showViewportPanel ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {/* Quick viewport buttons */}
        <div className="viewport-quick">
          <button
            className={`viewport-quick-btn ${currentViewport === 'responsive' ? 'active' : ''}`}
            onClick={() => handleSetViewport('responsive')}
            disabled={!engineRunning}
            title="Responsive"
          >
            <Maximize2 size={16} />
          </button>
          <button
            className={`viewport-quick-btn ${currentViewport === 'desktop' ? 'active' : ''}`}
            onClick={() => handleSetViewport('desktop')}
            disabled={!engineRunning}
            title="Desktop 1920×1080"
          >
            <Monitor size={16} />
          </button>
          <button
            className={`viewport-quick-btn ${currentViewport === 'laptop' ? 'active' : ''}`}
            onClick={() => handleSetViewport('laptop')}
            disabled={!engineRunning}
            title="Laptop 1366×768"
          >
            <Laptop size={16} />
          </button>
          <button
            className={`viewport-quick-btn ${currentViewport === 'tablet' ? 'active' : ''}`}
            onClick={() => handleSetViewport('tablet')}
            disabled={!engineRunning}
            title="Tablet 768×1024"
          >
            <Tablet size={16} />
          </button>
          <button
            className={`viewport-quick-btn ${currentViewport === 'mobile-lg' ? 'active' : ''}`}
            onClick={() => handleSetViewport('mobile-lg')}
            disabled={!engineRunning}
            title="Mobile 390×844"
          >
            <Smartphone size={16} />
          </button>
        </div>
      </div>

      {/* Viewport Panel (Expanded) */}
      {showViewportPanel && engineRunning && (
        <div className="viewport-panel">
          {DEVICE_CATEGORIES.map((category) => (
            <div key={category.name} className="viewport-category">
              <h4 className="viewport-category-title">
                <category.icon size={14} />
                {category.name}
              </h4>
              <div className="viewport-devices">
                {category.devices.map((device) => (
                  <button
                    key={device.id}
                    className={`viewport-device ${currentViewport === device.id ? 'active' : ''}`}
                    onClick={() => handleSetViewport(device.id)}
                  >
                    <span className="device-name">{device.name}</span>
                    <span className="device-size">{device.size}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}

          {/* Custom Size */}
          <div className="viewport-category">
            <h4 className="viewport-category-title">
              <Target size={14} />
              Custom
            </h4>
            <div className="viewport-custom">
              <input
                type="number"
                className="custom-input"
                placeholder="Width"
                value={customWidth}
                onChange={(e) => setCustomWidth(e.target.value)}
                min="320"
                max="3840"
              />
              <span className="custom-x">×</span>
              <input
                type="number"
                className="custom-input"
                placeholder="Height"
                value={customHeight}
                onChange={(e) => setCustomHeight(e.target.value)}
                min="480"
                max="2160"
              />
              <button
                className="btn btn-small btn-apply"
                onClick={handleSetCustomViewport}
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Status Bar */}
      <div className="status-bar">
        <span className={`status-indicator ${engineRunning ? "online" : "offline"}`}>
          {engineRunning ? <Circle size={8} fill="currentColor" /> : <Circle size={8} />}
        </span>
        <span className={`status-text ${loading || automationRunning ? "loading" : ""}`}>
          {status}
        </span>
        {pageTitle && <span className="page-info">| {pageTitle}</span>}
      </div>

      {/* Automation Bar */}
      {engineRunning && (
        <div className="automation-bar">
          <div className="automation-controls">
            {!automationRunning ? (
              <button
                className="btn btn-automation"
                onClick={startAutomation}
                disabled={loading || elements.length === 0}
                title="Start clicking all elements automatically"
              >
                <Bot size={16} />
                Automate
              </button>
            ) : (
              <>
                {!automationPaused ? (
                  <button className="btn btn-icon" onClick={pauseAutomation} title="Pause">
                    <Pause size={16} />
                  </button>
                ) : (
                  <button className="btn btn-icon" onClick={resumeAutomation} title="Resume">
                    <Play size={16} />
                  </button>
                )}
                <button className="btn btn-danger btn-sm" onClick={stopAutomation} title="Stop">
                  <StopCircle size={14} />
                  Stop
                </button>
              </>
            )}
          </div>

          {automationRunning && (
            <div className="automation-status">
              <span className="automation-progress">
                {automationStats.clicked + automationStats.inputs}/{automationStats.total}
              </span>
              <span className="automation-queue">
                Queue: {automationQueue}
              </span>
            </div>
          )}

          <button
            className={`btn btn-icon btn-sm ${showAutomationPanel ? 'active' : ''}`}
            onClick={() => setShowAutomationPanel(!showAutomationPanel)}
            title="Toggle action history"
          >
            <BarChart3 size={16} />
          </button>
        </div>
      )}

      {/* Automation Panel - Fixed above main content */}
      {showAutomationPanel && engineRunning && (automationRunning || automationHistory.length > 0) && (
        <div className="automation-panel">
          {/* Stats */}
          <div className="automation-stats">
            <div className="stat-item">
              <span className="stat-value">{automationStats.clicked}</span>
              <span className="stat-label">Clicked</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{automationStats.inputs}</span>
              <span className="stat-label">Inputs</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{automationStats.navigations}</span>
              <span className="stat-label">Navs</span>
            </div>
            <div className="stat-item stat-error">
              <span className="stat-value">{automationStats.errors}</span>
              <span className="stat-label">Errors</span>
            </div>
          </div>

          {/* Current Action */}
          {currentAction && (
            <div className="current-action">
              <div className="current-action-header">Processing</div>
              <div className="current-action-content">
                <span className="current-action-icon">{getTypeIcon(currentAction.elementType)}</span>
                <span className="current-action-text">
                  {currentAction.text || currentAction.attributes?.placeholder || `<${currentAction.tag}>`}
                </span>
              </div>
            </div>
          )}

          {/* Action History */}
          {automationHistory.length > 0 && (
            <div className="action-history">
              <div className="action-history-header">
                Recent Actions ({automationHistory.length})
              </div>
              <div className="action-history-list">
                {[...automationHistory].reverse().slice(0, 10).map((action, idx) => (
                  <div
                    key={`${action.mmid}-${idx}`}
                    className={`action-item ${action.success ? '' : 'action-error'} ${action.navigated ? 'action-nav' : ''}`}
                  >
                    <span className="action-icon">{getClassificationIcon(action.classification)}</span>
                    <div className="action-content">
                      <span className="action-text">
                        {action.text || `<${action.tag}>`}
                      </span>
                      {action.inputValue && (
                        <span className="action-input-value">"{action.inputValue}"</span>
                      )}
                      {action.navigated && (
                        <span className="action-nav-indicator">
                          <ExternalLink size={10} /> navigated
                        </span>
                      )}
                      {action.newElements > 0 && (
                        <span className="action-new-elements">
                          <Plus size={10} /> {action.newElements} new
                        </span>
                      )}
                      {action.error && (
                        <span className="action-error-text">
                          <AlertCircle size={10} /> {action.error}
                        </span>
                      )}
                    </div>
                    <span className={`action-status ${action.success ? 'success' : 'error'}`}>
                      {action.success ? <Check size={14} /> : <X size={14} />}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Content - Left Panel */}
      <main className="main-content">
        {/* Not started */}
        {!engineRunning && !loading && (
          <div className="empty-state">
            <Globe size={48} className="empty-icon" />
            <h2>Welcome to YaliTest</h2>
            <p>Click "Start" to launch the embedded browser.</p>
            <p className="hint">Test responsive layouts with viewport presets.</p>
          </div>
        )}

        {/* Started but no URL */}
        {engineRunning && elements.length === 0 && !loading && (
          <div className="empty-state">
            <Search size={48} className="empty-icon" />
            <h2>Ready to Explore</h2>
            <p>Enter a URL above to start.</p>
            <p className="hint">Use viewport controls to test different screen sizes.</p>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="empty-state">
            <div className="loading-spinner"></div>
            <p>{status}</p>
          </div>
        )}

        {/* Elements List */}
        {elements.length > 0 && !loading && (
          <div className="elements-container">
            <div className="elements-header">
              <h2>Elements ({elements.length})</h2>
              <button className="btn btn-small" onClick={handleRefresh}>
                <RefreshCw size={12} />
                Refresh
              </button>
            </div>

            <div className="elements-scroll">
              {typeOrder.map((type) => {
                const typeElements = groupedElements[type];
                if (!typeElements || typeElements.length === 0) return null;

                return (
                  <div key={type} className="element-group">
                    <h3 className="group-title">
                      {getTypeIcon(type)}
                      <span>{type.charAt(0).toUpperCase() + type.slice(1)}s ({typeElements.length})</span>
                    </h3>
                    <div className="element-list">
                      {typeElements.slice(0, 15).map((el) => (
                        <button
                          key={el.mmid}
                          className="element-card"
                          onClick={() => handleClick(el.mmid, el.text)}
                          disabled={loading}
                          title={el.attributes.href || el.text || `${el.tag} element`}
                        >
                          <span className="element-icon">{getTypeIcon(el.elementType)}</span>
                          <span className="element-content">
                            <span className="element-text">
                              {el.text || el.attributes.placeholder || el.attributes["aria-label"] || `<${el.tag}>`}
                            </span>
                            {el.attributes.href && (
                              <span className="element-href">
                                {el.attributes.href.length > 30
                                  ? el.attributes.href.substring(0, 30) + "..."
                                  : el.attributes.href}
                              </span>
                            )}
                          </span>
                          <span className="element-mmid">#{el.mmid}</span>
                        </button>
                      ))}
                      {typeElements.length > 15 && (
                        <div className="more-elements">
                          +{typeElements.length - 15} more
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <span>YaliTest v1.0</span>
        {currentUrl && (
          <>
            <span>•</span>
            <span className="current-url">{currentUrl}</span>
          </>
        )}
      </footer>
    </div>
  );
}

export default App;
