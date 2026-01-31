/**
 * YaliTest - Preload Script for Main Window
 *
 * Exposes safe IPC methods to React renderer
 * These functions are designed to be reusable for Chrome extension
 */

const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer
contextBridge.exposeInMainWorld('yalitest', {
  // Engine control
  startEngine: () => ipcRenderer.invoke('start-engine'),
  stopEngine: () => ipcRenderer.invoke('stop-engine'),

  // Navigation
  navigate: (url) => ipcRenderer.invoke('navigate', url),
  goBack: () => ipcRenderer.invoke('go-back'),
  goForward: () => ipcRenderer.invoke('go-forward'),
  reload: () => ipcRenderer.invoke('reload'),

  // Element interaction
  clickElement: (mmid) => ipcRenderer.invoke('click-element', mmid),
  inputText: (mmid, text) => ipcRenderer.invoke('input-text', { mmid, text }),

  // State
  getState: () => ipcRenderer.invoke('get-state'),
  refreshElements: () => ipcRenderer.invoke('refresh-elements'),

  // Screenshot
  takeScreenshot: () => ipcRenderer.invoke('take-screenshot'),

  // Automation
  startAutomation: () => ipcRenderer.invoke('start-automation'),
  pauseAutomation: () => ipcRenderer.invoke('pause-automation'),
  resumeAutomation: () => ipcRenderer.invoke('resume-automation'),
  stopAutomation: () => ipcRenderer.invoke('stop-automation'),
  getAutomationState: () => ipcRenderer.invoke('get-automation-state'),

  // Viewport
  getViewportPresets: () => ipcRenderer.invoke('get-viewport-presets'),
  setViewport: (viewport, customWidth, customHeight) =>
    ipcRenderer.invoke('set-viewport', { viewport, customWidth, customHeight }),
  getCurrentViewport: () => ipcRenderer.invoke('get-current-viewport'),

  // Event listeners
  onEngineReady: (callback) => {
    ipcRenderer.on('engine-ready', (event, data) => callback(data));
  },
  onEngineStopped: (callback) => {
    ipcRenderer.on('engine-stopped', (event, data) => callback(data));
  },
  onPageNavigated: (callback) => {
    ipcRenderer.on('page-navigated', (event, data) => callback(data));
  },
  onPageTitle: (callback) => {
    ipcRenderer.on('page-title', (event, data) => callback(data));
  },
  onPageLoaded: (callback) => {
    ipcRenderer.on('page-loaded', (event, data) => callback(data));
  },
  onElementsExtracted: (callback) => {
    ipcRenderer.on('elements-extracted', (event, data) => callback(data));
  },
  onExtractionError: (callback) => {
    ipcRenderer.on('extraction-error', (event, data) => callback(data));
  },
  onViewportChanged: (callback) => {
    ipcRenderer.on('viewport-changed', (event, data) => callback(data));
  },

  // Automation events
  onAutomationStarted: (callback) => {
    ipcRenderer.on('automation-started', (event, data) => callback(data));
  },
  onAutomationActionStart: (callback) => {
    ipcRenderer.on('automation-action-start', (event, data) => callback(data));
  },
  onAutomationActionComplete: (callback) => {
    ipcRenderer.on('automation-action-complete', (event, data) => callback(data));
  },
  onAutomationPaused: (callback) => {
    ipcRenderer.on('automation-paused', (event, data) => callback(data));
  },
  onAutomationResumed: (callback) => {
    ipcRenderer.on('automation-resumed', (event, data) => callback(data));
  },
  onAutomationStopped: (callback) => {
    ipcRenderer.on('automation-stopped', (event, data) => callback(data));
  },
  onAutomationComplete: (callback) => {
    ipcRenderer.on('automation-complete', (event, data) => callback(data));
  },

  // Remove listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});

// Also expose as window.electronAPI for compatibility
contextBridge.exposeInMainWorld('electronAPI', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  on: (channel, callback) => {
    ipcRenderer.on(channel, (event, ...args) => callback(...args));
  },
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});
