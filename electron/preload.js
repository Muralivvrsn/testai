const { contextBridge, ipcRenderer } = require('electron')

// Track listeners for cleanup
const listeners = new Map()

// Helper to add listener with cleanup support
function addListener(channel, callback) {
  const wrappedCallback = (_, ...args) => callback(...args)
  ipcRenderer.on(channel, wrappedCallback)

  // Store for cleanup
  if (!listeners.has(channel)) {
    listeners.set(channel, [])
  }
  listeners.get(channel).push(wrappedCallback)

  // Return cleanup function
  return () => {
    ipcRenderer.removeListener(channel, wrappedCallback)
    const channelListeners = listeners.get(channel)
    if (channelListeners) {
      const idx = channelListeners.indexOf(wrappedCallback)
      if (idx > -1) channelListeners.splice(idx, 1)
    }
  }
}

contextBridge.exposeInMainWorld('api', {
  // ============ NAVIGATION ============
  navigate: (url) => ipcRenderer.invoke('navigate', url),
  goBack: () => ipcRenderer.invoke('go-back'),
  goForward: () => ipcRenderer.invoke('go-forward'),
  reload: () => ipcRenderer.invoke('reload'),

  // ============ LAYOUT ============
  setSidebarWidth: (width) => ipcRenderer.invoke('set-sidebar-width', width),
  setChatWidth: (width) => ipcRenderer.invoke('set-chat-width', width),
  setViewport: (width, height) => ipcRenderer.invoke('set-viewport', width, height),

  // ============ DOM ============
  extractDom: () => ipcRenderer.invoke('extract-dom'),
  clickElement: (id) => ipcRenderer.invoke('click-element', id),
  typeInElement: (id, text) => ipcRenderer.invoke('type-in-element', id, text),
  getPageInfo: () => ipcRenderer.invoke('get-page-info'),

  // ============ PLATFORM ============
  getPlatform: () => ipcRenderer.invoke('get-platform'),

  // ============ EVENTS (with cleanup) ============
  onUrlChanged: (callback) => addListener('url-changed', callback),
  onTitleChanged: (callback) => addListener('title-changed', callback),
  onPageLoaded: (callback) => addListener('page-loaded', callback),
  onPageError: (callback) => addListener('page-error', callback),
  onPlatformInfo: (callback) => addListener('platform-info', callback),
  onAgentMessage: (callback) => addListener('agent-message', callback),

  // ============ AGENT API ============
  setApiKey: (key) => ipcRenderer.invoke('set-api-key', key),
  getAgentStatus: () => ipcRenderer.invoke('agent-status'),
  analyzePage: () => ipcRenderer.invoke('analyze-page'),
  generateTests: (pageData) => ipcRenderer.invoke('generate-tests', pageData),
  startAutonomousTest: () => ipcRenderer.invoke('start-autonomous-test'),
  stopAutonomousTest: () => ipcRenderer.invoke('stop-autonomous-test'),
  chatWithAgent: (message, context) => ipcRenderer.invoke('chat-with-agent', message, context),
  getWelcomeMessage: () => ipcRenderer.invoke('get-welcome-message'),
  smartAnalyze: () => ipcRenderer.invoke('smart-analyze'),

  // ============ ACTION API ============
  performAction: (intent) => ipcRenderer.invoke('perform-action', intent),
  pageAction: (action, value) => ipcRenderer.invoke('page-action', action, value),
  executeTask: (task) => ipcRenderer.invoke('execute-task', task),
  searchElements: (query) => ipcRenderer.invoke('search-elements', query),
  getElementsByCategory: () => ipcRenderer.invoke('get-elements-by-category'),

  // ============ SCRIPT API ============
  generateScript: (taskDescription) => ipcRenderer.invoke('generate-script', taskDescription),
  executeScript: (scriptText) => ipcRenderer.invoke('execute-script', scriptText),

  // ============ CLEANUP ============
  removeAllListeners: (channel) => {
    if (channel) {
      const channelListeners = listeners.get(channel)
      if (channelListeners) {
        channelListeners.forEach(cb => ipcRenderer.removeListener(channel, cb))
        listeners.delete(channel)
      }
    } else {
      // Remove all listeners
      listeners.forEach((callbacks, ch) => {
        callbacks.forEach(cb => ipcRenderer.removeListener(ch, cb))
      })
      listeners.clear()
    }
  },
})
