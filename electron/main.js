/**
 * YaliTest - Electron Main Process
 *
 * Simple, stable implementation:
 * - Main window with React UI on left (420px)
 * - BrowserView embedded on right
 * - Viewport presets resize the BrowserView
 */

const { app, BrowserWindow, BrowserView, ipcMain } = require('electron');
const path = require('path');

let mainWindow = null;
let browserView = null;

let currentState = {
  url: '',
  title: '',
  elements: []
};

// Automation state
let automationState = {
  running: false,
  paused: false,
  queue: [],           // Elements to process
  processed: new Set(), // mmids already processed
  actionHistory: [],   // All actions taken
  currentAction: null,
  stats: {
    total: 0,
    clicked: 0,
    inputs: 0,
    navigations: 0,
    errors: 0
  }
};

// Viewport presets
const VIEWPORT_PRESETS = {
  responsive: { width: null, height: null, name: 'Responsive' },
  desktop: { width: 1920, height: 1080, name: 'Desktop 1920×1080' },
  'desktop-sm': { width: 1440, height: 900, name: 'Desktop 1440×900' },
  laptop: { width: 1366, height: 768, name: 'Laptop 1366×768' },
  'laptop-sm': { width: 1280, height: 800, name: 'Laptop 1280×800' },
  tablet: { width: 768, height: 1024, name: 'iPad 768×1024' },
  'tablet-landscape': { width: 1024, height: 768, name: 'iPad Landscape' },
  mobile: { width: 375, height: 667, name: 'iPhone SE' },
  'mobile-lg': { width: 390, height: 844, name: 'iPhone 12/13' },
  'mobile-android': { width: 360, height: 740, name: 'Android' }
};

let currentViewport = 'responsive';
let customViewport = { width: 1280, height: 720 };

const PANEL_WIDTH = 420;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const isDev = !app.isPackaged;
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
    browserView = null;
  });

  mainWindow.on('resize', updateBrowserViewBounds);
}

function getTargetSize() {
  if (currentViewport === 'responsive') return null;
  if (currentViewport === 'custom') return customViewport;
  const preset = VIEWPORT_PRESETS[currentViewport];
  return preset ? { width: preset.width, height: preset.height } : null;
}

function updateBrowserViewBounds() {
  if (!mainWindow || !browserView) return;

  const [winWidth, winHeight] = mainWindow.getContentSize();
  const availWidth = winWidth - PANEL_WIDTH;
  const availHeight = winHeight;

  const target = getTargetSize();

  let viewWidth, viewHeight, x, y;

  if (!target) {
    // Responsive - fill available space
    viewWidth = availWidth;
    viewHeight = availHeight;
    x = PANEL_WIDTH;
    y = 0;
  } else {
    // Fixed viewport - fit within available space
    const scaleX = availWidth / target.width;
    const scaleY = availHeight / target.height;
    const scale = Math.min(scaleX, scaleY, 1);

    viewWidth = Math.round(target.width * scale);
    viewHeight = Math.round(target.height * scale);
    x = PANEL_WIDTH + Math.round((availWidth - viewWidth) / 2);
    y = Math.round((availHeight - viewHeight) / 2);
  }

  browserView.setBounds({ x, y, width: viewWidth, height: viewHeight });

  sendToRenderer('viewport-changed', {
    viewport: currentViewport,
    width: viewWidth,
    height: viewHeight,
    scale: target ? Math.min(availWidth / target.width, availHeight / target.height, 1) : 1
  });
}

function createBrowserView() {
  if (browserView) {
    mainWindow.removeBrowserView(browserView);
    browserView = null;
  }

  browserView = new BrowserView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.addBrowserView(browserView);
  updateBrowserViewBounds();

  browserView.webContents.on('did-finish-load', () => {
    sendToRenderer('page-loaded', {
      url: browserView.webContents.getURL(),
      title: browserView.webContents.getTitle()
    });
    extractElements();
  });

  browserView.webContents.on('did-navigate', (e, url) => {
    currentState.url = url;
    sendToRenderer('page-navigated', { url });
  });

  browserView.webContents.on('page-title-updated', (e, title) => {
    currentState.title = title;
    sendToRenderer('page-title', { title });
  });

  browserView.webContents.setWindowOpenHandler(({ url }) => {
    browserView.webContents.loadURL(url);
    return { action: 'deny' };
  });
}

function sendToRenderer(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

async function extractElements() {
  if (!browserView) return;

  try {
    const elements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = [];
        let id = 1;
        const selectors = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick]';

        document.querySelectorAll(selectors).forEach(el => {
          const rect = el.getBoundingClientRect();
          const style = getComputedStyle(el);

          if (rect.width === 0 || rect.height === 0) return;
          if (style.display === 'none' || style.visibility === 'hidden') return;

          const mmid = 'el-' + id++;
          el.setAttribute('data-mmid', mmid);

          let type = 'clickable';
          const tag = el.tagName.toLowerCase();
          if (tag === 'a') type = 'link';
          else if (tag === 'button') type = 'button';
          else if (tag === 'input') type = 'input';
          else if (tag === 'select') type = 'dropdown';

          let text = el.innerText?.trim().slice(0, 80) ||
                     el.value?.slice(0, 80) ||
                     el.getAttribute('aria-label') ||
                     el.getAttribute('placeholder') || '';

          elements.push({
            mmid, tag, text, elementType: type,
            attributes: {
              href: el.getAttribute('href'),
              type: el.getAttribute('type'),
              placeholder: el.getAttribute('placeholder')
            }
          });
        });

        return elements;
      })()
    `);

    currentState.elements = elements;
    sendToRenderer('elements-extracted', { elements, count: elements.length });
  } catch (e) {
    console.error('Extract error:', e);
  }
}

// IPC Handlers
ipcMain.handle('start-engine', () => {
  createBrowserView();
  sendToRenderer('engine-ready', { success: true });
  return { success: true };
});

ipcMain.handle('stop-engine', () => {
  if (browserView) {
    mainWindow.removeBrowserView(browserView);
    browserView = null;
  }
  currentState = { url: '', title: '', elements: [] };
  sendToRenderer('engine-stopped', {});
  return { success: true };
});

ipcMain.handle('navigate', async (e, url) => {
  if (!browserView) return { success: false, error: 'Not started' };
  if (!url.startsWith('http')) url = 'https://' + url;
  try {
    await browserView.webContents.loadURL(url);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('click-element', async (e, mmid) => {
  if (!browserView) return { success: false };
  try {
    await browserView.webContents.executeJavaScript(`
      const el = document.querySelector('[data-mmid="${mmid}"]');
      if (el) { el.scrollIntoView({block:'center'}); el.click(); }
    `);
    setTimeout(extractElements, 500);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('set-viewport', (e, { viewport, customWidth, customHeight }) => {
  if (viewport === 'custom' && customWidth && customHeight) {
    customViewport = { width: customWidth, height: customHeight };
  }
  currentViewport = viewport;
  updateBrowserViewBounds();
  return { success: true, viewport };
});

ipcMain.handle('get-viewport-presets', () => VIEWPORT_PRESETS);
ipcMain.handle('refresh-elements', () => { extractElements(); return { success: true }; });
ipcMain.handle('go-back', () => { browserView?.webContents.goBack(); return { success: true }; });
ipcMain.handle('go-forward', () => { browserView?.webContents.goForward(); return { success: true }; });
ipcMain.handle('reload', () => { browserView?.webContents.reload(); return { success: true }; });

// Input text into an element
ipcMain.handle('input-text', async (e, { mmid, text }) => {
  if (!browserView) return { success: false, error: 'Not started' };
  try {
    await browserView.webContents.executeJavaScript(`
      const el = document.querySelector('[data-mmid="${mmid}"]');
      if (el) {
        el.scrollIntoView({block:'center'});
        el.focus();
        el.value = '${text.replace(/'/g, "\\'")}';
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    `);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ AUTOMATION ============

// Classify element type for automation
function classifyElement(el) {
  const tag = el.tag?.toLowerCase() || '';
  const type = el.elementType || '';
  const text = (el.text || '').toLowerCase();
  const href = el.attributes?.href || '';
  const inputType = el.attributes?.type || '';

  // Navigation elements - links that go to other pages
  if (tag === 'a' && href && !href.startsWith('#') && !href.startsWith('javascript:')) {
    return 'navigation';
  }

  // Input elements - need text input
  if (tag === 'input' && ['text', 'email', 'password', 'search', 'tel', 'url', 'number'].includes(inputType)) {
    return 'input';
  }
  if (tag === 'textarea') {
    return 'input';
  }

  // Select/dropdown
  if (tag === 'select') {
    return 'select';
  }

  // Checkbox/radio
  if (tag === 'input' && ['checkbox', 'radio'].includes(inputType)) {
    return 'toggle';
  }

  // Submit buttons
  if ((tag === 'button' || (tag === 'input' && inputType === 'submit')) &&
      (text.includes('submit') || text.includes('send') || text.includes('sign'))) {
    return 'submit';
  }

  // Regular clickable
  return 'click';
}

// Generate test input based on element
function generateTestInput(el) {
  const placeholder = el.attributes?.placeholder?.toLowerCase() || '';
  const name = el.attributes?.name?.toLowerCase() || '';
  const type = el.attributes?.type || 'text';

  if (type === 'email' || placeholder.includes('email') || name.includes('email')) {
    return 'test@example.com';
  }
  if (type === 'password' || placeholder.includes('password') || name.includes('password')) {
    return 'TestPassword123!';
  }
  if (type === 'tel' || placeholder.includes('phone') || name.includes('phone')) {
    return '555-123-4567';
  }
  if (type === 'search' || placeholder.includes('search') || name.includes('search')) {
    return 'test search';
  }
  if (placeholder.includes('name') || name.includes('name')) {
    return 'Test User';
  }
  if (type === 'url') {
    return 'https://example.com';
  }
  if (type === 'number') {
    return '42';
  }
  return 'test input';
}

// Add elements to automation queue
function queueElements(elements) {
  for (const el of elements) {
    // Skip if already processed
    if (automationState.processed.has(el.mmid)) continue;

    // Skip if already in queue
    if (automationState.queue.find(q => q.mmid === el.mmid)) continue;

    const classification = classifyElement(el);
    automationState.queue.push({
      ...el,
      classification,
      testInput: classification === 'input' ? generateTestInput(el) : null
    });
  }
  automationState.stats.total = automationState.queue.length + automationState.processed.size;
}

// Process next element in queue
async function processNextElement() {
  if (!automationState.running || automationState.paused) return null;
  if (!browserView) return null;
  if (automationState.queue.length === 0) return null;

  const element = automationState.queue.shift();
  automationState.currentAction = element;
  automationState.processed.add(element.mmid);

  const action = {
    mmid: element.mmid,
    tag: element.tag,
    text: element.text,
    classification: element.classification,
    timestamp: Date.now(),
    urlBefore: browserView.webContents.getURL(),
    urlAfter: null,
    success: false,
    error: null,
    newElements: 0
  };

  try {
    sendToRenderer('automation-action-start', {
      element,
      remaining: automationState.queue.length
    });

    // Handle different element types
    if (element.classification === 'input') {
      // Input text
      await browserView.webContents.executeJavaScript(`
        const el = document.querySelector('[data-mmid="${element.mmid}"]');
        if (el) {
          el.scrollIntoView({block:'center'});
          el.focus();
          el.value = '${element.testInput.replace(/'/g, "\\'")}';
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }
      `);
      automationState.stats.inputs++;
      action.inputValue = element.testInput;
    } else {
      // Click the element
      await browserView.webContents.executeJavaScript(`
        const el = document.querySelector('[data-mmid="${element.mmid}"]');
        if (el) { el.scrollIntoView({block:'center'}); el.click(); }
      `);
      automationState.stats.clicked++;
    }

    action.success = true;

    // Wait for potential navigation/content load
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Check if navigation occurred
    action.urlAfter = browserView.webContents.getURL();
    if (action.urlBefore !== action.urlAfter) {
      automationState.stats.navigations++;
      action.navigated = true;
    }

    // Re-extract elements and find new ones
    const newElements = await browserView.webContents.executeJavaScript(`
      (function() {
        const elements = [];
        let id = 1;
        const selectors = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick]';

        document.querySelectorAll(selectors).forEach(el => {
          const rect = el.getBoundingClientRect();
          const style = getComputedStyle(el);

          if (rect.width === 0 || rect.height === 0) return;
          if (style.display === 'none' || style.visibility === 'hidden') return;

          const existingMmid = el.getAttribute('data-mmid');
          const mmid = existingMmid || 'el-' + Date.now() + '-' + id++;
          if (!existingMmid) el.setAttribute('data-mmid', mmid);

          let type = 'clickable';
          const tag = el.tagName.toLowerCase();
          if (tag === 'a') type = 'link';
          else if (tag === 'button') type = 'button';
          else if (tag === 'input') type = 'input';
          else if (tag === 'select') type = 'dropdown';

          let text = el.innerText?.trim().slice(0, 80) ||
                     el.value?.slice(0, 80) ||
                     el.getAttribute('aria-label') ||
                     el.getAttribute('placeholder') || '';

          elements.push({
            mmid, tag, text, elementType: type,
            attributes: {
              href: el.getAttribute('href'),
              type: el.getAttribute('type'),
              placeholder: el.getAttribute('placeholder'),
              name: el.getAttribute('name')
            }
          });
        });

        return elements;
      })()
    `);

    // Queue new elements
    const beforeCount = automationState.queue.length;
    queueElements(newElements);
    action.newElements = automationState.queue.length - beforeCount;

    currentState.elements = newElements;
    sendToRenderer('elements-extracted', { elements: newElements, count: newElements.length });

  } catch (err) {
    action.success = false;
    action.error = err.message;
    automationState.stats.errors++;
  }

  automationState.actionHistory.push(action);
  automationState.currentAction = null;

  sendToRenderer('automation-action-complete', {
    action,
    stats: automationState.stats,
    remaining: automationState.queue.length,
    history: automationState.actionHistory.slice(-20) // Last 20 actions
  });

  return action;
}

// Automation loop
async function runAutomationLoop() {
  while (automationState.running && !automationState.paused && automationState.queue.length > 0) {
    await processNextElement();
    // Small delay between actions
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  if (automationState.running && automationState.queue.length === 0) {
    // Automation complete
    automationState.running = false;
    sendToRenderer('automation-complete', {
      stats: automationState.stats,
      history: automationState.actionHistory
    });
  }
}

// Start automation
ipcMain.handle('start-automation', async () => {
  if (!browserView) return { success: false, error: 'Browser not started' };
  if (automationState.running) return { success: false, error: 'Already running' };

  // Reset state
  automationState.running = true;
  automationState.paused = false;
  automationState.queue = [];
  automationState.processed = new Set();
  automationState.actionHistory = [];
  automationState.currentAction = null;
  automationState.stats = { total: 0, clicked: 0, inputs: 0, navigations: 0, errors: 0 };

  // Queue current elements
  queueElements(currentState.elements);

  sendToRenderer('automation-started', {
    queueSize: automationState.queue.length,
    stats: automationState.stats
  });

  // Start the loop
  runAutomationLoop();

  return { success: true, queueSize: automationState.queue.length };
});

// Pause automation
ipcMain.handle('pause-automation', () => {
  automationState.paused = true;
  sendToRenderer('automation-paused', {
    stats: automationState.stats,
    remaining: automationState.queue.length
  });
  return { success: true };
});

// Resume automation
ipcMain.handle('resume-automation', () => {
  if (!automationState.running) return { success: false, error: 'Not running' };
  automationState.paused = false;
  sendToRenderer('automation-resumed', {
    stats: automationState.stats,
    remaining: automationState.queue.length
  });
  runAutomationLoop();
  return { success: true };
});

// Stop automation
ipcMain.handle('stop-automation', () => {
  automationState.running = false;
  automationState.paused = false;
  sendToRenderer('automation-stopped', {
    stats: automationState.stats,
    history: automationState.actionHistory
  });
  return { success: true, stats: automationState.stats };
});

// Get automation state
ipcMain.handle('get-automation-state', () => {
  return {
    running: automationState.running,
    paused: automationState.paused,
    queueSize: automationState.queue.length,
    processedCount: automationState.processed.size,
    stats: automationState.stats,
    currentAction: automationState.currentAction,
    history: automationState.actionHistory.slice(-20)
  };
});

// App lifecycle
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
