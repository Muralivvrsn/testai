# YaliTest - Autonomous Web Testing

An Electron desktop app for intelligent web exploration with DOM extraction, element classification, viewport testing, and automated interaction capabilities. YaliTest explores websites like a curious QA engineer, systematically discovering and interacting with every interactive element.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (src/)                     │
│  - Split-pane UI: control panel (420px) + browser view      │
│  - Tailwind CSS + lucide-react icons                        │
│  - IPC communication via preload bridge                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Electron Main Process (electron/)             │
│  - BrowserView for embedded web browsing                    │
│  - DOM extraction with data-mmid injection                  │
│  - Element classification and automation                    │
│  - Viewport preset management                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     BrowserView                              │
│  - Embedded Chromium instance                               │
│  - JavaScript execution for DOM manipulation                │
│  - Navigation and interaction handling                      │
└─────────────────────────────────────────────────────────────┘
```

## Build & Run

```bash
# Development (runs Vite + Electron concurrently)
npm run start

# Or separately:
npm run dev          # Vite dev server only
npm run electron     # Electron only (requires Vite running)

# Production build
npm run build
```

## Core Concepts

### DOM Extraction

Every interactive element gets a unique `data-mmid` attribute injected:
```html
<button data-mmid="el-42">Click me</button>
<a href="/page" data-mmid="el-43">Link</a>
```

The extraction script in `electron/main.js` finds elements matching:
```javascript
'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],[onclick]'
```

Each element is extracted with:
- `mmid`: Unique identifier for targeting
- `tag`: HTML tag name
- `text`: Visible text content (truncated to 80 chars)
- `elementType`: Classified type (link, button, input, dropdown, clickable)
- `attributes`: href, type, placeholder, name

### Viewport Testing

Built-in viewport presets for responsive testing:

| Category | Presets |
|----------|---------|
| Desktop | Responsive (auto), 1920×1080, 1440×900 |
| Laptop | 1366×768, 1280×800 |
| Tablet | 768×1024 (iPad), 1024×768 (Landscape), 1024×1366 (Pro) |
| Mobile | 375×667 (iPhone SE), 390×844 (iPhone 12/13), 360×740 (Android), 414×896 (Plus) |

Custom viewport sizes are also supported.

### Element Classification

Elements are classified into interaction types:

| Classification | Detection Logic |
|----------------|-----------------|
| `navigation` | Links (`<a>`) with valid href (not # or javascript:) |
| `input` | Text inputs, email, password, search, tel, url, number, textarea |
| `select` | Dropdown selects |
| `toggle` | Checkboxes and radio buttons |
| `submit` | Buttons containing "submit", "send", or "sign" |
| `click` | Other clickable elements |

### Smart Input Generation

For form testing, YaliTest generates contextual test inputs:

| Input Type | Generated Value |
|------------|-----------------|
| Email | `test@example.com` |
| Password | `TestPassword123!` |
| Phone | `555-123-4567` |
| Search | `test search` |
| Name | `Test User` |
| URL | `https://example.com` |
| Number | `42` |
| Default | `test input` |

Detection uses input `type`, `placeholder`, and `name` attributes.

## Automation System

### Automation Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Start      │────▶│ Queue all    │────▶│ Process     │
│  Automation │     │ elements     │     │ next item   │
└─────────────┘     └──────────────┘     └─────────────┘
                                                │
                    ┌──────────────┐            ▼
                    │ Complete?    │◀───┌─────────────┐
                    │              │    │ Click/Input │
                    └──────────────┘    │ element     │
                           │            └─────────────┘
                           ▼
                    ┌──────────────┐
                    │ Re-extract   │
                    │ & queue new  │
                    └──────────────┘
```

### Automation Stats

The automation tracks:
- `total`: Total elements queued
- `clicked`: Elements clicked
- `inputs`: Form fields filled
- `navigations`: Page navigations caused
- `errors`: Failed interactions

### Automation Controls

| Action | Description |
|--------|-------------|
| Start | Queues all current elements and begins processing |
| Pause | Pauses processing (can resume) |
| Resume | Continues from paused state |
| Stop | Stops completely and shows summary |

## IPC API (window.yalitest)

### Engine Control

```typescript
// Start the BrowserView engine
await window.yalitest.startEngine()

// Stop the engine
await window.yalitest.stopEngine()
```

### Navigation

```typescript
// Navigate to URL
await window.yalitest.navigate(url)

// Browser history
await window.yalitest.goBack()
await window.yalitest.goForward()
await window.yalitest.reload()
```

### Element Interaction

```typescript
// Click element by mmid
await window.yalitest.clickElement(mmid)

// Input text into element
await window.yalitest.inputText(mmid, text)

// Refresh element extraction
await window.yalitest.refreshElements()
```

### Automation

```typescript
// Start automation
await window.yalitest.startAutomation()

// Pause/Resume
await window.yalitest.pauseAutomation()
await window.yalitest.resumeAutomation()

// Stop automation
await window.yalitest.stopAutomation()

// Get current state
await window.yalitest.getAutomationState()
```

### Viewport

```typescript
// Set viewport preset
await window.yalitest.setViewport('mobile-lg')

// Set custom viewport
await window.yalitest.setViewport('custom', 1280, 720)

// Get available presets
await window.yalitest.getViewportPresets()
```

## Event Listeners

```typescript
// Engine events
window.yalitest.onEngineReady((data) => {})
window.yalitest.onEngineStopped((data) => {})

// Page events
window.yalitest.onPageNavigated(({ url }) => {})
window.yalitest.onPageTitle(({ title }) => {})
window.yalitest.onPageLoaded(({ url, title }) => {})

// Element events
window.yalitest.onElementsExtracted(({ elements, count }) => {})
window.yalitest.onExtractionError(({ message }) => {})

// Viewport events
window.yalitest.onViewportChanged(({ viewport, width, height, scale }) => {})

// Automation events
window.yalitest.onAutomationStarted(({ queueSize, stats }) => {})
window.yalitest.onAutomationActionStart(({ element, remaining }) => {})
window.yalitest.onAutomationActionComplete(({ action, stats, remaining, history }) => {})
window.yalitest.onAutomationPaused(({ stats, remaining }) => {})
window.yalitest.onAutomationResumed(({ stats, remaining }) => {})
window.yalitest.onAutomationStopped(({ stats, history }) => {})
window.yalitest.onAutomationComplete(({ stats, history }) => {})

// Cleanup
window.yalitest.removeAllListeners(channel)
```

## File Structure

```
yalitest/
├── electron/
│   ├── main.js            # Main process - BrowserView, IPC handlers, automation
│   └── preload.js         # Context bridge exposing yalitest API
├── src/
│   ├── App.tsx            # Main React component with all UI
│   ├── App.css            # Styles
│   ├── main.tsx           # React entry point
│   ├── components/
│   │   ├── ui/            # shadcn/ui components
│   │   ├── CrawlDashboard.tsx
│   │   ├── LiveBrowserView.tsx
│   │   ├── InteractionTreeView.tsx
│   │   └── ErrorBoundary.tsx
│   ├── lib/
│   │   ├── api.ts         # (Legacy Tauri API - not used)
│   │   ├── schemas.ts     # Zod schemas
│   │   └── utils.ts       # Utilities
│   └── hooks/
│       ├── useApi.ts      # API hooks
│       └── use-mobile.ts  # Mobile detection
├── package.json
├── vite.config.ts
├── index.html
└── CLAUDE.md              # This file
```

## UI Layout

```
┌────────────────────────────────────────────────────────────────────┐
│  Header: YaliTest logo + Start/Stop button                         │
├────────────────────────────────────────────────────────────────────┤
│  URL Bar: ← → ↻ | [URL input___________________________] [Go]     │
├────────────────────────────────────────────────────────────────────┤
│  Viewport Bar: [Responsive ▼] | 🖥️ 💻 📱 (quick presets)          │
├────────────────────────────────────────────────────────────────────┤
│  Status Bar: ● Ready | Page title                                  │
├────────────────────────────────────────────────────────────────────┤
│  Automation Bar: [🤖 Automate] [⏸️] [⏹️ Stop] | 15/42 Queue: 27    │
├────────────────────────────────────────────────────────────────────┤
│  Automation Panel (collapsible):                                   │
│  ├── Stats: Clicked: 8 | Inputs: 3 | Navs: 2 | Errors: 1          │
│  ├── Current Action: Processing "Submit" button                    │
│  └── History: Last 10 actions with status icons                   │
├──────────────────────────┬─────────────────────────────────────────┤
│  Left Panel (420px)      │  Right: BrowserView                     │
│  ├── Elements (142)      │  ┌─────────────────────────────────┐   │
│  │   Links (45)          │  │                                 │   │
│  │   ├── 🔗 Home         │  │    Embedded Web Page            │   │
│  │   ├── 🔗 About        │  │                                 │   │
│  │   └── +43 more        │  │    (Chromium BrowserView)       │   │
│  │   Buttons (23)        │  │                                 │   │
│  │   ├── 🖱️ Submit       │  │                                 │   │
│  │   └── +22 more        │  │                                 │   │
│  │   Inputs (12)         │  │                                 │   │
│  │   └── 📝 Email        │  │                                 │   │
│  └────────────────────   │  └─────────────────────────────────┘   │
├──────────────────────────┴─────────────────────────────────────────┤
│  Footer: YaliTest v1.0 • https://current-url.com                   │
└────────────────────────────────────────────────────────────────────┘
```

## Timing & Delays

| Operation | Delay |
|-----------|-------|
| Post-click wait | 500ms (for DOM updates) |
| Post-action extraction | 1000ms |
| Between automation actions | 500ms |

## Dependencies

### Electron Main Process
- `electron` - Desktop framework
- `path` - File paths

### React Frontend (package.json)
- `react` + `react-dom` - UI framework
- `lucide-react` - Icons
- `vite` - Build tool
- `typescript` - Type checking
- `concurrently` - Run Vite + Electron together
- `wait-on` - Wait for Vite before launching Electron

## Known Limitations

1. **Single BrowserView**: Only one embedded browser at a time
2. **No persistent state**: Automation state resets when stopped
3. **Sequential automation**: Elements processed one at a time
4. **No network monitoring**: Doesn't capture API requests
5. **No visual cursor**: Uses direct element targeting via mmid

## Troubleshooting

### Port 5173 in use
```bash
# Find and kill process using the port
lsof -ti:5173 | xargs kill -9
```

### Electron doesn't launch
```bash
# Run Vite first
npm run dev

# Then in another terminal
npm run electron
```

### Elements not extracted
- Page may still be loading - wait or click Refresh
- Some elements may be in iframes (not extracted)
- Dynamic content may need interaction to appear
