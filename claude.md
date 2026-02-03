# Yalitest - AI-Powered QA Testing Tool

## Vision

**Quality assurance, simplified.** Yalitest is an AI-powered desktop application that automates web testing. Instead of writing test scripts, you simply tell Yali what to test in plain English.

## What Yalitest Does

### Conversational Testing
Talk to Yali naturally:
- "Test the console.yalikit.com and login with Google"
- "Check if all buttons work on this page"
- "Find accessibility issues"
- "Test the checkout flow"

Yali understands your intent, navigates pages, clicks buttons, fills forms, and reports what it finds.

### Autonomous Exploration
Yali acts like a curious QA engineer:
- Explores pages step-by-step
- Remembers what it's already tested (doesn't repeat actions)
- Detects login pages and asks for credentials
- Continues working until your goal is satisfied

### Real Browser Testing
- Embedded Chromium browser
- See exactly what users see
- Test across viewport sizes (desktop, tablet, mobile)
- Real mouse clicks and keyboard input

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Electron Desktop App                      │
├─────────────────────────────────────────────────────────────┤
│  React Frontend                                              │
│  ├── Toolbar (URL bar, navigation, viewport switcher)       │
│  ├── Sidebar (DOM elements explorer)                        │
│  ├── ChatPanel (conversation with Yali)                     │
│  └── Main Area (embedded browser view)                      │
├─────────────────────────────────────────────────────────────┤
│  Electron Main Process                                       │
│  ├── BrowserView (embedded Chromium)                        │
│  ├── DOM Extractor (page analysis)                          │
│  ├── Input Simulator (mouse, keyboard events)               │
│  ├── AI Agent (reasoning loop)                              │
│  └── Cortex System (QA knowledge base)                      │
└─────────────────────────────────────────────────────────────┘
```

## Key Files

### Frontend (src/)
- `App.tsx` - Main application layout
- `components/Toolbar.tsx` - Navigation bar with URL input
- `components/Sidebar.tsx` - DOM elements panel
- `components/ChatPanel.tsx` - AI chat interface
- `hooks/useStore.ts` - Global state (Zustand)

### Electron (electron/)
- `main.js` - Main process, IPC handlers, BrowserView management
- `preload.js` - Secure bridge between main/renderer
- `lib/agent.js` - AI agent with step-by-step reasoning
- `lib/dom-extractor.js` - Extract interactive elements from pages
- `lib/input-simulator.js` - Real mouse/keyboard simulation
- `lib/api.js` - DeepSeek API integration
- `lib/cortex/` - QA knowledge base modules

## AI Agent Behavior

Yali is designed to be a **doer, not an asker**:

1. **Receives user request** - "Test the login page"
2. **Analyzes current page** - Extracts all interactive elements
3. **Plans next action** - Based on user goal and page state
4. **Executes action** - Click, type, scroll, etc.
5. **Observes result** - Did the page change? Any errors?
6. **Continues** - Repeats until goal is achieved or stuck

### Step Tracking
The agent tracks every action taken:
```
📋 STEPS COMPLETED SO FAR:
   Step 1: 👆 click "Continue with Google" → ✓ Success
   Step 2: ⌨️ type "Email or phone" with "user@example.com" → ✓ Success
   Step 3: 👆 click "Next" → ✓ Success
```

This prevents repeating the same action and helps the AI understand progress.

## Data Privacy & User Data

### What We Collect
- **No user data is stored on our servers** - Yalitest runs entirely on your machine
- **No browsing history saved** - Pages you test are not logged
- **No credentials stored** - Login info you provide is used only during the session

### API Usage
- AI requests go to DeepSeek API (or your configured provider)
- Only page structure (element IDs, text) is sent to AI - not full page content
- API key is stored locally in your `.env` file

### Local Storage
- `localStorage` stores UI preferences (sidebar state, theme)
- No sensitive data persists between sessions

## Development

```bash
# Install dependencies
npm install

# Start development (Vite + Electron)
npm run start

# Build for production
npm run build

# Build Windows installer
npm run dist:win

# Build macOS app
npm run dist:mac
```

## Tech Stack

- **Frontend:** React 18, TypeScript, Tailwind CSS, Framer Motion
- **UI Components:** Radix UI primitives
- **Desktop:** Electron 28
- **Build:** Vite 5, electron-builder
- **AI:** DeepSeek API (configurable)

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```
DEEPSEEK_API_KEY=your_api_key_here
```

### Supported AI Providers
- DeepSeek (default)
- Any OpenAI-compatible API

## Design Principles

1. **AI Decides Everything** - No hardcoded patterns, AI interprets user intent
2. **Continuous Operation** - Agent keeps working until goal is satisfied
3. **Step-by-Step Transparency** - Shows what it's doing and why
4. **No Repetition** - Tracks actions to avoid loops
5. **Graceful Recovery** - Detects when stuck and reports clearly

## Roadmap

- [x] Conversational testing
- [x] Autonomous page exploration
- [x] Login/authentication handling
- [x] Step-by-step action tracking
- [x] Windows/macOS builds
- [ ] Test recording and playback
- [ ] CI/CD integration
- [ ] Team collaboration
- [ ] Visual regression testing
