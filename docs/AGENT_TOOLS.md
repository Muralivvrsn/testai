# Agent Tools

> Complete tool definitions for the autonomous QA agent - every tool the agent can use to interact with browsers, analyze pages, and report findings.

---

## Table of Contents

1. [Tool Architecture](#tool-architecture)
2. [Browser Tools](#browser-tools)
3. [Assertion Tools](#assertion-tools)
4. [Analysis Tools](#analysis-tools)
5. [Data Tools](#data-tools)
6. [Memory Tools](#memory-tools)
7. [Reporting Tools](#reporting-tools)
8. [Tool Registry](#tool-registry)

---

## Tool Architecture

### Tool Definition Structure

```typescript
/**
 * Base interface for all tools
 */

interface Tool {
  // Metadata
  name: string;
  description: string;
  category: ToolCategory;

  // Parameters
  parameters: ToolParameter[];

  // Execution
  execute: (args: Record<string, any>, context: ToolContext) => Promise<ToolResult>;

  // Validation
  validate?: (args: Record<string, any>) => ValidationResult;

  // Cost estimation
  estimateCost?: (args: Record<string, any>) => CostEstimate;
}

interface ToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required: boolean;
  default?: any;
  enum?: any[];
  validation?: (value: any) => boolean;
}

interface ToolContext {
  page: Page;                    // Playwright page instance
  browser: BrowserController;    // Browser controller
  memory: Hippocampus;          // Memory system
  logger: Logger;                // Logging
  config: AgentConfig;          // Configuration
}

interface ToolResult {
  success: boolean;
  output: any;
  error?: string;
  metadata: {
    duration: number;
    tokensUsed?: number;
    screenshotPath?: string;
  };
}

type ToolCategory =
  | 'browser'
  | 'assertion'
  | 'analysis'
  | 'data'
  | 'memory'
  | 'reporting';
```

### Tool Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           TOOL EXECUTION FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  LLM Decision                                                                    │
│       │                                                                          │
│       ▼                                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐          │
│  │  PARSE     │───▶│  VALIDATE  │───▶│  APPROVE   │───▶│  EXECUTE   │          │
│  │  Tool Call │    │  Arguments │    │  (if needed)│   │  Tool      │          │
│  └────────────┘    └────────────┘    └────────────┘    └────────────┘          │
│                          │                  │                  │                 │
│                          ▼                  ▼                  ▼                 │
│                    [Invalid?]         [Rejected?]        [Success?]             │
│                       │                  │                  │    │              │
│                       ▼                  ▼                  ▼    ▼              │
│                  Return Error      Return Error       Observation  Error        │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Browser Tools

### 1. navigate

```typescript
/**
 * Navigate to a URL
 */

const navigateTool: Tool = {
  name: 'navigate',
  description: 'Navigate to a URL and wait for the page to load',
  category: 'browser',

  parameters: [
    {
      name: 'url',
      type: 'string',
      description: 'The URL to navigate to',
      required: true,
      validation: (url) => /^https?:\/\/.+/.test(url)
    },
    {
      name: 'waitUntil',
      type: 'string',
      description: 'When to consider navigation complete',
      required: false,
      default: 'networkidle',
      enum: ['load', 'domcontentloaded', 'networkidle']
    },
    {
      name: 'timeout',
      type: 'number',
      description: 'Maximum wait time in milliseconds',
      required: false,
      default: 30000
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const response = await context.page.goto(args.url, {
        waitUntil: args.waitUntil,
        timeout: args.timeout
      });

      const finalUrl = context.page.url();
      const title = await context.page.title();
      const status = response?.status() || 0;

      // Capture network summary
      const networkSummary = await this.captureNetworkSummary(context);

      // Check for common issues
      const issues = await this.detectIssues(context, status);

      return {
        success: status >= 200 && status < 400,
        output: {
          url: args.url,
          finalUrl,
          redirected: args.url !== finalUrl,
          title,
          status,
          loadTime: Date.now() - startTime,
          networkSummary,
          issues
        },
        metadata: {
          duration: Date.now() - startTime
        }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  async captureNetworkSummary(context: ToolContext) {
    // This would be populated by network interceptor
    return {
      requests: context.browser.getNetworkLog().length,
      failedRequests: context.browser.getNetworkLog().filter(r => !r.ok).length,
      totalSize: context.browser.getTotalTransferSize()
    };
  },

  async detectIssues(context: ToolContext, status: number) {
    const issues: string[] = [];

    if (status === 404) issues.push('Page not found (404)');
    if (status >= 500) issues.push(`Server error (${status})`);

    // Check console errors
    const consoleErrors = context.browser.getConsoleErrors();
    if (consoleErrors.length > 0) {
      issues.push(`${consoleErrors.length} console errors detected`);
    }

    return issues;
  }
};
```

### 2. click

```typescript
/**
 * Click on an element
 */

const clickTool: Tool = {
  name: 'click',
  description: 'Click on an element identified by selector or mmid',
  category: 'browser',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'CSS selector, XPath, or data-mmid value',
      required: true
    },
    {
      name: 'button',
      type: 'string',
      description: 'Mouse button to use',
      required: false,
      default: 'left',
      enum: ['left', 'right', 'middle']
    },
    {
      name: 'clickCount',
      type: 'number',
      description: 'Number of clicks (1=single, 2=double)',
      required: false,
      default: 1
    },
    {
      name: 'force',
      type: 'boolean',
      description: 'Force click even if element is not visible',
      required: false,
      default: false
    },
    {
      name: 'waitForNavigation',
      type: 'boolean',
      description: 'Wait for navigation after click',
      required: false,
      default: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      // Resolve selector (support mmid shorthand)
      const selector = this.resolveSelector(args.selector);

      // Wait for element
      const element = await context.page.waitForSelector(selector, {
        timeout: 5000,
        state: 'visible'
      });

      if (!element) {
        return {
          success: false,
          output: null,
          error: `Element not found: ${selector}`,
          metadata: { duration: Date.now() - startTime }
        };
      }

      // Capture state before click
      const beforeUrl = context.page.url();
      const beforeScreenshot = await context.page.screenshot({ type: 'png' });

      // Perform click
      const clickPromise = element.click({
        button: args.button,
        clickCount: args.clickCount,
        force: args.force
      });

      // Optionally wait for navigation
      if (args.waitForNavigation) {
        await Promise.all([
          clickPromise,
          context.page.waitForNavigation({ timeout: 10000 }).catch(() => null)
        ]);
      } else {
        await clickPromise;
      }

      // Wait for any triggered actions to settle
      await context.page.waitForTimeout(500);

      // Capture state after click
      const afterUrl = context.page.url();
      const navigationTriggered = beforeUrl !== afterUrl;

      // Check for modals/dialogs
      const modalOpened = await this.detectModal(context);

      // Check for visible changes
      const visibleChange = await this.detectVisibleChange(
        beforeScreenshot,
        await context.page.screenshot({ type: 'png' })
      );

      return {
        success: true,
        output: {
          clicked: selector,
          navigationTriggered,
          newUrl: navigationTriggered ? afterUrl : null,
          modalOpened,
          visibleChange
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  resolveSelector(selector: string): string {
    // Support mmid shorthand: "el-42" -> "[data-mmid='el-42']"
    if (/^el-\d+$/.test(selector)) {
      return `[data-mmid='${selector}']`;
    }
    return selector;
  },

  async detectModal(context: ToolContext): Promise<boolean> {
    const modalSelectors = [
      '[role="dialog"]',
      '[role="alertdialog"]',
      '.modal',
      '.dialog',
      '[aria-modal="true"]'
    ];

    for (const sel of modalSelectors) {
      const modal = await context.page.$(sel);
      if (modal && await modal.isVisible()) {
        return true;
      }
    }
    return false;
  },

  async detectVisibleChange(before: Buffer, after: Buffer): Promise<boolean> {
    // Use pixelmatch to detect significant visual changes
    const { pixelmatch } = await import('pixelmatch');
    const { PNG } = await import('pngjs');

    const img1 = PNG.sync.read(before);
    const img2 = PNG.sync.read(after);

    const diff = pixelmatch(
      img1.data, img2.data, null,
      img1.width, img1.height,
      { threshold: 0.1 }
    );

    // More than 1% pixels changed = visible change
    return diff > (img1.width * img1.height * 0.01);
  }
};
```

### 3. type

```typescript
/**
 * Type text into an input element
 */

const typeTool: Tool = {
  name: 'type',
  description: 'Type text into an input field',
  category: 'browser',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'CSS selector or mmid of the input element',
      required: true
    },
    {
      name: 'text',
      type: 'string',
      description: 'Text to type',
      required: true
    },
    {
      name: 'clear',
      type: 'boolean',
      description: 'Clear existing text before typing',
      required: false,
      default: true
    },
    {
      name: 'delay',
      type: 'number',
      description: 'Delay between keystrokes (ms) for realistic typing',
      required: false,
      default: 50
    },
    {
      name: 'pressEnter',
      type: 'boolean',
      description: 'Press Enter after typing',
      required: false,
      default: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const selector = this.resolveSelector(args.selector);
      const element = await context.page.waitForSelector(selector, {
        timeout: 5000,
        state: 'visible'
      });

      if (!element) {
        return {
          success: false,
          output: null,
          error: `Input element not found: ${selector}`,
          metadata: { duration: Date.now() - startTime }
        };
      }

      // Clear existing text if requested
      if (args.clear) {
        await element.click({ clickCount: 3 }); // Select all
        await context.page.keyboard.press('Backspace');
      }

      // Type with realistic delay
      await element.type(args.text, { delay: args.delay });

      // Press Enter if requested
      if (args.pressEnter) {
        await context.page.keyboard.press('Enter');
        await context.page.waitForTimeout(500);
      }

      // Get final value
      const finalValue = await element.inputValue();

      // Check for validation errors
      const validationError = await this.checkValidation(context, selector);

      return {
        success: true,
        output: {
          selector,
          typed: args.text,
          finalValue,
          validationError,
          enterPressed: args.pressEnter
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  resolveSelector(selector: string): string {
    if (/^el-\d+$/.test(selector)) {
      return `[data-mmid='${selector}']`;
    }
    return selector;
  },

  async checkValidation(context: ToolContext, inputSelector: string): Promise<string | null> {
    // Check for HTML5 validation
    const validity = await context.page.$eval(inputSelector, (el: HTMLInputElement) => {
      return {
        valid: el.validity.valid,
        message: el.validationMessage
      };
    }).catch(() => ({ valid: true, message: '' }));

    if (!validity.valid) {
      return validity.message;
    }

    // Check for associated error messages
    const errorSelectors = [
      `${inputSelector} + .error`,
      `${inputSelector} ~ .error-message`,
      `[data-error-for="${inputSelector}"]`
    ];

    for (const sel of errorSelectors) {
      const errorEl = await context.page.$(sel);
      if (errorEl && await errorEl.isVisible()) {
        return await errorEl.textContent();
      }
    }

    return null;
  }
};
```

### 4. extractDOM

```typescript
/**
 * Extract DOM structure and interactive elements
 */

const extractDOMTool: Tool = {
  name: 'extractDOM',
  description: 'Extract interactive elements and page structure',
  category: 'browser',

  parameters: [
    {
      name: 'includeHidden',
      type: 'boolean',
      description: 'Include hidden elements',
      required: false,
      default: false
    },
    {
      name: 'maxElements',
      type: 'number',
      description: 'Maximum elements to extract',
      required: false,
      default: 200
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const extraction = await context.page.evaluate((options) => {
        const selector = [
          'a[href]',
          'button',
          'input:not([type=hidden])',
          'select',
          'textarea',
          '[role=button]',
          '[role=link]',
          '[role=checkbox]',
          '[role=radio]',
          '[role=textbox]',
          '[role=combobox]',
          '[onclick]',
          '[tabindex]:not([tabindex="-1"])'
        ].join(',');

        const elements = document.querySelectorAll(selector);
        const extracted: any[] = [];

        function isVisible(el: Element): boolean {
          const style = window.getComputedStyle(el);
          const rect = el.getBoundingClientRect();
          return (
            style.display !== 'none' &&
            style.visibility !== 'hidden' &&
            parseFloat(style.opacity) > 0 &&
            rect.width > 0 &&
            rect.height > 0
          );
        }

        function classifyElement(el: Element): string {
          const tag = el.tagName.toLowerCase();
          const type = el.getAttribute('type')?.toLowerCase();
          const role = el.getAttribute('role');

          if (tag === 'a') return 'link';
          if (tag === 'button' || role === 'button') return 'button';
          if (tag === 'select' || role === 'combobox') return 'dropdown';
          if (tag === 'textarea') return 'textarea';
          if (tag === 'input') {
            if (['checkbox', 'radio'].includes(type || '')) return 'toggle';
            if (['submit', 'button'].includes(type || '')) return 'button';
            return 'input';
          }
          return 'clickable';
        }

        function getInputType(el: Element): string | null {
          if (el.tagName.toLowerCase() !== 'input') return null;
          return el.getAttribute('type') || 'text';
        }

        elements.forEach((el, index) => {
          if (index >= options.maxElements) return;

          const visible = isVisible(el);
          if (!visible && !options.includeHidden) return;

          const mmid = `el-${index}`;
          el.setAttribute('data-mmid', mmid);

          const rect = el.getBoundingClientRect();

          extracted.push({
            mmid,
            tag: el.tagName.toLowerCase(),
            type: classifyElement(el),
            inputType: getInputType(el),
            text: el.textContent?.trim().slice(0, 80) || '',
            placeholder: el.getAttribute('placeholder') || '',
            name: el.getAttribute('name') || '',
            id: el.id || '',
            href: el.getAttribute('href') || '',
            value: (el as HTMLInputElement).value || '',
            checked: (el as HTMLInputElement).checked,
            disabled: (el as HTMLInputElement).disabled,
            required: (el as HTMLInputElement).required,
            visible,
            rect: {
              x: rect.x,
              y: rect.y,
              width: rect.width,
              height: rect.height
            },
            attributes: {
              class: el.className,
              'aria-label': el.getAttribute('aria-label'),
              'data-testid': el.getAttribute('data-testid')
            }
          });
        });

        // Classify page type
        const pageType = (() => {
          const url = window.location.pathname.toLowerCase();
          const title = document.title.toLowerCase();
          const hasLoginForm = !!document.querySelector('input[type=password]');
          const hasSearchForm = !!document.querySelector('input[type=search]');

          if (url.includes('login') || url.includes('signin') || hasLoginForm) return 'login';
          if (url.includes('signup') || url.includes('register')) return 'signup';
          if (url.includes('dashboard')) return 'dashboard';
          if (url.includes('settings')) return 'settings';
          if (url.includes('profile') || url.includes('account')) return 'profile';
          if (url.includes('search') || hasSearchForm) return 'search';
          if (url.includes('cart') || url.includes('checkout')) return 'ecommerce';
          if (url.includes('admin')) return 'admin';
          return 'general';
        })();

        return {
          url: window.location.href,
          title: document.title,
          pageType,
          elements: extracted,
          forms: Array.from(document.forms).map(f => ({
            id: f.id,
            name: f.name,
            action: f.action,
            method: f.method,
            fields: Array.from(f.elements).length
          })),
          headings: Array.from(document.querySelectorAll('h1,h2,h3')).map(h => ({
            level: parseInt(h.tagName[1]),
            text: h.textContent?.trim().slice(0, 100)
          }))
        };

      }, args);

      // Group elements by type
      const groupedElements = this.groupElements(extraction.elements);

      return {
        success: true,
        output: {
          ...extraction,
          elementCount: extraction.elements.length,
          groupedElements,
          summary: this.generateSummary(extraction)
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  groupElements(elements: any[]): Record<string, any[]> {
    const groups: Record<string, any[]> = {
      links: [],
      buttons: [],
      inputs: [],
      dropdowns: [],
      toggles: [],
      textareas: [],
      other: []
    };

    for (const el of elements) {
      const group = groups[el.type + 's'] || groups.other;
      group.push(el);
    }

    return groups;
  },

  generateSummary(extraction: any): string {
    const counts = extraction.elements.reduce((acc: any, el: any) => {
      acc[el.type] = (acc[el.type] || 0) + 1;
      return acc;
    }, {});

    return `Page: ${extraction.pageType}. ` +
           `Found: ${Object.entries(counts).map(([k, v]) => `${v} ${k}s`).join(', ')}. ` +
           `${extraction.forms.length} forms, ${extraction.headings.length} headings.`;
  }
};
```

### 5. screenshot

```typescript
/**
 * Capture screenshot of page or element
 */

const screenshotTool: Tool = {
  name: 'screenshot',
  description: 'Capture a screenshot of the page or specific element',
  category: 'browser',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'Element selector to screenshot (omit for full page)',
      required: false
    },
    {
      name: 'fullPage',
      type: 'boolean',
      description: 'Capture full scrollable page',
      required: false,
      default: false
    },
    {
      name: 'name',
      type: 'string',
      description: 'Name for the screenshot file',
      required: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const filename = args.name ||
        `screenshot-${Date.now()}.png`;
      const filepath = `evidence/screenshots/${filename}`;

      let buffer: Buffer;

      if (args.selector) {
        const element = await context.page.$(args.selector);
        if (!element) {
          return {
            success: false,
            output: null,
            error: `Element not found: ${args.selector}`,
            metadata: { duration: Date.now() - startTime }
          };
        }
        buffer = await element.screenshot({ type: 'png' });
      } else {
        buffer = await context.page.screenshot({
          type: 'png',
          fullPage: args.fullPage
        });
      }

      // Save to file system
      await context.browser.saveFile(filepath, buffer);

      return {
        success: true,
        output: {
          path: filepath,
          size: buffer.length,
          fullPage: args.fullPage,
          element: args.selector || null
        },
        metadata: {
          duration: Date.now() - startTime,
          screenshotPath: filepath
        }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

### 6. waitFor

```typescript
/**
 * Wait for various conditions
 */

const waitForTool: Tool = {
  name: 'waitFor',
  description: 'Wait for an element, navigation, or timeout',
  category: 'browser',

  parameters: [
    {
      name: 'condition',
      type: 'string',
      description: 'What to wait for',
      required: true,
      enum: ['selector', 'navigation', 'networkIdle', 'timeout', 'function']
    },
    {
      name: 'value',
      type: 'string',
      description: 'Selector, timeout ms, or function to evaluate',
      required: true
    },
    {
      name: 'state',
      type: 'string',
      description: 'For selector: visible, hidden, attached, detached',
      required: false,
      default: 'visible',
      enum: ['visible', 'hidden', 'attached', 'detached']
    },
    {
      name: 'timeout',
      type: 'number',
      description: 'Maximum wait time in milliseconds',
      required: false,
      default: 10000
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      let result: any;

      switch (args.condition) {
        case 'selector':
          result = await context.page.waitForSelector(args.value, {
            state: args.state,
            timeout: args.timeout
          });
          break;

        case 'navigation':
          result = await context.page.waitForNavigation({
            timeout: args.timeout
          });
          break;

        case 'networkIdle':
          result = await context.page.waitForLoadState('networkidle', {
            timeout: args.timeout
          });
          break;

        case 'timeout':
          await context.page.waitForTimeout(parseInt(args.value));
          result = true;
          break;

        case 'function':
          result = await context.page.waitForFunction(args.value, {
            timeout: args.timeout
          });
          break;
      }

      return {
        success: true,
        output: {
          condition: args.condition,
          waited: Date.now() - startTime,
          result: result ? 'satisfied' : 'completed'
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

---

## Assertion Tools

### 7. assertVisible

```typescript
/**
 * Assert element is visible
 */

const assertVisibleTool: Tool = {
  name: 'assertVisible',
  description: 'Verify an element is visible on the page',
  category: 'assertion',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'Element selector to check',
      required: true
    },
    {
      name: 'timeout',
      type: 'number',
      description: 'Max time to wait for visibility',
      required: false,
      default: 5000
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const selector = this.resolveSelector(args.selector);

      const element = await context.page.waitForSelector(selector, {
        state: 'visible',
        timeout: args.timeout
      }).catch(() => null);

      const visible = !!element;

      // Capture evidence
      const screenshot = await context.page.screenshot({ type: 'png' });
      const screenshotPath = `evidence/assertions/visible-${Date.now()}.png`;
      await context.browser.saveFile(screenshotPath, screenshot);

      return {
        success: true,
        output: {
          selector,
          visible,
          passed: visible,
          message: visible
            ? `Element "${selector}" is visible`
            : `ASSERTION FAILED: Element "${selector}" is NOT visible`
        },
        metadata: {
          duration: Date.now() - startTime,
          screenshotPath
        }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  resolveSelector(selector: string): string {
    if (/^el-\d+$/.test(selector)) {
      return `[data-mmid='${selector}']`;
    }
    return selector;
  }
};
```

### 8. assertText

```typescript
/**
 * Assert element contains expected text
 */

const assertTextTool: Tool = {
  name: 'assertText',
  description: 'Verify element contains expected text',
  category: 'assertion',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'Element selector',
      required: true
    },
    {
      name: 'expected',
      type: 'string',
      description: 'Expected text (partial match)',
      required: true
    },
    {
      name: 'exact',
      type: 'boolean',
      description: 'Require exact match',
      required: false,
      default: false
    },
    {
      name: 'caseSensitive',
      type: 'boolean',
      description: 'Case-sensitive comparison',
      required: false,
      default: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const selector = this.resolveSelector(args.selector);
      const element = await context.page.$(selector);

      if (!element) {
        return {
          success: true,
          output: {
            passed: false,
            message: `Element "${selector}" not found`
          },
          metadata: { duration: Date.now() - startTime }
        };
      }

      const actual = await element.textContent() || '';
      let passed: boolean;

      if (args.exact) {
        passed = args.caseSensitive
          ? actual === args.expected
          : actual.toLowerCase() === args.expected.toLowerCase();
      } else {
        passed = args.caseSensitive
          ? actual.includes(args.expected)
          : actual.toLowerCase().includes(args.expected.toLowerCase());
      }

      return {
        success: true,
        output: {
          selector,
          expected: args.expected,
          actual: actual.slice(0, 200),
          passed,
          message: passed
            ? `Text assertion passed`
            : `ASSERTION FAILED: Expected "${args.expected}", found "${actual.slice(0, 100)}"`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  resolveSelector(selector: string): string {
    if (/^el-\d+$/.test(selector)) {
      return `[data-mmid='${selector}']`;
    }
    return selector;
  }
};
```

### 9. assertUrl

```typescript
/**
 * Assert current URL matches expected pattern
 */

const assertUrlTool: Tool = {
  name: 'assertUrl',
  description: 'Verify current URL matches expected value or pattern',
  category: 'assertion',

  parameters: [
    {
      name: 'expected',
      type: 'string',
      description: 'Expected URL or regex pattern',
      required: true
    },
    {
      name: 'isRegex',
      type: 'boolean',
      description: 'Treat expected as regex pattern',
      required: false,
      default: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const actual = context.page.url();
      let passed: boolean;

      if (args.isRegex) {
        const regex = new RegExp(args.expected);
        passed = regex.test(actual);
      } else {
        passed = actual === args.expected || actual.includes(args.expected);
      }

      return {
        success: true,
        output: {
          expected: args.expected,
          actual,
          passed,
          message: passed
            ? `URL assertion passed`
            : `ASSERTION FAILED: Expected URL "${args.expected}", actual "${actual}"`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

### 10. compareScreenshot

```typescript
/**
 * Visual regression testing - compare screenshots
 */

const compareScreenshotTool: Tool = {
  name: 'compareScreenshot',
  description: 'Compare current screenshot against baseline for visual regression',
  category: 'assertion',

  parameters: [
    {
      name: 'baselinePath',
      type: 'string',
      description: 'Path to baseline screenshot',
      required: true
    },
    {
      name: 'selector',
      type: 'string',
      description: 'Element to capture (omit for full page)',
      required: false
    },
    {
      name: 'threshold',
      type: 'number',
      description: 'Pixel difference threshold (0-1)',
      required: false,
      default: 0.1
    },
    {
      name: 'updateBaseline',
      type: 'boolean',
      description: 'Update baseline if not found',
      required: false,
      default: false
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();
    const { pixelmatch } = await import('pixelmatch');
    const { PNG } = await import('pngjs');

    try {
      // Capture current screenshot
      let currentBuffer: Buffer;
      if (args.selector) {
        const element = await context.page.$(args.selector);
        if (!element) {
          return {
            success: false,
            output: null,
            error: `Element not found: ${args.selector}`,
            metadata: { duration: Date.now() - startTime }
          };
        }
        currentBuffer = await element.screenshot({ type: 'png' });
      } else {
        currentBuffer = await context.page.screenshot({ type: 'png', fullPage: true });
      }

      // Load baseline
      const baselineExists = await context.browser.fileExists(args.baselinePath);

      if (!baselineExists) {
        if (args.updateBaseline) {
          await context.browser.saveFile(args.baselinePath, currentBuffer);
          return {
            success: true,
            output: {
              passed: true,
              message: 'Baseline created (first run)',
              baselineCreated: true
            },
            metadata: { duration: Date.now() - startTime }
          };
        }
        return {
          success: true,
          output: {
            passed: false,
            message: `Baseline not found: ${args.baselinePath}`
          },
          metadata: { duration: Date.now() - startTime }
        };
      }

      const baselineBuffer = await context.browser.readFile(args.baselinePath);

      // Compare images
      const img1 = PNG.sync.read(baselineBuffer);
      const img2 = PNG.sync.read(currentBuffer);

      // Handle size mismatch
      if (img1.width !== img2.width || img1.height !== img2.height) {
        return {
          success: true,
          output: {
            passed: false,
            message: `Size mismatch: baseline ${img1.width}x${img1.height}, current ${img2.width}x${img2.height}`,
            sizeMismatch: true
          },
          metadata: { duration: Date.now() - startTime }
        };
      }

      const diff = new PNG({ width: img1.width, height: img1.height });

      const mismatchedPixels = pixelmatch(
        img1.data, img2.data, diff.data,
        img1.width, img1.height,
        { threshold: args.threshold }
      );

      const totalPixels = img1.width * img1.height;
      const mismatchPercentage = (mismatchedPixels / totalPixels) * 100;
      const passed = mismatchPercentage < 1; // Less than 1% difference

      // Save diff image if there are differences
      let diffPath: string | null = null;
      if (!passed) {
        diffPath = args.baselinePath.replace('.png', '-diff.png');
        await context.browser.saveFile(diffPath, PNG.sync.write(diff));
      }

      return {
        success: true,
        output: {
          passed,
          mismatchedPixels,
          mismatchPercentage: mismatchPercentage.toFixed(2),
          diffPath,
          message: passed
            ? `Visual comparison passed (${mismatchPercentage.toFixed(2)}% difference)`
            : `VISUAL REGRESSION: ${mismatchPercentage.toFixed(2)}% pixels differ`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

---

## Analysis Tools

### 11. analyzeAccessibility

```typescript
/**
 * Run accessibility audit using axe-core
 */

const analyzeAccessibilityTool: Tool = {
  name: 'analyzeAccessibility',
  description: 'Run accessibility audit on the current page',
  category: 'analysis',

  parameters: [
    {
      name: 'selector',
      type: 'string',
      description: 'Scope audit to specific element',
      required: false
    },
    {
      name: 'standards',
      type: 'array',
      description: 'Accessibility standards to check',
      required: false,
      default: ['wcag2aa']
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      // Inject axe-core
      await context.page.addScriptTag({
        url: 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.7.2/axe.min.js'
      });

      // Run audit
      const results = await context.page.evaluate((options) => {
        return new Promise((resolve) => {
          (window as any).axe.run(
            options.selector ? document.querySelector(options.selector) : document,
            {
              runOnly: {
                type: 'tag',
                values: options.standards
              }
            }
          ).then(resolve);
        });
      }, args);

      // Process results
      const violations = results.violations || [];
      const passes = results.passes || [];

      const summary = {
        violations: violations.length,
        passes: passes.length,
        critical: violations.filter((v: any) => v.impact === 'critical').length,
        serious: violations.filter((v: any) => v.impact === 'serious').length,
        moderate: violations.filter((v: any) => v.impact === 'moderate').length,
        minor: violations.filter((v: any) => v.impact === 'minor').length
      };

      return {
        success: true,
        output: {
          summary,
          violations: violations.map((v: any) => ({
            id: v.id,
            impact: v.impact,
            description: v.description,
            help: v.help,
            helpUrl: v.helpUrl,
            nodes: v.nodes.length
          })),
          passed: violations.length === 0,
          message: violations.length === 0
            ? 'Accessibility audit passed'
            : `Found ${violations.length} accessibility violations`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

### 12. analyzePerformance

```typescript
/**
 * Collect performance metrics
 */

const analyzePerformanceTool: Tool = {
  name: 'analyzePerformance',
  description: 'Collect Core Web Vitals and performance metrics',
  category: 'analysis',

  parameters: [],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const metrics = await context.page.evaluate(() => {
        const timing = performance.timing;
        const entries = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;

        return {
          // Core Web Vitals
          lcp: performance.getEntriesByType('largest-contentful-paint')[0]?.startTime,
          fid: performance.getEntriesByType('first-input')[0]?.processingStart -
               performance.getEntriesByType('first-input')[0]?.startTime,
          cls: performance.getEntriesByType('layout-shift')
                .filter((e: any) => !e.hadRecentInput)
                .reduce((sum: number, e: any) => sum + e.value, 0),

          // Navigation timing
          domContentLoaded: entries.domContentLoadedEventEnd - entries.startTime,
          fullyLoaded: entries.loadEventEnd - entries.startTime,
          ttfb: entries.responseStart - entries.requestStart,

          // Resource counts
          resources: performance.getEntriesByType('resource').length,
          totalTransferSize: performance.getEntriesByType('resource')
            .reduce((sum: number, r: any) => sum + (r.transferSize || 0), 0)
        };
      });

      // Evaluate against thresholds
      const issues: string[] = [];
      if (metrics.lcp > 2500) issues.push(`LCP too slow: ${metrics.lcp}ms (should be <2500ms)`);
      if (metrics.cls > 0.1) issues.push(`CLS too high: ${metrics.cls} (should be <0.1)`);
      if (metrics.ttfb > 800) issues.push(`TTFB too slow: ${metrics.ttfb}ms (should be <800ms)`);

      return {
        success: true,
        output: {
          metrics,
          issues,
          passed: issues.length === 0,
          message: issues.length === 0
            ? 'Performance metrics within acceptable range'
            : `Found ${issues.length} performance issues`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

### 13. analyzeConsoleErrors

```typescript
/**
 * Check console for errors and warnings
 */

const analyzeConsoleErrorsTool: Tool = {
  name: 'analyzeConsoleErrors',
  description: 'Check browser console for errors and warnings',
  category: 'analysis',

  parameters: [
    {
      name: 'includeWarnings',
      type: 'boolean',
      description: 'Include warnings in results',
      required: false,
      default: true
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const logs = context.browser.getConsoleLogs();

      const errors = logs.filter(log => log.type === 'error');
      const warnings = args.includeWarnings
        ? logs.filter(log => log.type === 'warning')
        : [];

      // Categorize errors
      const categorized = {
        jsErrors: errors.filter(e => e.text.includes('Error') || e.text.includes('TypeError')),
        networkErrors: errors.filter(e => e.text.includes('Failed to load') || e.text.includes('404')),
        securityErrors: errors.filter(e => e.text.includes('CORS') || e.text.includes('blocked')),
        other: errors.filter(e => !this.isCategorized(e))
      };

      return {
        success: true,
        output: {
          errorCount: errors.length,
          warningCount: warnings.length,
          errors: errors.slice(0, 20).map(e => ({
            type: e.type,
            text: e.text.slice(0, 200),
            location: e.location
          })),
          warnings: warnings.slice(0, 10).map(w => ({
            type: w.type,
            text: w.text.slice(0, 200)
          })),
          categorized,
          passed: errors.length === 0,
          message: errors.length === 0
            ? 'No console errors detected'
            : `Found ${errors.length} console errors`
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  },

  isCategorized(error: any): boolean {
    const text = error.text.toLowerCase();
    return text.includes('error') ||
           text.includes('failed to load') ||
           text.includes('cors');
  }
};
```

---

## Data Tools

### 14. generateTestData

```typescript
/**
 * Generate contextual test data
 */

const generateTestDataTool: Tool = {
  name: 'generateTestData',
  description: 'Generate test data appropriate for the input type',
  category: 'data',

  parameters: [
    {
      name: 'type',
      type: 'string',
      description: 'Type of data to generate',
      required: true,
      enum: ['email', 'password', 'name', 'phone', 'address', 'date', 'number', 'text', 'url']
    },
    {
      name: 'variant',
      type: 'string',
      description: 'Variant for edge case testing',
      required: false,
      enum: ['valid', 'invalid', 'edge', 'boundary', 'empty', 'xss', 'sql']
    },
    {
      name: 'count',
      type: 'number',
      description: 'Number of values to generate',
      required: false,
      default: 1
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();
    const faker = require('@faker-js/faker').faker;

    try {
      const generators: Record<string, Record<string, () => string>> = {
        email: {
          valid: () => faker.internet.email(),
          invalid: () => faker.helpers.arrayElement([
            'invalid-email',
            '@nodomain.com',
            'no@dot',
            'spaces in@email.com'
          ]),
          edge: () => faker.helpers.arrayElement([
            'a@b.co',
            'very.long.email.address.that.goes.on@extremely.long.domain.name.com',
            'special+chars@email.com',
            'dots...multiple@email.com'
          ]),
          xss: () => '<script>alert(1)</script>@evil.com'
        },
        password: {
          valid: () => 'TestPassword123!',
          invalid: () => faker.helpers.arrayElement(['123', 'password', 'abcdefgh']),
          edge: () => faker.helpers.arrayElement([
            'a'.repeat(100),
            '!@#$%^&*()',
            ' ',
            'пароль'
          ]),
          boundary: () => faker.helpers.arrayElement(['1234567', '12345678', '12345678901234567890123456789012'])
        },
        name: {
          valid: () => faker.person.fullName(),
          invalid: () => faker.helpers.arrayElement(['', '   ', '123']),
          edge: () => faker.helpers.arrayElement([
            "O'Connor-Smith",
            'José García',
            '山田太郎',
            'A'.repeat(200)
          ]),
          xss: () => '<img src=x onerror=alert(1)>'
        },
        phone: {
          valid: () => faker.phone.number(),
          invalid: () => faker.helpers.arrayElement(['abc', '123', '+++++']),
          edge: () => faker.helpers.arrayElement([
            '+1-800-555-0199',
            '(555) 555-5555',
            '+44 20 7946 0958'
          ])
        },
        number: {
          valid: () => faker.number.int({ min: 1, max: 100 }).toString(),
          invalid: () => faker.helpers.arrayElement(['abc', '12.34.56', '--1']),
          boundary: () => faker.helpers.arrayElement(['0', '-1', '2147483647', '-2147483648']),
          edge: () => faker.helpers.arrayElement(['1e10', 'Infinity', 'NaN'])
        },
        text: {
          valid: () => faker.lorem.sentence(),
          empty: () => '',
          edge: () => faker.helpers.arrayElement([
            'a'.repeat(1000),
            '\n\n\n',
            '\t\t\t',
            '🎉🚀💡'
          ]),
          xss: () => '"><script>alert(document.cookie)</script>',
          sql: () => "'; DROP TABLE users; --"
        },
        url: {
          valid: () => faker.internet.url(),
          invalid: () => faker.helpers.arrayElement(['not-a-url', 'ftp://invalid', '://']),
          edge: () => faker.helpers.arrayElement([
            'http://localhost:3000',
            'https://subdomain.domain.co.uk/path?query=value#anchor',
            'data:text/html,<script>alert(1)</script>'
          ])
        }
      };

      const generator = generators[args.type]?.[args.variant || 'valid'];
      if (!generator) {
        return {
          success: false,
          output: null,
          error: `Unknown type/variant: ${args.type}/${args.variant}`,
          metadata: { duration: Date.now() - startTime }
        };
      }

      const values = Array.from({ length: args.count }, generator);

      return {
        success: true,
        output: {
          type: args.type,
          variant: args.variant || 'valid',
          values: args.count === 1 ? values[0] : values
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

---

## Memory Tools

### 15. saveToMemory

```typescript
/**
 * Save information to persistent memory
 */

const saveToMemoryTool: Tool = {
  name: 'saveToMemory',
  description: 'Save important information for later recall',
  category: 'memory',

  parameters: [
    {
      name: 'key',
      type: 'string',
      description: 'Memory key/category',
      required: true
    },
    {
      name: 'value',
      type: 'object',
      description: 'Information to store',
      required: true
    },
    {
      name: 'tags',
      type: 'array',
      description: 'Tags for retrieval',
      required: false,
      default: []
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      await context.memory.store({
        type: 'user_memory',
        key: args.key,
        data: args.value,
        tags: args.tags,
        timestamp: new Date()
      });

      return {
        success: true,
        output: {
          stored: true,
          key: args.key,
          tags: args.tags
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

### 16. recallFromMemory

```typescript
/**
 * Recall information from memory
 */

const recallFromMemoryTool: Tool = {
  name: 'recallFromMemory',
  description: 'Recall previously stored information',
  category: 'memory',

  parameters: [
    {
      name: 'query',
      type: 'string',
      description: 'Search query or key',
      required: true
    },
    {
      name: 'limit',
      type: 'number',
      description: 'Maximum results to return',
      required: false,
      default: 5
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      const results = await context.memory.recall({
        query: args.query,
        limit: args.limit
      });

      return {
        success: true,
        output: {
          found: results.length,
          results: results.map(r => ({
            key: r.key,
            data: r.data,
            tags: r.tags,
            timestamp: r.timestamp
          }))
        },
        metadata: { duration: Date.now() - startTime }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

---

## Reporting Tools

### 17. logBug

```typescript
/**
 * Log a discovered bug
 */

const logBugTool: Tool = {
  name: 'logBug',
  description: 'Log a bug with evidence',
  category: 'reporting',

  parameters: [
    {
      name: 'title',
      type: 'string',
      description: 'Bug title',
      required: true
    },
    {
      name: 'severity',
      type: 'string',
      description: 'Bug severity',
      required: true,
      enum: ['critical', 'high', 'medium', 'low']
    },
    {
      name: 'description',
      type: 'string',
      description: 'Detailed description',
      required: true
    },
    {
      name: 'steps',
      type: 'array',
      description: 'Steps to reproduce',
      required: true
    },
    {
      name: 'expected',
      type: 'string',
      description: 'Expected behavior',
      required: true
    },
    {
      name: 'actual',
      type: 'string',
      description: 'Actual behavior',
      required: true
    }
  ],

  async execute(args, context): Promise<ToolResult> {
    const startTime = Date.now();

    try {
      // Capture screenshot as evidence
      const screenshot = await context.page.screenshot({ fullPage: true });
      const screenshotPath = `evidence/bugs/bug-${Date.now()}.png`;
      await context.browser.saveFile(screenshotPath, screenshot);

      // Create bug report
      const bug = {
        id: `BUG-${Date.now()}`,
        title: args.title,
        severity: args.severity,
        description: args.description,
        stepsToReproduce: args.steps,
        expected: args.expected,
        actual: args.actual,
        url: context.page.url(),
        timestamp: new Date().toISOString(),
        evidence: {
          screenshot: screenshotPath,
          consoleErrors: context.browser.getConsoleErrors(),
          networkErrors: context.browser.getNetworkErrors()
        },
        environment: {
          browser: context.config.browser,
          viewport: context.config.viewport
        }
      };

      // Store in memory
      await context.memory.store({
        type: 'bug',
        data: bug
      });

      return {
        success: true,
        output: {
          bugId: bug.id,
          logged: true,
          evidencePath: screenshotPath
        },
        metadata: {
          duration: Date.now() - startTime,
          screenshotPath
        }
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error.message,
        metadata: { duration: Date.now() - startTime }
      };
    }
  }
};
```

---

## Tool Registry

### Complete Registry Implementation

```typescript
/**
 * Tool registry - manages all available tools
 */

class ToolRegistry {
  private tools: Map<string, Tool> = new Map();

  constructor() {
    this.registerDefaultTools();
  }

  /**
   * Register all default tools
   */
  private registerDefaultTools(): void {
    // Browser tools
    this.register(navigateTool);
    this.register(clickTool);
    this.register(typeTool);
    this.register(extractDOMTool);
    this.register(screenshotTool);
    this.register(waitForTool);

    // Assertion tools
    this.register(assertVisibleTool);
    this.register(assertTextTool);
    this.register(assertUrlTool);
    this.register(compareScreenshotTool);

    // Analysis tools
    this.register(analyzeAccessibilityTool);
    this.register(analyzePerformanceTool);
    this.register(analyzeConsoleErrorsTool);

    // Data tools
    this.register(generateTestDataTool);

    // Memory tools
    this.register(saveToMemoryTool);
    this.register(recallFromMemoryTool);

    // Reporting tools
    this.register(logBugTool);
  }

  /**
   * Register a tool
   */
  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  /**
   * Get a tool by name
   */
  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all tool definitions for LLM
   */
  getToolDefinitions(): ToolDefinition[] {
    return Array.from(this.tools.values()).map(tool => ({
      type: 'function',
      function: {
        name: tool.name,
        description: tool.description,
        parameters: {
          type: 'object',
          properties: tool.parameters.reduce((acc, param) => {
            acc[param.name] = {
              type: param.type,
              description: param.description,
              enum: param.enum
            };
            return acc;
          }, {} as Record<string, any>),
          required: tool.parameters
            .filter(p => p.required)
            .map(p => p.name)
        }
      }
    }));
  }

  /**
   * Get available tools list
   */
  getAvailableTools(): { name: string; description: string; category: string }[] {
    return Array.from(this.tools.values()).map(tool => ({
      name: tool.name,
      description: tool.description,
      category: tool.category
    }));
  }
}
```

---

## Tool Categories Summary

| Category | Tools | Purpose |
|----------|-------|---------|
| **Browser** | navigate, click, type, extractDOM, screenshot, waitFor | Interact with web pages |
| **Assertion** | assertVisible, assertText, assertUrl, compareScreenshot | Verify expected behavior |
| **Analysis** | analyzeAccessibility, analyzePerformance, analyzeConsoleErrors | Run automated checks |
| **Data** | generateTestData | Create test inputs |
| **Memory** | saveToMemory, recallFromMemory | Persist information |
| **Reporting** | logBug | Document findings |

---

## Next Steps

- **[AGENT_MEMORY.md](./AGENT_MEMORY.md)** - Memory architecture deep dive
- **[AGENT_CONTEXT.md](./AGENT_CONTEXT.md)** - Context management strategies
- **[AGENT_ORCHESTRATION.md](./AGENT_ORCHESTRATION.md)** - Multi-agent patterns
