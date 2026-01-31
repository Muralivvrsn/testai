/**
 * Agent-E Style DOM Extractor
 * Injects mmid attributes and extracts structured DOM tree
 */

export interface DOMNode {
  mmid: string;
  tag: string;
  role: string | null;
  name: string | null;
  text: string | null;
  value: string | null;
  placeholder: string | null;
  href: string | null;
  src: string | null;
  type: string | null;
  isInteractive: boolean;
  isVisible: boolean;
  boundingBox: { x: number; y: number; width: number; height: number } | null;
  attributes: Record<string, string>;
  children: DOMNode[];
}

export interface ExtractionResult {
  url: string;
  title: string;
  timestamp: string;
  totalElements: number;
  interactiveElements: number;
  tree: DOMNode;
  flatInteractive: DOMNode[];
}

// Interactive element tags and roles
const INTERACTIVE_TAGS = new Set([
  'a', 'button', 'input', 'select', 'textarea', 'details', 'summary',
  'audio', 'video', 'iframe', 'embed', 'object'
]);

const INTERACTIVE_ROLES = new Set([
  'button', 'link', 'textbox', 'checkbox', 'radio', 'combobox', 'listbox',
  'menu', 'menuitem', 'menuitemcheckbox', 'menuitemradio', 'option',
  'searchbox', 'slider', 'spinbutton', 'switch', 'tab', 'treeitem'
]);

const SKIP_TAGS = new Set(['script', 'style', 'noscript', 'svg', 'path']);

let mmidCounter = 0;

/**
 * Check if element is visible
 */
function isElementVisible(element: Element): boolean {
  const style = window.getComputedStyle(element);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
    return false;
  }
  const rect = element.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

/**
 * Check if element is interactive
 */
function isInteractive(element: Element): boolean {
  const tag = element.tagName.toLowerCase();
  const role = element.getAttribute('role');
  const tabIndex = element.getAttribute('tabindex');
  const onclick = element.getAttribute('onclick');
  const hasClickListener = (element as any)._hasClickListener;

  return (
    INTERACTIVE_TAGS.has(tag) ||
    (role !== null && INTERACTIVE_ROLES.has(role)) ||
    tabIndex !== null ||
    onclick !== null ||
    hasClickListener ||
    element.hasAttribute('contenteditable')
  );
}

/**
 * Get accessible name for element
 */
function getAccessibleName(element: Element): string | null {
  // aria-label takes priority
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;

  // aria-labelledby
  const labelledBy = element.getAttribute('aria-labelledby');
  if (labelledBy) {
    const labelElement = document.getElementById(labelledBy);
    if (labelElement) return labelElement.textContent?.trim() || null;
  }

  // For inputs, check associated label
  if (element.tagName.toLowerCase() === 'input' || element.tagName.toLowerCase() === 'textarea') {
    const id = element.getAttribute('id');
    if (id) {
      const label = document.querySelector(`label[for="${id}"]`);
      if (label) return label.textContent?.trim() || null;
    }
  }

  // title attribute
  const title = element.getAttribute('title');
  if (title) return title;

  // alt for images
  if (element.tagName.toLowerCase() === 'img') {
    const alt = element.getAttribute('alt');
    if (alt) return alt;
  }

  // Button/link text content
  if (['button', 'a', 'label'].includes(element.tagName.toLowerCase())) {
    const text = element.textContent?.trim();
    if (text && text.length < 100) return text;
  }

  return null;
}

/**
 * Get element's role (explicit or implicit)
 */
function getRole(element: Element): string | null {
  const explicitRole = element.getAttribute('role');
  if (explicitRole) return explicitRole;

  // Implicit roles
  const tag = element.tagName.toLowerCase();
  const type = element.getAttribute('type');

  const implicitRoles: Record<string, string> = {
    'a': 'link',
    'button': 'button',
    'h1': 'heading',
    'h2': 'heading',
    'h3': 'heading',
    'h4': 'heading',
    'h5': 'heading',
    'h6': 'heading',
    'img': 'img',
    'input': type === 'checkbox' ? 'checkbox' : type === 'radio' ? 'radio' : type === 'submit' ? 'button' : 'textbox',
    'select': 'combobox',
    'textarea': 'textbox',
    'nav': 'navigation',
    'main': 'main',
    'header': 'banner',
    'footer': 'contentinfo',
    'aside': 'complementary',
    'form': 'form',
    'table': 'table',
    'ul': 'list',
    'ol': 'list',
    'li': 'listitem',
  };

  return implicitRoles[tag] || null;
}

/**
 * Extract relevant attributes
 */
function extractAttributes(element: Element): Record<string, string> {
  const attrs: Record<string, string> = {};
  const interestingAttrs = [
    'id', 'class', 'name', 'type', 'value', 'placeholder', 'href', 'src',
    'alt', 'title', 'aria-label', 'aria-describedby', 'aria-expanded',
    'aria-selected', 'aria-checked', 'aria-disabled', 'data-testid',
    'data-id', 'disabled', 'readonly', 'required', 'checked', 'selected'
  ];

  for (const attr of interestingAttrs) {
    const value = element.getAttribute(attr);
    if (value !== null && value !== '') {
      attrs[attr] = value;
    }
  }

  return attrs;
}

/**
 * Process a single element and its children
 */
function processElement(element: Element, depth: number = 0): DOMNode | null {
  const tag = element.tagName.toLowerCase();

  // Skip certain elements
  if (SKIP_TAGS.has(tag)) return null;

  // Skip invisible elements at shallow depths (keep structure)
  const visible = isElementVisible(element);
  if (!visible && depth > 2) return null;

  // Assign mmid
  const mmid = String(++mmidCounter);
  element.setAttribute('data-mmid', mmid);

  // Get bounding box
  const rect = element.getBoundingClientRect();
  const boundingBox = visible ? {
    x: Math.round(rect.x),
    y: Math.round(rect.y),
    width: Math.round(rect.width),
    height: Math.round(rect.height)
  } : null;

  // Get direct text content (not from children)
  let textContent: string | null = null;
  for (const child of element.childNodes) {
    if (child.nodeType === Node.TEXT_NODE) {
      const text = child.textContent?.trim();
      if (text) {
        textContent = textContent ? textContent + ' ' + text : text;
      }
    }
  }
  if (textContent && textContent.length > 200) {
    textContent = textContent.substring(0, 200) + '...';
  }

  // Process children
  const children: DOMNode[] = [];
  for (const child of element.children) {
    const processed = processElement(child, depth + 1);
    if (processed) {
      children.push(processed);
    }
  }

  const interactive = isInteractive(element);

  const node: DOMNode = {
    mmid,
    tag,
    role: getRole(element),
    name: getAccessibleName(element),
    text: textContent,
    value: (element as HTMLInputElement).value || null,
    placeholder: element.getAttribute('placeholder'),
    href: element.getAttribute('href'),
    src: element.getAttribute('src'),
    type: element.getAttribute('type'),
    isInteractive: interactive,
    isVisible: visible,
    boundingBox,
    attributes: extractAttributes(element),
    children
  };

  return node;
}

/**
 * Flatten tree to get only interactive elements
 */
function flattenInteractive(node: DOMNode): DOMNode[] {
  const result: DOMNode[] = [];

  if (node.isInteractive && node.isVisible) {
    // Create a copy without children for flat list
    const { children, ...nodeWithoutChildren } = node;
    result.push({ ...nodeWithoutChildren, children: [] });
  }

  for (const child of node.children) {
    result.push(...flattenInteractive(child));
  }

  return result;
}

/**
 * Main extraction function
 */
export function extractDOM(): ExtractionResult {
  // Reset counter
  mmidCounter = 0;

  // Remove any existing mmid attributes
  document.querySelectorAll('[data-mmid]').forEach(el => {
    el.removeAttribute('data-mmid');
  });

  // Process the document
  const tree = processElement(document.body);

  if (!tree) {
    throw new Error('Failed to process document body');
  }

  const flatInteractive = flattenInteractive(tree);

  return {
    url: window.location.href,
    title: document.title,
    timestamp: new Date().toISOString(),
    totalElements: mmidCounter,
    interactiveElements: flatInteractive.length,
    tree,
    flatInteractive
  };
}

/**
 * Get element by mmid
 */
export function getElementByMmid(mmid: string): Element | null {
  return document.querySelector(`[data-mmid="${mmid}"]`);
}

/**
 * Extract only interactive elements (lighter version)
 */
export function extractInteractiveOnly(): DOMNode[] {
  const result = extractDOM();
  return result.flatInteractive;
}
