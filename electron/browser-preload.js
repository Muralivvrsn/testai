/**
 * YaliTest - Preload Script for BrowserView (Target Websites)
 *
 * Minimal preload for the embedded browser viewing target websites.
 * We keep this minimal for security - most DOM manipulation is done
 * via executeJavaScript from the main process.
 */

// This file is intentionally minimal
// DOM extraction and interaction is handled via main process executeJavaScript
// to maintain security boundaries

console.log('[YaliTest] Browser preload loaded');
