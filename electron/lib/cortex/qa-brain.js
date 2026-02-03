/**
 * Yali Agent - QA Knowledge Base (Brain)
 * Ported from testai-agent/QA_BRAIN.md
 *
 * Provides the foundation for generating exhaustive, cited test cases.
 * Every section has a unique ID for precise citation tracking.
 *
 * Zero-Hallucination Approach:
 * - All knowledge is structured and traceable
 * - Every test recommendation includes source citation
 * - LLM augments but doesn't invent facts
 */

/**
 * Knowledge section structure
 */
function createSection(id, title, tags, content, tests = []) {
  return {
    id,
    title,
    tags,
    content,
    tests,
    cite() {
      return `Source: Section ${this.id} - ${this.title}`
    }
  }
}

/**
 * Complete QA Knowledge Base
 */
const QA_BRAIN = {
  // ─────────────────────────────────────────────────────────────────
  // SECTION 1: INPUT VALIDATION
  // ─────────────────────────────────────────────────────────────────
  '1.1': createSection('1.1', 'Text Field Validation', ['input', 'validation', 'text', 'security'], `
Input validation is the first line of defense against malformed data, security attacks, and user errors.
Core Principles:
- Validate on client AND server (client for UX, server for security)
- Use allowlists over denylists where possible
- Sanitize output, not just input
- Fail securely - reject invalid input by default`, [
    { type: 'test', description: 'Empty input submission', priority: 'high' },
    { type: 'test', description: 'Maximum length boundary (exact limit, limit+1)', priority: 'high' },
    { type: 'test', description: 'Minimum length boundary (exact limit, limit-1)', priority: 'high' },
    { type: 'test', description: 'Special characters: < > " \' & / \\ | ; : @ # $ % ^ * ( ) { } [ ]', priority: 'medium' },
    { type: 'test', description: 'Unicode characters: emojis, RTL text, zero-width characters', priority: 'medium' },
    { type: 'test', description: 'SQL injection patterns: \' OR \'1\'=\'1, "; DROP TABLE--, 1; SELECT * FROM', priority: 'critical' },
    { type: 'test', description: 'XSS patterns: <script>alert(1)</script>, javascript:alert(1)', priority: 'critical' },
    { type: 'test', description: 'Whitespace handling: leading/trailing spaces, multiple spaces, tabs, newlines', priority: 'medium' },
    { type: 'test', description: 'NULL byte injection: %00, \\0', priority: 'high' },
    { type: 'test', description: 'Very long input (10,000+ characters for buffer overflow)', priority: 'medium' }
  ]),

  '1.2': createSection('1.2', 'Numeric Input Validation', ['input', 'validation', 'numeric', 'numbers'], `
Numeric inputs require special handling for boundaries, formats, and type coercion.`, [
    { type: 'test', description: 'Zero value handling', priority: 'high' },
    { type: 'test', description: 'Negative numbers (if applicable)', priority: 'high' },
    { type: 'test', description: 'Decimal precision limits', priority: 'medium' },
    { type: 'test', description: 'Integer overflow: MAX_INT + 1, MIN_INT - 1', priority: 'high' },
    { type: 'test', description: 'Scientific notation: 1e10, 1E-5', priority: 'low' },
    { type: 'test', description: 'Non-numeric input in numeric fields', priority: 'high' },
    { type: 'test', description: 'Leading zeros: 007, 0123', priority: 'low' },
    { type: 'test', description: 'Currency formats: $100, 100.00, 100,00', priority: 'medium' },
    { type: 'test', description: 'Percentage values: 0%, 100%, 101%, -1%', priority: 'medium' }
  ]),

  '1.3': createSection('1.3', 'Date and Time Validation', ['input', 'validation', 'date', 'time'], `
Date/time inputs have numerous edge cases around formats, boundaries, and timezone handling.`, [
    { type: 'test', description: 'Invalid dates: 31/02/2024, 00/00/0000, 32/13/2024', priority: 'high' },
    { type: 'test', description: 'Leap year: 29/02/2024 (valid), 29/02/2023 (invalid)', priority: 'high' },
    { type: 'test', description: 'Timezone handling: UTC, local, DST transitions', priority: 'medium' },
    { type: 'test', description: 'Date boundaries: 01/01/1970, 31/12/9999', priority: 'medium' },
    { type: 'test', description: 'Future dates (if restricted)', priority: 'medium' },
    { type: 'test', description: 'Past dates (if restricted)', priority: 'medium' },
    { type: 'test', description: 'Date format variations: DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD', priority: 'medium' },
    { type: 'test', description: 'Time boundaries: 00:00:00, 23:59:59, 24:00:00', priority: 'medium' }
  ]),

  '1.4': createSection('1.4', 'File Upload Validation', ['input', 'validation', 'file', 'upload', 'security'], `
File uploads are a common attack vector requiring thorough validation.`, [
    { type: 'test', description: 'File type validation (extension AND MIME type)', priority: 'critical' },
    { type: 'test', description: 'Maximum file size boundary', priority: 'high' },
    { type: 'test', description: 'Zero-byte files', priority: 'medium' },
    { type: 'test', description: 'Corrupted files', priority: 'medium' },
    { type: 'test', description: 'Double extension attacks: file.jpg.exe', priority: 'critical' },
    { type: 'test', description: 'MIME type spoofing', priority: 'critical' },
    { type: 'test', description: 'Path traversal in filename: ../../../etc/passwd', priority: 'critical' },
    { type: 'test', description: 'Special characters in filename', priority: 'medium' },
    { type: 'test', description: 'Very long filenames (255+ characters)', priority: 'low' },
    { type: 'test', description: 'Archive extraction attacks (zip bombs)', priority: 'high' }
  ]),

  '1.5': createSection('1.5', 'Dropdown and Select Validation', ['input', 'validation', 'dropdown', 'select'], `
Dropdown/select inputs can be tampered with via browser dev tools.`, [
    { type: 'test', description: 'Unselected/default option submission', priority: 'high' },
    { type: 'test', description: 'Invalid option injection (modify DOM to add options)', priority: 'high' },
    { type: 'test', description: 'Multiple selection limits', priority: 'medium' },
    { type: 'test', description: 'Disabled option bypass', priority: 'medium' },
    { type: 'test', description: 'Empty value submission', priority: 'medium' },
    { type: 'test', description: 'Value tampering via developer tools', priority: 'high' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 2: SECURITY TESTING
  // ─────────────────────────────────────────────────────────────────
  '2.1': createSection('2.1', 'SQL Injection', ['security', 'sql', 'injection', 'database'], `
SQL injection remains one of the most dangerous vulnerabilities.
Attack Vectors:
- Classic: ' OR '1'='1' --
- Union-based: ' UNION SELECT username, password FROM users --
- Blind Boolean: ' AND 1=1 -- vs ' AND 1=2 --
- Time-based: '; WAITFOR DELAY '0:0:5' --
- Error-based: ' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)) --
- Second-order: stored payload executed later`, [
    { type: 'test', description: 'Classic SQL injection in all form inputs', priority: 'critical' },
    { type: 'test', description: 'SQL injection in URL parameters', priority: 'critical' },
    { type: 'test', description: 'SQL injection in HTTP headers (User-Agent, Referer, Cookie)', priority: 'high' },
    { type: 'test', description: 'SQL injection in JSON/XML body parameters', priority: 'critical' },
    { type: 'test', description: 'SQL injection in search functionality', priority: 'critical' },
    { type: 'test', description: 'SQL injection in sort/filter parameters', priority: 'high' }
  ]),

  '2.2': createSection('2.2', 'Cross-Site Scripting (XSS)', ['security', 'xss', 'scripting', 'injection'], `
XSS allows attackers to inject malicious scripts into pages viewed by other users.
Types:
- Reflected XSS: input immediately rendered
- Stored XSS: payload persisted and served to others
- DOM-based XSS: client-side script manipulation

Test Payloads:
- Basic: <script>alert('XSS')</script>
- Event handlers: <img src=x onerror=alert('XSS')>
- SVG: <svg onload=alert('XSS')>
- Encoded: %3Cscript%3Ealert('XSS')%3C/script%3E`, [
    { type: 'test', description: 'Reflected XSS in all input fields', priority: 'critical' },
    { type: 'test', description: 'Stored XSS in user-generated content', priority: 'critical' },
    { type: 'test', description: 'DOM-based XSS via URL fragments', priority: 'high' },
    { type: 'test', description: 'XSS via event handlers (onerror, onload, etc.)', priority: 'critical' },
    { type: 'test', description: 'XSS in file names during upload', priority: 'high' },
    { type: 'test', description: 'XSS through template injection', priority: 'high' }
  ]),

  '2.3': createSection('2.3', 'Cross-Site Request Forgery (CSRF)', ['security', 'csrf', 'forgery'], `
CSRF attacks trick users into performing unintended actions.`, [
    { type: 'test', description: 'Missing CSRF token', priority: 'critical' },
    { type: 'test', description: 'Invalid CSRF token', priority: 'critical' },
    { type: 'test', description: 'Token reuse across sessions', priority: 'high' },
    { type: 'test', description: 'Token in GET vs POST', priority: 'medium' },
    { type: 'test', description: 'Referer header validation bypass', priority: 'high' },
    { type: 'test', description: 'SameSite cookie attribute', priority: 'high' },
    { type: 'test', description: 'State-changing GET requests', priority: 'high' }
  ]),

  '2.4': createSection('2.4', 'Authentication Testing', ['security', 'authentication', 'login', 'password'], `
Authentication is the first line of defense for user accounts.`, [
    { type: 'test', description: 'Brute force protection (account lockout after N attempts)', priority: 'critical' },
    { type: 'test', description: 'Password complexity requirements', priority: 'high' },
    { type: 'test', description: 'Password reset flow vulnerabilities', priority: 'critical' },
    { type: 'test', description: 'Session fixation', priority: 'critical' },
    { type: 'test', description: 'Session timeout', priority: 'high' },
    { type: 'test', description: 'Concurrent session handling', priority: 'medium' },
    { type: 'test', description: 'Remember me functionality', priority: 'medium' },
    { type: 'test', description: 'OAuth/SSO integration security', priority: 'high' },
    { type: 'test', description: 'Default credentials', priority: 'critical' },
    { type: 'test', description: 'Username enumeration via timing/response differences', priority: 'high' }
  ]),

  '2.5': createSection('2.5', 'Authorization Testing', ['security', 'authorization', 'access', 'permissions'], `
Authorization ensures users can only access what they're allowed to.`, [
    { type: 'test', description: 'Horizontal privilege escalation (access other users\' data)', priority: 'critical' },
    { type: 'test', description: 'Vertical privilege escalation (access admin functions)', priority: 'critical' },
    { type: 'test', description: 'IDOR (Insecure Direct Object Reference)', priority: 'critical' },
    { type: 'test', description: 'Missing function-level access control', priority: 'critical' },
    { type: 'test', description: 'API endpoint authorization', priority: 'critical' },
    { type: 'test', description: 'File access authorization', priority: 'high' },
    { type: 'test', description: 'Admin panel access', priority: 'critical' }
  ]),

  '2.6': createSection('2.6', 'Sensitive Data Exposure', ['security', 'data', 'privacy', 'exposure'], `
Sensitive data must be protected in transit and at rest.`, [
    { type: 'test', description: 'Passwords in URL parameters', priority: 'critical' },
    { type: 'test', description: 'Sensitive data in browser history', priority: 'high' },
    { type: 'test', description: 'Autocomplete on sensitive fields', priority: 'medium' },
    { type: 'test', description: 'Data in error messages', priority: 'high' },
    { type: 'test', description: 'Source code comments with secrets', priority: 'high' },
    { type: 'test', description: 'Unencrypted transmission (HTTP vs HTTPS)', priority: 'critical' },
    { type: 'test', description: 'Sensitive data in logs', priority: 'high' },
    { type: 'test', description: 'Cache-Control headers for sensitive pages', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 3: FUNCTIONAL TESTING
  // ─────────────────────────────────────────────────────────────────
  '3.1': createSection('3.1', 'Form Submission', ['functional', 'form', 'submit', 'validation'], `
Form submission is a core user interaction requiring thorough testing.`, [
    { type: 'test', description: 'Successful submission with valid data', priority: 'critical' },
    { type: 'test', description: 'Error handling with invalid data', priority: 'high' },
    { type: 'test', description: 'Form persistence after validation error', priority: 'high' },
    { type: 'test', description: 'Double-click submission prevention', priority: 'high' },
    { type: 'test', description: 'Back button behavior after submission', priority: 'medium' },
    { type: 'test', description: 'Refresh after submission (POST/Redirect/GET)', priority: 'medium' },
    { type: 'test', description: 'Required field validation', priority: 'high' },
    { type: 'test', description: 'Optional field handling', priority: 'medium' },
    { type: 'test', description: 'Field dependency logic', priority: 'medium' },
    { type: 'test', description: 'Conditional field display', priority: 'medium' }
  ]),

  '3.2': createSection('3.2', 'Navigation and Links', ['functional', 'navigation', 'links', 'routing'], `
Navigation testing ensures users can move through the application correctly.`, [
    { type: 'test', description: 'All links lead to correct destinations', priority: 'high' },
    { type: 'test', description: 'Broken link detection', priority: 'high' },
    { type: 'test', description: 'External links open in new tab', priority: 'medium' },
    { type: 'test', description: 'Anchor links scroll to correct position', priority: 'low' },
    { type: 'test', description: 'Breadcrumb accuracy', priority: 'medium' },
    { type: 'test', description: 'Menu state on current page', priority: 'medium' },
    { type: 'test', description: 'Deep linking functionality', priority: 'medium' },
    { type: 'test', description: 'URL parameter preservation', priority: 'medium' }
  ]),

  '3.3': createSection('3.3', 'Search Functionality', ['functional', 'search', 'filter', 'results'], `
Search is often a primary user task requiring comprehensive testing.`, [
    { type: 'test', description: 'Exact match search', priority: 'high' },
    { type: 'test', description: 'Partial match search', priority: 'high' },
    { type: 'test', description: 'Case insensitivity', priority: 'medium' },
    { type: 'test', description: 'Special character handling', priority: 'medium' },
    { type: 'test', description: 'No results messaging', priority: 'medium' },
    { type: 'test', description: 'Search result relevance', priority: 'high' },
    { type: 'test', description: 'Pagination of results', priority: 'medium' },
    { type: 'test', description: 'Sort functionality', priority: 'medium' },
    { type: 'test', description: 'Filter combinations', priority: 'medium' },
    { type: 'test', description: 'Search history/suggestions', priority: 'low' }
  ]),

  '3.4': createSection('3.4', 'Error Handling', ['functional', 'error', 'exception', 'graceful'], `
Proper error handling improves user experience and security.`, [
    { type: 'test', description: '404 page display and navigation', priority: 'high' },
    { type: 'test', description: '500 error graceful degradation', priority: 'high' },
    { type: 'test', description: 'Form validation error messages', priority: 'high' },
    { type: 'test', description: 'Network timeout handling', priority: 'medium' },
    { type: 'test', description: 'Session expiry handling', priority: 'high' },
    { type: 'test', description: 'Concurrent modification conflicts', priority: 'medium' },
    { type: 'test', description: 'Rate limiting response', priority: 'medium' },
    { type: 'test', description: 'Maintenance mode messaging', priority: 'low' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 4: UI/UX TESTING
  // ─────────────────────────────────────────────────────────────────
  '4.1': createSection('4.1', 'Visual Consistency', ['ui', 'ux', 'visual', 'design'], `
Visual consistency builds trust and usability.`, [
    { type: 'test', description: 'Font consistency across pages', priority: 'medium' },
    { type: 'test', description: 'Color scheme adherence', priority: 'medium' },
    { type: 'test', description: 'Spacing and alignment', priority: 'medium' },
    { type: 'test', description: 'Icon consistency', priority: 'low' },
    { type: 'test', description: 'Button styling uniformity', priority: 'medium' },
    { type: 'test', description: 'Form element styling', priority: 'medium' },
    { type: 'test', description: 'Loading state indicators', priority: 'high' },
    { type: 'test', description: 'Error state styling', priority: 'high' },
    { type: 'test', description: 'Success state styling', priority: 'high' }
  ]),

  '4.2': createSection('4.2', 'Responsive Design', ['ui', 'ux', 'responsive', 'mobile'], `
Applications must work across device sizes.`, [
    { type: 'test', description: 'Desktop viewports (1920x1080, 1440x900, 1366x768)', priority: 'high' },
    { type: 'test', description: 'Tablet viewports (768x1024, 1024x768)', priority: 'high' },
    { type: 'test', description: 'Mobile viewports (375x667, 390x844, 414x896)', priority: 'high' },
    { type: 'test', description: 'Orientation change handling', priority: 'medium' },
    { type: 'test', description: 'Touch target sizes (minimum 44x44px)', priority: 'high' },
    { type: 'test', description: 'Text readability on small screens', priority: 'high' },
    { type: 'test', description: 'Image scaling', priority: 'medium' },
    { type: 'test', description: 'Navigation adaptation', priority: 'high' },
    { type: 'test', description: 'Form usability on mobile', priority: 'high' }
  ]),

  '4.3': createSection('4.3', 'Accessibility (WCAG 2.1)', ['ui', 'ux', 'accessibility', 'wcag', 'a11y'], `
Accessibility ensures all users can use the application.`, [
    { type: 'test', description: 'Keyboard navigation (Tab order, Enter/Space activation)', priority: 'critical' },
    { type: 'test', description: 'Screen reader compatibility', priority: 'critical' },
    { type: 'test', description: 'Alt text for images', priority: 'high' },
    { type: 'test', description: 'Form labels and ARIA attributes', priority: 'high' },
    { type: 'test', description: 'Color contrast (4.5:1 for normal text)', priority: 'high' },
    { type: 'test', description: 'Focus indicators', priority: 'high' },
    { type: 'test', description: 'Skip navigation links', priority: 'medium' },
    { type: 'test', description: 'Heading hierarchy', priority: 'medium' },
    { type: 'test', description: 'Error identification without color alone', priority: 'high' },
    { type: 'test', description: 'Timeout warnings for timed actions', priority: 'medium' }
  ]),

  '4.4': createSection('4.4', 'User Feedback', ['ui', 'ux', 'feedback', 'loading'], `
Users need clear feedback for their actions.`, [
    { type: 'test', description: 'Loading indicators for async operations', priority: 'high' },
    { type: 'test', description: 'Progress bars for multi-step processes', priority: 'medium' },
    { type: 'test', description: 'Success/error toast messages', priority: 'high' },
    { type: 'test', description: 'Form submission confirmation', priority: 'high' },
    { type: 'test', description: 'Button state changes (hover, active, disabled)', priority: 'medium' },
    { type: 'test', description: 'Input validation feedback timing', priority: 'medium' },
    { type: 'test', description: 'Help text and tooltips', priority: 'low' },
    { type: 'test', description: 'Empty state messaging', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 5: PERFORMANCE TESTING
  // ─────────────────────────────────────────────────────────────────
  '5.1': createSection('5.1', 'Page Load Performance', ['performance', 'loading', 'speed', 'vitals'], `
Page load performance directly impacts user experience and SEO.`, [
    { type: 'test', description: 'Initial page load time (target: <3s)', priority: 'high' },
    { type: 'test', description: 'Time to First Byte (TTFB)', priority: 'medium' },
    { type: 'test', description: 'First Contentful Paint (FCP)', priority: 'high' },
    { type: 'test', description: 'Largest Contentful Paint (LCP) - target: <2.5s', priority: 'high' },
    { type: 'test', description: 'First Input Delay (FID) - target: <100ms', priority: 'high' },
    { type: 'test', description: 'Cumulative Layout Shift (CLS) - target: <0.1', priority: 'high' },
    { type: 'test', description: 'Resource loading (CSS, JS, images)', priority: 'medium' },
    { type: 'test', description: 'Third-party script impact', priority: 'medium' }
  ]),

  '5.2': createSection('5.2', 'API Response Times', ['performance', 'api', 'latency', 'timeout'], `
API performance affects overall application responsiveness.`, [
    { type: 'test', description: 'Average response time (<200ms for most endpoints)', priority: 'high' },
    { type: 'test', description: '95th percentile response time', priority: 'medium' },
    { type: 'test', description: 'Response time under load', priority: 'medium' },
    { type: 'test', description: 'Timeout handling', priority: 'high' },
    { type: 'test', description: 'Large payload handling', priority: 'medium' },
    { type: 'test', description: 'Pagination efficiency', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 6: EDGE CASES AND BOUNDARIES
  // ─────────────────────────────────────────────────────────────────
  '6.1': createSection('6.1', 'Data Boundaries', ['edge', 'boundary', 'limits', 'data'], `
Edge cases reveal issues at the boundaries of expected behavior.`, [
    { type: 'test', description: 'Empty data sets (no results, empty cart)', priority: 'high' },
    { type: 'test', description: 'Single item edge case', priority: 'medium' },
    { type: 'test', description: 'Maximum item limits', priority: 'high' },
    { type: 'test', description: 'Integer boundaries (0, -1, MAX_INT)', priority: 'high' },
    { type: 'test', description: 'String length limits', priority: 'medium' },
    { type: 'test', description: 'Array size limits', priority: 'medium' },
    { type: 'test', description: 'Pagination edge cases (first page, last page, page 0)', priority: 'medium' }
  ]),

  '6.2': createSection('6.2', 'Time-Based Edge Cases', ['edge', 'time', 'timeout', 'race'], `
Time-based issues are often intermittent and hard to reproduce.`, [
    { type: 'test', description: 'Midnight transitions (23:59:59 to 00:00:00)', priority: 'medium' },
    { type: 'test', description: 'Month/year boundaries', priority: 'medium' },
    { type: 'test', description: 'Leap year handling', priority: 'medium' },
    { type: 'test', description: 'Daylight Saving Time transitions', priority: 'low' },
    { type: 'test', description: 'Session timeout at exactly N minutes', priority: 'medium' },
    { type: 'test', description: 'Scheduled task execution timing', priority: 'low' },
    { type: 'test', description: 'Race conditions in concurrent updates', priority: 'high' }
  ]),

  '6.3': createSection('6.3', 'Network Edge Cases', ['edge', 'network', 'offline', 'timeout'], `
Network conditions vary widely in real-world usage.`, [
    { type: 'test', description: 'Slow network (3G simulation)', priority: 'medium' },
    { type: 'test', description: 'Offline mode behavior', priority: 'high' },
    { type: 'test', description: 'Network switching (WiFi to mobile)', priority: 'low' },
    { type: 'test', description: 'Request timeout handling', priority: 'high' },
    { type: 'test', description: 'Partial response handling', priority: 'medium' },
    { type: 'test', description: 'Connection drop during submission', priority: 'high' },
    { type: 'test', description: 'Retry mechanism testing', priority: 'medium' }
  ]),

  '6.4': createSection('6.4', 'Browser Edge Cases', ['edge', 'browser', 'session', 'tabs'], `
Browser-specific behaviors need testing.`, [
    { type: 'test', description: 'Back/Forward button behavior', priority: 'high' },
    { type: 'test', description: 'Multiple tabs with same session', priority: 'medium' },
    { type: 'test', description: 'Browser crash recovery', priority: 'low' },
    { type: 'test', description: 'LocalStorage/SessionStorage limits', priority: 'medium' },
    { type: 'test', description: 'Cookie size limits', priority: 'medium' },
    { type: 'test', description: 'JavaScript disabled', priority: 'low' },
    { type: 'test', description: 'Pop-up blocker interference', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 7: LOGIN PAGE SPECIFIC
  // ─────────────────────────────────────────────────────────────────
  '7.1': createSection('7.1', 'Email Validation', ['login', 'email', 'validation', 'format'], `
Email validation has many edge cases.`, [
    { type: 'test', description: 'Valid email formats: user@domain.com, user+tag@domain.co.uk', priority: 'high', testData: ['yali.test@company.com', 'test+filter@domain.co.uk'] },
    { type: 'test', description: 'Invalid emails: user@, @domain.com, user@.com', priority: 'high', testData: ['user@', '@domain.com', 'user@.com', 'user@domain..com'] },
    { type: 'test', description: 'Case insensitivity: User@Domain.COM should match', priority: 'medium' },
    { type: 'test', description: 'Maximum length (254 characters per RFC 5321)', priority: 'medium' },
    { type: 'test', description: 'Special characters: user.name@domain.com, user_name@domain.com', priority: 'medium' },
    { type: 'test', description: 'Multiple @ symbols', priority: 'high' },
    { type: 'test', description: 'Leading/trailing whitespace', priority: 'medium' },
    { type: 'test', description: 'SQL injection in email field', priority: 'critical', testData: ['\' OR \'1\'=\'1', '"; DROP TABLE users--'] },
    { type: 'test', description: 'XSS in email field', priority: 'critical', testData: ['<script>alert(1)</script>@test.com'] }
  ]),

  '7.2': createSection('7.2', 'Password Validation', ['login', 'password', 'validation', 'security'], `
Password handling is security-critical.`, [
    { type: 'test', description: 'Minimum length (typically 8+ characters)', priority: 'critical' },
    { type: 'test', description: 'Maximum length (some systems limit to 72/128 characters)', priority: 'high' },
    { type: 'test', description: 'Complexity requirements (uppercase, lowercase, number, special char)', priority: 'high' },
    { type: 'test', description: 'Common password rejection (password123, qwerty, admin)', priority: 'high', testData: ['password', '123456', 'qwerty', 'admin'] },
    { type: 'test', description: 'Breached password detection', priority: 'medium' },
    { type: 'test', description: 'Password visibility toggle', priority: 'medium' },
    { type: 'test', description: 'Copy/paste behavior', priority: 'low' },
    { type: 'test', description: 'Password manager compatibility', priority: 'medium' },
    { type: 'test', description: 'Character encoding (UTF-8 passwords)', priority: 'low' }
  ]),

  '7.3': createSection('7.3', 'Login Flow', ['login', 'authentication', 'session', 'flow'], `
The login flow is critical for user access.`, [
    { type: 'test', description: 'Successful login redirect', priority: 'critical' },
    { type: 'test', description: 'Failed login messaging (avoid username/password specific messages)', priority: 'high' },
    { type: 'test', description: 'Account lockout after failed attempts', priority: 'critical' },
    { type: 'test', description: 'CAPTCHA trigger after failed attempts', priority: 'high' },
    { type: 'test', description: 'Remember me functionality', priority: 'medium' },
    { type: 'test', description: 'Session creation security', priority: 'critical' },
    { type: 'test', description: 'Login from multiple devices', priority: 'medium' },
    { type: 'test', description: 'Forced logout from other sessions', priority: 'medium' },
    { type: 'test', description: 'Login audit logging', priority: 'medium' }
  ]),

  '7.4': createSection('7.4', 'Social Login', ['login', 'oauth', 'social', 'sso'], `
Social/OAuth login has unique considerations.`, [
    { type: 'test', description: 'OAuth flow completion', priority: 'high' },
    { type: 'test', description: 'OAuth error handling', priority: 'high' },
    { type: 'test', description: 'Account linking (existing email)', priority: 'medium' },
    { type: 'test', description: 'Missing permissions handling', priority: 'medium' },
    { type: 'test', description: 'Token refresh behavior', priority: 'medium' },
    { type: 'test', description: 'Logout from provider impact', priority: 'medium' },
    { type: 'test', description: 'Multiple providers for same account', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 8: CHECKOUT AND PAYMENT
  // ─────────────────────────────────────────────────────────────────
  '8.1': createSection('8.1', 'Cart Functionality', ['checkout', 'cart', 'ecommerce', 'shopping'], `
Cart functionality is critical for e-commerce.`, [
    { type: 'test', description: 'Add to cart', priority: 'critical' },
    { type: 'test', description: 'Update quantity', priority: 'high' },
    { type: 'test', description: 'Remove item', priority: 'high' },
    { type: 'test', description: 'Cart persistence (session, logged in)', priority: 'high' },
    { type: 'test', description: 'Stock validation', priority: 'critical' },
    { type: 'test', description: 'Price updates', priority: 'critical' },
    { type: 'test', description: 'Discount/coupon application', priority: 'high' },
    { type: 'test', description: 'Cart abandonment recovery', priority: 'medium' },
    { type: 'test', description: 'Maximum cart size', priority: 'medium' },
    { type: 'test', description: 'Out-of-stock handling during checkout', priority: 'critical' }
  ]),

  '8.2': createSection('8.2', 'Payment Processing', ['checkout', 'payment', 'transaction', 'pci'], `
Payment processing requires the highest testing rigor.`, [
    { type: 'test', description: 'Valid card acceptance', priority: 'critical', testData: ['4111111111111111', '5500000000000004'] },
    { type: 'test', description: 'Invalid card rejection', priority: 'critical' },
    { type: 'test', description: 'Expired card handling', priority: 'high' },
    { type: 'test', description: 'Insufficient funds', priority: 'high' },
    { type: 'test', description: '3D Secure flow', priority: 'high' },
    { type: 'test', description: 'Payment timeout handling', priority: 'critical' },
    { type: 'test', description: 'Double payment prevention', priority: 'critical' },
    { type: 'test', description: 'Refund flow', priority: 'high' },
    { type: 'test', description: 'Partial refund', priority: 'medium' },
    { type: 'test', description: 'Currency conversion', priority: 'medium' }
  ]),

  '8.3': createSection('8.3', 'Order Management', ['checkout', 'order', 'confirmation', 'status'], `
Order management affects customer satisfaction.`, [
    { type: 'test', description: 'Order confirmation display', priority: 'critical' },
    { type: 'test', description: 'Confirmation email delivery', priority: 'high' },
    { type: 'test', description: 'Order history accuracy', priority: 'high' },
    { type: 'test', description: 'Order status tracking', priority: 'medium' },
    { type: 'test', description: 'Order cancellation', priority: 'high' },
    { type: 'test', description: 'Order modification', priority: 'medium' },
    { type: 'test', description: 'Invoice generation', priority: 'medium' },
    { type: 'test', description: 'Receipt download', priority: 'medium' }
  ]),

  // ─────────────────────────────────────────────────────────────────
  // SECTION 9: API TESTING
  // ─────────────────────────────────────────────────────────────────
  '9.1': createSection('9.1', 'HTTP Methods', ['api', 'http', 'rest', 'methods'], `
Each HTTP method has specific semantics to test.`, [
    { type: 'test', description: 'GET: retrieval, caching, idempotency', priority: 'high' },
    { type: 'test', description: 'POST: creation, non-idempotency', priority: 'high' },
    { type: 'test', description: 'PUT: full update', priority: 'high' },
    { type: 'test', description: 'PATCH: partial update', priority: 'high' },
    { type: 'test', description: 'DELETE: removal, soft vs hard delete', priority: 'high' },
    { type: 'test', description: 'OPTIONS: CORS preflight', priority: 'medium' },
    { type: 'test', description: 'HEAD: header retrieval', priority: 'low' }
  ]),

  '9.2': createSection('9.2', 'Response Codes', ['api', 'http', 'status', 'error'], `
Proper status codes improve API usability.`, [
    { type: 'test', description: '200 OK: successful request', priority: 'high' },
    { type: 'test', description: '201 Created: resource created', priority: 'high' },
    { type: 'test', description: '204 No Content: successful, no body', priority: 'medium' },
    { type: 'test', description: '400 Bad Request: invalid input', priority: 'high' },
    { type: 'test', description: '401 Unauthorized: missing auth', priority: 'critical' },
    { type: 'test', description: '403 Forbidden: insufficient permissions', priority: 'critical' },
    { type: 'test', description: '404 Not Found: resource doesn\'t exist', priority: 'high' },
    { type: 'test', description: '409 Conflict: state conflict', priority: 'medium' },
    { type: 'test', description: '422 Unprocessable Entity: validation error', priority: 'high' },
    { type: 'test', description: '429 Too Many Requests: rate limited', priority: 'high' },
    { type: 'test', description: '500 Internal Server Error: server failure', priority: 'critical' },
    { type: 'test', description: '503 Service Unavailable: maintenance/overload', priority: 'high' }
  ]),

  '9.3': createSection('9.3', 'API Security', ['api', 'security', 'auth', 'token'], `
API security is critical for modern applications.`, [
    { type: 'test', description: 'Authentication token validation', priority: 'critical' },
    { type: 'test', description: 'Token expiration', priority: 'critical' },
    { type: 'test', description: 'Token refresh', priority: 'high' },
    { type: 'test', description: 'API key management', priority: 'high' },
    { type: 'test', description: 'Rate limiting', priority: 'high' },
    { type: 'test', description: 'Input sanitization', priority: 'critical' },
    { type: 'test', description: 'Output encoding', priority: 'high' },
    { type: 'test', description: 'CORS configuration', priority: 'high' },
    { type: 'test', description: 'Request signing (if applicable)', priority: 'medium' }
  ])
}

/**
 * Get all sections
 */
function getAllSections() {
  return Object.values(QA_BRAIN)
}

/**
 * Get section by ID
 */
function getSection(id) {
  return QA_BRAIN[id]
}

/**
 * Search sections by tag
 */
function searchByTag(tag) {
  return getAllSections().filter(section =>
    section.tags.some(t => t.toLowerCase().includes(tag.toLowerCase()))
  )
}

/**
 * Search sections by keyword
 */
function searchByKeyword(keyword) {
  const lowerKeyword = keyword.toLowerCase()
  return getAllSections().filter(section =>
    section.title.toLowerCase().includes(lowerKeyword) ||
    section.content.toLowerCase().includes(lowerKeyword) ||
    section.tags.some(t => t.toLowerCase().includes(lowerKeyword))
  )
}

/**
 * Get sections relevant to a page type
 */
function getForPageType(pageType) {
  const pageTypeMap = {
    login: ['7.1', '7.2', '7.3', '7.4', '2.4', '2.5', '2.6', '3.1'],
    signup: ['7.1', '7.2', '3.1', '4.3', '2.4', '1.1'],
    checkout: ['8.1', '8.2', '8.3', '2.6', '3.1', '4.3'],
    payment: ['8.2', '2.6', '3.1', '9.3'],
    form: ['1.1', '1.2', '1.3', '1.4', '1.5', '3.1', '4.3'],
    search: ['3.3', '2.1', '2.2', '4.1'],
    settings: ['3.1', '2.4', '2.5', '4.3'],
    dashboard: ['4.1', '4.2', '5.1', '6.4'],
    profile: ['2.5', '2.6', '3.1', '4.3']
  }

  const sectionIds = pageTypeMap[pageType.toLowerCase()] || ['1.1', '2.2', '3.1', '4.3']
  return sectionIds.map(id => QA_BRAIN[id]).filter(Boolean)
}

/**
 * Get tests from sections
 */
function getTestsFromSections(sections) {
  const tests = []
  for (const section of sections) {
    for (const test of section.tests) {
      tests.push({
        ...test,
        source: section.cite(),
        sectionId: section.id,
        sectionTitle: section.title
      })
    }
  }
  return tests
}

/**
 * Format sections for LLM prompt
 */
function formatForPrompt(sections, maxChunks = 5) {
  if (!sections || sections.length === 0) {
    return 'No specific knowledge found. Use general QA principles.'
  }

  const lines = ['## Relevant Knowledge from QA Brain:\n']

  for (let i = 0; i < Math.min(sections.length, maxChunks); i++) {
    const section = sections[i]
    lines.push(`### [${i + 1}] ${section.title}`)
    lines.push(`Tags: ${section.tags.join(', ')}`)
    lines.push(`Content:\n${section.content.slice(0, 500)}...`)
    lines.push('')
  }

  return lines.join('\n')
}

/**
 * Get edge case test data for a field type
 */
function getEdgeCases(fieldType) {
  const edgeCases = {
    email: [
      'test@example.com',
      'a@b.co',
      'very.long.email.address.that.goes.on.and.on@subdomain.example.com',
      'test+filter@example.com',
      'user.name@example.com',
      '\' OR \'1\'=\'1',
      '<script>alert(1)</script>@test.com',
      'user@',
      '@example.com',
      'user@.com',
      'user@@example.com'
    ],
    password: [
      'short',
      'a'.repeat(100),
      'password123',
      'P@ssw0rd!',
      '\' OR \'1\'=\'1',
      '<script>alert(1)</script>',
      '🔒🔐🔑',
      'null',
      '     '
    ],
    text: [
      '',
      ' ',
      'a'.repeat(10000),
      '\' OR \'1\'=\'1',
      '<script>alert(1)</script>',
      '../../../etc/passwd',
      '%00',
      '\\0',
      '<img src=x onerror=alert(1)>',
      '🎉🚀💡',
      'مرحبا',
      '你好'
    ],
    number: [
      0,
      -1,
      1.5,
      Number.MAX_SAFE_INTEGER,
      Number.MIN_SAFE_INTEGER,
      '1e10',
      'NaN',
      'Infinity',
      '007',
      '$100'
    ],
    date: [
      '2024-02-29',
      '2023-02-29',
      '1970-01-01',
      '9999-12-31',
      '2024-13-01',
      '2024-00-00',
      '32/13/2024'
    ]
  }

  return edgeCases[fieldType] || edgeCases.text
}

module.exports = {
  QA_BRAIN,
  createSection,
  getAllSections,
  getSection,
  searchByTag,
  searchByKeyword,
  getForPageType,
  getTestsFromSections,
  formatForPrompt,
  getEdgeCases
}
