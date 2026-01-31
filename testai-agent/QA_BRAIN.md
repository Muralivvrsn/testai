# TestAI Agent - QA Knowledge Base (Brain)

> This knowledge base provides the foundation for generating exhaustive, cited test cases.
> Every section has a unique ID for precise citation tracking.

---

## 1. Input Validation

Input validation is the first line of defense against malformed data, security attacks, and user errors.

### Core Principles
- Validate on client AND server (client for UX, server for security)
- Use allowlists over denylists where possible
- Sanitize output, not just input
- Fail securely - reject invalid input by default

## 1.1 Text Field Validation

**Required Tests:**
- Empty input submission
- Maximum length boundary (exact limit, limit+1)
- Minimum length boundary (exact limit, limit-1)
- Special characters: < > " ' & / \ | ; : @ # $ % ^ * ( ) { } [ ]
- Unicode characters: emojis, RTL text, zero-width characters
- SQL injection patterns: ' OR '1'='1, "; DROP TABLE--, 1; SELECT * FROM
- XSS patterns: <script>alert(1)</script>, javascript:alert(1), <img onerror=alert(1)>
- Whitespace handling: leading/trailing spaces, multiple spaces, tabs, newlines
- NULL byte injection: %00, \0
- Very long input (10,000+ characters for buffer overflow)

## 1.2 Numeric Input Validation

**Required Tests:**
- Zero value
- Negative numbers (if applicable)
- Decimal precision limits
- Integer overflow: MAX_INT + 1, MIN_INT - 1
- Scientific notation: 1e10, 1E-5
- Non-numeric input in numeric fields
- Leading zeros: 007, 0123
- Currency formats: $100, 100.00, 100,00
- Percentage values: 0%, 100%, 101%, -1%

## 1.3 Date and Time Validation

**Required Tests:**
- Invalid dates: 31/02/2024, 00/00/0000, 32/13/2024
- Leap year: 29/02/2024 (valid), 29/02/2023 (invalid)
- Timezone handling: UTC, local, DST transitions
- Date boundaries: 01/01/1970, 31/12/9999
- Future dates (if restricted)
- Past dates (if restricted)
- Date format variations: DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD
- Time boundaries: 00:00:00, 23:59:59, 24:00:00
- 12-hour vs 24-hour format

## 1.4 File Upload Validation

**Required Tests:**
- File type validation (extension AND MIME type)
- Maximum file size boundary
- Zero-byte files
- Corrupted files
- Double extension attacks: file.jpg.exe
- MIME type spoofing
- Path traversal in filename: ../../../etc/passwd
- Special characters in filename
- Very long filenames (255+ characters)
- Multiple file upload limits
- Archive extraction attacks (zip bombs)

## 1.5 Dropdown and Select Validation

**Required Tests:**
- Unselected/default option submission
- Invalid option injection (modify DOM to add options)
- Multiple selection limits
- Disabled option bypass
- Empty value submission
- Value tampering via developer tools

---

## 2. Security Testing

Security testing identifies vulnerabilities before malicious actors can exploit them.

## 2.1 SQL Injection

**Attack Vectors:**
- Classic: ' OR '1'='1' --
- Union-based: ' UNION SELECT username, password FROM users --
- Blind Boolean: ' AND 1=1 -- vs ' AND 1=2 --
- Time-based: '; WAITFOR DELAY '0:0:5' --
- Error-based: ' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)) --
- Second-order: stored payload executed later

**Test Points:**
- All form inputs
- URL parameters
- HTTP headers (User-Agent, Referer, Cookie)
- JSON/XML body parameters
- Search functionality
- Sort/filter parameters

## 2.2 Cross-Site Scripting (XSS)

**Types:**
- Reflected XSS: input immediately rendered
- Stored XSS: payload persisted and served to others
- DOM-based XSS: client-side script manipulation

**Test Payloads:**
- Basic: <script>alert('XSS')</script>
- Event handlers: <img src=x onerror=alert('XSS')>
- SVG: <svg onload=alert('XSS')>
- Encoded: %3Cscript%3Ealert('XSS')%3C/script%3E
- Polyglot: jaVasCript:/*-/*'/*\'/*"/**/(/* */oNcLiCk=alert() )//
- Template injection: {{constructor.constructor('alert(1)')()}}

## 2.3 Cross-Site Request Forgery (CSRF)

**Required Tests:**
- Missing CSRF token
- Invalid CSRF token
- Token reuse across sessions
- Token in GET vs POST
- Referer header validation bypass
- SameSite cookie attribute
- State-changing GET requests

## 2.4 Authentication Testing

**Required Tests:**
- Brute force protection (account lockout after N attempts)
- Password complexity requirements
- Password reset flow vulnerabilities
- Session fixation
- Session timeout
- Concurrent session handling
- Remember me functionality
- OAuth/SSO integration security
- Default credentials
- Username enumeration via timing/response differences

## 2.5 Authorization Testing

**Required Tests:**
- Horizontal privilege escalation (access other users' data)
- Vertical privilege escalation (access admin functions)
- IDOR (Insecure Direct Object Reference)
- Missing function-level access control
- API endpoint authorization
- File access authorization
- Admin panel access

## 2.6 Sensitive Data Exposure

**Required Tests:**
- Passwords in URL parameters
- Sensitive data in browser history
- Autocomplete on sensitive fields
- Data in error messages
- Source code comments with secrets
- Unencrypted transmission (HTTP vs HTTPS)
- Sensitive data in logs
- Cache-Control headers for sensitive pages

---

## 3. Functional Testing

Functional testing verifies the application behaves according to requirements.

## 3.1 Form Submission

**Required Tests:**
- Successful submission with valid data
- Error handling with invalid data
- Form persistence after validation error
- Double-click submission prevention
- Back button behavior after submission
- Refresh after submission (POST/Redirect/GET)
- Required field validation
- Optional field handling
- Field dependency logic
- Conditional field display

## 3.2 Navigation and Links

**Required Tests:**
- All links lead to correct destinations
- Broken link detection
- External links open in new tab
- Anchor links scroll to correct position
- Breadcrumb accuracy
- Menu state on current page
- Deep linking functionality
- URL parameter preservation

## 3.3 Search Functionality

**Required Tests:**
- Exact match search
- Partial match search
- Case insensitivity
- Special character handling
- No results messaging
- Search result relevance
- Pagination of results
- Sort functionality
- Filter combinations
- Search history/suggestions

## 3.4 Error Handling

**Required Tests:**
- 404 page display and navigation
- 500 error graceful degradation
- Form validation error messages
- Network timeout handling
- Session expiry handling
- Concurrent modification conflicts
- Rate limiting response
- Maintenance mode messaging

---

## 4. UI/UX Testing

UI/UX testing ensures the application is usable and accessible.

## 4.1 Visual Consistency

**Required Tests:**
- Font consistency across pages
- Color scheme adherence
- Spacing and alignment
- Icon consistency
- Button styling uniformity
- Form element styling
- Loading state indicators
- Error state styling
- Success state styling

## 4.2 Responsive Design

**Required Tests:**
- Desktop (1920x1080, 1440x900, 1366x768)
- Tablet (768x1024, 1024x768)
- Mobile (375x667, 390x844, 414x896)
- Orientation change handling
- Touch target sizes (minimum 44x44px)
- Text readability on small screens
- Image scaling
- Navigation adaptation
- Form usability on mobile

## 4.3 Accessibility (WCAG 2.1)

**Required Tests:**
- Keyboard navigation (Tab order, Enter/Space activation)
- Screen reader compatibility
- Alt text for images
- Form labels and ARIA attributes
- Color contrast (4.5:1 for normal text)
- Focus indicators
- Skip navigation links
- Heading hierarchy
- Error identification without color alone
- Timeout warnings for timed actions

## 4.4 User Feedback

**Required Tests:**
- Loading indicators for async operations
- Progress bars for multi-step processes
- Success/error toast messages
- Form submission confirmation
- Button state changes (hover, active, disabled)
- Input validation feedback timing
- Help text and tooltips
- Empty state messaging

---

## 5. Performance Testing

Performance testing ensures the application meets speed and scalability requirements.

## 5.1 Page Load Performance

**Required Tests:**
- Initial page load time (target: <3s)
- Time to First Byte (TTFB)
- First Contentful Paint (FCP)
- Largest Contentful Paint (LCP) - target: <2.5s
- First Input Delay (FID) - target: <100ms
- Cumulative Layout Shift (CLS) - target: <0.1
- Resource loading (CSS, JS, images)
- Third-party script impact

## 5.2 API Response Times

**Required Tests:**
- Average response time (<200ms for most endpoints)
- 95th percentile response time
- Response time under load
- Timeout handling
- Large payload handling
- Pagination efficiency

## 5.3 Stress Testing

**Required Tests:**
- Concurrent user simulation
- Spike traffic handling
- Sustained load behavior
- Memory leak detection
- Database connection pooling
- Cache effectiveness
- CDN performance
- Failover behavior

---

## 6. Edge Cases and Boundary Testing

Edge cases reveal issues at the boundaries of expected behavior.

## 6.1 Data Boundaries

**Required Tests:**
- Empty data sets (no results, empty cart)
- Single item edge case
- Maximum item limits
- Integer boundaries (0, -1, MAX_INT)
- String length limits
- Array size limits
- Pagination edge cases (first page, last page, page 0, negative page)

## 6.2 Time-Based Edge Cases

**Required Tests:**
- Midnight transitions (23:59:59 to 00:00:00)
- Month/year boundaries
- Leap year handling
- Daylight Saving Time transitions
- Session timeout at exactly N minutes
- Scheduled task execution timing
- Race conditions in concurrent updates

## 6.3 Network Edge Cases

**Required Tests:**
- Slow network (3G simulation)
- Offline mode behavior
- Network switching (WiFi to mobile)
- Request timeout handling
- Partial response handling
- Connection drop during submission
- Retry mechanism testing

## 6.4 Browser Edge Cases

**Required Tests:**
- Back/Forward button behavior
- Multiple tabs with same session
- Browser crash recovery
- LocalStorage/SessionStorage limits
- Cookie size limits
- JavaScript disabled
- Pop-up blocker interference

---

## 7. Login Page Specific

Login functionality requires comprehensive security and usability testing.

## 7.1 Email Validation

**Required Tests:**
- Valid email formats: user@domain.com, user+tag@domain.co.uk
- Invalid emails: user@, @domain.com, user@.com, user@domain, user@domain..com
- Case insensitivity: User@Domain.COM should match user@domain.com
- Maximum length (254 characters per RFC 5321)
- Unicode/IDN emails: user@muenchen.de
- Special characters: user.name@domain.com, user_name@domain.com
- Multiple @ symbols
- Leading/trailing whitespace
- SQL injection in email field
- XSS in email field

## 7.2 Password Validation

**Required Tests:**
- Minimum length (typically 8+ characters)
- Maximum length (some systems limit to 72/128 characters)
- Complexity requirements (uppercase, lowercase, number, special char)
- Common password rejection (password123, qwerty, admin)
- Breached password detection
- Password visibility toggle
- Copy/paste behavior
- Password manager compatibility
- Character encoding (UTF-8 passwords)

## 7.3 Login Flow

**Required Tests:**
- Successful login redirect
- Failed login messaging (avoid username/password specific messages)
- Account lockout after failed attempts
- CAPTCHA trigger after failed attempts
- Remember me functionality
- Session creation security
- Login from multiple devices
- Forced logout from other sessions
- Login audit logging

## 7.4 Social Login

**Required Tests:**
- OAuth flow completion
- OAuth error handling
- Account linking (existing email)
- Missing permissions handling
- Token refresh behavior
- Logout from provider impact
- Multiple providers for same account

---

## 8. Checkout and Payment

Payment flows require the highest level of testing rigor due to financial impact.

## 8.1 Cart Functionality

**Required Tests:**
- Add to cart
- Update quantity
- Remove item
- Cart persistence (session, logged in)
- Stock validation
- Price updates
- Discount/coupon application
- Cart abandonment recovery
- Maximum cart size
- Out-of-stock handling during checkout

## 8.2 Payment Processing

**Required Tests:**
- Valid card acceptance
- Invalid card rejection
- Expired card handling
- Insufficient funds
- 3D Secure flow
- Payment timeout handling
- Double payment prevention
- Refund flow
- Partial refund
- Currency conversion

## 8.3 Order Management

**Required Tests:**
- Order confirmation display
- Confirmation email delivery
- Order history accuracy
- Order status tracking
- Order cancellation
- Order modification
- Invoice generation
- Receipt download

## 8.4 Shipping and Address

**Required Tests:**
- Address validation
- International address formats
- Shipping option selection
- Shipping cost calculation
- Delivery date estimation
- Multiple shipping addresses
- Billing vs shipping address
- Address autocomplete

---

## 9. API Testing

API testing ensures backend services function correctly independently of the UI.

## 9.1 HTTP Methods

**Required Tests:**
- GET: retrieval, caching, idempotency
- POST: creation, non-idempotency
- PUT: full update
- PATCH: partial update
- DELETE: removal, soft vs hard delete
- OPTIONS: CORS preflight
- HEAD: header retrieval

## 9.2 Response Codes

**Required Tests:**
- 200 OK: successful request
- 201 Created: resource created
- 204 No Content: successful, no body
- 400 Bad Request: invalid input
- 401 Unauthorized: missing auth
- 403 Forbidden: insufficient permissions
- 404 Not Found: resource doesn't exist
- 409 Conflict: state conflict
- 422 Unprocessable Entity: validation error
- 429 Too Many Requests: rate limited
- 500 Internal Server Error: server failure
- 503 Service Unavailable: maintenance/overload

## 9.3 Data Formats

**Required Tests:**
- JSON parsing/serialization
- XML support (if applicable)
- Content-Type header validation
- Accept header handling
- Character encoding (UTF-8)
- Large payload handling
- Empty body handling
- Malformed body handling

## 9.4 API Security

**Required Tests:**
- Authentication token validation
- Token expiration
- Token refresh
- API key management
- Rate limiting
- Input sanitization
- Output encoding
- CORS configuration
- Request signing (if applicable)

---

## 10. Mobile Testing

Mobile testing covers device-specific behaviors and limitations.

## 10.1 Touch Interactions

**Required Tests:**
- Tap accuracy (44x44px minimum)
- Swipe gestures
- Pinch to zoom
- Long press actions
- Pull to refresh
- Scroll behavior
- Double tap handling
- Multi-touch gestures

## 10.2 Device Features

**Required Tests:**
- Camera integration
- GPS/location services
- Push notifications
- Biometric authentication
- Device orientation
- Accelerometer (if used)
- Offline data sync
- Background app behavior

## 10.3 Mobile-Specific UX

**Required Tests:**
- Keyboard behavior
- Autocorrect handling
- Form input zooming
- Fixed header/footer behavior
- Safe area insets (notch handling)
- Status bar integration
- Navigation gestures
- App switching behavior
- Memory management

---

## 11. Testing Priorities by Risk Level

## 11.1 Critical (Must Test)
- Authentication and authorization
- Payment processing
- Sensitive data handling
- Security vulnerabilities (XSS, SQL Injection, CSRF)
- Core business functionality

## 11.2 High (Should Test)
- Form validation
- Error handling
- Data integrity
- API reliability
- Performance under load

## 11.3 Medium (Nice to Test)
- UI consistency
- Accessibility
- Browser compatibility
- Edge cases
- Non-critical features

## 11.4 Low (If Time Permits)
- Minor UI issues
- Documentation accuracy
- Advanced features rarely used
- Cosmetic improvements

---

## 12. Test Case Generation Rules

## 12.1 Naming Convention
Format: TC-{CATEGORY}-{NUMBER}: {Description}
Example: TC-SEC-001: SQL injection in login email field

## 12.2 Required Elements
Every test case MUST include:
1. Unique ID
2. Category classification
3. Risk level assignment
4. Clear preconditions
5. Step-by-step instructions
6. Expected result
7. Source citation

## 12.3 Citation Format
Always cite the source section:
Source: Section {ID} - {Title}
Example: Source: Section 7.1 - Email Validation

---

End of QA Knowledge Base
Version: 1.0
Last Updated: 2025-01-29

---

## 13. Common Web Application Patterns

## 13.1 CRUD Operations

**Required Tests:**
- Create: Successful creation with valid data
- Create: Validation of required fields
- Create: Duplicate entry handling
- Read: Retrieve single item by ID
- Read: List with pagination
- Read: Filter and search functionality
- Read: Sorting in ascending/descending order
- Update: Successful update with valid data
- Update: Partial update (PATCH behavior)
- Update: Conflict handling (optimistic locking)
- Delete: Successful deletion
- Delete: Soft delete vs hard delete
- Delete: Cascade delete behavior
- Delete: Cannot delete referenced items

## 13.2 State Management

**Required Tests:**
- Application state persistence after page refresh
- State synchronization across tabs
- State recovery after network failure
- Undo/redo functionality
- Auto-save behavior
- Draft saving
- State compression for large data
- Memory leak prevention

## 13.3 Caching Behavior

**Required Tests:**
- Browser cache utilization
- Cache invalidation on data change
- Stale-while-revalidate patterns
- Cache headers (ETags, Last-Modified)
- Service Worker cache (if applicable)
- CDN cache behavior
- Cache bypass mechanisms
- Offline content availability

---

## 14. Internationalization (i18n)

## 14.1 Language Support

**Required Tests:**
- Language switching
- RTL (Right-to-Left) text display
- Character encoding (UTF-8, UTF-16)
- Font rendering for different scripts
- Date/time localization
- Number formatting (1,000 vs 1.000)
- Currency formatting
- Pluralization rules
- Gender-specific translations

## 14.2 Locale Handling

**Required Tests:**
- Browser language detection
- User preference storage
- Fallback language behavior
- URL-based locale (/en/, /de/, etc.)
- Cookie/session locale persistence
- API locale headers (Accept-Language)

---

## 15. Error Recovery and Resilience

## 15.1 Error States

**Required Tests:**
- Network failure handling
- Server error (5xx) recovery
- Timeout recovery
- Partial data load failure
- Retry mechanism with backoff
- Circuit breaker pattern
- Graceful degradation
- Error boundary containment

## 15.2 Data Integrity

**Required Tests:**
- Transaction atomicity
- Rollback on failure
- Data consistency after crash
- Concurrent modification handling
- Conflict resolution
- Version control/history
- Audit trail integrity

---

## 16. Real-time Features

## 16.1 WebSocket Testing

**Required Tests:**
- Connection establishment
- Reconnection after disconnect
- Message ordering
- Message acknowledgment
- Heartbeat/ping-pong
- Connection timeout
- Multiple simultaneous connections
- Message queue overflow

## 16.2 Push Notifications

**Required Tests:**
- Permission request handling
- Notification delivery
- Notification click behavior
- Badge/count updates
- Sound preferences
- Do Not Disturb mode
- Notification grouping
- Background vs foreground behavior

---

## 17. Data Export and Import

## 17.1 Export Functionality

**Required Tests:**
- CSV export with proper encoding
- Excel export formatting
- PDF generation quality
- JSON/XML data export
- Large dataset handling
- Progress indication
- Cancellation support
- File naming conventions

## 17.2 Import Functionality

**Required Tests:**
- File format validation
- Data mapping/transformation
- Duplicate handling
- Partial import on error
- Import progress tracking
- Rollback on failure
- Preview before import
- Size/row limits

---

## 18. Third-Party Integrations

## 18.1 OAuth/Social Login

**Required Tests:**
- Provider button functionality
- Authorization flow completion
- Token storage security
- Token refresh
- Scope handling
- Error handling (user cancel, provider error)
- Account linking
- Logout from provider

## 18.2 Payment Gateways

**Required Tests:**
- Card tokenization
- PCI compliance
- 3D Secure flow
- Webhook handling
- Refund processing
- Subscription management
- Currency conversion
- Tax calculation

## 18.3 Analytics Integration

**Required Tests:**
- Page view tracking
- Event tracking
- User identification
- Custom dimensions
- E-commerce tracking
- Cross-domain tracking
- Consent management
- Ad blocker handling

---

## 19. Accessibility Deep Dive

## 19.1 Screen Reader Testing

**Required Tests:**
- Landmark regions (header, main, nav, footer)
- Heading hierarchy (h1-h6)
- Link text clarity
- Form field labels
- Error announcement
- Live regions (aria-live)
- Table structure
- Image descriptions

## 19.2 Motor Accessibility

**Required Tests:**
- Target size (minimum 44x44px)
- Click/tap area spacing
- Drag and drop alternatives
- Time-based interaction alternatives
- Voice control compatibility
- Single pointer gestures
- Motion-based interaction alternatives

---

## 20. Performance Deep Dive

## 20.1 Core Web Vitals

**Required Tests:**
- LCP (Largest Contentful Paint) < 2.5s
- FID (First Input Delay) < 100ms
- CLS (Cumulative Layout Shift) < 0.1
- FCP (First Contentful Paint)
- TTFB (Time to First Byte)
- TTI (Time to Interactive)
- TBT (Total Blocking Time)

## 20.2 Resource Optimization

**Required Tests:**
- Image lazy loading
- Code splitting
- Tree shaking effectiveness
- Bundle size analysis
- Critical CSS extraction
- Font loading strategy
- Preload/prefetch usage
- CDN utilization

---

*End of Extended QA Knowledge Base*
*Sections 13-20 added for comprehensive coverage*
