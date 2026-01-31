/**
 * TestAI Agent - Specification Templates
 *
 * Pre-built templates for common feature types to help users
 * quickly create specifications for test generation.
 *
 * ★ Insight ─────────────────────────────────────
 * These templates are GOLD for users who don't know where to start.
 *
 * Each template includes:
 * - Common user stories for that feature type
 * - Standard acceptance criteria
 * - Typical data requirements
 * - Known security concerns
 *
 * Users can customize these templates for their specific needs.
 * ─────────────────────────────────────────────────
 */

import {
  FeatureSpecification,
  UserStory,
  AcceptanceCriterion,
  DataRequirement,
  SecurityRequirement,
  SpecificationType,
} from '../types';

/**
 * Template factory - creates a specification template for a given type
 */
export function createSpecificationTemplate(
  type: SpecificationType,
  customizations?: Partial<FeatureSpecification>
): FeatureSpecification {
  const base = SPECIFICATION_TEMPLATES[type] || SPECIFICATION_TEMPLATES.custom;
  const id = `spec_${Date.now()}_${Math.random().toString(36).substring(7)}`;

  return {
    ...base,
    id,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...customizations,
  };
}

/**
 * Pre-built templates for common feature types
 */
export const SPECIFICATION_TEMPLATES: Record<SpecificationType, Omit<FeatureSpecification, 'id' | 'createdAt' | 'updatedAt'>> = {
  // ============================================================================
  // LOGIN FLOW
  // ============================================================================
  login_flow: {
    name: 'User Login',
    type: 'login_flow',
    description: 'Allow existing users to authenticate and access their account',
    priority: 'critical',

    userStories: [
      {
        id: 'US_LOGIN_01',
        asA: 'registered user',
        iWant: 'to log in with my email and password',
        soThat: 'I can access my account',
        priority: 1,
      },
      {
        id: 'US_LOGIN_02',
        asA: 'user',
        iWant: 'to stay logged in if I choose "Remember Me"',
        soThat: 'I don\'t have to log in every time',
        priority: 2,
      },
      {
        id: 'US_LOGIN_03',
        asA: 'user who forgot my password',
        iWant: 'to reset my password via email',
        soThat: 'I can regain access to my account',
        priority: 1,
      },
      {
        id: 'US_LOGIN_04',
        asA: 'user with 2FA enabled',
        iWant: 'to verify my identity with a code',
        soThat: 'my account is more secure',
        priority: 2,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_LOGIN_01',
        given: 'I am on the login page',
        when: 'I enter valid credentials and click login',
        then: 'I am redirected to the dashboard',
        category: 'happy_path',
      },
      {
        id: 'AC_LOGIN_02',
        given: 'I am on the login page',
        when: 'I enter invalid credentials',
        then: 'I see an error message without revealing which field is wrong',
        category: 'error_handling',
      },
      {
        id: 'AC_LOGIN_03',
        given: 'I have failed login 5 times',
        when: 'I try to login again',
        then: 'my account is temporarily locked',
        category: 'security',
      },
      {
        id: 'AC_LOGIN_04',
        given: 'I am on the login page',
        when: 'I leave email or password empty',
        then: 'I see validation errors',
        category: 'edge_case',
      },
    ],

    dataRequirements: [
      {
        id: 'DR_LOGIN_01',
        entityType: 'LoginCredentials',
        fields: [
          { name: 'email', type: 'email', required: true },
          { name: 'password', type: 'string', required: true, minLength: 8 },
          { name: 'rememberMe', type: 'boolean', required: false, defaultValue: false },
        ],
        validations: [
          { field: 'email', type: 'format', message: 'Invalid email format', rule: 'RFC 5322' },
          { field: 'password', type: 'required', message: 'Password is required', rule: 'not empty' },
        ],
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_LOGIN_01',
        type: 'authentication',
        description: 'Implement rate limiting on login attempts',
        severity: 'high',
        controls: ['Max 5 attempts per 15 minutes', 'Progressive delays', 'CAPTCHA after 3 failures'],
      },
      {
        id: 'SEC_LOGIN_02',
        type: 'session_management',
        description: 'Use secure, HttpOnly cookies for session tokens',
        severity: 'critical',
        controls: ['HttpOnly flag', 'Secure flag', 'SameSite=Strict'],
      },
      {
        id: 'SEC_LOGIN_03',
        type: 'input_validation',
        description: 'Prevent timing attacks on user enumeration',
        severity: 'medium',
        controls: ['Same error message for wrong email and wrong password', 'Consistent response time'],
      },
    ],

    tags: ['auth', 'security', 'critical'],
  },

  // ============================================================================
  // SIGNUP FLOW
  // ============================================================================
  signup_flow: {
    name: 'User Registration',
    type: 'signup_flow',
    description: 'Allow new users to create an account',
    priority: 'critical',

    userStories: [
      {
        id: 'US_SIGNUP_01',
        asA: 'new visitor',
        iWant: 'to create an account with my email',
        soThat: 'I can use the application',
        priority: 1,
      },
      {
        id: 'US_SIGNUP_02',
        asA: 'new user',
        iWant: 'to verify my email address',
        soThat: 'I can confirm ownership',
        priority: 1,
      },
      {
        id: 'US_SIGNUP_03',
        asA: 'new visitor',
        iWant: 'to sign up with Google/GitHub',
        soThat: 'registration is faster',
        priority: 2,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_SIGNUP_01',
        given: 'I am on the signup page',
        when: 'I fill in all required fields correctly',
        then: 'my account is created and I receive a verification email',
        category: 'happy_path',
      },
      {
        id: 'AC_SIGNUP_02',
        given: 'I try to sign up',
        when: 'the email is already registered',
        then: 'I see an error (without revealing account existence in auth context)',
        category: 'edge_case',
      },
      {
        id: 'AC_SIGNUP_03',
        given: 'I am signing up',
        when: 'my password is too weak',
        then: 'I see specific feedback on requirements',
        category: 'error_handling',
      },
    ],

    dataRequirements: [
      {
        id: 'DR_SIGNUP_01',
        entityType: 'RegistrationForm',
        fields: [
          { name: 'email', type: 'email', required: true },
          { name: 'password', type: 'string', required: true, minLength: 8, maxLength: 128 },
          { name: 'confirmPassword', type: 'string', required: true },
          { name: 'firstName', type: 'string', required: true, minLength: 1, maxLength: 50 },
          { name: 'lastName', type: 'string', required: true, minLength: 1, maxLength: 50 },
          { name: 'acceptTerms', type: 'boolean', required: true },
        ],
        validations: [
          { field: 'email', type: 'unique', message: 'Email already registered', rule: 'check database' },
          { field: 'password', type: 'custom', message: 'Password too weak', rule: 'min 8 chars, 1 upper, 1 number, 1 special' },
          { field: 'confirmPassword', type: 'dependency', message: 'Passwords must match', rule: 'equals password' },
          { field: 'acceptTerms', type: 'required', message: 'You must accept terms', rule: 'must be true' },
        ],
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_SIGNUP_01',
        type: 'input_validation',
        description: 'Validate and sanitize all input fields',
        severity: 'high',
        controls: ['Server-side validation', 'XSS prevention', 'SQL injection prevention'],
      },
      {
        id: 'SEC_SIGNUP_02',
        type: 'authentication',
        description: 'Hash passwords with bcrypt (cost factor 12+)',
        severity: 'critical',
        controls: ['bcrypt with work factor 12', 'Never store plain text', 'Secure comparison'],
      },
    ],

    tags: ['auth', 'onboarding', 'critical'],
  },

  // ============================================================================
  // CHECKOUT FLOW
  // ============================================================================
  checkout_flow: {
    name: 'Checkout Process',
    type: 'checkout_flow',
    description: 'Allow users to complete purchase of items in their cart',
    priority: 'critical',

    userStories: [
      {
        id: 'US_CHECKOUT_01',
        asA: 'customer',
        iWant: 'to complete my purchase',
        soThat: 'I can receive my items',
        priority: 1,
      },
      {
        id: 'US_CHECKOUT_02',
        asA: 'customer',
        iWant: 'to enter my shipping address',
        soThat: 'items are delivered to the right place',
        priority: 1,
      },
      {
        id: 'US_CHECKOUT_03',
        asA: 'customer',
        iWant: 'to apply a discount code',
        soThat: 'I can save money',
        priority: 2,
      },
      {
        id: 'US_CHECKOUT_04',
        asA: 'customer',
        iWant: 'to pay with my credit card',
        soThat: 'the transaction is completed',
        priority: 1,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_CHECKOUT_01',
        given: 'I have items in my cart',
        when: 'I proceed to checkout and complete payment',
        then: 'my order is confirmed and I receive a confirmation email',
        category: 'happy_path',
      },
      {
        id: 'AC_CHECKOUT_02',
        given: 'I am at checkout',
        when: 'my payment is declined',
        then: 'I see an error and can try a different payment method',
        category: 'error_handling',
      },
      {
        id: 'AC_CHECKOUT_03',
        given: 'I am at checkout',
        when: 'an item in my cart goes out of stock',
        then: 'I am notified and can update my cart',
        category: 'edge_case',
      },
    ],

    dataRequirements: [
      {
        id: 'DR_CHECKOUT_01',
        entityType: 'ShippingAddress',
        fields: [
          { name: 'fullName', type: 'string', required: true, maxLength: 100 },
          { name: 'addressLine1', type: 'string', required: true, maxLength: 200 },
          { name: 'addressLine2', type: 'string', required: false, maxLength: 200 },
          { name: 'city', type: 'string', required: true, maxLength: 100 },
          { name: 'state', type: 'string', required: true },
          { name: 'postalCode', type: 'string', required: true, pattern: '^[0-9]{5}(-[0-9]{4})?$' },
          { name: 'country', type: 'string', required: true },
          { name: 'phone', type: 'phone', required: true },
        ],
        validations: [
          { field: 'postalCode', type: 'format', message: 'Invalid postal code', rule: 'Match country format' },
          { field: 'phone', type: 'format', message: 'Invalid phone number', rule: 'E.164 format' },
        ],
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_CHECKOUT_01',
        type: 'data_privacy',
        description: 'Never store full credit card numbers',
        severity: 'critical',
        controls: ['Use tokenization', 'PCI compliance', 'Encrypted transmission'],
      },
      {
        id: 'SEC_CHECKOUT_02',
        type: 'business_logic',
        description: 'Prevent price manipulation',
        severity: 'critical',
        controls: ['Server-side price calculation', 'Validate cart state', 'Audit logging'],
      },
    ],

    performanceRequirements: [
      {
        id: 'PERF_CHECKOUT_01',
        metric: 'page_load_time',
        target: 2000,
        unit: 'ms',
        priority: 'required',
      },
    ],

    tags: ['ecommerce', 'payment', 'critical'],
  },

  // ============================================================================
  // SEARCH FEATURE
  // ============================================================================
  search_feature: {
    name: 'Search Functionality',
    type: 'search_feature',
    description: 'Allow users to search and find content',
    priority: 'high',

    userStories: [
      {
        id: 'US_SEARCH_01',
        asA: 'user',
        iWant: 'to search for content by keywords',
        soThat: 'I can find what I need',
        priority: 1,
      },
      {
        id: 'US_SEARCH_02',
        asA: 'user',
        iWant: 'to filter search results',
        soThat: 'I can narrow down options',
        priority: 2,
      },
      {
        id: 'US_SEARCH_03',
        asA: 'user',
        iWant: 'to see search suggestions',
        soThat: 'I can find things faster',
        priority: 3,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_SEARCH_01',
        given: 'I am on the search page',
        when: 'I enter a search query',
        then: 'I see relevant results',
        category: 'happy_path',
      },
      {
        id: 'AC_SEARCH_02',
        given: 'I search for something',
        when: 'no results match',
        then: 'I see a helpful empty state with suggestions',
        category: 'edge_case',
      },
      {
        id: 'AC_SEARCH_03',
        given: 'I search for content',
        when: 'the query contains special characters',
        then: 'the search handles it gracefully',
        category: 'edge_case',
      },
    ],

    tags: ['search', 'ux'],
  },

  // ============================================================================
  // CRUD OPERATIONS
  // ============================================================================
  crud_operations: {
    name: 'Resource Management',
    type: 'crud_operations',
    description: 'Create, Read, Update, Delete operations for a resource',
    priority: 'high',

    userStories: [
      {
        id: 'US_CRUD_01',
        asA: 'user',
        iWant: 'to create new items',
        soThat: 'I can add content',
        priority: 1,
      },
      {
        id: 'US_CRUD_02',
        asA: 'user',
        iWant: 'to view item details',
        soThat: 'I can see all information',
        priority: 1,
      },
      {
        id: 'US_CRUD_03',
        asA: 'user',
        iWant: 'to edit existing items',
        soThat: 'I can update information',
        priority: 1,
      },
      {
        id: 'US_CRUD_04',
        asA: 'user',
        iWant: 'to delete items',
        soThat: 'I can remove unwanted content',
        priority: 2,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_CRUD_01',
        given: 'I am on the create page',
        when: 'I fill in required fields and submit',
        then: 'the item is created and I see confirmation',
        category: 'happy_path',
      },
      {
        id: 'AC_CRUD_02',
        given: 'I am editing an item',
        when: 'another user deletes it',
        then: 'I am notified of the conflict',
        category: 'edge_case',
      },
      {
        id: 'AC_CRUD_03',
        given: 'I delete an item',
        when: 'I confirm the deletion',
        then: 'the item is removed and I can undo within 5 seconds',
        category: 'happy_path',
      },
    ],

    tags: ['crud', 'forms'],
  },

  // ============================================================================
  // DASHBOARD
  // ============================================================================
  dashboard: {
    name: 'Dashboard',
    type: 'dashboard',
    description: 'Main dashboard showing overview and key metrics',
    priority: 'high',

    userStories: [
      {
        id: 'US_DASH_01',
        asA: 'user',
        iWant: 'to see key metrics at a glance',
        soThat: 'I understand my current status',
        priority: 1,
      },
      {
        id: 'US_DASH_02',
        asA: 'user',
        iWant: 'to customize my dashboard widgets',
        soThat: 'I see the most relevant information',
        priority: 3,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_DASH_01',
        given: 'I log in',
        when: 'I land on the dashboard',
        then: 'I see all widgets with current data',
        category: 'happy_path',
      },
      {
        id: 'AC_DASH_02',
        given: 'data is loading',
        when: 'I view the dashboard',
        then: 'I see loading states for each widget',
        category: 'edge_case',
      },
    ],

    performanceRequirements: [
      {
        id: 'PERF_DASH_01',
        metric: 'time_to_interactive',
        target: 3000,
        unit: 'ms',
        priority: 'required',
      },
    ],

    tags: ['dashboard', 'analytics'],
  },

  // ============================================================================
  // SETTINGS PAGE
  // ============================================================================
  settings_page: {
    name: 'User Settings',
    type: 'settings_page',
    description: 'Allow users to manage their preferences',
    priority: 'medium',

    userStories: [
      {
        id: 'US_SETTINGS_01',
        asA: 'user',
        iWant: 'to update my profile information',
        soThat: 'my account is accurate',
        priority: 1,
      },
      {
        id: 'US_SETTINGS_02',
        asA: 'user',
        iWant: 'to change my password',
        soThat: 'I can maintain security',
        priority: 1,
      },
      {
        id: 'US_SETTINGS_03',
        asA: 'user',
        iWant: 'to manage notification preferences',
        soThat: 'I control what alerts I receive',
        priority: 2,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_SETTINGS_01',
        given: 'I am on settings page',
        when: 'I make changes and save',
        then: 'changes are saved and I see confirmation',
        category: 'happy_path',
      },
      {
        id: 'AC_SETTINGS_02',
        given: 'I have unsaved changes',
        when: 'I try to navigate away',
        then: 'I am warned about unsaved changes',
        category: 'edge_case',
      },
    ],

    tags: ['settings', 'profile'],
  },

  // ============================================================================
  // INTEGRATION
  // ============================================================================
  integration: {
    name: 'Third-Party Integration',
    type: 'integration',
    description: 'Integration with external service',
    priority: 'medium',

    userStories: [
      {
        id: 'US_INT_01',
        asA: 'user',
        iWant: 'to connect my account to external service',
        soThat: 'I can sync data',
        priority: 1,
      },
      {
        id: 'US_INT_02',
        asA: 'user',
        iWant: 'to disconnect integration',
        soThat: 'I can revoke access',
        priority: 2,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_INT_01',
        given: 'I click connect',
        when: 'I complete OAuth flow',
        then: 'the integration is active',
        category: 'happy_path',
      },
      {
        id: 'AC_INT_02',
        given: 'OAuth fails',
        when: 'I return to app',
        then: 'I see error with retry option',
        category: 'error_handling',
      },
    ],

    tags: ['integration', 'oauth'],
  },

  // ============================================================================
  // API ENDPOINT
  // ============================================================================
  api_endpoint: {
    name: 'API Endpoint',
    type: 'api_endpoint',
    description: 'RESTful API endpoint',
    priority: 'high',

    userStories: [
      {
        id: 'US_API_01',
        asA: 'developer',
        iWant: 'to access data via API',
        soThat: 'I can build integrations',
        priority: 1,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_API_01',
        given: 'valid API request',
        when: 'endpoint is called',
        then: 'correct data is returned',
        category: 'happy_path',
      },
      {
        id: 'AC_API_02',
        given: 'invalid request',
        when: 'endpoint is called',
        then: '4xx error with helpful message',
        category: 'error_handling',
      },
    ],

    tags: ['api', 'integration'],
  },

  // ============================================================================
  // NOTIFICATION SYSTEM
  // ============================================================================
  notification_system: {
    name: 'Notifications',
    type: 'notification_system',
    description: 'System for sending and displaying notifications',
    priority: 'medium',

    userStories: [
      {
        id: 'US_NOTIF_01',
        asA: 'user',
        iWant: 'to receive notifications about important events',
        soThat: 'I stay informed',
        priority: 1,
      },
      {
        id: 'US_NOTIF_02',
        asA: 'user',
        iWant: 'to mark notifications as read',
        soThat: 'I can track what I have seen',
        priority: 2,
      },
    ],

    tags: ['notifications', 'realtime'],
  },

  // ============================================================================
  // PAYMENT FLOW
  // ============================================================================
  payment_flow: {
    name: 'Payment Processing',
    type: 'payment_flow',
    description: 'Process payments securely',
    priority: 'critical',

    userStories: [
      {
        id: 'US_PAY_01',
        asA: 'customer',
        iWant: 'to pay securely',
        soThat: 'my transaction is safe',
        priority: 1,
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_PAY_01',
        type: 'data_privacy',
        description: 'PCI-DSS compliance required',
        severity: 'critical',
        controls: ['Tokenization', 'Encryption', 'Access controls'],
      },
    ],

    tags: ['payment', 'security', 'critical'],
  },

  // ============================================================================
  // MESSAGING
  // ============================================================================
  messaging: {
    name: 'Messaging System',
    type: 'messaging',
    description: 'Direct messaging between users',
    priority: 'medium',

    userStories: [
      {
        id: 'US_MSG_01',
        asA: 'user',
        iWant: 'to send messages to other users',
        soThat: 'I can communicate',
        priority: 1,
      },
    ],

    tags: ['messaging', 'realtime'],
  },

  // ============================================================================
  // FILE UPLOAD
  // ============================================================================
  file_upload: {
    name: 'File Upload',
    type: 'file_upload',
    description: 'Upload and manage files',
    priority: 'medium',

    userStories: [
      {
        id: 'US_FILE_01',
        asA: 'user',
        iWant: 'to upload files',
        soThat: 'I can share content',
        priority: 1,
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_FILE_01',
        type: 'input_validation',
        description: 'Validate file types and scan for malware',
        severity: 'high',
        controls: ['MIME type validation', 'File size limits', 'Antivirus scan'],
      },
    ],

    tags: ['upload', 'files'],
  },

  // ============================================================================
  // REPORTING
  // ============================================================================
  reporting: {
    name: 'Reports',
    type: 'reporting',
    description: 'Generate and view reports',
    priority: 'medium',

    userStories: [
      {
        id: 'US_REPORT_01',
        asA: 'user',
        iWant: 'to generate reports',
        soThat: 'I can analyze data',
        priority: 1,
      },
    ],

    tags: ['reports', 'analytics'],
  },

  // ============================================================================
  // ADMIN PANEL
  // ============================================================================
  admin_panel: {
    name: 'Admin Panel',
    type: 'admin_panel',
    description: 'Administrative functions',
    priority: 'high',

    userStories: [
      {
        id: 'US_ADMIN_01',
        asA: 'admin',
        iWant: 'to manage users',
        soThat: 'I can control access',
        priority: 1,
      },
    ],

    securityRequirements: [
      {
        id: 'SEC_ADMIN_01',
        type: 'authorization',
        description: 'Role-based access control',
        severity: 'critical',
        controls: ['Admin role verification', 'Audit logging', 'Session management'],
      },
    ],

    tags: ['admin', 'security'],
  },

  // ============================================================================
  // CUSTOM
  // ============================================================================
  custom: {
    name: 'Custom Feature',
    type: 'custom',
    description: 'Custom feature specification',
    priority: 'medium',

    userStories: [],
    acceptanceCriteria: [],

    tags: ['custom'],
  },
};

/**
 * Get all available template types
 */
export function getAvailableTemplates(): SpecificationType[] {
  return Object.keys(SPECIFICATION_TEMPLATES) as SpecificationType[];
}

/**
 * Get template description
 */
export function getTemplateDescription(type: SpecificationType): string {
  return SPECIFICATION_TEMPLATES[type]?.description || '';
}
