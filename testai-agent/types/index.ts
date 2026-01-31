/**
 * TestAI Agent - Core Type Definitions
 *
 * This module defines all the types used across the TestAI agent system.
 * The architecture is designed to support multiple LLM providers and
 * generate comprehensive test cases that beat larger models.
 */

// ============================================================================
// LLM Provider Types
// ============================================================================

export type LLMProvider =
  | 'openai'
  | 'anthropic'
  | 'google'
  | 'deepseek'
  | 'together'
  | 'groq'
  | 'mistral'
  | 'minimax'
  | 'local';

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens: number;
  temperature: number;
  topP?: number;
  costPerInputToken: number;   // Cost per 1M tokens
  costPerOutputToken: number;  // Cost per 1M tokens
  contextWindow: number;       // Max context window size
  supportsVision: boolean;
  supportsTools: boolean;
  supportsStructuredOutput: boolean;
}

export interface ModelCapabilities {
  reasoning: number;      // 0-100 score
  codeGeneration: number;
  classification: number;
  edgeCaseDetection: number;
  securityAnalysis: number;
  speed: number;          // Tokens per second
  costEfficiency: number; // Quality per dollar
}

// ============================================================================
// Task Types - What the agent can do
// ============================================================================

export type TaskType =
  | 'classify_page'
  | 'classify_elements'
  | 'generate_test_cases'
  | 'generate_edge_cases'
  | 'security_analysis'
  | 'accessibility_audit'
  | 'api_contract_analysis'
  | 'visual_regression_analysis'
  | 'performance_analysis'
  | 'i18n_analysis'
  | 'summarize_context'
  | 'prioritize_tests';

export interface Task {
  id: string;
  type: TaskType;
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  input: TaskInput;
  context?: ContextChunk[];
  constraints?: TaskConstraints;
}

export interface TaskInput {
  specification?: FeatureSpecification;
  pageContext?: PageContext;
  elements?: ElementInfo[];
  previousResults?: TestResult[];
  customPrompt?: string;
}

export interface TaskConstraints {
  maxTokens?: number;
  maxCost?: number;
  preferredProvider?: LLMProvider;
  requireStructuredOutput?: boolean;
  timeoutMs?: number;
}

// ============================================================================
// Feature Specification Types
// ============================================================================

export interface FeatureSpecification {
  id: string;
  name: string;
  type: SpecificationType;
  description: string;

  // Structured specification
  userStories?: UserStory[];
  acceptanceCriteria?: AcceptanceCriterion[];
  businessRules?: BusinessRule[];
  dataRequirements?: DataRequirement[];

  // Page/UI context
  pages?: PageSpecification[];
  components?: ComponentSpecification[];

  // Integration context
  apis?: APISpecification[];
  integrations?: IntegrationSpecification[];

  // Constraints
  securityRequirements?: SecurityRequirement[];
  performanceRequirements?: PerformanceRequirement[];
  accessibilityLevel?: 'WCAG-A' | 'WCAG-AA' | 'WCAG-AAA';

  // Metadata
  priority: 'critical' | 'high' | 'medium' | 'low';
  tags?: string[];
  createdAt: Date;
  updatedAt: Date;
}

export type SpecificationType =
  | 'login_flow'
  | 'signup_flow'
  | 'checkout_flow'
  | 'search_feature'
  | 'crud_operations'
  | 'dashboard'
  | 'settings_page'
  | 'integration'
  | 'api_endpoint'
  | 'notification_system'
  | 'payment_flow'
  | 'messaging'
  | 'file_upload'
  | 'reporting'
  | 'admin_panel'
  | 'custom';

export interface UserStory {
  id: string;
  asA: string;        // As a [role]
  iWant: string;      // I want [feature]
  soThat: string;     // So that [benefit]
  priority: number;
}

export interface AcceptanceCriterion {
  id: string;
  given: string;      // Given [precondition]
  when: string;       // When [action]
  then: string;       // Then [expected result]
  category: 'happy_path' | 'edge_case' | 'error_handling' | 'security' | 'performance';
}

export interface BusinessRule {
  id: string;
  name: string;
  description: string;
  condition: string;
  consequence: string;
  exceptions?: string[];
}

export interface DataRequirement {
  id: string;
  entityType: string;
  fields: FieldRequirement[];
  validations: ValidationRule[];
  relationships?: EntityRelationship[];
}

export interface FieldRequirement {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date' | 'email' | 'phone' | 'url' | 'file' | 'enum' | 'array' | 'object';
  required: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: string;
  enumValues?: string[];
  defaultValue?: any;
}

export interface ValidationRule {
  field: string;
  type: 'required' | 'format' | 'range' | 'unique' | 'custom' | 'dependency';
  message: string;
  rule: string;
}

export interface EntityRelationship {
  targetEntity: string;
  type: 'one-to-one' | 'one-to-many' | 'many-to-many';
  required: boolean;
}

// ============================================================================
// Page & Component Specifications
// ============================================================================

export interface PageSpecification {
  id: string;
  name: string;
  path: string;
  type: PageType;
  description: string;
  components: string[];          // Component IDs
  accessibleTo: string[];        // Role names
  preConditions?: string[];
  postConditions?: string[];
}

export type PageType =
  | 'login'
  | 'signup'
  | 'forgot_password'
  | 'reset_password'
  | 'mfa'
  | 'dashboard'
  | 'list'
  | 'detail'
  | 'create'
  | 'edit'
  | 'delete_confirm'
  | 'settings'
  | 'profile'
  | 'search'
  | 'checkout'
  | 'cart'
  | 'product'
  | 'admin'
  | 'error'
  | 'custom';

export interface ComponentSpecification {
  id: string;
  name: string;
  type: ComponentType;
  description: string;
  props?: PropSpecification[];
  events?: EventSpecification[];
  states?: StateSpecification[];
  children?: string[];
}

export type ComponentType =
  | 'form'
  | 'button'
  | 'input'
  | 'select'
  | 'checkbox'
  | 'radio'
  | 'table'
  | 'list'
  | 'card'
  | 'modal'
  | 'dropdown'
  | 'navigation'
  | 'tabs'
  | 'accordion'
  | 'carousel'
  | 'chart'
  | 'file_upload'
  | 'date_picker'
  | 'rich_text'
  | 'custom';

export interface PropSpecification {
  name: string;
  type: string;
  required: boolean;
  defaultValue?: any;
  description: string;
}

export interface EventSpecification {
  name: string;
  description: string;
  payload?: string;
}

export interface StateSpecification {
  name: string;
  initial: boolean;
  transitions: string[];
}

// ============================================================================
// API & Integration Specifications
// ============================================================================

export interface APISpecification {
  id: string;
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  endpoint: string;
  description: string;
  requestSchema?: JSONSchema;
  responseSchema?: JSONSchema;
  errorResponses?: ErrorResponse[];
  authentication?: 'none' | 'bearer' | 'api_key' | 'oauth' | 'session';
  rateLimit?: RateLimit;
}

export interface JSONSchema {
  type: 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null';
  properties?: Record<string, JSONSchema>;
  items?: JSONSchema;
  required?: string[];
  enum?: any[];
  format?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

export interface ErrorResponse {
  statusCode: number;
  description: string;
  schema?: JSONSchema;
}

export interface RateLimit {
  requests: number;
  period: 'second' | 'minute' | 'hour' | 'day';
}

export interface IntegrationSpecification {
  id: string;
  name: string;
  type: IntegrationType;
  description: string;
  webhooks?: WebhookSpecification[];
  oauth?: OAuthSpecification;
  apiEndpoints?: string[];
}

export type IntegrationType =
  | 'oauth'
  | 'webhook'
  | 'api'
  | 'email'
  | 'sms'
  | 'payment'
  | 'storage'
  | 'analytics'
  | 'search'
  | 'ai'
  | 'messaging'
  | 'calendar'
  | 'crm'
  | 'custom';

export interface WebhookSpecification {
  event: string;
  endpoint: string;
  payload: JSONSchema;
  retryPolicy?: RetryPolicy;
}

export interface OAuthSpecification {
  provider: string;
  scopes: string[];
  callbackUrl: string;
}

export interface RetryPolicy {
  maxRetries: number;
  backoffMultiplier: number;
  initialDelay: number;
}

// ============================================================================
// Security & Performance Requirements
// ============================================================================

export interface SecurityRequirement {
  id: string;
  type: SecurityType;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  controls: string[];
}

export type SecurityType =
  | 'authentication'
  | 'authorization'
  | 'input_validation'
  | 'xss_prevention'
  | 'csrf_prevention'
  | 'sql_injection'
  | 'rate_limiting'
  | 'encryption'
  | 'secure_headers'
  | 'data_privacy'
  | 'session_management'
  | 'api_security';

export interface PerformanceRequirement {
  id: string;
  metric: PerformanceMetric;
  target: number;
  unit: string;
  priority: 'required' | 'desired' | 'stretch';
}

export type PerformanceMetric =
  | 'page_load_time'
  | 'time_to_interactive'
  | 'first_contentful_paint'
  | 'largest_contentful_paint'
  | 'cumulative_layout_shift'
  | 'api_response_time'
  | 'throughput'
  | 'memory_usage'
  | 'concurrent_users';

// ============================================================================
// Page Context Types (Runtime)
// ============================================================================

export interface PageContext {
  url: string;
  title: string;
  type: PageType;
  dom?: string;               // Compressed DOM
  elements: ElementInfo[];
  forms: FormInfo[];
  metadata: PageMetadata;
}

export interface ElementInfo {
  mmid: string;               // Unique identifier
  tag: string;
  type: ElementType;
  text: string;
  attributes: Record<string, string>;
  selector: string;
  boundingBox?: BoundingBox;
  isVisible: boolean;
  isEnabled: boolean;
  testId?: string;
}

export type ElementType =
  | 'navigation'
  | 'read'
  | 'write'
  | 'click'
  | 'submit'
  | 'destructive'
  | 'payment'
  | 'toggle'
  | 'select'
  | 'file_input'
  | 'unknown';

export interface FormInfo {
  id: string;
  name?: string;
  action?: string;
  method?: string;
  fields: FormField[];
  submitButton?: ElementInfo;
}

export interface FormField {
  mmid: string;
  name: string;
  type: string;
  label?: string;
  placeholder?: string;
  required: boolean;
  validation?: string;
}

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface PageMetadata {
  loadTime: number;
  elementCount: number;
  formCount: number;
  linkCount: number;
  hasErrors: boolean;
  locale?: string;
  viewport?: Viewport;
}

export interface Viewport {
  width: number;
  height: number;
  deviceScaleFactor: number;
}

// ============================================================================
// Test Case Types
// ============================================================================

export interface TestCase {
  id: string;
  name: string;
  description: string;
  category: TestCategory;
  priority: 'P0' | 'P1' | 'P2' | 'P3';

  // Test structure
  preconditions: string[];
  steps: TestStep[];
  expectedResults: ExpectedResult[];
  postconditions?: string[];

  // Metadata
  tags: string[];
  estimatedDuration: number;   // milliseconds
  dataRequirements?: TestDataRequirement[];

  // Source tracking
  sourceSpecification?: string;
  sourceRule?: string;
  generatedBy: string;         // Model that generated this
  confidence: number;          // 0-1 confidence score
}

export type TestCategory =
  | 'smoke'
  | 'happy_path'
  | 'edge_case'
  | 'boundary'
  | 'negative'
  | 'security'
  | 'performance'
  | 'accessibility'
  | 'visual'
  | 'integration'
  | 'e2e'
  | 'regression';

export interface TestStep {
  order: number;
  action: TestAction;
  target?: string;            // Element selector or identifier
  value?: any;                // Input value
  waitFor?: WaitCondition;
  screenshot?: boolean;
  description: string;
}

export type TestAction =
  | 'navigate'
  | 'click'
  | 'double_click'
  | 'right_click'
  | 'fill'
  | 'clear'
  | 'select'
  | 'check'
  | 'uncheck'
  | 'upload'
  | 'drag_drop'
  | 'hover'
  | 'scroll'
  | 'press'
  | 'wait'
  | 'assert'
  | 'screenshot'
  | 'api_call'
  | 'mock'
  | 'custom';

export interface WaitCondition {
  type: 'visible' | 'hidden' | 'enabled' | 'disabled' | 'text' | 'url' | 'network_idle' | 'timeout';
  target?: string;
  value?: string;
  timeout?: number;
}

export interface ExpectedResult {
  type: 'visible' | 'hidden' | 'text' | 'value' | 'attribute' | 'url' | 'api_response' | 'console' | 'custom';
  target?: string;
  expected: any;
  comparison: 'equals' | 'contains' | 'matches' | 'greater_than' | 'less_than' | 'exists' | 'not_exists';
}

export interface TestDataRequirement {
  name: string;
  type: string;
  generator: 'faker' | 'static' | 'factory' | 'api';
  constraints?: Record<string, any>;
}

// ============================================================================
// Test Result Types
// ============================================================================

export interface TestResult {
  testId: string;
  status: 'passed' | 'failed' | 'skipped' | 'flaky';
  duration: number;
  startTime: Date;
  endTime: Date;

  // Results
  stepResults: StepResult[];
  assertions: AssertionResult[];

  // Artifacts
  screenshots?: string[];
  video?: string;
  trace?: string;
  logs?: string[];

  // Analysis
  errorMessage?: string;
  errorStack?: string;
  failureCategory?: FailureCategory;
  retryCount?: number;
}

export interface StepResult {
  stepOrder: number;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  screenshot?: string;
}

export interface AssertionResult {
  description: string;
  passed: boolean;
  expected: any;
  actual: any;
  error?: string;
}

export type FailureCategory =
  | 'element_not_found'
  | 'timeout'
  | 'assertion_failed'
  | 'network_error'
  | 'auth_error'
  | 'data_error'
  | 'flaky'
  | 'unknown';

// ============================================================================
// Context Management Types
// ============================================================================

export interface ContextChunk {
  id: string;
  type: ContextType;
  content: string;
  tokenCount: number;
  relevanceScore: number;
  source: string;
  metadata: Record<string, any>;
}

export type ContextType =
  | 'qa_rule'
  | 'qa_example'
  | 'qa_checklist'
  | 'page_context'
  | 'element_context'
  | 'specification'
  | 'previous_result'
  | 'memory'
  | 'custom';

export interface ContextBudget {
  maxTokens: number;
  reservedForOutput: number;
  reservedForSystem: number;
  availableForContext: number;
}

export interface ContextStrategy {
  name: string;
  prioritize: ContextType[];
  compress: boolean;
  summarize: boolean;
  maxChunksPerType: Record<ContextType, number>;
}

// ============================================================================
// Agent Memory Types
// ============================================================================

export interface AgentMemory {
  sessionId: string;
  startTime: Date;

  // Structural memory
  visitedUrls: Set<string>;
  discoveredPages: Map<string, PageContext>;
  pageGraph: NavigationEdge[];

  // Entity memory
  discoveredEntities: Map<string, EntityMemory>;
  apiContracts: Map<string, JSONSchema>;

  // Operational memory
  actionHistory: ActionMemory[];
  testResults: TestResult[];
  errors: ErrorMemory[];

  // Learned patterns
  selectorPreferences: Map<string, string>;
  timingPatterns: Map<string, number>;
  flakeHistory: Map<string, boolean[]>;
}

export interface NavigationEdge {
  from: string;
  to: string;
  trigger: string;
  timestamp: Date;
}

export interface EntityMemory {
  id: string;
  type: string;
  data: Record<string, any>;
  discoveredAt: Date;
  lastSeen: Date;
}

export interface ActionMemory {
  id: string;
  timestamp: Date;
  url: string;
  action: string;
  target: string;
  result: 'success' | 'failure' | 'partial';
  causedNavigation: boolean;
  duration: number;
}

export interface ErrorMemory {
  id: string;
  timestamp: Date;
  url: string;
  action: string;
  error: string;
  category: FailureCategory;
  recoverable: boolean;
  recoveryAttempted: boolean;
}

// ============================================================================
// Report Types
// ============================================================================

export interface TestReport {
  id: string;
  name: string;
  generatedAt: Date;

  // Summary
  summary: ReportSummary;

  // Details
  specifications: FeatureSpecification[];
  testCases: TestCase[];
  results: TestResult[];

  // Analysis
  coverage: CoverageReport;
  riskAssessment: RiskAssessment;
  recommendations: Recommendation[];
}

export interface ReportSummary {
  totalTests: number;
  passed: number;
  failed: number;
  skipped: number;
  flaky: number;
  duration: number;
  coverage: number;
}

export interface CoverageReport {
  byCategory: Record<TestCategory, CategoryCoverage>;
  byPage: Record<string, PageCoverage>;
  byRequirement: Record<string, RequirementCoverage>;
}

export interface CategoryCoverage {
  total: number;
  covered: number;
  percentage: number;
}

export interface PageCoverage {
  elements: number;
  coveredElements: number;
  forms: number;
  coveredForms: number;
}

export interface RequirementCoverage {
  requirementId: string;
  testIds: string[];
  status: 'covered' | 'partial' | 'not_covered';
}

export interface RiskAssessment {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  risks: Risk[];
}

export interface Risk {
  id: string;
  area: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  mitigation: string;
}

export interface Recommendation {
  id: string;
  type: 'test_gap' | 'security' | 'performance' | 'accessibility' | 'improvement';
  description: string;
  priority: 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
}
