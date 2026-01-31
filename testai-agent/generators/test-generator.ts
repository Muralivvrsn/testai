/**
 * TestAI Agent - Test Case Generator
 *
 * The core engine that generates comprehensive test cases from specifications.
 *
 * ★ Insight ─────────────────────────────────────
 * This is where the MAGIC happens. The test generator:
 *
 * 1. Takes a feature specification (login flow, checkout, etc.)
 * 2. Retrieves relevant QA rules from the knowledge base
 * 3. Builds optimized context within token limits
 * 4. Routes to the best model for the task
 * 5. Generates structured test cases
 * 6. Validates and enhances the output
 *
 * The architecture beats larger models because:
 * - Specialized prompts for each task
 * - Relevant context only (no noise)
 * - Smart model routing (cheap for simple, expensive for complex)
 * - Structured output validation
 * ─────────────────────────────────────────────────
 */

import {
  TestCase,
  TestStep,
  ExpectedResult,
  FeatureSpecification,
  PageContext,
  TaskType,
  TestCategory,
} from '../types';
import { BaseLLMProvider, CompletionOptions, LLMMessage } from '../providers/base';
import { getSmartRouter, getProviderForTask } from '../providers';
import { ContextManager, BuiltContext } from '../context/manager';
import { BaseKnowledgeBase } from '../brain/knowledge-base';
import { getSystemPrompt, getFeaturePrompt, getPageTypeHints } from '../prompts/system';

/**
 * Options for test generation
 */
export interface GenerationOptions {
  specification: FeatureSpecification;
  pageContext?: PageContext;
  previousResults?: any[];
  customContext?: string;
  categories?: TestCategory[];
  maxTestCases?: number;
  preferredProvider?: string;
  includeEdgeCases?: boolean;
  includeSecurityTests?: boolean;
  includeAccessibilityTests?: boolean;
}

/**
 * Result from test generation
 */
export interface GenerationResult {
  testCases: TestCase[];
  coverage: {
    happyPaths: number;
    edgeCases: number;
    negativeCases: number;
    securityTests: number;
    accessibilityTests: number;
    total: number;
  };
  metadata: {
    model: string;
    tokensUsed: number;
    cost: number;
    duration: number;
  };
}

/**
 * Test Case Generator
 */
export class TestCaseGenerator {
  private knowledgeBase: BaseKnowledgeBase;
  private contextManager: ContextManager;

  constructor(knowledgeBase: BaseKnowledgeBase) {
    this.knowledgeBase = knowledgeBase;
    this.contextManager = new ContextManager(knowledgeBase);
  }

  /**
   * Generate comprehensive test cases for a feature specification
   */
  async generate(options: GenerationOptions): Promise<GenerationResult> {
    const startTime = Date.now();
    const allTestCases: TestCase[] = [];
    let totalTokens = 0;
    let totalCost = 0;
    let modelUsed = '';

    // 1. Generate main test cases
    const mainResult = await this.generateMainTestCases(options);
    allTestCases.push(...mainResult.testCases);
    totalTokens += mainResult.tokens;
    totalCost += mainResult.cost;
    modelUsed = mainResult.model;

    // 2. Generate edge cases if requested
    if (options.includeEdgeCases !== false) {
      const edgeCaseResult = await this.generateEdgeCases(options);
      allTestCases.push(...edgeCaseResult.testCases);
      totalTokens += edgeCaseResult.tokens;
      totalCost += edgeCaseResult.cost;
    }

    // 3. Generate security tests if requested
    if (options.includeSecurityTests) {
      const securityResult = await this.generateSecurityTests(options);
      allTestCases.push(...securityResult.testCases);
      totalTokens += securityResult.tokens;
      totalCost += securityResult.cost;
    }

    // 4. Generate accessibility tests if requested
    if (options.includeAccessibilityTests) {
      const a11yResult = await this.generateAccessibilityTests(options);
      allTestCases.push(...a11yResult.testCases);
      totalTokens += a11yResult.tokens;
      totalCost += a11yResult.cost;
    }

    // 5. Deduplicate and validate
    const validatedTestCases = this.validateAndDeduplicate(allTestCases);

    // 6. Apply max limit if specified
    const finalTestCases = options.maxTestCases
      ? validatedTestCases.slice(0, options.maxTestCases)
      : validatedTestCases;

    // 7. Calculate coverage
    const coverage = this.calculateCoverage(finalTestCases);

    return {
      testCases: finalTestCases,
      coverage,
      metadata: {
        model: modelUsed,
        tokensUsed: totalTokens,
        cost: totalCost,
        duration: Date.now() - startTime,
      },
    };
  }

  /**
   * Generate main test cases (happy path, edge cases, negative)
   */
  private async generateMainTestCases(options: GenerationOptions): Promise<{
    testCases: TestCase[];
    tokens: number;
    cost: number;
    model: string;
  }> {
    // Get the best provider for test generation
    const provider = await getProviderForTask('generate_test_cases');

    // Build context
    const context = await this.contextManager.buildContext({
      task: 'generate_test_cases',
      query: this.buildQuery(options.specification),
      pageContext: options.pageContext,
      specification: options.specification,
      previousResults: options.previousResults,
      maxTokens: provider.getAvailableContext(2000),
    });

    // Build the prompt
    const messages = this.buildMessages(
      'generate_test_cases',
      options.specification,
      context
    );

    // Call the LLM
    const response = await provider.complete({
      messages,
      maxTokens: 4000,
      temperature: 0.2,
      responseFormat: { type: 'json_object' },
    });

    // Parse response
    const testCases = this.parseTestCasesResponse(
      response.structuredOutput || response.content,
      options.specification
    );

    return {
      testCases,
      tokens: response.usage.totalTokens,
      cost: response.usage.estimatedCost,
      model: provider.getConfig().model,
    };
  }

  /**
   * Generate edge case tests
   */
  private async generateEdgeCases(options: GenerationOptions): Promise<{
    testCases: TestCase[];
    tokens: number;
    cost: number;
  }> {
    const provider = await getProviderForTask('generate_edge_cases');

    const context = await this.contextManager.buildContext({
      task: 'generate_edge_cases',
      query: `Edge cases for: ${options.specification.name}`,
      specification: options.specification,
      maxTokens: provider.getAvailableContext(2000),
    });

    const messages = this.buildMessages(
      'generate_edge_cases',
      options.specification,
      context
    );

    const response = await provider.complete({
      messages,
      maxTokens: 3000,
      temperature: 0.3,
      responseFormat: { type: 'json_object' },
    });

    const edgeCases = this.parseEdgeCasesResponse(
      response.structuredOutput || response.content,
      options.specification
    );

    return {
      testCases: edgeCases,
      tokens: response.usage.totalTokens,
      cost: response.usage.estimatedCost,
    };
  }

  /**
   * Generate security tests
   */
  private async generateSecurityTests(options: GenerationOptions): Promise<{
    testCases: TestCase[];
    tokens: number;
    cost: number;
  }> {
    const provider = await getProviderForTask('security_analysis');

    const context = await this.contextManager.buildContext({
      task: 'security_analysis',
      query: `Security analysis for: ${options.specification.name}`,
      specification: options.specification,
      maxTokens: provider.getAvailableContext(2000),
    });

    const messages = this.buildMessages(
      'security_analysis',
      options.specification,
      context
    );

    const response = await provider.complete({
      messages,
      maxTokens: 3000,
      temperature: 0.2,
      responseFormat: { type: 'json_object' },
    });

    const securityTests = this.parseSecurityResponse(
      response.structuredOutput || response.content,
      options.specification
    );

    return {
      testCases: securityTests,
      tokens: response.usage.totalTokens,
      cost: response.usage.estimatedCost,
    };
  }

  /**
   * Generate accessibility tests
   */
  private async generateAccessibilityTests(options: GenerationOptions): Promise<{
    testCases: TestCase[];
    tokens: number;
    cost: number;
  }> {
    const provider = await getProviderForTask('accessibility_audit');

    const context = await this.contextManager.buildContext({
      task: 'accessibility_audit',
      query: `Accessibility audit for: ${options.specification.name}`,
      specification: options.specification,
      pageContext: options.pageContext,
      maxTokens: provider.getAvailableContext(2000),
    });

    const messages = this.buildMessages(
      'accessibility_audit',
      options.specification,
      context
    );

    const response = await provider.complete({
      messages,
      maxTokens: 3000,
      temperature: 0.2,
      responseFormat: { type: 'json_object' },
    });

    const a11yTests = this.parseAccessibilityResponse(
      response.structuredOutput || response.content,
      options.specification
    );

    return {
      testCases: a11yTests,
      tokens: response.usage.totalTokens,
      cost: response.usage.estimatedCost,
    };
  }

  // =========================================================================
  // Helper Methods
  // =========================================================================

  private buildQuery(spec: FeatureSpecification): string {
    const parts = [
      spec.name,
      spec.type,
      spec.description,
      ...(spec.userStories?.map((s) => s.iWant) || []),
      ...(spec.acceptanceCriteria?.map((c) => c.when + ' ' + c.then) || []),
    ];
    return parts.join(' ');
  }

  private buildMessages(
    task: TaskType,
    spec: FeatureSpecification,
    context: BuiltContext
  ): LLMMessage[] {
    const systemPrompt = getSystemPrompt(task);
    const featurePrompt = getFeaturePrompt(spec.type);
    const formattedContext = this.contextManager.formatContext(context);

    const userPrompt = `${featurePrompt}

## Feature Specification

Name: ${spec.name}
Type: ${spec.type}
Description: ${spec.description}

${spec.userStories ? `### User Stories
${spec.userStories.map((s) => `- As a ${s.asA}, I want ${s.iWant}, so that ${s.soThat}`).join('\n')}` : ''}

${spec.acceptanceCriteria ? `### Acceptance Criteria
${spec.acceptanceCriteria.map((c) => `- Given ${c.given}, When ${c.when}, Then ${c.then}`).join('\n')}` : ''}

${spec.dataRequirements ? `### Data Requirements
${JSON.stringify(spec.dataRequirements, null, 2)}` : ''}

${spec.securityRequirements ? `### Security Requirements
${spec.securityRequirements.map((r) => `- [${r.severity}] ${r.type}: ${r.description}`).join('\n')}` : ''}

## QA Knowledge Base Context

${formattedContext}

---

Based on the above specification and QA knowledge, generate comprehensive test cases.`;

    return [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ];
  }

  private parseTestCasesResponse(response: any, spec: FeatureSpecification): TestCase[] {
    try {
      const data = typeof response === 'string' ? JSON.parse(response) : response;
      const testCases = data.testCases || [];

      return testCases.map((tc: any, idx: number) => this.normalizeTestCase(tc, spec, idx));
    } catch (error) {
      console.error('Failed to parse test cases response:', error);
      return [];
    }
  }

  private parseEdgeCasesResponse(response: any, spec: FeatureSpecification): TestCase[] {
    try {
      const data = typeof response === 'string' ? JSON.parse(response) : response;
      const edgeCases = data.edgeCases || [];

      return edgeCases.map((ec: any, idx: number) => ({
        id: ec.id || `EC_${idx + 1}`,
        name: ec.name || ec.scenario,
        description: ec.scenario || ec.description,
        category: 'edge_case' as TestCategory,
        priority: ec.priority || 'P2',
        preconditions: [],
        steps: [
          {
            order: 1,
            action: 'custom' as const,
            description: ec.scenario || ec.input,
          },
        ],
        expectedResults: [
          {
            type: 'custom' as const,
            expected: ec.expectedBehavior,
            comparison: 'equals' as const,
          },
        ],
        tags: [ec.category, 'edge-case'],
        estimatedDuration: 10000,
        sourceSpecification: spec.id,
        generatedBy: 'test-generator',
        confidence: 0.8,
      }));
    } catch (error) {
      console.error('Failed to parse edge cases response:', error);
      return [];
    }
  }

  private parseSecurityResponse(response: any, spec: FeatureSpecification): TestCase[] {
    try {
      const data = typeof response === 'string' ? JSON.parse(response) : response;
      const vulnerabilities = data.vulnerabilities || [];
      const securityTests = data.securityTests || [];

      // Convert vulnerabilities to test cases
      const vulnTests = vulnerabilities.map((v: any, idx: number) => ({
        id: v.id || `SEC_${idx + 1}`,
        name: `Security: ${v.title}`,
        description: v.description,
        category: 'security' as TestCategory,
        priority: v.severity === 'critical' ? 'P0' : v.severity === 'high' ? 'P1' : 'P2',
        preconditions: [],
        steps: [
          {
            order: 1,
            action: 'custom' as const,
            description: v.attackVector,
          },
        ],
        expectedResults: [
          {
            type: 'custom' as const,
            expected: 'Attack should be prevented',
            comparison: 'equals' as const,
          },
        ],
        tags: ['security', v.type, v.cwe || ''],
        estimatedDuration: 15000,
        sourceSpecification: spec.id,
        generatedBy: 'security-analyzer',
        confidence: 0.9,
      }));

      // Add explicit security tests
      const explicitTests = securityTests.map((st: any, idx: number) => ({
        id: st.id || `ST_${idx + 1}`,
        name: st.name,
        description: st.name,
        category: 'security' as TestCategory,
        priority: 'P1' as const,
        preconditions: [],
        steps: st.steps.map((s: string, i: number) => ({
          order: i + 1,
          action: 'custom' as const,
          description: s,
        })),
        expectedResults: [
          {
            type: 'custom' as const,
            expected: st.expectedResult,
            comparison: 'equals' as const,
          },
        ],
        tags: ['security'],
        estimatedDuration: 10000,
        sourceSpecification: spec.id,
        generatedBy: 'security-analyzer',
        confidence: 0.85,
      }));

      return [...vulnTests, ...explicitTests];
    } catch (error) {
      console.error('Failed to parse security response:', error);
      return [];
    }
  }

  private parseAccessibilityResponse(response: any, spec: FeatureSpecification): TestCase[] {
    try {
      const data = typeof response === 'string' ? JSON.parse(response) : response;
      const issues = data.issues || [];
      const a11yTests = data.accessibilityTests || [];

      // Convert issues to test cases
      const issueTests = issues.map((issue: any, idx: number) => ({
        id: issue.id || `A11Y_${idx + 1}`,
        name: `A11y: ${issue.title}`,
        description: issue.description,
        category: 'accessibility' as TestCategory,
        priority: issue.severity === 'critical' ? 'P0' : issue.severity === 'major' ? 'P1' : 'P2',
        preconditions: [],
        steps: [
          {
            order: 1,
            action: 'custom' as const,
            target: issue.element,
            description: `Check element: ${issue.element}`,
          },
        ],
        expectedResults: [
          {
            type: 'custom' as const,
            expected: issue.expectedState,
            comparison: 'equals' as const,
          },
        ],
        tags: ['accessibility', issue.wcagCriteria, `WCAG-${issue.level}`],
        estimatedDuration: 5000,
        sourceSpecification: spec.id,
        generatedBy: 'accessibility-auditor',
        confidence: 0.9,
      }));

      // Add explicit a11y tests
      const explicitTests = a11yTests.map((at: any, idx: number) => ({
        id: at.id || `AT_${idx + 1}`,
        name: at.name,
        description: `WCAG: ${at.wcagCriteria}`,
        category: 'accessibility' as TestCategory,
        priority: 'P1' as const,
        preconditions: [],
        steps: at.steps.map((s: string, i: number) => ({
          order: i + 1,
          action: 'custom' as const,
          description: s,
        })),
        expectedResults: [
          {
            type: 'custom' as const,
            expected: at.expectedResult,
            comparison: 'equals' as const,
          },
        ],
        tags: ['accessibility', at.wcagCriteria],
        estimatedDuration: 5000,
        sourceSpecification: spec.id,
        generatedBy: 'accessibility-auditor',
        confidence: 0.85,
      }));

      return [...issueTests, ...explicitTests];
    } catch (error) {
      console.error('Failed to parse accessibility response:', error);
      return [];
    }
  }

  private normalizeTestCase(tc: any, spec: FeatureSpecification, idx: number): TestCase {
    return {
      id: tc.id || `TC_${idx + 1}`,
      name: tc.name,
      description: tc.description,
      category: tc.category || 'happy_path',
      priority: tc.priority || 'P2',
      preconditions: tc.preconditions || [],
      steps: (tc.steps || []).map((s: any, i: number) => ({
        order: s.order || i + 1,
        action: s.action || 'custom',
        target: s.target,
        value: s.value,
        waitFor: s.waitFor,
        screenshot: s.screenshot,
        description: s.description,
      })),
      expectedResults: (tc.expectedResults || []).map((er: any) => ({
        type: er.type || 'custom',
        target: er.target,
        expected: er.expected,
        comparison: er.comparison || 'equals',
      })),
      tags: tc.tags || [],
      estimatedDuration: tc.estimatedDuration || 5000,
      sourceSpecification: spec.id,
      generatedBy: 'test-generator',
      confidence: 0.85,
    };
  }

  private validateAndDeduplicate(testCases: TestCase[]): TestCase[] {
    const seen = new Set<string>();
    const validated: TestCase[] = [];

    for (const tc of testCases) {
      // Skip invalid test cases
      if (!tc.name || !tc.steps || tc.steps.length === 0) {
        continue;
      }

      // Create a fingerprint for deduplication
      const fingerprint = `${tc.name}_${tc.category}_${tc.steps.length}`;
      if (seen.has(fingerprint)) {
        continue;
      }

      seen.add(fingerprint);
      validated.push(tc);
    }

    return validated;
  }

  private calculateCoverage(testCases: TestCase[]): GenerationResult['coverage'] {
    return {
      happyPaths: testCases.filter((tc) => tc.category === 'happy_path' || tc.category === 'smoke').length,
      edgeCases: testCases.filter((tc) => tc.category === 'edge_case' || tc.category === 'boundary').length,
      negativeCases: testCases.filter((tc) => tc.category === 'negative').length,
      securityTests: testCases.filter((tc) => tc.category === 'security').length,
      accessibilityTests: testCases.filter((tc) => tc.category === 'accessibility').length,
      total: testCases.length,
    };
  }
}

/**
 * Factory function to create a test generator
 */
export function createTestGenerator(knowledgeBase: BaseKnowledgeBase): TestCaseGenerator {
  return new TestCaseGenerator(knowledgeBase);
}
