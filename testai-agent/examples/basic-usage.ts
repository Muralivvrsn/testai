/**
 * TestAI Agent - Basic Usage Example
 *
 * This example demonstrates how to use the TestAI Agent to generate
 * comprehensive test cases from a feature specification.
 *
 * Run with: npx ts-node examples/basic-usage.ts
 */

import path from 'path';
import {
  createQAAgent,
  createSpecificationTemplate,
  FeatureSpecification,
} from '../index';

async function main() {
  console.log('🚀 TestAI Agent - Basic Usage Example\n');

  // ============================================================================
  // Step 1: Create the QA Agent
  // ============================================================================
  console.log('Step 1: Creating QA Agent...');

  const agent = await createQAAgent({
    // API keys can be provided here or via environment variables
    // openaiApiKey: process.env.OPENAI_API_KEY,
    // anthropicApiKey: process.env.ANTHROPIC_API_KEY,
  });

  console.log('✓ Agent created\n');

  // ============================================================================
  // Step 2: Load QA Knowledge Base
  // ============================================================================
  console.log('Step 2: Loading QA Knowledge Base...');

  // Path to the QA Brain markdown file
  const knowledgePath = path.join(__dirname, '../../QA_BRAIN.md');

  try {
    await agent.loadKnowledge(knowledgePath);
    const stats = agent.getStatus().knowledgeBaseStats;
    console.log(`✓ Loaded ${stats?.totalChunks} knowledge chunks (${stats?.totalTokens} tokens)\n`);
  } catch (error) {
    console.log('⚠ QA_BRAIN.md not found, using built-in knowledge\n');
    // The agent can still work with just the prompts
  }

  // ============================================================================
  // Step 3: Create a Feature Specification
  // ============================================================================
  console.log('Step 3: Creating Feature Specification...');

  // Option A: Use a pre-built template
  const loginSpec = createSpecificationTemplate('login_flow', {
    name: 'My App Login',
    description: 'User authentication for My App using email and password',
  });

  // Option B: Create a custom specification
  const customSpec: FeatureSpecification = {
    id: 'custom_spec_001',
    name: 'User Profile Update',
    type: 'settings_page',
    description: 'Allow users to update their profile information including name, email, and avatar',
    priority: 'high',

    userStories: [
      {
        id: 'US_01',
        asA: 'registered user',
        iWant: 'to update my profile name',
        soThat: 'my account shows my preferred name',
        priority: 1,
      },
      {
        id: 'US_02',
        asA: 'user',
        iWant: 'to upload a profile picture',
        soThat: 'others can recognize me',
        priority: 2,
      },
      {
        id: 'US_03',
        asA: 'user',
        iWant: 'to change my email address',
        soThat: 'I receive notifications at my new email',
        priority: 1,
      },
    ],

    acceptanceCriteria: [
      {
        id: 'AC_01',
        given: 'I am on the profile settings page',
        when: 'I update my name and click save',
        then: 'my name is updated and I see a success message',
        category: 'happy_path',
      },
      {
        id: 'AC_02',
        given: 'I try to change my email',
        when: 'the new email is already in use',
        then: 'I see an error message',
        category: 'error_handling',
      },
      {
        id: 'AC_03',
        given: 'I upload an image',
        when: 'the file is larger than 5MB',
        then: 'I see a file size error',
        category: 'edge_case',
      },
    ],

    dataRequirements: [
      {
        id: 'DR_01',
        entityType: 'ProfileUpdate',
        fields: [
          { name: 'firstName', type: 'string', required: true, minLength: 1, maxLength: 50 },
          { name: 'lastName', type: 'string', required: true, minLength: 1, maxLength: 50 },
          { name: 'email', type: 'email', required: true },
          { name: 'avatar', type: 'file', required: false },
        ],
        validations: [
          { field: 'email', type: 'format', message: 'Invalid email', rule: 'RFC 5322' },
          { field: 'email', type: 'unique', message: 'Email already in use', rule: 'database check' },
          { field: 'avatar', type: 'custom', message: 'File too large', rule: 'max 5MB' },
        ],
      },
    ],

    tags: ['profile', 'settings', 'user'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  console.log(`✓ Created specification: "${customSpec.name}"\n`);

  // ============================================================================
  // Step 4: Generate Test Cases
  // ============================================================================
  console.log('Step 4: Generating Test Cases...');
  console.log('  (This may take 10-30 seconds depending on the LLM provider)\n');

  try {
    const result = await agent.generateTests(customSpec, {
      includeEdgeCases: true,
      includeSecurityTests: true,
      includeAccessibilityTests: false, // Skip for this example
      maxTestCases: 20,
    });

    // ============================================================================
    // Step 5: Display Results
    // ============================================================================
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('                     TEST GENERATION RESULTS                      ');
    console.log('═══════════════════════════════════════════════════════════════\n');

    console.log(`📊 Coverage Summary:`);
    console.log(`   - Happy Paths:      ${result.coverage.happyPaths}`);
    console.log(`   - Edge Cases:       ${result.coverage.edgeCases}`);
    console.log(`   - Negative Cases:   ${result.coverage.negativeCases}`);
    console.log(`   - Security Tests:   ${result.coverage.securityTests}`);
    console.log(`   - Accessibility:    ${result.coverage.accessibilityTests}`);
    console.log(`   ─────────────────────────────`);
    console.log(`   Total:              ${result.coverage.total}\n`);

    console.log(`⚙️  Metadata:`);
    console.log(`   - Model Used:       ${result.metadata.model}`);
    console.log(`   - Tokens Used:      ${result.metadata.tokensUsed}`);
    console.log(`   - Cost:             $${result.metadata.cost.toFixed(4)}`);
    console.log(`   - Duration:         ${result.metadata.duration}ms\n`);

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('                        TEST CASES                               ');
    console.log('═══════════════════════════════════════════════════════════════\n');

    for (const testCase of result.testCases) {
      console.log(`📝 ${testCase.id}: ${testCase.name}`);
      console.log(`   Category: ${testCase.category} | Priority: ${testCase.priority}`);
      console.log(`   Description: ${testCase.description}`);

      if (testCase.preconditions.length > 0) {
        console.log(`   Preconditions:`);
        testCase.preconditions.forEach((p) => console.log(`     - ${p}`));
      }

      console.log(`   Steps:`);
      testCase.steps.forEach((step) => {
        console.log(`     ${step.order}. [${step.action}] ${step.description}`);
        if (step.target) console.log(`        Target: ${step.target}`);
        if (step.value) console.log(`        Value: ${step.value}`);
      });

      console.log(`   Expected Results:`);
      testCase.expectedResults.forEach((er) => {
        console.log(`     - [${er.type}] ${er.expected} (${er.comparison})`);
      });

      console.log(`   Tags: ${testCase.tags.join(', ')}`);
      console.log('');
    }

    console.log('═══════════════════════════════════════════════════════════════\n');
    console.log('✅ Test generation complete!\n');

  } catch (error: any) {
    console.error('❌ Error generating tests:', error.message);
    console.log('\nMake sure you have valid API keys set:');
    console.log('  - OPENAI_API_KEY');
    console.log('  - ANTHROPIC_API_KEY');
    console.log('  - GOOGLE_API_KEY');
    console.log('  - DEEPSEEK_API_KEY');
    console.log('\nAt least one provider must be configured.');
  }
}

// Run the example
main().catch(console.error);
