/**
 * Tests for Zod validation schemas
 */
import { describe, it, expect } from 'vitest';
import {
  PageStateSchema,
  DetectedIssueSchema,
  DNAStatsSchema,
  ElementCategorySchema,
  IssueSeveritySchema,
  safeParseWithLog,
} from './schemas';

describe('PageStateSchema', () => {
  it('should validate a valid page state', () => {
    const validPageState = {
      id: 'page-123',
      url: 'https://example.com',
      title: 'Example Page',
      timestamp: '2024-01-01T00:00:00Z',
      totalElements: 100,
      interactiveElements: 25,
      tree: null,
      flatInteractive: [],
      screenshot: null,
    };

    const result = PageStateSchema.safeParse(validPageState);
    expect(result.success).toBe(true);
  });

  it('should reject invalid page state', () => {
    const invalidPageState = {
      id: 123, // Should be string
      url: 'https://example.com',
    };

    const result = PageStateSchema.safeParse(invalidPageState);
    expect(result.success).toBe(false);
  });
});

describe('DetectedIssueSchema', () => {
  it('should validate a valid detected issue', () => {
    const validIssue = {
      id: 'issue-123',
      issueType: 'broken_link',
      severity: 'medium',
      title: 'Broken Link Found',
      description: 'Link returns 404',
      pageUrl: 'https://example.com/page',
      pageTitle: 'Example Page',
      elementSelector: 'a.broken-link',
      evidence: '404 Not Found',
      recommendation: 'Fix or remove the broken link',
      detectedAt: '2024-01-01T00:00:00Z',
    };

    const result = DetectedIssueSchema.safeParse(validIssue);
    expect(result.success).toBe(true);
  });

  it('should reject invalid severity', () => {
    const invalidIssue = {
      id: 'issue-123',
      issueType: 'broken_link',
      severity: 'invalid_severity', // Invalid
      title: 'Test',
      description: 'Test',
      pageUrl: 'https://example.com',
      pageTitle: 'Test',
      elementSelector: null,
      evidence: null,
      recommendation: null,
      detectedAt: '2024-01-01T00:00:00Z',
    };

    const result = DetectedIssueSchema.safeParse(invalidIssue);
    expect(result.success).toBe(false);
  });
});

describe('DNAStatsSchema', () => {
  it('should validate valid stats', () => {
    const validStats = {
      totalPages: 10,
      totalElements: 500,
      totalTransitions: 25,
      navigationActions: 15,
      readActions: 5,
      writeActions: 3,
      destructiveActions: 1,
      paymentActions: 1,
      detectedFlows: 2,
    };

    const result = DNAStatsSchema.safeParse(validStats);
    expect(result.success).toBe(true);
  });
});

describe('ElementCategorySchema', () => {
  it('should accept valid categories', () => {
    const categories = ['navigation', 'read', 'write', 'destructive', 'payment'];

    categories.forEach((cat) => {
      const result = ElementCategorySchema.safeParse(cat);
      expect(result.success).toBe(true);
    });
  });

  it('should reject invalid category', () => {
    const result = ElementCategorySchema.safeParse('invalid');
    expect(result.success).toBe(false);
  });
});

describe('IssueSeveritySchema', () => {
  it('should accept valid severities', () => {
    const severities = ['critical', 'high', 'medium', 'low', 'info'];

    severities.forEach((sev) => {
      const result = IssueSeveritySchema.safeParse(sev);
      expect(result.success).toBe(true);
    });
  });
});

describe('safeParseWithLog', () => {
  it('should return parsed data on success', () => {
    const validStats = {
      totalPages: 5,
      totalElements: 100,
      totalTransitions: 10,
      navigationActions: 5,
      readActions: 3,
      writeActions: 1,
      destructiveActions: 0,
      paymentActions: 1,
      detectedFlows: 0,
    };

    const result = safeParseWithLog(DNAStatsSchema, validStats, 'test');
    expect(result).toEqual(validStats);
  });

  it('should return null on failure', () => {
    const invalidStats = { invalid: 'data' };

    const result = safeParseWithLog(DNAStatsSchema, invalidStats, 'test');
    expect(result).toBeNull();
  });
});
