/**
 * Property-based tests for Zod schemas using fast-check
 * Tests that schemas handle arbitrary inputs correctly
 */
import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import {
  PageStateSchema,
  DOMNodeSchema,
  PendingActionSchema,
  DNAStatsSchema,
  ElementCategorySchema,
  IssueSeveritySchema,
  ClassifiedActionSchema,
  safeParseWithLog,
  parseWithFallback,
} from "./schemas";

// ============ Arbitraries for generating test data ============

const domNodeArbitrary = fc.record({
  mmid: fc.string({ minLength: 1, maxLength: 20 }),
  tag: fc.constantFrom("div", "button", "a", "input", "span", "form"),
  role: fc.option(fc.constantFrom("button", "link", "textbox", "navigation"), {
    nil: null,
  }),
  name: fc.option(fc.string({ maxLength: 50 }), { nil: null }),
  text: fc.option(fc.string({ maxLength: 100 }), { nil: null }),
  value: fc.option(fc.string({ maxLength: 100 }), { nil: null }),
  placeholder: fc.option(fc.string({ maxLength: 50 }), { nil: null }),
  href: fc.option(fc.webUrl(), { nil: null }),
  src: fc.option(fc.webUrl(), { nil: null }),
  type: fc.option(fc.constantFrom("text", "button", "submit", "email"), { nil: null }),
  isInteractive: fc.boolean(),
  attributes: fc.dictionary(
    fc.string({ minLength: 1, maxLength: 20 }),
    fc.string({ maxLength: 50 })
  ),
  children: fc.constant([]),
});

const pageStateArbitrary = fc.record({
  id: fc.uuid(),
  url: fc.webUrl(),
  title: fc.string({ minLength: 1, maxLength: 100 }),
  timestamp: fc.date().map((d) => d.toISOString()),
  totalElements: fc.nat({ max: 10000 }),
  interactiveElements: fc.nat({ max: 1000 }),
  tree: fc.option(domNodeArbitrary, { nil: null }),
  flatInteractive: fc.array(domNodeArbitrary, { maxLength: 50 }),
  screenshot: fc.option(fc.base64String({ maxLength: 100 }), { nil: null }),
});

const pendingActionArbitrary = fc.record({
  id: fc.uuid(),
  mmid: fc.string({ minLength: 1, maxLength: 20 }),
  actionType: fc.constantFrom("click", "input", "select", "hover"),
  inputValue: fc.option(fc.string({ maxLength: 100 }), { nil: null }),
  tag: fc.constantFrom("button", "a", "input", "select"),
  label: fc.option(fc.string({ maxLength: 50 }), { nil: null }),
  sourceUrl: fc.webUrl(),
  priority: fc.integer({ min: 0, max: 100 }),
  mightNavigate: fc.boolean(),
});

const elementCategoryArbitrary = fc.constantFrom(
  "navigation",
  "read",
  "write",
  "destructive",
  "payment"
);

const issueSeverityArbitrary = fc.constantFrom(
  "critical",
  "high",
  "medium",
  "low",
  "info"
);

// ============ Property Tests ============

describe("DOMNodeSchema property tests", () => {
  it("should accept all valid DOM nodes", () => {
    fc.assert(
      fc.property(domNodeArbitrary, (node) => {
        const result = DOMNodeSchema.safeParse(node);
        expect(result.success).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it("should reject objects missing required fields", () => {
    fc.assert(
      fc.property(
        fc.record({
          mmid: fc.string(),
          // Missing other required fields
        }),
        (partial) => {
          const result = DOMNodeSchema.safeParse(partial);
          expect(result.success).toBe(false);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe("PageStateSchema property tests", () => {
  it("should accept all valid page states", () => {
    fc.assert(
      fc.property(pageStateArbitrary, (state) => {
        const result = PageStateSchema.safeParse(state);
        expect(result.success).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it("should reject non-object inputs", () => {
    fc.assert(
      fc.property(
        fc.oneof(fc.string(), fc.integer(), fc.boolean(), fc.constant(null)),
        (invalid) => {
          const result = PageStateSchema.safeParse(invalid);
          expect(result.success).toBe(false);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe("PendingActionSchema property tests", () => {
  it("should accept all valid pending actions", () => {
    fc.assert(
      fc.property(pendingActionArbitrary, (action) => {
        const result = PendingActionSchema.safeParse(action);
        expect(result.success).toBe(true);
      }),
      { numRuns: 100 }
    );
  });
});

describe("ElementCategorySchema property tests", () => {
  it("should accept all valid categories", () => {
    fc.assert(
      fc.property(elementCategoryArbitrary, (category) => {
        const result = ElementCategorySchema.safeParse(category);
        expect(result.success).toBe(true);
      }),
      { numRuns: 20 }
    );
  });

  it("should reject invalid category strings", () => {
    fc.assert(
      fc.property(
        fc.string().filter(
          (s) =>
            !["navigation", "read", "write", "destructive", "payment"].includes(s)
        ),
        (invalid) => {
          const result = ElementCategorySchema.safeParse(invalid);
          expect(result.success).toBe(false);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe("IssueSeveritySchema property tests", () => {
  it("should accept all valid severities", () => {
    fc.assert(
      fc.property(issueSeverityArbitrary, (severity) => {
        const result = IssueSeveritySchema.safeParse(severity);
        expect(result.success).toBe(true);
      }),
      { numRuns: 20 }
    );
  });
});

describe("DNAStatsSchema property tests", () => {
  it("should accept valid stats with non-negative numbers", () => {
    fc.assert(
      fc.property(
        fc.record({
          totalPages: fc.nat({ max: 100000 }),
          totalElements: fc.nat({ max: 1000000 }),
          totalTransitions: fc.nat({ max: 100000 }),
          navigationActions: fc.nat({ max: 50000 }),
          readActions: fc.nat({ max: 50000 }),
          writeActions: fc.nat({ max: 50000 }),
          destructiveActions: fc.nat({ max: 10000 }),
          paymentActions: fc.nat({ max: 10000 }),
          detectedFlows: fc.nat({ max: 1000 }),
        }),
        (stats) => {
          const result = DNAStatsSchema.safeParse(stats);
          expect(result.success).toBe(true);
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe("safeParseWithLog property tests", () => {
  it("should return data for valid inputs and null for invalid", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          // Valid
          fc.record({
            totalPages: fc.nat(),
            totalElements: fc.nat(),
            totalTransitions: fc.nat(),
            navigationActions: fc.nat(),
            readActions: fc.nat(),
            writeActions: fc.nat(),
            destructiveActions: fc.nat(),
            paymentActions: fc.nat(),
            detectedFlows: fc.nat(),
          }),
          // Invalid
          fc.record({ invalid: fc.string() })
        ),
        (input) => {
          const result = safeParseWithLog(DNAStatsSchema, input, "test");
          if ("totalPages" in input) {
            expect(result).not.toBeNull();
          } else {
            expect(result).toBeNull();
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

describe("parseWithFallback property tests", () => {
  const fallbackStats = {
    totalPages: 0,
    totalElements: 0,
    totalTransitions: 0,
    navigationActions: 0,
    readActions: 0,
    writeActions: 0,
    destructiveActions: 0,
    paymentActions: 0,
    detectedFlows: 0,
  };

  it("should return fallback for any invalid input", () => {
    fc.assert(
      fc.property(
        fc.oneof(fc.string(), fc.integer(), fc.array(fc.anything())),
        (invalid) => {
          const result = parseWithFallback(
            DNAStatsSchema,
            invalid,
            fallbackStats,
            "test"
          );
          expect(result).toEqual(fallbackStats);
        }
      ),
      { numRuns: 50 }
    );
  });

  it("should return parsed data for valid inputs", () => {
    fc.assert(
      fc.property(
        fc.record({
          totalPages: fc.nat(),
          totalElements: fc.nat(),
          totalTransitions: fc.nat(),
          navigationActions: fc.nat(),
          readActions: fc.nat(),
          writeActions: fc.nat(),
          destructiveActions: fc.nat(),
          paymentActions: fc.nat(),
          detectedFlows: fc.nat(),
        }),
        (valid) => {
          const result = parseWithFallback(
            DNAStatsSchema,
            valid,
            fallbackStats,
            "test"
          );
          expect(result).toEqual(valid);
        }
      ),
      { numRuns: 50 }
    );
  });
});

describe("ClassifiedActionSchema property tests", () => {
  it("should accept valid classified actions", () => {
    const classifiedActionArbitrary = fc.record({
      action: pendingActionArbitrary,
      category: elementCategoryArbitrary,
      selector: fc.option(fc.string({ maxLength: 200 }), { nil: null }),
      depth: fc.nat({ max: 100 }),
      flowId: fc.option(fc.uuid(), { nil: null }),
    });

    fc.assert(
      fc.property(classifiedActionArbitrary, (action) => {
        const result = ClassifiedActionSchema.safeParse(action);
        expect(result.success).toBe(true);
      }),
      { numRuns: 100 }
    );
  });
});
