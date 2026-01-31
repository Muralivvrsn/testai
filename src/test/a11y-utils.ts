/**
 * Accessibility testing utilities using axe-core
 */
import { axe } from "vitest-axe";
import type { AxeResults } from "axe-core";

/**
 * Run accessibility audit on an HTML element
 */
export async function checkAccessibility(
  container: Element,
  options?: Parameters<typeof axe>[1]
): Promise<AxeResults> {
  return axe(container, options);
}

/**
 * Format axe violations for readable output
 */
export function formatViolations(results: AxeResults): string {
  if (results.violations.length === 0) {
    return "No accessibility violations found";
  }

  return results.violations
    .map((violation) => {
      const nodes = violation.nodes
        .map((node) => `  - ${node.html}`)
        .join("\n");
      return `${violation.impact?.toUpperCase()}: ${violation.help}\n${nodes}`;
    })
    .join("\n\n");
}

/**
 * Common axe rules to disable for specific test scenarios
 */
export const a11yRuleOverrides = {
  // Disable color contrast for components tested in isolation
  skipColorContrast: { rules: { "color-contrast": { enabled: false } } },
  // Disable region rule for isolated components
  skipRegion: { rules: { region: { enabled: false } } },
  // Disable landmark rules for isolated components
  skipLandmarks: {
    rules: {
      region: { enabled: false },
      "landmark-one-main": { enabled: false },
    },
  },
};
