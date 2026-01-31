/**
 * Accessibility tests for Button component
 */
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { axe } from "vitest-axe";
import { Button } from "./button";

describe("Button accessibility", () => {
  it("should have no accessibility violations for default button", async () => {
    const { container } = render(<Button>Click me</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("should have no accessibility violations for disabled button", async () => {
    const { container } = render(<Button disabled>Disabled</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("should have no accessibility violations for destructive variant", async () => {
    const { container } = render(<Button variant="destructive">Delete</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("should have no accessibility violations for outline variant", async () => {
    const { container } = render(<Button variant="outline">Outline</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("should have no accessibility violations for icon button with aria-label", async () => {
    const { container } = render(
      <Button size="icon" aria-label="Close dialog">
        <span>×</span>
      </Button>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("should render as a link when asChild is used with anchor", async () => {
    const { container } = render(
      <Button asChild>
        <a href="/test">Link Button</a>
      </Button>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

describe("Button functionality", () => {
  it("should render with correct text", () => {
    const { getByRole } = render(<Button>Submit</Button>);
    expect(getByRole("button")).toHaveTextContent("Submit");
  });

  it("should apply variant class", () => {
    const { getByRole } = render(<Button variant="destructive">Delete</Button>);
    expect(getByRole("button")).toHaveAttribute("data-variant", "destructive");
  });

  it("should apply size class", () => {
    const { getByRole } = render(<Button size="lg">Large</Button>);
    expect(getByRole("button")).toHaveAttribute("data-size", "lg");
  });
});
