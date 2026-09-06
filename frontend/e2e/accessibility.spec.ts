import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.setTimeout(60_000);

const routes = [
  "http://127.0.0.1:3000/",
  "http://127.0.0.1:3000/catalogue",
  "http://127.0.0.1:3000/produit/baskets-noma-court",
  "http://127.0.0.1:3001/",
  "http://127.0.0.1:3001/products",
  "http://127.0.0.1:3001/products/baskets-noma-court/edit",
  "http://127.0.0.1:3001/orders",
  "http://127.0.0.1:3001/orders/ORD-2026-008471",
  "http://127.0.0.1:3001/inventory",
  "http://127.0.0.1:3001/payments/PAY-2026-008471",
  "http://127.0.0.1:3001/tablet",
  "http://127.0.0.1:3001/mobile",
] as const;

test("aucune violation d’accessibilité grave ou critique", async ({ page }) => {
  const issues: Array<{ route: string; rule: string; targets: string[] }> = [];

  for (const route of routes) {
    await page.goto(route);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    const blockingViolations = results.violations.filter(
      ({ impact }) => impact === "serious" || impact === "critical",
    );

    for (const violation of blockingViolations) {
      issues.push({
        route,
        rule: violation.id,
        targets: violation.nodes.flatMap(({ target }) => target),
      });
    }
  }

  expect(issues).toEqual([]);
});
