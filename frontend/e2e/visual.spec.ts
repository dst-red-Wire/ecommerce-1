import { test } from "@playwright/test";

test.beforeEach(({}, testInfo) =>
  test.skip(
    testInfo.project.name !== "desktop",
    "Captured once with explicit golden viewport",
  ),
);

const references = [
  {
    name: "storefront-home-desktop",
    url: "http://127.0.0.1:3000/",
    viewport: { width: 1440, height: 900 },
  },
  {
    name: "storefront-home-mobile",
    url: "http://127.0.0.1:3000/",
    viewport: { width: 390, height: 844 },
  },
  {
    name: "storefront-catalogue-desktop",
    url: "http://127.0.0.1:3000/catalogue",
    viewport: { width: 1440, height: 900 },
  },
  {
    name: "storefront-catalogue-mobile",
    url: "http://127.0.0.1:3000/catalogue",
    viewport: { width: 390, height: 844 },
  },
  {
    name: "storefront-product-desktop",
    url: "http://127.0.0.1:3000/produit/baskets-noma-court",
    viewport: { width: 1440, height: 900 },
  },
  {
    name: "storefront-product-mobile",
    url: "http://127.0.0.1:3000/produit/baskets-noma-court",
    viewport: { width: 390, height: 844 },
  },
  {
    name: "admin-dashboard",
    url: "http://127.0.0.1:3001/",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-products",
    url: "http://127.0.0.1:3001/products",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-product-editor",
    url: "http://127.0.0.1:3001/products/baskets-noma-court/edit",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-orders",
    url: "http://127.0.0.1:3001/orders",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-order-detail",
    url: "http://127.0.0.1:3001/orders/ORD-2026-008471",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-inventory",
    url: "http://127.0.0.1:3001/inventory",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-refund",
    url: "http://127.0.0.1:3001/payments/PAY-2026-008471",
    viewport: { width: 1536, height: 1024 },
  },
  {
    name: "admin-tablet",
    url: "http://127.0.0.1:3001/tablet",
    viewport: { width: 1086, height: 900 },
  },
  {
    name: "admin-mobile",
    url: "http://127.0.0.1:3001/mobile",
    viewport: { width: 798, height: 1100 },
  },
] as const;

for (const reference of references) {
  test(`capture ${reference.name}`, async ({ page }) => {
    await page.setViewportSize(reference.viewport);
    await page.goto(reference.url);
    await page.screenshot({
      path: `screenshots/${reference.name}.png`,
      fullPage: true,
      animations: "disabled",
    });
  });
}
