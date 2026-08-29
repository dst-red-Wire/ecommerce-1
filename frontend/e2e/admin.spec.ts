import { expect, test } from "@playwright/test";

test("Admin: navigation produit, filtre et édition simulée", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:3001/products");
  await expect(
    page.getByRole("heading", { name: "Produits", exact: true }),
  ).toBeVisible();
  await page.getByPlaceholder("Rechercher un produit").fill("Casque Audio");
  await expect(page.getByText("NOMA Casque Audio")).toBeVisible();
  await page.getByPlaceholder("Rechercher un produit").fill("");
  await page
    .getByRole("link", { name: /NOMA Runner 2.0/ })
    .first()
    .click();
  await page.getByLabel(/Nom du produit/).fill("Baskets NOMA Court — démo");
  await page.getByRole("button", { name: "Enregistrer" }).click();
  await expect(page.getByRole("status")).toContainText("mock local");
});

test("Admin: stock et remboursement restent explicitement simulés", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:3001/inventory");
  await expect(
    page.getByRole("heading", { name: "Ajuster le stock" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Confirmer l’ajustement" }).click();
  await expect(page.getByRole("status")).toContainText(
    "aucune donnée backend modifiée",
  );

  await page.goto("http://127.0.0.1:3001/payments/PAY-2026-008471");
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("heading", { name: "Rembourser le paiement" }),
  ).toBeVisible();
  await dialog.locator("select").selectOption({ label: "Retour accepté" });
  await dialog.getByRole("checkbox").check();
  await dialog.getByPlaceholder("Tapez CONFIRMER").fill("CONFIRMER");
  await expect(
    dialog.getByRole("button", { name: "Confirmer le remboursement" }),
  ).toBeEnabled();
});

test("Admin: vue mobile d’urgence et acquittement", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/mobile");
  await expect(
    page.getByRole("heading", { name: "Urgences opérationnelles" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Accuser réception" }).click();
  await expect(
    page.getByRole("button", { name: /Accusé réception/ }),
  ).toBeDisabled();
});
