import { expect, test } from "@playwright/test";

test("Storefront: accueil vers produit et panier simulé", async ({ page }) => {
  await page.goto("http://127.0.0.1:3000/");
  await expect(
    page.getByRole("heading", { name: /L’essentiel/ }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Baskets NOMA Court" }).click();
  await expect(
    page.getByRole("heading", { name: "Baskets NOMA Court" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Augmenter la quantité" }).click();
  await page.getByRole("button", { name: /Ajouter au panier/ }).click();
  await expect(page.getByText(/2 × Baskets NOMA Court/)).toBeVisible();
});

test("Storefront: catalogue filtrable et état vide", async ({ page }) => {
  await page.goto("http://127.0.0.1:3000/catalogue");
  await expect(page.getByRole("heading", { name: "Nouveautés" })).toBeVisible();
  const filters = page.getByRole("complementary", {
    name: "Filtres catalogue",
  });
  if (await filters.isVisible()) {
    await filters.getByLabel("Maison").uncheck();
    await expect(page.getByText("Lampe NOMA Halo")).not.toBeVisible();
  } else {
    await page.getByRole("button", { name: /Filtrer/ }).click();
    await page.getByRole("dialog").getByLabel("Maison").uncheck();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: /Voir \d+ produits/ })
      .click();
    await expect(page.getByText("Lampe NOMA Halo")).not.toBeVisible();
  }

  await page.goto("http://127.0.0.1:3000/catalogue?q=introuvable");
  await expect(
    page.getByRole("heading", { name: "Aucun produit trouvé" }),
  ).toBeVisible();
});
