import { categories, products } from "@/fixtures/catalog";
import type { CatalogRepository } from "@/ports/catalog-repository";

export const mockCatalogRepository: CatalogRepository = {
  async listProducts() {
    return products;
  },
  async listCategories() {
    return categories;
  },
  async findProductBySlug(slug) {
    return products.find((product) => product.slug === slug) ?? null;
  },
};
