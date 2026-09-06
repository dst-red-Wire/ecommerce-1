import { mockCatalogRepository } from "@/adapters/mock-catalog-repository";

// Composition root for Phase 1. A future BFF adapter will replace this binding.
const catalogRepository = mockCatalogRepository;

export async function getHomeView() {
  const [products, categories] = await Promise.all([
    catalogRepository.listProducts(),
    catalogRepository.listCategories(),
  ]);
  return { products: products.slice(0, 4), categories };
}

export function getCatalogView() {
  return catalogRepository.listProducts();
}

export function getProductView(slug: string) {
  return catalogRepository.findProductBySlug(slug);
}
