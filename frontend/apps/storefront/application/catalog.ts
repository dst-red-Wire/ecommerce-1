import { mockCatalogRepository } from "@/adapters/mock-catalog-repository";
import { publicCatalogRepository } from "@/adapters/public-catalog-repository";

// Keep deterministic mock mode as the default for CI/offline development.
// Public providers are an explicit demo mode and remain behind this composition root.
const catalogRepository =
  process.env.NOMA_DATA_ADAPTER === "public" ? publicCatalogRepository : mockCatalogRepository;

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
