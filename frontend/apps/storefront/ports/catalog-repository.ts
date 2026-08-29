import type { CategoryViewModel, ProductViewModel } from "@/domain/models";

export interface CatalogRepository {
  listProducts(): Promise<readonly ProductViewModel[]>;
  listCategories(): Promise<readonly CategoryViewModel[]>;
  findProductBySlug(slug: string): Promise<ProductViewModel | null>;
}
