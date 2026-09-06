import type { ProductArtKind } from "@noma/ui";

export type ProductAvailability = "available" | "low" | "unavailable";

export interface ProductViewModel {
  id: string;
  slug: string;
  name: string;
  category: string;
  price: number;
  previousPrice?: number;
  rating: number;
  reviewCount: number;
  availability: ProductAvailability;
  badge?: string;
  art: ProductArtKind;
  description: string;
  colors: readonly string[];
  sizes: readonly string[];
}

export interface CategoryViewModel {
  id: string;
  label: string;
  symbol: string;
}
