import type { ProductArtKind } from "@noma/ui";

export type ProductAvailability = "available" | "low" | "unavailable";

export interface ProductMediaViewModel {
  url: string;
  alt: string;
  sourceUrl: string;
  provider: "Pexels";
  creator: string;
  creatorUrl: string;
}

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
  media?: ProductMediaViewModel;
  colors: readonly string[];
  sizes: readonly string[];
}

export interface CategoryViewModel {
  id: string;
  label: string;
  symbol: string;
}
