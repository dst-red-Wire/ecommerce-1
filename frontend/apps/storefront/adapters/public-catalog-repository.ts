import type { CategoryViewModel, ProductViewModel } from "@/domain/models";
import type { CatalogRepository } from "@/ports/catalog-repository";
import { mockCatalogRepository } from "@/adapters/mock-catalog-repository";

const DUMMYJSON_PRODUCTS =
  "https://dummyjson.com/products?limit=12&select=id,title,description,category,price,discountPercentage,rating,stock";
const PEXELS_SEARCH =
  "https://api.pexels.com/v1/search?query=ecommerce%20product&orientation=square&per_page=12";

interface DummyProduct {
  id: number;
  title: string;
  description: string;
  category: string;
  price: number;
  discountPercentage?: number;
  rating?: number;
  stock?: number;
}

interface DummyProductsResponse {
  products?: DummyProduct[];
}

interface PexelsPhoto {
  id: number;
  url: string;
  alt?: string;
  photographer: string;
  photographer_url: string;
  src: { medium: string };
}

interface PexelsResponse {
  photos?: PexelsPhoto[];
}

function slugify(value: string) {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function availability(stock = 0): ProductViewModel["availability"] {
  if (stock <= 0) return "unavailable";
  if (stock < 10) return "low";
  return "available";
}

async function loadPublicProducts(): Promise<DummyProduct[]> {
  const response = await fetch(DUMMYJSON_PRODUCTS, {
    cache: "no-store",
    signal: AbortSignal.timeout(4_000),
  });
  if (!response.ok) throw new Error(`DummyJSON HTTP ${response.status}`);
  const payload = (await response.json()) as DummyProductsResponse;
  if (!Array.isArray(payload.products) || payload.products.length === 0) {
    throw new Error("DummyJSON returned no products");
  }
  return payload.products;
}

async function loadLicensedPhotos(): Promise<PexelsPhoto[]> {
  const apiKey = process.env.PEXELS_API_KEY?.trim();
  if (!apiKey) return [];

  const response = await fetch(PEXELS_SEARCH, {
    headers: { Authorization: apiKey },
    cache: "no-store",
    signal: AbortSignal.timeout(4_000),
  });
  if (!response.ok) throw new Error(`Pexels HTTP ${response.status}`);
  const payload = (await response.json()) as PexelsResponse;
  return Array.isArray(payload.photos) ? payload.photos : [];
}

async function buildCatalog(): Promise<ProductViewModel[]> {
  try {
    const products = await loadPublicProducts();
    let photos: PexelsPhoto[] = [];
    try {
      photos = await loadLicensedPhotos();
    } catch {
      // Photos are optional enrichment. Product data must remain usable if the
      // external media provider is unavailable or rate-limited.
    }

    return products.map((product, index) => {
      const discount = Math.max(0, product.discountPercentage ?? 0);
      const previousPrice =
        discount > 0 ? Number((product.price / (1 - discount / 100)).toFixed(2)) : undefined;
      const photo = photos[index % Math.max(photos.length, 1)];

      return {
        id: `dummyjson-${product.id}`,
        slug: `${slugify(product.title)}-${product.id}`,
        name: product.title,
        category: product.category,
        price: product.price,
        ...(previousPrice ? { previousPrice } : {}),
        rating: Math.max(0, Math.min(5, product.rating ?? 0)),
        reviewCount: 0,
        availability: availability(product.stock),
        ...(discount >= 10 ? { badge: `-${Math.round(discount)}%` } : {}),
        art: "shoe" as const,
        description: product.description,
        colors: ["Noir", "Blanc"],
        sizes: ["39", "40", "41", "42", "43"],
        ...(photo
          ? {
              media: {
                url: photo.src.medium,
                alt: photo.alt || product.title,
                sourceUrl: photo.url,
                provider: "Pexels" as const,
                creator: photo.photographer,
                creatorUrl: photo.photographer_url,
              },
            }
          : {}),
      } satisfies ProductViewModel;
    });
  } catch {
    // Public providers must never make the storefront unusable. The deterministic
    // repository fixture remains the fail-closed demo fallback.
    return [...(await mockCatalogRepository.listProducts())];
  }
}

let inFlightCatalog: Promise<ProductViewModel[]> | null = null;

async function getCatalog() {
  if (inFlightCatalog) return inFlightCatalog;

  inFlightCatalog = buildCatalog().finally(() => {
    inFlightCatalog = null;
  });
  return inFlightCatalog;
}

export const publicCatalogRepository: CatalogRepository = {
  async listProducts() {
    return getCatalog();
  },
  async listCategories() {
    const products = await getCatalog();
    const labels = [...new Set(products.map((product) => product.category))];
    if (labels.length === 0) return mockCatalogRepository.listCategories();
    return labels.map(
      (label, index) =>
        ({ id: slugify(label), label, symbol: String(index + 1) }) satisfies CategoryViewModel,
    );
  },
  async findProductBySlug(slug: string) {
    const products = await getCatalog();
    return products.find((product) => product.slug === slug) ?? null;
  },
};
