import { afterEach, describe, expect, it, vi } from "vitest";

import { publicCatalogRepository } from "./public-catalog-repository";

const originalKey = process.env.PEXELS_API_KEY;

afterEach(() => {
  vi.restoreAllMocks();
  if (originalKey === undefined) delete process.env.PEXELS_API_KEY;
  else process.env.PEXELS_API_KEY = originalKey;
});

describe("publicCatalogRepository", () => {
  it("maps DummyJSON products without requiring a media secret", async () => {
    delete process.env.PEXELS_API_KEY;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          products: [
            {
              id: 7,
              title: "Demo Sneaker",
              description: "Public demo product",
              category: "mens-shoes",
              price: 100,
              discountPercentage: 20,
              rating: 4.5,
              stock: 5,
            },
          ],
        }),
      }),
    );

    const products = await publicCatalogRepository.listProducts();
    expect(products[0]).toMatchObject({
      id: "dummyjson-7",
      slug: "demo-sneaker-7",
      name: "Demo Sneaker",
      price: 100,
      previousPrice: 125,
      availability: "low",
    });
    expect(products[0]?.media).toBeUndefined();
  });

  it("adds Pexels attribution metadata when the server-side key is available", async () => {
    process.env.PEXELS_API_KEY = "test-only";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            products: [
              {
                id: 8,
                title: "Demo Bag",
                description: "Public demo product",
                category: "womens-bags",
                price: 80,
                rating: 4,
                stock: 20,
              },
            ],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            photos: [
              {
                id: 99,
                url: "https://www.pexels.com/photo/99/",
                alt: "Product photo",
                photographer: "Demo Photographer",
                photographer_url: "https://www.pexels.com/@demo/",
                src: { medium: "https://images.pexels.com/photos/99/demo.jpeg" },
              },
            ],
          }),
        }),
    );

    const products = await publicCatalogRepository.listProducts();
    expect(products[0]?.media).toEqual({
      url: "https://images.pexels.com/photos/99/demo.jpeg",
      alt: "Product photo",
      sourceUrl: "https://www.pexels.com/photo/99/",
      provider: "Pexels",
      creator: "Demo Photographer",
      creatorUrl: "https://www.pexels.com/@demo/",
    });
  });

  it("falls back to deterministic fixtures when public product data fails", async () => {
    delete process.env.PEXELS_API_KEY;
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    const products = await publicCatalogRepository.listProducts();
    expect(products.length).toBeGreaterThan(0);
    expect(products[0]?.id).not.toMatch(/^dummyjson-/);
  });
});
