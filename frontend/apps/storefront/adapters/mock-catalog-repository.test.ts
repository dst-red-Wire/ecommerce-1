import { describe, expect, it } from "vitest";

import { mockCatalogRepository } from "./mock-catalog-repository";

describe("mockCatalogRepository", () => {
  it("returns stable view models without exposing a backend DTO", async () => {
    const first = await mockCatalogRepository.listProducts();
    const second = await mockCatalogRepository.listProducts();

    expect(first).toEqual(second);
    expect(first[0]?.slug).toBe("baskets-noma-court");
    expect(await mockCatalogRepository.findProductBySlug("missing")).toBeNull();
  });
});
