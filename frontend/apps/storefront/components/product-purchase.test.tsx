import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { products } from "@/fixtures/catalog";
import { ProductGallery, ProductPurchase } from "./product-purchase";

describe("ProductGallery", () => {
  it("keeps visible Pexels attribution on the product detail media", () => {
    const product = products[0];
    expect(product).toBeDefined();
    if (!product) return;

    render(
      <ProductGallery
        product={{
          ...product,
          media: {
            url: "/demo-product.jpg",
            alt: "Demo product",
            sourceUrl: "https://www.pexels.com/photo/99/",
            provider: "Pexels",
            creator: "Demo Photographer",
            creatorUrl: "https://www.pexels.com/@demo/",
          },
        }}
      />,
    );

    expect(
      screen.getByRole("link", {
        name: "Photo: Demo Photographer / Pexels",
      }),
    ).toHaveAttribute("href", "https://www.pexels.com/photo/99/");
  });
});

describe("ProductPurchase", () => {
  it("keeps the mock cart interaction deterministic and reversible", () => {
    const product = products[0];
    expect(product).toBeDefined();
    if (!product) return;

    render(<ProductPurchase product={product} />);
    fireEvent.click(screen.getByRole("button", { name: "Augmenter la quantité" }));
    fireEvent.click(screen.getByRole("button", { name: /Ajouter au panier/ }));

    expect(screen.getByText(new RegExp(`2 × ${product.name}`))).toBeInTheDocument();
    expect(screen.getByLabelText("Quantité")).toHaveTextContent("2");
  });
});
