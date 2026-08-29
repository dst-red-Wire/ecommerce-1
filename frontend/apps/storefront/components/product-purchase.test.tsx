import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { products } from "@/fixtures/catalog";
import { ProductPurchase } from "./product-purchase";

describe("ProductPurchase", () => {
  it("keeps the mock cart interaction deterministic and reversible", () => {
    const product = products[0];
    expect(product).toBeDefined();
    if (!product) return;

    render(<ProductPurchase product={product} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Augmenter la quantité" }),
    );
    fireEvent.click(screen.getByRole("button", { name: /Ajouter au panier/ }));

    expect(
      screen.getByText(new RegExp(`2 × ${product.name}`)),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Quantité")).toHaveTextContent("2");
  });
});
