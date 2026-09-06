import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { adminProducts } from "@/fixtures/admin-data";
import { ProductsTable } from "./products-table";

describe("ProductsTable", () => {
  it("filters deterministic product fixtures", () => {
    render(<ProductsTable products={adminProducts} />);
    fireEvent.change(screen.getByPlaceholderText("Rechercher un produit"), {
      target: { value: "Casque Audio" },
    });

    expect(screen.getByText("NOMA Casque Audio")).toBeInTheDocument();
    expect(screen.queryByText("NOMA Lampe Oslo")).not.toBeInTheDocument();
  });
});
