"use client";

import { ProductArt } from "@noma/ui";
import { Columns3, Download, MoreVertical, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import type { AdminProductViewModel } from "@/domain/models";
import { AdminPagination, StatusBadge } from "./admin-ui";

export function ProductsTable({
  products,
}: {
  products: readonly AdminProductViewModel[];
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<readonly string[]>([
    "p2",
    "p3",
    "p5",
  ]);
  const visible = useMemo(
    () =>
      products.filter((product) =>
        `${product.name} ${product.sku}`
          .toLocaleLowerCase("fr")
          .includes(query.toLocaleLowerCase("fr")),
      ),
    [products, query],
  );

  function toggle(id: string) {
    setSelected((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id],
    );
  }

  return (
    <section
      className="data-panel noma-panel"
      aria-labelledby="product-table-title"
    >
      <h2 id="product-table-title" className="sr-only">
        Liste des produits
      </h2>
      <div className="table-filters">
        <label className="admin-search">
          <Search aria-hidden="true" />
          <span className="sr-only">Rechercher un produit</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rechercher un produit"
          />
        </label>
        <select aria-label="Catégorie">
          <option>Catégorie</option>
          <option>Sneakers</option>
          <option>Maison</option>
        </select>
        <select aria-label="Statut">
          <option>Statut</option>
          <option>Actif</option>
          <option>Brouillon</option>
        </select>
        <select aria-label="Visibilité">
          <option>Visibilité</option>
          <option>Visible</option>
          <option>Masqué</option>
        </select>
        <button type="button" className="noma-button noma-button--secondary">
          Vues enregistrées
        </button>
      </div>
      <div className="bulk-toolbar">
        <strong>
          {selected.length} sélectionné{selected.length > 1 ? "s" : ""}
        </strong>
        <button type="button">Actions groupées⌄</button>
        <span />
        <button type="button">
          <Columns3 aria-hidden="true" /> Colonnes
        </button>
        <button type="button">
          <Download aria-hidden="true" /> Exporter
        </button>
      </div>
      <div className="table-scroll">
        <table className="admin-table products-table">
          <thead>
            <tr>
              <th>
                <span className="sr-only">Sélection</span>
              </th>
              <th>Image</th>
              <th>Produit</th>
              <th>SKU</th>
              <th>Catégorie</th>
              <th>Prix</th>
              <th>Stock</th>
              <th>Visibilité</th>
              <th>Statut</th>
              <th>Mis à jour</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((product) => (
              <tr
                key={product.id}
                data-selected={selected.includes(product.id)}
              >
                <td>
                  <input
                    type="checkbox"
                    checked={selected.includes(product.id)}
                    onChange={() => toggle(product.id)}
                    aria-label={`Sélectionner ${product.name} ${product.variant}`}
                  />
                </td>
                <td>
                  <div className="table-product-art">
                    <ProductArt kind={product.art} compact />
                  </div>
                </td>
                <td>
                  <Link href="/products/baskets-noma-court/edit">
                    <strong>{product.name}</strong>
                    <small>{product.variant}</small>
                  </Link>
                </td>
                <td>{product.sku}</td>
                <td>{product.category}</td>
                <td>{product.price.toFixed(2).replace(".", ",")} €</td>
                <td className={product.stock === 0 ? "danger-text" : ""}>
                  {product.stock}
                </td>
                <td>
                  <StatusBadge value={product.visibility} />
                </td>
                <td>
                  <StatusBadge value={product.status} />
                </td>
                <td>{product.updatedAt}</td>
                <td>
                  <button
                    className="icon-action"
                    type="button"
                    aria-label={`Actions pour ${product.name}`}
                  >
                    <MoreVertical aria-hidden="true" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <AdminPagination />
    </section>
  );
}
