"use client";

import { SlidersHorizontal, X } from "lucide-react";
import { useMemo, useState } from "react";

import type { ProductViewModel } from "@/domain/models";
import { ProductCard } from "./product-card";

const categoryOptions = [
  "Maison",
  "Mode",
  "Électronique",
  "Accessoires",
] as const;

export function CatalogExplorer({
  products,
  initialQuery = "",
}: {
  products: readonly ProductViewModel[];
  initialQuery?: string;
}) {
  const [categories, setCategories] = useState<readonly string[]>([
    "Maison",
    "Mode",
  ]);
  const [sort, setSort] = useState("new");
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false);

  const visibleProducts = useMemo(() => {
    const query = initialQuery.trim().toLocaleLowerCase("fr");
    const filtered = products.filter((product) => {
      const matchesQuery =
        !query || product.name.toLocaleLowerCase("fr").includes(query);
      const matchesCategory =
        categories.length === 0 || categories.includes(product.category);
      return matchesQuery && matchesCategory;
    });
    return [...filtered].sort((left, right) => {
      if (sort === "price-asc") return left.price - right.price;
      if (sort === "price-desc") return right.price - left.price;
      return left.id.localeCompare(right.id);
    });
  }, [categories, initialQuery, products, sort]);

  function toggleCategory(category: string) {
    setCategories((current) =>
      current.includes(category)
        ? current.filter((item) => item !== category)
        : [...current, category],
    );
  }

  const filters = (
    <div className="catalog-filters__content">
      <div className="filter-heading">
        <strong>Filtres</strong>
        <SlidersHorizontal aria-hidden="true" />
      </div>
      <fieldset>
        <legend>Catégories</legend>
        {categoryOptions.map((category) => (
          <label key={category}>
            <input
              checked={categories.includes(category)}
              onChange={() => toggleCategory(category)}
              type="checkbox"
            />
            <span>{category}</span>
          </label>
        ))}
      </fieldset>
      <fieldset>
        <legend>Disponibilité</legend>
        <label>
          <input defaultChecked type="checkbox" /> <span>En stock</span>
        </label>
        <label>
          <input type="checkbox" /> <span>Indisponible</span>
        </label>
      </fieldset>
      <fieldset>
        <legend>Avis</legend>
        <label>
          <input type="checkbox" /> <span>★★★★ et plus</span>
        </label>
      </fieldset>
    </div>
  );

  return (
    <div className="catalog-layout">
      <aside
        className="catalog-filters desktop-filters"
        aria-label="Filtres catalogue"
      >
        {filters}
      </aside>
      <section className="catalog-results" aria-live="polite">
        <div className="catalog-toolbar">
          <button
            className="filter-trigger mobile-only"
            type="button"
            onClick={() => setMobileFiltersOpen(true)}
          >
            <SlidersHorizontal aria-hidden="true" /> Filtrer
          </button>
          <div className="active-filters">
            {categories.map((category) => (
              <button
                key={category}
                type="button"
                onClick={() => toggleCategory(category)}
              >
                {category} <X aria-hidden="true" />
              </button>
            ))}
          </div>
          <label className="sort-control">
            <span>Trier par</span>
            <select
              value={sort}
              onChange={(event) => setSort(event.target.value)}
            >
              <option value="new">Nouveautés</option>
              <option value="price-asc">Prix croissant</option>
              <option value="price-desc">Prix décroissant</option>
            </select>
          </label>
        </div>
        {visibleProducts.length ? (
          <div className="product-grid catalog-grid">
            {visibleProducts.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        ) : (
          <div className="catalog-empty noma-panel">
            <h2>Aucun produit trouvé</h2>
            <p>
              Retirez un filtre pour retrouver les produits de démonstration.
            </p>
            <button
              className="noma-button"
              type="button"
              onClick={() => setCategories([])}
            >
              Réinitialiser les filtres
            </button>
          </div>
        )}
        <nav className="pagination" aria-label="Pagination catalogue">
          <button type="button" aria-current="page">
            1
          </button>
          <button type="button">2</button>
          <button type="button">3</button>
          <span aria-hidden="true">…</span>
          <button type="button">12</button>
        </nav>
      </section>
      {mobileFiltersOpen ? (
        <div
          className="filter-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="filter-title"
        >
          <button
            className="filter-backdrop"
            type="button"
            onClick={() => setMobileFiltersOpen(false)}
            aria-label="Fermer les filtres"
          />
          <div className="filter-sheet">
            <div className="filter-sheet__header">
              <h2 id="filter-title">Filtrer les produits</h2>
              <button
                type="button"
                onClick={() => setMobileFiltersOpen(false)}
                aria-label="Fermer"
              >
                <X aria-hidden="true" />
              </button>
            </div>
            {filters}
            <button
              className="noma-button"
              type="button"
              onClick={() => setMobileFiltersOpen(false)}
            >
              Voir {visibleProducts.length} produits
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
