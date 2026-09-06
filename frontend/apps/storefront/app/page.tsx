import { Button, ProductArt } from "@noma/ui";
import { ArrowRight, RotateCcw, Truck } from "lucide-react";
import Link from "next/link";

import { getHomeView } from "@/application/catalog";
import { ProductCard } from "@/components/product-card";

export default async function HomePage() {
  const { products, categories } = await getHomeView();
  return (
    <main id="main" className="store-main home-page">
      <section className="home-hero">
        <div className="home-hero__copy">
          <p>Nouveautés NOMA</p>
          <h1>
            L’essentiel,
            <br />
            mieux choisi.
          </h1>
          <Button className="hero-cta" type="button">
            Découvrir la sélection
          </Button>
        </div>
        <div
          className="home-hero__art"
          aria-label="Illustrations temporaires de produits NOMA"
        >
          <ProductArt kind="shoe" />
          <ProductArt kind="lamp" />
        </div>
      </section>

      <section className="home-section" aria-labelledby="categories-title">
        <h2 id="categories-title">Catégories</h2>
        <div className="category-grid">
          {categories.map((category) => (
            <Link
              key={category.id}
              href={
                category.id === "all"
                  ? "/catalogue"
                  : `/catalogue?category=${category.label}`
              }
            >
              <span aria-hidden="true">{category.symbol}</span>
              {category.label}
            </Link>
          ))}
        </div>
      </section>

      <section className="home-section" aria-labelledby="essentials-title">
        <div className="section-heading">
          <h2 id="essentials-title">Nos essentiels</h2>
          <Link href="/catalogue">
            Voir tout <ArrowRight aria-hidden="true" />
          </Link>
        </div>
        <div className="product-grid featured-grid">
          {products.map((product) => (
            <ProductCard key={product.id} product={product} />
          ))}
        </div>
      </section>

      <section className="reassurance" aria-label="Engagements de service">
        <div>
          <Truck aria-hidden="true" />
          <p>
            <strong>Livraison offerte</strong>
            <br />
            dès 60 €
          </p>
        </div>
        <div>
          <RotateCcw aria-hidden="true" />
          <p>
            <strong>Retours sous</strong>
            <br />
            30 jours
          </p>
        </div>
      </section>

      <section className="editorial-panel">
        <div>
          <p className="eyebrow">L’univers NOMA</p>
          <h2>
            Des matières sincères,
            <br />
            des objets durables
          </h2>
          <p>
            Une esthétique épurée et intemporelle, pensée pour vous accompagner
            au quotidien.
          </p>
          <Link href="/catalogue">
            En savoir plus <ArrowRight aria-hidden="true" />
          </Link>
        </div>
        <div
          className="editorial-art"
          role="img"
          aria-label="Illustration temporaire d’un intérieur aux tons naturels"
        >
          <span aria-hidden="true">⌇</span>
          <span aria-hidden="true">☘</span>
          <span aria-hidden="true">▱</span>
        </div>
      </section>
    </main>
  );
}
