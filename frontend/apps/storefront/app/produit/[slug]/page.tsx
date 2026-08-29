import { Price, Rating } from "@noma/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getCatalogView, getProductView } from "@/application/catalog";
import { ProductCard } from "@/components/product-card";
import { ProductGallery, ProductPurchase } from "@/components/product-purchase";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const product = await getProductView((await params).slug);
  if (!product) return { title: "Produit introuvable" };
  return {
    title: product.name,
    description: product.description,
    alternates: { canonical: `/produit/${product.slug}` },
  };
}

export default async function ProductPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const product = await getProductView((await params).slug);
  if (!product) notFound();
  const recommendations = (await getCatalogView())
    .filter((item) => item.id !== product.id)
    .slice(0, 4);
  return (
    <main id="main" className="store-main product-page">
      <nav className="breadcrumb" aria-label="Fil d’Ariane">
        <Link href="/">Accueil</Link>
        <span aria-hidden="true">/</span>
        <Link href="/catalogue">Nouveautés</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{product.name}</span>
      </nav>
      <div className="product-layout">
        <ProductGallery product={product} />
        <section
          className="purchase-panel noma-panel"
          aria-labelledby="product-title"
        >
          <h1 id="product-title">{product.name}</h1>
          <div className="product-rating">
            <Rating value={product.rating} />
            <strong>{product.rating}/5</strong>
            <span>|</span>
            <a href="#reviews">{product.reviewCount} avis</a>
          </div>
          <div className="product-price">
            <Price
              amount={product.price}
              {...(product.previousPrice !== undefined
                ? { previous: product.previousPrice }
                : {})}
            />
            <small>TVA incluse</small>
          </div>
          <ProductPurchase product={product} />
          <div className="purchase-reassurance">
            <span>
              ▱ <strong>Livraison offerte</strong>
              <br />
              dès 60 €
            </span>
            <span>
              ↻ <strong>Retours sous</strong>
              <br />
              30 jours
            </span>
          </div>
        </section>
      </div>
      <div className="product-detail-grid">
        <section
          className="product-accordions"
          aria-label="Informations produit"
        >
          <details open>
            <summary>Description</summary>
            <p>{product.description}</p>
          </details>
          <details>
            <summary>Caractéristiques</summary>
            <p>
              Données de démonstration. Les caractéristiques définitives
              nécessitent un contenu validé.
            </p>
          </details>
          <details>
            <summary>Livraison et retours</summary>
            <p>
              Modalités illustratives, à confirmer avant intégration
              commerciale.
            </p>
          </details>
        </section>
        <section id="reviews" className="review-summary noma-panel">
          <h2>Avis clients</h2>
          <Rating value={product.rating} count={product.reviewCount} />
          {[5, 4, 3, 2, 1].map((score) => (
            <div key={score}>
              <span>{score} ★</span>
              <progress value={score === 5 ? 84 : 6 - score} max="100" />
              <span>{score === 5 ? 98 : 6 - score}</span>
            </div>
          ))}
        </section>
      </div>
      <section
        className="recommendations"
        aria-labelledby="recommendations-title"
      >
        <h2 id="recommendations-title">Vous aimerez aussi</h2>
        <div className="product-grid featured-grid">
          {recommendations.map((item) => (
            <ProductCard key={item.id} product={item} />
          ))}
        </div>
      </section>
    </main>
  );
}
