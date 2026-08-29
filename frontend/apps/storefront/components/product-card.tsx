import { Price, ProductArt, Rating } from "@noma/ui";
import { Heart } from "lucide-react";
import Link from "next/link";

import type { ProductViewModel } from "@/domain/models";

export function ProductCard({ product }: { product: ProductViewModel }) {
  return (
    <article className="product-card">
      <div className="product-card__media">
        <ProductArt kind={product.art} />
        {product.badge ? (
          <span
            className={`product-flag ${product.availability === "unavailable" ? "product-flag--dark" : ""}`}
          >
            {product.badge}
          </span>
        ) : null}
        <button
          type="button"
          className="favorite-button"
          aria-label={`Ajouter ${product.name} aux favoris`}
        >
          <Heart aria-hidden="true" />
        </button>
      </div>
      <div className="product-card__body">
        <h3>
          <Link href={`/produit/${product.slug}`}>{product.name}</Link>
        </h3>
        <Rating value={product.rating} count={product.reviewCount} />
        <Price
          amount={product.price}
          {...(product.previousPrice !== undefined
            ? { previous: product.previousPrice }
            : {})}
        />
      </div>
    </article>
  );
}
