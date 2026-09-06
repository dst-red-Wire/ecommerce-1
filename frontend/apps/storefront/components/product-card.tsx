import { Price, ProductArt, Rating } from "@noma/ui";
import { Heart } from "lucide-react";
import Image from "next/image";
import Link from "next/link";

import type { ProductViewModel } from "@/domain/models";

export function ProductCard({ product }: { product: ProductViewModel }) {
  return (
    <article className="product-card">
      <div className="product-card__media">
        {product.media ? (
          <Image
            className="product-card__photo"
            src={product.media.url}
            alt={product.media.alt}
            fill
            sizes="(max-width: 768px) 50vw, 25vw"
          />
        ) : (
          <ProductArt kind={product.art} />
        )}
        {product.media ? (
          <a
            className="product-media-credit"
            href={product.media.sourceUrl}
            target="_blank"
            rel="noreferrer"
          >
            Photo: {product.media.creator} / {product.media.provider}
          </a>
        ) : null}
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
