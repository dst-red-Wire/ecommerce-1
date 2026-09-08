"use client";

import { Button, ProductArt } from "@noma/ui";
import { Check, Heart, Minus, Plus, ShoppingBag } from "lucide-react";
import Image from "next/image";
import { useState } from "react";

import type { ProductViewModel } from "@/domain/models";

export function ProductGallery({ product }: { product: ProductViewModel }) {
  const [active, setActive] = useState(0);
  return (
    <section className="product-gallery" aria-label={`Galerie de ${product.name}`}>
      <div className={`product-gallery__main product-gallery__variant-${active}`}>
        {product.media ? (
          <Image
            className="product-gallery__photo"
            src={product.media.url}
            alt={product.media.alt}
            fill
            sizes="(max-width: 900px) 100vw, 50vw"
            priority
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
        <button
          type="button"
          className="favorite-button"
          aria-label={`Ajouter ${product.name} aux favoris`}
        >
          <Heart aria-hidden="true" />
        </button>
      </div>
      <div className="product-thumbnails" aria-label="Vues du produit">
        {[
          "Vue principale",
          "Vue arrière",
          "Vue de dessus",
          "Détail matière",
          "Détail finition",
        ].map((label, index) => (
          <button
            key={label}
            type="button"
            aria-label={label}
            aria-pressed={active === index}
            onClick={() => setActive(index)}
          >
            <ProductArt kind={product.art} compact />
          </button>
        ))}
      </div>
    </section>
  );
}

export function ProductPurchase({ product }: { product: ProductViewModel }) {
  const [size, setSize] = useState(product.sizes[0] ?? "");
  const [quantity, setQuantity] = useState(1);
  const [message, setMessage] = useState("");

  return (
    <div className="purchase-controls">
      <div className="option-heading">
        <strong>Couleur</strong>
        <span>{product.colors[0]}</span>
      </div>
      <div className="color-options" aria-label="Couleur">
        {product.colors.map((color, index) => (
          <button
            key={color}
            type="button"
            aria-label={color}
            aria-pressed={index === 0}
            className={`color-swatch color-swatch--${index}`}
          />
        ))}
      </div>
      <div className="option-heading">
        <strong>Taille</strong>
        <button className="text-link" type="button">
          Guide des tailles
        </button>
      </div>
      <div className="size-options" aria-label="Taille">
        {product.sizes.map((item) => (
          <button
            key={item}
            type="button"
            aria-pressed={size === item}
            onClick={() => setSize(item)}
            disabled={item === "41"}
          >
            {item}
          </button>
        ))}
      </div>
      <p className={`stock-state stock-state--${product.availability}`}>
        <Check aria-hidden="true" />
        {product.availability === "unavailable"
          ? "Indisponible"
          : product.availability === "low"
            ? "Stock limité"
            : "En stock"}
      </p>
      <div className="quantity-control">
        <button
          type="button"
          onClick={() => setQuantity((value) => Math.max(1, value - 1))}
          aria-label="Réduire la quantité"
        >
          <Minus aria-hidden="true" />
        </button>
        <output aria-label="Quantité">{quantity}</output>
        <button
          type="button"
          onClick={() => setQuantity((value) => value + 1)}
          aria-label="Augmenter la quantité"
        >
          <Plus aria-hidden="true" />
        </button>
      </div>
      <Button
        className="add-to-cart"
        disabled={product.availability === "unavailable" || !size}
        onClick={() =>
          setMessage(`${quantity} × ${product.name} ajouté au panier de démonstration`)
        }
      >
        <ShoppingBag aria-hidden="true" /> Ajouter au panier
      </Button>
      {message ? (
        <output className="cart-toast">
          <Check aria-hidden="true" /> {message}
        </output>
      ) : null}
    </div>
  );
}
