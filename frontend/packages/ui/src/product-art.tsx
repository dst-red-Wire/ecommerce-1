import type { CSSProperties } from "react";

export type ProductArtKind =
  "shoe" | "lamp" | "bag" | "headphones" | "vase" | "throw" | "cap" | "mug";

const art: Record<ProductArtKind, { glyph: string; label: string }> = {
  shoe: { glyph: "⌁", label: "Illustration temporaire d'une paire de baskets" },
  lamp: { glyph: "◒", label: "Illustration temporaire d'une lampe" },
  bag: { glyph: "▱", label: "Illustration temporaire d'un sac à dos" },
  headphones: {
    glyph: "Ω",
    label: "Illustration temporaire d'un casque audio",
  },
  vase: { glyph: "♢", label: "Illustration temporaire d'un vase" },
  throw: { glyph: "≋", label: "Illustration temporaire d'un plaid" },
  cap: { glyph: "⌒", label: "Illustration temporaire d'une casquette" },
  mug: { glyph: "◧", label: "Illustration temporaire d'un mug" },
};

export function ProductArt({
  kind,
  compact = false,
  className = "",
}: {
  kind: ProductArtKind;
  compact?: boolean;
  className?: string;
}) {
  const item = art[kind];
  const style = {
    "--art-size": compact ? "3.2rem" : "clamp(5rem, 10vw, 9rem)",
  } as CSSProperties;
  return (
    <span
      className={`product-art product-art--${kind} ${className}`.trim()}
      role="img"
      aria-label={item.label}
      style={style}
    >
      <span aria-hidden="true">{item.glyph}</span>
    </span>
  );
}
