import type { ButtonHTMLAttributes, ReactNode } from "react";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger";
}) {
  return (
    <button
      className={`noma-button ${variant === "secondary" ? "noma-button--secondary" : ""} ${variant === "danger" ? "noma-button--danger" : ""} ${className}`.trim()}
      {...props}
    />
  );
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: BadgeTone;
}) {
  return (
    <span className="noma-badge" data-tone={tone}>
      {children}
    </span>
  );
}

export function Rating({ value, count }: { value: number; count?: number }) {
  const rounded = Math.round(value);
  return (
    <span
      role="img"
      aria-label={`${value.toLocaleString("fr-FR")} étoiles sur 5${count ? `, ${count} avis` : ""}`}
    >
      <span
        aria-hidden="true"
        style={{ color: "#e99a00", letterSpacing: "0.08em" }}
      >
        {Array.from({ length: 5 }, (_, index) =>
          index < rounded ? "★" : "☆",
        ).join("")}
      </span>
      {count ? (
        <span
          style={{ color: "var(--noma-muted)", marginInlineStart: "0.45rem" }}
        >
          ({count})
        </span>
      ) : null}
    </span>
  );
}

export function Price({
  amount,
  previous,
}: {
  amount: number;
  previous?: number;
}) {
  const formatter = new Intl.NumberFormat("fr-FR", {
    style: "currency",
    currency: "EUR",
  });
  return (
    <span className="noma-price">
      <strong>{formatter.format(amount)}</strong>{" "}
      {previous ? (
        <del style={{ color: "var(--noma-muted)", fontWeight: 400 }}>
          {formatter.format(previous)}
        </del>
      ) : null}
    </span>
  );
}
