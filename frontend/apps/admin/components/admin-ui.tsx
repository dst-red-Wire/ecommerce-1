import { Badge, type BadgeTone } from "@noma/ui";
import type { ReactNode } from "react";

export function PageHeader({
  eyebrow,
  title,
  actions,
}: {
  eyebrow: string;
  title: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p>{eyebrow}</p>
        <h1>{title}</h1>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

const statusTones: Record<string, BadgeTone> = {
  Actif: "success",
  Visible: "success",
  Confirmée: "success",
  Livrée: "success",
  CAPTURED: "success",
  DELIVERED: "success",
  Brouillon: "info",
  Expédiée: "info",
  SHIPPED: "info",
  IN_TRANSIT: "info",
  AUTHORISED: "info",
  Traitement: "warning",
  "En attente": "warning",
  PROCESSING: "warning",
  "Remboursement demandé": "warning",
  REFUND_REQUESTED: "warning",
  MEDIUM: "warning",
  Rupture: "danger",
  Annulée: "danger",
  CANCELLED: "danger",
  FRAUD_REVIEW: "danger",
  "Révision fraude": "danger",
  AUTHORISATION_FAILED: "danger",
  HIGH: "danger",
  LOW: "success",
  REFUNDED: "neutral",
  Archivé: "neutral",
  Masqué: "neutral",
};

export function StatusBadge({ value }: { value: string }) {
  return (
    <Badge tone={statusTones[value] ?? "neutral"}>
      {value.replaceAll("_", " ")}
    </Badge>
  );
}

export function Sparkline({ values }: { values: readonly number[] }) {
  const max = Math.max(...values);
  const min = Math.min(...values);
  const points = values
    .map(
      (value, index) =>
        `${(index / (values.length - 1)) * 100},${30 - ((value - min) / Math.max(max - min, 1)) * 24}`,
    )
    .join(" ");
  return (
    <svg
      className="sparkline"
      viewBox="0 0 100 32"
      role="img"
      aria-label="Évolution de la métrique"
    >
      <polyline points={points} />
    </svg>
  );
}

export function AdminPagination({ total = "128" }: { total?: string }) {
  return (
    <div className="admin-pagination">
      <span>1–10 sur {total} résultats</span>
      <nav aria-label="Pagination">
        <button type="button">‹</button>
        <button type="button" aria-current="page">
          1
        </button>
        <button type="button">2</button>
        <button type="button">3</button>
        <span>…</span>
        <button type="button">13</button>
        <button type="button">›</button>
      </nav>
    </div>
  );
}
