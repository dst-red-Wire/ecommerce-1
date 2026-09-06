import { Button } from "@noma/ui";

import { PageHeader, StatusBadge } from "@/components/admin-ui";
import { PaymentRefundDialog } from "@/components/payment-refund-dialog";

export default async function PaymentPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return (
    <main className="admin-page payment-page" id="main">
      <PageHeader
        eyebrow={`Tableau de bord / Payments / ${id}`}
        title={`Paiement ${id}`}
        actions={<PaymentRefundDialog />}
      />
      <div className="payment-layout">
        <section className="payment-main">
          {[
            ["Montant", "129,90 EUR"],
            ["Statut du paiement", "Paiement capturé"],
            ["Fournisseur de paiement", "Hyperswitch"],
            ["Références", "Clé d’idempotence : idem_6JX123456789FR"],
          ].map(([title, content]) => (
            <article className="detail-card noma-panel" key={title}>
              <h2>{title}</h2>
              {title === "Statut du paiement" ? (
                <StatusBadge value="CAPTURED" />
              ) : (
                <strong>{content}</strong>
              )}
              <p>Donnée de démonstration non connectée.</p>
            </article>
          ))}
        </section>
        <aside>
          {[
            ["Fraude & risque", "LOW — Décision acceptée"],
            ["Remboursements", "0,00 EUR"],
            ["Chronologie du paiement", "Autorisation 10:24 · Capture 10:25"],
            ["Métadonnées", "Commande ORD-2026-008471 · Visa •••• 4242"],
          ].map(([title, content]) => (
            <article className="detail-card noma-panel" key={title}>
              <h2>{title}</h2>
              <p>{content}</p>
              <Button variant="secondary" type="button">
                Voir le détail
              </Button>
            </article>
          ))}
        </aside>
      </div>
    </main>
  );
}
