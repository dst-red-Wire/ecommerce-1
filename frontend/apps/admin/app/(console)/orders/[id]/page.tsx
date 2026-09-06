import { Button, ProductArt } from "@noma/ui";
import { Check, MoreHorizontal, ShieldCheck, Truck } from "lucide-react";

import { getOrders } from "@/application/admin";
import { PageHeader, StatusBadge } from "@/components/admin-ui";

export default async function OrderDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const id = (await params).id;
  const order =
    (await getOrders()).find((item) => item.id === id) ??
    (await getOrders())[0];
  if (!order) return null;
  return (
    <main className="admin-page order-detail" id="main">
      <PageHeader
        eyebrow={`Tableau de bord / Orders / ${order.id}`}
        title={`Commande ${order.id}`}
        actions={
          <>
            <Button variant="secondary" type="button">
              Renvoyer la facture
            </Button>
            <Button variant="secondary" type="button">
              Créer un retour
            </Button>
            <button
              className="icon-action"
              type="button"
              aria-label="Autres actions"
            >
              <MoreHorizontal />
            </button>
          </>
        }
      />
      <div className="order-kpis">
        {[
          [
            "Montant total",
            `${order.amount.toFixed(2).replace(".", ",")} EUR`,
            null,
          ],
          ["Paiement", "Paiement capturé", Check],
          ["Risque", "Risque faible", ShieldCheck],
          ["Livraison", "En transit", Truck],
          ["Stock", "Réservé", null],
        ].map(([label, value, Icon]) => (
          <article className="noma-panel" key={String(label)}>
            <span>{String(label)}</span>
            <strong>
              {Icon ? <Icon aria-hidden="true" /> : null}
              {String(value)}
            </strong>
            <small>Donnée de démonstration</small>
          </article>
        ))}
      </div>
      <div className="order-detail-grid">
        <div className="order-detail-main">
          <section className="detail-card noma-panel">
            <h2>Articles commandés</h2>
            <div className="ordered-item">
              <ProductArt kind="shoe" compact />
              <p>
                <strong>NOMA Runner 2.0</strong>
                <small>Blanc / Gris clair · Taille EU 42</small>
              </p>
              <span>SKU-NMA-RUN-20-WG-42</span>
              <b>129,90 EUR</b>
            </div>
            <div className="snapshot-grid">
              <div>
                <h3>Détail des prix (instantané)</h3>
                <dl>
                  <div>
                    <dt>Sous-total</dt>
                    <dd>109,16 EUR</dd>
                  </div>
                  <div>
                    <dt>TVA (20%)</dt>
                    <dd>20,74 EUR</dd>
                  </div>
                  <div>
                    <dt>Livraison</dt>
                    <dd>0,00 EUR</dd>
                  </div>
                  <div>
                    <dt>Total</dt>
                    <dd>129,90 EUR</dd>
                  </div>
                </dl>
              </div>
              <div>
                <h3>TVA (instantané)</h3>
                <dl>
                  <div>
                    <dt>Taux</dt>
                    <dd>20 %</dd>
                  </div>
                  <div>
                    <dt>Base HT</dt>
                    <dd>109,16 EUR</dd>
                  </div>
                  <div>
                    <dt>Montant TVA</dt>
                    <dd>20,74 EUR</dd>
                  </div>
                </dl>
              </div>
            </div>
          </section>
          <section className="timeline-card noma-panel">
            <h2>Chronologie opérationnelle</h2>
            <ol>
              {[
                "Créée",
                "Paiement autorisé",
                "Confirmée",
                "Expédition créée",
                "Expédiée",
                "Livrée",
              ].map((step, index) => (
                <li key={step} data-complete={index < 5}>
                  <span>{index < 5 ? "✓" : ""}</span>
                  <strong>{step}</strong>
                  <small>
                    {index < 5 ? `16/05/2026 10:${24 + index}` : "—"}
                  </small>
                </li>
              ))}
            </ol>
          </section>
          <section className="address-grid">
            {[
              ["Client", "Jean Dupont\nclient@example.com"],
              [
                "Adresse de facturation",
                "12 rue de la Paix\n75002 Paris\nFrance",
              ],
              [
                "Adresse de livraison",
                "12 rue de la Paix\n75002 Paris\nFrance",
              ],
              ["Méthode de paiement", "Visa •••• 4242\nExp. 04/2027"],
              ["Transporteur", "Chronopost\n6JX123456789FR"],
            ].map(([title, content]) => (
              <article className="noma-panel" key={title}>
                <h3>{title}</h3>
                <p>{content}</p>
              </article>
            ))}
          </section>
        </div>
        <aside className="order-detail-side">
          <section className="detail-card noma-panel">
            <div
              className="detail-tabs"
              role="tablist"
              aria-label="Détails de commande"
            >
              <button type="button" role="tab" aria-selected="true">
                Facture
              </button>
              <button type="button" role="tab" aria-selected="false">
                Retours
              </button>
              <button type="button" role="tab" aria-selected="false">
                Remboursements
              </button>
              <button type="button" role="tab" aria-selected="false">
                Audit
              </button>
            </div>
            <h2>Facture #INV-2026-008471</h2>
            <StatusBadge value="Confirmée" />
            <p>Émise le 16/05/2026 10:24</p>
            <strong>129,90 EUR</strong>
          </section>
          {[
            "Retours",
            "Remboursements",
            "Notifications",
            "Historique d’audit",
          ].map((title) => (
            <section className="detail-card noma-panel" key={title}>
              <h2>{title}</h2>
              <p>
                {title === "Notifications"
                  ? "Confirmation de commande envoyée à client@example.com"
                  : `Aucun élément ${title.toLocaleLowerCase("fr")} pour cette démonstration.`}
              </p>
            </section>
          ))}
        </aside>
      </div>
    </main>
  );
}
