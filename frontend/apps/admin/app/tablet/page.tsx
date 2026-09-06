import { getDashboardMetrics, getOrders } from "@/application/admin";
import { Sparkline, StatusBadge } from "@/components/admin-ui";
import { ProductArt } from "@noma/ui";
import Link from "next/link";

export default async function TabletPage() {
  const [metrics, orders] = await Promise.all([
    getDashboardMetrics(),
    getOrders(),
  ]);
  return (
    <div className="tablet-view">
      <header>
        <strong>NOMA ADMIN</strong>
        <label>
          <span className="sr-only">Recherche</span>
          <input placeholder="Rechercher une commande, un client, un produit…" />
        </label>
        <span>AD Alex Dupont</span>
        <b>PREVIEW</b>
      </header>
      <aside>
        <Link href="/">Dashboard</Link>
        <Link href="/products">Produits</Link>
        <Link href="/inventory">Inventaire</Link>
        <Link href="/orders">Commandes</Link>
        <Link href="/payments/PAY-2026-008471">Paiements</Link>
        <Link href="/mobile">Alertes</Link>
      </aside>
      <main>
        <h1>Suivi opérationnel</h1>
        <p>Données mises à jour le 16/05/2026 10:25 · Canal Web</p>
        <section className="tablet-metrics">
          {metrics.slice(0, 4).map((metric) => (
            <article className="noma-panel" key={metric.label}>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
              <em>↑ {metric.change}</em>
              <Sparkline values={metric.series} />
            </article>
          ))}
        </section>
        <section className="tablet-panels">
          <article className="noma-panel">
            <h2>Actions requises</h2>
            <p>
              <strong>Stock faible</strong>
              <span>96 produits en stock faible</span>
            </p>
            <p>
              <strong>Révision fraude</strong>
              <span>28 commandes à examiner</span>
            </p>
          </article>
          <article className="noma-panel">
            <h2>Chiffre d’affaires</h2>
            <strong>312 540,00 €</strong>
            <Sparkline values={[4, 8, 5, 11, 6, 14, 8, 10, 12, 7, 15, 11]} />
          </article>
        </section>
        <section className="data-panel noma-panel">
          <h2>Commandes récentes</h2>
          <div
            className="table-scroll"
            tabIndex={0}
            aria-label="Commandes récentes, défilement horizontal"
          >
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Commande</th>
                  <th>Client</th>
                  <th>Statut</th>
                  <th>Paiement</th>
                  <th>Montant</th>
                </tr>
              </thead>
              <tbody>
                {orders.slice(0, 5).map((order) => (
                  <tr key={order.id}>
                    <td>{order.id}</td>
                    <td>{order.customerName}</td>
                    <td>
                      <StatusBadge value={order.status} />
                    </td>
                    <td>
                      <StatusBadge value={order.payment} />
                    </td>
                    <td>{order.amount.toFixed(2)} EUR</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
      <section className="tablet-drawer">
        <div>
          <h2>ORD-2026-008471</h2>
          <StatusBadge value="Confirmée" />
        </div>
        <article>
          <span>Client</span>
          <strong>Jean Dupont</strong>
          <small>client@example.com</small>
        </article>
        <article className="tablet-item">
          <ProductArt kind="shoe" compact />
          <p>
            <strong>NOMA Runner 2.0</strong>
            <small>Blanc / Gris clair</small>
          </p>
          <b>129,90 EUR</b>
        </article>
        <article>
          <span>Livraison</span>
          <strong>En transit</strong>
          <small>Chronopost · 6JX123456789FR</small>
        </article>
      </section>
    </div>
  );
}
