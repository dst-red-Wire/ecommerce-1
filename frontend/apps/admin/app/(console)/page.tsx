import { Button } from "@noma/ui";
import {
  ArrowRight,
  Box,
  RotateCcw,
  ShieldAlert,
  ShoppingCart,
  Truck,
} from "lucide-react";
import Link from "next/link";

import { getDashboardMetrics, getOrders } from "@/application/admin";
import { PageHeader, Sparkline, StatusBadge } from "@/components/admin-ui";

export default async function DashboardPage() {
  const [metrics, orders] = await Promise.all([
    getDashboardMetrics(),
    getOrders(),
  ]);
  const actions = [
    {
      label: "Commandes en attente",
      value: "15",
      detail: "Nécessitent une action",
      icon: ShoppingCart,
      tone: "danger",
    },
    {
      label: "Stock faible",
      value: "23",
      detail: "Produits sous le seuil",
      icon: Box,
      tone: "warning",
    },
    {
      label: "Retours à traiter",
      value: "8",
      detail: "En attente de validation",
      icon: RotateCcw,
      tone: "warning",
    },
    {
      label: "Révisions fraude",
      value: "3",
      detail: "Transactions à examiner",
      icon: ShieldAlert,
      tone: "danger",
    },
    {
      label: "Exceptions livraison",
      value: "6",
      detail: "Problèmes d’expédition",
      icon: Truck,
      tone: "warning",
    },
  ] as const;
  return (
    <main className="admin-page" id="main">
      <PageHeader
        eyebrow="Vue d’ensemble"
        title="Tableau de bord"
        actions={
          <Link className="preview-link" href="/tablet">
            Voir la vue tablette
          </Link>
        }
      />
      <section className="metric-grid" aria-label="Indicateurs clés">
        {metrics.map((metric) => (
          <article className="metric-card noma-panel" key={metric.label}>
            <p>{metric.label}</p>
            <strong>{metric.value}</strong>
            <span className="success-text">↑ {metric.change}</span>
            <Sparkline values={metric.series} />
          </article>
        ))}
      </section>
      <section className="action-section noma-panel">
        <h2>Actions requises</h2>
        <div className="action-grid">
          {actions.map(({ icon: Icon, ...action }) => (
            <article key={action.label} data-tone={action.tone}>
              <Icon aria-hidden="true" />
              <div>
                <p>{action.label}</p>
                <strong>{action.value}</strong>
                <small>{action.detail}</small>
              </div>
              <Button variant="secondary" type="button">
                Voir
              </Button>
            </article>
          ))}
        </div>
      </section>
      <section className="chart-grid">
        <article className="chart-card noma-panel">
          <h2>Chiffre d’affaires</h2>
          <div className="chart-legend">
            <span>Période actuelle</span>
            <span>Période précédente</span>
          </div>
          <svg
            viewBox="0 0 600 180"
            role="img"
            aria-label="Évolution du chiffre d’affaires sur sept jours"
          >
            <path
              className="grid-line"
              d="M0 30H600M0 75H600M0 120H600M0 165H600"
            />
            <polyline
              className="chart-previous"
              points="0,130 90,75 180,125 270,92 360,120 450,70 540,132 600,96"
            />
            <polyline
              className="chart-current"
              points="0,112 90,48 180,100 270,68 360,94 450,50 540,112 600,76"
            />
          </svg>
        </article>
        <article className="chart-card noma-panel">
          <h2>Commandes</h2>
          <div className="chart-legend">
            <span>Période actuelle</span>
            <span>Période précédente</span>
          </div>
          <svg
            viewBox="0 0 600 180"
            role="img"
            aria-label="Évolution des commandes"
          >
            <path
              className="grid-line"
              d="M0 30H600M0 75H600M0 120H600M0 165H600"
            />
            <polyline
              className="chart-previous"
              points="0,135 90,90 180,130 270,87 360,139 450,96 540,130 600,105"
            />
            <polyline
              className="chart-current"
              points="0,105 90,48 180,93 270,55 360,112 450,72 540,108 600,82"
            />
          </svg>
        </article>
      </section>
      <section className="dashboard-bottom">
        <article className="data-panel noma-panel">
          <h2>Activité récente</h2>
          <div className="table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Commande</th>
                  <th>Client</th>
                  <th>Statut</th>
                  <th>Total</th>
                  <th>Date</th>
                  <th>Paiement</th>
                </tr>
              </thead>
              <tbody>
                {orders.slice(0, 5).map((order) => (
                  <tr key={order.id}>
                    <td>
                      <Link href={`/orders/${order.id}`}>{order.id}</Link>
                    </td>
                    <td>{order.customerName}</td>
                    <td>
                      <StatusBadge value={order.status} />
                    </td>
                    <td>{order.amount.toFixed(2).replace(".", ",")} €</td>
                    <td>{order.date}</td>
                    <td>Visa •••• 4242</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
        <article className="quick-actions noma-panel">
          <h2>Actions rapides</h2>
          {[
            "Créer une commande",
            "Ajouter un produit",
            "Gérer les prix",
            "Importer des produits",
            "Exporter les commandes",
            "Voir tous les clients",
          ].map((item) => (
            <button type="button" key={item}>
              {item}
              <ArrowRight aria-hidden="true" />
            </button>
          ))}
        </article>
      </section>
    </main>
  );
}
