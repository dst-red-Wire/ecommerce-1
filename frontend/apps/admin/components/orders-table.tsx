"use client";

import { Download, Filter, MoreVertical, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import type { OrderViewModel } from "@/domain/models";
import { AdminPagination, StatusBadge } from "./admin-ui";

const tabs = [
  "En attente",
  "Confirmée",
  "Traitement",
  "Expédiée",
  "Livrée",
  "Annulée",
  "Remboursement demandé",
  "Révision fraude",
] as const;

export function OrdersTable({ orders }: { orders: readonly OrderViewModel[] }) {
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<string>("En attente");
  const visible = useMemo(
    () =>
      orders.filter(
        (order) =>
          !query ||
          `${order.id} ${order.customerReference} ${order.customerName}`
            .toLocaleLowerCase("fr")
            .includes(query.toLocaleLowerCase("fr")),
      ),
    [orders, query],
  );
  return (
    <section className="data-panel noma-panel">
      <div className="orders-toolbar">
        <label className="admin-search">
          <Search aria-hidden="true" />
          <span className="sr-only">Rechercher une commande</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rechercher une commande"
          />
        </label>
        <span />
        <button type="button">
          <Filter aria-hidden="true" /> Filtres avancés
        </button>
        <button type="button">Vues enregistrées⌄</button>
        <button type="button">
          <Download aria-hidden="true" /> Exporter
        </button>
      </div>
      <div
        className="status-tabs"
        role="tablist"
        aria-label="Statut de commande"
      >
        {tabs.map((item, index) => (
          <button
            key={item}
            type="button"
            role="tab"
            aria-selected={tab === item}
            onClick={() => setTab(item)}
          >
            {item}
            <span>{[15, 214, 312, 892, 2451, 142, 18, 7][index]}</span>
          </button>
        ))}
      </div>
      <div className="bulk-toolbar">
        <strong>0 sélectionné</strong>
        <button type="button">Actions groupées⌄</button>
      </div>
      <div className="table-scroll">
        <table className="admin-table orders-table">
          <thead>
            <tr>
              <th>
                <span className="sr-only">Sélection</span>
              </th>
              <th>Commande</th>
              <th>Date</th>
              <th>Référence client</th>
              <th>Montant</th>
              <th>Paiement</th>
              <th>Exécution</th>
              <th>Risque</th>
              <th>Livraison</th>
              <th>Statut</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((order) => (
              <tr key={order.id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Sélectionner ${order.id}`}
                  />
                </td>
                <td>
                  <Link href={`/orders/${order.id}`}>{order.id}</Link>
                </td>
                <td>{order.date}</td>
                <td>{order.customerReference}</td>
                <td>{order.amount.toFixed(2).replace(".", ",")} EUR</td>
                <td>
                  <StatusBadge value={order.payment} />
                </td>
                <td>
                  <StatusBadge value={order.fulfillment} />
                </td>
                <td>
                  <StatusBadge value={order.risk} />
                </td>
                <td className="multiline-cell">{order.shipping}</td>
                <td>
                  <StatusBadge value={order.status} />
                </td>
                <td>
                  <button
                    className="icon-action"
                    type="button"
                    aria-label={`Actions ${order.id}`}
                  >
                    <MoreVertical aria-hidden="true" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <AdminPagination total="3 845" />
    </section>
  );
}
