"use client";

import { Button, ProductArt } from "@noma/ui";
import { Filter, MoreVertical, Search, X } from "lucide-react";
import { useState } from "react";

import type { InventoryItemViewModel } from "@/domain/models";
import { AdminPagination, StatusBadge } from "./admin-ui";

function inventoryStatus(item: InventoryItemViewModel) {
  if (item.available === 0 || item.available < item.reorderLevel * 0.15)
    return "Rupture";
  if (item.available < item.reorderLevel) return "Stock faible";
  return "En stock";
}

export function InventoryTable({
  inventory,
}: {
  inventory: readonly InventoryItemViewModel[];
}) {
  const [selected, setSelected] = useState(inventory[0] ?? null);
  const [quantity, setQuantity] = useState("20");
  const [confirmed, setConfirmed] = useState(false);
  return (
    <>
      <section
        className={`inventory-content ${selected ? "inventory-content--drawer" : ""}`}
      >
        <div className="inventory-filters">
          <label>
            Entrepôt / site
            <select className="noma-field">
              <option>Entrepôt principal — Paris (PAR-01)</option>
            </select>
          </label>
          <label className="admin-search">
            <Search aria-hidden="true" />
            <span className="sr-only">Rechercher un SKU</span>
            <input placeholder="Rechercher un SKU, un produit…" />
          </label>
          <button type="button">
            <span className="warning-dot" /> Stock faible
          </button>
          <button type="button">
            <span className="danger-dot" /> Rupture de stock
          </button>
          <button type="button">
            <Filter aria-hidden="true" /> Filtres
          </button>
        </div>
        <div className="inventory-kpis">
          {[
            ["Articles suivis", "1 284"],
            ["En stock", "1 102"],
            ["Stock faible", "96"],
            ["Rupture de stock", "86"],
            ["Quantité disponible", "28 456"],
            ["Valeur du stock", "312 540,00 €"],
          ].map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
        <div className="data-panel noma-panel">
          <div className="bulk-toolbar">
            <strong>{selected ? "1 sélectionné" : "0 sélectionné"}</strong>
            <button type="button">Ajustement groupé⌄</button>
          </div>
          <div
            className="table-scroll"
            tabIndex={0}
            aria-label="Inventaire, défilement horizontal"
          >
            <table className="admin-table">
              <thead>
                <tr>
                  <th>
                    <span className="sr-only">Sélection</span>
                  </th>
                  <th>SKU</th>
                  <th>Produit</th>
                  <th>Disponible</th>
                  <th>Réservé</th>
                  <th>En main</th>
                  <th>Niveau de réappro.</th>
                  <th>Site</th>
                  <th>Statut</th>
                  <th>Mis à jour</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {inventory.map((item) => (
                  <tr key={item.sku} data-selected={selected?.sku === item.sku}>
                    <td>
                      <input
                        type="radio"
                        name="inventory-item"
                        checked={selected?.sku === item.sku}
                        onChange={() => {
                          setSelected(item);
                          setConfirmed(false);
                        }}
                        aria-label={`Sélectionner ${item.sku}`}
                      />
                    </td>
                    <td>
                      <button
                        className="table-link"
                        type="button"
                        onClick={() => setSelected(item)}
                      >
                        {item.sku}
                      </button>
                    </td>
                    <td>
                      <strong>{item.product}</strong>
                      <small>{item.variant}</small>
                    </td>
                    <td>{item.available}</td>
                    <td>{item.reserved}</td>
                    <td>{item.onHand}</td>
                    <td>{item.reorderLevel}</td>
                    <td>{item.site}</td>
                    <td>
                      <StatusBadge value={inventoryStatus(item)} />
                    </td>
                    <td>{item.updatedAt}</td>
                    <td>
                      <MoreVertical aria-hidden="true" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <AdminPagination total="1 284" />
        </div>
        <section className="movement-panel noma-panel">
          <h2>Historique des mouvements</h2>
          <div
            className="table-scroll"
            tabIndex={0}
            aria-label="Historique des mouvements, défilement horizontal"
          >
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Type</th>
                  <th>SKU</th>
                  <th>Variation</th>
                  <th>Avant</th>
                  <th>Après</th>
                  <th>Site</th>
                  <th>Motif</th>
                  <th>Acteur</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>16/05/2026 10:24</td>
                  <td>Ajustement</td>
                  <td>SKU-NOMA-0471-BLK-M</td>
                  <td className="success-text">+20</td>
                  <td>180</td>
                  <td>200</td>
                  <td>PAR-01</td>
                  <td>Correction d’inventaire</td>
                  <td>Alex Dupont</td>
                </tr>
                <tr>
                  <td>15/05/2026 16:03</td>
                  <td>Vente</td>
                  <td>SKU-NOMA-0471-BLK-M</td>
                  <td>-1</td>
                  <td>181</td>
                  <td>180</td>
                  <td>PAR-01</td>
                  <td>Commande ORD-2026-008471</td>
                  <td>Système</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>
      {selected ? (
        <aside
          className="inventory-drawer"
          aria-labelledby="stock-drawer-title"
        >
          <div className="drawer-header">
            <h2 id="stock-drawer-title">Ajuster le stock</h2>
            <button
              type="button"
              onClick={() => setSelected(null)}
              aria-label="Fermer"
            >
              <X aria-hidden="true" />
            </button>
          </div>
          <div className="drawer-product">
            <ProductArt kind="shoe" compact />
            <p>
              <strong>{selected.sku}</strong>
              <span>{selected.product}</span>
              <small>
                {selected.variant} / {selected.site}
              </small>
            </p>
          </div>
          <h3>Comptes actuels</h3>
          <div className="stock-counts">
            <div>
              <span>Disponible</span>
              <strong>{selected.available}</strong>
            </div>
            <div>
              <span>Réservé</span>
              <strong>{selected.reserved}</strong>
            </div>
            <div>
              <span>En main</span>
              <strong>{selected.onHand}</strong>
            </div>
          </div>
          <label>
            Type d’ajustement <b>*</b>
            <select className="noma-field">
              <option>Ajustement d’inventaire</option>
            </select>
          </label>
          <label>
            Quantité <b>*</b>
            <input
              className="noma-field"
              value={quantity}
              onChange={(event) => setQuantity(event.target.value)}
              inputMode="numeric"
            />
          </label>
          <label>
            Motif obligatoire <b>*</b>
            <select className="noma-field">
              <option>Correction d’inventaire</option>
              <option>Comptage physique</option>
            </select>
          </label>
          <label>
            Notes
            <textarea
              className="noma-field"
              rows={4}
              defaultValue="Correction du comptage physique de démonstration."
            />
          </label>
          <div className="impact-summary">
            <h3>Impact de l’ajustement</h3>
            <p>
              <span>Avant en main</span>
              <strong>{selected.onHand}</strong>
            </p>
            <p>
              <span>Variation</span>
              <strong className="success-text">+{quantity || 0}</strong>
            </p>
            <p>
              <span>Après en main</span>
              <strong>{selected.onHand + (Number(quantity) || 0)}</strong>
            </p>
          </div>
          {confirmed ? (
            <p className="saved-banner" role="status">
              Ajustement simulé — aucune donnée backend modifiée.
            </p>
          ) : null}
          <div className="drawer-actions">
            <Button
              variant="secondary"
              type="button"
              onClick={() => setSelected(null)}
            >
              Annuler
            </Button>
            <Button type="button" onClick={() => setConfirmed(true)}>
              Confirmer l’ajustement
            </Button>
          </div>
        </aside>
      ) : null}
    </>
  );
}
