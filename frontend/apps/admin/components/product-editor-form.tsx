"use client";

import { Button, ProductArt } from "@noma/ui";
import { CheckCircle2, Eye, Plus, TriangleAlert } from "lucide-react";
import { useState } from "react";

export function ProductEditorForm() {
  const [dirty, setDirty] = useState(true);
  const [saved, setSaved] = useState(false);
  function markDirty() {
    setDirty(true);
    setSaved(false);
  }
  function save() {
    setDirty(false);
    setSaved(true);
  }
  return (
    <form
      className="editor-layout"
      onSubmit={(event) => {
        event.preventDefault();
        save();
      }}
    >
      <div className="editor-main">
        {dirty ? (
          <p className="unsaved-banner">
            <TriangleAlert aria-hidden="true" /> Modifications non enregistrées
          </p>
        ) : null}
        {saved ? (
          <p className="saved-banner" role="status">
            <CheckCircle2 aria-hidden="true" /> Modifications enregistrées dans
            le mock local
          </p>
        ) : null}
        <div
          className="editor-tabs"
          role="tablist"
          aria-label="Sections produit"
        >
          <button type="button" role="tab" aria-selected="true">
            Général
          </button>
          <button type="button" role="tab">
            Médias
          </button>
          <button type="button" role="tab">
            Variantes / SKU
          </button>
          <button type="button" role="tab">
            Tarification
          </button>
          <button type="button" role="tab">
            Inventaire
          </button>
          <button type="button" role="tab">
            Historique d’audit
          </button>
        </div>
        <section className="form-card noma-panel">
          <div className="form-grid">
            <label>
              Nom du produit <b>*</b>
              <input
                className="noma-field"
                defaultValue="Baskets NOMA Court"
                onChange={markDirty}
              />
            </label>
            <label>
              Marque <b>*</b>
              <select
                className="noma-field"
                defaultValue="NOMA"
                onChange={markDirty}
              >
                <option>NOMA</option>
              </select>
            </label>
            <label className="wide-field">
              Description du produit <b>*</b>
              <textarea
                className="noma-field"
                rows={6}
                defaultValue="Les Baskets NOMA Court allient style minimaliste et confort au quotidien. Contenu de démonstration à valider."
                onChange={markDirty}
              />
            </label>
            <label>
              Catégorie <b>*</b>
              <select
                className="noma-field"
                defaultValue="Sneakers"
                onChange={markDirty}
              >
                <option>Sneakers</option>
                <option>Maison</option>
              </select>
            </label>
            <label>
              Statut <b>*</b>
              <select
                className="noma-field"
                defaultValue="Actif"
                onChange={markDirty}
              >
                <option>Actif</option>
                <option>Brouillon</option>
              </select>
            </label>
          </div>
          <fieldset className="media-fieldset">
            <legend>Médias de démonstration</legend>
            <div className="media-grid">
              {[0, 1, 2, 3].map((index) => (
                <button
                  key={index}
                  type="button"
                  aria-label={`Sélectionner le média ${index + 1}`}
                >
                  <ProductArt kind="shoe" compact />
                </button>
              ))}
              <button type="button" className="add-media">
                <Plus aria-hidden="true" />
                Ajouter
                <br />
                un média
              </button>
            </div>
            <small>
              Illustrations temporaires — ASSET_REQUIRED avant production.
            </small>
          </fieldset>
        </section>
        <div className="editor-bottom-grid">
          <section className="form-card noma-panel">
            <h2>Variante sélectionnée</h2>
            <div className="variant-row">
              <ProductArt kind="shoe" compact />
              <p>
                <strong>Noir / 42</strong>
                <small>SKU : NMA-CRT-BK-42</small>
              </p>
              <StatusPill />
            </div>
            <dl>
              <div>
                <dt>Couleur</dt>
                <dd>Noir</dd>
              </div>
              <div>
                <dt>Taille</dt>
                <dd>42</dd>
              </div>
              <div>
                <dt>Stock</dt>
                <dd>18 unités</dd>
              </div>
            </dl>
          </section>
          <section className="form-card noma-panel">
            <h2>Tarification (EUR)</h2>
            <div className="form-grid">
              <label>
                Prix de vente <b>*</b>
                <input
                  className="noma-field"
                  defaultValue="129,00"
                  onChange={markDirty}
                />
              </label>
              <label>
                Prix comparé
                <input
                  className="noma-field"
                  defaultValue="159,00"
                  onChange={markDirty}
                />
              </label>
              <label>
                Coût
                <input
                  className="noma-field"
                  defaultValue="58,00"
                  onChange={markDirty}
                />
              </label>
              <label>
                Marge
                <input className="noma-field" value="55,04 %" readOnly />
              </label>
            </div>
          </section>
        </div>
      </div>
      <aside className="editor-aside">
        <div className="editor-actions">
          <Button variant="secondary" type="button">
            <Eye aria-hidden="true" /> Aperçu
          </Button>
          <Button variant="secondary" type="submit">
            Enregistrer
          </Button>
          <Button type="button" onClick={save}>
            Publier
          </Button>
        </div>
        <section className="form-card noma-panel">
          <h2>Publication</h2>
          {[
            "Informations générales complètes",
            "Médias",
            "Variantes / SKU",
            "Tarification",
            "Inventaire",
          ].map((item) => (
            <p className="check-line" key={item}>
              <CheckCircle2 aria-hidden="true" />
              {item}
            </p>
          ))}
        </section>
        <section className="form-card noma-panel">
          <h2>Aperçu boutique</h2>
          <div className="preview-product">
            <ProductArt kind="shoe" compact />
            <p>
              <strong>Baskets NOMA Court</strong>
              <small>NOMA</small>
              <b>129,00 €</b>
            </p>
          </div>
        </section>
        <section className="form-card noma-panel">
          <h2>Résumé inventaire</h2>
          <dl className="summary-list">
            <div>
              <dt>Stock total</dt>
              <dd>78 unités</dd>
            </div>
            <div>
              <dt>Réservé</dt>
              <dd>12 unités</dd>
            </div>
            <div>
              <dt>Disponible</dt>
              <dd className="success-text">66 unités</dd>
            </div>
          </dl>
        </section>
      </aside>
    </form>
  );
}

function StatusPill() {
  return (
    <span className="noma-badge" data-tone="success">
      Actif
    </span>
  );
}
