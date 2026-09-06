"use client";

import {
  Bell,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Package,
  Search,
  ShieldAlert,
  Truck,
  XCircle,
} from "lucide-react";
import { useState } from "react";

import type { OperationalAlertViewModel } from "@/domain/models";

const icons = [XCircle, ShieldAlert, Package, Truck] as const;

export function MobileAlerts({
  alerts,
}: {
  alerts: readonly OperationalAlertViewModel[];
}) {
  const [openId, setOpenId] = useState(alerts[0]?.id ?? "");
  const [acknowledged, setAcknowledged] = useState<readonly string[]>([]);
  return (
    <div className="mobile-monitor">
      <header>
        <strong>NOMA ADMIN</strong>
        <button type="button" aria-label="Notifications, cinq">
          <Bell aria-hidden="true" />
          <span>5</span>
        </button>
        <b>● PRODUCTION</b>
      </header>
      <label className="mobile-monitor-search">
        <Search aria-hidden="true" />
        <span className="sr-only">Rechercher</span>
        <input placeholder="Rechercher un ordre, un client, un SKU…" />
      </label>
      <main>
        <div className="mobile-title">
          <div>
            <p>Supervision locale</p>
            <h1>Urgences opérationnelles</h1>
          </div>
          <button type="button">
            ↻ Mise à jour
            <br />
            10:25
          </button>
        </div>
        <div className="alert-chips">
          <button type="button">
            Critique <b>8</b>
          </button>
          <button type="button">
            Avertissement <b>12</b>
          </button>
          <button type="button">
            Tous <b>20</b>
          </button>
        </div>
        <section className="alert-list" aria-label="Alertes opérationnelles">
          {alerts.map((alert, index) => {
            const Icon = icons[index] ?? Bell;
            const open = openId === alert.id;
            const done = acknowledged.includes(alert.id);
            return (
              <article
                key={alert.id}
                data-severity={alert.severity}
                data-open={open}
              >
                <button
                  className="alert-summary"
                  type="button"
                  onClick={() => setOpenId(open ? "" : alert.id)}
                  aria-expanded={open}
                >
                  <span className="alert-icon">
                    <Icon aria-hidden="true" />
                  </span>
                  <span>
                    <strong>
                      {alert.title} <b>{alert.count}</b>
                    </strong>
                    <small>{alert.detail}</small>
                  </span>
                  <time>{alert.time}</time>
                  {open ? (
                    <ChevronUp aria-hidden="true" />
                  ) : (
                    <ChevronDown aria-hidden="true" />
                  )}
                </button>
                {open ? (
                  <div className="alert-detail">
                    <h2>Contexte</h2>
                    <p>
                      Signal de démonstration détecté sur les quinze dernières
                      minutes.
                    </p>
                    <h2>Impact</h2>
                    <p>
                      Une vérification humaine est nécessaire avant toute action
                      réelle.
                    </p>
                    <hr />
                    <p>
                      <strong>Acteur</strong>
                      <br />
                      Alex Dupont — Administrateur simulé
                    </p>
                    <button
                      type="button"
                      disabled={done}
                      onClick={() =>
                        setAcknowledged((current) => [...current, alert.id])
                      }
                    >
                      {done ? (
                        <>
                          <CheckCircle2 aria-hidden="true" /> Accusé réception
                        </>
                      ) : (
                        "Accuser réception"
                      )}
                    </button>
                  </div>
                ) : null}
              </article>
            );
          })}
        </section>
        <section className="health-section">
          <h2>Santé opérationnelle</h2>
          <div>
            {alerts.map((alert, index) => (
              <article key={alert.id}>
                <span>{alert.title}</span>
                <strong>{index === 1 ? "8 453 €" : alert.count}</strong>
                <b>
                  {alert.severity === "critical" ? "Critique" : "Avertissement"}
                </b>
              </article>
            ))}
          </div>
        </section>
      </main>
      <nav className="mobile-bottom-nav" aria-label="Navigation mobile">
        <span>
          ▦<small>Dashboard</small>
        </span>
        <span aria-current="page">
          ♧<small>Alertes</small>
        </span>
        <span>
          ⌕<small>Recherche</small>
        </span>
        <span>
          AD<small>Compte</small>
        </span>
      </nav>
    </div>
  );
}
