import { Bell, CircleHelp, Menu, Search } from "lucide-react";

import { AdminNavigation } from "./admin-navigation";

export function AdminShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="admin-shell">
      <header className="admin-topbar">
        <div className="admin-brand">NOMA ADMIN</div>
        <button
          className="topbar-search"
          type="button"
          aria-label="Ouvrir la recherche globale de démonstration"
        >
          <Menu aria-hidden="true" />
          <span>Rechercher une commande, un client, un produit…</span>
          <kbd>⌘K</kbd>
        </button>
        <div className="topbar-actions">
          <button type="button" aria-label="Notifications, une nouvelle">
            <Bell aria-hidden="true" />
            <i />
          </button>
          <button type="button" aria-label="Aide">
            <CircleHelp aria-hidden="true" />
          </button>
          <div className="admin-user">
            <span>AD</span>
            <p>
              <strong>Alex Dupont</strong>
              <small>Administrateur simulé</small>
            </p>
          </div>
          <span className="environment-badge">PRODUCTION</span>
        </div>
        <button className="mobile-admin-search" type="button">
          <Search aria-hidden="true" />
          <span>Rechercher…</span>
        </button>
      </header>
      <AdminNavigation />
      <div className="admin-workspace">{children}</div>
    </div>
  );
}
