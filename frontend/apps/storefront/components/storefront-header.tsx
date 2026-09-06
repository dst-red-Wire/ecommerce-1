import { Menu, Search, ShoppingBag, UserRound } from "lucide-react";
import Link from "next/link";

export function StorefrontHeader() {
  return (
    <header className="store-header">
      <div className="service-strip" aria-label="Services NOMA">
        <span>▱ Livraison offerte dès 60 €</span>
        <span aria-hidden="true">|</span>
        <span>↻ Retours sous 30 jours</span>
      </div>
      <div className="store-nav">
        <Link className="brand" href="/" aria-label="NOMA, accueil">
          NOMA
        </Link>
        <nav className="desktop-nav" aria-label="Navigation principale">
          <Link href="/catalogue">Nouveautés</Link>
          <Link href="/catalogue?category=Maison">Maison</Link>
          <Link href="/catalogue?category=Mode">Mode</Link>
          <Link href="/catalogue?category=Électronique">Électronique</Link>
          <Link href="/catalogue?category=Accessoires">Accessoires</Link>
        </nav>
        <div className="header-actions">
          <button
            className="header-icon mobile-only"
            type="button"
            aria-label="Ouvrir le menu"
          >
            <Menu aria-hidden="true" />
          </button>
          <button
            className="header-icon"
            type="button"
            aria-label="Compte de démonstration non connecté"
          >
            <UserRound aria-hidden="true" />
          </button>
          <button
            className="header-icon"
            type="button"
            aria-label="Panier, vide"
          >
            <ShoppingBag aria-hidden="true" />
          </button>
        </div>
        <form className="header-search" action="/catalogue" role="search">
          <label className="sr-only" htmlFor="global-search">
            Rechercher un produit
          </label>
          <Search aria-hidden="true" />
          <input
            id="global-search"
            name="q"
            type="search"
            placeholder="Rechercher un produit"
          />
        </form>
      </div>
    </header>
  );
}
