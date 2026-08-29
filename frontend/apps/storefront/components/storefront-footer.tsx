import Link from "next/link";

export function StorefrontFooter() {
  return (
    <footer className="store-footer">
      <div className="footer-brand">NOMA</div>
      <nav aria-label="Pied de page">
        <span>À propos</span>
        <span>Livraison</span>
        <span>Retours</span>
        <span>CGV</span>
        <span>Contact</span>
      </nav>
      <div
        className="footer-social"
        aria-label="Réseaux sociaux de démonstration"
      >
        <span aria-label="Instagram">◎</span>
        <span aria-label="Pinterest">Ⓟ</span>
        <span aria-label="Facebook">ⓕ</span>
      </div>
      <small>© 2026 NOMA. Interface de démonstration.</small>
      <Link className="sr-only" href="#main">
        Revenir au contenu
      </Link>
    </footer>
  );
}
