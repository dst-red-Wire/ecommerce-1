import Link from "next/link";

export default function NotFound() {
  return (
    <main id="main" className="store-main page-state">
      <p className="state-icon" aria-hidden="true">
        ?
      </p>
      <h1>Page introuvable</h1>
      <p>Cette page n’existe pas dans la démonstration NOMA.</p>
      <Link className="noma-button" href="/">
        Revenir à l’accueil
      </Link>
    </main>
  );
}
