import Link from "next/link";

export default function NotFound() {
  return (
    <main className="admin-state">
      <h1>Vue non implémentée</h1>
      <p>
        Cette entrée de navigation appartient à une future milestone métier.
      </p>
      <Link className="noma-button" href="/">
        Revenir au tableau de bord
      </Link>
    </main>
  );
}
