import type { Metadata } from "next";
import Link from "next/link";

import { getCatalogView } from "@/application/catalog";
import { CatalogExplorer } from "@/components/catalog-explorer";

export const metadata: Metadata = {
  title: "Nouveautés",
  description: "Parcourir les produits de démonstration NOMA.",
  alternates: { canonical: "/catalogue" },
};

export default async function CatalogPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const [{ q = "" }, products] = await Promise.all([
    searchParams,
    getCatalogView(),
  ]);
  return (
    <main id="main" className="store-main catalog-page">
      <nav className="breadcrumb" aria-label="Fil d’Ariane">
        <Link href="/">Accueil</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">Nouveautés</span>
      </nav>
      <div className="catalog-intro">
        <h1>Nouveautés</h1>
        <p>
          Découvrez nos derniers arrivages : des nouveautés pensées pour
          embellir votre quotidien.
        </p>
        <strong>{products.length * 6} produits</strong>
      </div>
      <CatalogExplorer products={products} initialQuery={q} />
    </main>
  );
}
