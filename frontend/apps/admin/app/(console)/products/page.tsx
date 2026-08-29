import { Button } from "@noma/ui";
import Link from "next/link";

import { getAdminProducts } from "@/application/admin";
import { PageHeader } from "@/components/admin-ui";
import { ProductsTable } from "@/components/products-table";

export default async function ProductsPage() {
  const products = await getAdminProducts();
  return (
    <main className="admin-page" id="main">
      <PageHeader
        eyebrow="Tableau de bord / Produits"
        title="Produits"
        actions={<Button type="button">Ajouter un produit</Button>}
      />
      <ProductsTable products={products} />
      <p className="page-footnote">
        <Link href="/products/baskets-noma-court/edit">
          Ouvrir l’éditeur du produit de démonstration
        </Link>
      </p>
    </main>
  );
}
