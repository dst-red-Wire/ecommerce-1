import { ProductEditorForm } from "@/components/product-editor-form";
import { PageHeader } from "@/components/admin-ui";

export default function ProductEditorPage() {
  return (
    <main className="admin-page editor-page" id="main">
      <PageHeader
        eyebrow="Tableau de bord / Produits / Baskets NOMA Court"
        title="Baskets NOMA Court"
      />
      <ProductEditorForm />
    </main>
  );
}
