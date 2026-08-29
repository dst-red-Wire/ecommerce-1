import { getInventory } from "@/application/admin";
import { PageHeader } from "@/components/admin-ui";
import { InventoryTable } from "@/components/inventory-table";

export default async function InventoryPage() {
  return (
    <main className="admin-page inventory-page" id="main">
      <PageHeader eyebrow="Tableau de bord / Inventory" title="Inventaire" />
      <InventoryTable inventory={await getInventory()} />
    </main>
  );
}
