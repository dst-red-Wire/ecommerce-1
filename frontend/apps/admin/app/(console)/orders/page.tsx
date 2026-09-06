import { getOrders } from "@/application/admin";
import { PageHeader } from "@/components/admin-ui";
import { OrdersTable } from "@/components/orders-table";

export default async function OrdersPage() {
  return (
    <main className="admin-page" id="main">
      <PageHeader eyebrow="Tableau de bord / Orders" title="Commandes" />
      <OrdersTable orders={await getOrders()} />
    </main>
  );
}
