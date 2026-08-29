import type { BadgeTone, ProductArtKind } from "@noma/ui";

export interface DashboardMetricViewModel {
  label: string;
  value: string;
  change: string;
  tone: BadgeTone;
  series: readonly number[];
}

export interface AdminProductViewModel {
  id: string;
  name: string;
  variant: string;
  sku: string;
  category: string;
  price: number;
  stock: number;
  visibility: "Visible" | "Masqué";
  status: "Actif" | "Brouillon" | "Rupture" | "Archivé";
  updatedAt: string;
  art: ProductArtKind;
}

export interface OrderViewModel {
  id: string;
  date: string;
  customerReference: string;
  customerName: string;
  amount: number;
  payment: "CAPTURED" | "AUTHORISED" | "REFUNDED" | "AUTHORISATION_FAILED";
  fulfillment:
    | "IN_TRANSIT"
    | "PROCESSING"
    | "SHIPPED"
    | "DELIVERED"
    | "CANCELLED"
    | "REFUND_REQUESTED"
    | "FRAUD_REVIEW";
  risk: "LOW" | "MEDIUM" | "HIGH";
  shipping: string;
  status:
    | "En attente"
    | "Confirmée"
    | "Traitement"
    | "Expédiée"
    | "Livrée"
    | "Annulée"
    | "Remboursement demandé"
    | "Révision fraude";
}

export interface InventoryItemViewModel {
  sku: string;
  product: string;
  variant: string;
  available: number;
  reserved: number;
  onHand: number;
  reorderLevel: number;
  site: string;
  updatedAt: string;
}

export interface OperationalAlertViewModel {
  id: string;
  title: string;
  detail: string;
  time: string;
  count: number;
  severity: "critical" | "warning";
}
