import type {
  AdminProductViewModel,
  DashboardMetricViewModel,
  InventoryItemViewModel,
  OperationalAlertViewModel,
  OrderViewModel,
} from "@/domain/models";

export const dashboardMetrics: readonly DashboardMetricViewModel[] = [
  {
    label: "Chiffre d’affaires",
    value: "129 245,30 €",
    change: "+18,6 %",
    tone: "success",
    series: [12, 16, 14, 21, 15, 19, 25, 17],
  },
  {
    label: "Commandes",
    value: "342",
    change: "+14,2 %",
    tone: "info",
    series: [8, 14, 11, 16, 10, 15, 9, 18],
  },
  {
    label: "Conversion",
    value: "2,65 %",
    change: "+0,4 pt",
    tone: "info",
    series: [10, 13, 9, 12, 14, 11, 16, 17],
  },
  {
    label: "Panier moyen",
    value: "377,32 €",
    change: "+3,8 %",
    tone: "success",
    series: [15, 11, 16, 12, 17, 18, 13, 16],
  },
  {
    label: "Paiements réussis",
    value: "98,52 %",
    change: "+1,1 pt",
    tone: "success",
    series: [17, 14, 16, 12, 15, 13, 10, 16],
  },
];

export const adminProducts: readonly AdminProductViewModel[] = [
  {
    id: "p1",
    name: "NOMA Runner 2.0",
    variant: "Blanc / Gris clair",
    sku: "NMA-RUN-20-WG-42",
    category: "Sneakers",
    price: 129,
    stock: 42,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "16/05/2026 10:24",
    art: "shoe",
  },
  {
    id: "p2",
    name: "NOMA Runner 2.0",
    variant: "Noir / Anthracite",
    sku: "NMA-RUN-20-BA-42",
    category: "Sneakers",
    price: 129,
    stock: 18,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "16/05/2026 10:18",
    art: "shoe",
  },
  {
    id: "p3",
    name: "NOMA Court Classic",
    variant: "Blanc / Marine",
    sku: "NMA-CRT-CL-WM-41",
    category: "Sneakers",
    price: 109,
    stock: 0,
    visibility: "Visible",
    status: "Rupture",
    updatedAt: "16/05/2026 09:58",
    art: "shoe",
  },
  {
    id: "p4",
    name: "NOMA Lampe Oslo",
    variant: "Lin naturel",
    sku: "NMA-LMP-OSL-LN",
    category: "Maison",
    price: 89,
    stock: 27,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "16/05/2026 09:32",
    art: "lamp",
  },
  {
    id: "p5",
    name: "NOMA Sac à dos Street",
    variant: "Noir",
    sku: "NMA-BAG-ST-BK",
    category: "Accessoires",
    price: 79,
    stock: 6,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "16/05/2026 09:15",
    art: "bag",
  },
  {
    id: "p6",
    name: "NOMA Sac à dos Travel",
    variant: "Beige",
    sku: "NMA-BAG-TR-BG",
    category: "Accessoires",
    price: 99,
    stock: 2,
    visibility: "Masqué",
    status: "Brouillon",
    updatedAt: "15/05/2026 18:33",
    art: "bag",
  },
  {
    id: "p7",
    name: "NOMA Casque Audio",
    variant: "Noir",
    sku: "NMA-HDP-100-BK",
    category: "Électronique",
    price: 149,
    stock: 0,
    visibility: "Visible",
    status: "Rupture",
    updatedAt: "15/05/2026 16:47",
    art: "headphones",
  },
  {
    id: "p8",
    name: "NOMA Court Retro",
    variant: "Blanc / Gum",
    sku: "NMA-CRT-RT-WG-42",
    category: "Sneakers",
    price: 119,
    stock: 34,
    visibility: "Visible",
    status: "Archivé",
    updatedAt: "15/05/2026 11:21",
    art: "shoe",
  },
  {
    id: "p9",
    name: "NOMA Trail 1.0",
    variant: "Kaki / Noir",
    sku: "NMA-TRL-10-KN-42",
    category: "Sneakers",
    price: 139,
    stock: 11,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "15/05/2026 09:08",
    art: "shoe",
  },
  {
    id: "p10",
    name: "NOMA Lampe Kyoto",
    variant: "Céramique sable",
    sku: "NMA-LMP-KYT-SB",
    category: "Maison",
    price: 119,
    stock: 15,
    visibility: "Visible",
    status: "Actif",
    updatedAt: "14/05/2026 17:53",
    art: "lamp",
  },
];

const statusSequence: readonly OrderViewModel["status"][] = [
  "Expédiée",
  "Traitement",
  "Expédiée",
  "Livrée",
  "Traitement",
  "Livrée",
  "Annulée",
  "Remboursement demandé",
  "Expédiée",
  "Annulée",
  "Livrée",
  "Révision fraude",
];
const fulfillmentSequence: readonly OrderViewModel["fulfillment"][] = [
  "IN_TRANSIT",
  "PROCESSING",
  "SHIPPED",
  "DELIVERED",
  "PROCESSING",
  "DELIVERED",
  "CANCELLED",
  "REFUND_REQUESTED",
  "IN_TRANSIT",
  "CANCELLED",
  "DELIVERED",
  "FRAUD_REVIEW",
];
const paymentSequence: readonly OrderViewModel["payment"][] = [
  "CAPTURED",
  "CAPTURED",
  "CAPTURED",
  "CAPTURED",
  "AUTHORISED",
  "CAPTURED",
  "CAPTURED",
  "REFUNDED",
  "CAPTURED",
  "AUTHORISATION_FAILED",
  "CAPTURED",
  "CAPTURED",
];

export const orders: readonly OrderViewModel[] = Array.from(
  { length: 12 },
  (_, index) => ({
    id: `ORD-2026-${String(8471 - index).padStart(6, "0")}`,
    date:
      index < 6
        ? `16/05/2026 ${["10:24", "10:18", "09:58", "09:32", "09:15", "08:33"][index]}`
        : `15/05/2026 ${String(18 - index).padStart(2, "0")}:20`,
    customerReference: `PO-${5578 - index}`,
    customerName:
      ["Jean Dupont", "Sophie Martin", "Lucas Bernard", "Alice Moreau"][
        index % 4
      ] ?? "Client NOMA",
    amount:
      [129.9, 89, 109, 149, 79, 99, 149, 119, 139, 89, 109, 159][index] ?? 99,
    payment: paymentSequence[index] ?? "CAPTURED",
    fulfillment: fulfillmentSequence[index] ?? "PROCESSING",
    risk:
      index === 11
        ? "HIGH"
        : index === 4 || index === 6 || index === 9
          ? "MEDIUM"
          : "LOW",
    shipping:
      index === 6 || index === 7 || index === 9 || index === 11
        ? "—"
        : `${index % 2 ? "Chronopost" : "Colissimo"}\n6JX${123456789 + index}FR`,
    status: statusSequence[index] ?? "En attente",
  }),
);

export const inventory: readonly InventoryItemViewModel[] = Array.from(
  { length: 10 },
  (_, index) => {
    const available = [184, 120, 42, 0, 6, 210, 15, 320, 2, 58][index] ?? 0;
    const reserved = [16, 10, 8, 4, 2, 20, 5, 30, 1, 6][index] ?? 0;
    return {
      sku: `SKU-NOMA-${String(471 + Math.floor(index / 3)).padStart(4, "0")}-${index % 2 ? "WHT" : "BLK"}-${["M", "L", "XL"][index % 3]}`,
      product:
        index < 5
          ? "NOMA Runner 2.0"
          : index < 8
            ? "NOMA Court Classic"
            : "NOMA Trail",
      variant: index % 2 ? "Blanc" : "Noir",
      available,
      reserved,
      onHand: available + reserved,
      reorderLevel: [100, 100, 60, 50, 50, 120, 60, 150, 40, 40][index] ?? 50,
      site: index > 6 ? "PAR-02" : "PAR-01",
      updatedAt: `16/05/2026 ${["10:24", "09:58", "09:32", "09:15", "08:47", "08:21", "08:05", "17:42", "16:18", "15:04"][index]}`,
    };
  },
);

export const operationalAlerts: readonly OperationalAlertViewModel[] = [
  {
    id: "a1",
    title: "Échecs de paiement",
    detail: "5 paiements · 8 453,20 €",
    time: "10:24",
    count: 5,
    severity: "critical",
  },
  {
    id: "a2",
    title: "Révisions fraude",
    detail: "3 commandes · 2 148,90 €",
    time: "10:21",
    count: 3,
    severity: "critical",
  },
  {
    id: "a3",
    title: "Ruptures de stock",
    detail: "4 SKU · 1 024 unités",
    time: "10:18",
    count: 4,
    severity: "warning",
  },
  {
    id: "a4",
    title: "Exceptions livraison",
    detail: "3 en retard · 2 en échec",
    time: "10:16",
    count: 3,
    severity: "warning",
  },
];
