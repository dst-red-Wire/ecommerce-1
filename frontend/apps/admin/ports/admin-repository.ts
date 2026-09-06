import type {
  AdminProductViewModel,
  DashboardMetricViewModel,
  InventoryItemViewModel,
  OperationalAlertViewModel,
  OrderViewModel,
} from "@/domain/models";

export interface AdminRepository {
  getDashboardMetrics(): Promise<readonly DashboardMetricViewModel[]>;
  listProducts(): Promise<readonly AdminProductViewModel[]>;
  listOrders(): Promise<readonly OrderViewModel[]>;
  listInventory(): Promise<readonly InventoryItemViewModel[]>;
  listOperationalAlerts(): Promise<readonly OperationalAlertViewModel[]>;
}
