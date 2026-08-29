import {
  adminProducts,
  dashboardMetrics,
  inventory,
  operationalAlerts,
  orders,
} from "@/fixtures/admin-data";
import type { AdminRepository } from "@/ports/admin-repository";

export const mockAdminRepository: AdminRepository = {
  async getDashboardMetrics() {
    return dashboardMetrics;
  },
  async listProducts() {
    return adminProducts;
  },
  async listOrders() {
    return orders;
  },
  async listInventory() {
    return inventory;
  },
  async listOperationalAlerts() {
    return operationalAlerts;
  },
};
