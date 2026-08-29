import { mockAdminRepository } from "@/adapters/mock-admin-repository";

// Phase 1 composition root. No authorization or backend connectivity is implied.
const adminRepository = mockAdminRepository;

export const getDashboardMetrics = () => adminRepository.getDashboardMetrics();
export const getAdminProducts = () => adminRepository.listProducts();
export const getOrders = () => adminRepository.listOrders();
export const getInventory = () => adminRepository.listInventory();
export const getOperationalAlerts = () =>
  adminRepository.listOperationalAlerts();
