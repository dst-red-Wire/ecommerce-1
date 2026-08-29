"use client";

import {
  Boxes,
  ClipboardList,
  CreditCard,
  Gauge,
  Package,
  RotateCcw,
  Settings,
  ShieldAlert,
  ShoppingBag,
  Star,
  Tags,
  Truck,
  Users,
  Warehouse,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const items = [
  { href: "/", label: "Tableau de bord", icon: Gauge },
  { href: "/products", label: "Products", icon: Package },
  { href: "/catalog", label: "Catalog", icon: Boxes },
  { href: "/pricing", label: "Pricing", icon: Tags },
  { href: "/inventory", label: "Inventory", icon: Warehouse },
  { href: "/orders", label: "Orders", icon: ShoppingBag, count: 15 },
  { href: "/payments/PAY-2026-008471", label: "Payments", icon: CreditCard },
  { href: "/returns", label: "Returns", icon: RotateCcw, count: 8 },
  { href: "/shipping", label: "Shipping", icon: Truck, count: 6 },
  { href: "/reviews", label: "Reviews", icon: Star },
  { href: "/fraud", label: "Fraud", icon: ShieldAlert, count: 3 },
  { href: "/users", label: "Users", icon: Users },
  { href: "/audit", label: "Audit", icon: ClipboardList },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

export function AdminNavigation() {
  const pathname = usePathname();
  return (
    <aside className="admin-sidebar">
      <nav aria-label="Navigation du backoffice">
        {items.map(({ href, label, icon: Icon, ...item }) => {
          const active =
            href === "/"
              ? pathname === "/"
              : pathname.startsWith(href.split("/").slice(0, 2).join("/"));
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? "page" : undefined}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
              {"count" in item ? <b>{item.count}</b> : null}
            </Link>
          );
        })}
      </nav>
      <button type="button" className="collapse-sidebar">
        ← <span>Réduire</span>
      </button>
    </aside>
  );
}
