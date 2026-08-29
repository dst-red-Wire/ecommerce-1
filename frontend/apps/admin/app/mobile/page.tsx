import { getOperationalAlerts } from "@/application/admin";
import { MobileAlerts } from "@/components/mobile-alerts";

export default async function MobilePage() {
  return <MobileAlerts alerts={await getOperationalAlerts()} />;
}
