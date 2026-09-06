import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { operationalAlerts } from "@/fixtures/admin-data";
import { MobileAlerts } from "./mobile-alerts";

describe("MobileAlerts", () => {
  it("acknowledges an alert only in local UI state", () => {
    render(<MobileAlerts alerts={operationalAlerts} />);
    const acknowledge = screen.getByRole("button", {
      name: "Accuser réception",
    });
    fireEvent.click(acknowledge);

    expect(
      screen.getByRole("button", { name: /Accusé réception/ }),
    ).toBeDisabled();
  });
});
