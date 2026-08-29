import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "NOMA Admin", template: "%s | NOMA Admin" },
  description: "Backoffice NOMA de démonstration avec données simulées.",
  robots: { index: false, follow: false },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
