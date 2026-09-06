import type { Metadata } from "next";

import { StorefrontFooter } from "@/components/storefront-footer";
import { StorefrontHeader } from "@/components/storefront-header";

import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://www.exemple.com"),
  title: { default: "NOMA — L’essentiel, mieux choisi", template: "%s | NOMA" },
  description:
    "NOMA, une sélection de produits utiles au quotidien. Démonstration frontend avec données simulées.",
  alternates: { canonical: "/" },
  openGraph: {
    title: "NOMA — L’essentiel, mieux choisi",
    description: "Une démonstration e-commerce premium et accessible.",
    type: "website",
    locale: "fr_FR",
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr" data-scroll-behavior="smooth">
      <body>
        <a className="skip-link" href="#main">
          Aller au contenu
        </a>
        <StorefrontHeader />
        {children}
        <StorefrontFooter />
      </body>
    </html>
  );
}
