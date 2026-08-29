"use client";

import { Button } from "@noma/ui";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return (
    <main id="main" className="store-main page-state">
      <p className="state-icon" aria-hidden="true">
        !
      </p>
      <h1>Une erreur est survenue</h1>
      <p>La démonstration n’a pas pu charger cette vue.</p>
      <Button onClick={reset}>Réessayer</Button>
    </main>
  );
}
