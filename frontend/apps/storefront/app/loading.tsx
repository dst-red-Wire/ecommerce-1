export default function Loading() {
  return (
    <main id="main" className="store-main page-state" aria-busy="true">
      <div className="skeleton-block" />
      <div className="skeleton-grid">
        <span />
        <span />
        <span />
        <span />
      </div>
      <p>Chargement de l’interface NOMA…</p>
    </main>
  );
}
