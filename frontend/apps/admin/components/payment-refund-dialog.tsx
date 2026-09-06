"use client";

import { Button } from "@noma/ui";
import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, Info, X } from "lucide-react";
import { useState } from "react";

export function PaymentRefundDialog() {
  const [open, setOpen] = useState(true);
  const [acknowledged, setAcknowledged] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [result, setResult] = useState("");
  const valid = acknowledged && confirmation === "CONFIRMER";
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <Button type="button">Rembourser</Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className="refund-dialog"
          aria-describedby="refund-description"
        >
          <Dialog.Title>Rembourser le paiement</Dialog.Title>
          <Dialog.Description id="refund-description">
            Commande : <strong>ORD-2026-008471</strong>. Action simulée, sans
            connexion backend.
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className="dialog-close" type="button" aria-label="Fermer">
              <X aria-hidden="true" />
            </button>
          </Dialog.Close>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (valid) {
                setResult("Remboursement simulé enregistré localement.");
                setOpen(false);
              }
            }}
          >
            <label>
              Montant <b>*</b>
              <div className="amount-field">
                <input
                  className="noma-field"
                  defaultValue="129,90"
                  inputMode="decimal"
                />
                <span>EUR</span>
              </div>
              <small>Maximum 129,90 EUR</small>
            </label>
            <label>
              Motif obligatoire <b>*</b>
              <select className="noma-field" required defaultValue="">
                <option value="" disabled>
                  Sélectionner un motif
                </option>
                <option>Retour accepté</option>
                <option>Commande annulée</option>
              </select>
              <small>Ce motif sera visible par le client.</small>
            </label>
            <div className="impact-box">
              <Info aria-hidden="true" />
              <div>
                <h3>Résumé de l’impact</h3>
                <p>
                  <span>Remboursement client</span>
                  <strong>129,90 EUR</strong>
                </p>
                <p>
                  <span>Statut après action</span>
                  <strong>REMBOURSÉ</strong>
                </p>
              </div>
            </div>
            <div className="sensitive-box">
              <AlertTriangle aria-hidden="true" />
              <p>
                <strong>Action sensible</strong>
                <br />
                Cette action peut être irréversible. Une future API devra
                revalider montant, droit et état.
              </p>
            </div>
            <label className="confirmation-check">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
              />
              <span>
                Je comprends qu’une fois confirmé, le remboursement peut être
                irréversible.
              </span>
            </label>
            <label>
              Confirmation
              <input
                className="noma-field"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                placeholder="Tapez CONFIRMER"
              />
            </label>
            <div className="dialog-actions">
              <Dialog.Close asChild>
                <Button variant="secondary" type="button">
                  Annuler
                </Button>
              </Dialog.Close>
              <Button variant="danger" type="submit" disabled={!valid}>
                Confirmer le remboursement
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
      {result ? (
        <p className="dialog-result" role="status">
          {result}
        </p>
      ) : null}
    </Dialog.Root>
  );
}
