import { useEffect, useState } from "react";
import {
  subscribePreparedConfirmation,
  type PendingConfirmation,
} from "../preparedConfirm";

/**
 * The authoritative view of what is about to be signed.
 *
 * Every field is built by the wallet core from the transaction it will actually
 * execute, not from anything this interface supplied. Shown immediately before
 * the biometric prompt so the user approves the same operation the core has
 * committed to.
 */
export default function PreparedOperationConfirm() {
  const [pending, setPending] = useState<PendingConfirmation | null>(null);

  useEffect(() => subscribePreparedConfirmation(setPending), []);

  if (!pending) return null;
  const { view } = pending;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-sheet">
        <h2>{view.display.title}</h2>
        <p className="muted small">{view.display.summary}</p>

        <div className="prepared-confirm-fields">
          {view.display.fields.map((field) => (
            <div key={`${field.label}:${field.value}`}>
              <span className="muted small">{field.label}</span>
              <span className="mono small">{field.value}</span>
            </div>
          ))}
        </div>

        <p className="muted small">
          Your device must approve this exact operation next. Approval covers only
          this operation and expires in {view.expires_in_secs} seconds.
        </p>
        <p className="muted small mono">Digest {view.digest.slice(0, 24)}…</p>

        <button type="button" className="primary" onClick={() => pending.resolve(true)}>
          Approve
        </button>
        <button type="button" onClick={() => pending.resolve(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
