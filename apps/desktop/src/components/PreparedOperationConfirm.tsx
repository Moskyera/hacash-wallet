import { useEffect, useState } from "react";
import {
  subscribePreparedConfirmation,
  type PendingConfirmation,
} from "../preparedConfirm";

/**
 * The authoritative view of what is about to be signed.
 *
 * Every field here is built by the wallet core from the transaction it will
 * actually execute, not from anything the rest of this interface supplied. It is
 * shown immediately before the platform ceremony so the user approves the same
 * operation the core has committed to.
 */
export default function PreparedOperationConfirm() {
  const [pending, setPending] = useState<PendingConfirmation | null>(null);

  useEffect(() => subscribePreparedConfirmation(setPending), []);

  useEffect(() => {
    if (!pending) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") pending.resolve(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pending]);

  if (!pending) return null;
  const { view } = pending;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal card prepared-confirm">
        <h3>{view.display.title}</h3>
        <p>{view.display.summary}</p>

        <dl className="prepared-confirm-fields">
          {view.display.fields.map((field) => (
            <div key={`${field.label}:${field.value}`}>
              <dt className="muted">{field.label}</dt>
              <dd className="mono">{field.value}</dd>
            </div>
          ))}
        </dl>

        <p className="muted small">
          {view.webauthn_required
            ? "Your security key must approve this exact operation next."
            : "Your device must approve this exact operation next."}{" "}
          Approval covers only this operation and expires in {view.expires_in_secs} seconds.
        </p>
        <p className="muted small mono">Digest {view.digest.slice(0, 32)}…</p>

        <div className="actions-row">
          <button type="button" onClick={() => pending.resolve(false)}>
            Cancel
          </button>
          <button type="button" className="primary" onClick={() => pending.resolve(true)}>
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}
