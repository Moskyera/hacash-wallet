import { useState } from "react";
import { WalletStatus } from "../api";
import { maskAddress } from "../privacy";

type Props = {
  status: WalletStatus | null;
  hideAddresses: boolean;
  busy: boolean;
  onUnlock: (passphrase: string) => void;
};

export default function UnlockScreen({ status, hideAddresses, busy, onUnlock }: Props) {
  const [passphrase, setPassphrase] = useState("");

  return (
    <section className="panel hero">
      <h1>Welcome back</h1>
      <p className="muted">{maskAddress(status?.address, hideAddresses)}</p>
      <input
        type="password"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
        placeholder="Passphrase"
      />
      <button disabled={busy || !passphrase} onClick={() => onUnlock(passphrase)}>
        Unlock
      </button>
      {status?.webauthn_enabled && (
        <div className="info-box">
          WebAuthn is enabled. Wallet auto-locks after{" "}
          <strong>{status.auto_lock_secs}s</strong> of inactivity. After unlock, verify your
          security key to refresh the session timer.
        </div>
      )}
    </section>
  );
}