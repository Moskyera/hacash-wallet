import { useState } from "react";
import { WalletStatus } from "../api";
import WalletLogo from "../components/WalletLogo";
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
    <div className="auth-layout auth-layout-welcome">
      <div className="auth-welcome">
        <div className="auth-hero">
          <WalletLogo size="lg" />
          <h1>Welcome back</h1>
          <p className="muted mono">{maskAddress(status?.address, hideAddresses)}</p>
        </div>
        <div className="auth-form auth-form-centered">
          <label>Passphrase</label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter your passphrase"
            onKeyDown={(e) => {
              if (e.key === "Enter" && passphrase && !busy) onUnlock(passphrase);
            }}
          />
          <button
            className="primary auth-submit"
            disabled={busy || !passphrase}
            onClick={() => onUnlock(passphrase)}
          >
            {busy ? "Unlocking…" : "Unlock wallet"}
          </button>
          {status?.webauthn_enabled && (
            <div className="info-box">
              WebAuthn is enabled. Wallet auto-locks after{" "}
              <strong>{status.auto_lock_secs}s</strong> of inactivity.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}