import Toast from "../components/Toast";
import WalletLogo from "../components/WalletLogo";
import type { ToastKind } from "../hooks/useToast";

type Props = {
  displayName: string;
  addressHint?: string | null;
  passphrase: string;
  setPassphrase: (v: string) => void;
  busy: boolean;
  onUnlock: () => void;
  biometricUnlockAvailable?: boolean;
  biometricKind?: string | null;
  onBiometricUnlock?: () => void;
  toast: { msg: string; kind: ToastKind } | null;
};

export default function UnlockScreen({
  displayName,
  addressHint,
  passphrase,
  setPassphrase,
  busy,
  onUnlock,
  biometricUnlockAvailable,
  biometricKind,
  onBiometricUnlock,
  toast,
}: Props) {
  const bioLabel = biometricKind ?? "Biometric";

  return (
    <div className="auth-screen">
      <div className="auth-hero">
        <WalletLogo size="lg" />
        <h1>{displayName}</h1>
        {addressHint ? <p className="muted mono">{addressHint}</p> : null}
        <p className="muted">Enter passphrase to unlock</p>
      </div>
      <div className="card">
        {biometricUnlockAvailable && onBiometricUnlock ? (
          <>
            <button
              type="button"
              className="primary"
              style={{ width: "100%", marginBottom: "0.75rem" }}
              disabled={busy}
              onClick={() => void onBiometricUnlock()}
            >
              Unlock with {bioLabel}
            </button>
            <p className="muted small" style={{ textAlign: "center", margin: "0 0 0.75rem" }}>
              or use passphrase
            </p>
          </>
        ) : null}
        <label className="label">Passphrase</label>
        <input
          type="password"
          placeholder="Enter passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void onUnlock()}
        />
        <button className="primary" disabled={busy || !passphrase} onClick={() => void onUnlock()}>
          Unlock
        </button>
      </div>
      {toast && <Toast message={toast.msg} kind={toast.kind} />}
    </div>
  );
}