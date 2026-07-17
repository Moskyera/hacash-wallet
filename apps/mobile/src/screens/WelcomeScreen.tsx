import { useState } from "react";
import Toast from "../components/Toast";
import WalletLogo from "../components/WalletLogo";
import PrivateKeyQrScanner from "../components/PrivateKeyQrScanner";
import type { ToastKind } from "../hooks/useToast";

type WelcomeTab = "create" | "import" | "watch";

type Props = {
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
  passphrase: string;
  setPassphrase: (v: string) => void;
  seed: string;
  setSeed: (v: string) => void;
  watchAddress: string;
  setWatchAddress: (v: string) => void;
  busy: boolean;
  onCreate: () => void;
  onImport: () => void;
  onWatchOnly: () => void;
  toast: { msg: string; kind: ToastKind } | null;
};

export default function WelcomeScreen({
  walletNameDraft,
  setWalletNameDraft,
  passphrase,
  setPassphrase,
  seed,
  setSeed,
  watchAddress,
  setWatchAddress,
  busy,
  onCreate,
  onImport,
  onWatchOnly,
  toast,
}: Props) {
  const [tab, setTab] = useState<WelcomeTab>("create");
  const [showQrScan, setShowQrScan] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  return (
    <div className="auth-screen">
      <div className="auth-hero">
        <WalletLogo size="lg" />
        <p className="muted small">Pay with QR. Fast Pay and Quantum options included.</p>
      </div>

      <div className="display-toggle">
        <button type="button" className={tab === "create" ? "selected" : ""} onClick={() => setTab("create")}>
          Create
        </button>
        <button type="button" className={tab === "import" ? "selected" : ""} onClick={() => setTab("import")}>
          Import
        </button>
        <button type="button" className={tab === "watch" ? "selected" : ""} onClick={() => setTab("watch")}>
          Watch
        </button>
      </div>

      {tab === "create" && (
        <div className="card">
          <h2>Create wallet</h2>
          <p className="muted small">New wallet on this phone.</p>
          <p className="muted small">Back up the key in Security as QR before you delete the app.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Encryption passphrase</label>
          <input
            type="password"
            placeholder="Min 8 characters"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || passphrase.length < 8} onClick={() => void onCreate()}>
            Create wallet
          </button>
        </div>
      )}

      {tab === "import" && (
        <div className="card">
          <h2>Import wallet</h2>
          <p className="muted small">Scan QR from old phone: More, Security, Reveal key.</p>
          <p className="muted small">Or paste hex or old passphrase below.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          {!showQrScan ? (
            <button
              type="button"
              className="primary"
              style={{ marginBottom: "0.75rem" }}
              disabled={busy}
              onClick={() => {
                setScanError(null);
                setShowQrScan(true);
              }}
            >
              Scan private key QR
            </button>
          ) : (
            <>
              <PrivateKeyQrScanner
                disabled={busy}
                onDetected={(hex) => {
                  setSeed(hex);
                  setScanError(null);
                  setShowQrScan(false);
                }}
                onError={(msg) => setScanError(msg)}
              />
              <button type="button" disabled={busy} onClick={() => setShowQrScan(false)}>
                Cancel scan
              </button>
            </>
          )}
          {scanError ? <p className="warn-text">{scanError}</p> : null}
          <label className="label">Secret hex or legacy passphrase</label>
          <textarea
            placeholder="64 character hex or old passphrase"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
          />
          <label className="label">Passphrase</label>
          <input
            type="password"
            placeholder="Passphrase for this phone"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || !seed.trim() || passphrase.length < 8} onClick={() => void onImport()}>
            Import
          </button>
        </div>
      )}

      {tab === "watch" && (
        <div className="card">
          <h2>Watch only</h2>
          <p className="muted small">View balance and receive. Cannot send.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. Cold watch"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Hacash address</label>
          <input
            placeholder="1ABC…"
            value={watchAddress}
            onChange={(e) => setWatchAddress(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || !watchAddress.trim().startsWith("1")}
            onClick={() => void onWatchOnly()}
          >
            Open watch wallet
          </button>
        </div>
      )}

      {toast && <Toast message={toast.msg} kind={toast.kind} />}
    </div>
  );
}
