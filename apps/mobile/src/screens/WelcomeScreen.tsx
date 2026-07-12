import { useState } from "react";
import Toast from "../components/Toast";
import WalletLogo from "../components/WalletLogo";
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

  return (
    <div className="auth-screen">
      <div className="auth-hero">
        <WalletLogo size="lg" />
        <p className="muted">Fast QR payments · L2 Fast Pay · Quantum-ready</p>
      </div>

      <div className="display-toggle">
        <button type="button" className={tab === "create" ? "selected" : ""} onClick={() => setTab("create")}>
          Create
        </button>
        <button type="button" className={tab === "import" ? "selected" : ""} onClick={() => setTab("import")}>
          Import
        </button>
        <button type="button" className={tab === "watch" ? "selected" : ""} onClick={() => setTab("watch")}>
          Watch-only
        </button>
      </div>

      {tab === "create" && (
        <div className="card">
          <h2>Create wallet</h2>
          <p className="muted">
            A unique random wallet is generated. Your passphrase only encrypts it on this phone — the
            same passphrase elsewhere creates a different wallet. Back up your secret in More →
            Security. Updating the app keeps your wallet; Delete wallet starts over.
          </p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Encryption passphrase</label>
          <input
            type="password"
            placeholder="Encrypts wallet on this device (min 8 chars)"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || !passphrase} onClick={() => void onCreate()}>
            Create wallet
          </button>
        </div>
      )}

      {tab === "import" && (
        <div className="card">
          <h2>Import wallet</h2>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Secret hex or legacy passphrase</label>
          <textarea
            placeholder="64-char hex, or legacy passphrase from older wallet versions"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
          />
          <label className="label">Passphrase</label>
          <input
            type="password"
            placeholder="Encryption passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || !seed || !passphrase} onClick={() => void onImport()}>
            Import
          </button>
        </div>
      )}

      {tab === "watch" && (
        <div className="card">
          <h2>Watch-only</h2>
          <p className="muted">Monitor balances and receive payments. Cannot sign transactions.</p>
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
            Open watch-only
          </button>
        </div>
      )}

      {toast && <Toast message={toast.msg} kind={toast.kind} />}
    </div>
  );
}