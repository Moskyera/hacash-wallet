import { useState } from "react";
import WalletLogo from "../components/WalletLogo";
import { isValidImportSeed, type WelcomeTab } from "./types";

type Props = {
  busy: boolean;
  onCreate: (passphrase: string) => void;
  onImport: (seed: string, passphrase: string) => void;
  onWatchOnly: (address: string) => void;
};

export default function WelcomeScreen({ busy, onCreate, onImport, onWatchOnly }: Props) {
  const [welcomeTab, setWelcomeTab] = useState<WelcomeTab>("create");
  const [passphrase, setPassphrase] = useState("");
  const [importSeed, setImportSeed] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");
  const [watchAddress, setWatchAddress] = useState("");

  return (
    <section className="panel hero">
      <WalletLogo size="lg" />
      <h1>Your modern Hacash wallet</h1>
      <p>
        Encrypted keys on device. Send HAC in one tap. Instant Fast Pay when available,
        otherwise standard on-chain.
      </p>
      <div className="tab-row">
        <button
          type="button"
          className={welcomeTab === "create" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("create")}
        >
          Create
        </button>
        <button
          type="button"
          className={welcomeTab === "import" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("import")}
        >
          Import
        </button>
        <button
          type="button"
          className={welcomeTab === "watch" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("watch")}
        >
          Watch-only
        </button>
      </div>

      {welcomeTab === "create" && (
        <>
          <p className="muted">
            A unique random wallet is generated. Your passphrase only encrypts it on this device —
            the same passphrase on another phone creates a different wallet. Back up your secret in
            Security after creating.
          </p>
          <label>Encryption passphrase</label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Passphrase (min 8 chars, 12+ recommended)"
          />
          <button
            disabled={busy || passphrase.length < 8}
            onClick={() => onCreate(passphrase)}
          >
            Create wallet
          </button>
        </>
      )}

      {welcomeTab === "watch" && (
        <>
          <label>Hacash address to monitor</label>
          <input
            value={watchAddress}
            onChange={(e) => setWatchAddress(e.target.value)}
            placeholder="1YourAddress..."
          />
          <p className="muted">
            Sparrow-style watch-only. No private key on this device. Cannot send or sign.
          </p>
          <button
            disabled={busy || watchAddress.trim().length < 10}
            onClick={() => onWatchOnly(watchAddress)}
          >
            Add watch-only wallet
          </button>
        </>
      )}

      {welcomeTab === "import" && (
        <>
          <label>Secret hex or legacy passphrase seed</label>
          <textarea
            className="textarea"
            value={importSeed}
            onChange={(e) => setImportSeed(e.target.value)}
            placeholder="64-char hex secret, or legacy passphrase from older wallet versions"
            rows={3}
          />
          <label>New passphrase for this device</label>
          <input
            type="password"
            value={importPassphrase}
            onChange={(e) => setImportPassphrase(e.target.value)}
            placeholder="Passphrase (min 8 chars)"
          />
          <button
            disabled={
              busy || !isValidImportSeed(importSeed) || importPassphrase.length < 8
            }
            onClick={() => onImport(importSeed, importPassphrase)}
          >
            Import wallet
          </button>
        </>
      )}
    </section>
  );
}