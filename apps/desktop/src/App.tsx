import { useEffect, useState } from "react";
import { api, SendPreview, WalletStatus } from "./api";

type Screen = "welcome" | "unlock" | "home" | "send" | "receive" | "security";

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [status, setStatus] = useState<WalletStatus | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [balance, setBalance] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [preview, setPreview] = useState<SendPreview | null>(null);
  const [lastTx, setLastTx] = useState("");

  async function refreshStatus() {
    const s = await api.status();
    setStatus(s);
    if (!s.has_wallet) setScreen("welcome");
    else if (s.locked) setScreen("unlock");
    else setScreen("home");
  }

  async function refreshBalance() {
    try {
      const b = await api.balance();
      setBalance(b);
    } catch {
      setBalance(null);
    }
  }

  useEffect(() => {
    refreshStatus().catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (status && !status.locked) {
      refreshBalance().catch(() => undefined);
    }
  }, [status?.locked, status?.address]);

  async function handleCreate() {
    setBusy(true);
    setError("");
    try {
      await api.create(passphrase);
      await refreshStatus();
      setPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlock() {
    setBusy(true);
    setError("");
    try {
      await api.unlock(passphrase);
      await refreshStatus();
      setPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleLock() {
    await api.lock();
    setBalance(null);
    await refreshStatus();
  }

  async function handlePreviewSend() {
    setBusy(true);
    setError("");
    setPreview(null);
    try {
      const p = await api.previewSend(sendTo.trim(), Number(sendAmount));
      setPreview(p);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirmSend() {
    setBusy(true);
    setError("");
    try {
      const result = await api.sendHac(
        sendTo.trim(),
        Number(sendAmount),
        true,
        false,
      );
      setLastTx(result.tx_hash);
      setPreview(null);
      setSendTo("");
      setSendAmount("");
      await refreshBalance();
      setScreen("home");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">H</div>
          <div>
            <div className="brand-title">Hacash Wallet</div>
            <div className="brand-sub">Secure · L1 + L2 Ready</div>
          </div>
        </div>
        {status && !status.locked && (
          <nav>
            <button className={screen === "home" ? "active" : ""} onClick={() => setScreen("home")}>Home</button>
            <button className={screen === "send" ? "active" : ""} onClick={() => setScreen("send")}>Send</button>
            <button className={screen === "receive" ? "active" : ""} onClick={() => setScreen("receive")}>Receive</button>
            <button className={screen === "security" ? "active" : ""} onClick={() => setScreen("security")}>Security</button>
          </nav>
        )}
        <div className="sidebar-foot">
          {status?.node_url && <span className="muted">{status.node_url}</span>}
        </div>
      </aside>

      <main className="content">
        {error && <div className="alert">{error}</div>}

        {screen === "welcome" && (
          <section className="panel hero">
            <h1>Your modern Hacash wallet</h1>
            <p>Encrypted keys on device. Human-readable signing. Fast Pay (L2) when hub is available.</p>
            <label>Choose a strong passphrase</label>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase (min 12 chars recommended)"
            />
            <button disabled={busy || passphrase.length < 8} onClick={handleCreate}>
              Create wallet
            </button>
          </section>
        )}

        {screen === "unlock" && (
          <section className="panel hero">
            <h1>Welcome back</h1>
            <p className="muted">{status?.address}</p>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase"
            />
            <button disabled={busy || !passphrase} onClick={handleUnlock}>
              Unlock
            </button>
          </section>
        )}

        {screen === "home" && (
          <section className="panel">
            <div className="balance-card">
              <span className="label">Available balance</span>
              <div className="balance-value">{balance?.toFixed(3) ?? "—"} <small>HAC</small></div>
              <div className="chips">
                <span className="chip">L1 On-chain</span>
                <span className="chip chip-accent">L2 Fast Pay (phase 2)</span>
              </div>
            </div>
            <div className="actions-row">
              <button className="primary" onClick={() => setScreen("send")}>Send</button>
              <button onClick={() => setScreen("receive")}>Receive</button>
              <button onClick={handleLock}>Lock</button>
            </div>
            {lastTx && (
              <div className="success-box">
                Last transaction: <code>{lastTx}</code>
              </div>
            )}
          </section>
        )}

        {screen === "send" && (
          <section className="panel">
            <h2>Send HAC</h2>
            <label>To address</label>
            <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} placeholder="1ABC..." />
            <label>Amount (mei)</label>
            <input value={sendAmount} onChange={(e) => setSendAmount(e.target.value)} placeholder="10" type="number" min="0" step="0.001" />
            <button disabled={busy || !sendTo || !sendAmount} onClick={handlePreviewSend}>
              Preview (human-readable)
            </button>
            {preview && (
              <div className="preview-card">
                <h3>Confirm payment</h3>
                <p>{preview.plan.summary}</p>
                <ul>
                  <li><strong>Rail:</strong> {preview.plan.rail}</li>
                  <li><strong>Fee:</strong> {preview.plan.estimated_fee}</li>
                  <li><strong>From:</strong> <code>{preview.from}</code></li>
                  <li><strong>To:</strong> <code>{preview.to}</code></li>
                </ul>
                <button className="primary" disabled={busy} onClick={handleConfirmSend}>
                  Sign & send
                </button>
              </div>
            )}
          </section>
        )}

        {screen === "receive" && (
          <section className="panel">
            <h2>Receive HAC</h2>
            <p>Share your address. L2 inbound will route via hub when enabled.</p>
            <div className="address-box"><code>{status?.address}</code></div>
          </section>
        )}

        {screen === "security" && (
          <section className="panel">
            <h2>Security</h2>
            <div className="security-grid">
              <div className="security-item done">
                <h4>Encrypted vault</h4>
                <p>Argon2id + AES-256-GCM. Keys never leave device unencrypted.</p>
              </div>
              <div className="security-item done">
                <h4>Local signing</h4>
                <p>Transactions signed in Rust core — private key never sent to node API.</p>
              </div>
              <div className="security-item soon">
                <h4>Biometric unlock</h4>
                <p>Windows Hello / Touch ID integration (phase 2).</p>
              </div>
              <div className="security-item soon">
                <h4>YubiKey WebAuthn</h4>
                <p>Second factor for sends above threshold (phase 2).</p>
              </div>
            </div>
            <div className="actions-row">
              <button onClick={() => api.setSecurityProfile("balanced")}>Balanced profile</button>
              <button onClick={() => api.setSecurityProfile("paranoid")}>Paranoid profile</button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}