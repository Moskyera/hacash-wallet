import { useEffect, useState } from "react";
import {
  api,
  ChannelInfo,
  ChannelSetupPreview,
  SendPreview,
  WalletSettings,
  WalletStatus,
} from "./api";
import { runWebAuthnAuth, runWebAuthnRegister, webAuthnAvailable } from "./webauthn";

type Screen = "welcome" | "unlock" | "home" | "send" | "receive" | "l2" | "security";

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [status, setStatus] = useState<WalletStatus | null>(null);
  const [settings, setSettings] = useState<WalletSettings | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [balance, setBalance] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [preview, setPreview] = useState<SendPreview | null>(null);
  const [lastTx, setLastTx] = useState("");

  const [hubUrl, setHubUrl] = useState("");
  const [hubAddress, setHubAddress] = useState("");
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [channelPreview, setChannelPreview] = useState<ChannelSetupPreview | null>(null);
  const [channelInfo, setChannelInfo] = useState<ChannelInfo | null>(null);

  const [webauthnReady, setWebauthnReady] = useState(false);

  async function refreshStatus() {
    const s = await api.status();
    setStatus(s);
    if (!s.has_wallet) setScreen("welcome");
    else if (s.locked) setScreen("unlock");
    else if (screen === "welcome" || screen === "unlock") setScreen("home");
  }

  async function refreshSettings() {
    const s = await api.getSettings();
    setSettings(s);
    setHubUrl(s.l2_hub_url ?? "");
    setHubAddress(s.hub_right_address ?? "");
  }

  async function refreshBalance() {
    try {
      const b = await api.balance();
      setBalance(b);
    } catch {
      setBalance(null);
    }
  }

  async function refreshChannel() {
    try {
      const info = await api.channelInfo();
      setChannelInfo(info);
    } catch {
      setChannelInfo(null);
    }
  }

  useEffect(() => {
    setWebauthnReady(webAuthnAvailable());
    refreshStatus().catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (status && !status.locked) {
      refreshBalance().catch(() => undefined);
      refreshSettings().catch(() => undefined);
      refreshChannel().catch(() => undefined);
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
    setWebauthnReady(webAuthnAvailable());
    await refreshStatus();
  }

  async function handleSaveL2Settings() {
    if (!settings) return;
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const next: WalletSettings = {
        ...settings,
        node_url: settings.node_url,
        l2_hub_url: hubUrl.trim() || null,
        hub_right_address: hubAddress.trim() || settings.hub_right_address,
      };
      await api.updateSettings(next);
      await refreshSettings();
      await refreshStatus();
      setInfo("L2 settings saved.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handlePreviewChannel() {
    setBusy(true);
    setError("");
    setChannelPreview(null);
    try {
      const p = await api.previewChannelOpen(
        hubAddress.trim(),
        Number(userDeposit),
        Number(hubDeposit),
      );
      setChannelPreview(p);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleOpenChannel() {
    setBusy(true);
    setError("");
    try {
      const hash = await api.openChannel(
        hubAddress.trim(),
        Number(userDeposit),
        Number(hubDeposit),
      );
      setInfo(`Channel open submitted: ${hash}`);
      setChannelPreview(null);
      await refreshStatus();
      await refreshChannel();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleRegisterWebAuthn() {
    if (!webauthnReady) {
      setError("WebAuthn not available in this environment.");
      return;
    }
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const options = await api.webauthnRegisterBegin();
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred);
      await refreshStatus();
      setInfo("YubiKey / Windows Hello registered.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleWebAuthnUnlock() {
    if (!webauthnReady || !status?.webauthn_enabled) return;
    setBusy(true);
    setError("");
    try {
      const options = await api.webauthnAuthBegin();
      const assertion = await runWebAuthnAuth(options);
      await api.webauthnAuthFinish(assertion);
      setWebauthnReady(true);
      setInfo("WebAuthn verified for this session.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
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
      if (status?.security_profile === "paranoid" && status.webauthn_enabled) {
        const options = await api.webauthnAuthBegin();
        const assertion = await runWebAuthnAuth(options);
        await api.webauthnAuthFinish(assertion);
      }
      const result = await api.sendHac(
        sendTo.trim(),
        Number(sendAmount),
        true,
        status?.webauthn_enabled ?? false,
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

  const l2Active = !!(status?.l2_hub_url && status?.channel_id);

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
            <button className={screen === "home" ? "active" : ""} onClick={() => setScreen("home")}>
              Home
            </button>
            <button className={screen === "send" ? "active" : ""} onClick={() => setScreen("send")}>
              Send
            </button>
            <button
              className={screen === "receive" ? "active" : ""}
              onClick={() => setScreen("receive")}
            >
              Receive
            </button>
            <button className={screen === "l2" ? "active" : ""} onClick={() => setScreen("l2")}>
              L2 Fast Pay
            </button>
            <button
              className={screen === "security" ? "active" : ""}
              onClick={() => setScreen("security")}
            >
              Security
            </button>
          </nav>
        )}
        <div className="sidebar-foot">
          {status?.node_url && <span className="muted">{status.node_url}</span>}
          {status && !status.locked && (
            <div className="status-chips">
              <span className={`chip ${l2Active ? "chip-accent" : ""}`}>
                L2 {l2Active ? "configured" : "off"}
              </span>
              {status.webauthn_enabled && <span className="chip chip-accent">WebAuthn</span>}
            </div>
          )}
        </div>
      </aside>

      <main className="content">
        {error && <div className="alert">{error}</div>}
        {info && <div className="info-box">{info}</div>}

        {screen === "welcome" && (
          <section className="panel hero">
            <h1>Your modern Hacash wallet</h1>
            <p>
              Encrypted keys on device. Human-readable signing. Fast Pay (L2) when hub is available.
            </p>
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
              <div className="balance-value">
                {balance?.toFixed(3) ?? "—"} <small>HAC</small>
              </div>
              <div className="chips">
                <span className="chip">L1 On-chain</span>
                <span className={`chip ${l2Active ? "chip-accent" : ""}`}>
                  L2 Fast Pay {l2Active ? "ready" : "(configure in L2 tab)"}
                </span>
              </div>
            </div>
            <div className="actions-row">
              <button className="primary" onClick={() => setScreen("send")}>
                Send
              </button>
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
            <input
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="10"
              type="number"
              min="0"
              step="0.001"
            />
            <button disabled={busy || !sendTo || !sendAmount} onClick={handlePreviewSend}>
              Preview (HIP-23 checks)
            </button>
            {preview && (
              <div className="preview-card">
                <h3>Confirm payment</h3>
                <p>{preview.plan.summary}</p>
                <ul>
                  <li>
                    <strong>Rail:</strong> {preview.plan.rail}
                  </li>
                  <li>
                    <strong>Fee:</strong> {preview.plan.estimated_fee}
                  </li>
                  <li>
                    <strong>From:</strong> <code>{preview.from}</code>
                  </li>
                  <li>
                    <strong>To:</strong> <code>{preview.to}</code>
                  </li>
                </ul>
                {preview.hip23.warnings.length > 0 && (
                  <div className="warn-box">
                    <strong>HIP-23 warnings</strong>
                    <ul>
                      {preview.hip23.warnings.map((w) => (
                        <li key={w}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {status?.security_profile === "paranoid" && status.webauthn_enabled && (
                  <p className="muted">
                    Paranoid mode: WebAuthn (YubiKey / Windows Hello) required before signing.
                  </p>
                )}
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
            <p>Share your address. L2 inbound routes via hub when channel is open.</p>
            <div className="address-box">
              <code>{status?.address}</code>
            </div>
          </section>
        )}

        {screen === "l2" && (
          <section className="panel">
            <h2>L2 Fast Pay</h2>
            <p className="muted">
              Configure a CSP hub URL and open an L1 payment channel. Payments auto-route to L2 when
              hub is healthy; otherwise L1 fallback applies.
            </p>

            <label>Hub API URL</label>
            <input
              value={hubUrl}
              onChange={(e) => setHubUrl(e.target.value)}
              placeholder="https://hub.example.com"
            />
            <button disabled={busy} onClick={handleSaveL2Settings}>
              Save hub URL
            </button>

            <hr className="divider" />

            <h3>Open payment channel (L1)</h3>
            <label>Hub / CSP address (right party)</label>
            <input
              value={hubAddress}
              onChange={(e) => setHubAddress(e.target.value)}
              placeholder="1Hub..."
            />
            <div className="two-col">
              <div>
                <label>Your deposit (mei)</label>
                <input
                  value={userDeposit}
                  onChange={(e) => setUserDeposit(e.target.value)}
                  type="number"
                  min="0"
                />
              </div>
              <div>
                <label>Hub deposit (mei)</label>
                <input
                  value={hubDeposit}
                  onChange={(e) => setHubDeposit(e.target.value)}
                  type="number"
                  min="0"
                />
              </div>
            </div>
            <div className="actions-row">
              <button disabled={busy || !hubAddress} onClick={handlePreviewChannel}>
                Preview channel
              </button>
              <button
                className="primary"
                disabled={busy || !channelPreview}
                onClick={handleOpenChannel}
              >
                Sign & open channel
              </button>
            </div>

            {channelPreview && (
              <div className="preview-card">
                <p>
                  <strong>Channel ID:</strong> <code>{channelPreview.channel_id}</code>
                </p>
                <p>
                  Left: <code>{channelPreview.left_address}</code> — {channelPreview.left_deposit}
                </p>
                <p>
                  Right: <code>{channelPreview.right_address}</code> —{" "}
                  {channelPreview.right_deposit}
                </p>
              </div>
            )}

            {status?.channel_id && (
              <div className="success-box">
                Active channel: <code>{status.channel_id}</code>
                {channelInfo && (
                  <p className="muted">
                    Status {channelInfo.status} · Left {channelInfo.left.hacash} · Right{" "}
                    {channelInfo.right.hacash}
                  </p>
                )}
              </div>
            )}

            {status && status.l2_bill_count > 0 && (
              <p className="muted">{status.l2_bill_count} L2 settlement bill(s) backed up locally.</p>
            )}
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
              <div className="security-item done">
                <h4>HIP-23 pre-sign checks</h4>
                <p>Address format, balance, and large-transfer warnings before every send.</p>
              </div>
              <div
                className={`security-item ${status?.webauthn_enabled ? "done" : webauthnReady ? "soon" : "soon"}`}
              >
                <h4>YubiKey / Windows Hello</h4>
                <p>
                  WebAuthn second factor for paranoid profile sends.
                  {status?.webauthn_enabled ? " Registered." : " Not registered yet."}
                </p>
              </div>
            </div>

            <div className="actions-row">
              <button
                disabled={busy || !webauthnReady}
                onClick={handleRegisterWebAuthn}
              >
                Register WebAuthn
              </button>
              <button
                disabled={busy || !status?.webauthn_enabled}
                onClick={handleWebAuthnUnlock}
              >
                Verify WebAuthn (session)
              </button>
            </div>

            <div className="actions-row">
              <button
                className={status?.security_profile === "balanced" ? "primary" : ""}
                onClick={async () => {
                  await api.setSecurityProfile("balanced");
                  await refreshStatus();
                }}
              >
                Balanced profile
              </button>
              <button
                className={status?.security_profile === "paranoid" ? "primary" : ""}
                onClick={async () => {
                  await api.setSecurityProfile("paranoid");
                  await refreshStatus();
                }}
              >
                Paranoid profile
              </button>
            </div>
            <p className="muted">
              Profile: <strong>{status?.security_profile ?? "balanced"}</strong>. Paranoid requires
              WebAuthn before high-value sends.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}