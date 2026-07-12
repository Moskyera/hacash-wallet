import { WalletStatus } from "../api";

type Props = {
  status: WalletStatus | null;
  webauthnReady: boolean;
  nativeBioAvailable: boolean;
  busy: boolean;
  onRegisterWebAuthn: () => void;
  onWebAuthnSession: () => void;
  onSetProfile: (profile: string) => void;
  onSetHardwareMode: (mode: "software" | "webauthn_gate" | "watch_only") => void;
};

export default function SecurityInfoScreen({
  status,
  webauthnReady,
  nativeBioAvailable,
  busy,
  onRegisterWebAuthn,
  onWebAuthnSession,
  onSetProfile,
  onSetHardwareMode,
}: Props) {
  return (
    <>
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
        <div className={`security-item ${status?.webauthn_enabled ? "done" : "soon"}`}>
          <h4>YubiKey / Windows Hello</h4>
          <p>
            WebAuthn second factor for paranoid profile sends.
            {status?.webauthn_enabled ? " Registered." : " Not registered yet."}
          </p>
        </div>
      </div>

      <div className="info-box">
        <strong>Enable YubiKey or Windows Hello</strong>
        <ol style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
          <li>Plug in your YubiKey (or use built-in Windows Hello).</li>
          <li>
            Click <strong>Register WebAuthn</strong> below and follow the browser prompt
            (touch the key or use PIN/biometric).
          </li>
          <li>
            Optional: choose <strong>Paranoid profile</strong> for stricter timeouts and
            WebAuthn on high-value sends.
          </li>
          <li>
            Optional: set <strong>WebAuthn gate (all signs)</strong> to require hardware
            verification before every transaction.
          </li>
        </ol>
      </div>

      <div className="actions-row">
        <button disabled={busy || !webauthnReady} onClick={onRegisterWebAuthn}>
          Register WebAuthn
        </button>
        <button disabled={busy || !status?.webauthn_enabled} onClick={onWebAuthnSession}>
          Verify WebAuthn (session)
        </button>
      </div>

      <div className="actions-row">
        <button
          className={status?.security_profile === "balanced" ? "primary" : ""}
          disabled={busy}
          onClick={() => onSetProfile("balanced")}
        >
          Balanced profile
        </button>
        <button
          className={status?.security_profile === "paranoid" ? "primary" : ""}
          disabled={busy}
          onClick={() => onSetProfile("paranoid")}
        >
          Paranoid profile
        </button>
      </div>

      <h3>Hardware signing mode</h3>
      <p className="muted">
        {nativeBioAvailable
          ? "Windows Hello available for native biometric 2FA."
          : "Register WebAuthn (YubiKey / Hello) for hardware-gated signing."}
      </p>
      <div className="actions-row">
        <button
          className={status?.hardware_signing_mode === "software" ? "primary" : ""}
          disabled={busy || status?.watch_only}
          onClick={() => onSetHardwareMode("software")}
        >
          Software key
        </button>
        <button
          className={status?.hardware_signing_mode === "webauthn_gate" ? "primary" : ""}
          disabled={busy || status?.watch_only}
          onClick={() => onSetHardwareMode("webauthn_gate")}
        >
          WebAuthn gate (all signs)
        </button>
      </div>
      <p className="muted">
        Profile: <strong>{status?.security_profile ?? "balanced"}</strong>. Balanced auto-locks
        after {status?.auto_lock_secs ?? 180}s. Paranoid uses shorter timeouts and requires
        WebAuthn before high-value sends.
      </p>
    </>
  );
}