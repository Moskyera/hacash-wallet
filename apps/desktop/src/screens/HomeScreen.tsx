import { AssetSummary, WalletStatus } from "../api";
import BalanceOverview from "../components/BalanceOverview";
import HacdDappConnect from "../components/HacdDappConnect";
import { PrivacySettings } from "../api";
import { maskHash } from "../privacy";
import { formatCountdown, type Screen } from "./types";

type Props = {
  status: WalletStatus | null;
  assets: AssetSummary | null;
  hideBalances: boolean;
  hideAddresses: boolean;
  fastPayReady: boolean;
  lastTx: string;
  busy: boolean;
  privacy: PrivacySettings;
  onNavigate: (screen: Screen) => void;
  onOpenQrPay: () => void;
  onWebAuthnSession: () => void;
  onLock: () => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  clearMessages: () => void;
};

export default function HomeScreen({
  status,
  assets,
  hideBalances,
  hideAddresses,
  fastPayReady,
  lastTx,
  busy,
  privacy,
  onNavigate,
  onOpenQrPay,
  onWebAuthnSession,
  onLock,
  onNotify,
  clearMessages,
}: Props) {
  return (
    <section className="panel">
      <div className="balance-card">
        <BalanceOverview assets={assets} hideBalances={hideBalances} />
        <div className="chips">
          {status?.seconds_until_lock != null && (
            <span className="chip chip-accent">
              Auto-lock in {formatCountdown(status.seconds_until_lock)}
            </span>
          )}
        </div>
      </div>
      {!status?.watch_only && (
        <div className={`home-fp-hint ${fastPayReady ? "home-fp-hint-on" : ""}`}>
          <span className="muted">Instant sends:</span>{" "}
          <button type="button" className="linkish" onClick={() => onNavigate("fastpay")}>
            {fastPayReady ? "Fast Pay is ON" : "Fast Pay is OFF. Open tab to enable."}
          </button>
        </div>
      )}
      <div className="actions-row">
        <button className="primary" onClick={() => onNavigate("send")}>
          Send HAC
        </button>
        {!status?.watch_only && <button onClick={onOpenQrPay}>Scan QR & Pay</button>}
        <button onClick={() => onNavigate("fastpay")}>Fast Pay</button>
        <button onClick={() => onNavigate("receive")}>Receive</button>
        {status?.webauthn_enabled && (
          <button disabled={busy} onClick={onWebAuthnSession}>
            Verify WebAuthn (session)
          </button>
        )}
        <button onClick={onLock}>Lock</button>
      </div>
      {lastTx && (
        <div className="success-box">
          Last transaction: <code>{maskHash(lastTx, hideAddresses)}</code>
        </div>
      )}
      <HacdDappConnect
        watchOnly={status?.watch_only}
        pauseAutoLockDapp={privacy.pause_auto_lock_dapp ?? true}
        onNotify={(msg, kind) => {
          clearMessages();
          onNotify(msg, kind);
        }}
      />
    </section>
  );
}