import { useState } from "react";
import {
  agentWalletApi,
  type AgentWalletOverview,
  type HacashL2ProtocolProbe,
} from "./api";
import {
  canConfirmL2ProviderPin,
  PROVIDER_BLOCKER_LABEL,
  PROVIDER_PIN_LABEL,
} from "./providerTrust";
import "./l2-provider.css";

type L2ProviderPanelProps = {
  overview: AgentWalletOverview;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
};

export function L2ProviderPanel({ overview, busy, run, onInfo }: L2ProviderPanelProps) {
  const [baseUrl, setBaseUrl] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [probe, setProbe] = useState<HacashL2ProtocolProbe | null>(null);

  const inspect = () => void run(async () => {
    const result = await agentWalletApi.probeL2Provider(overview.wallet_id, baseUrl.trim());
    setProbe(result);
    setConfirmation("");
  });

  const pin = () => void run(async () => {
    const result = await agentWalletApi.pinL2Provider(
      overview.wallet_id,
      baseUrl.trim(),
      confirmation.trim(),
    );
    setProbe(result);
    setConfirmation("");
    onInfo("The verified Hacash L2 provider identity is pinned to this Agent Wallet.");
  });

  return (
    <section>
      <div className="agent-page-head">
        <div>
          <span className="agent-eyebrow">Hacash L2 protocol</span>
          <h1>Trusted provider</h1>
        </div>
      </div>
      <p className="agent-lead">
        Inspect a hub's signed identity and pin it only after you compare the complete fingerprint with a trusted source from the operator.
      </p>
      <div className="agent-safe-note" role="status">
        This screen is read-only. It cannot quote, pay, sign, open a channel or access My Wallet. HPAY charges no Agent Wallet fee. A hub may later report its own routing or service fee separately.
      </div>

      <article className="agent-panel l2-provider-connect">
        <label className="agent-field">
          Hacash L2 hub URL
          <input
            value={baseUrl}
            placeholder="https://your-hacash-l2-hub.example"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            disabled={busy}
            onChange={(event) => {
              setBaseUrl(event.target.value);
              setProbe(null);
              setConfirmation("");
            }}
          />
        </label>
        <button
          type="button"
          className="agent-primary-action"
          disabled={busy || baseUrl.trim().length === 0}
          onClick={inspect}
        >
          {busy ? "Checking provider..." : "Verify signed identity"}
        </button>
      </article>

      {probe && (
        <article className="agent-panel l2-provider-result" aria-live="polite">
          <div className="agent-record-head">
            <div>
              <span className="agent-eyebrow">Observed provider</span>
              <h2>{probe.provider_id || "Invalid provider"}</h2>
            </div>
            <span className={`agent-status ${probe.provider_pin_status === "matched" ? "ok" : "stopped"}`}>
              {PROVIDER_PIN_LABEL[probe.provider_pin_status]}
            </span>
          </div>
          <dl className="agent-detail-grid">
            <div><dt>Agent protocol</dt><dd>{probe.protocol} / {probe.version}</dd></div>
            <div><dt>Read-only compatibility</dt><dd>{probe.read_only_compatible ? "Compatible" : "Blocked"}</dd></div>
            <div><dt>Finality model</dt><dd>{probe.finality.replace(/_/g, " ")}</dd></div>
            <div><dt>Mainnet spending</dt><dd>{probe.mainnet_spending_ready ? "Ready" : "Blocked"}</dd></div>
            <div className="wide"><dt>Verified origin</dt><dd>{probe.base_url || "Not verified"}</dd></div>
            {probe.provider_identity && (
              <>
                <div><dt>Mesh protocol</dt><dd>{probe.provider_identity.mesh_protocol_version}</dd></div>
                <div><dt>Verified at</dt><dd>{new Date(probe.provider_identity.verified_at_unix * 1000).toLocaleString()}</dd></div>
                <div className="wide"><dt>Identity address</dt><dd>{probe.provider_identity.identity_address}</dd></div>
                <div className="wide l2-provider-fingerprint"><dt>SHA3-256 fingerprint</dt><dd>{probe.provider_identity.fingerprint_sha3_hex}</dd></div>
              </>
            )}
          </dl>

          {probe.blockers.length > 0 && (
            <div className="l2-provider-blockers">
              <h3>Safety gates still closed</h3>
              <ul>{probe.blockers.map((blocker) => <li key={blocker}>{PROVIDER_BLOCKER_LABEL[blocker]}</li>)}</ul>
            </div>
          )}

          {probe.provider_pin_status === "unpinned" && probe.provider_identity && (
            <div className="l2-provider-pin">
              <div className="agent-warning">
                Do not copy the fingerprint only from this screen. Compare all 64 hexadecimal characters with a separate trusted channel from the hub operator, then type or paste that trusted value below.
              </div>
              <label className="agent-field">
                Confirm complete SHA3-256 fingerprint
                <input
                  value={confirmation}
                  maxLength={64}
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  disabled={busy}
                  onChange={(event) => setConfirmation(event.target.value)}
                />
              </label>
              <button
                type="button"
                className="agent-primary-action"
                disabled={busy || !canConfirmL2ProviderPin(probe, confirmation)}
                onClick={pin}
              >
                Confirm fingerprint and pin provider
              </button>
            </div>
          )}

          {probe.provider_pin_status === "matched" && (
            <div className="agent-safe-note">
              This signed identity matches the authenticated pin stored inside this Agent Wallet's encrypted state. That does not enable payments; the remaining safety gates stay closed.
            </div>
          )}
          {probe.provider_pin_status === "mismatch" && (
            <div className="alert" role="alert">
              Stop. The provider identity changed. HPAY will not replace the existing pin from this screen.
            </div>
          )}
        </article>
      )}
    </section>
  );
}