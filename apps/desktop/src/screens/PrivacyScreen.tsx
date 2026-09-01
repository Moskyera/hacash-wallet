import { useEffect, useRef, useState } from "react";
import {
  DustWhisperSettings,
  PrivacySettings,
  RelayEndpoint,
  RelayHealthStatus,
  WalletStatus,
} from "../api";
import { DEFAULT_DUST_WHISPER, DEFAULT_PRIVACY } from "../privacy";
import {
  ALLOWLIST_EXPLANATION,
  PLAIN_HTTP_LIMIT,
  SHARE_INSTRUCTION,
  firstAcceptWarning,
  relayReach,
  widenConsequences,
} from "../relayReach";

type Props = {
  status: WalletStatus | null;
  dustWhisper: DustWhisperSettings;
  relayHealth: RelayHealthStatus[];
  /** What this wallet is serving, from `wallet_relay_endpoint`. */
  relayEndpoint: RelayEndpoint | null;
  busy: boolean;
  onSavePrivacy: (draft: PrivacySettings) => void;
  onSaveWhisper: (draft: DustWhisperSettings, relayText: string) => Promise<DustWhisperSettings | null>;
  onClearHistory: () => void;
};

export default function PrivacyScreen({
  status,
  dustWhisper,
  relayHealth,
  relayEndpoint,
  busy,
  onSavePrivacy,
  onSaveWhisper,
  onClearHistory,
}: Props) {
  const [privacyDraft, setPrivacyDraft] = useState<PrivacySettings>(DEFAULT_PRIVACY);
  const [whisperDraft, setWhisperDraft] = useState<DustWhisperSettings>(DEFAULT_DUST_WHISPER);
  const [whisperRelayText, setWhisperRelayText] = useState("");
  const [whisperAllowText, setWhisperAllowText] = useState("");
  const syncedRef = useRef(false);
  const reach = relayReach(relayEndpoint);
  const bindDraft = whisperDraft.relay_bind ?? "loopback";
  const widening = bindDraft === "all_interfaces" && relayEndpoint?.bind !== "all_interfaces";
  const allowDraft = whisperAllowText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  // What the relay will actually serve once this draft is saved: this wallet's
  // own address first, then the additions. Composed the same way the backend
  // composes it (`desktop_relay::served_addresses`), because the consequences
  // box has to describe the state the person is about to be in and not the
  // contents of the text box, which leaves the owner out.
  const servedDraft = [relayEndpoint?.own_address ?? "", ...allowDraft]
    .map((a) => a.trim())
    .filter((a, i, all) => a.length > 0 && all.indexOf(a) === i);
  // The order of the relay list is not a preference, and getting it wrong is
  // silent in exactly one direction. See `firstAcceptWarning`.
  const ordering = firstAcceptWarning(relayEndpoint);

  // Sync drafts once when the tab mounts. not on status polls.
  useEffect(() => {
    if (syncedRef.current || !status) return;
    if (status.privacy) setPrivacyDraft(status.privacy);
    if (status.dust_whisper) {
      const relayUrls =
        status.dust_whisper.relay_urls.length > 0
          ? status.dust_whisper.relay_urls
          : DEFAULT_DUST_WHISPER.relay_urls;
      setWhisperDraft({ ...status.dust_whisper, relay_urls: relayUrls });
      setWhisperRelayText(relayUrls.join("\n"));
      setWhisperAllowText((status.dust_whisper.relay_allowlist ?? []).join("\n"));
    }
    syncedRef.current = true;
  }, [status]);

  return (
    <section className="panel">
      <h2>Privacy</h2>
      <p className="muted">
        Control what appears on screen and what is stored locally. Keys stay encrypted.
        these settings reduce shoulder-surfing and local metadata exposure.
      </p>

      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.hide_balances}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, hide_balances: e.target.checked }))
          }
        />
        Hide balances
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.hide_addresses}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, hide_addresses: e.target.checked }))
          }
        />
        Hide addresses &amp; tx hashes
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.screen_privacy}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, screen_privacy: e.target.checked }))
          }
        />
        Screen privacy (blur when unfocused)
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.store_tx_history}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, store_tx_history: e.target.checked }))
          }
        />
        Store transaction history locally
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.pause_auto_lock_dapp ?? true}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, pause_auto_lock_dapp: e.target.checked }))
          }
        />
        Pause auto-lock during HACD session (hacd.it)
      </label>

      <label>Clipboard auto-clear (seconds, 0 = off)</label>
      <input
        type="number"
        min="0"
        max="300"
        value={privacyDraft.clipboard_clear_secs}
        onChange={(e) =>
          setPrivacyDraft((p) => ({
            ...p,
            clipboard_clear_secs: Math.max(0, Number(e.target.value)),
          }))
        }
      />

      <div className="actions-row">
        <button className="primary" disabled={busy} onClick={() => onSavePrivacy(privacyDraft)}>
          Save privacy settings
        </button>
        <button disabled={busy} onClick={onClearHistory}>
          Clear local history
        </button>
      </div>

      <hr className="divider" />

      <h3>DUST Whisper</h3>
      <p className="muted">
        Encrypt signed transactions between this wallet and a relay. A remote relay can hide your
        IP from the full node. A relay on this device does not provide network anonymity. Balance
        queries still use your configured node directly.
      </p>
      <p className="muted">
        The encryption ends at the relay, not at the node. A relay decrypts each transaction in
        order to forward it, so whoever runs a remote relay sees the whole transaction: amounts,
        addresses, all of it. That is the trade this setting makes. The node learns the relay
        instead of you, and the relay operator learns everything.
      </p>
      <p className="muted">
        This wallet can be the relay. It runs one itself while DUST Whisper and auto-start are both
        on and a relay address on this computer is in the list below, and it follows the active node
        after a saved change or automatic failover. That is enough for two people to message each
        other with nothing else deployed: one of you hosts, the other points at you.{" "}
        <code>docs/RUNNING-A-RELAY.md</code> section 0 is that arrangement start to finish. Hosting
        does not hide your own IP from the node.
      </p>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.enabled}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, enabled: e.target.checked }))
          }
        />
        Enable DUST Whisper for tx broadcast
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.fallback_direct}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, fallback_direct: e.target.checked }))
          }
        />
        Fall back to direct node submit if relay fails
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.auto_start_relay ?? true}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, auto_start_relay: e.target.checked }))
          }
        />
        Auto-start the relay this wallet hosts, when the wallet opens
      </label>

      <div className="info-box">
        <strong>Your own relay</strong>
        {reach ? (
          <>
            <p>{reach.headline}</p>
            <p className={reach.tone === "warn" ? "warn-text" : undefined}>{reach.reach}</p>
            {reach.share ? (
              <>
                <p>
                  The address to give the other person: <code>{reach.share}</code>
                </p>
                <p className="muted small">{SHARE_INSTRUCTION}</p>
                <p className="muted small">{PLAIN_HTTP_LIMIT}</p>
              </>
            ) : null}
            {reach.conditions.length > 0 ? (
              <>
                <p>Before that address reaches anybody:</p>
                <ul>
                  {reach.conditions.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </>
        ) : (
          // The wallet has not answered. Saying nothing beats guessing at an
          // address somebody would then hand out.
          <p className="muted">The wallet has not reported a relay address yet.</p>
        )}
        {ordering ? (
          <p className="warn-text">
            <strong>Your messages are not leaving this computer.</strong> {ordering}
          </p>
        ) : null}
      </div>

      <label htmlFor="relay-bind">Who this relay accepts connections from</label>
      <select
        id="relay-bind"
        value={bindDraft}
        onChange={(e) =>
          setWhisperDraft((w) => ({
            ...w,
            relay_bind: e.target.value === "all_interfaces" ? "all_interfaces" : "loopback",
          }))
        }
      >
        <option value="loopback">This computer only (127.0.0.1)</option>
        <option value="all_interfaces">
          Any machine that can reach this computer (0.0.0.0)
        </option>
      </select>
      <p className="muted small">
        Nothing moves until you press Save DUST Whisper. On this computer only, the relay is
        reachable by nobody else and there is no address to share.
      </p>
      {widening ? (
        <div className="warn-box">
          <p>
            <strong>You are about to accept connections from other machines.</strong>
          </p>
          <ul>
            {widenConsequences(servedDraft).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          {servedDraft.length > 0 ? (
            <>
              <p>
                <strong>Who this relay will carry mail for, once you press Save:</strong>
              </p>
              <ul className="mono">
                {servedDraft.map((address) => (
                  <li key={address}>
                    {address}
                    {address === relayEndpoint?.own_address ? " (you)" : ""}
                  </li>
                ))}
              </ul>
              <p>Every other address gets nothing, on every route.</p>
            </>
          ) : null}
          <p>
            Being bound this way is not the same as being reachable. The wallet will tell you the
            address this computer holds on its network once it is listening, and what still has to
            be true for anybody outside your own network to get to it.
          </p>
        </div>
      ) : null}
      {(whisperDraft.enabled || dustWhisper.enabled) && (
        <div className="relay-status-list">
          <strong>Relay status</strong>
          {(relayHealth.length > 0
            ? relayHealth
            : dustWhisper.relay_urls.map((url) => ({
                url,
                online: false,
                error: "Checking…",
                node_url: null,
                protocol_version: null,
              }))
          ).map((row) => (
            <div
              key={row.url}
              className={`relay-status-row ${row.online ? "online" : "offline"}`}
            >
              <span className={`relay-status-dot ${row.online ? "online" : "offline"}`} />
              <code>{row.url}</code>
              <span className="muted">
                {row.online
                  ? `online · node ${row.node_url ?? "n/a"}`
                  : row.error ?? "offline"}
              </span>
            </div>
          ))}
          {dustWhisper.relay_urls.length === 0 && (
            <p className="muted">Add a relay URL to see status.</p>
          )}
        </div>
      )}
      <label>Relay URLs (one per line)</label>
      <p className="muted small">
        This box starts with <code>http://127.0.0.1:8787</code>, which is this wallet&apos;s own
        relay on this computer. Keeping that line is what makes this wallet host one at all. The
        wallet ships with no other address in it because there is no public relay to ship.
        Somebody has to run one, and it can be you: <code>docs/RUNNING-A-RELAY.md</code>.
      </p>
      <p className="muted small">
        <strong>If somebody else is hosting for you, their address goes above that line, or
        replaces it.</strong> A message you send stops at the first relay in this list that accepts
        it, and the relay on this computer always accepts, so a friend&apos;s address underneath it
        never receives anything you send. Collecting mail tries every relay in the list, so their
        replies would still arrive and the thread would look like a conversation carrying one
        direction. Section 0 step 4 of the guide is this same sentence.
      </p>
      <textarea
        className="textarea mono"
        rows={3}
        placeholder="http://127.0.0.1:8787"
        value={whisperRelayText}
        onChange={(e) => setWhisperRelayText(e.target.value)}
      />
      <label htmlFor="relay-allowlist">Addresses this relay carries mail for (one per line)</label>
      <p className="muted small">{ALLOWLIST_EXPLANATION}</p>
      <textarea
        id="relay-allowlist"
        className="textarea mono"
        rows={3}
        placeholder="1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8"
        value={whisperAllowText}
        onChange={(e) => setWhisperAllowText(e.target.value)}
      />
      <div className="actions-row">
        <button
          className="primary"
          disabled={busy}
          onClick={() =>
            void onSaveWhisper(
              { ...whisperDraft, relay_allowlist: allowDraft },
              whisperRelayText,
            ).then((next) => {
              if (next) {
                setWhisperDraft(next);
                setWhisperRelayText(next.relay_urls.join("\n"));
                setWhisperAllowText((next.relay_allowlist ?? []).join("\n"));
              }
            })
          }
        >
          Save DUST Whisper
        </button>
      </div>

      <div className="info-box">
        <strong>No analytics telemetry.</strong> Balance and ownership queries use your configured
        node. HACD metadata may use the official mainnet node in read-only mode. Air-gap signing
        keeps keys off the online coordinator when a separate offline signer is used.
      </div>
    </section>
  );
}
