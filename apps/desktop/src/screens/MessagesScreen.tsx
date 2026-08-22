/**
 * The desktop surface for the messenger.
 *
 * The five messenger commands have been registered for BOTH shells all along
 * (crates/wallet-tauri-common/src/handlers.rs, the shared block), and the
 * desktop shell is the only one that can host a relay
 * (crates/wallet-tauri-common/src/desktop_relay.rs). Until this file existed
 * nothing in apps/desktop/src called any of them, so the whole capability had
 * no way in on the platform that carries it.
 *
 * Three rules this screen holds to, because the wallet has shipped screens that
 * broke them:
 *
 * 1. Everything it says about privacy comes from `messenger_peer_security`,
 *    which reports whether the wallet holds a verified key for this contact and
 *    how many messages in the thread are not known to have been sealed. It
 *    never generalises that answer beyond what it covers.
 * 2. It never says a message was sent. `messenger_send` reports whether a relay
 *    accepted the envelope (`delivered`, crates/wallet-core/src/messenger.rs)
 *    and returns Ok either way. That flag, not the absence of an exception, is
 *    what the person is told.
 * 3. It never reports an empty inbox it has not seen. `messenger_poll_inbox`
 *    reports what it reached, and `pollReport` turns that into a sentence; a
 *    relay that never answered is not a relay with nothing to give.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  messengerApi,
  type ChatMessage,
  type ChatThread,
  type DustWhisperSettings,
  type MessengerPeerSecurity,
  type WalletStatus,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { peerRefusal } from "../messengerPeer";
import { pollReport } from "../messengerPoll";
import { privacyNotice, sealedLabel } from "../messengerPrivacy";
import { maskAddress } from "../privacy";
import type { Screen } from "./types";

export type SendOutcome = { text: string; kind: "success" | "error" };

/**
 * What the person is told after `messenger_send` returns.
 *
 * Called by `handleSend` below, which is the Send button's only handler. The
 * core stores the message locally whether or not a relay took it, so a returned
 * message with `delivered: false` is a message that is sitting on this computer
 * and nowhere else.
 */
export function sendOutcome(msg: ChatMessage): SendOutcome {
  return msg.delivered
    ? { text: "A relay accepted the message.", kind: "success" }
    : {
        text:
          "No relay accepted the message. It is saved on this computer only and has not been delivered.",
        kind: "error",
      };
}

/** Why the messenger is unavailable, or null when it is usable. */
export function messengerBlockedReason(status: WalletStatus | null): string | null {
  if (!status || status.locked) return "Unlock the wallet to open your messages.";
  if (status.watch_only) {
    return "A watch-only wallet has no signing key on this computer. The message store is sealed with that key, so it cannot be opened here.";
  }
  if (status.hardware_signing_mode === "airgap_only") {
    return "Cold Vault keeps the signing key off this computer. The message store is sealed with that key, so it cannot be opened here.";
  }
  return null;
}

type Props = {
  status: WalletStatus | null;
  dustWhisper: DustWhisperSettings;
  hideAddresses: boolean;
  onNavigate: (screen: Screen) => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
};

export default function MessagesScreen({
  status,
  dustWhisper,
  hideAddresses,
  onNavigate,
  onNotify,
}: Props) {
  const [threads, setThreads] = useState<ChatThread[]>([]);
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [newPeer, setNewPeer] = useState("");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [checkingPeer, setCheckingPeer] = useState(false);
  // null = the wallet was not asked or did not answer. The screen then says
  // nothing about privacy rather than guessing at it.
  const [peerSecurity, setPeerSecurity] = useState<MessengerPeerSecurity | null>(null);
  const activePeerRef = useRef<string | null>(null);

  const blocked = messengerBlockedReason(status);
  const relays = dustWhisper.relay_urls.map((u) => u.trim()).filter((u) => u.length > 0);
  const hasRelay = relays.length > 0;
  // `should_manage_relay` in crates/wallet-tauri-common/src/desktop_relay.rs
  // starts the embedded relay only when `enabled` AND `auto_start_relay` are
  // both set and a local relay URL is configured. With either switch off the
  // URL is there and nothing is listening on it.
  const localRelayIdle =
    hasRelay &&
    (!dustWhisper.enabled || !dustWhisper.auto_start_relay) &&
    relays.some((u) => /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(u));

  const refreshThreads = useCallback(async () => {
    if (blocked) return;
    try {
      setThreads(await messengerApi.threads());
    } catch (error) {
      onNotify(formatInvokeError(error), "error");
    }
  }, [blocked, onNotify]);

  const refreshPeerSecurity = useCallback(async (peer: string) => {
    try {
      const security = await messengerApi.peerSecurity(peer);
      if (activePeerRef.current === peer) setPeerSecurity(security);
    } catch {
      if (activePeerRef.current === peer) setPeerSecurity(null);
    }
  }, []);

  const loadMessages = useCallback(
    async (peer: string) => {
      try {
        const rows = await messengerApi.messages(peer);
        if (activePeerRef.current !== peer) return;
        setMessages(rows);
        await messengerApi.markRead(peer);
        if (activePeerRef.current === peer) await refreshThreads();
      } catch (error) {
        if (activePeerRef.current === peer) onNotify(formatInvokeError(error), "error");
      }
    },
    [onNotify, refreshThreads],
  );

  useEffect(() => {
    void refreshThreads();
  }, [refreshThreads]);

  useEffect(() => {
    if (activePeer) void loadMessages(activePeer);
  }, [activePeer, loadMessages]);

  useEffect(() => {
    if (activePeer) void refreshPeerSecurity(activePeer);
  }, [activePeer, refreshPeerSecurity]);

  async function checkInbox() {
    setBusy(true);
    try {
      const outcome = await messengerApi.pollInbox();
      await refreshThreads();
      if (activePeerRef.current) {
        await loadMessages(activePeerRef.current);
        await refreshPeerSecurity(activePeerRef.current);
      }
      // Zero is not a fact about the relay's contents unless a relay actually
      // answered, so the counts decide the sentence, not the message total.
      const report = pollReport(outcome);
      onNotify(report.text, report.kind);
    } catch (error) {
      onNotify(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleSend() {
    const peer = activePeer;
    const body = draft.trim();
    if (!peer || !body) return;
    setBusy(true);
    try {
      const sent = await messengerApi.send(peer, body);
      // Cleared only once a relay took it. The failure notice asks the person
      // to send it again, and emptying the box first meant retyping the message
      // out of a chat bubble to do that.
      if (activePeerRef.current === peer && sent?.delivered === true) setDraft("");
      await loadMessages(peer);
      await refreshPeerSecurity(peer);
      const outcome = sendOutcome(sent);
      onNotify(outcome.text, outcome.kind);
    } catch (error) {
      onNotify(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }

  function openPeer(peer: string) {
    const normalized = peer.trim();
    if (!normalized) return;
    activePeerRef.current = normalized;
    setPeerSecurity(null);
    setMessages([]);
    setDraft("");
    setNewPeer("");
    setActivePeer(normalized);
  }

  /**
   * A new conversation may only be started against an address that could
   * receive one.
   *
   * The decoding is the wallet's own (`wallet_inspect_address` -> Rust
   * `parse_address`), so a typo or a half-paste fails there and the person is
   * shown the decoder's own reason. `peerRefusal` covers the addresses that do
   * decode but have no signing key behind them, and so no key that could ever
   * claim their inbox. `require_messenger_peer` in
   * crates/wallet-core/src/messenger.rs refuses the same set on the send
   * itself; this is the earlier copy, so the refusal lands on the typo rather
   * than after a message has been written against it.
   *
   * Threads already on this computer still open through `openPeer`: existing
   * history stays readable.
   */
  async function openCheckedPeer(peer: string) {
    const candidate = peer.trim();
    if (!candidate) return;
    setCheckingPeer(true);
    try {
      const parsed = await api.inspectAddress(candidate);
      const refusal = peerRefusal(parsed);
      if (refusal) {
        onNotify(refusal, "error");
        return;
      }
      openPeer(candidate);
    } catch (error) {
      onNotify(formatInvokeError(error), "error");
    } finally {
      setCheckingPeer(false);
    }
  }

  function closePeer() {
    activePeerRef.current = null;
    setPeerSecurity(null);
    setMessages([]);
    setDraft("");
    setActivePeer(null);
  }

  if (blocked) {
    return (
      <section className="panel">
        <h2>Messages</h2>
        <p className="warn-box">{blocked}</p>
      </section>
    );
  }

  const relayNotice = !hasRelay ? (
    <div className="warn-box">
      <p>
        No message relay is configured, so nothing can be sent or received. A relay is the
        mailbox both wallets collect from; the two of you have to name the same one.
      </p>
      <p>
        This computer can run one itself. The Privacy screen offers{" "}
        <code>http://127.0.0.1:8787</code>, and the wallet runs that relay while DUST Whisper
        and its auto-start option are both on. A relay on this computer is reachable only by
        wallets that can reach this computer.
      </p>
      <button type="button" className="primary" onClick={() => onNavigate("privacy")}>
        Open Privacy to set the relay
      </button>
    </div>
  ) : localRelayIdle ? (
    <div className="warn-box">
      <p>
        A relay on this computer is configured but is not running: the wallet starts it only
        while DUST Whisper and its auto-start option are both on, on the Privacy screen.
      </p>
      <button type="button" onClick={() => onNavigate("privacy")}>
        Open Privacy
      </button>
    </div>
  ) : null;

  if (!activePeer) {
    return (
      <section className="panel">
        <h2>Messages</h2>
        {relayNotice}
        <p className="muted small">
          {hasRelay
            ? `Relay: ${relays.join(", ")}`
            : "Relay: none configured."}
        </p>
        <label htmlFor="messenger-new-peer">New conversation. Hacash address</label>
        <div className="actions-row">
          <input
            id="messenger-new-peer"
            placeholder="1…"
            value={newPeer}
            onChange={(e) => setNewPeer(e.target.value)}
          />
          <button
            type="button"
            className="primary"
            disabled={checkingPeer || !newPeer.trim()}
            onClick={() => void openCheckedPeer(newPeer)}
          >
            {checkingPeer ? "Checking…" : "Open"}
          </button>
        </div>
        {threads.length === 0 ? (
          <p className="muted">No conversations yet.</p>
        ) : (
          <ul className="messenger-threads">
            {threads.map((t) => (
              <li key={t.peer}>
                <button type="button" className="messenger-thread" onClick={() => openPeer(t.peer)}>
                  <strong>{maskAddress(t.peer, hideAddresses)}</strong>
                  {t.unread > 0 && <span className="badge badge-warn">{t.unread}</span>}
                  <span className="muted">{t.last_message}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="actions-row">
          <button type="button" disabled={busy || !hasRelay} onClick={() => void checkInbox()}>
            Check the relay for new messages
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel messenger-chat">
      <button type="button" className="messenger-back" onClick={closePeer}>
        ← Conversations
      </button>
      <h2>{maskAddress(activePeer, hideAddresses)}</h2>
      {relayNotice}
      {(() => {
        const notice = privacyNotice(peerSecurity);
        if (!notice) return null;
        return (
          <p className={notice.tone === "ok" ? "muted small" : "warn-box"} role="status">
            {notice.text}
          </p>
        );
      })()}
      <div className="messenger-list">
        {messages.length === 0 ? (
          <p className="muted">No messages in this conversation.</p>
        ) : (
          messages.map((m) => (
            <div
              key={m.id}
              className={`messenger-bubble ${m.direction === "out" ? "out" : "in"}`}
            >
              <p>{m.body}</p>
              <span className="muted">
                {m.timestamp_utc.slice(11, 19)}
                {m.direction === "out" && !m.delivered ? " · not delivered" : ""}
                {sealedLabel(m.sealed) ? ` · ${sealedLabel(m.sealed)}` : ""}
              </span>
            </div>
          ))
        )}
      </div>
      <div className="messenger-compose">
        <input
          placeholder="Type a message…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void handleSend();
          }}
        />
        <button
          type="button"
          className="primary"
          disabled={busy || !draft.trim() || !hasRelay}
          onClick={() => void handleSend()}
        >
          Send
        </button>
      </div>
      {status?.address && (
        <p className="muted small">From {maskAddress(status.address, hideAddresses)}</p>
      )}
    </section>
  );
}
