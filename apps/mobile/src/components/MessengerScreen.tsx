import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  messengerApi,
  type ChatMessage,
  type ChatThread,
  type MessengerPeerSecurity,
  type WalletStatus,
} from "../api";
import { type SavedContact } from "../contacts";
import { formatInvokeError } from "../formatInvokeError";
import { peerRefusal } from "../messengerPeer";
import { maskAddress } from "../privacy";
import { deliveryLabel, sendReceipt } from "../messengerDelivery";
import { messengerBlockedReason } from "../messengerAccess";
import { pollReport } from "../messengerPoll";
import { privacyNotice, sealedLabel } from "../messengerPrivacy";
import { arrivalNote } from "../messengerTiming";
import {
  failedProbe,
  isCurrentKeyedRequest,
  loadingProbe,
  readyProbe,
  type AsyncProbe,
  type KeyedRequest,
} from "../asyncProbe";

type Props = {
  myAddress?: string | null;
  hideAddresses?: boolean;
  whisperEnabled?: boolean;
  /**
   * Needed so the screen can decline before it asks. A watch-only or Cold Vault
   * wallet has no key to open the message store with, and asking anyway threw
   * raw policy text at the person every fifteen seconds.
   */
  status?: WalletStatus | null;
  contacts: SavedContact[];
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onGoPay?: (peer: string) => void;
};

function contactLabel(contacts: SavedContact[], peer: string): string {
  const c = contacts.find((x) => x.address === peer);
  return c?.label ?? peer.slice(0, 10) + "…";
}

export default function MessengerScreen({
  myAddress,
  hideAddresses,
  whisperEnabled,
  status,
  contacts,
  onToast,
  onGoPay,
}: Props) {
  const [threads, setThreads] = useState<ChatThread[]>([]);
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [messageProbe, setMessageProbe] = useState<AsyncProbe<ChatMessage[]>>(
    () => readyProbe([]),
  );
  const [draft, setDraft] = useState("");
  const [newPeer, setNewPeer] = useState("");
  const [busy, setBusy] = useState(false);
  const [checkingPeer, setCheckingPeer] = useState(false);
  const [polling, setPolling] = useState(false);
  // null = not established. The screen says nothing about privacy in that state.
  const [peerSecurity, setPeerSecurity] = useState<MessengerPeerSecurity | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const activePeerRef = useRef<string | null>(null);
  /** True once a background poll has already reported a failure. */
  const warnedRef = useRef(false);
  const messageGeneration = useRef(0);
  const messages = messageProbe.value;
  const blocked = messengerBlockedReason(status);

  const refreshThreads = useCallback(async () => {
    if (blocked) return;
    try {
      setThreads(await messengerApi.threads());
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    }
  }, [blocked, onToast]);

  /**
   * Ask the wallet what is true about this conversation, and say only that.
   *
   * A message is sealed to a contact's own key only when this wallet holds that
   * key. It learns one from an envelope the contact signed, and on a first
   * message it asks the configured relays for one and keeps it only if it
   * derives back to that contact's address (`lookup_peer_key`,
   * crates/wallet-core/src/messenger.rs). Without a key that survives that,
   * `encrypt_for_send` falls back to one derived from the two addresses, and
   * the relay stores both of those in clear next to the body, so the operator
   * can read the message. The answer also carries how many messages already in
   * this thread were sent that way, because a banner about the next message
   * says nothing about the ones already on screen. When the answer cannot be
   * obtained the banner stays silent instead of guessing.
   *
   * This is read from disk, so before the very first send it says the wallet
   * holds no key even when the send is about to fetch and verify one. Under
   * claiming is the only direction that cannot turn into a false claim, and it
   * corrects itself immediately after the send, which is why every call site
   * refreshes once the send returns.
   */
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
      if (activePeerRef.current !== peer) return;
      const request: KeyedRequest<string> = {
        key: peer,
        generation: ++messageGeneration.current,
      };
      setMessageProbe(loadingProbe([]));
      try {
        const rows = await messengerApi.messages(peer);
        if (
          !isCurrentKeyedRequest(
            activePeerRef.current,
            messageGeneration.current,
            request,
          )
        ) {
          return;
        }
        setMessageProbe(readyProbe(rows));
        try {
          await messengerApi.markRead(peer);
          if (
            isCurrentKeyedRequest(
              activePeerRef.current,
              messageGeneration.current,
              request,
            )
          ) {
            await refreshThreads();
          }
        } catch (error) {
          if (
            isCurrentKeyedRequest(
              activePeerRef.current,
              messageGeneration.current,
              request,
            )
          ) {
            onToast(formatInvokeError(error), "error");
          }
        }
      } catch (error) {
        if (
          isCurrentKeyedRequest(
            activePeerRef.current,
            messageGeneration.current,
            request,
          )
        ) {
          setMessageProbe(failedProbe([], formatInvokeError(error)));
          onToast(formatInvokeError(error), "error");
        }
      }
    },
    [onToast, refreshThreads],
  );

  /**
   * `announce` is false for the fifteen-second timer and true for the button.
   *
   * The button always answers, because a control that changes nothing on screen
   * reads as a broken control. The timer stays quiet except for messages that
   * arrived, and one warning the first time a pass fails, so a relay that has
   * been down for an hour is reported once rather than 240 times. It never
   * reports a healthy empty inbox it did not see: that is what `pollReport`
   * refuses to say.
   */
  const pollInbox = useCallback(
    async (announce: boolean) => {
      if (blocked || !whisperEnabled) return;
      if (announce) setPolling(true);
      try {
        const outcome = await messengerApi.pollInbox();
        await refreshThreads();
        if (activePeer) {
          await loadMessages(activePeer);
          // A verified inbound envelope is where a contact's key comes from, so
          // the conversation can become sealed on this very poll.
          await refreshPeerSecurity(activePeer);
        }
        const report = pollReport(outcome);
        const firstFailure = report.kind === "error" && !warnedRef.current;
        if (report.kind === "error") warnedRef.current = true;
        else warnedRef.current = false;
        if (announce || outcome.added > 0 || firstFailure) {
          onToast(report.text, report.kind);
        }
      } catch (e) {
        if (announce || !warnedRef.current) onToast(formatInvokeError(e), "error");
        warnedRef.current = true;
      } finally {
        if (announce) setPolling(false);
      }
    },
    [
      activePeer,
      blocked,
      loadMessages,
      onToast,
      refreshPeerSecurity,
      refreshThreads,
      whisperEnabled,
    ],
  );

  useEffect(() => {
    void refreshThreads();
  }, [refreshThreads]);

  useEffect(() => {
    if (!whisperEnabled) return;
    const t = window.setInterval(() => void pollInbox(false), 15000);
    return () => window.clearInterval(t);
  }, [pollInbox, whisperEnabled]);

  useEffect(() => {
    if (activePeer) void loadMessages(activePeer);
  }, [activePeer, loadMessages]);

  useEffect(() => {
    if (activePeer) void refreshPeerSecurity(activePeer);
  }, [activePeer, refreshPeerSecurity]);

  useEffect(
    () => () => {
      activePeerRef.current = null;
      messageGeneration.current += 1;
    },
    [],
  );

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  async function handleSend() {
    if (!activePeer || !draft.trim()) return;
    const peer = activePeer;
    const message = draft.trim();
    if (!whisperEnabled) {
      onToast("Enable DUST Whisper and configure a relay first.", "error");
      return;
    }
    setBusy(true);
    try {
      // messenger_send returns Ok as soon as the message is written to local
      // history, whether or not a relay took it. The returned message carries
      // the only fact about transport there is, so report that and not the
      // absence of an exception.
      const sent = await messengerApi.send(peer, message);
      // The draft is only cleared once a relay took it. The failure receipt
      // tells the person to send it again, and clearing the box first meant
      // retyping the message out of a chat bubble to do that.
      if (activePeerRef.current === peer && sent?.delivered === true) setDraft("");
      await loadMessages(peer);
      await refreshPeerSecurity(peer);
      const receipt = sendReceipt(sent);
      onToast(receipt.text, receipt.kind);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  function openPeer(peer: string) {
    const normalized = peer.trim();
    activePeerRef.current = normalized;
    messageGeneration.current += 1;
    setMessageProbe(loadingProbe([]));
    setPeerSecurity(null);
    setActivePeer(normalized);
    setDraft("");
    setNewPeer("");
  }

  /**
   * Start a conversation only against an address that could receive one.
   *
   * A mistyped or half-pasted address used to open a thread, take a message,
   * and report a send for something nobody could ever collect. The decoding is
   * the wallet's own (`wallet_inspect_address` -> Rust `parse_address`), so a
   * bad string fails there and the person sees the decoder's own reason;
   * `peerRefusal` covers the addresses that decode but have no signing key
   * behind them. `require_messenger_peer` in crates/wallet-core/src/messenger.rs
   * refuses exactly the same set on the send itself - this copy exists only so
   * the refusal arrives at the typo instead of after a message is written.
   *
   * Existing threads deliberately still open through `openPeer`: history that
   * is already on the device stays readable.
   */
  async function openCheckedPeer(peer: string) {
    const candidate = peer.trim();
    if (!candidate) return;
    setCheckingPeer(true);
    try {
      const parsed = await api.inspectAddress(candidate);
      const refusal = peerRefusal(parsed);
      if (refusal) {
        onToast(refusal, "error");
        return;
      }
      openPeer(candidate);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setCheckingPeer(false);
    }
  }

  function closePeer() {
    activePeerRef.current = null;
    messageGeneration.current += 1;
    setMessageProbe(readyProbe([]));
    setPeerSecurity(null);
    setDraft("");
    setActivePeer(null);
  }

  if (blocked) {
    return (
      <div className="card">
        <h2>Messages</h2>
        <p className="warn-text" role="status">
          {blocked}
        </p>
      </div>
    );
  }

  if (!activePeer) {
    return (
      <>
        {!whisperEnabled && (
          <div className="card">
            <p className="warn-text">
              DUST Whisper is off. Turn it on and name a relay (More, then DUST
              Whisper) before anything can be sent or collected. There is no
              public relay, so somebody has to run one and it can be you:
              docs/RUNNING-A-RELAY.md.
            </p>
          </div>
        )}
        <div className="card">
          <h2>Messages</h2>
          <p className="muted small">
            A conversation is sealed to a contact's own key only once this
            wallet holds that key. It learns one from anything they have sent
            you, and before a first message it asks the relays you have named
            for one, using an answer only if that key proves it belongs to that
            address. If none does, the relay operator can read what you send.
            Open a conversation to see where it stands, and read each message's
            own marker for how it actually travelled.
          </p>
          <label className="label">New chat. Hacash address</label>
          <div className="row-btns">
            <input
              placeholder="1…"
              value={newPeer}
              onChange={(e) => setNewPeer(e.target.value)}
            />
            <button
              type="button"
              className="primary small"
              disabled={checkingPeer || !newPeer.trim()}
              onClick={() => void openCheckedPeer(newPeer)}
            >
              {checkingPeer ? "Checking…" : "Open"}
            </button>
          </div>
          {contacts.length > 0 && (
            <div className="chip-row">
              {contacts.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className="chip"
                  disabled={checkingPeer}
                  onClick={() => void openCheckedPeer(c.address)}
                >
                  {c.label}
                </button>
              ))}
            </div>
          )}
          {threads.length === 0 ? (
            <p className="muted">No conversations yet.</p>
          ) : (
            threads.map((t) => (
              <div key={t.peer} className="list-item" onClick={() => openPeer(t.peer)}>
                <div>
                  <strong>{contactLabel(contacts, t.peer)}</strong>
                  {t.unread > 0 && <span className="badge badge-warn"> {t.unread}</span>}
                </div>
                <div className="muted">{t.last_message}</div>
              </div>
            ))
          )}
          {whisperEnabled && (
            <button
              type="button"
              className="ghost"
              disabled={polling}
              onClick={() => void pollInbox(true)}
            >
              {polling ? "Checking…" : "Check inbox now"}
            </button>
          )}
        </div>
      </>
    );
  }

  return (
    <div className="card messenger-chat">
      <button type="button" className="ghost small" onClick={closePeer}>
        ← Threads
      </button>
      <h2>{contactLabel(contacts, activePeer)}</h2>
      <p className="muted">{maskAddress(activePeer, hideAddresses ?? false)}</p>
      {onGoPay && (
        <button type="button" className="small" onClick={() => onGoPay(activePeer)}>
          Pay this contact
        </button>
      )}
      {(() => {
        const notice = privacyNotice(peerSecurity);
        if (!notice) return null;
        return (
          <p
            className={
              notice.tone === "ok"
                ? "muted small messenger-sealed"
                : "warn-text small messenger-sealed"
            }
            role="status"
          >
            {notice.text}
          </p>
        );
      })()}
      <div className="messenger-list" ref={listRef}>
        {messageProbe.status === "loading" ? (
          <p className="muted" aria-live="polite">Loading messages…</p>
        ) : null}
        {messageProbe.status === "failed" ? (
          <div className="error-box" role="alert">
            <p>{messageProbe.message}</p>
            <button type="button" className="small" onClick={() => void loadMessages(activePeer)}>
              Retry messages
            </button>
          </div>
        ) : null}
        {messageProbe.status === "ready" && messages.length === 0 ? (
          <p className="muted">No messages. say hello!</p>
        ) : null}
        {messageProbe.status === "ready" && messages.length > 0 ? (
          messages.map((m) => {
            const delivery = deliveryLabel(m);
            const seal = sealedLabel(m.sealed);
            const held = arrivalNote(m);
            return (
              <div
                key={m.id}
                className={`messenger-bubble ${m.direction === "out" ? "out" : "in"}`}
              >
                <p>{m.body}</p>
                <span className="muted">{m.timestamp_utc.slice(11, 19)}</span>
                {held ? <span className="warn-text messenger-status">{held}</span> : null}
                {delivery ? (
                  <span
                    className={
                      delivery.delivered
                        ? "muted messenger-status"
                        : "warn-text messenger-status"
                    }
                  >
                    {delivery.text}
                  </span>
                ) : null}
                {seal ? (
                  <span
                    className={
                      m.sealed === true
                        ? "muted messenger-status"
                        : "warn-text messenger-status"
                    }
                  >
                    {seal}
                  </span>
                ) : null}
              </div>
            );
          })
        ) : null}
      </div>
      <div className="messenger-compose">
        <input
          placeholder="Type a message…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void handleSend()}
        />
        <button type="button" className="primary" disabled={busy || !draft.trim()} onClick={() => void handleSend()}>
          Send
        </button>
      </div>
      {myAddress && <p className="muted small">From {maskAddress(myAddress, hideAddresses ?? false)}</p>}
    </div>
  );
}