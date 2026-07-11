import { useCallback, useEffect, useRef, useState } from "react";
import { messengerApi, type ChatMessage, type ChatThread } from "../api";
import { type SavedContact } from "../contacts";
import { formatInvokeError } from "../formatInvokeError";
import { maskAddress } from "../privacy";

type Props = {
  myAddress?: string | null;
  hideAddresses?: boolean;
  whisperEnabled?: boolean;
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
  contacts,
  onToast,
  onGoPay,
}: Props) {
  const [threads, setThreads] = useState<ChatThread[]>([]);
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [newPeer, setNewPeer] = useState("");
  const [busy, setBusy] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const refreshThreads = useCallback(async () => {
    try {
      setThreads(await messengerApi.threads());
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    }
  }, [onToast]);

  const loadMessages = useCallback(
    async (peer: string) => {
      try {
        const rows = await messengerApi.messages(peer);
        setMessages(rows);
        await messengerApi.markRead(peer);
        await refreshThreads();
      } catch (e) {
        onToast(formatInvokeError(e), "error");
      }
    },
    [onToast, refreshThreads],
  );

  const pollInbox = useCallback(async () => {
    if (!whisperEnabled) return;
    try {
      const n = await messengerApi.pollInbox();
      if (n > 0) {
        await refreshThreads();
        if (activePeer) await loadMessages(activePeer);
        onToast(`${n} new message(s)`, "info");
      }
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    }
  }, [activePeer, loadMessages, onToast, refreshThreads, whisperEnabled]);

  useEffect(() => {
    void refreshThreads();
  }, [refreshThreads]);

  useEffect(() => {
    if (!whisperEnabled) return;
    const t = window.setInterval(() => void pollInbox(), 15000);
    return () => window.clearInterval(t);
  }, [pollInbox, whisperEnabled]);

  useEffect(() => {
    if (activePeer) void loadMessages(activePeer);
  }, [activePeer, loadMessages]);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  async function handleSend() {
    if (!activePeer || !draft.trim()) return;
    if (!whisperEnabled) {
      onToast("Enable DUST Whisper and configure a relay first.", "error");
      return;
    }
    setBusy(true);
    try {
      await messengerApi.send(activePeer, draft.trim());
      setDraft("");
      await loadMessages(activePeer);
      await refreshThreads();
      onToast("Message sent.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  function openPeer(peer: string) {
    setActivePeer(peer);
    setNewPeer("");
  }

  if (!activePeer) {
    return (
      <>
        {!whisperEnabled && (
          <div className="card">
            <p className="warn-text">
              Enable DUST Whisper (More → DUST Whisper) to send and receive encrypted messages.
            </p>
          </div>
        )}
        <div className="card">
          <h2>Messages</h2>
          <p className="muted small">End-to-end encrypted with your wallet signing keys.</p>
          <label className="label">New chat — Hacash address</label>
          <div className="row-btns">
            <input
              placeholder="1…"
              value={newPeer}
              onChange={(e) => setNewPeer(e.target.value)}
            />
            <button
              type="button"
              className="primary small"
              disabled={!newPeer.trim()}
              onClick={() => openPeer(newPeer.trim())}
            >
              Open
            </button>
          </div>
          {contacts.length > 0 && (
            <div className="chip-row">
              {contacts.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className="chip"
                  onClick={() => openPeer(c.address)}
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
            <button type="button" className="ghost" onClick={() => void pollInbox()}>
              Check inbox now
            </button>
          )}
        </div>
      </>
    );
  }

  return (
    <div className="card messenger-chat">
      <button type="button" className="ghost small" onClick={() => setActivePeer(null)}>
        ← Threads
      </button>
      <h2>{contactLabel(contacts, activePeer)}</h2>
      <p className="muted">{maskAddress(activePeer, hideAddresses ?? false)}</p>
      {onGoPay && (
        <button type="button" className="small" onClick={() => onGoPay(activePeer)}>
          Pay this contact
        </button>
      )}
      <div className="messenger-list" ref={listRef}>
        {messages.length === 0 ? (
          <p className="muted">No messages — say hello!</p>
        ) : (
          messages.map((m) => (
            <div
              key={m.id}
              className={`messenger-bubble ${m.direction === "out" ? "out" : "in"}`}
            >
              <p>{m.body}</p>
              <span className="muted">{m.timestamp_utc.slice(11, 19)}</span>
            </div>
          ))
        )}
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