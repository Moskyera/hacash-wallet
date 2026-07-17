import { useCallback, useEffect, useState, type CSSProperties } from "react";
import { api, type DappApprovalView } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { runWebAuthnAuth, webAuthnClientOrigin } from "../webauthn";

type Props = {
  unlocked: boolean;
  onNotify?: (msg: string, kind: "error" | "info" | "success") => void;
};

const POLL_MS = 400;

type KindMeta = {
  label: string;
  glyph: string;
  accent: string;
  hint: string;
};

const KIND_META: Record<string, KindMeta> = {
  connect: {
    label: "Connect",
    glyph: "⬡",
    accent: "#f5a623",
    hint: "The app will be able to request transaction signatures from your wallet.",
  },
  sign: {
    label: "Sign",
    glyph: "✦",
    accent: "#f5a623",
    hint: "Review the transaction details before you approve.",
  },
  transfer: {
    label: "Transfer",
    glyph: "◎",
    accent: "#f5a623",
    hint: "This will move HAC from your wallet if you accept.",
  },
};

function hostFromOrigin(origin: string): string {
  try {
    return new URL(origin).host || origin;
  } catch {
    return origin.replace(/^https?:\/\//, "").split("/")[0] || origin;
  }
}

function metaForKind(kind: string): KindMeta {
  return (
    KIND_META[kind] ?? {
      label: kind,
      glyph: "◆",
      accent: "#f5a623",
      hint: "Only approve if you trust this application.",
    }
  );
}

export default function DappApprovalPanel({ unlocked, onNotify }: Props) {
  const [pending, setPending] = useState<DappApprovalView | null>(null);
  const [busy, setBusy] = useState(false);
  const [showDetail, setShowDetail] = useState(false);

  const refresh = useCallback(async () => {
    if (!unlocked) {
      setPending(null);
      return;
    }
    try {
      const next = await api.dappPending();
      setPending(next);
      if (next) setShowDetail(false);
    } catch {
      setPending(null);
    }
  }, [unlocked]);

  useEffect(() => {
    if (!unlocked) return;
    void api.dappBridgeStart().catch(() => undefined);
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [unlocked, refresh]);

  const handleApprove = async () => {
    if (!pending || busy) return;
    setBusy(true);
    try {
      if (pending.kind === "transfer" || pending.kind === "sign") {
        const status = await api.status();
        if (status.webauthn_enabled) {
          const options = await api.webauthnAuthBegin(webAuthnClientOrigin());
          const assertion = await runWebAuthnAuth(options);
          await api.webauthnAuthFinish(assertion);
        } else {
          await api.confirmBiometricNative();
        }
      }
      await api.dappApprove(pending.id);
      setPending(null);
      onNotify?.("Request approved.", "success");
      void refresh();
    } catch (e) {
      onNotify?.(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const handleReject = async () => {
    if (!pending || busy) return;
    setBusy(true);
    try {
      await api.dappReject(pending.id, "User declined");
      setPending(null);
      onNotify?.("Request declined.", "info");
      void refresh();
    } catch (e) {
      onNotify?.(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!pending) return null;

  const meta = metaForKind(pending.kind);
  const host = hostFromOrigin(pending.origin);

  return (
    <div
      className="dapp-approval-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dapp-approval-title"
    >
      <div
        className="dapp-approval-modal"
        style={{ "--dapp-accent": meta.accent } as CSSProperties}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="dapp-approval-glow" aria-hidden />

        <header className="dapp-approval-header">
          <div className="dapp-approval-icon" aria-hidden>
            {meta.glyph}
          </div>
          <div className="dapp-approval-head-text">
            <span className="dapp-approval-kind">{meta.label}</span>
            <h2 id="dapp-approval-title">{pending.title}</h2>
          </div>
        </header>

        <div className="dapp-approval-origin-row">
          <span className="dapp-approval-origin-label">From</span>
          <span className="dapp-approval-origin-host" title={pending.origin}>
            {host}
          </span>
        </div>

        <p className="dapp-approval-summary">{pending.summary}</p>
        <p className="dapp-approval-hint">{meta.hint}</p>

        {pending.detail ? (
          <div className="dapp-approval-detail-wrap">
            <button
              type="button"
              className="dapp-approval-detail-toggle"
              onClick={() => setShowDetail((v) => !v)}
              aria-expanded={showDetail}
            >
              {showDetail ? "Hide technical details" : "Show technical details"}
            </button>
            {showDetail && (
              <pre className="dapp-approval-detail">{pending.detail}</pre>
            )}
          </div>
        ) : null}

        <footer className="dapp-approval-actions">
          <button
            type="button"
            className="dapp-approval-btn-decline"
            disabled={busy}
            onClick={() => void handleReject()}
          >
            Decline
          </button>
          <button
            type="button"
            className="dapp-approval-btn-accept"
            disabled={busy}
            onClick={() => void handleApprove()}
          >
            {busy ? "Working…" : "Accept"}
          </button>
        </footer>

        <p className="dapp-approval-footnote">
          Only accept requests from sites you trust. Decline if you did not start this action.
        </p>
      </div>
    </div>
  );
}
