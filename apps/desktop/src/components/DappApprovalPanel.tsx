import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { Webview } from "@tauri-apps/api/webview";
import {
  dappApprovalKindCopy,
  translatedDappApprovalCopy,
  type DappApprovalCopy,
} from "@hacash/wallet-ui";
import { api, type DappApprovalView } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { runWebAuthnAuth, webAuthnClientOrigin } from "../webauthn";
import { useLocale } from "../locale";

type Props = {
  unlocked: boolean;
  onNotify?: (msg: string, kind: "error" | "info" | "success") => void;
};

const POLL_MS = 400;

type KindVisual = {
  glyph: string;
  accent: string;
};

const KIND_VISUAL: Record<string, KindVisual> = {
  connect: {
    glyph: "⬡",
    accent: "#f5a623",
  },
  sign: {
    glyph: "✦",
    accent: "#f5a623",
  },
  transfer: {
    glyph: "◎",
    accent: "#f5a623",
  },
};

function hostFromOrigin(origin: string): string {
  try {
    return new URL(origin).host || origin;
  } catch {
    return origin.replace(/^https?:\/\//, "").split("/")[0] || origin;
  }
}

function metaForKind(kind: string, copy: DappApprovalCopy) {
  return {
    ...dappApprovalKindCopy(kind, copy),
    ...(KIND_VISUAL[kind] ?? {
      glyph: "◆",
      accent: "#f5a623",
    }),
  };
}

export default function DappApprovalPanel({ unlocked, onNotify }: Props) {
  const { t } = useLocale();
  const copy = useMemo(() => translatedDappApprovalCopy(t), [t]);
  const [pending, setPending] = useState<DappApprovalView | null>(null);
  const [busy, setBusy] = useState(false);
  const [showDetail, setShowDetail] = useState(false);
  const hiddenLaunchpad = useRef(false);
  const previousId = useRef<string | null>(null);

  const refresh = useCallback(async () => {
    if (!unlocked) {
      previousId.current = null;
      setPending(null);
      return;
    }
    try {
      const next = await api.dappPending();
      if (next?.id !== previousId.current) {
        previousId.current = next?.id ?? null;
        setShowDetail(false);
      }
      setPending(next);
    } catch {
      // Preserve an active approval across a transient IPC error.
    }
  }, [unlocked]);

  useEffect(() => {
    if (!unlocked) return;
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [unlocked, refresh]);
  useEffect(() => {
    let cancelled = false;
    void Webview.getByLabel("launchpad").then(async (webview) => {
      if (!webview || cancelled) return;
      if (pending && !hiddenLaunchpad.current) {
        await webview.hide().catch(() => undefined);
        hiddenLaunchpad.current = true;
      } else if (!pending && hiddenLaunchpad.current) {
        await webview.show().catch(() => undefined);
        hiddenLaunchpad.current = false;
      }
    });
    return () => {
      cancelled = true;
    };
  }, [pending]);

  useEffect(() => () => {
    if (!hiddenLaunchpad.current) return;
    void Webview.getByLabel("launchpad").then((webview) => {
      void webview?.show().catch(() => undefined);
    });
    hiddenLaunchpad.current = false;
  }, []);

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
      previousId.current = null;
      setPending(null);
      onNotify?.(copy.requestApproved, "success");
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
      await api.dappReject(pending.id, copy.requestDeclined);
      previousId.current = null;
      setPending(null);
      onNotify?.(copy.requestDeclined, "info");
      void refresh();
    } catch (e) {
      onNotify?.(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!pending) return null;

  const meta = metaForKind(pending.kind, copy);
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
            <h2 id="dapp-approval-title">{meta.label}</h2>
          </div>
        </header>

        <div className="dapp-approval-origin-row">
          <span className="dapp-approval-origin-label">{copy.from}</span>
          <span className="dapp-approval-origin-host" title={pending.origin}>
            {host}
          </span>
        </div>

        <p className="dapp-approval-summary">{meta.hint}</p>

        {pending.detail ? (
          <div className="dapp-approval-detail-wrap">
            <button
              type="button"
              className="dapp-approval-detail-toggle"
              onClick={() => setShowDetail((v) => !v)}
              aria-expanded={showDetail}
            >
              {showDetail ? copy.hideDetails : copy.showDetails}
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
            {copy.decline}
          </button>
          <button
            type="button"
            className="dapp-approval-btn-accept"
            disabled={busy}
            onClick={() => void handleApprove()}
          >
            {busy ? copy.working : copy.accept}
          </button>
        </footer>

        <p className="dapp-approval-footnote">{copy.approvalFootnote}</p>
      </div>
    </div>
  );
}
