import { useCallback, useEffect, useRef, useState } from "react";
import { Webview } from "@tauri-apps/api/webview";
import { api, type DappApprovalView } from "../api";

type Props = {
  onNotify: (message: string, kind: "error" | "info" | "success") => void;
};

const POLL_MS = 350;

function displayHost(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

export default function DappApprovalPanel({ onNotify }: Props) {
  const [pending, setPending] = useState<DappApprovalView | null>(null);
  const [busy, setBusy] = useState(false);
  const [showDetail, setShowDetail] = useState(false);
  const hiddenLaunchpad = useRef(false);
  const previousId = useRef<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const next = await api.dappPending();
      if (next?.id !== previousId.current) {
        previousId.current = next?.id ?? null;
        setShowDetail(false);
      }
      setPending(next);
    } catch {
      // Keep the current prompt visible across a transient IPC error.
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

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

  const decide = async (approved: boolean) => {
    if (!pending || busy) return;
    setBusy(true);
    try {
      if (approved) {
        if (pending.kind === "transfer" || pending.kind === "sign") {
          await api.confirmBiometric();
        }
        await api.dappApprove(pending.id);
        onNotify("dApp request approved.", "success");
      } else {
        await api.dappReject(pending.id, "User declined");
        onNotify("dApp request declined.", "info");
      }
      previousId.current = null;
      setPending(null);
      void refresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };

  if (!pending) return null;

  return (
    <div className="dapp-mobile-backdrop" role="dialog" aria-modal="true" aria-labelledby="dapp-mobile-title">
      <section className="dapp-mobile-modal">
        <div className="dapp-mobile-badge">{pending.kind.toUpperCase()}</div>
        <h2 id="dapp-mobile-title">{pending.title}</h2>
        <p className="dapp-mobile-origin">Request from <strong>{displayHost(pending.origin)}</strong></p>
        <p className="dapp-mobile-summary">{pending.summary}</p>

        {pending.detail ? (
          <div className="dapp-mobile-detail-wrap">
            <button type="button" className="dapp-mobile-detail-toggle" onClick={() => setShowDetail((value) => !value)}>
              {showDetail ? "Hide transaction details" : "Review transaction details"}
            </button>
            {showDetail ? <pre className="dapp-mobile-detail">{pending.detail}</pre> : null}
          </div>
        ) : null}

        <p className="dapp-mobile-warning">Approve only if you started this action and every detail is correct.</p>
        <div className="dapp-mobile-actions">
          <button type="button" disabled={busy} onClick={() => void decide(false)}>Decline</button>
          <button type="button" className="primary" disabled={busy} onClick={() => void decide(true)}>
            {busy ? "Checking..." : "Approve"}
          </button>
        </div>
      </section>
    </div>
  );
}
