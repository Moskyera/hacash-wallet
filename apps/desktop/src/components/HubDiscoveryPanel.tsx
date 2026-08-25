import { useState } from "react";
import {
  api,
  type HubDeclaration,
  type HubDiscoveryEntry,
  type HubDiscoveryReport,
  type WalletSettings,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import {
  FAST_PAY_NO_HUB_EXPLANATION,
  FAST_PAY_PILOT_ALLOWLIST_NOTE,
  FAST_PAY_SELF_HOSTED_HUB_NOTE,
  HUB_OPERATOR_URL,
  HubDeclarationCard,
} from "@hacash/wallet-ui";

type Props = {
  settings: WalletSettings | null;
  activeHubUrl?: string;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  /** Keeps a host screen's own hub-URL draft in step with the one typed here. */
  onHubUrlChange?: (url: string) => void;
  /** Injected so this component gains no shell privileges of its own. */
  openExternal?: (url: string) => void | Promise<unknown>;
};

/**
 * Find, inspect and adopt a Fast Pay provider, all on one surface.
 *
 * Three things were wrong here and all three are fixed together, because they
 * were one dead end wearing three hats.
 *
 * The panel's copy told people to paste the address their provider gave them
 * into a field "above". On Settings that field was above; on the Fast Pay
 * screen there was no such field anywhere, and on desktop it was below and
 * collapsed inside "Technical settings (advanced)". So the panel now owns the
 * field, and the sentence is true wherever the panel renders.
 *
 * Discovery then read the SAVED hub URL, so a URL typed and not yet saved was
 * the one candidate the scan skipped. The typed value is now passed to the
 * scan as an explicit argument.
 *
 * And a person who found a Hub was shown this build's compile-time ceilings
 * rather than that Hub's declared caps. "Check this hub" reads the Hub's own
 * /v1/health and /v1/readiness/mainnet and prints them verbatim, including its
 * blockers, before any money is committed.
 *
 * No preset is invented. There is genuinely no public Hub, and a fabricated
 * address would be worse than an empty list, so the empty state says the true
 * thing instead.
 */
export default function HubDiscoveryPanel({
  settings,
  activeHubUrl,
  busy,
  setBusy,
  onApplyHub,
  onToast,
  onHubUrlChange,
  openExternal,
}: Props) {
  const [report, setReport] = useState<HubDiscoveryReport | null>(null);
  const [scanning, setScanning] = useState(false);
  /**
   * What the person has typed, or `null` while they have typed nothing.
   *
   * This used to be `useState(activeHubUrl ?? "")`, and that is why "Check this
   * hub" was greyed out on arrival every single time, with a hub saved. A
   * `useState` initializer runs once, at mount, and at mount `activeHubUrl` is
   * empty: the parent holds `useState("")` and fills it from settings inside a
   * `useEffect`, which by definition runs after this child has already mounted
   * and taken its snapshot. Nothing resynced it. So the field rendered empty
   * whatever was saved, the button's `!draftUrl.trim()` clause held forever, and
   * "Scan for hubs" passed that same empty string to `discoverHubs`, skipping
   * the one hub the person had actually configured.
   *
   * Deriving it instead of snapshotting it means the saved URL appears the
   * moment it arrives, on this render or any later one. `null` rather than `""`
   * as the untouched value is what lets somebody deliberately clear the field
   * and have it stay cleared, instead of the saved URL springing back.
   */
  const [typedUrl, setTypedUrl] = useState<string | null>(null);
  const draftUrl = typedUrl ?? activeHubUrl ?? "";
  const [declaration, setDeclaration] = useState<HubDeclaration | null>(null);
  const [checking, setChecking] = useState(false);

  const isMainnet = settings?.network_mode === "mainnet";

  function updateDraft(value: string) {
    setTypedUrl(value);
    setDeclaration(null);
    onHubUrlChange?.(value);
  }

  async function handleDiscover() {
    if (!settings) {
      onToast("Unlock wallet first.", "error");
      return;
    }
    setScanning(true);
    setReport(null);
    try {
      // The typed value, not the saved one. Scanning everything except the
      // field this panel tells people to fill in was the defect.
      const next = await api.discoverHubs(draftUrl);
      setReport(next);
      if (next.online_count === 0) {
        onToast("No online hubs answered.", "info");
      } else {
        onToast(`${next.online_count} online hub(s) found.`, "success");
      }
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setScanning(false);
    }
  }

  async function handleCheck() {
    if (!settings) {
      onToast("Unlock wallet first.", "error");
      return;
    }
    const url = draftUrl.trim();
    if (!url) {
      onToast("Enter the hub address your provider gave you.", "error");
      return;
    }
    setChecking(true);
    setDeclaration(null);
    try {
      setDeclaration(await api.hubDeclaration(url));
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setChecking(false);
    }
  }

  async function handleUse(entry: HubDiscoveryEntry) {
    if (!settings) {
      // `onApplyHub` opens with `if (!settings || !entry.online) return;` - a
      // bare return, before `setBusy`, so absolutely nothing moved on screen.
      // The reason is said here, where the press happened.
      onToast(
        "The wallet settings are not loaded yet, so there is nothing to save the provider into. Try again in a moment.",
        "error",
      );
      return;
    }
    if (!entry.online) {
      onToast(
        "That provider is not answering, so it was not saved. Check it again first.",
        "error",
      );
      return;
    }
    /**
     * A scanned result could be adopted with no address, and report success.
     *
     * `probe_hub_entry` returns `online: true` with `hub_address: None` whenever
     * a healthy zero-fee Hub publishes no address and no preset supplies one.
     * The list button was gated on `entry.online` alone, so it was offered;
     * `handleApplyHub` then writes `entry.hub_address ?? settings.hub_right_address`,
     * leaving the address unset; the toast said "Using <name>" and the button
     * flipped to "In use". Enable Fast Pay then stayed greyed on
     * `!providerAddressChosen` and told the person to do the step they had just
     * done. The declaration path already refused this by name; the scan path did
     * not, and this is that refusal.
     */
    if (!entry.hub_address) {
      onToast(
        `${entry.name} answered, but it publishes no on-chain address, so a channel has no counterparty to bind to and it was not saved. Ask its operator to publish hub_address on /v1/health.`,
        "error",
      );
      return;
    }
    setBusy(true);
    try {
      await onApplyHub(entry);
      onHubUrlChange?.(entry.hub_url);
      setTypedUrl(entry.hub_url);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  /**
   * Adopt the Hub whose declaration is on screen.
   *
   * Routed through the same `onApplyHub` a discovery result uses, so the Hub's
   * published address is saved alongside its URL. Saving only a URL used to
   * leave `hub_right_address` empty, and Enable then failed with "Choose an
   * online Fast Pay provider first" for a provider the person had just chosen.
   *
   * Requires the Hub to have published an address: a channel binds to an exact
   * counterparty and must never be guessed. The live Hub is checked against
   * that address again at funding time by `require_channel_binding_ready`, so
   * nothing here is taken on trust.
   */
  async function handleUseDeclared() {
    // Every branch here used to `return` with no word to the person who
    // pressed the button. A control that does nothing and says nothing is the
    // worst of the three possible outcomes: worse than refusing, because they
    // cannot tell a refusal from a dead button, and they press it again.
    if (!declaration) {
      onToast(
        'Check the provider first: type its address above and press "Check this hub".',
        "error",
      );
      return;
    }
    if (!declaration.reachable) {
      onToast(
        declaration.error
          ? `That provider did not answer: ${declaration.error}`
          : "That provider did not answer, so it was not saved.",
        "error",
      );
      return;
    }
    if (!declaration.hub_address) {
      onToast(
        "That provider did not publish an on-chain address, so a channel cannot bind to it. Ask its operator to publish one on /v1/health.",
        "error",
      );
      return;
    }
    await handleUse({
      id: "custom",
      name: declaration.name ?? "Your provider",
      hub_url: declaration.hub_url,
      online: true,
      hub_address: declaration.hub_address,
      hub_fee_mei: declaration.hub_fee_mei,
      error: null,
    });
  }

  const normalizedActive = activeHubUrl?.trim().replace(/\/$/, "") ?? "";
  const declaredIsActive =
    declaration !== null &&
    normalizedActive !== "" &&
    declaration.hub_url === normalizedActive;

  return (
    <div className="hub-discovery">
      <p className="muted small">{FAST_PAY_NO_HUB_EXPLANATION}</p>

      <label htmlFor="hub-discovery-url">Hub address</label>
      <input
        id="hub-discovery-url"
        value={draftUrl}
        onChange={(e) => updateDraft(e.target.value)}
        placeholder="https://hub.example.com"
        inputMode="url"
        autoComplete="off"
        spellCheck={false}
      />
      <p className="muted small">
        HTTPS, or http://127.0.0.1:PORT for a hub on this machine.
      </p>

      <div className="actions-row">
        {/*
          * Not greyed on an empty field. `handleCheck` already refuses an empty
          * URL by name, and a refusal that names its cause beats a grey button
          * that carries none. The `!settings` clause is gone for the same
          * reason: `handleDiscover` says "Unlock wallet first" and this one now
          * does too, which is a sentence, where the grey was silence.
          */}
        <button
          type="button"
          className="primary"
          disabled={busy || checking}
          onClick={() => void handleCheck()}
        >
          {checking ? "Checking…" : "Check this hub"}
        </button>
        <button
          type="button"
          disabled={busy || scanning || !settings}
          onClick={() => void handleDiscover()}
        >
          {scanning ? "Scanning…" : "Scan for hubs"}
        </button>
      </div>

      <HubDeclarationCard declaration={declaration} />

      {declaration?.reachable && !declaration.hub_address && (
        <p className="muted small">
          This hub did not publish its on-chain address, so it cannot be used
          yet. A channel binds to an exact counterparty and the wallet will not
          guess one. Ask the operator to publish it on /v1/health.
        </p>
      )}
      {declaration?.reachable && declaration.hub_address && (
        <button
          type="button"
          className={declaredIsActive ? undefined : "primary"}
          disabled={busy || declaredIsActive}
          onClick={() => void handleUseDeclared()}
        >
          {declaredIsActive ? "In use" : "Use this hub"}
        </button>
      )}

      {report && (
        <div className="hub-discovery-list">
          {report.hubs.map((hub) => {
            const isActive = normalizedActive !== "" && hub.hub_url === normalizedActive;
            return (
              <div key={`${hub.id}:${hub.hub_url}`} className="hub-discovery-item">
                <div className="hub-discovery-head">
                  <strong>{hub.name}</strong>
                  <span className={hub.online ? "badge badge-ok" : "badge badge-warn"}>
                    {hub.online ? "online" : "offline"}
                  </span>
                </div>
                <p className="muted small hub-discovery-url">{hub.hub_url}</p>
                {hub.online && <p className="muted small">Fast Pay fee: 0 HAC</p>}
                {!hub.online && hub.error && <p className="muted small">{hub.error}</p>}
                {hub.online && (
                  <button
                    type="button"
                    className={isActive ? undefined : "primary"}
                    disabled={busy || isActive}
                    onClick={() => void handleUse(hub)}
                  >
                    {isActive ? "In use" : "Use this hub"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {isMainnet && (
        <>
          <p className="muted small">{FAST_PAY_PILOT_ALLOWLIST_NOTE}</p>
          <p className="muted small">{FAST_PAY_SELF_HOSTED_HUB_NOTE}</p>
        </>
      )}
      <p className="muted small">
        Somebody has to run a hub, and it can be you.{" "}
        {/*
          * `.catch(() => undefined)` was on the button below, and it is the
          * reason it could do nothing and say nothing. It is also the only route
          * out of the empty state, because FAST_PAY_NO_HUB_EXPLANATION tells the
          * person their only option is to run a Hub themselves. If the browser
          * does not open they need to be told, and handed the URL so they can
          * open it by hand. The correct form was already in this tree at
          * SettingsScreen.tsx:95.
          */}
        {openExternal ? (
          <button
            type="button"
            className="linkish"
            onClick={() =>
              void Promise.resolve(openExternal(HUB_OPERATOR_URL)).catch((error) =>
                onToast(
                  `The browser did not open: ${formatInvokeError(error)}. The guide is at ${HUB_OPERATOR_URL}`,
                  "error",
                ),
              )
            }
          >
            Read the hub operator guide
          </button>
        ) : (
          <span className="hub-discovery-url">{HUB_OPERATOR_URL}</span>
        )}
      </p>
    </div>
  );
}
