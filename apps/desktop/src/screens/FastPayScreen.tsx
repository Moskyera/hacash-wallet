import { useEffect, useRef, useState } from "react";
import {
  api,
  ChannelInfo,
  ChannelSetupPreview,
  FastPayInboxItem,
  HubDiscoveryEntry,
  HubHealth,
  NativeRailPreflight,
  WalletSettings,
  WalletStatus,
} from "../api";
import BillsPanel from "../components/BillsPanel";
import HubDiscoveryPanel from "../components/HubDiscoveryPanel";
import {
  fastPayStatusHeadline,
  fastPayStatusTitle,
  type FastPayStatus,
} from "../fastPayUi";
import type { Screen } from "./types";
import { open } from "@tauri-apps/plugin-shell";
import {
  DECLARED_CAPS_LEDE,
  DeclaredCapsList,
  Disclosure,
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CHANNEL_REFUSED,
  FAST_PAY_MAINNET_CONSENT,
  FAST_PAY_SELF_HOSTED_HUB_NOTE,
  MAINNET_SIGNING_TRANSPORT_NOTICE,
  NativeRailPreflightCard,
  PREFLIGHT_NOT_GREEN_SHORT,
  closeVoucherSentence,
  fastPayEnableFoldSummary,
  fastPayEnableRefusals,
  fastPayNextStep,
  fastPayRemainingLine,
  hubIsProbablySelfHosted,
  mainnetSigningTransportIsEligible,
  preflightVerdict,
} from "@hacash/wallet-ui";

/**
 * What the bounded pilot consent block's own submit control should do.
 *
 * Pulled out as a function so the rule can be tested without a DOM. The
 * ceremony had no submit control at all: the consent text, the checkbox and
 * the passphrase field rendered here while the only caller of
 * onSaveL2Settings sat inside the collapsed "Technical settings (advanced)"
 * section, which renders nothing until it is expanded.
 *
 * The asymmetry is deliberate and matches the core. GRANTING consent chooses
 * the settlement model every later mainnet payment is judged under, so it
 * needs the passphrase and goes through the authenticated consent command.
 * WITHDRAWING is a tightening and needs nothing.
 */
export function consentSubmitState(
  ticked: boolean,
  saved: boolean,
  passphrase: string,
  busy: boolean,
) {
  const granting = ticked && !saved;
  return {
    // Nothing to submit while the tick already matches what is saved.
    visible: ticked !== saved,
    needsPassphrase: granting,
    disabled: busy || (granting && passphrase.length === 0),
    label: ticked ? "Confirm this choice" : "Withdraw consent",
  };
}

/**
 * The payment the preflight judges the Hub's per-payment cap against.
 *
 * 0.1 HAC, which is the single payment this bounded pilot is sized for. It is
 * a fixed number rather than a field because the cap question is "will this
 * Hub take the payment I am about to make", and inventing a larger one here
 * would produce a red item for a payment nobody intends to send.
 */
const FAST_PAY_PREFLIGHT_PAYMENT_HAC = "0.1";

type Props = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  fastPayDetail: FastPayStatus | null;
  channelInfo: ChannelInfo | null;
  hubHealth: HubHealth | null | undefined;
  billsCount: number;
  fastPayReady: boolean;
  fastPayNeedsSetup: boolean;
  hideAddresses: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onNavigate: (screen: Screen) => void;
  /** Resolves to the refusal text, or `null` when the open was submitted. */
  onEnableFastPay: (userDeposit: string) => Promise<string | null>;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onSaveL2Settings: (
    nodeUrl: string,
    hubUrl: string,
    hubAddress: string,
    trustedMainnetFastPayPilot: boolean,
    currentPassphrase: string,
  ) => void;
  onHubHealth: () => void;
  onPreviewChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: ChannelSetupPreview | null) => void,
  ) => void;
  onOpenChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: ChannelSetupPreview | null) => void,
  ) => void;
  onCloseChannel: (setChannelPreview: (p: ChannelSetupPreview | null) => void) => void;
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  clearMessages: () => void;
};

export default function FastPayScreen({
  status,
  settings,
  fastPayDetail,
  channelInfo,
  hubHealth,
  billsCount,
  fastPayReady,
  fastPayNeedsSetup,
  hideAddresses,
  busy,
  setBusy,
  onNavigate,
  onEnableFastPay,
  onApplyHub,
  onSaveL2Settings,
  onHubHealth,
  onPreviewChannel,
  onOpenChannel,
  onCloseChannel,
  onRefresh,
  onNotify,
  clearMessages,
}: Props) {
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [nodeUrl, setNodeUrl] = useState("");
  const [hubUrl, setHubUrl] = useState("");
  const [hubAddress, setHubAddress] = useState("");
  const [trustedMainnetPilot, setTrustedMainnetPilot] = useState(false);
  // Turning the pilot on is an authenticated change, so the screen has to be
  // able to ask for the passphrase. Turning it off needs nothing.
  const [mainnetPilotPassphrase, setMainnetPilotPassphrase] = useState("");
  const [channelPreview, setChannelPreview] = useState<ChannelSetupPreview | null>(null);
  const [preflight, setPreflight] = useState<NativeRailPreflight | null>(null);
  const [preflightRunning, setPreflightRunning] = useState(false);
  const [showFastPayAdvanced, setShowFastPayAdvanced] = useState(false);
  const [inbox, setInbox] = useState<FastPayInboxItem[]>([]);
  const inboxRequestRef = useRef<Promise<void> | null>(null);
  /**
   * The last refusal Enable produced, kept on the screen.
   *
   * `onNotify` puts it in a toast that clears itself after four seconds and in a
   * banner at the very top of a scrolling page. A person standing at the Enable
   * button, near the bottom of that page, sees neither. That is the whole of
   * "the button did nothing": it refused, out of sight, and cleared itself. This
   * keeps the exact text beside the control that produced it until the next
   * press.
   */
  const [lastRefusal, setLastRefusal] = useState<string | null>(null);
  const preflightAutoRunRef = useRef<string | null>(null);
  useEffect(() => {
    const recommended = fastPayDetail?.default_deposit_mei;
    if (recommended != null && Number.isFinite(recommended) && recommended > 0) {
      setUserDeposit(String(recommended));
    }
  }, [fastPayDetail?.default_deposit_mei]);

  useEffect(() => {
    if (!fastPayReady || status?.locked) {
      setInbox([]);
      return;
    }
    let cancelled = false;
    const load = (): Promise<void> => {
      if (inboxRequestRef.current) return inboxRequestRef.current;
      const request = (async () => {
        try {
          const items = await api.fastPayInbox();
          if (!cancelled) setInbox(items);
        } catch {
          if (!cancelled) setInbox([]);
        }
      })().finally(() => {
        if (inboxRequestRef.current === request) inboxRequestRef.current = null;
      });
      inboxRequestRef.current = request;
      return request;
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [fastPayReady, status?.locked, status?.address]);

  const acceptIncoming = async (item: FastPayInboxItem) => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.acceptFastPay(item.payment_id);
      setInbox((current) => current.filter((entry) => entry.payment_id !== item.payment_id));
      onNotify(result.summary, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };

  const finishPendingOpen = async () => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.recoverChannelOpen();
      onNotify(result, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };

  const finishPendingClose = async () => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.recoverChannelClose();
      onNotify(result, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (!settings) return;
    setNodeUrl(settings.node_url);
    setHubUrl(settings.l2_hub_url ?? "");
    setHubAddress(settings.hub_right_address ?? "");
    setTrustedMainnetPilot(settings.trusted_mainnet_fast_pay_pilot);
  }, [
    settings?.node_url,
    settings?.l2_hub_url,
    settings?.hub_right_address,
    settings?.trusted_mainnet_fast_pay_pilot,
    settings,
  ]);

  // Mirrors validate_signing_node_url. Used only to SAY the rule on screen
  // before the ceremony; the core still enforces it at prepare and at signing.
  const signingTransportEligible = mainnetSigningTransportIsEligible(
    settings?.node_url,
    settings?.network_mode,
  );
  /**
   * The state that was actually measured, with the placeholder only as a
   * fallback. See the banner below for why the placeholder cannot answer.
   */
  const measuredState = fastPayDetail?.state ?? status?.fast_pay_state ?? "no_provider";
  /**
   * Run the read-only preflight for the values on this screen.
   *
   * It sends the deposit the person has actually typed and a payment sized to
   * the deposit, so the Hub's declared caps are judged against the real
   * numbers rather than against a placeholder. Nothing is saved and nothing is
   * signed.
   */
  const runPreflight = async () => {
    setPreflightRunning(true);
    clearMessages();
    try {
      setPreflight(
        await api.nativeRailPreflight({
          nodeUrl: settings?.node_url,
          hubUrl,
          hubAddress: settings?.hub_right_address ?? hubAddress,
          ownerAddress: status?.address ?? undefined,
          channelDepositHac: userDeposit,
          paymentHac: FAST_PAY_PREFLIGHT_PAYMENT_HAC,
        }),
      );
    } catch (error) {
      setPreflight(null);
      onNotify(String(error), "error");
    } finally {
      setPreflightRunning(false);
    }
  };

  /**
   * Run the read-only check once, without being asked, when this screen opens.
   *
   * It is the only thing on the wallet that answers all four of the questions a
   * person needs before they fund a channel: is my node reachable, does my Hub
   * answer, what does my Hub actually allow, and what is stopping me. Leaving it
   * behind a button meant the default state of this screen was silence, and the
   * owner read that silence as "everything is fine" right up until Enable
   * refused.
   *
   * It sends read-only requests, signs nothing, unlocks nothing and broadcasts
   * nothing, which is what makes running it unasked acceptable. It runs once per
   * (hub, node, deposit) so a person typing in the deposit field does not fire a
   * request per keystroke, and the button below still re-runs it on demand.
   */
  const preflightKey = `${settings?.node_url ?? ""}|${hubUrl}|${settings?.hub_right_address ?? ""}|${userDeposit}`;
  useEffect(() => {
    if (!settings || !hubUrl.trim() || status?.locked) return;
    if (preflightAutoRunRef.current === preflightKey) return;
    preflightAutoRunRef.current = preflightKey;
    const id = window.setTimeout(() => void runPreflight(), 400);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preflightKey, settings, hubUrl, status?.locked]);

  const consentSubmit = consentSubmitState(
    trustedMainnetPilot,
    settings?.trusted_mainnet_fast_pay_pilot ?? false,
    mainnetPilotPassphrase,
    busy,
  );

  /**
   * Everything this screen can see that would stop Enable, all at once.
   *
   * It gates nothing. The button below is not disabled by it, and every rule in
   * it is enforced again in `prepare_channel_open`, at the signing boundary and
   * by the Hub. It exists so a refusal has a cause on screen before the press
   * rather than only after it, and so the two conditions that used to grey the
   * button out carry their reason with them.
   */
  const enableRefusals = fastPayEnableRefusals({
    settingsLoaded: settings !== null,
    watchOnly: Boolean(status?.watch_only),
    locked: Boolean(status?.locked),
    networkMode: settings?.network_mode,
    nodeUrl: settings?.node_url,
    hubAddress: settings?.hub_right_address,
    consentGranted: Boolean(settings?.trusted_mainnet_fast_pay_pilot),
    depositHac: userDeposit,
    declaredChannelCapHac: preflight?.declared_caps.max_channel_funding_hac ?? null,
    signingTransportEligible,
    signingTransportNotice: MAINNET_SIGNING_TRANSPORT_NOTICE,
  });

  const pressEnable = async () => {
    setLastRefusal(null);
    setLastRefusal(await onEnableFastPay(userDeposit));
  };

  /**
   * Did the preflight reach the node? `null` means nobody has asked yet.
   *
   * The preflight has known this all along, in a check called
   * `node_can_be_reached`, buried in a list of a dozen items further down the
   * page. It is the fact that makes every other step pointless when it is
   * false, so it gets promoted. `skip` counts as unknown, not as broken:
   * reporting unmeasured as failed sends somebody to fix a node that is fine.
   */
  /**
   * Two different questions were being answered by one flag, and the wrong one
   * won.
   *
   * `node_can_be_reached` asks whether anybody ELSE can reach this node. On a
   * node behind a router that is `warn`, not `pass`, so `status === "pass"`
   * made `nodeReachable` false and the screen announced "Your node is not
   * answering" for a node that had just told it its own peer counts. That sent
   * a person to fix a node that was fine, which is the exact wrong-cause
   * failure the comment on `fastPayNextStep` warns about.
   *
   * The question this flag exists to answer is whether THIS WALLET reached the
   * node, and `node_identity` is what answers it: `fatal_skip` when the node
   * could not be read at all, otherwise it was read. Being unreachable from
   * outside is surfaced by its own item and does not block funding.
   */
  const nodeIdentityCheck = preflight?.checks.find(
    (check) => check.id === "node_identity",
  );
  const nodeReachable =
    nodeIdentityCheck === undefined
      ? null
      : nodeIdentityCheck.status !== "skip";

  /**
   * The one thing to do next, at the top, in words.
   *
   * This screen could answer every question except the first one a person has.
   * It showed a state pill, a route hint, a consent block, a hub finder, a
   * preflight report and a refusal list, and left somebody to read all six and
   * work out which was their turn.
   *
   * It gates nothing: `canActNow` is a summary of what this screen can see, the
   * Enable button below stays pressable either way, and the core and the Hub
   * both re-check everything when it is pressed.
   */
  const nextStep = fastPayNextStep({
    state: measuredState,
    refusals: enableRefusals,
    nodeReachable,
    // Saving a provider unblocks the deposit field and the declared caps, so it
    // opens up more of the screen than anything else and goes first.
    preferOrder: [
      "settings_not_loaded",
      "wallet_locked",
      "watch_only_wallet",
      "no_provider_address",
      "signing_transport_ineligible",
      "mainnet_consent_withheld",
      "deposit_not_a_number",
      "channel_cap_unknown",
      "deposit_over_declared_cap",
    ],
  });

  /**
   * The verdict of the read-only check, as one line for the top of the screen.
   *
   * "NOT READY. Do not put money in yet." used to sit about 1500 words down the
   * page, under the whole report. It answers "can I act now", so it belongs in
   * the first block a person reads. The report keeps its own banner.
   */
  const verdict = preflight ? preflightVerdict(preflight) : null;

  /**
   * The no-way-out sentence, when this Hub discloses that gap.
   *
   * The identifier travels in the preflight's `hub_disclosed_gaps` item, in its
   * observed text and its reason, which is the only place this screen can see
   * it without a Hub declaration of its own.
   *
   * It used to be introduced here as the single action on the screen that
   * changed the stranding risk. It was not an action: this wallet has no
   * close-voucher command, so the screen was instructing a person to do
   * something it could not do, beside a consent box saying the opposite. The
   * sentence now explains why wallet-core refuses to open a mainnet channel at
   * all, and names the rail where the voucher does exist. Still read without
   * opening anything, for a better reason than before.
   */
  const voucherSentence = closeVoucherSentence(
    (preflight?.checks ?? []).flatMap((check) => [check.observed, check.reason]),
  );

  /** Their own machine, or somebody else's? See hubIsProbablySelfHosted. */
  const selfHostedHub = hubIsProbablySelfHosted(settings?.l2_hub_url ?? hubUrl);

  return (
    <section className="panel">
      <h2>Fast Pay</h2>

      {/*
        BAND 1. CAN I ACT RIGHT NOW.

        One block, first on the screen, and it carries the control. The owner's
        complaint was that the answer to "can I act now" was at the bottom, under
        every disclosure and every limitation. Everything in this block is an
        answer to that question and nothing else is allowed in: the one next
        step, how many are queued behind it, the check's verdict in four words,
        the deposit field and the button, and the refusal the last press
        produced.

        It gates nothing. `canActNow` is a summary of what this screen can see,
        the button below is pressable either way, and the core and the Hub both
        re-check everything when it is pressed.
      */}
      <div
        className={`fp-next-step ${nextStep.canActNow ? "fp-next-ready" : "fp-next-blocked"}`}
        role="status"
      >
        <div className="fp-next-label">
          {nextStep.canActNow ? "Your next step" : "What is stopping you"}
        </div>
        <h3>{nextStep.headline}</h3>
        <p>{nextStep.action}</p>
        {nextStep.remaining > 0 && (
          <p className="muted small">{fastPayRemainingLine(nextStep.remaining)}</p>
        )}
        {nodeReachable === null && (
          <p className="muted small">
            Nobody has checked whether your node answers yet.
          </p>
        )}
        {/*
          The verdict, lifted out of the report. The report still shows it; this
          is the copy a person reads before they have scrolled anywhere.
        */}
        {verdict && (
          <p className="muted small">
            <strong>{verdict.pill}.</strong> {verdict.headline}.
          </p>
        )}

        {/*
          The Enable control, in the block that says whether you can press it.

          This used to be a separate card roughly a thousand words further down,
          so "yes, and here is the button" was answered in two places a screen
          apart. The card is dissolved into this block rather than duplicated:
          there is exactly one Enable button on this screen.

          It renders whenever Fast Pay is not already on. It used to be
          conditional on `fastPayNeedsSetup || can_enable`, so a person whose Hub
          was refusing for a nameable reason lost the deposit field, the check
          and the button altogether. Making the control vanish is worse than
          greying it out, and greying it out is already the thing this repository
          has shipped before. It renders, it is pressable, and it says why.
        */}
        {!fastPayReady && !status?.watch_only && (
          <div className="fp-enable">
            <h4>Turn Fast Pay ON</h4>
            <p className="muted small">
              One-time setup. Deposit stays in your channel until you close it.
            </p>
            <label htmlFor="fp-channel-deposit">Your channel deposit (HAC)</label>
            <input
              id="fp-channel-deposit"
              value={userDeposit}
              onChange={(e) => setUserDeposit(e.target.value)}
              type="number"
              min="0.001"
              step="0.001"
            />
            {fastPayDetail && fastPayDetail.default_deposit_mei > 0 && (
              <p className="muted small">
                Your provider's own recommendation is{" "}
                {fastPayDetail.default_deposit_mei} HAC, the smaller of its
                declared per-channel cap and this wallet's default.
              </p>
            )}

            <button className="primary" disabled={busy} onClick={() => void pressEnable()}>
              Enable Fast Pay
            </button>

            {/*
              The refusal the last press produced, kept where the press happened.
              The toast that carried it clears after four seconds and the banner
              that carried it sits at the top of a page this button is below.
            */}
            {lastRefusal && (
              <div className="alert" role="alert">
                <strong>Enable refused, and nothing was signed</strong>
                <p className="small">{lastRefusal}</p>
                <p className="muted small">
                  Nothing left your wallet. This is the wallet or your Hub
                  answering, in its own words.
                </p>
              </div>
            )}

            {/*
              The button is NOT disabled on a red preflight. The preflight is a
              read-only opinion about the infrastructure, not a gate, and every
              gate it previews runs again for real inside enable and inside the
              channel open. Wiring the button to it would swap a real refusal
              with a reason for a greyed-out control with none. Saying it plainly
              is the honest half, and it is the sentence that stops the live
              button reading as broken, so it never folds. The longer form of it
              is inside the check's own report.
            */}
            {verdict && !verdict.pass && (
              <p className="small">{PREFLIGHT_NOT_GREEN_SHORT}</p>
            )}
          </div>
        )}
      </div>

      {/*
        The rest of the queue, folded. BAND 1 already names the first refusal in
        full; this holds the others, with their identifiers, in one place the
        counter above can point at by name.
      */}
      {enableRefusals.length > 0 && (
        <Disclosure summary={fastPayEnableFoldSummary(enableRefusals)}>
          <ul className="small">
            {enableRefusals.map((refusal) => (
              <li key={refusal.id}>
                <strong>{refusal.title}.</strong> {refusal.detail}{" "}
                <code>{refusal.id}</code>
              </li>
            ))}
          </ul>
        </Disclosure>
      )}

      {fastPayReady && (
        <div className="success-box">
          <p>
            Provider: <strong>{fastPayDetail?.provider_name ?? "connected"}</strong>
            {status?.channel_id && (
              <>
                {" "}
                · Channel active · {billsCount} bill{billsCount === 1 ? "" : "s"} backed up
              </>
            )}
          </p>
          <button className="primary" onClick={() => onNavigate("send")}>
            Go to Send
          </button>
        </div>
      )}

      {/*
        BAND 2. WHAT AM I ABOUT TO AGREE TO.

        The counterparty by name, URL and on-chain address; what it lets me
        move; the one action that changes the risk; and the sentence I tick.
        None of this is evidence and none of it folds. The consent text in
        particular is the checkbox label itself, verbatim: a person who ticks a
        box whose words are behind a disclosure has agreed to something they did
        not read.
      */}

      {/*
        The headline reads the measured state, not `status.fast_pay_state`.

        `WalletStatus.fast_pay_state` comes from `fast_pay_status_sync`, which
        answers "checking" for any wallet with a Hub URL and "no_provider" for
        any wallet without one. It never contacts the Hub, so it can never say
        "ready" and never say "needs_channel". This banner therefore said
        "Checking Fast Pay provider" forever, and the pill beside it said OFF for
        a wallet whose channel was open and working. `fastPayDetail` is
        `wallet_fast_pay_status`, which measures it.
      */}
      <div className={`fp-status-banner ${fastPayReady ? "fp-status-on" : "fp-status-off"}`}>
        <div className="fp-status-pill">
          {fastPayReady ? "ON" : fastPayDetail ? "OFF" : "…"}
        </div>
        <div>
          <h3>{fastPayStatusTitle(measuredState)}</h3>
          <p>
            {fastPayDetail?.message ??
              status?.fast_pay_message ??
              fastPayStatusHeadline(measuredState)}
          </p>
          <p className="muted small">
            Provider: <code>{settings?.l2_hub_url ?? "none saved"}</code>
            {" · "}Provider address:{" "}
            <code>{settings?.hub_right_address?.trim() || "none saved"}</code>
            {" · "}Node: <code>{settings?.node_url ?? "unknown"}</code>
          </p>
        </div>
      </div>

      <div className="fp-route-hint">
        <strong>When you tap Send:</strong>{" "}
        {fastPayReady
          ? "payments go via Fast Pay (instant)."
          : fastPayDetail
            ? "payments go on-chain (standard, few minutes)."
            : "not known yet. This screen is still reading your provider."}
      </div>

      {/*
        What this Hub lets you move, beside the box you tick rather than inside
        the hub finder, where it appeared only after somebody pressed "Check this
        hub". These are the same numbers `fastPayEnableRefusals` judges the
        deposit against.
      */}
      {preflight && (
        <div className="preview-card" role="note">
          <p className="small">
            <strong>Caps this Hub declares.</strong> {DECLARED_CAPS_LEDE}
          </p>
          <DeclaredCapsList caps={preflight.declared_caps} />
          {voucherSentence && <p className="small">{voucherSentence}</p>}
        </div>
      )}

      {/*
        Whose failure the consent text is describing.

        It says "if the Hub stops answering, refuses to sign, or disappears",
        and an owner whose Hub is their own machine reads that as a third
        party's failure. It is their own key and their own durable state. Shown
        without opening anything in that case; folded with the rest of the hub
        material otherwise.
      */}
      {settings?.network_mode === "mainnet" && selfHostedHub && (
        <p className="small">{FAST_PAY_SELF_HOSTED_HUB_NOTE}</p>
      )}

      {settings?.network_mode === "mainnet" && (
        <div className="alert" role="note">
          <strong>Bounded mainnet pilot</strong>
          {/*
            ABOVE the ceilings and above the box, because it is the answer to
            "will I be able to get this out", and that outranks "how much may
            I put in". It does not depend on the preflight having reached a
            Hub, because the fact does not depend on any Hub. wallet-core is
            the authority; this is only the sentence that gets there first.
          */}
          <p>
            <strong>{FAST_PAY_MAINNET_CHANNEL_REFUSED}</strong>
          </p>
          <p>{FAST_PAY_MAINNET_CEILINGS}</p>
          <label>
            <input
              type="checkbox"
              checked={trustedMainnetPilot}
              onChange={(event) => setTrustedMainnetPilot(event.target.checked)}
            />
            {FAST_PAY_MAINNET_CONSENT}
          </label>
          {consentSubmit.needsPassphrase && (
            <>
              <label htmlFor="mainnet-pilot-passphrase">
                Wallet passphrase, to confirm this choice
              </label>
              <input
                id="mainnet-pilot-passphrase"
                type="password"
                autoComplete="current-password"
                value={mainnetPilotPassphrase}
                onChange={(event) => setMainnetPilotPassphrase(event.target.value)}
              />
            </>
          )}
          {/*
            The ceremony's own submit control.

            The consent text, the checkbox and the passphrase field all render
            here, and the only button that submitted them lived inside the
            collapsed "Technical settings (advanced)" section further down. So
            a person read the consent, ticked the box, typed their wallet
            passphrase, and there was no control on screen that did anything
            with it.

            No gate moves. This calls the same onSaveL2Settings path the
            advanced Save settings button calls, which still refuses to grant
            consent without a passphrase and still routes granting through the
            authenticated api.setMainnetFastPayConsent rather than
            wallet_update_settings. The advanced button stays exactly as it is.
          */}
          {consentSubmit.visible && (
            <button
              type="button"
              className="primary"
              disabled={consentSubmit.disabled}
              onClick={() =>
                // Consent only. Every other argument is the value already
                // saved, so this ceremony cannot carry a half-typed node or
                // hub URL along with it and cannot fail for a reason that has
                // nothing to do with consent. The advanced Save settings
                // button remains the place that submits the form.
                onSaveL2Settings(
                  settings?.node_url ?? "",
                  settings?.l2_hub_url ?? "",
                  settings?.hub_right_address ?? "",
                  trustedMainnetPilot,
                  mainnetPilotPassphrase,
                )
              }
            >
              {consentSubmit.label}
            </button>
          )}
        </div>
      )}

      {!signingTransportEligible && (
        <div className="alert" role="note">
          <strong>This node cannot sign on mainnet</strong>
          <p>{MAINNET_SIGNING_TRANSPORT_NOTICE}</p>
          <p className="small">
            Current node: <code>{settings?.node_url}</code>
          </p>
        </div>
      )}

      <div className="fast-pay-card">
        <h3>Find a hub</h3>
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={onApplyHub}
          onHubUrlChange={setHubUrl}
          openExternal={(url) => open(url)}
          onToast={(msg, kind) => {
            clearMessages();
            onNotify(msg, kind);
          }}
        />
      </div>

      {/*
        The infrastructure check, on the screen rather than behind a decision.

        It used to live inside the "Turn Fast Pay ON" card, which renders only
        when the Fast Pay evaluation says setup is possible. So the one surface
        that says whether the node is reachable and what the Hub allows
        disappeared in exactly the situation where somebody needed it most: a
        Hub that answers but is refusing. It is read-only, so it belongs on the
        screen unconditionally.
      */}
      <div className="fast-pay-card">
        <h3>Your node and your Hub, right now</h3>
        <NativeRailPreflightCard
          report={preflight}
          running={preflightRunning}
          disabled={busy}
          onRun={() => void runPreflight()}
        />
      </div>

      {/*
        The screen's own explanation, folded. The route hint in band 2 already
        answers what these three bullets explain, in one line, before this.
      */}
      <div className="fp-how-it-works">
        <Disclosure summary="How it works">
          <p className="muted">
            Instant fee-free payments on the Hacash payment network. Check this tab to see
            whether your sends will be Fast Pay or on-chain.
          </p>
          <ul>
            <li>
              <strong>Fast Pay ON:</strong> Send tab uses instant routing with no Fast Pay fee.
            </li>
            <li>
              <strong>Fast Pay OFF:</strong> Send tab uses on-chain (dynamic L1 fee from node).
            </li>
            <li>You always see which route is used before you confirm a payment.</li>
          </ul>
        </Disclosure>
      </div>

      {fastPayReady && (
        <div className="fast-pay-card">
          <h3>Incoming Fast Pay requests</h3>
          <p className="muted small">
            A routed payment settles only after you verify and sign your recipient channel update.
          </p>
          {inbox.length === 0 ? (
            <p className="muted">No payment is waiting for your signature.</p>
          ) : (
            inbox.map((item) => (
              <div className="preview-card" key={item.payment_id}>
                <p>
                  <strong>{item.amount} HAC</strong> from{" "}
                  {hideAddresses ? `${item.payer.slice(0, 7)}...` : item.payer}
                </p>
                <p className="muted small">
                  No Fast Pay fee. Both channel updates are verified locally before signing.
                </p>
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() => void acceptIncoming(item)}
                >
                  Verify and accept
                </button>
              </div>
            ))
          )}
        </div>
      )}

      <BillsPanel
        hideAddresses={hideAddresses}
        onError={(msg) => onNotify(msg, "error")}
        onInfo={(msg) => onNotify(msg, "info")}
      />

      <button
        type="button"
        className="collapse-toggle"
        onClick={() => setShowFastPayAdvanced((v) => !v)}
      >
        {showFastPayAdvanced ? "▾" : "▸"} Technical settings (advanced)
      </button>
      {showFastPayAdvanced && (
        <>
          <label>Node API URL</label>
          <input
            value={nodeUrl}
            onChange={(e) => setNodeUrl(e.target.value)}
            placeholder="https://node.example.com"
          />
          <label>Hub API URL</label>
          <input
            value={hubUrl}
            onChange={(e) => setHubUrl(e.target.value)}
            placeholder="https://hub.example.com"
          />
          <p className="muted small">
            There is no public hub, so this is somebody's machine. It can be yours:{" "}
            <code>docs/HUB-OPERATOR.md</code>.
          </p>
          <div className="actions-row">
            <button
              disabled={busy}
              onClick={() =>
                onSaveL2Settings(
                  nodeUrl,
                  hubUrl,
                  hubAddress,
                  trustedMainnetPilot,
                  mainnetPilotPassphrase,
                )
              }
            >
              Save settings
            </button>
            <button disabled={busy || !hubUrl.trim()} onClick={onHubHealth}>
              Hub health check
            </button>
          </div>
          {hubHealth !== undefined && (
            <div className={hubHealth?.ok ? "success-box" : "alert"}>
              {hubHealth === null && "Hub unreachable or misconfigured."}
              {hubHealth && hubHealth.ok && (
                <>
                  Hub OK. <strong>{hubHealth.name ?? "hub"}</strong> (protocol v
                  {hubHealth.version})
                </>
              )}
              {hubHealth && !hubHealth.ok && "Hub returned unhealthy status."}
            </div>
          )}
          <hr className="divider" />
          <h3>Payment channel (L1)</h3>
          <label>Provider address (hub)</label>
          <input
            value={hubAddress}
            onChange={(e) => setHubAddress(e.target.value)}
            placeholder="1Hub..."
          />
          <div className="two-col">
            <div>
              <label>Your deposit (HAC)</label>
              <input
                value={userDeposit}
                onChange={(e) => setUserDeposit(e.target.value)}
                type="number"
                min="0"
              />
            </div>
            <div>
              <label>Hub deposit (HAC)</label>
              <input
                value={hubDeposit}
                onChange={(e) => setHubDeposit(e.target.value)}
                type="number"
                min="0"
              />
            </div>
          </div>
          <div className="actions-row">
            <button
              disabled={busy || !hubAddress}
              onClick={() => onPreviewChannel(hubAddress, userDeposit, hubDeposit, setChannelPreview)}
            >
              Preview channel
            </button>
            <button
              className="primary"
              disabled={busy || !channelPreview}
              onClick={() => onOpenChannel(hubAddress, userDeposit, hubDeposit, setChannelPreview)}
            >
              Sign & open channel
            </button>
            <button disabled={busy} onClick={() => void finishPendingOpen()}>
              Finish pending setup
            </button>
            <button
              disabled={busy || !status?.channel_id}
              onClick={() => onCloseChannel(setChannelPreview)}
            >
              Close channel
            </button>
            <button
              disabled={busy || !status?.channel_id}
              onClick={() => void finishPendingClose()}
            >
              Finish pending close
            </button>
          </div>
          {channelPreview && (
            <div className="preview-card">
              <p>
                <strong>Channel ID:</strong> <code>{channelPreview.channel_id}</code>
              </p>
              <p>
                <strong>Hacash incarnation:</strong> {channelPreview.reuse_version}
              </p>
            </div>
          )}
          {status?.channel_id && channelInfo && (
            <p className="muted">
              Channel {channelInfo.status} · Left {channelInfo.left.hacash} · Right{" "}
              {channelInfo.right.hacash}
            </p>
          )}
        </>
      )}
    </section>
  );
}
