import type { ReactNode } from "react";
import { FAST_PAY_MAINNET_CEILINGS } from "./securityPolicy";

/**
 * One folded section, and the only one either app is allowed to use.
 *
 * WHY IT IS A `<details>` AND NOT A `useState` TOGGLE. The owner's complaint
 * was volume, not content, and the fix for volume must not become a fix for
 * content. A `useState` toggle removes the closed text from the DOM, which
 * removes it from find-in-page, from a screen reader's document, and from the
 * copy assertions that keep the risk sentences on this screen. `<details>`
 * keeps every word in the document, reachable by keyboard, and hides it from
 * the eye only. Folding is allowed here. Removing is not.
 *
 * Nothing folded behind this may be a thing a person is agreeing to, and
 * nothing folded may answer "can I act now". Those two bands render above it,
 * unfolded, always.
 */
export function Disclosure({
  summary,
  children,
  className,
}: {
  /**
   * The whole of what a person gets to read before they decide to open it, so
   * it has to be as honest as what is inside. Counts in it must be computed
   * from the data they describe, never typed in: a summary that says "3 things
   * this Hub discloses" while the Hub declares four is worse than the wall of
   * text it replaced, because a wrong count reads as authority.
   */
  summary: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <details className={`wallet-disclosure${className ? ` ${className}` : ""}`}>
      <summary>{summary}</summary>
      <div className="wallet-disclosure-body">{children}</div>
    </details>
  );
}

/** "a, b and c", so a computed summary reads like a sentence. */
export function joinWithAnd(parts: string[]): string {
  if (parts.length === 0) return "";
  if (parts.length === 1) return parts[0];
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/**
 * The caps one Hub declares, in HAC. `null` per cap the Hub did not send,
 * which is how an older Hub that omits the aggregate cap is told apart from
 * one declaring zero.
 */
export type DeclaredHubCapsView = {
  max_payment_hac: string | null;
  max_channel_funding_hac: string | null;
  max_aggregate_tvl_hac: string | null;
  aggregate_tvl_within_limit: boolean | null;
};

export type HubDeclarationView = {
  hub_url: string;
  reachable: boolean;
  error: string | null;
  name: string | null;
  hub_address: string | null;
  version: number | null;
  settlement_ready: boolean;
  cross_channel_ready: boolean;
  hub_fee_mei: string | null;
  deployment_profile: string | null;
  mainnet_checked: boolean;
  readiness_profile: string | null;
  payments_enabled: boolean | null;
  declared_caps: DeclaredHubCapsView;
  blockers: string[];
  disclosed_blockers: string[];
  limitations: string[];
  readiness_error: string | null;
};

function capRow(label: string, value: string | null) {
  return (
    <li key={label}>
      <strong>{label}:</strong> {value === null ? "not declared" : `${value} HAC`}
    </li>
  );
}

/**
 * One Hub, answering for itself, before any money.
 *
 * Everything rendered here is transcribed from that Hub's own /v1/health and
 * /v1/readiness/mainnet. Nothing in it is this build's opinion.
 *
 * It exists because the screens showed a person the compile-time ceilings
 * (1 HAC per payment, 10 per channel, 100 aggregate) and called them the
 * limits, while the Hub they were about to fund could declare a tenth of that
 * and refuse the first channel. securityPolicy.ts promises "what your Hub
 * declares is what applies to you"; the wallet could not keep that promise
 * because no screen ever showed the Hub's answer.
 *
 * It also prints the Hub's blockers verbatim rather than summarising them into
 * "provider incompatible". When a Hub refuses, its own named blockers are the
 * only actionable thing anybody has, and a wrong summarised cause sends a
 * person off to change providers, which fixes nothing.
 *
 * This is a preview and not an authority. The readiness document is fetched
 * again and gated again at the signing boundary, so a green card here grants
 * nothing.
 */
/**
 * A plain sentence for each blocker a Hub can name.
 *
 * The identifiers stay on screen. They are what an operator greps for and what
 * a person quotes when they ask for help, and summarising them away is how a
 * wrong cause sends somebody off to change providers when nothing was wrong
 * with the provider. So this ADDS a sentence beside the identifier rather than
 * replacing it, and an identifier this table does not know still shows raw:
 * a Hub that grows a new blocker must never have it silently disappear here.
 */
const BLOCKER_SENTENCES: Array<[string, string]> = [
  [
    "fullnode_below_pinned_mainnet_checkpoint_",
    "The full node behind this Hub has not caught up to the height where channel actions became valid. It needs to finish syncing.",
  ],
  [
    "fullnode_missing_required_channel_open_action_2",
    "The full node behind this Hub does not accept channel opening, so no channel can be created at all.",
  ],
  [
    "fullnode_missing_required_cooperative_close_action_3",
    "The full node behind this Hub does not accept channel closing, so a channel could be opened and then not closed.",
  ],
  [
    "fullnode_does_not_report_verified_registry_unilateral_exit",
    "The node cannot confirm a deployed exit contract, so there is no way out of a channel except this Hub co-signing.",
  ],
  [
    "wallet_cannot_build_a_unilateral_exit_without_the_hub",
    "Your wallet cannot build a way out on its own. Take a close voucher before you pay anything, and your deposit stops depending on this Hub staying reachable.",
  ],
  [
    "unilateral_l1_dispute_path_is_not_ready",
    "There is no dispute path on the chain, so a disagreement cannot be settled unless this Hub agrees to settle it.",
  ],
  [
    "no_watcher_answers_for_an_offline_owner",
    "Nobody is watching on your behalf while you are away. Nothing will act for you until you come back.",
  ],
  [
    "external_monotonic_rollback_anchor_is_not_ready",
    "No independent witness is watching this Hub, so a Hub restored from an older backup would not be caught by anything outside itself.",
  ],
  [
    "rollback_anchor_channels_latched_in_refusal",
    "This Hub has frozen channels because its own records went backwards. It needs its operator before it should be trusted again.",
  ],
  [
    "hub_signer_authenticated_storage_or_recovery_gate_is_not_ready",
    "This Hub cannot prove its signing key and its records are intact, so it should not be handed a deposit.",
  ],
  [
    "mainnet_detected_but_deployment_profile_is_not_mainnet_pilot",
    "This Hub is pointed at real Hacash while configured as a test deployment, so the limits and checks it is running are not the mainnet ones.",
  ],
  [
    "official_channelpay_mainnet_profile_not_enabled",
    "This Hub has not turned on the mainnet channel rail, so it cannot carry real value yet.",
  ],
  [
    "mainnet_pilot_user_allowlist_is_not_configured",
    "This Hub has no list of who may use it. Ask the operator to add your address, because a Hub will not publish who is on its list.",
  ],
  [
    "mainnet_pilot_admission_policy_not_evaluated",
    "This Hub has not worked out who it will serve, so it cannot say whether it would accept you.",
  ],
  [
    "mainnet_pilot_aggregate_tvl_could_not_be_verified",
    "This Hub cannot total what it already holds, so it cannot tell whether your deposit would push it past its own ceiling.",
  ],
];

export function explainBlocker(blocker: string): string | null {
  for (const [key, sentence] of BLOCKER_SENTENCES) {
    if (blocker === key || blocker.startsWith(key)) return sentence;
  }
  return null;
}

function BlockerList({ blockers }: { blockers: string[] }) {
  return (
    <ul className="muted small">
      {blockers.map((blocker) => {
        const sentence = explainBlocker(blocker);
        return (
          <li key={blocker}>
            <code>{blocker}</code>
            {sentence ? <div>{sentence}</div> : null}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The identifier for the one disclosure that has an action attached to it.
 *
 * Every other blocker on the list is something to know. This one is something
 * to DO: take a close voucher, and the deposit stops depending on the Hub
 * staying reachable. That is why its sentence is lifted out of the folded list
 * and shown beside the caps, while also staying inside the list. Duplicating a
 * risk sentence is safe. Folding this one is not.
 */
export const NO_UNILATERAL_EXIT_BLOCKER =
  "wallet_cannot_build_a_unilateral_exit_without_the_hub";

/**
 * The close-voucher sentence, when anything on screen discloses that gap.
 *
 * `texts` may be blocker identifiers or whole sentences: the preflight carries
 * the same identifiers inside `hub_disclosed_gaps`, in its observed text and
 * its reason, so the Fast Pay screen can find this without a Hub declaration
 * of its own. Matching on substring rather than equality is deliberate, and it
 * fails towards SHOWING the sentence rather than towards hiding it.
 */
export function closeVoucherSentence(texts: Array<string | null | undefined>): string | null {
  const found = texts.some(
    (text) => typeof text === "string" && text.includes(NO_UNILATERAL_EXIT_BLOCKER),
  );
  return found ? explainBlocker(NO_UNILATERAL_EXIT_BLOCKER) : null;
}

export const DECLARED_CAPS_LEDE =
  "These are its numbers, not this build's ceilings, and they are what will actually apply to you.";

/**
 * The three caps one Hub declares, on their own, so a screen with a preflight
 * but no Hub declaration can still answer "what does it let me move".
 */
export function DeclaredCapsList({ caps }: { caps: DeclaredHubCapsView }) {
  return (
    <ul className="muted small">
      {capRow("Per payment", caps.max_payment_hac)}
      {capRow("Per channel", caps.max_channel_funding_hac)}
      {capRow("Total across all channels", caps.max_aggregate_tvl_hac)}
    </ul>
  );
}

/**
 * What is inside the fold, counted from the arrays that are inside the fold.
 *
 * Never hardcoded, and never derived from a summary field the Hub sends: the
 * first Hub to disclose a fourth blocker must make this say four by itself.
 */
export function hubDeclarationFoldSummary(declaration: HubDeclarationView): string {
  const parts: string[] = [];
  const disclosed = declaration.disclosed_blockers.length;
  if (disclosed > 0) {
    parts.push(
      `${disclosed} thing${disclosed === 1 ? "" : "s"} it discloses but does not block on`,
    );
  }
  const limitations = declaration.limitations.length;
  if (limitations > 0) {
    parts.push(`${limitations} limitation${limitations === 1 ? "" : "s"} it publishes`);
  }
  const declared: string[] = [];
  if (declaration.deployment_profile || declaration.readiness_profile) {
    declared.push("profile");
  }
  if (declaration.payments_enabled !== null) declared.push("payment switch");
  if (declaration.hub_fee_mei !== null) declared.push("fee");
  if (declared.length > 0) parts.push(`the ${joinWithAnd(declared)} it declares`);
  if (declaration.readiness_error) parts.push("the readiness error it returned");
  if (parts.length === 0) return "What this Hub says about itself";
  return `What this Hub says about itself: ${joinWithAnd(parts)}.`;
}

export function HubDeclarationCard({
  declaration,
}: {
  declaration: HubDeclarationView | null;
}) {
  if (!declaration) return null;

  if (!declaration.reachable) {
    return (
      <div className="alert" role="note">
        <strong>Could not read this Hub</strong>
        <p className="small">{declaration.hub_url}</p>
        {declaration.error && <p className="small">{declaration.error}</p>}
      </div>
    );
  }

  const caps = declaration.declared_caps;
  const anyCap =
    caps.max_payment_hac !== null ||
    caps.max_channel_funding_hac !== null ||
    caps.max_aggregate_tvl_hac !== null;

  const voucher = closeVoucherSentence([
    ...declaration.blockers,
    ...declaration.disclosed_blockers,
  ]);

  return (
    <div className="preview-card hub-declaration">
      {/*
        Band 2, "what am I about to agree to", in the order a person asks it:
        who this counterparty is, what it lets me move, and the one thing I can
        do about the risk. You cannot agree to a counterparty you cannot see,
        so the name, the URL and the on-chain address never fold.
      */}
      <h4>{declaration.name ?? "This Hub"} says</h4>
      <p className="muted small hub-discovery-url">{declaration.hub_url}</p>
      {declaration.hub_address && (
        <p className="muted small">
          <strong>Provider address:</strong> {declaration.hub_address}
        </p>
      )}

      {declaration.mainnet_checked && anyCap && (
        <>
          <p className="small">
            <strong>Caps this Hub declares.</strong> {DECLARED_CAPS_LEDE}
          </p>
          <DeclaredCapsList caps={caps} />
          {caps.max_aggregate_tvl_hac !== null &&
            caps.max_channel_funding_hac !== null &&
            Number(caps.max_aggregate_tvl_hac) < Number(caps.max_channel_funding_hac) && (
              <p className="small">
                This Hub's total cap is below its own per-channel cap, so it
                will refuse any channel larger than{" "}
                {caps.max_aggregate_tvl_hac} HAC even though it advertises{" "}
                {caps.max_channel_funding_hac}.
              </p>
            )}
          {caps.aggregate_tvl_within_limit === false && (
            <p className="small">
              This Hub is already at or over its own total cap, so it will not
              take a new channel right now.
            </p>
          )}
        </>
      )}

      {/*
        The only sentence on this card that changes the risk rather than
        describing it. It stays out of the fold and it also stays inside the
        disclosed list below.
      */}
      {voucher && <p className="small">{voucher}</p>}

      {/*
        A BLOCKING blocker is not evidence, it is the answer to "can I act now",
        so it never folds. readiness.rs deliberately moves some identifiers from
        `blockers` into `disclosed_blockers`; the two lists must stay told apart
        and neither may vanish.
      */}
      {declaration.blockers.length > 0 && (
        <>
          <p className="small">
            <strong>What this Hub says is stopping it:</strong>
          </p>
          <BlockerList blockers={declaration.blockers} />
        </>
      )}

      {/*
        Band 3. Everything below is evidence: true, hard won, and none of it the
        answer to a question a person has before they act. It is folded, never
        removed, and every word is still in the document.
      */}
      <Disclosure summary={hubDeclarationFoldSummary(declaration)}>
        <ul className="muted small">
          {declaration.deployment_profile && (
            <li>
              <strong>Deployment:</strong> {declaration.deployment_profile}
            </li>
          )}
          {declaration.readiness_profile && (
            <li>
              <strong>Mainnet profile:</strong> {declaration.readiness_profile}
            </li>
          )}
          {declaration.payments_enabled !== null && (
            <li>
              <strong>Mainnet payments:</strong>{" "}
              {declaration.payments_enabled ? "enabled" : "not enabled"}
            </li>
          )}
          {declaration.hub_fee_mei !== null && (
            <li>
              <strong>Fast Pay fee:</strong> {declaration.hub_fee_mei} HAC
            </li>
          )}
        </ul>

        {/*
          The second copy of the ceilings text. The screens that host this card
          print it in full beside the consent box, so a person met 65 identical
          words twice on one scroll. It is folded rather than dropped, because
          this card also renders on Settings, where it may be the only copy.
        */}
        {declaration.mainnet_checked && anyCap && (
          <p className="muted small">{FAST_PAY_MAINNET_CEILINGS}</p>
        )}

        {declaration.readiness_error && (
          <p className="small">
            <strong>Mainnet readiness could not be read:</strong>{" "}
            {declaration.readiness_error}
          </p>
        )}

        {declaration.disclosed_blockers.length > 0 && (
          <>
            <p className="small">
              <strong>What this Hub discloses but does not block on:</strong>
            </p>
            <BlockerList blockers={declaration.disclosed_blockers} />
          </>
        )}

        {declaration.limitations.length > 0 && (
          <>
            <p className="small">
              <strong>Limitations this Hub publishes:</strong>
            </p>
            <ul className="muted small">
              {declaration.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </>
        )}
      </Disclosure>
    </div>
  );
}
