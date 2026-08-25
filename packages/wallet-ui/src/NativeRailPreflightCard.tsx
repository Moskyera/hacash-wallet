/**
 * The read-only mainnet preflight, on the screen where somebody is about to
 * turn Fast Pay on or open a channel.
 *
 * It exists because the only preflight before it checked the wrong rail and
 * needed a Rust toolchain. It demanded the node report features.hvm,
 * contract_state_leasing and actions 40/41/44, plus a verified on-chain HVM
 * shared-registry deployment. That contract costs roughly 2000 HAC to deploy,
 * this owner holds 7, and nothing on the native ChannelPay rail reads any of
 * it. So a person who was ready would have been told they were not, and sent
 * shopping for a node feature no code on their path will ever look at. And it
 * ran through "cargo run --example", which a wallet owner does not have.
 *
 * Two rules are load bearing here and neither may be softened:
 *
 * 1. A PASS is never shown while any fatal item failed OR was skipped. A
 *    skipped check is not a passed check: an unreachable Hub leaves its items
 *    unjudged, and unjudged must not render as fine. The verdict is computed
 *    from the items on this side as well as in the core, so a report that
 *    somehow arrived with a stale verdict field still cannot paint the header
 *    green.
 * 2. The copy does not overclaim. Green means the infrastructure answered
 *    correctly, read-only, at one instant. It does not mean the money is safe,
 *    it does not make the pilot trustless, and the Hub can still refuse the
 *    voucher afterwards. What cannot be checked is on the screen, not in a
 *    comment.
 */

import { Disclosure } from "./HubDeclarationCard";

export type PreflightCheckStatus = "pass" | "fail" | "skip";
export type PreflightCheckSeverity = "fatal" | "warning";

export type PreflightCheckView = {
  id: string;
  title: string;
  severity: PreflightCheckSeverity;
  status: PreflightCheckStatus;
  observed: string;
  reason: string | null;
};

export type UncheckableFactView = {
  id: string;
  title: string;
  detail: string;
};

export type NativeRailPreflightView = {
  schema: string;
  generated_unix: number;
  node_url: string;
  hub_url: string;
  owner_address: string;
  hub_address: string;
  channel_deposit_hac: string;
  payment_hac: string;
  verdict: "pass" | "not_pass";
  fatal_failed: number;
  fatal_skipped: number;
  warnings: number;
  validity_seconds: number;
  checks: PreflightCheckView[];
  declared_caps: {
    max_payment_hac: string | null;
    max_channel_funding_hac: string | null;
    max_aggregate_tvl_hac: string | null;
    aggregate_tvl_within_limit: boolean | null;
  };
  cannot_be_checked: UncheckableFactView[];
};

/**
 * The one rule the screen hangs on, recomputed from the items.
 *
 * Deliberately NOT `report.verdict`. The core computes the same thing, and
 * both agree today, but the header is the thing a person acts on and it must
 * not be able to go green because a single field said so. A fatal item that
 * failed or was never reached denies the pass, and a report with no fatal
 * items in it is not a pass either: nothing failed only because nothing was
 * asked.
 */
export function preflightShowsPass(checks: PreflightCheckView[]): boolean {
  const fatal = checks.filter((check) => check.severity === "fatal");
  if (fatal.length === 0) return false;
  return fatal.every((check) => check.status === "pass");
}

export function fatalFailed(checks: PreflightCheckView[]): PreflightCheckView[] {
  return checks.filter(
    (check) => check.severity === "fatal" && check.status === "fail",
  );
}

export function fatalSkipped(checks: PreflightCheckView[]): PreflightCheckView[] {
  return checks.filter(
    (check) => check.severity === "fatal" && check.status === "skip",
  );
}

/**
 * The id of the item that asks whether anybody can reach this node.
 *
 * It is a WARNING in the core, on purpose, so it never blocks the verdict. But
 * a person about to fund a channel has to see it, and a warning that only
 * appears in the list below a green READY header is a warning somebody scrolls
 * past. So this one item is also pulled out and shown directly under the
 * banner, in both colours.
 */
export const NODE_REACH_CHECK_ID = "node_can_be_reached";

export function nodeReachCheck(
  checks: PreflightCheckView[],
): PreflightCheckView | undefined {
  return checks.find((check) => check.id === NODE_REACH_CHECK_ID);
}

export const PREFLIGHT_LEAF_HEADLINE =
  "Nothing can reach your node, so it may not be able to pass your payment on";

export const PREFLIGHT_REACH_UNKNOWN_HEADLINE =
  "Whether anything can reach your node is unknown, which is not the same as fine";

export const PREFLIGHT_REACH_DOES_NOT_BLOCK =
  "This does not stop you and it is not a reason to distrust what you see above. " +
  "A node nobody can reach still downloads every block and checks it for itself, " +
  "so everything else on this screen means what it says. It is here because green " +
  "above means your node told the truth about the chain, not that your signed " +
  "transaction can get out to the miners.";

export const PREFLIGHT_GREEN_MEANS =
  "Green means the node and the Hub answered these questions correctly just now, " +
  "over read-only requests. It does not mean your money is safe, it does not make " +
  "this pilot trustless, and the Hub can still refuse to countersign your voucher " +
  "after your deposit is already in the channel.";

export const PREFLIGHT_RED_MEANS =
  "Anything marked FATAL below has to be green before you put money in. A check " +
  "that could not be run counts as failed here, because a question nobody answered " +
  "is not a question that came back clean.";

export const PREFLIGHT_WHAT_IT_DOES =
  "This sends five read-only requests and signs nothing, unlocks nothing and " +
  "broadcasts nothing. It checks the native ChannelPay rail with a close voucher, " +
  "which is the path you are on. It does not check the HVM registry contract, " +
  "because that rail costs around 2000 HAC to deploy and nothing on your path " +
  "reads it. It also asks your node how many other nodes have reached it, which " +
  "you used to have to work out yourself by counting connections in a terminal.";

/**
 * The verdict as one line, for the top of a screen rather than the middle of a
 * report.
 *
 * "NOT READY. Do not put money in yet." is a "can I act now" answer, and it was
 * sitting roughly 1500 words down the page, under everything the check had to
 * say. The screens render this above everything; the report below keeps the
 * same banner and folds only its body.
 *
 * Recomputed from the items, never from `report.verdict`. See preflightShowsPass.
 */
export type PreflightVerdictLine = {
  pass: boolean;
  pill: string;
  headline: string;
};

export function preflightVerdict(report: NativeRailPreflightView): PreflightVerdictLine {
  const pass = preflightShowsPass(report.checks);
  return {
    pass,
    pill: pass ? "READY" : "NOT READY",
    headline: pass
      ? "The infrastructure answered correctly, right now"
      : "Do not put money in yet",
  };
}

/**
 * What is behind the fold, counted from the items that are behind the fold.
 *
 * Every number here is recomputed from `report.checks` and
 * `report.cannot_be_checked` on each render. Hardcoding any of them, or reading
 * `report.fatal_failed` instead, would let this line drift from the list it
 * describes, and a wrong count in a summary reads as authority. A skipped check
 * gets its own number and is never added to the green one: a question nobody
 * answered is not a question that came back clean.
 */
export function preflightItemSummary(report: NativeRailPreflightView): string {
  const total = report.checks.length;
  const green = report.checks.filter((check) => check.status === "pass").length;
  const failed = report.checks.filter((check) => check.status === "fail").length;
  const notRun = report.checks.filter((check) => check.status === "skip").length;
  const cannot = report.cannot_be_checked.length;
  const tail =
    cannot === 0
      ? ""
      : `, plus ${cannot} thing${cannot === 1 ? "" : "s"} no check can tell you, starting with "${report.cannot_be_checked[0].title}"`;
  return `Every item this check ran. ${total} item${total === 1 ? "" : "s"}: ${green} green, ${failed} failed, ${notRun} not run${tail}.`;
}

/** The summary before anything has been run, so the fold still has an honest label. */
export const PREFLIGHT_WHAT_IT_DOES_SUMMARY =
  "What this check does. It signs nothing, unlocks nothing and moves no money.";

/**
 * The sentence that stops the Enable button reading as broken on a red check.
 *
 * The short form goes beside the button and never folds: without it, a person
 * looking at a red report and a live button cannot tell which of the two is
 * wrong. The long form keeps the reasoning and folds into the report.
 */
export const PREFLIGHT_NOT_GREEN_SHORT =
  "The check below is not green. You can still press Enable, and the same gates will refuse again with a reason.";

export const PREFLIGHT_NOT_GREEN_FULL =
  "The check above is not green. You can still continue, and the same gates will refuse you again with a reason when the money actually moves. Fixing what it named first is the cheaper order.";

function statusLabel(check: PreflightCheckView): string {
  if (check.status === "pass") return check.severity === "fatal" ? "PASS" : "OK";
  if (check.severity === "warning") {
    return check.status === "skip" ? "NOT CHECKED" : "WORTH KNOWING";
  }
  return check.status === "skip" ? "FATAL, NOT CHECKED" : "FATAL, FAILED";
}

function statusClass(check: PreflightCheckView): string {
  if (check.status === "pass") return "badge badge-ok";
  return check.severity === "fatal" ? "badge badge-error" : "badge badge-warn";
}

function CheckRow({ check }: { check: PreflightCheckView }) {
  return (
    <li className="preflight-item">
      <div className="preflight-item-head">
        <span className={statusClass(check)}>{statusLabel(check)}</span>
        <strong>{check.title}</strong>
      </div>
      <p className="muted small">{check.observed}</p>
      {check.reason && <p className="small">{check.reason}</p>}
      <p className="muted small">
        <code>{check.id}</code>
      </p>
    </li>
  );
}

export function NativeRailPreflightCard({
  report,
  running,
  onRun,
  disabled,
}: {
  report: NativeRailPreflightView | null;
  running: boolean;
  onRun: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="preview-card native-rail-preflight">
      <h4>Check the infrastructure before you put money in</h4>
      <button
        type="button"
        className="primary"
        disabled={running || disabled}
        onClick={onRun}
      >
        {running ? "Checking…" : "Run the check"}
      </button>

      {report ? (
        <PreflightResult report={report} />
      ) : (
        /*
          With no report there is no item summary to compute, and
          PREFLIGHT_WHAT_IT_DOES must not simply disappear: it is what tells a
          person that pressing the button costs them nothing.
        */
        <Disclosure summary={PREFLIGHT_WHAT_IT_DOES_SUMMARY}>
          <p className="muted small">{PREFLIGHT_WHAT_IT_DOES}</p>
        </Disclosure>
      )}
    </div>
  );
}

export function PreflightResult({ report }: { report: NativeRailPreflightView }) {
  // Recomputed here on purpose. See preflightShowsPass.
  const pass = preflightShowsPass(report.checks);
  const failed = fatalFailed(report.checks);
  const skipped = fatalSkipped(report.checks);
  const minutes = Math.floor(report.validity_seconds / 60);
  const reach = nodeReachCheck(report.checks);
  const reachUnproven = reach !== undefined && reach.status !== "pass";
  const warnings = report.checks.filter(
    (check) =>
      check.severity === "warning" &&
      check.status !== "pass" &&
      // Shown in full under the banner instead, rather than twice.
      !(reachUnproven && check.id === NODE_REACH_CHECK_ID),
  );

  const verdict = preflightVerdict(report);

  return (
    <>
      {/*
        The verdict keeps its banner and loses its paragraph. The pill and the
        headline answer "can I act now" in four words; the reasoning underneath
        them is evidence and moves into the fold below, where it is still read
        in full by anyone who opens it.
      */}
      <div
        className={pass ? "fp-status-banner fp-status-on" : "fp-status-banner fp-status-off"}
        role="status"
      >
        <div className="fp-status-pill">{verdict.pill}</div>
        <div>
          <h3>{verdict.headline}</h3>
        </div>
      </div>

      {/*
        The node-reach warning stays visible, headline only.
        NODE_REACH_CHECK_ID was already promoted out of the list once, on the
        finding that a warning under a green banner is a warning people scroll
        past. Re-folding the headline would undo that. Its three explanatory
        paragraphs, which are the ones the owner counted as a 200-word section,
        fold under it.
      */}
      {reachUnproven && reach && (
        <div className="alert" role="note">
          <strong>
            {reach.status === "fail"
              ? PREFLIGHT_LEAF_HEADLINE
              : PREFLIGHT_REACH_UNKNOWN_HEADLINE}
          </strong>
          <Disclosure summary="Why this does not stop you">
            <p className="small">{reach.observed}</p>
            {reach.reason && <p className="small">{reach.reason}</p>}
            <p className="muted small">{PREFLIGHT_REACH_DOES_NOT_BLOCK}</p>
            <p className="muted small">
              <code>{reach.id}</code>
            </p>
          </Disclosure>
        </div>
      )}

      {/*
        The report itself: one fold, and the single biggest saving on the screen.
        It is a diagnostic listing, every word of it still in the document.
      */}
      <Disclosure summary={preflightItemSummary(report)}>
        <p className="muted small">{PREFLIGHT_WHAT_IT_DOES}</p>

        <p className="small">
          {pass
            ? PREFLIGHT_GREEN_MEANS
            : `${failed.length} check(s) failed and ${skipped.length} could not be run. ${PREFLIGHT_RED_MEANS}`}
        </p>

        {!pass && <p className="small">{PREFLIGHT_NOT_GREEN_FULL}</p>}

        {pass && (
          <p className="small">
            <strong>This answer goes stale in about {minutes} minutes.</strong> The
            Hub's readiness document is good for {report.validity_seconds} seconds
            at most, and your wallet fetches and judges it again at the moment you
            sign. Nothing here grants any later permission.
          </p>
        )}

        {!pass && (skipped.length > 0) && (
          <p className="small">
            A check that could not be run is shown as failed, not as passed. If the
            Hub or the node was unreachable, the honest answer is that nobody knows.
          </p>
        )}

        <ul className="preflight-list">
          {report.checks
            .filter((check) => check.severity === "fatal" && check.status !== "pass")
            .map((check) => (
              <CheckRow key={check.id} check={check} />
            ))}
          {warnings.map((check) => (
            <CheckRow key={check.id} check={check} />
          ))}
          {report.checks
            .filter((check) => check.status === "pass")
            .map((check) => (
              <CheckRow key={check.id} check={check} />
            ))}
        </ul>

        <div className="alert" role="note">
          <strong>What this check cannot tell you, whatever colour it is</strong>
          <ul className="muted small">
            {report.cannot_be_checked.map((fact) => (
              <li key={fact.id}>
                <strong>{fact.title}.</strong> {fact.detail}
              </li>
            ))}
          </ul>
        </div>

        <p className="muted small">
          Checked node <code>{report.node_url}</code> and Hub{" "}
          <code>{report.hub_url}</code> for a {report.channel_deposit_hac} HAC
          deposit and a {report.payment_hac} HAC payment.
        </p>
      </Disclosure>
    </>
  );
}
