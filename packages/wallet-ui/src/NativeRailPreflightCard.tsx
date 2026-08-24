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
  "reads it.";

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
      <p className="muted small">{PREFLIGHT_WHAT_IT_DOES}</p>
      <button
        type="button"
        className="primary"
        disabled={running || disabled}
        onClick={onRun}
      >
        {running ? "Checking…" : "Run the check"}
      </button>

      {report && <PreflightResult report={report} />}
    </div>
  );
}

export function PreflightResult({ report }: { report: NativeRailPreflightView }) {
  // Recomputed here on purpose. See preflightShowsPass.
  const pass = preflightShowsPass(report.checks);
  const failed = fatalFailed(report.checks);
  const skipped = fatalSkipped(report.checks);
  const warnings = report.checks.filter(
    (check) => check.severity === "warning" && check.status !== "pass",
  );
  const minutes = Math.floor(report.validity_seconds / 60);

  return (
    <>
      <div
        className={pass ? "fp-status-banner fp-status-on" : "fp-status-banner fp-status-off"}
        role="status"
      >
        <div className="fp-status-pill">{pass ? "READY" : "NOT READY"}</div>
        <div>
          <h3>
            {pass
              ? "The infrastructure answered correctly, right now"
              : "Do not put money in yet"}
          </h3>
          <p>
            {pass
              ? PREFLIGHT_GREEN_MEANS
              : `${failed.length} check(s) failed and ${skipped.length} could not be run. ${PREFLIGHT_RED_MEANS}`}
          </p>
        </div>
      </div>

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
    </>
  );
}
