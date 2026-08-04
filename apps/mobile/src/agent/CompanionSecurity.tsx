import { Detail } from "./CompanionReadOnlyPages";
import {
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_RECHECK_IDENTITY_ACTION,
  COMPANION_RESET_PAIRING_ACTION,
} from "./companionStatus";
import {
  COMPANION_PLATFORM_UNSUPPORTED_BODY,
  COMPANION_PLATFORM_UNSUPPORTED_ROUTE,
  COMPANION_PLATFORM_UNSUPPORTED_TITLE,
} from "./companionLayout";
import {
  COMPANION_REVOKED_ALTERNATIVE,
  COMPANION_REVOKED_PERMANENCE,
  COMPANION_REVOKED_RECOVERY_STEPS,
  COMPANION_REVOKED_RESET_DOES_NOT_HELP,
  COMPANION_REVOKED_ROUTE,
  COMPANION_REVOKED_TITLE,
} from "./companionRevokedRecovery";
import type {
  AgentCompanionIdentityStatus,
  CompanionStoredStateView,
} from "./types";

type Props = {
  identity: AgentCompanionIdentityStatus | null;
  stored: CompanionStoredStateView | null;
  busy: boolean;
  createConfirm: boolean;
  resetConfirm: boolean;
  resetText: string;
  onBeginCreate: () => void;
  onCancelCreate: () => void;
  onCreate: () => void;
  onRetry: () => void;
  onBeginReset: () => void;
  onCancelReset: () => void;
  onResetText: (value: string) => void;
  onReset: () => void;
  onRotationStep: () => void;
  /**
   * Whether revocation is one of the live explanations for the last failure.
   * It only decides whether the revocation reference opens by itself; the text
   * inside is identical either way, and it still never claims a revocation the
   * phone cannot know about.
   */
  revocationSuspected: boolean;
};

export function CompanionSecurity({
  identity,
  stored,
  busy,
  createConfirm,
  resetConfirm,
  resetText,
  onBeginCreate,
  onCancelCreate,
  onCreate,
  onRetry,
  onBeginReset,
  onCancelReset,
  onResetText,
  onReset,
  onRotationStep,
  revocationSuspected,
}: Props) {
  return (
    <>
      {/* The one state in the whole phone app where nothing can proceed used to
          render a two-column list reading "Platform support: Unavailable" and
          not one other word: no explanation, no next step, no control. No
          control is added, because none can exist here. That is the point, and
          it is now said. */}
      {identity && !identity.platformSupported ? (
        <section className="agent-boundary-card" role="note">
          <strong>{COMPANION_PLATFORM_UNSUPPORTED_TITLE}</strong>
          <p>{COMPANION_PLATFORM_UNSUPPORTED_BODY}</p>
          <p>{COMPANION_PLATFORM_UNSUPPORTED_ROUTE}</p>
        </section>
      ) : null}

      <section className="agent-panel">
        <h2>Mobile companion identity</h2>
        {!identity ? (
          <p className="agent-muted">
            This phone's security status could not be read. Nothing is wrong
            with your wallet and nothing was changed. Checking again costs
            nothing.
          </p>
        ) : (
          <dl className="agent-detail-list">
            <Detail label="Platform support" value={identity.platformSupported ? "Available" : "Unavailable"} />
            <Detail label="Identity" value={identity.configured ? "Created" : "Not created"} />
            <Detail label="Ready" value={identity.ready ? "Yes" : "No"} />
            <Detail label="Hardware protection" value={identity.hardwareBacked ? identity.keySecurityLevel : "Unavailable"} />
            <Detail label="Authentication per use" value={identity.authPerUse ? "Required" : "Unavailable"} />
            <Detail label="StrongBox" value={identity.strongBoxBacked ? "Active" : "Not active"} />
          </dl>
        )}
        {/* An owner whose identity read "Ready: No" had no way to look again:
            this control existed only in the branch where the status could not
            be read at all. It is a read; it creates and changes nothing. It is
            still withheld from the unsupported handset, where re-reading cannot
            change the answer and offering it would imply otherwise. */}
        {identity && !identity.platformSupported ? null : (
          <button type="button" disabled={busy} onClick={onRetry}>
            {COMPANION_RECHECK_IDENTITY_ACTION}
          </button>
        )}
      </section>

      {/* The desktop can refuse this phone forever, and until now the phone
          never said why or what to do. Explanation only: no reset, no pairing
          and no identity is performed here, and the desktop still admits a new
          identity through its ordinary first-pairing flow.

          It is a reference, not news, and it was the largest block of standing
          prose in either app - shown in full on every healthy phone that had
          never been revoked. Same words, folded away, and opened by the app
          itself the moment a refusal makes revocation one of the explanations. */}
      {identity?.platformSupported ? (
        <section className="agent-panel">
          <details className="agent-disclosure" open={revocationSuspected}>
            <summary>{COMPANION_REVOKED_TITLE}</summary>
            <p className="agent-muted">{COMPANION_REVOKED_PERMANENCE}</p>
            <p className="agent-muted">{COMPANION_REVOKED_RESET_DOES_NOT_HELP}</p>
            <p className="agent-muted">{COMPANION_REVOKED_ROUTE}</p>
            <ol className="agent-security-list">
              {COMPANION_REVOKED_RECOVERY_STEPS.map((step) => (
                <li key={step.action}>
                  <strong>{step.where}:</strong> {step.action}
                  <br />
                  <span className="agent-muted">{step.detail}</span>
                </li>
              ))}
            </ol>
            <p className="agent-muted">{COMPANION_REVOKED_ALTERNATIVE}</p>
          </details>
        </section>
      ) : null}

      {stored?.configured && stored.pilotEnabled ? (
        <section className="agent-panel">
          <h2>Approval phone rotation</h2>
          <dl className="agent-detail-list">
            <Detail label="Rotation phase" value={stored.rotationPhase?.replace(/_/g, " ") ?? "stable"} />
          </dl>
          <button type="button" className="agent-primary-action" disabled={busy} onClick={onRotationStep}>
            Check and continue rotation
          </button>
          <details className="agent-disclosure">
            <summary>What is rotation?</summary>
            <p className="agent-muted">
              After preparing a replacement on the trusted desktop, continue here.
              Every authorization uses Android secure identity and explicit biometric approval.
            </p>
          </details>
        </section>
      ) : null}

      {identity?.platformSupported && !identity.configured && !createConfirm ? (
        <section className="agent-panel">
          <h2>Create identity</h2>
          <button type="button" className="agent-primary-action" disabled={busy} onClick={onBeginCreate}>
            {COMPANION_CREATE_IDENTITY_ACTION}
          </button>
          <details className="agent-disclosure">
            <summary>What does this create?</summary>
            <p className="agent-muted">
              Creates a separate non-exportable Android identity. It is not a
              Hacash private key and cannot access My Wallet. It costs nothing and
              moves no money. Android will ask for your fingerprint.
            </p>
          </details>
        </section>
      ) : null}

      {createConfirm ? (
        <section className="agent-boundary-card" role="alert">
          <strong>Confirm identity creation</strong>
          <p>
            This identity remains isolated from My Wallet keys and funds. It
            spends nothing. Once created, it can only be replaced by enrolling a
            new fingerprint or face on this phone, which also affects other apps
            that use your biometrics.
          </p>
          <div className="agent-confirm-actions">
            <button type="button" disabled={busy} onClick={onCancelCreate}>Do not create it</button>
            <button type="button" className="agent-primary-action" disabled={busy} onClick={onCreate}>Create identity</button>
          </div>
        </section>
      ) : null}

      <section className="agent-panel">
        <details className="agent-disclosure">
          <summary>Security boundary</summary>
          <ul className="agent-security-list">
            <li>No Personal Wallet key or vault access</li>
            <li>No generic wallet sends, arbitrary signing or admin commands</li>
            <li>Only exact testnet approvals and rollback witness receipts in pilot builds</li>
            <li>No public listener, relay or background session</li>
            <li>No connected claim without an authenticated native session</li>
            <li>HPAY wallet fee must be exactly zero</li>
          </ul>
        </details>
      </section>

      {stored?.configured ? (
        <section className="agent-panel">
          <h2>Reset this phone's pairing</h2>
          {stored.controlledRotationRequired ? (
            <div className="agent-boundary-card" role="alert">
              <strong>Controlled witness rotation required</strong>
              <p>
                Reset is disabled because durable pilot approval or witness state
                exists. Rotate the witness together on desktop and mobile; do not
                delete one side or assume the retained identity can simply re-pair.
              </p>
              {/* The instruction above names a joint desktop-and-phone flow.
                  The phone half is the rotation panel, and that panel only
                  exists in a pilot build, so in any other build this sentence
                  used to name a control the owner could not find. It now says
                  where the control is, or that this build has none. */}
              <p>
                {stored.pilotEnabled
                  ? "The phone half is Check and continue rotation, in Approval phone rotation on this screen. Start the desktop half first, in AI Agent Wallet on HPAY Desktop."
                  : "This build has no rotation control on the phone. Run the rotation from AI Agent Wallet on HPAY Desktop."}
              </p>
            </div>
          ) : !resetConfirm ? (
            <>
              {/* "Begin companion reset" hid the safe action behind a
                  destructive-sounding name. The only reset this screen offers
                  is the pairing-only one, so the button says that. What it
                  keeps and what it costs stays beside the button; the rest is
                  reference and folds away. */}
              <p className="agent-muted">
                This removes only this phone's pairing with the desktop. It
                keeps this phone's secure identity, keeps My Wallet untouched
                and moves no money. Afterwards this phone is not paired, so you
                pair it again from HPAY Desktop.
              </p>
              <button type="button" disabled={busy} onClick={onBeginReset}>
                {COMPANION_RESET_PAIRING_ACTION}
              </button>
              <details className="agent-disclosure">
                <summary>What this reset cannot do</summary>
                <p className="agent-muted">
                  Before any pilot approval or rollback witness is recorded, this removes
                  only mobile pairing, replay and session state. My Wallet and Agent Wallet
                  funds are untouched.
                </p>
                <p className="agent-muted">
                  After pilot signing starts, local reset is blocked. A controlled desktop
                  and mobile witness rotation is required. This reset keeps the Android
                  identity on purpose, so it cannot recover a phone the desktop has
                  already revoked, and revoking a working phone is permanent rather
                  than a way to re-pair it. See {COMPANION_REVOKED_TITLE} on this screen.
                </p>
              </details>
            </>
          ) : (
            <>
              <p className="agent-muted">
                <strong>This cannot be undone.</strong> The pairing on this phone
                is deleted. Nothing is spent and no key is lost, but this phone
                stops seeing the Agent Wallet until you pair it again from HPAY
                Desktop. Type the words below to confirm.
              </p>
              <label className="agent-field">
                Type RESET COMPANION
                <input
                  value={resetText}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={busy}
                  onChange={(event) => onResetText(event.target.value)}
                />
              </label>
              {/* The destructive confirm and the safe way out looked
                  identical. Keeping the pairing is the primary here, and the
                  reset carries the danger styling the confirm dialog for
                  identity creation already uses. Neither is re-wired and the
                  typed confirmation still gates the reset. */}
              <div className="agent-confirm-actions">
                <button
                  type="button"
                  className="agent-primary-action"
                  disabled={busy}
                  onClick={onCancelReset}
                >
                  Keep this phone paired
                </button>
                <button
                  type="button"
                  className="agent-danger-action"
                  disabled={busy || resetText !== "RESET COMPANION"}
                  onClick={onReset}
                >
                  {COMPANION_RESET_PAIRING_ACTION}
                </button>
              </div>
            </>
          )}
        </section>
      ) : null}
    </>
  );
}
