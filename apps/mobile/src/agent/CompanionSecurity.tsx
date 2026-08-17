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
  COMPANION_RETIRE_PAIRING_ACTION,
  COMPANION_REVOKED_ALTERNATIVE,
  COMPANION_REVOKED_ORDER_MATTERS,
  COMPANION_REVOKED_PERMANENCE,
  COMPANION_REVOKED_RECOVERY_STEPS,
  COMPANION_REVOKED_RESET_DOES_NOT_HELP,
  COMPANION_REVOKED_ROUTE,
  COMPANION_REVOKED_TITLE,
} from "./companionRevokedRecovery";
import {
  COMPANION_DISCARD_CONSENT_ACTION,
  COMPANION_DISCARD_CONSENT_EFFECTS,
  COMPANION_DISCARD_CONSENT_PHRASE,
  COMPANION_DISCARD_HISTORY_TITLE,
  COMPANION_HELD_CONSENT_TITLE,
  discardedConsentNotice,
  discardedConsentOverflowNotice,
  heldConsentExplanation,
  heldConsentFacts,
} from "./companionHeldConsent";
import {
  REGISTRY_EXIT_COST,
  REGISTRY_EXIT_LEASE,
  REGISTRY_EXIT_PHONE_CANNOT,
  REGISTRY_EXIT_REASSURANCE,
  REGISTRY_EXIT_ROUTE,
  REGISTRY_EXIT_TITLE,
} from "./registryExitRoute";
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
  retireConfirm: boolean;
  retireText: string;
  onBeginRetire: () => void;
  onCancelRetire: () => void;
  onRetireText: (value: string) => void;
  onRetire: () => void;
  /**
   * Whether revocation is one of the live explanations for the last failure.
   * It only decides whether the revocation reference opens by itself; the text
   * inside is identical either way, and it still never claims a revocation the
   * phone cannot know about.
   */
  revocationSuspected: boolean;
  discardConfirm: boolean;
  discardText: string;
  onBeginDiscard: () => void;
  onCancelDiscard: () => void;
  onDiscardText: (value: string) => void;
  onDiscard: () => void;
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
  retireConfirm,
  retireText,
  onBeginRetire,
  onCancelRetire,
  onRetireText,
  onRetire,
  revocationSuspected,
  discardConfirm,
  discardText,
  onBeginDiscard,
  onCancelDiscard,
  onDiscardText,
  onDiscard,
}: Props) {
  // The predicate the storage layer actually enforces, not the narrower one the
  // screen used to read. `reset_before_witness_rotation` refuses on this and
  // durably rewrites the rotation phase while doing so, so a reset offered here
  // could only refuse - and being refused permanently replaced this section.
  const resetBlocked = Boolean(
    stored?.controlledRotationRequired || stored?.resetBlockingPhase,
  );
  // The pairing is bound to a companion key this phone no longer holds, so the
  // witness state it carries can never be presented to anyone again.
  const pairingOrphaned =
    stored?.pairingIdentity === "replaced" || stored?.pairingIdentity === "absent";
  // The one payment this phone is still holding a consent record for. It is
  // the reason the reset refuses in every case below where it exists, and it
  // is not a rotation problem: running a rotation does not clear it, and being
  // told to run one is what turned this into a dead end.
  const heldConsent = stored?.pendingConsent ?? null;
  // Every receipt, newest first, not just the last one. A single slot meant a
  // second discard erased the first receipt before the owner could ever read
  // it, and a trace nobody can read is not a trace.
  const discardedConsents = stored?.discardedConsents ?? [];
  const discardOverflow = discardedConsentOverflowNotice(
    stored?.discardedConsentsDropped ?? "0",
  );
  // Until this exists, nothing else on the phone can happen: no pairing, no
  // connection, no approval. It used to be the fourth section of this screen,
  // under an identity table and a revocation reference, and on a 960px phone
  // that put the only control the state depends on below the fold. Same
  // section, same button, same confirmation: only its position changed.
  const createIdentity =
    identity?.platformSupported && !identity.configured && !createConfirm ? (
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
    ) : null;

  const confirmIdentity = createConfirm ? (
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
  ) : null;

  return (
    <>
      {createIdentity}
      {confirmIdentity}

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

      {/* The day the provider stops answering, this phone is the device the
          owner has in their hand, and it used to say nothing about it at all.

          Unconditional: every build, paired or not, read-only or not. A
          read-only companion is the build an owner is most likely to be
          holding and the one with nothing else on this subject anywhere. No
          control is added, because this handset holds an approval identity and
          not a Hacash key, so none could exist here - the route to the one
          that does exist is named exactly instead, and a test reads the
          desktop's own control table to keep it named exactly. */}
      <section className="agent-panel">
        <h2>{REGISTRY_EXIT_TITLE}</h2>
        <p>{REGISTRY_EXIT_REASSURANCE}</p>
        <p className="agent-muted">{REGISTRY_EXIT_COST}</p>
        {/* Never behind a disclosure: this is the only clock in the system
            that destroys the money instead of delaying it. */}
        <p className="agent-warning-copy" role="status">{REGISTRY_EXIT_LEASE}</p>
        <p className="agent-muted">{REGISTRY_EXIT_PHONE_CANNOT}</p>
        <p>{REGISTRY_EXIT_ROUTE}</p>
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

      {/* This panel used to exist only in a pilot build. A read-only build that
          had been marked as needing a controlled rotation therefore had no
          control at all: the reset was refused, this panel was hidden and the
          rotation command refused too, so the handset was stuck for good. The
          old-phone half of a rotation - ask the desktop what it prepared, then
          authorize this handset's own replacement - now runs in every build,
          because it authorizes nothing and spends nothing. */}
      {stored?.configured && (stored.pilotEnabled || resetBlocked) ? (
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
            {!stored.pilotEnabled ? (
              <p className="agent-muted">
                This build can only run the old phone's half: it hands this
                phone's authority to the replacement. It cannot act as the
                replacement phone. If this phone is meant to be the replacement,
                use a build that supports approvals.
              </p>
            ) : null}
          </details>
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

      {/* A discard is never silent. Whether the phone retired the record by
          itself, because the desktop said the payment was no longer waiting on
          it, or the owner discarded it here, the owner can still find out that
          it happened and which payment it was. This claims nothing about
          whether the payment succeeded - the phone does not know that. */}
      {discardedConsents.length > 0 ? (
        <section className="agent-panel">
          {discardedConsents.length > 1 ? (
            <h2>{COMPANION_DISCARD_HISTORY_TITLE}</h2>
          ) : null}
          {/* The history is bounded, and what the bound drops has to be said.
              Dropping the oldest without a word would be the same defect as
              the single slot this list replaced. */}
          {discardOverflow ? (
            <p className="agent-muted" role="note">
              {discardOverflow}
            </p>
          ) : null}
          {discardedConsents.map((record, index) => {
            const notice = discardedConsentNotice(record);
            return (
              <div
                // One payment can be confirmed and discarded more than once,
                // so neither the operation nor the time alone is a key.
                key={`${record.operationId}-${record.discardedAtUnix}-${index}`}
                className="agent-boundary-card"
                role="note"
              >
                <strong>{notice.title}</strong>
                <p>{notice.body}</p>
                <dl className="agent-detail-list">
                  {notice.facts.map((fact) => (
                    <Detail key={fact.label} label={fact.label} value={fact.value} />
                  ))}
                </dl>
              </div>
            );
          })}
        </section>
      ) : null}

      {stored?.configured ? (
        <section className="agent-panel">
          <h2>Reset this phone's pairing</h2>
          {/* A held consent record is the blocker, and it is not a rotation
              matter. The old card said "controlled witness rotation required"
              whatever was holding the reset, so an owner in this state ran the
              rotation, finished it, and was refused again - because a held
              record blocks the reset regardless of any rotation phase. The
              phone now names what it is holding, says what discarding does and
              does not do, and offers the discard behind its own words. */}
          {resetBlocked && heldConsent ? (
            <div className="agent-boundary-card" role="alert">
              <strong>{COMPANION_HELD_CONSENT_TITLE}</strong>
              <p>{heldConsentExplanation(heldConsent)}</p>
              <dl className="agent-detail-list">
                {heldConsentFacts(heldConsent).map((fact) => (
                  <Detail key={fact.label} label={fact.label} value={fact.value} />
                ))}
              </dl>
              {!discardConfirm ? (
                <button type="button" disabled={busy} onClick={onBeginDiscard}>
                  {COMPANION_DISCARD_CONSENT_ACTION}
                </button>
              ) : (
                <>
                  <ul className="agent-security-list">
                    {COMPANION_DISCARD_CONSENT_EFFECTS.map((effect) => (
                      <li key={effect}>{effect}</li>
                    ))}
                  </ul>
                  <label className="agent-field">
                    Type {COMPANION_DISCARD_CONSENT_PHRASE}
                    <input
                      value={discardText}
                      autoComplete="off"
                      spellCheck={false}
                      disabled={busy}
                      onChange={(event) => onDiscardText(event.target.value)}
                    />
                  </label>
                  <div className="agent-confirm-actions">
                    <button
                      type="button"
                      className="agent-primary-action"
                      disabled={busy}
                      onClick={onCancelDiscard}
                    >
                      Keep holding it
                    </button>
                    <button
                      type="button"
                      className="agent-danger-action"
                      disabled={
                        busy || discardText !== COMPANION_DISCARD_CONSENT_PHRASE
                      }
                      onClick={onDiscard}
                    >
                      {COMPANION_DISCARD_CONSENT_ACTION}
                    </button>
                  </div>
                </>
              )}
            </div>
          ) : resetBlocked ? (
            <div className="agent-boundary-card" role="alert">
              <strong>Controlled witness rotation required</strong>
              <p>
                Reset is disabled because durable pilot approval or witness state
                exists. Rotate the witness together on desktop and mobile; do not
                delete one side or assume the retained identity can simply re-pair.
              </p>
              {/* The instruction above names a joint desktop-and-phone flow.
                  The phone half is the rotation panel, which now exists in every
                  build for the old phone's half of a rotation. */}
              <p>
                The phone half is Check and continue rotation, in Approval phone
                rotation on this screen. Start the desktop half first, in AI
                Agent Wallet on HPAY Desktop.
              </p>
              {/* Until this existed, a phone the desktop had already revoked
                  was finished: it could not run a joint rotation with a desktop
                  that had revoked it, and the pairing-only reset was refused
                  forever. Once the companion key this pairing is bound to is
                  gone, the rollback memory it holds can never be presented to
                  anyone, so clearing it takes nothing away. The native side
                  re-reads the Keystore and refuses if the key is still live. */}
              {pairingOrphaned ? (
                !retireConfirm ? (
                  <>
                    <p>
                      This phone no longer holds the secure identity this pairing
                      was made with, so it can never take part in that rotation
                      again. You can retire the pairing instead and start over.
                    </p>
                    <button type="button" disabled={busy} onClick={onBeginRetire}>
                      {COMPANION_RETIRE_PAIRING_ACTION}
                    </button>
                  </>
                ) : (
                  <>
                    <p className="agent-warning-copy" role="alert">
                      <strong>This cannot be undone.</strong> The pairing on this
                      phone is deleted, together with the record of which wallet
                      states it has already witnessed. That record is only kept
                      out of this phone's own secure key, and that key is gone,
                      so nothing that was protecting you is lost. Nothing is
                      spent and no money moves. Afterwards this phone is not
                      paired, and the desktop must pair it again as a new phone.
                      If you are not sure the old identity is really gone, stop
                      and check the identity table above first.
                    </p>
                    <label className="agent-field">
                      Type RETIRE THIS PAIRING
                      <input
                        value={retireText}
                        autoComplete="off"
                        spellCheck={false}
                        disabled={busy}
                        onChange={(event) => onRetireText(event.target.value)}
                      />
                    </label>
                    <div className="agent-confirm-actions">
                      <button
                        type="button"
                        className="agent-primary-action"
                        disabled={busy}
                        onClick={onCancelRetire}
                      >
                        Keep this pairing
                      </button>
                      <button
                        type="button"
                        className="agent-danger-action"
                        disabled={busy || retireText !== "RETIRE THIS PAIRING"}
                        onClick={onRetire}
                      >
                        {COMPANION_RETIRE_PAIRING_ACTION}
                      </button>
                    </div>
                  </>
                )
              ) : (
                <p className="agent-muted">{COMPANION_REVOKED_ORDER_MATTERS}</p>
              )}
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
              {/* This screen now reads reset_blocking_phase, the predicate
                  reset_before_witness_rotation
                  (apps/mobile/src-tauri/src/agent_companion/storage.rs)
                  actually enforces, so the button is not offered when the reset
                  would refuse. The residual case is a race: an approval or a
                  witness record can land between the read and the press. The
                  refusal is still not a no-op, so it is still said here. */}
              <p className="agent-warning-copy" role="alert">
                It may do something else instead. If this phone approves a
                testnet payment, or records any witness state, between this
                screen loading and this press, the reset is refused and nothing
                is deleted - but the refusal permanently marks this phone as
                needing a controlled rotation, and this section is then replaced
                for good by Controlled witness rotation required. Nothing is
                paid, signed or lost either way. If you are not sure, start the
                replacement from AI Agent Wallet on HPAY Desktop under Replace
                the paired phone instead, and leave this phone alone.
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
