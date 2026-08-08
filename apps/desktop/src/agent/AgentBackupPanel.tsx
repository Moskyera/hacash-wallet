import { useEffect, useState } from "react";
import {
  agentWalletApi,
  type AgentBackupAcknowledgement,
  type AgentBackupPreview,
  type AgentBackupWarning,
  type AgentBackupWarnings,
  type AgentRestoreOutcome,
} from "./api";
import {
  EMPTY_ACKNOWLEDGEMENT,
  outstandingPoints,
  restoreFollowUp,
  sealAcknowledgement,
  toggleAcknowledgement,
  warningGatePasses,
  warningPoints,
} from "./backupWarning";

type Props = {
  walletId: string | null;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
};

/// The warning, rendered from the core's own text, with one checkbox per fact.
///
/// Nothing here re-words a point and nothing here can leave one out: the list
/// comes from `warningPoints`, which throws on a missing point rather than
/// quietly rendering three of four.
export function WarningBlock({
  warning,
  acknowledgement,
  onToggle,
  idPrefix,
}: {
  warning: AgentBackupWarning;
  acknowledgement: AgentBackupAcknowledgement;
  onToggle: (next: AgentBackupAcknowledgement) => void;
  idPrefix: string;
}) {
  return (
    <div className="agent-warning-block">
      <p className="agent-warning-headline">{warning.headline}</p>
      <ul className="agent-warning-list">
        {warningPoints(warning).map((point) => (
          <li key={point.key}>
            <label htmlFor={`${idPrefix}-${point.key}`}>
              <input
                id={`${idPrefix}-${point.key}`}
                type="checkbox"
                checked={acknowledgement[point.key]}
                onChange={(event) =>
                  onToggle(
                    toggleAcknowledgement(
                      acknowledgement,
                      point.key,
                      event.target.checked,
                    ),
                  )
                }
              />
              <span>{point.text}</span>
            </label>
          </li>
        ))}
      </ul>
      {outstandingPoints(warning, acknowledgement).length > 0 && (
        <p className="agent-warning-outstanding">
          Still to read and accept:{" "}
          {outstandingPoints(warning, acknowledgement).length} of{" "}
          {warningPoints(warning).length}.
        </p>
      )}
    </div>
  );
}

export function AgentBackupPanel({ walletId, busy, run, onInfo }: Props) {
  const [warnings, setWarnings] = useState<AgentBackupWarnings | null>(null);
  const [backupAck, setBackupAck] = useState<AgentBackupAcknowledgement>(
    EMPTY_ACKNOWLEDGEMENT,
  );
  const [restoreAck, setRestoreAck] = useState<AgentBackupAcknowledgement>(
    EMPTY_ACKNOWLEDGEMENT,
  );
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [document, setDocument] = useState("");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [preview, setPreview] = useState<AgentBackupPreview | null>(null);
  const [outcome, setOutcome] = useState<AgentRestoreOutcome | null>(null);

  useEffect(() => {
    let cancelled = false;
    void agentWalletApi
      .backupWarnings()
      .then((next) => {
        if (!cancelled) setWarnings(next);
      })
      .catch(() => {
        if (!cancelled) setWarnings(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function createBackup() {
    // No warning on screen, no backup. The screen that has not loaded it renders
    // nothing but that fact.
    if (!walletId || !warnings) return;
    // The seal is what the API accepts, and it is checked against the warning
    // that is on screen rather than against a list kept here. A missing point
    // throws instead of being skipped.
    const result = await agentWalletApi.backupCreate(
      walletId,
      backupPassphrase,
      sealAcknowledgement(warnings.backup, backupAck),
    );
    setCreated(result.document);
    setBackupPassphrase("");
    setBackupAck(EMPTY_ACKNOWLEDGEMENT);
    onInfo(
      "Backup created. It was not saved anywhere: copy it out yourself, and keep it away from its passphrase.",
    );
  }

  async function loadPreview() {
    if (!document.trim()) return;
    setPreview(await agentWalletApi.backupPreview(document.trim()));
    setOutcome(null);
  }

  async function restore() {
    if (!document.trim() || !warnings) return;
    const result = await agentWalletApi.backupRestore(
      document.trim(),
      restorePassphrase,
      sealAcknowledgement(warnings.restore, restoreAck),
    );
    setOutcome(result);
    setRestorePassphrase("");
    setDocument("");
    setPreview(null);
    setRestoreAck(EMPTY_ACKNOWLEDGEMENT);
    onInfo("Wallet restored. Read what it says you still have to do.");
  }

  if (!warnings) {
    return (
      <section className="agent-panel" aria-label="Agent Wallet backup">
        <h2>Backup and restore</h2>
        <p>Loading the backup warning. Nothing can be backed up or restored until it is on screen.</p>
      </section>
    );
  }

  return (
    <section className="agent-panel" aria-label="Agent Wallet backup">
      <span className="agent-eyebrow">Read first</span>
      <h2>Backup and restore</h2>
      <p>
        This backup saves the record of what your agents have spent, not only your
        keys. Restoring it puts that record back, which is why every line below
        has to be read.
      </p>

      <h3>Create a backup</h3>
      <WarningBlock
        warning={warnings.backup}
        acknowledgement={backupAck}
        onToggle={setBackupAck}
        idPrefix="agent-backup"
      />
      <label htmlFor="agent-backup-passphrase">Agent Wallet passphrase</label>
      <input
        id="agent-backup-passphrase"
        type="password"
        autoComplete="off"
        value={backupPassphrase}
        onChange={(event) => setBackupPassphrase(event.target.value)}
      />
      <button
        type="button"
        disabled={
          busy ||
          !walletId ||
          backupPassphrase.length === 0 ||
          !warningGatePasses(warnings.backup, backupAck)
        }
        onClick={() => void run(createBackup)}
      >
        Create backup
      </button>
      {created && (
        <div className="agent-card-list">
          <strong>Your backup</strong>
          <p>
            Copy this out and store it as you would store cash. It is a working
            wallet: whoever has it and the passphrase can spend from this wallet
            at the same time as you.
          </p>
          <textarea readOnly rows={6} value={created} aria-label="Backup document" />
        </div>
      )}

      <h3>Restore a backup</h3>
      <label htmlFor="agent-restore-document">Backup document</label>
      <textarea
        id="agent-restore-document"
        rows={6}
        value={document}
        onChange={(event) => setDocument(event.target.value)}
      />
      <button
        type="button"
        disabled={busy || document.trim().length === 0}
        onClick={() => void run(loadPreview)}
      >
        Check this backup
      </button>
      {preview && (
        <div className="agent-card-list">
          <div>
            <strong>Wallet</strong>
            <span>{preview.address}</span>
          </div>
          <div>
            <strong>Record position</strong>
            <span>
              journal {preview.journal_sequence} &middot; taken at{" "}
              {new Date(preview.backed_up_at_unix * 1000).toISOString()}
            </span>
          </div>
          {preview.already_present && (
            <p className="agent-warning-outstanding">
              This wallet is already on this computer, and a restore will be
              refused. A restore never overwrites a live wallet, because that
              would destroy the only record of what it has spent.
            </p>
          )}
        </div>
      )}
      <WarningBlock
        warning={warnings.restore}
        acknowledgement={restoreAck}
        onToggle={setRestoreAck}
        idPrefix="agent-restore"
      />
      <label htmlFor="agent-restore-passphrase">Backup passphrase</label>
      <input
        id="agent-restore-passphrase"
        type="password"
        autoComplete="off"
        value={restorePassphrase}
        onChange={(event) => setRestorePassphrase(event.target.value)}
      />
      <button
        type="button"
        disabled={
          busy ||
          document.trim().length === 0 ||
          restorePassphrase.length === 0 ||
          !warningGatePasses(warnings.restore, restoreAck)
        }
        onClick={() => void run(restore)}
      >
        Restore this wallet
      </button>
      {outcome && (
        <div className="agent-card-list">
          <strong>Restored. What you still have to do</strong>
          <ul>
            {restoreFollowUp(outcome).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
