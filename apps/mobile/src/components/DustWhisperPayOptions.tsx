import type { DustWhisperSettings } from "../api";
import { hasWhisperRelays } from "../dustWhisper";

type Props = {
  dustWhisper: DustWhisperSettings;
  onPersist: (patch: Partial<DustWhisperSettings>) => void | Promise<void>;
  disabled?: boolean;
  /** When paying HAC, Fast Pay may skip whisper — show that in the note. */
  showFastPayNote?: boolean;
};

export default function DustWhisperPayOptions({
  dustWhisper,
  onPersist,
  disabled,
  showFastPayNote,
}: Props) {
  const relaysConfigured = hasWhisperRelays(dustWhisper);

  return (
    <>
      <p className="label" style={{ marginTop: "0.5rem" }}>
        Private broadcast
      </p>
      <label className="check-row">
        <input
          type="checkbox"
          checked={dustWhisper.enabled}
          disabled={disabled || (!relaysConfigured && !dustWhisper.enabled)}
          onChange={(e) => void onPersist({ enabled: e.target.checked })}
        />
        DUST Whisper (encrypted relay)
      </label>
      {dustWhisper.enabled ? (
        <label className="check-row">
          <input
            type="checkbox"
            checked={dustWhisper.fallback_direct}
            disabled={disabled}
            onChange={(e) => void onPersist({ fallback_direct: e.target.checked })}
          />
          Fall back to direct node if relay fails
        </label>
      ) : null}
      <p className="muted small">
        {showFastPayNote
          ? "On-chain (L1) sends only — Fast Pay is unchanged."
          : "On-chain broadcast via relay; the node does not see your IP."}
        {!relaysConfigured ? (
          <>
            {" "}
            Add relay URLs in <strong>More → DUST Whisper</strong> before enabling.
          </>
        ) : null}
      </p>
    </>
  );
}