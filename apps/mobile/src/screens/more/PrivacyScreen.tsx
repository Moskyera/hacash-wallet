import type { PrivacySettings } from "../../api";

type Props = {
  privacy: PrivacySettings;
  onPersistPrivacy: (patch: Partial<PrivacySettings>) => void;
};

export default function PrivacyScreen({ privacy, onPersistPrivacy }: Props) {
  return (
    <div className="card">
      <h2>Privacy</h2>
      <div className="toggle-row">
        <span>Hide balances</span>
        <input
          type="checkbox"
          checked={privacy.hide_balances}
          onChange={(e) => void onPersistPrivacy({ hide_balances: e.target.checked })}
        />
      </div>
      <div className="toggle-row">
        <span>Hide addresses</span>
        <input
          type="checkbox"
          checked={privacy.hide_addresses}
          onChange={(e) => void onPersistPrivacy({ hide_addresses: e.target.checked })}
        />
      </div>
      <div className="toggle-row">
        <span>Screen privacy shield</span>
        <input
          type="checkbox"
          checked={privacy.screen_privacy}
          onChange={(e) => void onPersistPrivacy({ screen_privacy: e.target.checked })}
        />
      </div>
      <div className="toggle-row">
        <span>Store tx history</span>
        <input
          type="checkbox"
          checked={privacy.store_tx_history}
          onChange={(e) => void onPersistPrivacy({ store_tx_history: e.target.checked })}
        />
      </div>
      <div className="toggle-row">
        <span>Pause auto-lock on HACD</span>
        <input
          type="checkbox"
          checked={privacy.pause_auto_lock_dapp ?? true}
          onChange={(e) => void onPersistPrivacy({ pause_auto_lock_dapp: e.target.checked })}
        />
      </div>
      <label className="label">Clipboard clear (seconds)</label>
      <input
        type="number"
        min={0}
        max={300}
        value={privacy.clipboard_clear_secs}
        onChange={(e) => void onPersistPrivacy({ clipboard_clear_secs: Number(e.target.value) || 0 })}
      />
    </div>
  );
}