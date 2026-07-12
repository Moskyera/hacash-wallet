import { useEffect, useState } from "react";
import { WalletSettings } from "../api";
import AppUpdateSection from "../components/AppUpdateSection";

type Props = {
  settings: WalletSettings | null;
  busy: boolean;
  onSave: (nodeUrl: string) => void;
  onInfo: (msg: string) => void;
  onError: (msg: string) => void;
};

export default function SettingsScreen({ settings, busy, onSave, onInfo, onError }: Props) {
  const [nodeUrl, setNodeUrl] = useState("");

  useEffect(() => {
    if (settings?.node_url) setNodeUrl(settings.node_url);
  }, [settings?.node_url]);

  return (
    <section className="panel">
      <h2>Settings</h2>

      <AppUpdateSection onInfo={onInfo} onError={onError} />

      <hr className="divider" />

      <h3>Node</h3>
      <label>Node API URL</label>
      <input
        value={nodeUrl}
        onChange={(e) => setNodeUrl(e.target.value)}
        placeholder="https://node.example.com"
      />
      <button disabled={busy} onClick={() => onSave(nodeUrl)}>
        Save node URL
      </button>
    </section>
  );
}