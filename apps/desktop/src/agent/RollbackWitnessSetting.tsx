import { useState } from "react";
import { AGENT_ROLLBACK_WITNESS_TRADE } from "@hacash/wallet-ui";
import { agentWalletApi, type AgentWalletOverview } from "./api";

/**
 * THE SCREEN WHERE THE ROLLBACK WITNESS SETTING LIVES.
 *
 * It carries the trade in plain words, because a control that changes what a
 * wallet checks before it spends should not be a bare switch with a label. The
 * sentence shown is `AGENT_ROLLBACK_WITNESS_TRADE`, the same two facts the Rust
 * doc comment beside the setting states, so the code and the screen cannot tell
 * a person two different stories.
 *
 * IT DOES NOT OVERSELL EITHER SIDE. Turning the witness on does not make an
 * agent safer to run unattended, and turning it off does not make a wallet
 * insecure. Every payment needs the passphrase and a press in this window
 * either way. What the setting decides is whether this wallet can notice that
 * the computer under it was restored from an older backup, with its spending
 * counters, its revocations and its policy silently rolled back.
 *
 * WHY THE PASSPHRASE FIELD IS HERE. The command behind it is guarded twice, and
 * this is the second guard. `require_wallet_shell` already limits the command to
 * this window, and `set_rollback_witness_requirement` then re-verifies the
 * passphrase against the vault, so a person who walks up to an unlocked screen
 * cannot turn the check off.
 */
export default function RollbackWitnessSetting({
  overview,
  busy,
  run,
  onInfo,
}: {
  overview: AgentWalletOverview;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const required = overview.rollback_witness_required;
  const target = !required;
  // Anchors are minted on the pilot rail only - `pending_rollback_anchor`
  // refuses every other network, and `set_rollback_witness_requirement` refuses
  // to switch this ON there. Rendering the button anyway offered a control that
  // could only ever fail, and failed with payment-flavoured text about giving up
  // a protection this network never had. Say what is true instead.
  if (overview.network_mode === "mainnet") {
    return (
      <section className="agent-panel" aria-label="Rollback witness">
        <h2>Rollback witness</h2>
        <p className="agent-note">
          Payments complete on this computer. Each one needs your wallet
          passphrase and a press in this window, and none is ever made without
          both. No phone is involved and none is needed.
        </p>
        <p className="agent-note">
          There is nothing to switch on here. The rollback witness adds one
          extra countersignature from a second device, and this wallet does not
          use it.
        </p>
      </section>
    );
  }
  return (
    <section className="agent-panel" aria-label="Rollback witness">
      <h2>Rollback witness</h2>
      <dl className="agent-detail-grid">
        <div>
          <dt>Status</dt>
          <dd>{required ? "On for this wallet" : "Off"}</dd>
        </div>
        <div>
          <dt>Paired phone</dt>
          <dd>
            {overview.mobile_witness_ready
              ? "Paired"
              : required
                ? "Needed before the next payment"
                : "None, and none needed"}
          </dd>
        </div>
      </dl>
      <p className="agent-note">{AGENT_ROLLBACK_WITNESS_TRADE}</p>
      <label className="agent-field">
        <span>Wallet passphrase</span>
        <input
          type="password"
          value={passphrase}
          autoComplete="current-password"
          onChange={(event) => setPassphrase(event.target.value)}
        />
      </label>
      <button
        type="button"
        disabled={busy || passphrase.length === 0}
        onClick={() =>
          run(async () => {
            await agentWalletApi.setRollbackWitnessRequirement(
              overview.wallet_id,
              target,
              passphrase,
            );
            setPassphrase("");
            onInfo(
              target
                ? "Rollback witness is on. Pair a phone before the next payment."
                : "Rollback witness is off. Payments complete on this computer.",
            );
          })
        }
      >
        {target ? "Turn the rollback witness on" : "Turn the rollback witness off"}
      </button>
      {/* Said before the button is pressed rather than surfaced as an error
          after it. The Rust side refuses a change while any payment is still
          in flight, because a payment is pinned to the answer that was current
          when it was created and the two must not disagree. */}
      <p className="agent-note">
        This can only be changed when no payment is in progress and no witness
        rotation is running. A payment already under way keeps the answer it
        started with.
      </p>
    </section>
  );
}
