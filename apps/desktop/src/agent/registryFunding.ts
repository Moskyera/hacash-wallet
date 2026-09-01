/**
 * What the desktop says between opening a provider channel and having one.
 *
 * `registryOpen.ts` covers the press that costs nothing: the wallet left-signs
 * a receipt returning the whole deposit, the provider countersigns it, and this
 * wallet verifies and stores it. That press ends with an owner holding a full
 * refund for a channel that contains no money. This file covers the two presses
 * that follow, and the first of them is the only press in this app that
 * deliberately makes an owner's money irreversible.
 *
 * Five rules shape every line.
 *
 * FIRST, it names the exact amount before the press, and says plainly that the
 * transfer cannot be undone by this app, by the provider or by anyone else.
 *
 * SECOND, it names the fee separately and never folds it into the deposit. A
 * registry call is a contract call and the chain takes the whole gas budget out
 * of the main balance before the call runs, so the number an owner must be able
 * to hold is larger than the network fee alone.
 *
 * THIRD, it says the refund is already held. Not "will be", not "your provider
 * guarantees it": the countersigned bill exists, this wallet checked the
 * signature itself, it does not expire, and it has been held since the moment
 * the channel was opened. That is the fact that makes the deposit safe and it
 * has to be readable in the same breath as the amount.
 *
 * FOURTH, it resumes rather than starting over. A funding transaction that has
 * been signed and handed to the network survives this app closing, and the
 * wallet will never sign a second transfer into one channel: pressing again
 * hands the same bytes over and asks the chain what became of them. An owner
 * returning to a half-finished channel is the ordinary case, so the screen
 * speaks about carrying on and not about beginning.
 *
 * FIFTH, it never claims a capability the phone has. A paired phone holds an
 * approval identity, not a Hacash spending key, so it can never sign the
 * transfer that locks this deposit up.
 *
 * Copy, formatting and one stage derivation. No gate, no validation, no call.
 */
import { DESKTOP_CONTROLS } from "./desktopControls";
import { OPEN_PHONE_CANNOT } from "./registryOpen";
import type { AgentHvmRegistryChannelInProgress } from "./registryOpen";

/** What one press of the funding control actually did. */
export type AgentHvmRegistryFundingResult = {
  schema: string;
  /** The transaction this wallet signed, whether or not it is in a block. */
  transaction_hash: string;
  contract_address: string;
  /** What was locked up, read out of the countersigned bill. */
  deposit_zhu: number;
  /** What the network charged, from the main balance and not the deposit. */
  network_fee_zhu: number;
  /** True only once this wallet has seen the transfer in a block. */
  confirmed: boolean;
  confirmed_block_height: number | null;
};

/** What one press of the finishing control actually did. */
export type AgentHvmRegistryAdoptionResult = {
  schema: string;
  binding_commitment: string;
  hub_address: string;
  hub_url: string;
  /** True from the moment the binding is written, never before. */
  exit_available: boolean;
};

/**
 * This desktop's own note of a channel it opened and has not finished.
 *
 * It is written from the backend's own answers and it decides nothing. Every
 * press it offers is re-derived inside the wallet from the sealed record: a
 * note that is stale, copied from another machine, or simply wrong buys nobody
 * anything, because a wallet holding no countersigned refund refuses to fund
 * and says so in its own words. What the note buys is that an owner who closed
 * the laptop between the two presses is offered the second one instead of an
 * empty form that pretends the first never happened.
 */
export type RegistryChannelNote = {
  schema: "hpay-desktop-registry-channel-note/1";
  /** Which Agent Wallet this note belongs to. */
  wallet_id: string;
  hub_url: string;
  binding_commitment: string;
  contract_address: string;
  /** What the channel locks up, from the countersigned bill. */
  deposit_zhu: number;
  /** What that bill returns. Equal to the deposit on every channel this opens. */
  refunded_zhu: number;
  /** Everything the funding transaction can take on top of the deposit. */
  required_l1_fee_zhu: number;
  /** Set once a funding transaction exists, whether or not it is in a block. */
  funding_transaction_hash: string | null;
  /** True once this desktop has seen that transfer in a block. */
  funding_confirmed: boolean;
  /** What the network actually charged, once there is a transaction. */
  network_fee_zhu: number | null;
};

/**
 * Where a channel this desktop opened has got to.
 *
 * `refund_held`  the receipt is saved and no deposit has been sent.
 * `funding_sent` a transfer exists and this desktop has not seen it in a block.
 * `funded`       the transfer is in a block and the channel is not adopted yet.
 */
export type RegistryChannelStage = "refund_held" | "funding_sent" | "funded";

export function registryChannelStage(note: RegistryChannelNote): RegistryChannelStage {
  if (!note.funding_transaction_hash) return "refund_held";
  return note.funding_confirmed ? "funded" : "funding_sent";
}

/** The key this desktop's note is stored under, versioned with its schema. */
export const REGISTRY_CHANNEL_NOTE_KEY = "hpay.registry-channel-note.v1";

type NoteStore = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
};

/**
 * The note for one wallet, or null.
 *
 * Anything unreadable, anything of another schema and anything belonging to a
 * different wallet reads as no note at all, because the only thing a bad note
 * could do is offer a press the wallet is going to refuse anyway.
 */
export function readChannelNote(
  store: NoteStore,
  walletId: string,
): RegistryChannelNote | null {
  let parsed: unknown;
  try {
    const raw = store.getItem(REGISTRY_CHANNEL_NOTE_KEY);
    if (!raw) return null;
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const note = parsed as Partial<RegistryChannelNote>;
  if (note.schema !== "hpay-desktop-registry-channel-note/1") return null;
  if (note.wallet_id !== walletId) return null;
  if (typeof note.deposit_zhu !== "number" || typeof note.refunded_zhu !== "number") {
    return null;
  }
  return note as RegistryChannelNote;
}

/**
 * The wallet's own record of an unfinished channel, in the shape this panel
 * renders. `null` when the wallet has no unfinished channel to show.
 *
 * # Why this exists
 *
 * The panel used to be built from a note in `window.localStorage` and from
 * nothing else. That note is one key for every Agent Wallet on the machine, it
 * does not follow a wallet restored somewhere else, and clearing browser data
 * removes it. Losing it stranded money: with the note gone and the provider
 * gone, the only control left on the screen was the open form, and the open
 * form asks the provider before anything else and answers "no channel was
 * opened. Nothing was funded and nothing was spent" over a deposit already in
 * a block.
 *
 * The wallet is now asked instead, and it answers from its own sealed record.
 * The note is kept only as a fallback for the moments before a status read
 * returns, and it is no longer the only thing that knows.
 *
 * `hub_url` is carried in rather than read from the record because the panel
 * shows the provider an owner is looking at; nothing here decides where a
 * press goes. Both presses re-derive that from the wallet's sealed record,
 * which is also why a wrong `hub_url` here cannot send money anywhere.
 */
export function channelNoteFromWallet(
  walletId: string,
  hubUrl: string,
  inProgress: AgentHvmRegistryChannelInProgress | null | undefined,
  requiredL1FeeZhu: number,
): RegistryChannelNote | null {
  // No record, or a record with no countersigned refund, is nothing to finish:
  // until that refund is held the wallet refuses to fund at all, so there is
  // no deposit to recover and the open form is the right screen.
  if (!inProgress || !inProgress.refund_held) return null;
  if (typeof inProgress.deposit_zhu !== "number") return null;
  return {
    schema: "hpay-desktop-registry-channel-note/1",
    wallet_id: walletId,
    hub_url: hubUrl,
    // The panel shows these two only when it has them from a press. The
    // wallet's record is authoritative about money and about nothing else, and
    // inventing an identifier here would put a number on screen that no
    // signature stands behind.
    binding_commitment: "",
    contract_address: "",
    deposit_zhu: inProgress.deposit_zhu,
    // Every channel this flow opens is refunded in full, and the wallet
    // refuses to fund one that is not.
    refunded_zhu: inProgress.deposit_zhu,
    required_l1_fee_zhu: requiredL1FeeZhu,
    funding_transaction_hash: inProgress.funding_transaction_hash,
    funding_confirmed: inProgress.funding_confirmed,
    network_fee_zhu: inProgress.network_fee_zhu,
  };
}

/**
 * The channel the finishing panel should show: the wallet's record for
 * anything about money, this desktop's note for the two identifiers the wallet
 * does not report.
 *
 * Preferring the wallet outright would blank the channel contract and the
 * binding commitment on the ordinary path, where a note exists and is
 * perfectly good for the parts nothing is spent on. Preferring the note
 * outright is what stranded deposits. So neither wins the whole object: the
 * wallet decides the deposit, the transaction and whether it is in a block,
 * and the note is allowed to fill in labels and nothing else.
 */
export function mergeResumableChannel(
  fromWallet: RegistryChannelNote | null,
  fromNote: RegistryChannelNote | null,
): RegistryChannelNote | null {
  if (!fromWallet) return fromNote;
  if (!fromNote) return fromWallet;
  return {
    ...fromWallet,
    // Display only. Both are empty in the wallet's answer because no signature
    // in that record stands behind them as text, and showing a blank row where
    // this desktop still holds the real value helps nobody.
    hub_url: fromWallet.hub_url || fromNote.hub_url,
    binding_commitment: fromNote.binding_commitment,
    contract_address: fromNote.contract_address,
  };
}

export function writeChannelNote(store: NoteStore, note: RegistryChannelNote): void {
  try {
    store.setItem(REGISTRY_CHANNEL_NOTE_KEY, JSON.stringify(note));
  } catch {
    // A desktop that cannot keep the note still funds and still finishes; it
    // just cannot offer the resume. Nothing here is allowed to take the panel
    // down over a storage quota.
  }
}

export function clearChannelNote(store: NoteStore): void {
  try {
    store.removeItem(REGISTRY_CHANNEL_NOTE_KEY);
  } catch {
    // Same reasoning as above.
  }
}

export type RegistryFundingView = {
  heading: string;
  stage: RegistryChannelStage;
  /** What this note is, and that it decides nothing. */
  noteLine: string;
  /** The full refund, already held, and who checked it. */
  refundHeldLine: string;
  /** The exact amount this press locks up, and that it cannot be recalled. */
  lockUpLine: string;
  /** Fee and reserved gas, from the main balance, on top of the deposit. */
  feeLine: string;
  /** What a failure of this press leaves behind. */
  refusalLine: string;
  /**
   * What has already happened to this channel's deposit, or "" before there is
   * anything to resume.
   */
  resumeLine: string;
  /** What finishing does, and that the provider is not asked. */
  finishLine: string;
  /** What a paired phone can and cannot do here. */
  phoneLine: string;
  /**
   * True while the offered control is the one that spends money.
   *
   * Which label that control carries is decided in the view, from `stage`,
   * the same way the exit decides between starting and carrying on. The label
   * strings themselves stay in `desktopControls.ts` and are read from there,
   * so a control this file describes cannot drift from the one a person sees.
   */
  actionSpendsMoney: boolean;
};

/**
 * The section that stands between a saved receipt and a usable channel.
 *
 * `formatZhu` renders an exact zhu amount; the caller owns that conversion so
 * this module never carries a second copy of the unit rules.
 */
export function registryFundingView(
  note: RegistryChannelNote,
  formatZhu: (zhu: string) => string,
): RegistryFundingView {
  const stage = registryChannelStage(note);
  const deposit = formatZhu(String(note.deposit_zhu));
  const refunded = formatZhu(String(note.refunded_zhu));
  const fee = formatZhu(String(note.required_l1_fee_zhu));
  const charged =
    note.network_fee_zhu === null ? "" : formatZhu(String(note.network_fee_zhu));
  return {
    heading:
      stage === "funded"
        ? "Finishing the channel you have already funded"
        : "Finishing the channel you have already opened",
    stage,
    noteLine:
      "This is this desktop's own note of a channel it opened for you and has not finished. It decides " +
      "nothing on its own: every press below is worked out again inside this wallet from its own sealed " +
      "record, and a press this wallet cannot back is refused in its own words rather than performed.",
    refundHeldLine:
      `Your provider has already signed a receipt returning all ${refunded} of this deposit to you, and this ` +
      "wallet checked that signature itself before saving it. You have held that full refund from the moment " +
      "this channel was opened, it never expires, and it is what lets you close the channel and be paid " +
      "without your provider's permission. Nothing below can be reached without it.",
    lockUpLine:
      `Sending the deposit moves ${deposit} out of your main balance and into the channel contract. That is ` +
      "an ordinary transfer on the chain: it is not a hold, it cannot be cancelled once it is in a block, and " +
      "neither this app nor your provider can reverse it. It stays in the contract until the channel is closed.",
    feeLine:
      `Sending it costs up to ${fee} from your main balance on top of the deposit: the network fee, plus gas ` +
      "that the chain holds while the contract runs and gives most of back afterwards. That cost is spent " +
      "once the transaction is sent, whatever happens to the channel afterwards.",
    refusalLine:
      "If this wallet cannot send the deposit, it says why and nothing is locked up. A transfer that is never " +
      "built costs nothing at all, and a transfer this wallet has already built is never built a second time.",
    resumeLine: resumeLine(note, stage, charged),
    finishLine:
      `Finishing does not ask your provider anything. This wallet reads the funded channel from your own ` +
      `fullnode and writes its own record of it, and that record is what makes "` +
      `${DESKTOP_CONTROLS.start_exit_without_provider}" work. A provider that disappears between the deposit ` +
      "and this press cannot stop you finishing, and cannot keep the money.",
    phoneLine: OPEN_PHONE_CANNOT,
    actionSpendsMoney: stage !== "funded",
  };
}

function resumeLine(
  note: RegistryChannelNote,
  stage: RegistryChannelStage,
  charged: string,
): string {
  if (stage === "refund_held") return "";
  const hash = note.funding_transaction_hash ?? "";
  if (stage === "funding_sent") {
    return (
      "This deposit has already been signed and handed to the network, and this desktop has not yet seen it " +
      `in a block. The transaction is ${hash}. Pressing again does not sign a second transfer: it hands the ` +
      "same bytes over again and asks the chain what became of them, so nothing here can charge you twice."
    );
  }
  return (
    `This deposit is in a block. The transaction is ${hash}` +
    (charged ? `, and the network charged ${charged} for it from your main balance` : "") +
    ". Nothing further is spent by the press below: it writes this wallet's own record of the funded channel " +
    "and sends no transaction."
  );
}

/**
 * The one sentence to show after a funding press, built from what it returned.
 *
 * A deposit that has been signed and sent but not yet seen in a block is not
 * the same thing as a funded channel, and printing one fixed sentence over both
 * is the failure the exit screen already had once: it sends an owner looking
 * for a channel balance that is not there and hides the step they still have to
 * take.
 */
export function fundPressResultLine(
  result: AgentHvmRegistryFundingResult,
  formatZhu: (zhu: string) => string,
): string {
  const deposit = formatZhu(String(result.deposit_zhu));
  const fee = formatZhu(String(result.network_fee_zhu));
  if (!result.confirmed) {
    return (
      `Your ${deposit} deposit has been signed and sent to the network, and this wallet has not yet seen it ` +
      `in a block. The transaction is ${result.transaction_hash}. Nothing else happens until it confirms, and ` +
      "pressing again hands the same transaction over rather than signing a second one. Your refund receipt " +
      "is unchanged and still covers the whole deposit."
    );
  }
  return (
    `Your ${deposit} deposit is in the channel contract and this wallet has seen it in a block at height ` +
    `${result.confirmed_block_height ?? 0}. The network charged ${fee} from your main balance for sending it. ` +
    `The channel is not finished yet: "${DESKTOP_CONTROLS.finish_opening_channel}" writes this wallet's own ` +
    "record of it, which is what lets you close it and be paid without your provider."
  );
}

/** The one sentence to show after a finishing press. */
export function adoptPressResultLine(result: AgentHvmRegistryAdoptionResult): string {
  if (!result.exit_available) {
    return (
      "This wallet did not finish opening the channel, so it still has no record of it and nothing on this " +
      "page can close it yet. No money moved and nothing was sent to the network."
    );
  }
  return (
    "This channel is open and this wallet holds its own record of it. Your provider was not asked and cannot " +
    `undo it. "${DESKTOP_CONTROLS.start_exit_without_provider}" now works on this page, and it needs nothing ` +
    "from your provider to pay you."
  );
}
