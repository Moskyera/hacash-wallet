import type { MessengerPollOutcome } from "./api";

export type PollReport = { text: string; kind: "success" | "info" | "error" };

/**
 * What the person is told after "Check inbox now".
 *
 * The screen used to be handed a single number and said "the relay had nothing
 * new" whenever it was zero. Zero is also what an unreachable relay, a relay
 * that refused the inbox claim, and a wallet with no relay configured all
 * produce, so somebody whose relay had been down for a week was told their
 * mailbox was empty. `messenger_poll_inbox` now reports what it actually
 * reached (crates/wallet-core/src/messenger.rs, MessengerPollOutcome) and this
 * says only what those counts support.
 *
 * The order below is deliberate: the failures are reported before the count,
 * because a poll that reached nothing has nothing to say about the count.
 */
export function pollReport(outcome: MessengerPollOutcome | null | undefined): PollReport {
  const o = outcome ?? null;
  if (!o || o.relays_tried === 0) {
    return {
      text: "No relay is configured, so there was nothing to check. Somebody has to run a relay. Set one on the DUST Whisper screen, or run your own with docs/RUNNING-A-RELAY.md.",
      kind: "error",
    };
  }
  if (o.relays_answered === 0 && o.relays_refused > 0) {
    return {
      text: "The relay refused to hand over your inbox. That is a refusal, not a report on what is waiting in it.",
      kind: "error",
    };
  }
  if (o.relays_answered === 0) {
    return {
      text: "No relay answered, so nothing could be checked. Messages may be waiting.",
      kind: "error",
    };
  }
  const notes: string[] = [];
  if (o.rejected_envelopes > 0) {
    notes.push(
      `${o.rejected_envelopes} item(s) were discarded because nobody could be shown to have sent them, or because they were addressed to somebody else.`,
    );
  }
  if (o.undecryptable > 0) {
    // Saying nothing about these is what let an inbox be wedged shut in
    // silence: hundreds of correctly signed envelopes of noise sat at the
    // relay's per-recipient cap, every correspondent was refused with "inbox
    // full", and the owner's own screen said the mailbox was empty.
    notes.push(
      `${o.undecryptable} item(s) were signed by a real key but could not be read by this wallet, so they were cleared off the relay. Somebody may be filling your mailbox.`,
    );
  }
  if (o.store_full) {
    notes.push(
      "This wallet's message store is full, so anything else is still waiting on the relay.",
    );
  }
  const trailer = notes.length > 0 ? ` ${notes.join(" ")}` : "";
  if (o.added > 0) {
    return { text: `${o.added} new message(s).${trailer}`, kind: "success" };
  }
  if (notes.length > 0) {
    return { text: `The relay answered. Nothing new.${trailer}`, kind: "error" };
  }
  return { text: "The relay answered. Nothing new.", kind: "info" };
}
