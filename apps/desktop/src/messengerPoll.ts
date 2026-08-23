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
      text: "No relay is configured, so there was nothing to check. Somebody has to run a relay. Set one on the Privacy screen, or run your own with docs/RUNNING-A-RELAY.md.",
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
  const rejected =
    o.rejected_envelopes > 0
      ? ` ${o.rejected_envelopes} item(s) were discarded because nobody could be shown to have sent them.`
      : "";
  if (o.added > 0) {
    return { text: `${o.added} new message(s).${rejected}`, kind: "success" };
  }
  return { text: `The relay answered. Nothing new.${rejected}`, kind: "info" };
}
