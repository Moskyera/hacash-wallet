import type { ChatMessage } from "./api";

/**
 * What the wallet actually knows after `messenger_send` returns.
 *
 * The command returns Ok whenever the message was written to local history,
 * whether or not a relay took it (crates/wallet-core/src/messenger.rs, the
 * `relay_ok` flag is stored as `delivered` and the function returns Ok either
 * way). So a call that did not throw is NOT evidence that anything left the
 * device. The only evidence is the `delivered` flag on the message the command
 * hands back, and these helpers are the single place that reads it.
 *
 * Nothing here may claim the recipient received the message: an accepted
 * envelope means one relay took custody of it, no more.
 */

export type SendReceipt = {
  text: string;
  kind: "success" | "info" | "error";
};

/** The relay accepted the envelope. Storage said yes; the recipient is unknown. */
export const SENT_TEXT = "Sent to the relay.";

/**
 * No relay accepted it. The message is in local history and nothing re-sends
 * it, so the person has to send it again themselves. Do not call this state
 * "queued" or "pending" - there is no retry anywhere in the codebase.
 */
export const NOT_SENT_TEXT =
  "Not sent. No relay accepted this message. It is saved on this device only, so send it again once a relay is reachable.";

/**
 * Turn the message the send command returned into what the toast may say.
 *
 * Only `delivered === true` earns the success line. A missing record, or a
 * record without the flag, is not evidence of anything and is reported as not
 * sent: the wrong answer in that direction costs a needless re-send, the wrong
 * answer in the other direction is a message the person believes they sent.
 */
export function sendReceipt(
  msg: Pick<ChatMessage, "delivered"> | null | undefined,
): SendReceipt {
  return msg?.delivered === true
    ? { text: SENT_TEXT, kind: "success" }
    : { text: NOT_SENT_TEXT, kind: "error" };
}

export type DeliveryLabel = {
  text: string;
  delivered: boolean;
};

/**
 * The per-message status line under an outgoing bubble.
 *
 * Incoming messages get none: on that direction `delivered` is reused as the
 * read flag by MessengerStore::mark_read, so it says nothing about transport.
 */
export function deliveryLabel(
  msg: Pick<ChatMessage, "direction" | "delivered">,
): DeliveryLabel | null {
  if (msg.direction !== "out") return null;
  return msg.delivered
    ? { text: "Sent to relay", delivered: true }
    : { text: "Not sent", delivered: false };
}
