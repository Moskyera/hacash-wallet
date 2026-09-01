import type { ChatMessage } from "./api";

/**
 * How late a message has to be before the screen says so.
 *
 * Clocks disagree by seconds and messages take seconds to arrive, so a small
 * gap is nothing. Ten minutes is not nothing.
 */
export const LATE_ARRIVAL_MS = 10 * 60 * 1000;

/** `2026-08-23 02:19 UTC`, which is a date and not just a clock face. */
export function utcStamp(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/**
 * The marker on a message that arrived long after it says it was written.
 *
 * A relay decides when it hands an envelope over, and the time on the envelope
 * is the sender's own signed claim, which the relay cannot change and does not
 * have to respect. Held mail therefore used to arrive looking ordinary: the
 * bubble showed a clock time with no date, and nothing anywhere said the
 * message had been sitting on somebody else's machine. The wallet now keeps its
 * own arrival time (`received_utc`) and this is where the difference is said out
 * loud. Returns null when there is nothing worth saying, including for outgoing
 * messages and for records written before the wallet kept an arrival time.
 */
export function arrivalNote(
  msg: Pick<ChatMessage, "direction" | "timestamp_utc" | "received_utc">,
): string | null {
  if (msg.direction !== "in") return null;
  const received = msg.received_utc;
  if (!received) return null;
  const sent = Date.parse(msg.timestamp_utc);
  const got = Date.parse(received);
  if (!Number.isFinite(sent) || !Number.isFinite(got)) return null;
  if (got - sent < LATE_ARRIVAL_MS) return null;
  return `held, arrived ${utcStamp(received)}`;
}
