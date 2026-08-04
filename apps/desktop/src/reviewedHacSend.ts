import type {
  ReviewedSendExpectation,
  SendOptions,
  SendPreview,
} from "./api";

export type ReviewedHacSend = Readonly<{
  to: string;
  amountMei: number;
  options: Readonly<SendOptions>;
  expectation: Readonly<ReviewedSendExpectation>;
}>;

/**
 * Copy the exact wallet-core preview into a detached, immutable execution request.
 * Confirmation must never read recipient, amount or rail preferences from the live form.
 */
export function bindReviewedHacSend(preview: SendPreview): ReviewedHacSend {
  const options = Object.freeze({ ...preview.send_options });
  const expectation = Object.freeze({
    from: preview.from,
    to: preview.to,
    amount_wire: preview.amount_wire,
    rail: preview.plan.rail,
    channel_id: preview.plan.channel_id ?? null,
  });

  return Object.freeze({
    to: preview.to,
    amountMei: preview.amount_mei,
    options,
    expectation,
  });
}
