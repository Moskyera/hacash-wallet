/**
 * THE HALF HOUR THE WALLET SHOWED NOTHING.
 *
 * An owner opened the first mainnet Fast Pay channel on this rail. Between the
 * confirm and the moment the channel settled there was a stretch of about half
 * an hour in which 0.2 HAC of their own money was committed on the chain and
 * this screen rendered NOTHING for it: the exit panel is gated on
 * `binding && !binding.closed`, and the binding provably cannot exist until the
 * wait is already over. An ordinary wait and a dead app looked identical
 * because there was no element for that state at all.
 *
 * This module holds the two numbers that stretch was missing, as pure
 * functions, so they can be argued with by a test rather than by reading JSX.
 *
 *
 * WHICH CONFIRMATION COUNT ACTUALLY GATES THE EXIT
 *
 * The tree looks like it disagrees with itself:
 *
 *   crates/agent-wallet-core/src/service/l2.rs:50
 *       const REQUIRED_OPEN_CONFIRMATIONS: u64 = 6;
 *   crates/agent-wallet-core/src/service/l2/channel_setup.rs:634
 *       if snapshot.current_height < channel.open_height.saturating_add(5)
 *
 * It does not. The constant is never used bare; both of its use sites subtract
 * one (`REQUIRED_OPEN_CONFIRMATIONS - 1`), at l2.rs:1058 in
 * `AgentL2Binding::from_verified_channel` and again at l2.rs:1108 in
 * `AgentL2Binding::validate`, which re-runs on every load from disk. So the
 * gate is `current_height >= open_height + 5` in all three places. Six
 * confirmations counted inclusively: the open block itself is confirmation 1,
 * so the sixth lands at `open_height + 5`.
 *
 * That is the rule the owner's exit really turns on. "Take my way out" reaches
 * the voucher path, and channel_voucher.rs:125 refuses without an active
 * binding; the only non-test producer of a binding is channel_setup.rs:647,
 * reached only by falling past the height check three lines above it.
 *
 * So the bar counts `current_height - open_height + 1` out of 6 and fills at
 * `open_height + 5`. A bar that fills at +6 fills one block late and a bar that
 * fills at +4 fills one block early. Both are the screen that lies.
 *
 *
 * WHAT THE SCREEN IS ALLOWED TO DRAW
 *
 * The uncomfortable part: during the wait itself the open height is NOT on the
 * screen. `AgentChannelSetupReview` carries no open height, no confirmed
 * height and no transaction hash, and `l2_binding` is null until the wait is
 * over. The only anchor a bar could use in that window is a height the screen
 * remembered for itself, which is not the open height and is lost on reload.
 * Labelling that "3 of 6 confirmations" would be exactly the fabricated number
 * this work exists to remove.
 *
 * Hence three outcomes and no fourth. When the count cannot be known, this
 * returns a shape that carries no count and no percentage at all, so there is
 * nothing for a caller to accidentally render as zero.
 */

/**
 * Six, counted the way a person counts: the open block is the first one.
 *
 * Deliberately NOT the bare 5 that appears in channel_setup.rs. Five is that
 * same rule with the subtraction already done, and a screen that printed "5"
 * would be reporting the arithmetic instead of the fact.
 */
export const REQUIRED_OPEN_CONFIRMATIONS = 6;

export type ChannelOpenProgress =
  /** No node answered, so the chain height is not known. Never draw a zero. */
  | { kind: "chain_height_unknown" }
  /**
   * The chain height is known and moving, but which block the open landed in
   * is not on this screen yet. A height, and honestly no count.
   */
  | { kind: "open_height_unknown"; currentHeight: number }
  /** Both known. This is the only shape that carries a count or a percentage. */
  | {
      kind: "counting";
      currentHeight: number;
      openHeight: number;
      confirmations: number;
      required: number;
      percent: number;
      /** True exactly when the core would let the voucher be taken. */
      settled: boolean;
    };

/**
 * @param currentHeight `overview.node.current_height`, or null whenever the
 *   node probe returned no snapshot. `overview.node` is nullable and is null
 *   for offline, network_mismatch and capability_mismatch, so this must never
 *   be defaulted to 0.
 * @param openHeight the block the channel open landed in, which only
 *   `l2_binding.channel_open_height` and the close reviews carry. Null during
 *   the wait, because nothing on the screen knows it then.
 * @param confirmedAtHeight `l2_binding.confirmed_at_height`, the height the
 *   core ACCEPTED the open at. This is the honest floor, and leaving it out was
 *   a real defect: `AgentL2Binding::validate` re-checks this STORED height, not
 *   the live one, and the voucher path never consults the chain height at all.
 *   So a node that is behind, resyncing or freshly restarted made the panel
 *   read "0 of 6" beside a working exit button. The count must never fall below
 *   what the wallet has already banked.
 */
export function channelOpenProgress(input: {
  currentHeight: number | null | undefined;
  openHeight: number | null | undefined;
  confirmedAtHeight?: number | null | undefined;
}): ChannelOpenProgress {
  const liveHeight = usableHeight(input.currentHeight);
  const bankedHeight = usableHeight(input.confirmedAtHeight);
  // Where the chain is, and what the wallet has banked, are two different
  // facts and only one of them may be printed as a chain height. The first
  // version of this floor conflated them and the panel announced
  // "Chain is at 777938" while no node could be reached. A count may rest on
  // the banked height; a claim about the chain may not.
  if (liveHeight === null) return { kind: "chain_height_unknown" };
  // Floor the COUNT on what the core accepted. `AgentL2Binding::validate`
  // re-checks that stored height, not the live one, and the voucher path never
  // consults the chain at all, so a node that is behind or resyncing must not
  // make the panel read "0 of 6" beside an exit button that works.
  const currentHeight =
    bankedHeight === null ? liveHeight : Math.max(liveHeight, bankedHeight);

  const openHeight = usableHeight(input.openHeight);
  if (openHeight === null) return { kind: "open_height_unknown", currentHeight };

  // Clamped at both ends. Below the open height is a real state after a reorg
  // or a swap to a shorter node, and it must read as fewer confirmations, not
  // as a negative one. Above six it stays six, because six is where the core
  // stops caring and a count that keeps climbing implies a gate that has not
  // opened.
  const elapsed = currentHeight - openHeight;
  const confirmations = Math.min(
    REQUIRED_OPEN_CONFIRMATIONS,
    Math.max(0, elapsed + 1),
  );

  return {
    kind: "counting",
    // The LIVE height, never the floored one, because this is the number the
    // screen labels "Chain is at".
    currentHeight: liveHeight,
    openHeight,
    confirmations,
    required: REQUIRED_OPEN_CONFIRMATIONS,
    percent: Math.round((confirmations / REQUIRED_OPEN_CONFIRMATIONS) * 100),
    // Written as the core writes it rather than as `confirmations >= 6`, so
    // that the one line a reader compares against l2.rs is the same shape.
    settled: currentHeight >= openHeight + (REQUIRED_OPEN_CONFIRMATIONS - 1),
  };
}

function usableHeight(value: number | null | undefined): number | null {
  if (typeof value !== "number") return null;
  if (!Number.isFinite(value)) return null;
  if (!Number.isInteger(value)) return null;
  if (value <= 0) return null;
  return value;
}

export type ReviewCountdown =
  /** No review on the screen, or no deadline on it. */
  | { kind: "unknown" }
  | { kind: "live"; secondsRemaining: number; label: string }
  | { kind: "expired" };

/**
 * The 300 second envelope that was in the shipped build and was never drawn.
 *
 * `l2_channel_setup.expires_at` has always been on the overview and was only
 * ever read to compute two booleans. The owner's first attempt expired unseen,
 * and the refusal afterwards was the same five generic words eight other
 * causes produce.
 *
 * @param nowSeconds passed in rather than read from the clock, so the caller
 *   owns the tick and a test owns the instant.
 */
export function reviewCountdown(input: {
  expiresAt: number | null | undefined;
  nowSeconds: number;
}): ReviewCountdown {
  const { expiresAt, nowSeconds } = input;
  if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) {
    return { kind: "unknown" };
  }
  const secondsRemaining = Math.floor(expiresAt - nowSeconds);
  // At exactly zero the wallet already refuses, so zero is expired, not "0:00
  // left". The screen must not offer a second a button will not honour.
  if (secondsRemaining <= 0) return { kind: "expired" };
  return {
    kind: "live",
    secondsRemaining,
    label: countdownLabel(secondsRemaining),
  };
}

function countdownLabel(secondsRemaining: number): string {
  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = secondsRemaining % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}
