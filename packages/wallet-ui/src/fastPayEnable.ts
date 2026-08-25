/**
 * Why "Enable Fast Pay" would refuse, right now, in the person's own words.
 *
 * WHY THIS EXISTS. The owner sat on the Fast Pay screen with a working Hub and
 * pressed Enable, and nothing happened that they could see. Every refusal on
 * that path did arrive: it went to a toast that clears itself after four
 * seconds and to a banner pinned to the top of a screen they had scrolled past.
 * Two of the conditions did not produce a refusal at all, they greyed the
 * button out instead, and a greyed button carries no reason.
 *
 * So this names every local condition the Enable path checks, with the value it
 * currently has, all at once. A person fixes three things in one pass instead of
 * discovering them one refusal at a time.
 *
 * IT GATES NOTHING. Every rule mirrored here is enforced again, for real, in
 * `WalletService::prepare_channel_open` and in the L1 signing boundary, and the
 * Hub re-judges its own readiness document at the moment of funding. This is the
 * saying half, never the deciding half: an empty list here is not permission,
 * and the core still refuses on its own account. Nothing here may ever be used
 * to skip a core check.
 */

export type FastPayEnableRefusal = {
  /** Stable identifier, so a person can quote it and a test can assert it. */
  id: string;
  /** One line naming the condition. */
  title: string;
  /** What to do about it, or what value was actually seen. */
  detail: string;
};

export type FastPayEnableInput = {
  /** False while `wallet_get_settings` has not answered yet. */
  settingsLoaded: boolean;
  /** A watch-only wallet holds no key and can sign no channel open. */
  watchOnly: boolean;
  /** A locked wallet cannot sign. */
  locked: boolean;
  networkMode: string | null | undefined;
  nodeUrl: string | null | undefined;
  /** `settings.hub_right_address`. A channel binds to an exact counterparty. */
  hubAddress: string | null | undefined;
  /** `settings.trusted_mainnet_fast_pay_pilot`. */
  consentGranted: boolean;
  /** Exactly the string in the deposit field. */
  depositHac: string;
  /**
   * The Hub's own per-channel cap in HAC, when this screen has read it from
   * the Hub. `null` means nobody has asked yet, and an unknown cap is reported
   * as unknown rather than as satisfied.
   */
  declaredChannelCapHac: string | null;
  /** Mirrors `mainnetSigningTransportIsEligible` for the same node and mode. */
  signingTransportEligible: boolean;
  /** The notice text for an ineligible signing transport. */
  signingTransportNotice: string;
};

export function fastPayEnableRefusals(
  input: FastPayEnableInput,
): FastPayEnableRefusal[] {
  const refusals: FastPayEnableRefusal[] = [];
  const isMainnet = input.networkMode === "mainnet";

  if (!input.settingsLoaded) {
    refusals.push({
      id: "settings_not_loaded",
      title: "This screen has not read your settings yet",
      detail:
        "Nothing has been refused. Wait a moment, or reopen this tab if it stays this way.",
    });
    return refusals;
  }

  if (input.watchOnly) {
    refusals.push({
      id: "watch_only_wallet",
      title: "This is a watch-only wallet",
      detail:
        "It holds no signing key, so it cannot open a channel. Unlock the wallet that holds the key on this device.",
    });
  }

  if (input.locked) {
    refusals.push({
      id: "wallet_locked",
      title: "The wallet is locked",
      detail: "Unlock it first. Opening a channel signs a real transaction.",
    });
  }

  if (!input.hubAddress || input.hubAddress.trim() === "") {
    refusals.push({
      id: "no_provider_address",
      title: "No provider address is saved",
      detail:
        'Use "Check this hub" or "Scan for hubs" above, then "Use this hub", so the wallet has the provider\'s on-chain address. A channel binds to an exact counterparty and the wallet will not guess one.',
    });
  }

  if (!input.signingTransportEligible) {
    refusals.push({
      id: "signing_transport_ineligible",
      title: "This node cannot sign on mainnet",
      detail: `${input.signingTransportNotice} Current node: ${
        input.nodeUrl?.trim() || "not set"
      }`,
    });
  }

  if (isMainnet && !input.consentGranted) {
    refusals.push({
      id: "mainnet_consent_withheld",
      title: "The bounded mainnet pilot has not been accepted",
      detail:
        'Tick the consent box near the top of this screen and press "Confirm this choice" with your wallet passphrase. Without it this wallet asks the Hub for trustless settlement, which no bounded pilot Hub can offer, and the channel open is refused.',
    });
  }

  const deposit = Number(input.depositHac);
  if (!Number.isFinite(deposit) || deposit <= 0) {
    refusals.push({
      id: "deposit_not_a_number",
      title: "The channel deposit is not a usable amount",
      detail: `Enter a positive number of HAC. This field currently holds "${input.depositHac}".`,
    });
  } else if (input.declaredChannelCapHac === null) {
    refusals.push({
      id: "channel_cap_unknown",
      title: "This Hub's per-channel cap has not been read yet",
      detail:
        // Named by the BUTTON rather than by a card heading. The heading "Your
        // node and your Hub, right now" exists only on the desktop screen, and
        // this sentence is now the first thing a phone reads when the cap is
        // unread, so it pointed at something a person could not find. "Run the
        // check" is the control's label on both platforms.
        'Press "Run the check" further down this screen to see the caps this Hub declares. Unknown is not the same as fine: the Hub judges the deposit again when the money moves, and it refuses anything over its own cap.',
    });
  } else {
    const cap = Number(input.declaredChannelCapHac);
    if (Number.isFinite(cap) && deposit > cap) {
      refusals.push({
        id: "deposit_over_declared_cap",
        title: "The deposit is larger than this Hub will accept",
        detail: `You typed ${input.depositHac} HAC and this Hub declares a per-channel cap of ${input.declaredChannelCapHac} HAC. It will refuse the open. Lower the deposit to ${input.declaredChannelCapHac} HAC or less.`,
      });
    }
  }

  return refusals;
}

/**
 * The one line above the list.
 *
 * Deliberately does not say "ready" when the list is empty. Every gate runs
 * again in the core and at the Hub, and this side has checked only what a
 * screen can see.
 */
export function fastPayEnableHeadline(refusals: FastPayEnableRefusal[]): string {
  if (refusals.length === 0) {
    return "Nothing this screen can see is stopping you. The wallet and the Hub check everything again when you press Enable, and either of them can still refuse with a reason.";
  }
  if (refusals.length === 1) {
    return "One thing is stopping Enable right now.";
  }
  return `${refusals.length} things are stopping Enable right now.`;
}

/**
 * The label on the fold that holds the whole refusal queue.
 *
 * A constant because two screens print it and a third sentence points at it by
 * name. The counter under the next step used to point at "Turn Fast Pay ON",
 * which is a card that no longer exists as a separate thing, so it named a
 * heading a person could not find.
 */
export const FAST_PAY_ENABLE_FOLD_LABEL = "Everything stopping Enable";

/** The fold's summary: the label, then the count, computed from the list. */
export function fastPayEnableFoldSummary(refusals: FastPayEnableRefusal[]): string {
  return `${FAST_PAY_ENABLE_FOLD_LABEL}. ${fastPayEnableHeadline(refusals)}`;
}

/**
 * "and here is how many more after this one", pointing somewhere real.
 *
 * The count comes from the refusal list, so it cannot claim two when there are
 * three.
 */
export function fastPayRemainingLine(remaining: number): string {
  const plural = remaining === 1 ? "" : "s";
  const verb = remaining === 1 ? "s" : "";
  return `${remaining} other thing${plural} still need${verb} attention after this one, listed under "${FAST_PAY_ENABLE_FOLD_LABEL}" below.`;
}

/**
 * The one next action, and whether it can be taken right now.
 *
 * WHY THIS EXISTS. The Fast Pay screen could answer every question except the
 * first one a person actually has. It showed a state pill, a route hint, a
 * consent block, a hub finder, a preflight report and a refusal list, and left
 * somebody to read all six and work out which was their turn. The owner sat on
 * this screen with a healthy Hub and could not tell whether they were waiting on
 * the wallet, on their Hub, on their node, or on themselves.
 *
 * So this picks ONE step and says it in words. It reads the refusal list that
 * `fastPayEnableRefusals` already produces and the measured Fast Pay state; it
 * introduces no new rule and no new check.
 *
 * IT GATES NOTHING, exactly like the list it reads. `canActNow: true` is not
 * permission, it means "nothing this screen can see is in the way". The core
 * still refuses on its own account and the Hub still re-judges its own document.
 */
export type FastPayNextStep = {
  /** What state the person is in, as a sentence. */
  headline: string;
  /** The single thing to do next, in words a person can act on. */
  action: string;
  /** True when nothing this screen can see is in the way. Never permission. */
  canActNow: boolean;
  /** The refusal id responsible, or `null` when nothing is blocking. */
  blockedBy: string | null;
  /** How many other refusals are queued behind this one. */
  remaining: number;
};

export type FastPayNextStepInput = {
  /** The MEASURED state, from `wallet_fast_pay_status`. Never `status.fast_pay_state`. */
  state: string | null | undefined;
  refusals: FastPayEnableRefusal[];
  /**
   * Whether the preflight reached the node. `null` means nobody has checked.
   *
   * Unknown is reported as unknown and never as broken: sending a person to fix
   * a node that is fine is exactly the wrong-cause failure this screen already
   * warns about elsewhere.
   */
  nodeReachable: boolean | null;
  /**
   * Refusal ids in the order they should be tackled. Ids not listed keep their
   * original relative order behind the ones that are.
   */
  preferOrder?: string[];
};

export function fastPayNextStep(input: FastPayNextStepInput): FastPayNextStep {
  // A node nobody can reach makes every other step pointless, and the preflight
  // already knows this. It was the one fact the screen never promoted.
  if (input.nodeReachable === false) {
    return {
      headline: "Your node is not answering.",
      action:
        // Same reason as `channel_cap_unknown` above: named by the control, not
        // by a heading only one of the two platforms has.
        'Fix the node first: check the node URL in your settings and that the node is running, then press "Run the check" again. A channel open is a real transaction and it has to be submitted through a node.',
      canActNow: false,
      blockedBy: "node_unreachable",
      remaining: input.refusals.length,
    };
  }

  if (input.state === "ready") {
    return {
      headline: "Fast Pay is on.",
      action: "Nothing to do here. Go to Send and your payment routes instantly.",
      canActNow: true,
      blockedBy: null,
      remaining: 0,
    };
  }

  const ordered = orderRefusals(input.refusals, input.preferOrder);
  const first = ordered[0];
  if (first) {
    return {
      headline: first.title + ".",
      action: first.detail,
      canActNow: false,
      blockedBy: first.id,
      remaining: ordered.length - 1,
    };
  }

  if (input.state === "no_provider") {
    return {
      headline: "No Fast Pay provider is saved.",
      action:
        'Find one in "Find a hub" above: type its address, press "Check this hub", then "Use this hub".',
      canActNow: false,
      blockedBy: "no_provider",
      remaining: 0,
    };
  }

  if (input.state === "checking" || !input.state) {
    return {
      headline: "Still reading your provider.",
      action:
        "Wait a moment. This screen is asking your Hub what it allows; nothing has been refused.",
      canActNow: false,
      blockedBy: "checking",
      remaining: 0,
    };
  }

  return {
    headline: "Nothing this screen can see is stopping you.",
    action:
      'Press "Enable Fast Pay" below. The wallet and your Hub check everything again when you do, and either can still refuse with a reason.',
    canActNow: true,
    blockedBy: null,
    remaining: 0,
  };
}

/** Stable sort that floats the preferred ids to the front in the given order. */
function orderRefusals(
  refusals: FastPayEnableRefusal[],
  preferOrder: string[] | undefined,
): FastPayEnableRefusal[] {
  if (!preferOrder || preferOrder.length === 0) return refusals;
  const rank = (refusal: FastPayEnableRefusal) => {
    const at = preferOrder.indexOf(refusal.id);
    return at === -1 ? preferOrder.length : at;
  };
  return refusals
    .map((refusal, index) => ({ refusal, index }))
    .sort((a, b) => rank(a.refusal) - rank(b.refusal) || a.index - b.index)
    .map((entry) => entry.refusal);
}
